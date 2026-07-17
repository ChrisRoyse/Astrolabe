use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, c_char};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Mutex, MutexGuard};

use calyx_core::{CalyxError, Result, RuntimeExecutionAttestation};
use fastembed::SessionPolicy;
use memmap2::Mmap;
use ort::session::Session;
use ort::{AsPointer, Error as OrtError};
use sha2::{Digest, Sha256};

use super::cpu_fallback_audit::{AuditMode, audit_from_trace, profiling_file_path};
use super::{OnnxModelFiles, OnnxProviderPolicy};

const CUDA_REMEDIATION: &str = "verify ORT_DYLIB_PATH points to the pinned CUDA 13 ONNX Runtime, CUDA device 0 is usable, and every frozen model operator has a CUDA kernel; select the explicit CPU constructor only when CUDA is genuinely unavailable, and never retry a failed CUDA session on CPU";
const CPU_REMEDIATION: &str = "verify ORT_DYLIB_PATH points to the pinned ONNX Runtime and repair the explicit CPU model/session configuration before retrying";
const MAX_PROTO_RECURSION: usize = 64;

#[derive(Clone, Debug)]
pub(super) struct FastembedModelContext {
    label: String,
    model_code: String,
    model_path: PathBuf,
    weights_sha256: String,
    provider_policy: OnnxProviderPolicy,
    device: String,
    profile_prefix: Option<PathBuf>,
    frozen_operators: String,
}

impl FastembedModelContext {
    pub(super) fn new(
        label: String,
        model_code: &str,
        files: &OnnxModelFiles,
        weights_sha256: [u8; 32],
        provider_policy: OnnxProviderPolicy,
    ) -> Result<Self> {
        let selected_device = super::runtime_bundle::selected_cuda_device(provider_policy)?;
        let device = selected_device
            .map(|device| format!("cuda:{}", device.ordinal))
            .unwrap_or_else(|| "cpu".to_string());
        let profile_prefix = (provider_policy == OnnxProviderPolicy::CudaFailLoud)
            .then(|| profiling_file_path(&label));
        let mut context = Self {
            label,
            model_code: model_code.to_string(),
            model_path: files.model_file.clone(),
            weights_sha256: hex_sha256(weights_sha256),
            provider_policy,
            device,
            profile_prefix,
            frozen_operators: "unread".to_string(),
        };
        let frozen_operators = frozen_operator_inventory(&context.model_path)
            .map_err(|reason| context.error("frozen_graph_operator_inventory", reason))?;
        context.frozen_operators = frozen_operators;
        Ok(context)
    }

    pub(super) fn session_policy(&self) -> SessionPolicy {
        match self.provider_policy {
            OnnxProviderPolicy::CudaFailLoud => SessionPolicy::cuda_no_cpu_fallback(
                self.profile_prefix
                    .as_ref()
                    .expect("CUDA FastEmbed context has a profiling prefix")
                    .clone(),
            ),
            OnnxProviderPolicy::CpuExplicit => SessionPolicy::explicit_cpu(),
        }
    }

    pub(super) fn error(&self, stage: &'static str, reason: impl ToString) -> CalyxError {
        CalyxError {
            code: "CALYX_ONNX_FASTEMBED_EXECUTION_UNATTESTED",
            message: format!(
                "fastembed model={} path={} weights_sha256={} provider={} device={} profile_prefix={} stage={} frozen_operators={} reason={}",
                self.model_code,
                self.model_path.display(),
                self.weights_sha256,
                self.provider_policy.as_str(),
                self.device,
                self.profile_prefix
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "none".to_string()),
                stage,
                self.frozen_operators,
                reason.to_string()
            ),
            remediation: match self.provider_policy {
                OnnxProviderPolicy::CudaFailLoud => CUDA_REMEDIATION,
                OnnxProviderPolicy::CpuExplicit => CPU_REMEDIATION,
            },
        }
    }
}

#[derive(Clone, Debug)]
struct GraphAssignment {
    total_nodes: u64,
    cpu_nodes: u64,
    cuda_nodes: u64,
    per_provider: String,
    per_provider_operators: String,
}

#[derive(Clone, Debug)]
enum ExecutionState {
    Pending,
    Finalizing,
    Attested(RuntimeExecutionAttestation),
    Failed(CalyxError),
}

/// Placement evidence retained for one exact committed FastEmbed session.
pub(super) struct FastembedExecutionState {
    context: FastembedModelContext,
    assignment: GraphAssignment,
    state: Mutex<ExecutionState>,
}

impl FastembedExecutionState {
    pub(super) fn inspect(session: &Session, context: FastembedModelContext) -> Result<Self> {
        let assignment = read_graph_assignment(session)
            .map_err(|error| context.error("api24_graph_assignment_readback", error))?;
        validate_assignment(&context, &assignment)?;
        eprintln!(
            "CALYX_ONNX_RUNTIME phase=fastembed_api24_graph_assignment label={} model={} path={} weights_sha256={} provider={} device={} total_nodes={} cuda_nodes={} cpu_nodes={} providers={} assigned_operators={}",
            context.label,
            context.model_code,
            context.model_path.display(),
            context.weights_sha256,
            context.provider_policy.as_str(),
            context.device,
            assignment.total_nodes,
            assignment.cuda_nodes,
            assignment.cpu_nodes,
            assignment.per_provider,
            assignment.per_provider_operators
        );
        Ok(Self {
            context,
            assignment,
            state: Mutex::new(ExecutionState::Pending),
        })
    }

    pub(super) fn error(&self, stage: &'static str, reason: impl ToString) -> CalyxError {
        self.context.error(stage, reason)
    }

    pub(super) fn ensure_usable(&self) -> Result<()> {
        match &*self.lock_state()? {
            ExecutionState::Failed(error) => Err(error.clone()),
            ExecutionState::Finalizing => Err(self.context.error(
                "first_inference_profile_state",
                "profiling finalization is already in progress",
            )),
            ExecutionState::Pending | ExecutionState::Attested(_) => Ok(()),
        }
    }

    /// Finalizes profiling at most once, after the caller has completed and
    /// synchronized a successful real inference and materialized its output.
    pub(super) fn complete_first_inference(
        &self,
        end_profiling: impl FnOnce() -> ort::Result<String>,
    ) -> Result<()> {
        let mut state = self.lock_state()?;
        match &*state {
            ExecutionState::Attested(_) => return Ok(()),
            ExecutionState::Failed(error) => return Err(error.clone()),
            ExecutionState::Finalizing => {
                return Err(self.context.error(
                    "first_inference_profile_state",
                    "profiling finalization is already in progress",
                ));
            }
            ExecutionState::Pending => {}
        }
        *state = ExecutionState::Finalizing;

        let result = match self.context.provider_policy {
            OnnxProviderPolicy::CudaFailLoud => self.cuda_profile_attestation(end_profiling),
            OnnxProviderPolicy::CpuExplicit => Ok(self.assignment_attestation(
                "onnx_api24_committed_session_after_first_real_synchronized_inference",
                self.assignment.per_provider.clone(),
                None,
            )),
        };
        match result {
            Ok(attestation) => {
                eprintln!(
                    "CALYX_ONNX_RUNTIME phase=fastembed_execution_attestation_committed label={} model={} provider={} device={} total_nodes={} cpu_nodes={}",
                    self.context.label,
                    self.context.model_code,
                    attestation.provider,
                    attestation.device,
                    attestation.total_compute_nodes.unwrap_or(0),
                    attestation.cpu_compute_nodes.unwrap_or(0)
                );
                *state = ExecutionState::Attested(attestation);
                Ok(())
            }
            Err(error) => {
                eprintln!(
                    "CALYX_ONNX_RUNTIME phase=fastembed_execution_attestation_failed label={} model={} code={} message={} remediation={}",
                    self.context.label,
                    self.context.model_code,
                    error.code,
                    error.message,
                    error.remediation
                );
                *state = ExecutionState::Failed(error.clone());
                Err(error)
            }
        }
    }

    pub(super) fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>> {
        match &*self.lock_state()? {
            ExecutionState::Pending | ExecutionState::Finalizing => Ok(None),
            ExecutionState::Attested(attestation) => Ok(Some(attestation.clone())),
            ExecutionState::Failed(error) => Err(error.clone()),
        }
    }

    fn cuda_profile_attestation(
        &self,
        end_profiling: impl FnOnce() -> ort::Result<String>,
    ) -> Result<RuntimeExecutionAttestation> {
        let trace_path = end_profiling()
            .map_err(|error| self.context.error("first_inference_end_profiling", error))?;
        self.validate_profile_path(&trace_path)?;
        let trace = std::fs::read_to_string(&trace_path).map_err(|error| {
            self.context.error(
                "first_inference_profile_readback",
                format!("read {} failed: {error}", trace_path),
            )
        })?;
        let trace_sha256 = format!("{:x}", Sha256::digest(trace.as_bytes()));
        let profile = audit_from_trace(&self.context.label, &trace, true, AuditMode::Fail, 0.0)
            .map_err(|error| self.context.error("first_inference_profile_parse", error))?;
        if profile.total_nodes == 0
            || profile.cpu_nodes != 0
            || profile.cuda_nodes != profile.total_nodes
        {
            return Err(self.context.error(
                "first_inference_profile_validation",
                format!(
                    "expected every profiled compute node on CUDA, observed cuda={}/{} cpu={} providers={} trace={}",
                    profile.cuda_nodes,
                    profile.total_nodes,
                    profile.cpu_nodes,
                    profile.per_provider,
                    trace_path
                ),
            ));
        }
        eprintln!(
            "CALYX_ONNX_RUNTIME phase=fastembed_first_inference_attested label={} model={} provider={} api24_nodes={} profile_nodes={} profile_path={} profile_sha256={}",
            self.context.label,
            self.context.model_code,
            self.context.provider_policy.as_str(),
            self.assignment.total_nodes,
            profile.total_nodes,
            trace_path,
            trace_sha256
        );
        Ok(self.assignment_attestation(
            "onnx_api24_committed_session+first_real_synchronized_inference_profile",
            format!(
                "api24={};profile={}",
                self.assignment.per_provider, profile.per_provider
            ),
            Some((&trace_path, &trace_sha256)),
        ))
    }

    fn validate_profile_path(&self, trace_path: &str) -> Result<()> {
        let prefix = self
            .context
            .profile_prefix
            .as_ref()
            .expect("CUDA FastEmbed context has a profiling prefix");
        let observed = Path::new(trace_path);
        let expected_name = prefix
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                self.context.error(
                    "first_inference_profile_path_validation",
                    "profiling prefix has no UTF-8 file name",
                )
            })?;
        let observed_name = observed
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                self.context.error(
                    "first_inference_profile_path_validation",
                    format!("returned profiling path {trace_path} has no UTF-8 file name"),
                )
            })?;
        if observed.parent() != prefix.parent() || !observed_name.starts_with(expected_name) {
            return Err(self.context.error(
                "first_inference_profile_path_validation",
                format!(
                    "ORT returned profile path {trace_path}, outside expected prefix {}",
                    prefix.display()
                ),
            ));
        }
        Ok(())
    }

    fn assignment_attestation(
        &self,
        evidence_mechanism: &str,
        provider: String,
        profile: Option<(&str, &str)>,
    ) -> RuntimeExecutionAttestation {
        let profile_evidence = profile
            .map(|(path, sha256)| format!(";profile_path={path};profile_sha256={sha256}"))
            .unwrap_or_default();
        RuntimeExecutionAttestation {
            runtime: "onnx-fastembed-5.16.0-owned".to_string(),
            provider,
            device: self.context.device.clone(),
            loader_dtype: None,
            compute_dtype: None,
            evidence: format!(
                "{};model={};path={};weights_sha256={};profile_prefix={};frozen_operators={};assigned_operators={}{}",
                evidence_mechanism,
                self.context.model_code,
                self.context.model_path.display(),
                self.context.weights_sha256,
                self.context
                    .profile_prefix
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "none".to_string()),
                self.context.frozen_operators,
                self.assignment.per_provider_operators,
                profile_evidence
            ),
            total_compute_nodes: Some(self.assignment.total_nodes),
            cpu_compute_nodes: Some(self.assignment.cpu_nodes),
        }
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ExecutionState>> {
        self.state.lock().map_err(|_| {
            self.context.error(
                "execution_attestation_state",
                "FastEmbed execution-attestation mutex is poisoned",
            )
        })
    }
}

fn validate_assignment(
    context: &FastembedModelContext,
    assignment: &GraphAssignment,
) -> Result<()> {
    if assignment.total_nodes == 0 {
        return Err(context.error(
            "api24_graph_assignment_validation",
            "API-24 graph assignment reported zero compute nodes",
        ));
    }
    match context.provider_policy {
        OnnxProviderPolicy::CudaFailLoud
            if assignment.cpu_nodes != 0
                || assignment.cuda_nodes != assignment.total_nodes =>
        {
            Err(context.error(
                "api24_graph_assignment_validation",
                format!(
                    "expected every committed-session node on CUDA, observed cuda={}/{} cpu={} providers={} assigned_operators={}",
                    assignment.cuda_nodes,
                    assignment.total_nodes,
                    assignment.cpu_nodes,
                    assignment.per_provider,
                    assignment.per_provider_operators
                ),
            ))
        }
        OnnxProviderPolicy::CpuExplicit if assignment.cpu_nodes != assignment.total_nodes => {
            Err(context.error(
                "api24_graph_assignment_validation",
                format!(
                    "expected every committed-session node on explicit CPU, observed cpu={}/{} providers={} assigned_operators={}",
                    assignment.cpu_nodes,
                    assignment.total_nodes,
                    assignment.per_provider,
                    assignment.per_provider_operators
                ),
            ))
        }
        _ => Ok(()),
    }
}

fn read_graph_assignment(session: &Session) -> std::result::Result<GraphAssignment, OrtError> {
    let mut subgraphs = ptr::null();
    let mut subgraph_count = 0usize;
    // ORT owns the returned assignment objects for the committed session's
    // lifetime. This routine only reads them while `session` is borrowed.
    status_result(unsafe {
        (ort::api().Session_GetEpGraphAssignmentInfo)(
            session.ptr(),
            &mut subgraphs,
            &mut subgraph_count,
        )
    })?;
    if subgraph_count > 0 && subgraphs.is_null() {
        return Err(OrtError::new(
            "Session_GetEpGraphAssignmentInfo returned a null subgraph array",
        ));
    }
    let subgraphs = if subgraph_count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(subgraphs, subgraph_count) }
    };

    let mut counts = BTreeMap::<String, u64>::new();
    let mut operators = BTreeMap::<String, BTreeSet<String>>::new();
    for &subgraph in subgraphs {
        if subgraph.is_null() {
            return Err(OrtError::new(
                "Session_GetEpGraphAssignmentInfo returned a null subgraph",
            ));
        }
        let provider = assigned_string(|out| unsafe {
            (ort::api().EpAssignedSubgraph_GetEpName)(subgraph, out)
        })?;
        if provider.trim().is_empty() {
            return Err(OrtError::new(
                "EpAssignedSubgraph_GetEpName returned an empty provider",
            ));
        }
        let mut nodes = ptr::null();
        let mut node_count = 0usize;
        status_result(unsafe {
            (ort::api().EpAssignedSubgraph_GetNodes)(subgraph, &mut nodes, &mut node_count)
        })?;
        if node_count > 0 && nodes.is_null() {
            return Err(OrtError::new(
                "EpAssignedSubgraph_GetNodes returned a null node array",
            ));
        }
        let node_count_u64 = u64::try_from(node_count)
            .map_err(|_| OrtError::new("assigned ONNX node count exceeds u64"))?;
        *counts.entry(provider.clone()).or_default() += node_count_u64;
        let nodes = if node_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(nodes, node_count) }
        };
        for &node in nodes {
            if node.is_null() {
                return Err(OrtError::new(
                    "EpAssignedSubgraph_GetNodes returned a null node",
                ));
            }
            let operator = assigned_string(|out| unsafe {
                (ort::api().EpAssignedNode_GetOperatorType)(node, out)
            })?;
            if operator.trim().is_empty() {
                return Err(OrtError::new(
                    "EpAssignedNode_GetOperatorType returned an empty operator",
                ));
            }
            operators
                .entry(provider.clone())
                .or_default()
                .insert(operator);
        }
    }

    let total_nodes = counts.values().copied().sum();
    let cpu_nodes = counts
        .iter()
        .filter(|(provider, _)| provider_name_contains(provider, "CPU"))
        .map(|(_, count)| *count)
        .sum();
    let cuda_nodes = counts
        .iter()
        .filter(|(provider, _)| provider_name_contains(provider, "CUDA"))
        .map(|(_, count)| *count)
        .sum();
    let per_provider = counts
        .iter()
        .map(|(provider, count)| format!("{provider}:{count}"))
        .collect::<Vec<_>>()
        .join(",");
    let per_provider_operators = operators
        .iter()
        .map(|(provider, names)| {
            format!(
                "{}:[{}]",
                provider,
                names.iter().cloned().collect::<Vec<_>>().join(",")
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    Ok(GraphAssignment {
        total_nodes,
        cpu_nodes,
        cuda_nodes,
        per_provider,
        per_provider_operators,
    })
}

fn provider_name_contains(provider: &str, expected: &str) -> bool {
    provider.to_ascii_uppercase().contains(expected)
}

fn assigned_string(
    call: impl FnOnce(*mut *const c_char) -> ort::sys::OrtStatusPtr,
) -> std::result::Result<String, OrtError> {
    let mut raw = ptr::null();
    status_result(call(&mut raw))?;
    if raw.is_null() {
        return Err(OrtError::new(
            "ONNX graph assignment returned a null string",
        ));
    }
    unsafe { CStr::from_ptr(raw) }
        .to_str()
        .map(str::to_owned)
        .map_err(|error| {
            OrtError::new(format!(
                "ONNX graph assignment string is not UTF-8: {error}"
            ))
        })
}

fn status_result(status: ort::sys::OrtStatusPtr) -> std::result::Result<(), OrtError> {
    unsafe { OrtError::result_from_status(status) }
}

fn frozen_operator_inventory(path: &Path) -> std::result::Result<String, String> {
    let file =
        File::open(path).map_err(|error| format!("open frozen ONNX graph failed: {error}"))?;
    let map = unsafe { Mmap::map(&file) }
        .map_err(|error| format!("memory-map frozen ONNX graph failed: {error}"))?;
    if map.is_empty() {
        return Err("frozen ONNX graph is empty".to_string());
    }
    let mut model = ProtoCursor::new(&map);
    let mut graph = None;
    while let Some(field) = model.next_field()? {
        if field.number == 7 {
            let bytes = field.bytes("ModelProto.graph")?;
            if graph.replace(bytes).is_some() {
                return Err("ModelProto contains more than one graph field".to_string());
            }
        }
    }
    let graph = graph.ok_or_else(|| "ModelProto has no graph field".to_string())?;
    let mut inventory = BTreeMap::<String, u64>::new();
    parse_graph(graph, 0, &mut inventory)?;
    if inventory.is_empty() {
        return Err("frozen ONNX graph contains no operator nodes".to_string());
    }
    Ok(inventory
        .into_iter()
        .map(|(operator, count)| format!("{operator}:{count}"))
        .collect::<Vec<_>>()
        .join(","))
}

fn parse_graph(
    bytes: &[u8],
    depth: usize,
    inventory: &mut BTreeMap<String, u64>,
) -> std::result::Result<(), String> {
    if depth > MAX_PROTO_RECURSION {
        return Err(format!(
            "ONNX nested graph depth exceeds {MAX_PROTO_RECURSION}"
        ));
    }
    let mut graph = ProtoCursor::new(bytes);
    while let Some(field) = graph.next_field()? {
        if field.number == 1 {
            parse_node(field.bytes("GraphProto.node")?, depth, inventory)?;
        }
    }
    Ok(())
}

fn parse_node(
    bytes: &[u8],
    depth: usize,
    inventory: &mut BTreeMap<String, u64>,
) -> std::result::Result<(), String> {
    let mut node = ProtoCursor::new(bytes);
    let mut operator = None;
    let mut domain = None;
    let mut attributes = Vec::new();
    while let Some(field) = node.next_field()? {
        match field.number {
            4 => operator = Some(field.string("NodeProto.op_type")?),
            5 => attributes.push(field.bytes("NodeProto.attribute")?),
            7 => domain = Some(field.string("NodeProto.domain")?),
            _ => {}
        }
    }
    let operator = operator
        .filter(|operator| !operator.is_empty())
        .ok_or_else(|| "ONNX NodeProto has no non-empty op_type".to_string())?;
    let key = domain
        .filter(|domain| !domain.is_empty())
        .map(|domain| format!("{domain}::{operator}"))
        .unwrap_or_else(|| operator.to_string());
    let count = inventory.entry(key).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| "ONNX operator count exceeds u64".to_string())?;
    for attribute in attributes {
        parse_attribute(attribute, depth + 1, inventory)?;
    }
    Ok(())
}

fn parse_attribute(
    bytes: &[u8],
    depth: usize,
    inventory: &mut BTreeMap<String, u64>,
) -> std::result::Result<(), String> {
    let mut attribute = ProtoCursor::new(bytes);
    while let Some(field) = attribute.next_field()? {
        if field.number == 6 || field.number == 11 {
            parse_graph(field.bytes("AttributeProto.graph")?, depth, inventory)?;
        }
    }
    Ok(())
}

struct ProtoField<'a> {
    number: u32,
    value: ProtoValue<'a>,
}

impl<'a> ProtoField<'a> {
    fn bytes(self, label: &str) -> std::result::Result<&'a [u8], String> {
        match self.value {
            ProtoValue::Bytes(bytes) => Ok(bytes),
            _ => Err(format!("{label} is not length-delimited")),
        }
    }

    fn string(self, label: &str) -> std::result::Result<&'a str, String> {
        std::str::from_utf8(self.bytes(label)?)
            .map_err(|error| format!("{label} is not UTF-8: {error}"))
    }
}

enum ProtoValue<'a> {
    Varint,
    Fixed,
    Bytes(&'a [u8]),
}

struct ProtoCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ProtoCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn next_field(&mut self) -> std::result::Result<Option<ProtoField<'a>>, String> {
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let number =
            u32::try_from(key >> 3).map_err(|_| "protobuf field number exceeds u32".to_string())?;
        if number == 0 {
            return Err("protobuf field number is zero".to_string());
        }
        let value = match key & 0x07 {
            0 => {
                self.varint()?;
                ProtoValue::Varint
            }
            1 => {
                self.advance(8)?;
                ProtoValue::Fixed
            }
            2 => {
                let length = usize::try_from(self.varint()?)
                    .map_err(|_| "protobuf length exceeds usize".to_string())?;
                let start = self.offset;
                self.advance(length)?;
                ProtoValue::Bytes(&self.bytes[start..self.offset])
            }
            5 => {
                self.advance(4)?;
                ProtoValue::Fixed
            }
            wire => return Err(format!("unsupported protobuf wire type {wire}")),
        };
        Ok(Some(ProtoField { number, value }))
    }

    fn varint(&mut self) -> std::result::Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or_else(|| "truncated protobuf varint".to_string())?;
            self.offset += 1;
            if shift == 63 && byte > 1 {
                return Err("protobuf varint exceeds u64".to_string());
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("protobuf varint exceeds ten bytes".to_string())
    }

    fn advance(&mut self, length: usize) -> std::result::Result<(), String> {
        self.offset = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "protobuf field extends past end of input".to_string())?;
        Ok(())
    }
}

fn hex_sha256(hash: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(64);
    for byte in hash {
        rendered.push(char::from(HEX[usize::from(byte >> 4)]));
        rendered.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    rendered
}
