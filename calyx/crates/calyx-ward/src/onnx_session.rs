//! Owned ONNX Runtime session policy and graph-placement attestation for Ward.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, c_char};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use calyx_core::RuntimeExecutionAttestation;
use memmap2::Mmap;
use ort::ep::{self, ArenaExtendStrategy, ExecutionProviderDispatch};
use ort::session::{Session, builder::GraphOptimizationLevel};
use ort::{AsPointer, Error as OrtError};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::WardError;

const GRAPH_ASSIGNMENT_CONFIG: &str = "session.record_ep_graph_assignment_info";
const CUDA_REMEDIATION: &str = "verify ORT_DYLIB_PATH points to the pinned CUDA 13 ONNX Runtime, CUDA device 0 is usable, and every frozen model operator has a CUDA kernel; select the explicit CPU constructor only when CUDA is genuinely unavailable, and never retry a failed CUDA session or inference on CPU";
const CPU_REMEDIATION: &str = "verify ORT_DYLIB_PATH points to the pinned ONNX Runtime and repair the explicit CPU model/session configuration before retrying";
const MAX_PROTO_RECURSION: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Placement {
    Cuda,
    CpuExplicit,
}

impl Placement {
    const fn provider(self) -> &'static str {
        match self {
            Self::Cuda => crate::CUDA_ONNX_PROVIDER_POLICY,
            Self::CpuExplicit => crate::CPU_ONNX_PROVIDER_POLICY,
        }
    }

    const fn device(self) -> &'static str {
        match self {
            Self::Cuda => "cuda:0",
            Self::CpuExplicit => "cpu",
        }
    }

    const fn remediation(self) -> &'static str {
        match self {
            Self::Cuda => CUDA_REMEDIATION,
            Self::CpuExplicit => CPU_REMEDIATION,
        }
    }
}

#[derive(Clone, Debug)]
struct SessionContext {
    lens: &'static str,
    model: PathBuf,
    model_sha256: String,
    frozen_operators: String,
    placement: Placement,
    profile_prefix: PathBuf,
}

impl SessionContext {
    fn new(lens: &'static str, model: &Path, placement: Placement) -> Result<Self, WardError> {
        let mut context = Self {
            lens,
            model: model.to_path_buf(),
            model_sha256: "unavailable".to_string(),
            frozen_operators: "unavailable".to_string(),
            placement,
            profile_prefix: profiling_file_path(lens),
        };
        if !model.is_file() {
            return Err(context.error("model_validation", "model path is not a regular file"));
        }
        let file = File::open(model).map_err(|error| context.error("frozen_graph_open", error))?;
        let map = unsafe { Mmap::map(&file) }
            .map_err(|error| context.error("frozen_graph_map", error))?;
        if map.is_empty() {
            return Err(context.error("frozen_graph_validation", "frozen ONNX graph is empty"));
        }
        context.model_sha256 = format!("{:x}", Sha256::digest(&map[..]));
        context.frozen_operators = frozen_operator_inventory(&map)
            .map_err(|error| context.error("frozen_graph_operator_inventory", error))?;
        Ok(context)
    }

    fn error(&self, stage: &'static str, reason: impl ToString) -> WardError {
        let reason = reason.to_string();
        eprintln!(
            "CALYX_WARD_ONNX phase=failure lens={} stage={} model={} model_sha256={} provider={} device={} frozen_operators={} reason={} remediation={}",
            self.lens,
            stage,
            self.model.display(),
            self.model_sha256,
            self.placement.provider(),
            self.placement.device(),
            self.frozen_operators,
            reason,
            self.placement.remediation(),
        );
        WardError::Onnx {
            lens: self.lens,
            stage,
            model: self.model.clone(),
            model_sha256: self.model_sha256.clone(),
            frozen_operators: self.frozen_operators.clone(),
            provider: self.placement.provider(),
            device: self.placement.device(),
            reason,
            remediation: self.placement.remediation(),
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
    Attested(RuntimeExecutionAttestation),
    Failed(WardError),
}

/// Exact committed ORT session plus runtime placement evidence.
pub(crate) struct ManagedWardOnnxSession {
    session: Mutex<Session>,
    context: SessionContext,
    assignment: GraphAssignment,
    execution_state: Mutex<ExecutionState>,
}

impl ManagedWardOnnxSession {
    /// Accesses committed-session metadata. Productive inference must use
    /// [`Self::run_real_inference`] so the first run and profile finalization
    /// cannot race with another caller.
    pub(crate) fn inspect_session<T>(
        &self,
        action: impl FnOnce(&Session) -> Result<T, WardError>,
    ) -> Result<T, WardError> {
        let session = self.lock_session()?;
        action(&session)
    }

    /// Runs one real inference while holding the session through output host
    /// materialization and one-time profiling finalization. Callers return an
    /// owned, validated output from `action`; Ward never attests a borrowed or
    /// not-yet-materialized provider output.
    pub(crate) fn run_real_inference<T>(
        &self,
        action: impl FnOnce(&mut Session) -> Result<T, WardError>,
    ) -> Result<T, WardError> {
        let mut session = self.lock_session()?;
        self.ensure_usable()?;
        let output = action(&mut session)?;
        self.complete_first_inference(&mut session)?;
        Ok(output)
    }

    pub(crate) fn error(&self, stage: &'static str, reason: impl ToString) -> WardError {
        self.context.error(stage, reason)
    }

    pub(crate) const fn provider_policy(&self) -> &'static str {
        self.context.placement.provider()
    }

    /// Returns evidence only after this exact committed session completed a
    /// synchronous real inference, materialized its output on the host, and
    /// passed the independent ORT profiling readback.
    pub(crate) fn execution_attestation(
        &self,
    ) -> Result<Option<RuntimeExecutionAttestation>, WardError> {
        match &*self.lock_execution_state()? {
            ExecutionState::Pending => Ok(None),
            ExecutionState::Attested(attestation) => Ok(Some(attestation.clone())),
            ExecutionState::Failed(error) => Err(error.clone()),
        }
    }

    fn complete_first_inference(&self, session: &mut Session) -> Result<(), WardError> {
        let mut state = self.lock_execution_state()?;
        match &*state {
            ExecutionState::Attested(_) => return Ok(()),
            ExecutionState::Failed(error) => return Err(error.clone()),
            ExecutionState::Pending => {}
        }
        let result = self.profile_attestation(session);
        match result {
            Ok(attestation) => {
                eprintln!(
                    "CALYX_WARD_ONNX phase=first_real_inference_attested lens={} model={} model_sha256={} provider={} device={} total_nodes={} cpu_nodes={} evidence={}",
                    self.context.lens,
                    self.context.model.display(),
                    self.context.model_sha256,
                    attestation.provider,
                    attestation.device,
                    attestation.total_compute_nodes.unwrap_or(0),
                    attestation.cpu_compute_nodes.unwrap_or(0),
                    attestation.evidence,
                );
                *state = ExecutionState::Attested(attestation);
                Ok(())
            }
            Err(error) => {
                eprintln!(
                    "CALYX_WARD_ONNX phase=first_real_inference_attestation_failed lens={} code={} error={}",
                    self.context.lens,
                    error.code(),
                    error,
                );
                *state = ExecutionState::Failed(error.clone());
                Err(error)
            }
        }
    }

    fn profile_attestation(
        &self,
        session: &mut Session,
    ) -> Result<RuntimeExecutionAttestation, WardError> {
        // ORT `Session::run` is synchronous unless a caller explicitly sets
        // disable_synchronize_execution_providers. Ward never sets it. The
        // caller has also copied/pooled the returned tensor into owned host
        // data before this point, so end_profiling observes a quiescent run.
        let trace_path = session
            .end_profiling()
            .map_err(|error| self.error("first_inference_end_profiling", error))?;
        self.validate_profile_path(&trace_path)?;
        let trace = std::fs::read(&trace_path).map_err(|error| {
            self.error(
                "first_inference_profile_readback",
                format!("read {trace_path} failed: {error}"),
            )
        })?;
        let trace_sha256 = format!("{:x}", Sha256::digest(&trace));
        let profile = parse_profile_assignment(&trace)
            .map_err(|error| self.error("first_inference_profile_parse", error))?;
        validate_profile_assignment(&self.context, &profile)?;
        Ok(RuntimeExecutionAttestation {
            runtime: format!("ward-onnx-{}", self.context.lens),
            provider: format!(
                "api24={};profile={}",
                self.assignment.per_provider, profile.per_provider
            ),
            device: self.context.placement.device().to_string(),
            loader_dtype: None,
            compute_dtype: None,
            evidence: format!(
                "onnx_api24_committed_session+first_real_synchronous_host_materialized_inference_profile;model={};model_sha256={};provider_policy={};frozen_operators={};api24_total_nodes={};api24_cuda_nodes={};api24_cpu_nodes={};assigned_operators={};profile_total_nodes={};profile_cuda_nodes={};profile_cpu_nodes={};profile_operators={};profile_path={};profile_sha256={}",
                self.context.model.display(),
                self.context.model_sha256,
                self.context.placement.provider(),
                self.context.frozen_operators,
                self.assignment.total_nodes,
                self.assignment.cuda_nodes,
                self.assignment.cpu_nodes,
                self.assignment.per_provider_operators,
                profile.total_nodes,
                profile.cuda_nodes,
                profile.cpu_nodes,
                profile.per_provider_operators,
                trace_path,
                trace_sha256,
            ),
            total_compute_nodes: Some(self.assignment.total_nodes),
            cpu_compute_nodes: Some(self.assignment.cpu_nodes),
        })
    }

    fn validate_profile_path(&self, trace_path: &str) -> Result<(), WardError> {
        let observed = Path::new(trace_path);
        let expected_name = self
            .context
            .profile_prefix
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                self.error(
                    "first_inference_profile_path_validation",
                    "profiling prefix has no UTF-8 file name",
                )
            })?;
        let observed_name = observed
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                self.error(
                    "first_inference_profile_path_validation",
                    format!("returned profiling path {trace_path} has no UTF-8 file name"),
                )
            })?;
        if observed.parent() != self.context.profile_prefix.parent()
            || !observed_name.starts_with(expected_name)
            || !observed.is_file()
        {
            return Err(self.error(
                "first_inference_profile_path_validation",
                format!(
                    "ORT returned missing or unexpected profile path {trace_path}; expected prefix {}",
                    self.context.profile_prefix.display()
                ),
            ));
        }
        Ok(())
    }

    fn ensure_usable(&self) -> Result<(), WardError> {
        match &*self.lock_execution_state()? {
            ExecutionState::Failed(error) => Err(error.clone()),
            ExecutionState::Pending | ExecutionState::Attested(_) => Ok(()),
        }
    }

    fn lock_session(&self) -> Result<MutexGuard<'_, Session>, WardError> {
        self.session
            .lock()
            .map_err(|_| self.error("session_lock", "ORT session mutex poisoned"))
    }

    fn lock_execution_state(&self) -> Result<MutexGuard<'_, ExecutionState>, WardError> {
        self.execution_state.lock().map_err(|_| {
            self.error(
                "execution_attestation_state",
                "execution-attestation mutex poisoned",
            )
        })
    }
}

/// Builds a CUDA-only Ward session. Unsupported graph nodes fail at commit;
/// no construction or inference failure is retried on CPU.
pub(crate) fn build_cuda_session(
    lens: &'static str,
    model: &Path,
) -> Result<ManagedWardOnnxSession, WardError> {
    build_session(lens, model, Placement::Cuda)
}

/// Builds the separately selected, explicit CPU Ward session.
pub(crate) fn build_cpu_session(
    lens: &'static str,
    model: &Path,
) -> Result<ManagedWardOnnxSession, WardError> {
    build_session(lens, model, Placement::CpuExplicit)
}

fn build_session(
    lens: &'static str,
    model: &Path,
    placement: Placement,
) -> Result<ManagedWardOnnxSession, WardError> {
    let context = SessionContext::new(lens, model, placement)?;
    crate::ort_runtime::ensure_dynamic_ort()
        .map_err(|error| context.error("dynamic_runtime_validation", error))?;

    let mut builder = Session::builder()
        .map_err(|error| context.error("session_builder", error))?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|error| context.error("graph_optimization", error))?
        .with_execution_providers(execution_providers(placement))
        .map_err(|error| context.error("provider_registration", error))?;
    if placement == Placement::Cuda {
        builder = builder
            .with_disable_cpu_fallback()
            .map_err(|error| context.error("disable_cpu_fallback", error))?;
    }
    builder = builder
        .with_config_entry(GRAPH_ASSIGNMENT_CONFIG, "1")
        .map_err(|error| context.error("graph_assignment_recording", error))?
        .with_profiling(&context.profile_prefix)
        .map_err(|error| context.error("first_inference_profiling_enable", error))?;

    let session = builder
        .commit_from_file(model)
        .map_err(|error| context.error("model_commit", error))?;
    let assignment = read_graph_assignment(&session)
        .map_err(|error| context.error("api24_graph_assignment_readback", error))?;
    validate_graph_assignment(&context, &assignment)?;
    eprintln!(
        "CALYX_WARD_ONNX phase=api24_graph_assignment lens={} model={} model_sha256={} provider={} device={} total_nodes={} cuda_nodes={} cpu_nodes={} providers={} assigned_operators={} frozen_operators={}",
        context.lens,
        context.model.display(),
        context.model_sha256,
        context.placement.provider(),
        context.placement.device(),
        assignment.total_nodes,
        assignment.cuda_nodes,
        assignment.cpu_nodes,
        assignment.per_provider,
        assignment.per_provider_operators,
        context.frozen_operators,
    );

    Ok(ManagedWardOnnxSession {
        session: Mutex::new(session),
        context,
        assignment,
        execution_state: Mutex::new(ExecutionState::Pending),
    })
}

fn execution_providers(placement: Placement) -> Vec<ExecutionProviderDispatch> {
    match placement {
        Placement::Cuda => vec![
            ep::CUDA::default()
                .with_device_id(0)
                .with_arena_extend_strategy(ArenaExtendStrategy::SameAsRequested)
                .build()
                .error_on_failure(),
        ],
        Placement::CpuExplicit => vec![ep::CPU::default().build()],
    }
}

fn read_graph_assignment(session: &Session) -> Result<GraphAssignment, OrtError> {
    let mut subgraphs = ptr::null();
    let mut subgraph_count = 0usize;
    // ORT owns every returned assignment object for the session lifetime; this
    // function only reads them while `session` is borrowed.
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
        let provider_count = counts.entry(provider.clone()).or_default();
        *provider_count = provider_count
            .checked_add(node_count_u64)
            .ok_or_else(|| OrtError::new("assigned ONNX provider node count exceeds u64"))?;
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

    assignment_from_counts(counts, operators)
}

fn assignment_from_counts(
    counts: BTreeMap<String, u64>,
    operators: BTreeMap<String, BTreeSet<String>>,
) -> Result<GraphAssignment, OrtError> {
    let total_nodes = checked_count_sum(counts.values().copied())?;
    let cpu_nodes = checked_count_sum(
        counts
            .iter()
            .filter(|(provider, _)| provider_name_contains(provider, "CPU"))
            .map(|(_, count)| *count),
    )?;
    let cuda_nodes = checked_count_sum(
        counts
            .iter()
            .filter(|(provider, _)| provider_name_contains(provider, "CUDA"))
            .map(|(_, count)| *count),
    )?;
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

fn checked_count_sum(counts: impl IntoIterator<Item = u64>) -> Result<u64, OrtError> {
    counts.into_iter().try_fold(0u64, |total, count| {
        total
            .checked_add(count)
            .ok_or_else(|| OrtError::new("ONNX placement node count exceeds u64"))
    })
}

fn validate_graph_assignment(
    context: &SessionContext,
    assignment: &GraphAssignment,
) -> Result<(), WardError> {
    validate_exact_placement(context, "api24_graph_assignment_validation", assignment)
}

fn validate_profile_assignment(
    context: &SessionContext,
    assignment: &GraphAssignment,
) -> Result<(), WardError> {
    validate_exact_placement(context, "first_inference_profile_validation", assignment)
}

fn validate_exact_placement(
    context: &SessionContext,
    stage: &'static str,
    assignment: &GraphAssignment,
) -> Result<(), WardError> {
    if assignment.total_nodes == 0 {
        return Err(context.error(stage, "placement evidence reported zero compute nodes"));
    }
    match context.placement {
        Placement::Cuda
            if assignment.cpu_nodes != 0 || assignment.cuda_nodes != assignment.total_nodes =>
        {
            Err(context.error(
                stage,
                format!(
                    "expected every compute node on CUDA, observed cuda={}/{} cpu={} providers={} operators={}",
                    assignment.cuda_nodes,
                    assignment.total_nodes,
                    assignment.cpu_nodes,
                    assignment.per_provider,
                    assignment.per_provider_operators,
                ),
            ))
        }
        Placement::CpuExplicit if assignment.cpu_nodes != assignment.total_nodes => {
            Err(context.error(
                stage,
                format!(
                    "expected every compute node on explicit CPU, observed cpu={}/{} providers={} operators={}",
                    assignment.cpu_nodes,
                    assignment.total_nodes,
                    assignment.per_provider,
                    assignment.per_provider_operators,
                ),
            ))
        }
        _ => Ok(()),
    }
}

fn parse_profile_assignment(bytes: &[u8]) -> Result<GraphAssignment, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("ONNX profiling trace is not valid JSON: {error}"))?;
    let events = match &value {
        Value::Array(events) => events.as_slice(),
        Value::Object(map) => match map.get("traceEvents") {
            Some(Value::Array(events)) => events.as_slice(),
            _ => return Err("ONNX profiling trace object has no traceEvents array".to_string()),
        },
        _ => return Err("ONNX profiling trace is not an event array or traceEvents object".into()),
    };

    let mut kernel_counts = BTreeMap::<String, u64>::new();
    let mut all_counts = BTreeMap::<String, u64>::new();
    let mut kernel_operators = BTreeMap::<String, BTreeSet<String>>::new();
    let mut all_operators = BTreeMap::<String, BTreeSet<String>>::new();
    for event in events {
        let Some(event) = event.as_object() else {
            continue;
        };
        if event.get("cat").and_then(Value::as_str) != Some("Node") {
            continue;
        }
        let Some(args) = event.get("args").and_then(Value::as_object) else {
            continue;
        };
        let Some(provider) = args
            .get("provider")
            .and_then(Value::as_str)
            .filter(|provider| !provider.trim().is_empty())
        else {
            continue;
        };
        let operator = profile_operator(event, args);
        increment_profile_count(&mut all_counts, provider)?;
        if let Some(operator) = operator.clone() {
            all_operators
                .entry(provider.to_string())
                .or_default()
                .insert(operator);
        }
        if event
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| name.ends_with("_kernel_time"))
        {
            increment_profile_count(&mut kernel_counts, provider)?;
            if let Some(operator) = operator {
                kernel_operators
                    .entry(provider.to_string())
                    .or_default()
                    .insert(operator);
            }
        }
    }
    let (counts, operators) = if kernel_counts.is_empty() {
        (all_counts, all_operators)
    } else {
        (kernel_counts, kernel_operators)
    };
    assignment_from_counts(counts, operators).map_err(|error| error.to_string())
}

fn profile_operator(
    event: &serde_json::Map<String, Value>,
    args: &serde_json::Map<String, Value>,
) -> Option<String> {
    ["op_name", "op_type", "operator"]
        .into_iter()
        .find_map(|key| args.get(key).and_then(Value::as_str))
        .filter(|operator| !operator.trim().is_empty())
        .map(str::to_owned)
        .or_else(|| {
            event
                .get("name")
                .and_then(Value::as_str)
                .and_then(|name| name.strip_suffix("_kernel_time"))
                .filter(|operator| !operator.trim().is_empty())
                .map(str::to_owned)
        })
}

fn increment_profile_count(
    counts: &mut BTreeMap<String, u64>,
    provider: &str,
) -> Result<(), String> {
    let count = counts.entry(provider.to_string()).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| "profile compute-node count exceeds u64".to_string())?;
    Ok(())
}

fn provider_name_contains(provider: &str, expected: &str) -> bool {
    provider.to_ascii_uppercase().contains(expected)
}

fn assigned_string(
    call: impl FnOnce(*mut *const c_char) -> ort::sys::OrtStatusPtr,
) -> Result<String, OrtError> {
    let mut raw = ptr::null();
    status_result(call(&mut raw))?;
    if raw.is_null() {
        return Err(OrtError::new(
            "ONNX graph assignment returned a null string",
        ));
    }
    // API-24 documents this as an ORT-owned, NUL-terminated UTF-8 string.
    unsafe { CStr::from_ptr(raw) }
        .to_str()
        .map(str::to_owned)
        .map_err(|error| {
            OrtError::new(format!(
                "ONNX graph assignment string is not UTF-8: {error}"
            ))
        })
}

fn status_result(status: ort::sys::OrtStatusPtr) -> Result<(), OrtError> {
    // The ORT API transfers ownership of a non-null status to the caller.
    unsafe { OrtError::result_from_status(status) }
}

fn profiling_file_path(label: &str) -> PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let label = label
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    std::env::temp_dir().join(format!(
        "calyx_ward_onnx_profile_{}_{}_{sequence}",
        std::process::id(),
        label,
    ))
}

fn frozen_operator_inventory(bytes: &[u8]) -> Result<String, String> {
    let mut model = ProtoCursor::new(bytes);
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
) -> Result<(), String> {
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
) -> Result<(), String> {
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
) -> Result<(), String> {
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
    fn bytes(self, label: &str) -> Result<&'a [u8], String> {
        match self.value {
            ProtoValue::Bytes(bytes) => Ok(bytes),
            _ => Err(format!("{label} is not length-delimited")),
        }
    }

    fn string(self, label: &str) -> Result<&'a str, String> {
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

    fn next_field(&mut self) -> Result<Option<ProtoField<'a>>, String> {
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

    fn varint(&mut self) -> Result<u64, String> {
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

    fn advance(&mut self, length: usize) -> Result<(), String> {
        self.offset = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "protobuf field extends past end of input".to_string())?;
        Ok(())
    }
}
