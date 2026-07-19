//! Per-provider node-placement audit for GPU-policy ONNX sessions (#1142).
//!
//! The CUDA execution provider has no kernels for int8-quantized ops
//! (`QLinearMatMul`, `QGemm`, `MatMulInteger`, `DynamicQuantizeLinear`,
//! `ConvInteger`, …). ORT silently places those nodes on the implicit CPU EP,
//! so a session that reports `provider=CudaFailLoud` can execute most of its
//! compute on the CPU with a device↔host copy per node — measured at
//! 130–250 ms/input, unusable for bulk encode. The `session_ready` telemetry
//! said "gpu" while execution was CPU-bound (#1142), and `#1136`'s I/O binding
//! cannot fix it — it addresses the copy path of GPU-executable graphs.
//!
//! Generic ONNX and ColBERT sessions inspect ORT's committed graph assignment
//! through API 24 before they become usable, then parse the profiling trace
//! after the first real run. CUDA sessions require every substantive compute
//! node on CUDA and authorize CPU nodes only through the separate bounded
//! shape-metadata contract. This is mandatory runtime evidence, not optional
//! telemetry.
//!
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, c_char};
use std::ptr;

use calyx_core::{CalyxError, Result};
use ort::session::Session;
use ort::{AsPointer, Error as OrtError};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::placement_contract::OptimizedGraphReceipt;

pub(super) const GRAPH_ASSIGNMENT_CONFIG: &str = "session.record_ep_graph_assignment_info";
pub(super) const API24_PARTITION_RECEIPT_SCHEMA: &str = "calyx.onnx.api24_partition_receipt.v2";

// The crates.io ort-sys 2.0.0-rc.12 binding omitted
// KernelInfo_GetOperatorSinceVersion from the API-24 OrtApi tail. That moved
// every later Rust field one pointer before its C ABI slot, so invoking
// Session_GetEpGraphAssignmentInfo actually invoked CreateEnvWithOptions.
// These values are independently measured from ONNX Runtime v1.24.3's
// official C header with native x86_64 offsetof/sizeof. Keep the whole tail
// pinned: a binding with missing, reordered, or extra fields must not build.
#[cfg(all(target_os = "windows", target_pointer_width = "64"))]
const _: () = {
    assert!(ort::sys::ORT_API_VERSION == 24);
    assert!(std::mem::size_of::<ort::sys::OrtApi>() == 3_320);
    assert!(std::mem::offset_of!(ort::sys::OrtApi, TensorTypeAndShape_HasShape) == 3_120);
    assert!(std::mem::offset_of!(ort::sys::OrtApi, KernelInfo_GetOperatorSinceVersion) == 3_152);
    assert!(std::mem::offset_of!(ort::sys::OrtApi, GetInteropApi) == 3_160);
    assert!(std::mem::offset_of!(ort::sys::OrtApi, CreateEnvWithOptions) == 3_248);
    assert!(std::mem::offset_of!(ort::sys::OrtApi, Session_GetEpGraphAssignmentInfo) == 3_256);
    assert!(
        std::mem::offset_of!(ort::sys::OrtApi, GetTensorElementTypeAndShapeDataReference) == 3_312
    );
};

/// Exact provider assignment read from one committed ORT session through API
/// 24. ORT owns every returned subgraph and node for the borrowed session's
/// lifetime. This is a pre-fusion partition receipt: its identities must never
/// be relabeled as post-fusion optimized-graph identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AssignedNode {
    pub(super) subgraph_index: u64,
    pub(super) node_index_in_subgraph: u64,
    pub(super) provider: String,
    pub(super) name: String,
    pub(super) domain: String,
    pub(super) operator: String,
}

impl AssignedNode {
    pub(super) fn qualified_operator(&self) -> String {
        if self.domain.is_empty() {
            self.operator.clone()
        } else {
            format!("{}::{}", self.domain, self.operator)
        }
    }

    pub(super) fn inventory_entry(&self) -> String {
        format!(
            "{}:{}:{}={}@{}",
            self.subgraph_index,
            self.node_index_in_subgraph,
            self.name,
            self.qualified_operator(),
            self.provider
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CommittedGraphAssignment {
    pub(super) schema: &'static str,
    pub(super) subgraph_count: u64,
    pub(super) total_nodes: u64,
    pub(super) cpu_nodes: u64,
    pub(super) cuda_nodes: u64,
    pub(super) partition_sha256: String,
    pub(super) per_provider: String,
    pub(super) per_provider_operators: String,
    pub(super) per_provider_nodes: String,
    pub(super) nodes: Vec<AssignedNode>,
}

pub(super) fn read_committed_graph_assignment(
    session: &Session,
    label: &str,
) -> Result<CommittedGraphAssignment> {
    read_graph_assignment(session).map_err(|error| CalyxError {
        code: "CALYX_ONNX_GRAPH_ASSIGNMENT_READBACK",
        message: format!(
            "read committed-session ONNX API-24 graph assignment for {label} failed: {error}"
        ),
        remediation: "preserve the exact model and pinned ONNX Runtime logs, repair the committed-session provider assignment readback, and retry in a new process",
    })
}

pub(super) fn validate_partition_receipt(
    assignment: &CommittedGraphAssignment,
    label: &str,
    require_cuda: bool,
) -> Result<()> {
    let inventory_count = u64::try_from(assignment.nodes.len()).map_err(|_| CalyxError {
        code: "CALYX_ONNX_API24_PARTITION_INVALID",
        message: format!("API-24 partition inventory for {label} exceeds u64"),
        remediation: "repair the exact API-24 reader before admitting the session",
    })?;
    let counted_cuda = u64::try_from(
        assignment
            .nodes
            .iter()
            .filter(|node| node.provider == "CUDAExecutionProvider")
            .count(),
    )
    .map_err(|_| partition_invalid(label, "CUDA node count exceeds u64"))?;
    let counted_cpu = u64::try_from(
        assignment
            .nodes
            .iter()
            .filter(|node| node.provider == "CPUExecutionProvider")
            .count(),
    )
    .map_err(|_| partition_invalid(label, "CPU node count exceeds u64"))?;
    if assignment.schema != API24_PARTITION_RECEIPT_SCHEMA
        || assignment.subgraph_count == 0
        || assignment.total_nodes == 0
        || inventory_count != assignment.total_nodes
    {
        return Err(partition_invalid(
            label,
            format!(
                "schema={} subgraphs={} total={} inventory={} providers={} assigned_operators={} assigned_nodes={} partition_sha256={}",
                assignment.schema,
                assignment.subgraph_count,
                assignment.total_nodes,
                inventory_count,
                assignment.per_provider,
                assignment.per_provider_operators,
                assignment.per_provider_nodes,
                assignment.partition_sha256
            ),
        ));
    }
    let unknown_nodes = assignment
        .nodes
        .iter()
        .filter(|node| {
            !matches!(
                node.provider.as_str(),
                "CUDAExecutionProvider" | "CPUExecutionProvider"
            )
        })
        .map(AssignedNode::inventory_entry)
        .collect::<Vec<_>>();
    if !unknown_nodes.is_empty() {
        return Err(CalyxError {
            code: "CALYX_ONNX_PROVIDER_UNKNOWN",
            message: format!(
                "API-24 partition receipt for {label} contains unknown provider assignments: {}; providers={} assigned_operators={} partition_sha256={}",
                unknown_nodes.join(","),
                assignment.per_provider,
                assignment.per_provider_operators,
                assignment.partition_sha256
            ),
            remediation: "preserve the exact API-24 node inventory, commission only explicit CPU/CUDA provider placement, and retry in a new process",
        });
    }
    if counted_cuda != assignment.cuda_nodes
        || counted_cpu != assignment.cpu_nodes
        || counted_cuda
            .checked_add(counted_cpu)
            .is_none_or(|count| count != assignment.total_nodes)
    {
        return Err(partition_invalid(
            label,
            format!(
                "reported cuda={} cpu={} but exact inventory re-counted cuda={counted_cuda} cpu={counted_cpu}; total={} providers={} assigned_operators={} assigned_nodes={} partition_sha256={}",
                assignment.cuda_nodes,
                assignment.cpu_nodes,
                assignment.total_nodes,
                assignment.per_provider,
                assignment.per_provider_operators,
                assignment.per_provider_nodes,
                assignment.partition_sha256
            ),
        ));
    }
    if require_cuda && assignment.cuda_nodes == 0 {
        return Err(CalyxError {
            code: "CALYX_ONNX_CUDA_COMPUTE_MISSING",
            message: format!(
                "CUDA-policy API-24 partition for {label} contains no CUDA compute: total={} cuda={} cpu={} providers={} assigned_operators={} assigned_nodes={} partition_sha256={}",
                assignment.total_nodes,
                assignment.cuda_nodes,
                assignment.cpu_nodes,
                assignment.per_provider,
                assignment.per_provider_operators,
                assignment.per_provider_nodes,
                assignment.partition_sha256
            ),
            remediation: "commission a graph with real CUDAExecutionProvider content compute; never relabel an all-CPU graph as CUDA or retry through CPU fallback",
        });
    }
    if !require_cuda && assignment.cpu_nodes != assignment.total_nodes {
        return Err(CalyxError {
            code: "CALYX_ONNX_EXPLICIT_CPU_COMPUTE_MISMATCH",
            message: format!(
                "explicit-CPU API-24 partition for {label} is not entirely CPU: total={} cuda={} cpu={} providers={} assigned_operators={} assigned_nodes={} partition_sha256={}",
                assignment.total_nodes,
                assignment.cuda_nodes,
                assignment.cpu_nodes,
                assignment.per_provider,
                assignment.per_provider_operators,
                assignment.per_provider_nodes,
                assignment.partition_sha256
            ),
            remediation: "commission an explicit CPU-only session or use the fail-loud CUDA policy; never mix the two execution contracts",
        });
    }
    let mut names = BTreeSet::new();
    let mut expected_subgraph = 0u64;
    let mut expected_node = 0u64;
    for (position, node) in assignment.nodes.iter().enumerate() {
        if node.subgraph_index != expected_subgraph
            || node.node_index_in_subgraph != expected_node
            || node.name.trim().is_empty()
            || node.name.trim() != node.name
            || !names.insert(node.name.as_str())
            || node.operator.trim().is_empty()
            || node.operator.trim() != node.operator
            || node.domain.trim() != node.domain
            || !matches!(
                node.provider.as_str(),
                "CUDAExecutionProvider" | "CPUExecutionProvider"
            )
        {
            return Err(partition_invalid(
                label,
                format!(
                    "noncanonical node at observed subgraph={} node={}: expected subgraph={expected_subgraph} node={expected_node}, provider={:?} name={:?} domain={:?} operator={:?}",
                    node.subgraph_index,
                    node.node_index_in_subgraph,
                    node.provider,
                    node.name,
                    node.domain,
                    node.operator
                ),
            ));
        }
        expected_node = expected_node
            .checked_add(1)
            .ok_or_else(|| partition_invalid(label, "node ordinal exceeds u64"))?;
        let next = position
            .checked_add(1)
            .and_then(|position| assignment.nodes.get(position));
        if next.is_some_and(|next| next.subgraph_index != node.subgraph_index) {
            expected_subgraph = expected_subgraph
                .checked_add(1)
                .ok_or_else(|| partition_invalid(label, "subgraph ordinal exceeds u64"))?;
            expected_node = 0;
        }
    }
    if expected_subgraph
        .checked_add(1)
        .is_none_or(|count| count != assignment.subgraph_count)
    {
        return Err(partition_invalid(
            label,
            format!(
                "observed subgraph ordinal terminates at {expected_subgraph}, receipt reports {} subgraphs",
                assignment.subgraph_count
            ),
        ));
    }
    let expected_hash = hash_partition_receipt(assignment.subgraph_count, &assignment.nodes)
        .map_err(|error| partition_invalid(label, error))?;
    if expected_hash != assignment.partition_sha256 {
        return Err(partition_invalid(
            label,
            format!(
                "partition SHA-256 mismatch: expected {expected_hash}, observed {}",
                assignment.partition_sha256
            ),
        ));
    }
    Ok(())
}

fn partition_invalid(label: &str, reason: impl ToString) -> CalyxError {
    CalyxError {
        code: "CALYX_ONNX_API24_PARTITION_INVALID",
        message: format!(
            "API-24 partition receipt for {label} is invalid: {}",
            reason.to_string()
        ),
        remediation: "preserve the exact API-24 receipt, repair its canonical pre-fusion partition readback, and retry in a new process",
    }
}

fn read_graph_assignment(
    session: &Session,
) -> std::result::Result<CommittedGraphAssignment, OrtError> {
    let mut subgraphs = ptr::null();
    let mut subgraph_count = 0usize;
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
    validate_pointer_array_len(subgraph_count, "subgraph")?;
    let subgraphs = if subgraph_count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(subgraphs, subgraph_count) }
    };

    let mut counts = BTreeMap::<String, u64>::new();
    let mut operators = BTreeMap::<String, BTreeSet<String>>::new();
    let mut assigned_nodes = Vec::new();
    let mut assigned_node_names = BTreeSet::new();
    for (subgraph_index, &subgraph) in subgraphs.iter().enumerate() {
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
        if node_count == 0 {
            return Err(OrtError::new(format!(
                "EpAssignedSubgraph_GetNodes returned an empty assignment for provider {provider}"
            )));
        }
        validate_pointer_array_len(node_count, "node")?;
        let node_count = u64::try_from(node_count)
            .map_err(|_| OrtError::new("assigned ONNX node count exceeds u64"))?;
        let provider_count = counts.entry(provider.clone()).or_default();
        *provider_count = provider_count
            .checked_add(node_count)
            .ok_or_else(|| OrtError::new("assigned ONNX provider node count exceeds u64"))?;

        let nodes = if node_count == 0 {
            &[]
        } else {
            unsafe {
                std::slice::from_raw_parts(
                    nodes,
                    usize::try_from(node_count)
                        .map_err(|_| OrtError::new("assigned ONNX node count exceeds usize"))?,
                )
            }
        };
        let subgraph_index = u64::try_from(subgraph_index)
            .map_err(|_| OrtError::new("assigned ONNX subgraph index exceeds u64"))?;
        for (node_index_in_subgraph, &node) in nodes.iter().enumerate() {
            if node.is_null() {
                return Err(OrtError::new(
                    "EpAssignedSubgraph_GetNodes returned a null node",
                ));
            }
            let name =
                assigned_string(|out| unsafe { (ort::api().EpAssignedNode_GetName)(node, out) })?;
            if name.trim().is_empty() || name.trim() != name {
                return Err(OrtError::new(
                    "EpAssignedNode_GetName returned an empty or noncanonical node name",
                ));
            }
            if !assigned_node_names.insert(name.clone()) {
                return Err(OrtError::new(format!(
                    "ONNX graph assignment contains duplicate node name {name:?}"
                )));
            }
            let operator = assigned_string(|out| unsafe {
                (ort::api().EpAssignedNode_GetOperatorType)(node, out)
            })?;
            if operator.trim().is_empty() {
                return Err(OrtError::new(
                    "EpAssignedNode_GetOperatorType returned an empty operator",
                ));
            }
            let domain =
                assigned_string(|out| unsafe { (ort::api().EpAssignedNode_GetDomain)(node, out) })?;
            let qualified_operator = if domain.is_empty() {
                operator.clone()
            } else {
                format!("{domain}::{operator}")
            };
            operators
                .entry(provider.clone())
                .or_default()
                .insert(qualified_operator);
            assigned_nodes.push(AssignedNode {
                subgraph_index,
                node_index_in_subgraph: u64::try_from(node_index_in_subgraph)
                    .map_err(|_| OrtError::new("assigned ONNX node index exceeds u64"))?,
                provider: provider.clone(),
                name,
                domain,
                operator,
            });
        }
    }
    assigned_nodes.sort_by_key(|node| (node.subgraph_index, node.node_index_in_subgraph));

    let checked_sum = |values: Vec<u64>, label: &'static str| {
        values.into_iter().try_fold(0u64, |sum, value| {
            sum.checked_add(value)
                .ok_or_else(|| OrtError::new(format!("assigned ONNX {label} count exceeds u64")))
        })
    };
    let total_nodes = checked_sum(counts.values().copied().collect(), "total node")?;
    let cpu_nodes = checked_sum(
        counts
            .iter()
            .filter(|(provider, _)| provider_name_is(provider, "CPUExecutionProvider"))
            .map(|(_, count)| *count)
            .collect(),
        "CPU node",
    )?;
    let cuda_nodes = checked_sum(
        counts
            .iter()
            .filter(|(provider, _)| provider_name_is(provider, "CUDAExecutionProvider"))
            .map(|(_, count)| *count)
            .collect(),
        "CUDA node",
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
    let mut provider_nodes = BTreeMap::<String, Vec<String>>::new();
    for node in &assigned_nodes {
        provider_nodes
            .entry(node.provider.clone())
            .or_default()
            .push(node.inventory_entry());
    }
    let per_provider_nodes = provider_nodes
        .into_iter()
        .map(|(provider, nodes)| format!("{provider}:[{}]", nodes.join(",")))
        .collect::<Vec<_>>()
        .join(";");
    let subgraph_count = u64::try_from(subgraph_count)
        .map_err(|_| OrtError::new("assigned ONNX subgraph count exceeds u64"))?;
    let partition_sha256 = hash_partition_receipt(subgraph_count, &assigned_nodes)?;
    Ok(CommittedGraphAssignment {
        schema: API24_PARTITION_RECEIPT_SCHEMA,
        subgraph_count,
        total_nodes,
        cpu_nodes,
        cuda_nodes,
        partition_sha256,
        per_provider,
        per_provider_operators,
        per_provider_nodes,
        nodes: assigned_nodes,
    })
}

fn hash_partition_receipt(
    subgraph_count: u64,
    nodes: &[AssignedNode],
) -> std::result::Result<String, OrtError> {
    let mut hash = Sha256::new();
    update_length_delimited_hash(&mut hash, API24_PARTITION_RECEIPT_SCHEMA.as_bytes())?;
    update_length_delimited_hash(&mut hash, &subgraph_count.to_be_bytes())?;
    for node in nodes {
        update_length_delimited_hash(&mut hash, &node.subgraph_index.to_be_bytes())?;
        update_length_delimited_hash(&mut hash, &node.node_index_in_subgraph.to_be_bytes())?;
        update_length_delimited_hash(&mut hash, node.provider.as_bytes())?;
        update_length_delimited_hash(&mut hash, node.name.as_bytes())?;
        update_length_delimited_hash(&mut hash, node.domain.as_bytes())?;
        update_length_delimited_hash(&mut hash, node.operator.as_bytes())?;
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn update_length_delimited_hash(
    hash: &mut Sha256,
    part: &[u8],
) -> std::result::Result<(), OrtError> {
    let length = u64::try_from(part.len())
        .map_err(|_| OrtError::new("API-24 partition receipt hash field exceeds u64 bytes"))?;
    hash.update(length.to_be_bytes());
    hash.update(part);
    Ok(())
}

fn provider_name_is(provider: &str, expected: &str) -> bool {
    provider == expected
}

fn validate_pointer_array_len(
    count: usize,
    label: &'static str,
) -> std::result::Result<(), OrtError> {
    if count > isize::MAX as usize / std::mem::size_of::<usize>() {
        return Err(OrtError::new(format!(
            "ONNX graph assignment {label} array exceeds the addressable slice length"
        )));
    }
    Ok(())
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProfiledNode {
    pub(super) provider: String,
    pub(super) name: String,
    pub(super) domain: String,
    pub(super) operator: String,
    pub(super) node_index: u64,
    pub(super) output_size: u64,
    pub(super) output_elements: u64,
    pub(super) output_dtypes: String,
}

impl ProfiledNode {
    pub(super) fn inventory_entry(&self) -> String {
        format!(
            "{}={}@{}#{};bytes={};elements={};dtypes={}",
            self.name,
            self.operator,
            self.provider,
            self.node_index,
            self.output_size,
            self.output_elements,
            self.output_dtypes
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProfiledGraphExecution {
    pub(super) total_nodes: u64,
    pub(super) cuda_compute_nodes: u64,
    pub(super) cpu_metadata_nodes: u64,
    pub(super) per_provider: String,
    pub(super) node_inventory: String,
    pub(super) nodes: Vec<ProfiledNode>,
}

/// Parse the first real ORT profile without discarding identity, then
/// reconcile every executed kernel one-to-one with the post-fusion optimized
/// graph. Provider roles are not classified here; the placement classifier
/// consumes this exact final-graph execution inventory in a separate phase.
pub(super) fn reconcile_profile_with_optimized_graph(
    label: &str,
    trace_json: &str,
    optimized: &OptimizedGraphReceipt,
) -> Result<ProfiledGraphExecution> {
    let value: Value = serde_json::from_str(trace_json).map_err(|error| {
        profile_error(format!(
            "ONNX profiling trace for {label} is not valid JSON: {error}"
        ))
    })?;
    let events = profile_events(&value)?;
    let expected = optimized
        .nodes
        .iter()
        .map(|node| (node.name.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let expected_total = usize::try_from(optimized.total_graph_nodes).map_err(|_| {
        profile_error(format!(
            "optimized graph {} total_graph_nodes={} exceeds usize",
            optimized.optimized_graph_sha256, optimized.total_graph_nodes
        ))
    })?;
    if expected.len() != expected_total {
        return Err(profile_error(format!(
            "optimized graph {} has total_graph_nodes={} but {} unique node identities",
            optimized.optimized_graph_sha256,
            optimized.total_graph_nodes,
            expected.len()
        )));
    }

    let execute_events = events
        .iter()
        .filter(|event| {
            event.as_object().is_some_and(|event| {
                event.get("cat").and_then(Value::as_str) == Some("Session")
                    && event.get("name").and_then(Value::as_str)
                        == Some("SequentialExecutor::Execute")
            })
        })
        .count();
    if execute_events != 1 {
        return Err(profile_error(format!(
            "first-inference profile for {label} contains {execute_events} SequentialExecutor::Execute events; exactly one real ORT Run is required for one-to-one final-graph placement proof"
        )));
    }

    let mut profiled_names = BTreeSet::new();
    let mut profiled_indices = BTreeSet::new();
    let mut nodes = Vec::new();
    for (event_index, event) in events.iter().enumerate() {
        let object = event.as_object().ok_or_else(|| {
            profile_error(format!(
                "ONNX profiling event {event_index} is not an object"
            ))
        })?;
        let category = required_event_string(object, "cat", event_index, "event")?;
        if category != "Node" {
            continue;
        }
        let event_name = required_event_string(object, "name", event_index, "Node event")?;
        let args = object
            .get("args")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                profile_error(format!(
                    "ONNX Node profiling event {event_index} has no args object"
                ))
            })?;
        if event_name.ends_with("_fence_before") || event_name.ends_with("_fence_after") {
            if let Some(provider) = args.get("provider")
                && provider
                    .as_str()
                    .filter(|provider| {
                        !provider.is_empty()
                            && provider.trim() == *provider
                            && matches!(*provider, "CUDAExecutionProvider" | "CPUExecutionProvider")
                    })
                    .is_none()
            {
                return Err(profile_error(format!(
                    "ONNX fence event {event_index} has malformed provider {provider}"
                )));
            }
            continue;
        }
        let Some(node_name) = event_name.strip_suffix("_kernel_time") else {
            return Err(profile_error(format!(
                "ONNX Node profiling event {event_index} has unsupported name {event_name:?}"
            )));
        };
        if node_name.trim().is_empty() || node_name.trim() != node_name {
            return Err(profile_error(format!(
                "ONNX kernel event {event_index} has empty or noncanonical node identity {node_name:?}"
            )));
        }
        if !profiled_names.insert(node_name.to_string()) {
            return Err(profile_error(format!(
                "ONNX first-forward profile executes node {node_name:?} more than once; the placement contract requires one control-flow-free execution per final graph node"
            )));
        }
        let operator = required_arg_string(args, "op_name", event_index)?;
        let provider = required_arg_string(args, "provider", event_index)?;
        if !matches!(provider, "CUDAExecutionProvider" | "CPUExecutionProvider") {
            return Err(CalyxError {
                code: "CALYX_ONNX_PROVIDER_UNKNOWN",
                message: format!(
                    "first real profile for {label} has kernel event index={event_index} node={node_name:?} operator={operator:?} on unknown provider={provider:?}; optimized_graph_path={} optimized_graph_sha256={}",
                    optimized.optimized_graph_path, optimized.optimized_graph_sha256
                ),
                remediation: "terminally discard the session, preserve the optimized graph and raw profile, and commission only exact CPUExecutionProvider/CUDAExecutionProvider placement",
            });
        }
        if matches!(operator, "Memcpy" | "MemcpyFromHost" | "MemcpyToHost") {
            return Err(CalyxError {
                code: "CALYX_ONNX_INTER_PROVIDER_MEMCPY",
                message: format!(
                    "first real profile for {label} executed forbidden transfer node {node_name:?} ({operator}) on {provider}"
                ),
                remediation: "use a graph whose substantive compute remains on CUDA and whose CPU shape metadata requires zero graph-internal transfer kernels",
            });
        }
        let node_index = parse_profile_u64(
            required_arg_string(args, "node_index", event_index)?,
            "node_index",
            event_index,
        )?;
        if !profiled_indices.insert(node_index) {
            return Err(profile_error(format!(
                "ONNX first-forward profile contains duplicate internal node_index {node_index}"
            )));
        }
        let output_size = parse_profile_u64(
            required_arg_string(args, "output_size", event_index)?,
            "output_size",
            event_index,
        )?;
        let input_type_shape = required_arg_string(args, "input_type_shape", event_index)?;
        parse_profile_type_shapes(input_type_shape, event_index, "input_type_shape")?;
        let output_type_shape = required_arg_string(args, "output_type_shape", event_index)?;
        let output_shapes =
            parse_profile_type_shapes(output_type_shape, event_index, "output_type_shape")?;
        if output_shapes.total_bytes != output_size {
            return Err(profile_error(format!(
                "ONNX kernel event {event_index} node {node_name:?} reports output_size={output_size} but output_type_shape accounts for {} bytes",
                output_shapes.total_bytes
            )));
        }

        let graph_node = expected.get(node_name).ok_or_else(|| {
            profile_error(format!(
                "ONNX first-forward profile contains node {node_name:?} ({operator}) on {provider} that is absent from optimized graph {}",
                optimized.optimized_graph_sha256
            ))
        })?;
        if graph_node.operator != operator {
            return Err(CalyxError {
                code: "CALYX_ONNX_FIRST_FORWARD_PLACEMENT_DRIFT",
                message: format!(
                    "profile node {node_name:?} executed operator {operator} on {provider}, but the post-fusion optimized graph records {}",
                    graph_node.qualified_operator()
                ),
                remediation: "terminally discard the session, preserve optimized-graph/profile bytes, and repair execution-plan drift before retrying",
            });
        }
        nodes.push(ProfiledNode {
            provider: provider.to_string(),
            name: node_name.to_string(),
            domain: graph_node.domain.clone(),
            operator: operator.to_string(),
            node_index,
            output_size,
            output_elements: output_shapes.total_elements,
            output_dtypes: output_shapes.dtypes,
        });
    }

    if nodes.is_empty() {
        return Err(profile_error(format!(
            "ONNX first-forward profile for {label} contains no *_kernel_time events"
        )));
    }
    let observed_names = nodes
        .iter()
        .map(|node| node.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected_names = expected.keys().copied().collect::<BTreeSet<_>>();
    if observed_names != expected_names {
        let missing = expected_names
            .difference(&observed_names)
            .copied()
            .collect::<Vec<_>>()
            .join(",");
        let unexpected = observed_names
            .difference(&expected_names)
            .copied()
            .collect::<Vec<_>>()
            .join(",");
        return Err(CalyxError {
            code: "CALYX_ONNX_FIRST_FORWARD_NODE_SET_MISMATCH",
            message: format!(
                "first real profile for {label} does not match committed graph: missing=[{missing}] unexpected=[{unexpected}]"
            ),
            remediation: "terminally discard the session, preserve all three receipts, and repair assignment/profile identity reconciliation before retrying",
        });
    }
    nodes.sort_by(|left, right| left.name.cmp(&right.name));
    let cuda_compute_nodes = u64::try_from(
        nodes
            .iter()
            .filter(|node| node.provider == "CUDAExecutionProvider")
            .count(),
    )
    .map_err(|_| profile_error("profile CUDA node count exceeds u64"))?;
    let cpu_metadata_nodes = u64::try_from(
        nodes
            .iter()
            .filter(|node| node.provider == "CPUExecutionProvider")
            .count(),
    )
    .map_err(|_| profile_error("profile CPU metadata node count exceeds u64"))?;
    let total_nodes = cuda_compute_nodes
        .checked_add(cpu_metadata_nodes)
        .ok_or_else(|| {
            profile_error("profile total node count exceeds the u64 evidence contract")
        })?;
    if total_nodes != optimized.total_graph_nodes {
        return Err(CalyxError {
            code: "CALYX_ONNX_FIRST_FORWARD_COUNT_MISMATCH",
            message: format!(
                "first real profile for {label} reports total={total_nodes} cuda_provider={cuda_compute_nodes} cpu_provider={cpu_metadata_nodes}, optimized graph reports total={}",
                optimized.total_graph_nodes
            ),
            remediation: "terminally discard the session and repair optimized-graph/profile reconciliation",
        });
    }
    let per_provider = if cpu_metadata_nodes == 0 {
        format!("CUDAExecutionProvider:{cuda_compute_nodes}")
    } else {
        format!(
            "CPUExecutionProvider:{cpu_metadata_nodes},CUDAExecutionProvider:{cuda_compute_nodes}"
        )
    };
    let node_inventory = nodes
        .iter()
        .map(ProfiledNode::inventory_entry)
        .collect::<Vec<_>>()
        .join(",");
    Ok(ProfiledGraphExecution {
        total_nodes,
        cuda_compute_nodes,
        cpu_metadata_nodes,
        per_provider,
        node_inventory,
        nodes,
    })
}

struct ProfileTypeShapes {
    total_elements: u64,
    total_bytes: u64,
    dtypes: String,
}

fn profile_events(value: &Value) -> Result<&[Value]> {
    match value {
        Value::Array(events) => Ok(events),
        Value::Object(map) => match map.get("traceEvents") {
            Some(Value::Array(events)) => Ok(events),
            _ => Err(profile_error(
                "ONNX profiling trace object has no traceEvents array",
            )),
        },
        _ => Err(profile_error(
            "ONNX profiling trace is neither an array nor a traceEvents object",
        )),
    }
}

fn required_event_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    event_index: usize,
    context: &str,
) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.trim() == *value)
        .ok_or_else(|| {
            profile_error(format!(
                "ONNX {context} {event_index} has no canonical string {key}"
            ))
        })
}

fn required_arg_string<'a>(
    args: &'a serde_json::Map<String, Value>,
    key: &str,
    event_index: usize,
) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.trim() == *value)
        .ok_or_else(|| {
            profile_error(format!(
                "ONNX kernel event {event_index} has no canonical args.{key} string"
            ))
        })
}

fn parse_profile_u64(raw: &str, field: &str, event_index: usize) -> Result<u64> {
    if raw.is_empty()
        || !raw.bytes().all(|byte| byte.is_ascii_digit())
        || (raw.len() > 1 && raw.starts_with('0'))
    {
        return Err(profile_error(format!(
            "ONNX kernel event {event_index} args.{field} is not canonical unsigned decimal: {raw:?}"
        )));
    }
    raw.parse::<u64>().map_err(|error| {
        profile_error(format!(
            "ONNX kernel event {event_index} args.{field} exceeds u64: {raw:?}: {error}"
        ))
    })
}

fn parse_profile_type_shapes(
    raw: &str,
    event_index: usize,
    field: &str,
) -> Result<ProfileTypeShapes> {
    let value: Value = serde_json::from_str(raw).map_err(|error| {
        profile_error(format!(
            "ONNX kernel event {event_index} args.{field} is not valid nested JSON: {error}"
        ))
    })?;
    let tensors = value.as_array().ok_or_else(|| {
        profile_error(format!(
            "ONNX kernel event {event_index} args.{field} is not an array"
        ))
    })?;
    let mut total_elements = 0u64;
    let mut total_bytes = 0u64;
    let mut dtype_names = BTreeSet::new();
    for (tensor_index, tensor) in tensors.iter().enumerate() {
        let object = tensor.as_object().filter(|object| object.len() == 1).ok_or_else(|| {
            profile_error(format!(
                "ONNX kernel event {event_index} args.{field}[{tensor_index}] is not a one-entry dtype/shape object"
            ))
        })?;
        let (dtype, dimensions) = object.iter().next().ok_or_else(|| {
            profile_error(format!(
                "ONNX kernel event {event_index} args.{field}[{tensor_index}] is empty"
            ))
        })?;
        if dtype.trim() != dtype || dtype.is_empty() {
            return Err(profile_error(format!(
                "ONNX kernel event {event_index} args.{field}[{tensor_index}] has noncanonical dtype {dtype:?}"
            )));
        }
        let bits_per_element = runtime_dtype_bits(dtype).ok_or_else(|| {
            profile_error(format!(
                "ONNX kernel event {event_index} args.{field}[{tensor_index}] has unsupported runtime dtype {dtype:?}"
            ))
        })?;
        let dimensions = dimensions.as_array().ok_or_else(|| {
            profile_error(format!(
                "ONNX kernel event {event_index} args.{field}[{tensor_index}] shape is not an array"
            ))
        })?;
        let elements = dimensions.iter().try_fold(1u64, |elements, dimension| {
            let dimension = dimension.as_u64().ok_or_else(|| {
                profile_error(format!(
                    "ONNX kernel event {event_index} args.{field}[{tensor_index}] has a non-u64 runtime dimension {dimension}"
                ))
            })?;
            elements.checked_mul(dimension).ok_or_else(|| {
                profile_error(format!(
                    "ONNX kernel event {event_index} args.{field}[{tensor_index}] element count exceeds u64"
                ))
            })
        })?;
        let tensor_bits = elements.checked_mul(bits_per_element).ok_or_else(|| {
            profile_error(format!(
                "ONNX kernel event {event_index} args.{field}[{tensor_index}] byte size exceeds u64"
            ))
        })?;
        let tensor_bytes = tensor_bits.checked_add(7).ok_or_else(|| {
            profile_error(format!(
                "ONNX kernel event {event_index} args.{field}[{tensor_index}] packed byte size exceeds u64"
            ))
        })? / 8;
        total_elements = total_elements.checked_add(elements).ok_or_else(|| {
            profile_error(format!(
                "ONNX kernel event {event_index} args.{field} element count exceeds u64"
            ))
        })?;
        total_bytes = total_bytes.checked_add(tensor_bytes).ok_or_else(|| {
            profile_error(format!(
                "ONNX kernel event {event_index} args.{field} byte size exceeds u64"
            ))
        })?;
        dtype_names.insert(dtype.clone());
    }
    let dtypes = dtype_names.iter().cloned().collect::<Vec<_>>().join(",");
    Ok(ProfileTypeShapes {
        total_elements,
        total_bytes,
        dtypes,
    })
}

fn runtime_dtype_bits(dtype: &str) -> Option<u64> {
    match dtype {
        "bool" | "int8" | "uint8" | "Float8E4M3FN" | "Float8E4M3FNUZ" | "Float8E5M2"
        | "Float8E5M2FNUZ" | "Float8E8M0" => Some(8),
        "int16" | "uint16" | "float16" | "bfloat16" => Some(16),
        "int32" | "uint32" | "float" => Some(32),
        "int64" | "uint64" | "double" | "complex64" => Some(64),
        "complex128" => Some(128),
        "Float4E2M1x2" | "Int4x2" | "UInt4x2" => Some(4),
        "Int2x4" | "UInt2x4" => Some(2),
        _ => None,
    }
}

fn profile_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_ONNX_PROFILE_PARSE",
        message: message.into(),
        remediation: "preserve the malformed trace, optimized graph, and API-24 assignment; repair exact first-forward profiling before retrying in a new process",
    }
}
