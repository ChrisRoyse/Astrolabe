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
//! after the first real run. CUDA sessions require every committed and executed
//! compute node to be assigned to CUDA. This is mandatory runtime evidence, not
//! optional telemetry.
//!
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, c_char};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use calyx_core::{CalyxError, Result};
use ort::session::Session;
use ort::{AsPointer, Error as OrtError};
use serde_json::Value;

pub(super) const CPU_FALLBACK_CODE: &str = "CALYX_ONNX_QUANT_CPU_FALLBACK";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AuditMode {
    Fail,
}

impl AuditMode {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
        }
    }
}

/// A unique, writable profiling trace path for a session. ORT appends its own
/// timestamp and `.json` suffix and returns the final path from `end_profiling`.
pub(super) fn profiling_file_path(label: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let slug: String = label
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    std::env::temp_dir().join(format!(
        "calyx_onnx_profile_{}_{}_{seq}",
        std::process::id(),
        slug
    ))
}

/// Exact provider assignment read from one committed ORT session through API
/// 24. ORT owns every returned subgraph and node for the borrowed session's
/// lifetime; this receipt copies only provider names, operator names, and
/// counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CommittedGraphAssignment {
    pub(super) total_nodes: u64,
    pub(super) cpu_nodes: u64,
    pub(super) cuda_nodes: u64,
    pub(super) per_provider: String,
    pub(super) per_provider_operators: String,
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
            let domain =
                assigned_string(|out| unsafe { (ort::api().EpAssignedNode_GetDomain)(node, out) })?;
            let operator = if domain.is_empty() {
                operator
            } else {
                format!("{domain}::{operator}")
            };
            operators
                .entry(provider.clone())
                .or_default()
                .insert(operator);
        }
    }

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
    Ok(CommittedGraphAssignment {
        total_nodes,
        cpu_nodes,
        cuda_nodes,
        per_provider,
        per_provider_operators,
    })
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

/// Compute-node counts keyed by ORT execution-provider name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ProviderNodeCounts {
    counts: BTreeMap<String, usize>,
}

impl ProviderNodeCounts {
    fn add(&mut self, provider: &str) {
        *self.counts.entry(provider.to_string()).or_default() += 1;
    }

    fn total(&self) -> usize {
        self.counts.values().copied().sum()
    }

    fn cpu_nodes(&self) -> usize {
        self.counts
            .iter()
            .filter(|(provider, _)| is_cpu_provider(provider))
            .map(|(_, count)| *count)
            .sum()
    }

    fn cuda_nodes(&self) -> usize {
        self.counts
            .iter()
            .filter(|(provider, _)| provider_name_is(provider, "CUDAExecutionProvider"))
            .map(|(_, count)| *count)
            .sum()
    }

    fn render(&self) -> String {
        if self.counts.is_empty() {
            return "none".to_string();
        }
        self.counts
            .iter()
            .map(|(provider, count)| format!("{provider}:{count}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn is_cpu_provider(provider: &str) -> bool {
    provider_name_is(provider, "CPUExecutionProvider")
}

/// Parse an ORT profiling trace into per-provider compute-node counts.
///
/// ORT emits three events per node (`_fence_before`, `_kernel_time`,
/// `_fence_after`); the `_kernel_time` record is the actual compute and carries
/// `args.provider`. Mandatory placement evidence counts only those compute
/// events and rejects malformed or incomplete node records; it never infers
/// execution from fence or other provider-bearing events.
pub(super) fn parse_profiling_nodes(trace_json: &str) -> Result<ProviderNodeCounts> {
    let value: Value = serde_json::from_str(trace_json).map_err(|err| CalyxError {
        code: "CALYX_ONNX_PROFILE_PARSE",
        message: format!("ONNX profiling trace is not valid JSON: {err}"),
        remediation: "preserve the malformed trace and pinned runtime logs, repair mandatory ONNX profiling output, and retry in a new process",
    })?;
    let events = match &value {
        Value::Array(events) => events.as_slice(),
        Value::Object(map) => match map.get("traceEvents") {
            Some(Value::Array(events)) => events.as_slice(),
            _ => {
                return Err(CalyxError {
                    code: "CALYX_ONNX_PROFILE_PARSE",
                    message: "ONNX profiling trace object has no traceEvents array".to_string(),
                    remediation: "expected an ORT profiling trace (JSON array or {traceEvents:[...]})",
                });
            }
        },
        _ => {
            return Err(CalyxError {
                code: "CALYX_ONNX_PROFILE_PARSE",
                message: "ONNX profiling trace is neither an array nor a traceEvents object"
                    .to_string(),
                remediation: "expected an ORT profiling trace (JSON array or {traceEvents:[...]})",
            });
        }
    };

    let mut kernel = ProviderNodeCounts::default();
    for (index, event) in events.iter().enumerate() {
        let obj = event.as_object().ok_or_else(|| CalyxError {
            code: "CALYX_ONNX_PROFILE_PARSE",
            message: format!("ONNX profiling event {index} is not an object"),
            remediation: "preserve the malformed trace and pinned runtime logs, repair mandatory ONNX profiling output, and retry in a new process",
        })?;
        let category = obj
            .get("cat")
            .and_then(Value::as_str)
            .filter(|category| !category.trim().is_empty())
            .ok_or_else(|| CalyxError {
                code: "CALYX_ONNX_PROFILE_PARSE",
                message: format!(
                    "ONNX profiling event {index} has no non-empty string category"
                ),
                remediation: "preserve the malformed trace and pinned runtime logs, repair mandatory ONNX profiling output, and retry in a new process",
            })?;
        if category != "Node" {
            continue;
        }
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| CalyxError {
                code: "CALYX_ONNX_PROFILE_PARSE",
                message: format!(
                    "ONNX Node profiling event {index} has no non-empty string name"
                ),
                remediation: "preserve the malformed trace and pinned runtime logs, repair mandatory ONNX profiling output, and retry in a new process",
            })?;
        let args = obj
            .get("args")
            .and_then(Value::as_object)
            .ok_or_else(|| CalyxError {
                code: "CALYX_ONNX_PROFILE_PARSE",
                message: format!("ONNX Node profiling event {index} has no args object"),
                remediation: "preserve the malformed trace and pinned runtime logs, repair mandatory ONNX profiling output, and retry in a new process",
            })?;
        if name.ends_with("_kernel_time") {
            let provider = args
                .get("provider")
                .and_then(Value::as_str)
                .filter(|provider| !provider.trim().is_empty())
                .ok_or_else(|| CalyxError {
                    code: "CALYX_ONNX_PROFILE_PARSE",
                    message: format!(
                        "ONNX kernel-time event {index} has no non-empty args.provider string"
                    ),
                    remediation: "preserve the malformed trace and pinned runtime logs, repair mandatory ONNX profiling output, and retry in a new process",
                })?;
            kernel.add(provider);
        } else if name.ends_with("_fence_before") || name.ends_with("_fence_after") {
            if let Some(provider) = args.get("provider")
                && provider
                    .as_str()
                    .filter(|provider| !provider.trim().is_empty())
                    .is_none()
            {
                return Err(CalyxError {
                    code: "CALYX_ONNX_PROFILE_PARSE",
                    message: format!(
                        "ONNX fence event {index} has a malformed args.provider value"
                    ),
                    remediation: "preserve the malformed trace and pinned runtime logs, repair mandatory ONNX profiling output, and retry in a new process",
                });
            }
        } else {
            return Err(CalyxError {
                code: "CALYX_ONNX_PROFILE_PARSE",
                message: format!(
                    "ONNX Node profiling event {index} has unsupported name {name:?}; expected *_kernel_time or a fence event"
                ),
                remediation: "preserve the unknown trace and pinned runtime logs, validate the exact ONNX Runtime profiling schema, and retry only after the placement parser recognizes every compute event",
            });
        }
    }
    if kernel.total() == 0 {
        return Err(CalyxError {
            code: "CALYX_ONNX_PROFILE_EMPTY",
            message: "ONNX first-forward profiling trace contains no *_kernel_time compute events"
                .to_string(),
            remediation: "preserve the incomplete trace and pinned runtime logs, repair mandatory first-forward profiling, and retry in a new process",
        });
    }
    Ok(kernel)
}

/// The verdict of a placement audit — the numbers that also go to telemetry.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct CpuFallbackAudit {
    pub(super) total_nodes: usize,
    pub(super) cpu_nodes: usize,
    pub(super) cuda_nodes: usize,
    pub(super) cpu_fraction: f64,
    pub(super) max_cpu_fraction: f64,
    pub(super) over_threshold: bool,
    pub(super) per_provider: String,
}

pub(super) fn evaluate_placement(
    counts: &ProviderNodeCounts,
    gpu_policy: bool,
    max_cpu_fraction: f64,
) -> CpuFallbackAudit {
    let total_nodes = counts.total();
    let cpu_nodes = counts.cpu_nodes();
    let cuda_nodes = counts.cuda_nodes();
    let cpu_fraction = if total_nodes == 0 {
        0.0
    } else {
        cpu_nodes as f64 / total_nodes as f64
    };
    // Strictly greater than the budget so an exact-threshold panel passes, and
    // a session with no measured nodes never trips (nothing to judge).
    let over_threshold = gpu_policy && total_nodes > 0 && cpu_fraction > max_cpu_fraction;
    CpuFallbackAudit {
        total_nodes,
        cpu_nodes,
        cuda_nodes,
        cpu_fraction,
        max_cpu_fraction,
        over_threshold,
        per_provider: counts.render(),
    }
}

/// Parse the trace, evaluate placement, emit telemetry, and — in `fail` mode —
/// refuse a GPU-policy session that is over the CPU-node fraction.
pub(super) fn audit_from_trace(
    label: &str,
    trace_json: &str,
    gpu_policy: bool,
    mode: AuditMode,
    max_cpu_fraction: f64,
) -> Result<CpuFallbackAudit> {
    let counts = parse_profiling_nodes(trace_json)?;
    let audit = evaluate_placement(&counts, gpu_policy, max_cpu_fraction);
    let verdict = if audit.over_threshold { "over" } else { "ok" };
    eprintln!(
        "CALYX_ONNX_RUNTIME phase=cpu_fallback_audit label={label} mode={} gpu_policy={gpu_policy} total_nodes={} cuda_nodes={} cpu_nodes={} cpu_fraction={:.4} max_cpu_fraction={:.4} providers={} verdict={verdict}",
        mode.as_str(),
        audit.total_nodes,
        audit.cuda_nodes,
        audit.cpu_nodes,
        audit.cpu_fraction,
        audit.max_cpu_fraction,
        audit.per_provider,
    );
    if audit.over_threshold {
        return Err(CalyxError {
            code: CPU_FALLBACK_CODE,
            message: format!(
                "{label} claims a GPU execution provider but ran {}/{} compute nodes ({:.1}%) on CPU (providers={}), exceeding the mandatory CPU-node fraction {:.4} — int8/quantized ONNX graphs have no CUDA kernels, so QLinearMatMul/QGemm/MatMulInteger fall back to CPU per node with a device<->host copy each way",
                audit.cpu_nodes,
                audit.total_nodes,
                audit.cpu_fraction * 100.0,
                audit.per_provider,
                audit.max_cpu_fraction,
            ),
            remediation: "use the CUDA-capable fp16/fp32 ONNX variant for a CUDA session; construct a separate explicit-CPU lens only when CPU execution is genuinely intended, and never retry this failed CUDA session on CPU",
        });
    }
    Ok(audit)
}
