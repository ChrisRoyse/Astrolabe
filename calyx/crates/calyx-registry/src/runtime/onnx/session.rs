use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use calyx_core::{CalyxError, Result};
use ort::session::Session;

use super::cpu_fallback_audit::{
    CommittedGraphAssignment, GRAPH_ASSIGNMENT_CONFIG, read_committed_graph_assignment,
    validate_partition_receipt,
};
use super::cuda_guard::CudaDropGuard;
use super::evidence_artifact::{DurableOnnxArtifact, OnnxEvidenceTransaction};
use super::green_context::GreenContextHandle;
use super::placement_contract::{OptimizedGraphReceipt, inspect_optimized_graph};
use super::{OnnxProviderPolicy, config_invalid};

pub(super) const IO_BINDING_ENV: &str = "CALYX_ONNX_IO_BINDING";
pub(super) const REQUIRE_STATIC_BINDING_ENV: &str = "CALYX_ONNX_REQUIRE_STATIC_BINDING";
pub(super) const DISABLE_CPU_EP_FALLBACK_ENV: &str = "CALYX_ONNX_DISABLE_CPU_EP_FALLBACK";

pub(super) struct OnnxProfileSnapshot {
    pub(super) final_path: PathBuf,
    pub(super) bytes: Vec<u8>,
    pub(super) sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ManagedOnnxSessionId {
    process_id: u32,
    sequence: u64,
}

pub(super) struct ManagedOnnxSession {
    instance_id: ManagedOnnxSessionId,
    session: Session,
    _green_context: Option<GreenContextHandle>,
    provider_policy: OnnxProviderPolicy,
    device_id: i32,
    execution_device: String,
    assignment: CommittedGraphAssignment,
    optimized_graph_receipt: Option<OptimizedGraphReceipt>,
    evidence_transaction: Option<OnnxEvidenceTransaction>,
    optimized_graph_artifact: Option<DurableOnnxArtifact>,
    profile_artifact: Option<DurableOnnxArtifact>,
}

impl ManagedOnnxSession {
    pub(super) fn as_ref(&self) -> &Session {
        &self.session
    }

    pub(super) const fn instance_id(&self) -> ManagedOnnxSessionId {
        self.instance_id
    }

    /// The sole mutable ORT access path. A run plan must present the exact
    /// process-local identity captured from this session before any Run.
    pub(super) fn quarantined_session_mut(
        &mut self,
        expected: ManagedOnnxSessionId,
    ) -> Result<&mut Session> {
        if self.instance_id != expected {
            return Err(CalyxError {
                code: "CALYX_ONNX_SESSION_INSTANCE_MISMATCH",
                message: format!(
                    "ONNX run plan requested session identity {expected:?}, but the supplied managed session is {:?}",
                    self.instance_id
                ),
                remediation: "discard both objects and keep each run plan inseparably paired with the exact managed session that created it",
            });
        }
        Ok(&mut self.session)
    }

    pub(super) fn bound_stream(&self) -> Option<&GreenContextHandle> {
        self._green_context.as_ref()
    }

    pub(super) const fn provider_policy(&self) -> OnnxProviderPolicy {
        self.provider_policy
    }

    pub(super) fn execution_device(&self) -> &str {
        &self.execution_device
    }

    pub(super) const fn device_id(&self) -> i32 {
        self.device_id
    }

    pub(super) fn committed_assignment(&self) -> &CommittedGraphAssignment {
        &self.assignment
    }

    pub(super) fn optimized_graph_receipt(&self) -> Option<&OptimizedGraphReceipt> {
        self.optimized_graph_receipt.as_ref()
    }

    #[cfg(feature = "cuda")]
    pub(super) fn bound_stream_receipt(&self) -> Option<String> {
        self._green_context.as_ref().map(|stream| {
            format!(
                "stream_ptr={:p},driver_ordinal={},physical_identity={}",
                stream.stream_ptr(),
                stream.driver_ordinal(),
                stream.physical_identity()
            )
        })
    }

    #[cfg(not(feature = "cuda"))]
    pub(super) fn bound_stream_receipt(&self) -> Option<String> {
        None
    }

    pub(super) fn synchronize_and_attest_completion(&self, label: &str) -> Result<()> {
        super::green_context::synchronize_owned_stream(
            self._green_context.as_ref(),
            self.provider_policy,
            label,
        )
    }

    /// Reopen the exact durable optimized graph, reparse its post-fusion
    /// topology, and require byte-for-byte receipt equality before final
    /// placement classification.
    pub(super) fn revalidate_optimized_graph(&self, label: &str) -> Result<Vec<u8>> {
        let Some(receipt) = &self.optimized_graph_receipt else {
            if self.provider_policy == OnnxProviderPolicy::CpuExplicit {
                return Ok(Vec::new());
            }
            return Err(CalyxError {
                code: "CALYX_ONNX_OPTIMIZED_GRAPH_RECEIPT_MISSING",
                message: format!("CUDA ONNX session {label} retained no optimized-graph receipt"),
                remediation: "discard the session and rebuild it through the durable quarantined CUDA constructor",
            });
        };
        let artifact = self.optimized_graph_artifact.as_ref().ok_or_else(|| CalyxError {
            code: "CALYX_ONNX_OPTIMIZED_GRAPH_ARTIFACT_MISSING",
            message: format!(
                "CUDA ONNX session {label} retained a graph receipt without its durable content-addressed artifact"
            ),
            remediation: "discard the session and rebuild it while retaining the exact durable graph artifact",
        })?;
        let bytes = artifact.revalidate()?;
        let observed = inspect_optimized_graph(Path::new(&receipt.optimized_graph_path), &bytes)?;
        if &observed != receipt {
            return Err(CalyxError {
                code: "CALYX_ONNX_OPTIMIZED_GRAPH_DRIFT",
                message: format!(
                    "CUDA ONNX session {label} reparsed graph={} topology={} instead of retained graph={} topology={}",
                    observed.optimized_graph_sha256,
                    observed.final_graph_topology_sha256,
                    receipt.optimized_graph_sha256,
                    receipt.final_graph_topology_sha256
                ),
                remediation: "terminate the process, preserve both graph receipts, and repair nondeterministic or mutable graph handling before retrying",
            });
        }
        Ok(bytes)
    }

    /// End profiling after the first real CUDA forward and snapshot the exact
    /// trace into the durable content-addressed evidence store.
    pub(super) fn finish_profile_snapshot(&mut self, label: &str) -> Result<OnnxProfileSnapshot> {
        let trace_path = self.session.end_profiling().map_err(|error| CalyxError {
            code: "CALYX_ONNX_PROFILE_FINALIZE_FAILED",
            message: format!("end first-forward ONNX profiling for {label} failed: {error}"),
            remediation: "preserve the pinned ONNX Runtime logs and retry in a new process; never reuse a session whose placement profile could not be finalized",
        })?;
        let transaction = self.evidence_transaction.as_mut().ok_or_else(|| CalyxError {
            code: "CALYX_ONNX_EVIDENCE_TRANSACTION_MISSING",
            message: format!(
                "CUDA ONNX session {label} has no durable evidence transaction at profile finalization"
            ),
            remediation: "terminally discard the session and rebuild it through the durable CUDA constructor",
        })?;
        let artifact = transaction.publish_profile(Path::new(&trace_path))?;
        let snapshot = OnnxProfileSnapshot {
            final_path: artifact.final_path.clone(),
            bytes: artifact.bytes.clone(),
            sha256: artifact.sha256.clone(),
        };
        self.profile_artifact = Some(artifact);
        Ok(snapshot)
    }
}

impl std::ops::Deref for ManagedOnnxSession {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

/// CUDA Runtime-visible device ordinal from the environment; fails closed on garbage input.
pub(super) fn configured_cuda_device() -> Result<i32> {
    let ordinal = calyx_forge::configured_cuda_runtime_ordinal().map_err(|error| match error {
        calyx_forge::ForgeError::RuntimeBoundary {
            code,
            detail,
            remediation,
        } => CalyxError {
            code,
            message: detail,
            remediation,
        },
        other => CalyxError::lens_unreachable(format!(
            "shared CUDA Runtime device selection failed: {other}"
        )),
    })?;
    i32::try_from(ordinal).map_err(|_| CalyxError {
        code: "CALYX_ONNX_CUDA_DEVICE_INVALID",
        message: format!("shared CUDA Runtime-visible ordinal {ordinal} exceeds i32"),
        remediation: "set CALYX_CUDA_DEVICE to a valid CUDA Runtime-visible ordinal",
    })
}

pub(super) fn cpu_ep_fallback_session_config_enabled(policy: OnnxProviderPolicy) -> bool {
    policy == OnnxProviderPolicy::CpuExplicit && env_flag(DISABLE_CPU_EP_FALLBACK_ENV)
}

pub(super) fn configured_cuda_graphs() -> Result<bool> {
    super::cuda_graphs::configured_cuda_graphs()
}

/// Shared session build for Calyx-owned ONNX runtimes: device-aware provider
/// registration, mandatory CUDA profiling, and a classified, fail-closed
/// CUDA-compute/CPU-shape-metadata placement contract.
pub(super) fn build_session(
    label: &str,
    model_file: &std::path::Path,
    policy: OnnxProviderPolicy,
) -> Result<ManagedOnnxSession> {
    static NEXT_SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    let selected_device = super::runtime_bundle::selected_cuda_device(policy)?;
    let execution_device = selected_device
        .as_ref()
        .map(|device| device.frozen_execution_device())
        .unwrap_or_else(|| "cpu".to_string());
    let device_id = selected_device
        .as_ref()
        .map(|device| i32::try_from(device.ordinal))
        .transpose()
        .map_err(|_| config_invalid("attested CUDA Runtime ordinal exceeds the ORT device-id ABI"))?
        .unwrap_or(0);
    let green_context = super::green_context::create(label, policy, selected_device.as_ref())?;
    let compute_stream = green_context.as_ref().map(GreenContextHandle::stream_ptr);
    if policy == OnnxProviderPolicy::CudaFailLoud && env_flag(DISABLE_CPU_EP_FALLBACK_ENV) {
        return Err(CalyxError {
            code: "CALYX_ONNX_CPU_FALLBACK_CONFIG_CONFLICT",
            message: format!(
                "{DISABLE_CPU_EP_FALLBACK_ENV}=1 conflicts with the CUDA placement classifier for {label}: ORT's switch also rejects intentional CPU-resident shape metadata"
            ),
            remediation: "unset CALYX_ONNX_DISABLE_CPU_EP_FALLBACK for CUDA sessions; substantive CPU compute remains categorically forbidden by optimized-graph, API-24, and first-profile attestation",
        });
    }
    let mut evidence_transaction = (policy == OnnxProviderPolicy::CudaFailLoud)
        .then(|| OnnxEvidenceTransaction::begin(model_file, label))
        .transpose()?;
    let mut builder = Session::builder()
        .map_err(|err| config_invalid(format!("ONNX session builder failed: {err}")))?
        .with_intra_threads(1)
        .map_err(|err| config_invalid(format!("ONNX intra-thread config failed: {err}")))?
        .with_config_entry(GRAPH_ASSIGNMENT_CONFIG, "1")
        .map_err(|err| {
            config_invalid(format!(
                "ONNX graph-assignment recording config failed for {label}: {err}"
            ))
        })?
        .with_execution_providers(
            super::fastembed_runtime::execution_providers_for_attested_device(
                policy,
                selected_device.as_ref(),
                compute_stream,
            )?,
        )
        .map_err(|err| {
            config_invalid(format!(
                "ONNX provider config failed for {label} (policy={} device_id={device_id}): {err}",
                policy.as_str()
            ))
        })?;
    if cpu_ep_fallback_session_config_enabled(policy) {
        builder = builder.with_disable_cpu_fallback().map_err(|err| {
            config_invalid(format!(
                "ONNX disable_cpu_ep_fallback config failed for {label}: {err}"
            ))
        })?;
    }
    if let Some(profile_prefix) = evidence_transaction
        .as_ref()
        .map(OnnxEvidenceTransaction::profile_prefix)
    {
        builder = builder.with_profiling(profile_prefix).map_err(|err| {
            config_invalid(format!("ONNX profiling enable failed for {label}: {err}"))
        })?;
    }
    if let Some(optimized_graph_path) = evidence_transaction
        .as_ref()
        .map(OnnxEvidenceTransaction::optimized_graph_path)
    {
        builder = builder
            .with_optimized_model_path(optimized_graph_path)
            .map_err(|err| {
                config_invalid(format!(
                    "ONNX optimized-graph snapshot config failed for {label}: {err}"
                ))
            })?;
    }
    let session = builder.commit_from_file(model_file).map_err(|err| {
        config_invalid(format!(
            "load ONNX model failed for {label} (policy={} device_id={device_id}): {err}",
            policy.as_str()
        ))
    })?;
    let quarantine = CudaDropGuard::new((session, green_context), policy);
    let assignment = read_committed_graph_assignment(&quarantine.as_ref().0, label)?;
    let (optimized_graph_receipt, optimized_graph_artifact) =
        if let Some(transaction) = evidence_transaction.as_mut() {
            validate_partition_receipt(&assignment, label, true)?;
            let artifact = transaction.publish_optimized_graph()?;
            let receipt = inspect_optimized_graph(&artifact.final_path, &artifact.bytes)?;
            (Some(receipt), Some(artifact))
        } else {
            validate_explicit_cpu_assignment(label, &assignment)?;
            (None, None)
        };
    let sequence = NEXT_SESSION_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| CalyxError {
            code: "CALYX_ONNX_SESSION_ID_EXHAUSTED",
            message: "process-local managed ONNX session identity exhausted u64".to_string(),
            remediation: "restart the process and preserve the session-allocation diagnostics",
        })?;
    let (session, green_context) = quarantine.into_inner();
    Ok(ManagedOnnxSession {
        instance_id: ManagedOnnxSessionId {
            process_id: std::process::id(),
            sequence,
        },
        session,
        _green_context: green_context,
        provider_policy: policy,
        device_id,
        execution_device,
        assignment,
        optimized_graph_receipt,
        evidence_transaction,
        optimized_graph_artifact,
        profile_artifact: None,
    })
}

fn validate_explicit_cpu_assignment(
    label: &str,
    assignment: &CommittedGraphAssignment,
) -> Result<()> {
    validate_partition_receipt(assignment, label, false)?;
    let all_cpu = assignment.total_nodes > 0
        && assignment.cpu_nodes == assignment.total_nodes
        && assignment.cuda_nodes == 0
        && assignment
            .nodes
            .iter()
            .all(|node| node.provider == "CPUExecutionProvider");
    if all_cpu {
        return Ok(());
    }
    Err(CalyxError {
        code: "CALYX_ONNX_GRAPH_ASSIGNMENT_MISMATCH",
        message: format!(
            "explicit-CPU ONNX session {label} requires every committed node on CPUExecutionProvider, observed total={} cpu={} cuda={} providers={} nodes={}",
            assignment.total_nodes,
            assignment.cpu_nodes,
            assignment.cuda_nodes,
            assignment.per_provider,
            assignment.per_provider_nodes
        ),
        remediation: "repair the explicitly authorized CPU session so every committed node is assigned only to CPU before retrying",
    })
}

pub(super) fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|raw| {
            let raw = raw.trim();
            raw == "1" || raw.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}
