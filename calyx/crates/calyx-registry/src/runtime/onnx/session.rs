use std::path::{Path, PathBuf};

use calyx_core::{CalyxError, Result};
use ort::session::Session;
use sha2::{Digest, Sha256};

use super::cpu_fallback_audit::{
    CommittedGraphAssignment, GRAPH_ASSIGNMENT_CONFIG, profiling_file_path,
    read_committed_graph_assignment,
};
use super::cuda_guard::CudaDropGuard;
use super::green_context::GreenContextHandle;
use super::placement_contract::{
    CudaPlacementContract, inspect_cuda_placement, optimized_graph_file_path,
};
use super::{OnnxProviderPolicy, config_invalid};

pub(super) const IO_BINDING_ENV: &str = "CALYX_ONNX_IO_BINDING";
pub(super) const REQUIRE_STATIC_BINDING_ENV: &str = "CALYX_ONNX_REQUIRE_STATIC_BINDING";
pub(super) const DISABLE_CPU_EP_FALLBACK_ENV: &str = "CALYX_ONNX_DISABLE_CPU_EP_FALLBACK";
const MAX_PROFILE_TRACE_BYTES: u64 = 64 * 1024 * 1024;

pub(super) struct OnnxProfileSnapshot {
    pub(super) final_path: PathBuf,
    pub(super) bytes: Vec<u8>,
}

pub(super) struct ManagedOnnxSession {
    session: Session,
    _green_context: Option<GreenContextHandle>,
    provider_policy: OnnxProviderPolicy,
    device_id: i32,
    execution_device: String,
    profile_prefix: Option<PathBuf>,
    profile_root: Option<calyx_onnx_runtime::ImmutableDirectoryRoot>,
    assignment: CommittedGraphAssignment,
    placement_contract: Option<CudaPlacementContract>,
    optimized_graph_root: Option<calyx_onnx_runtime::ImmutableDirectoryRoot>,
}

impl ManagedOnnxSession {
    pub(super) fn as_ref(&self) -> &Session {
        &self.session
    }

    pub(super) fn as_mut(&mut self) -> &mut Session {
        &mut self.session
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

    pub(super) fn placement_contract(&self) -> Option<&CudaPlacementContract> {
        self.placement_contract.as_ref()
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

    /// Reopen the exact optimized graph through the retained immutable root,
    /// rerun the static classifier, and require byte-for-byte contract
    /// equality before execution evidence is published.
    pub(super) fn revalidate_optimized_graph(&self, label: &str) -> Result<()> {
        let Some(contract) = &self.placement_contract else {
            if self.provider_policy == OnnxProviderPolicy::CpuExplicit {
                return Ok(());
            }
            return Err(CalyxError {
                code: "CALYX_ONNX_PLACEMENT_CONTRACT_MISSING",
                message: format!("CUDA ONNX session {label} retained no optimized-graph contract"),
                remediation: "discard the session and rebuild it through the quarantined CUDA constructor",
            });
        };
        let root = self.optimized_graph_root.as_ref().ok_or_else(|| CalyxError {
            code: "CALYX_ONNX_OPTIMIZED_GRAPH_ROOT_MISSING",
            message: format!(
                "CUDA ONNX session {label} retained a placement contract without its immutable optimized-graph root"
            ),
            remediation: "discard the session and rebuild it while retaining the exact optimized-graph directory handle",
        })?;
        let snapshot = calyx_onnx_runtime::snapshot_immutable_file(
            Path::new(&contract.optimized_graph_path),
            Some(root),
            contract.optimized_graph_bytes,
        )?;
        let observed_sha256 = format!("{:x}", Sha256::digest(&snapshot.bytes));
        let snapshot_bytes = u64::try_from(snapshot.bytes.len()).map_err(|_| CalyxError {
            code: "CALYX_ONNX_OPTIMIZED_GRAPH_SIZE_OVERFLOW",
            message: format!(
                "optimized graph snapshot length exceeds u64 during revalidation for {label}"
            ),
            remediation: "terminally discard the session and commission an optimized graph within the native u64 evidence contract",
        })?;
        if snapshot_bytes != contract.optimized_graph_bytes
            || observed_sha256 != contract.optimized_graph_sha256
            || snapshot.final_path.to_str() != Some(contract.optimized_graph_path.as_str())
        {
            return Err(CalyxError {
                code: "CALYX_ONNX_OPTIMIZED_GRAPH_DRIFT",
                message: format!(
                    "CUDA ONNX session {label} optimized graph drifted: expected path={} bytes={} sha256={}, observed path={} bytes={} sha256={observed_sha256}",
                    contract.optimized_graph_path,
                    contract.optimized_graph_bytes,
                    contract.optimized_graph_sha256,
                    snapshot.final_path.display(),
                    snapshot.bytes.len()
                ),
                remediation: "terminate the process, preserve the original and observed receipts, and recommission from immutable model bytes",
            });
        }
        let reclassified =
            inspect_cuda_placement(&self.assignment, &snapshot.final_path, &snapshot.bytes)?;
        if &reclassified != contract {
            return Err(CalyxError {
                code: "CALYX_ONNX_PLACEMENT_CONTRACT_DRIFT",
                message: format!(
                    "CUDA ONNX session {label} reclassified optimized graph to contract_sha256={} instead of retained {}",
                    reclassified.contract_sha256, contract.contract_sha256
                ),
                remediation: "terminate the process, preserve both classification receipts, and repair nondeterministic graph/assignment handling before retrying",
            });
        }
        Ok(())
    }

    /// End profiling after the first real CUDA forward and snapshot the exact
    /// trace through one immutable handle under the retained profile root.
    pub(super) fn finish_profile_snapshot(&mut self, label: &str) -> Result<OnnxProfileSnapshot> {
        let prefix = self.profile_prefix.as_ref().ok_or_else(|| CalyxError {
            code: "CALYX_ONNX_PROFILE_NOT_ENABLED",
            message: format!(
                "CUDA ONNX session {label} has no mandatory first-forward profiling prefix"
            ),
            remediation: "rebuild the CUDA session through the mandatory generic ONNX constructor; do not admit a session without first-forward placement evidence",
        })?;
        let root = self.profile_root.as_ref().ok_or_else(|| CalyxError {
            code: "CALYX_ONNX_PROFILE_ROOT_MISSING",
            message: format!(
                "CUDA ONNX session {label} did not retain its profiling directory identity"
            ),
            remediation: "rebuild the CUDA session through the mandatory generic ONNX constructor and retain the profiling root until first-forward readback completes",
        })?;
        let trace_path = self.session.end_profiling().map_err(|error| CalyxError {
            code: "CALYX_ONNX_PROFILE_FINALIZE_FAILED",
            message: format!("end first-forward ONNX profiling for {label} failed: {error}"),
            remediation: "preserve the pinned ONNX Runtime logs and retry in a new process; never reuse a session whose placement profile could not be finalized",
        })?;
        let snapshot = calyx_onnx_runtime::snapshot_immutable_file(
            Path::new(&trace_path),
            Some(root),
            MAX_PROFILE_TRACE_BYTES,
        )?;
        let expected_name = prefix
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| CalyxError {
                code: "CALYX_ONNX_PROFILE_PATH_INVALID",
                message: format!(
                    "mandatory ONNX profiling prefix {} has no UTF-8 file name",
                    prefix.display()
                ),
                remediation: "use a normal UTF-8 Windows temporary directory and rebuild the session",
            })?;
        let observed_name = snapshot
            .final_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| CalyxError {
                code: "CALYX_ONNX_PROFILE_PATH_INVALID",
                message: format!(
                    "returned ONNX profiling path {} has no UTF-8 file name",
                    snapshot.final_path.display()
                ),
                remediation: "preserve the returned path and pinned runtime logs, repair the profiling path contract, and retry in a new process",
            })?;
        if !observed_name.starts_with(expected_name) {
            return Err(CalyxError {
                code: "CALYX_ONNX_PROFILE_PATH_INVALID",
                message: format!(
                    "ORT returned profile path {trace_path}, resolved to {}, outside expected prefix {} under retained root {}",
                    snapshot.final_path.display(),
                    prefix.display(),
                    root.final_path().display()
                ),
                remediation: "preserve the unexpected trace path and pinned runtime logs, repair the profiling path contract, and retry in a new process",
            });
        }
        Ok(OnnxProfileSnapshot {
            final_path: snapshot.final_path,
            bytes: snapshot.bytes,
        })
    }
}

impl std::ops::Deref for ManagedOnnxSession {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl std::ops::DerefMut for ManagedOnnxSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session
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
    let profile_prefix =
        (policy == OnnxProviderPolicy::CudaFailLoud).then(|| profiling_file_path(label));
    let profile_root = profile_prefix
        .as_ref()
        .map(|prefix| {
            let parent = prefix.parent().ok_or_else(|| CalyxError {
                code: "CALYX_ONNX_PROFILE_PATH_INVALID",
                message: format!(
                    "mandatory ONNX profiling prefix {} has no parent directory",
                    prefix.display()
                ),
                remediation: "use a normal Windows temporary directory and rebuild the session",
            })?;
            calyx_onnx_runtime::open_immutable_directory(parent)
        })
        .transpose()?;
    if policy == OnnxProviderPolicy::CudaFailLoud && env_flag(DISABLE_CPU_EP_FALLBACK_ENV) {
        return Err(CalyxError {
            code: "CALYX_ONNX_CPU_FALLBACK_CONFIG_CONFLICT",
            message: format!(
                "{DISABLE_CPU_EP_FALLBACK_ENV}=1 conflicts with the CUDA placement classifier for {label}: ORT's switch also rejects intentional CPU-resident shape metadata"
            ),
            remediation: "unset CALYX_ONNX_DISABLE_CPU_EP_FALLBACK for CUDA sessions; substantive CPU compute remains categorically forbidden by optimized-graph, API-24, and first-profile attestation",
        });
    }
    let optimized_graph_path = (policy == OnnxProviderPolicy::CudaFailLoud)
        .then(|| optimized_graph_file_path(label))
        .transpose()?;
    let optimized_graph_root = optimized_graph_path
        .as_ref()
        .map(|path| {
            let parent = path.parent().ok_or_else(|| CalyxError {
                code: "CALYX_ONNX_OPTIMIZED_GRAPH_PATH_INVALID",
                message: format!(
                    "mandatory optimized graph path {} has no parent directory",
                    path.display()
                ),
                remediation: "repair the exclusive optimized-graph path allocator and retry in a new process",
            })?;
            calyx_onnx_runtime::open_immutable_directory(parent)
        })
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
    if let Some(profile_prefix) = &profile_prefix {
        builder = builder.with_profiling(profile_prefix).map_err(|err| {
            config_invalid(format!("ONNX profiling enable failed for {label}: {err}"))
        })?;
    }
    if let Some(optimized_graph_path) = &optimized_graph_path {
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
    let placement_contract = if let Some(optimized_graph_path) = optimized_graph_path.as_ref() {
        let root = optimized_graph_root.as_ref().ok_or_else(|| CalyxError {
            code: "CALYX_ONNX_OPTIMIZED_GRAPH_ROOT_MISSING",
            message: format!(
                "CUDA ONNX session {label} has an optimized path without its immutable root"
            ),
            remediation: "discard the quarantined session and repair optimized-graph root retention",
        })?;
        let observed_bytes = std::fs::metadata(optimized_graph_path)
            .map_err(|error| CalyxError {
                code: "CALYX_ONNX_OPTIMIZED_GRAPH_METADATA_FAILED",
                message: format!(
                    "read optimized graph metadata {} for {label} failed: {error}",
                    optimized_graph_path.display()
                ),
                remediation: "preserve the quarantined session diagnostics and repair optimized-model serialization before retrying",
            })?
            .len();
        if observed_bytes == 0 {
            return Err(CalyxError {
                code: "CALYX_ONNX_OPTIMIZED_GRAPH_EMPTY",
                message: format!(
                    "ORT serialized an empty optimized graph for {label} at {}",
                    optimized_graph_path.display()
                ),
                remediation: "preserve the quarantined session and runtime logs, then repair optimized-model serialization",
            });
        }
        let snapshot = calyx_onnx_runtime::snapshot_immutable_file(
            optimized_graph_path,
            Some(root),
            observed_bytes,
        )?;
        Some(inspect_cuda_placement(
            &assignment,
            &snapshot.final_path,
            &snapshot.bytes,
        )?)
    } else {
        validate_explicit_cpu_assignment(label, &assignment)?;
        None
    };
    let (session, green_context) = quarantine.into_inner();
    Ok(ManagedOnnxSession {
        session,
        _green_context: green_context,
        provider_policy: policy,
        device_id,
        execution_device,
        profile_prefix,
        profile_root,
        assignment,
        placement_contract,
        optimized_graph_root,
    })
}

fn validate_explicit_cpu_assignment(
    label: &str,
    assignment: &CommittedGraphAssignment,
) -> Result<()> {
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
