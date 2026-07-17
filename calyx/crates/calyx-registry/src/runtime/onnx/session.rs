use std::path::{Path, PathBuf};

use calyx_core::{CalyxError, Result};
use ort::session::Session;

use super::cpu_fallback_audit::profiling_file_path;
use super::green_context::GreenContextHandle;
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
        )?;
        super::runtime_bundle::attest_after_model_constructor(
            self.provider_policy,
            self._green_context.as_ref(),
        )
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

pub(super) fn cpu_ep_fallback_disabled(policy: OnnxProviderPolicy) -> bool {
    matches!(policy, OnnxProviderPolicy::CudaFailLoud) || env_flag(DISABLE_CPU_EP_FALLBACK_ENV)
}

pub(super) fn configured_cuda_graphs() -> Result<bool> {
    super::cuda_graphs::configured_cuda_graphs()
}

/// Shared session build for Calyx-owned ONNX runtimes: device-aware provider
/// registration, mandatory CUDA profiling, and fail-closed CPU placement.
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
    let mut builder = Session::builder()
        .map_err(|err| config_invalid(format!("ONNX session builder failed: {err}")))?
        .with_intra_threads(1)
        .map_err(|err| config_invalid(format!("ONNX intra-thread config failed: {err}")))?
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
    if cpu_ep_fallback_disabled(policy) {
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
    let session = builder.commit_from_file(model_file).map_err(|err| {
        config_invalid(format!(
            "load ONNX model failed for {label} (policy={} device_id={device_id}): {err}",
            policy.as_str()
        ))
    })?;
    Ok(ManagedOnnxSession {
        session,
        _green_context: green_context,
        provider_policy: policy,
        device_id,
        execution_device,
        profile_prefix,
        profile_root,
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
