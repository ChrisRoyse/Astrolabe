use calyx_core::{CalyxError, Result};
use ort::session::Session;

use super::cpu_fallback_audit::{configured_audit_mode, profiling_file_path};
use super::green_context::GreenContextHandle;
use super::{OnnxProviderPolicy, config_invalid};

pub(super) const IO_BINDING_ENV: &str = "CALYX_ONNX_IO_BINDING";
pub(super) const REQUIRE_STATIC_BINDING_ENV: &str = "CALYX_ONNX_REQUIRE_STATIC_BINDING";
pub(super) const DISABLE_CPU_EP_FALLBACK_ENV: &str = "CALYX_ONNX_DISABLE_CPU_EP_FALLBACK";

pub(super) struct ManagedOnnxSession {
    session: Session,
    _green_context: Option<GreenContextHandle>,
    provider_policy: OnnxProviderPolicy,
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

    pub(super) fn synchronize_cuda_completion(&self, label: &str) -> Result<()> {
        super::green_context::synchronize_owned_stream(
            self._green_context.as_ref(),
            self.provider_policy,
            label,
        )
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
/// registration plus optional ORT-level refusal of node-level CPU placement.
pub(super) fn build_session(
    label: &str,
    model_file: &std::path::Path,
    policy: OnnxProviderPolicy,
) -> Result<ManagedOnnxSession> {
    let selected_device = super::runtime_bundle::selected_cuda_device(policy)?;
    let device_id = selected_device
        .as_ref()
        .map(|device| i32::try_from(device.ordinal))
        .transpose()
        .map_err(|_| config_invalid("attested CUDA Runtime ordinal exceeds the ORT device-id ABI"))?
        .unwrap_or(0);
    let green_context = super::green_context::create(label, policy, selected_device.as_ref())?;
    let compute_stream = green_context.as_ref().map(GreenContextHandle::stream_ptr);
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
    if configured_audit_mode()?.enabled() {
        builder = builder
            .with_profiling(profiling_file_path(label))
            .map_err(|err| {
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
