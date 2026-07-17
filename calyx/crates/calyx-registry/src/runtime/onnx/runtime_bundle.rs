//! Registry adapter for the process-global runtime owned by
//! `calyx-onnx-runtime`.

use std::path::PathBuf;

use calyx_core::{CalyxError, Result};
use calyx_onnx_runtime::OnnxRuntimePolicy;

use super::OnnxProviderPolicy;

pub use calyx_onnx_runtime::{
    OnnxCudaDeviceAttestation, OnnxLoadedModuleAttestation, OnnxRuntimeArtifactAttestation,
    OnnxRuntimeAttestation, OnnxRuntimeContractAttestation, current_runtime_attestation,
    expected_runtime_contract, initialize_pinned_cuda_runtime_boundary,
};

pub(super) fn ensure_runtime(policy: OnnxProviderPolicy) -> Result<PathBuf> {
    if policy == OnnxProviderPolicy::CpuExplicit {
        calyx_onnx_runtime::authorize_cpu_companion()?;
    }
    calyx_onnx_runtime::ensure_runtime(runtime_policy(policy), requested_ordinal(policy)?)
}

pub(super) fn authorize_execution_policy(policy: OnnxProviderPolicy) -> Result<()> {
    if policy == OnnxProviderPolicy::CpuExplicit {
        let authorization = calyx_onnx_runtime::authorize_cpu_companion()?;
        tracing::debug!(
            decision_code = authorization.decision_code(),
            requested_runtime_ordinal = authorization.requested_runtime_ordinal(),
            "obtained shared dual-zero authorization for explicit CPU FastEmbed construction"
        );
    }
    Ok(())
}

pub(super) fn selected_cuda_device(
    policy: OnnxProviderPolicy,
) -> Result<Option<OnnxCudaDeviceAttestation>> {
    if policy == OnnxProviderPolicy::CpuExplicit {
        calyx_onnx_runtime::authorize_cpu_companion()?;
    }
    calyx_onnx_runtime::selected_cuda_device(runtime_policy(policy), requested_ordinal(policy)?)
}

pub(super) fn attest_after_model_constructor(
    policy: OnnxProviderPolicy,
    bound_stream: Option<&super::green_context::GreenContextHandle>,
) -> Result<()> {
    if policy == OnnxProviderPolicy::CpuExplicit {
        if bound_stream.is_some() {
            return Err(CalyxError {
                code: "CALYX_ONNX_CPU_SESSION_HAS_CUDA_STREAM",
                message: "CPU-policy ONNX constructor retained a CUDA execution stream".into(),
                remediation: "construct CPU and CUDA companion lenses through distinct provider policies",
            });
        }
        ensure_runtime(policy)?;
        return Ok(());
    }

    ensure_runtime(policy)?;
    let receipt = current_runtime_attestation()?.ok_or_else(|| CalyxError {
        code: "CALYX_ONNX_RUNTIME_ATTESTATION_MISSING",
        message: "CUDA model construction completed without a live runtime attestation".into(),
        remediation: "terminate the process, preserve its logs, and restart from the pinned runtime bundle",
    })?;
    let selected = receipt.cuda_device.ok_or_else(|| CalyxError {
        code: "CALYX_ONNX_CUDA_DEVICE_ATTESTATION_MISSING",
        message: "CUDA model construction completed without a selected physical-device receipt"
            .into(),
        remediation: "terminate the process and restart from the pinned CUDA runtime boundary",
    })?;
    let stream = bound_stream.ok_or_else(|| CalyxError {
        code: "CALYX_ONNX_BOUND_STREAM_MISSING",
        message: "CUDA model construction did not retain an Astrolabe-owned execution stream".into(),
        remediation: "construct the CUDA EP with an attested compute stream and retain it for the full model lifetime",
    })?;
    super::green_context::attest_selected_stream(stream, &selected)
}

const fn runtime_policy(policy: OnnxProviderPolicy) -> OnnxRuntimePolicy {
    match policy {
        OnnxProviderPolicy::CudaFailLoud => OnnxRuntimePolicy::CudaFailLoud,
        OnnxProviderPolicy::CpuExplicit => OnnxRuntimePolicy::CpuExplicit,
    }
}

fn requested_ordinal(policy: OnnxProviderPolicy) -> Result<Option<u32>> {
    if policy == OnnxProviderPolicy::CpuExplicit {
        return Ok(None);
    }
    let ordinal = super::session::configured_cuda_device()?;
    u32::try_from(ordinal).map(Some).map_err(|_| CalyxError {
        code: "CALYX_ONNX_CUDA_DEVICE_INVALID",
        message: format!("configured CUDA Runtime ordinal {ordinal} is negative"),
        remediation: "set CALYX_CUDA_DEVICE to a CUDA Runtime-visible ordinal",
    })
}
