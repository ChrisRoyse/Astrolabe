use calyx_core::{CalyxError, Result};

use super::OnnxProviderPolicy;
#[cfg(feature = "cuda")]
use super::config_invalid;
use super::cuda_graphs::CUDA_GRAPHS_ENV;

pub(super) const GREEN_CONTEXT_SMS_ENV: &str = "CALYX_ONNX_GREEN_CONTEXT_SMS";

/// CUDA green contexts have no internal synchronization for concurrent host-thread access.
/// Retained model handles therefore stay behind a mutex instead of claiming the raw handle is Sync.
pub(super) type RetainedCudaStream = std::sync::Mutex<GreenContextHandle>;

pub(super) fn retain_for_model(stream: Option<GreenContextHandle>) -> Option<RetainedCudaStream> {
    stream.map(std::sync::Mutex::new)
}

pub(super) fn configured_green_context_sms() -> Result<Option<u32>> {
    let Ok(raw) = std::env::var(GREEN_CONTEXT_SMS_ENV) else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    raw.parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .map(Some)
        .ok_or_else(|| CalyxError {
            code: "CALYX_ONNX_GREEN_CONTEXT_SMS_INVALID",
            message: format!("{GREEN_CONTEXT_SMS_ENV}={raw} is not a positive SM count"),
            remediation: "set CALYX_ONNX_GREEN_CONTEXT_SMS to a positive CUDA SM count, or unset it to use the normal CUDA primary context",
        })
}

pub(super) fn validate_run_plan(policy: OnnxProviderPolicy, cuda_graphs: bool) -> Result<()> {
    let Some(_) = configured_green_context_sms()? else {
        return Ok(());
    };
    if policy != OnnxProviderPolicy::CudaFailLoud {
        return Err(CalyxError {
            code: "CALYX_ONNX_GREEN_CONTEXT_CPU_POLICY",
            message: format!("{GREEN_CONTEXT_SMS_ENV} was requested for a CPU-policy ONNX session"),
            remediation: "enable green contexts only on CudaFailLoud ONNX sessions, or unset CALYX_ONNX_GREEN_CONTEXT_SMS for CPU sessions",
        });
    }
    if cuda_graphs {
        return Err(CalyxError {
            code: "CALYX_ONNX_GREEN_CONTEXT_CUDA_GRAPHS",
            message: format!("{GREEN_CONTEXT_SMS_ENV} cannot be combined with {CUDA_GRAPHS_ENV}=1"),
            remediation: "benchmark green contexts and CUDA Graphs independently; unset one of the two opt-in env vars",
        });
    }
    Ok(())
}

#[cfg(feature = "cuda")]
pub(super) enum GreenContextHandle {
    Primary(calyx_forge::CudaPrimaryContextStream),
    Green(calyx_forge::CudaGreenContextStream),
}

#[cfg(feature = "cuda")]
impl GreenContextHandle {
    pub(super) fn stream_ptr(&self) -> *mut () {
        match self {
            Self::Primary(stream) => stream.stream_ptr(),
            Self::Green(stream) => stream.stream_ptr(),
        }
    }

    pub(super) fn driver_ordinal(&self) -> u32 {
        match self {
            Self::Primary(stream) => stream.driver_ordinal(),
            Self::Green(stream) => stream.driver_device_idx(),
        }
    }

    pub(super) fn physical_identity(&self) -> calyx_forge::PinnedCudaDeviceIdentity {
        match self {
            Self::Primary(stream) => stream.physical_identity(),
            Self::Green(stream) => stream.physical_identity(),
        }
    }

    pub(super) fn attest_identity(&self) -> Result<()> {
        match self {
            Self::Primary(stream) => stream.attest_identity(),
            Self::Green(stream) => stream.attest_identity(),
        }
        .map_err(|error| {
            CalyxError::lens_unreachable(format!(
                "ONNX bound CUDA stream identity re-attestation failed: {error}"
            ))
        })
    }

    fn synchronize(&self, label: &str) -> Result<()> {
        match self {
            Self::Primary(stream) => stream.synchronize(),
            Self::Green(stream) => stream.synchronize(),
        }
        .map_err(|error| {
            crate::runtime::common::gpu_synchronization_failed(
                label,
                "retained_cuda_stream_after_host_materialization",
                error,
            )
        })?;
        let selected =
            super::runtime_bundle::selected_cuda_device(OnnxProviderPolicy::CudaFailLoud)
                .map_err(|error| {
                    crate::runtime::common::gpu_synchronization_failed(
                        label,
                        "retained_cuda_stream_device_readback_after_host_materialization",
                        error,
                    )
                })?
                .ok_or_else(|| {
                    crate::runtime::common::gpu_synchronization_failed(
                        label,
                        "retained_cuda_stream_device_readback_after_host_materialization",
                        "CUDA execution completed without a selected physical-device receipt",
                    )
                })?;
        attest_selected_stream(self, &selected).map_err(|error| {
            crate::runtime::common::gpu_synchronization_failed(
                label,
                "retained_cuda_stream_identity_after_host_materialization",
                error,
            )
        })
    }
}

#[cfg(not(feature = "cuda"))]
pub(super) struct GreenContextHandle;

#[cfg(not(feature = "cuda"))]
impl GreenContextHandle {
    pub(super) fn stream_ptr(&self) -> *mut () {
        std::ptr::null_mut()
    }

    fn synchronize(&self, label: &str) -> Result<()> {
        Err(crate::runtime::common::gpu_synchronization_failed(
            label,
            "retained_cuda_stream_after_host_materialization",
            "calyx-registry/cuda is disabled",
        ))
    }
}

pub(super) fn synchronize_owned_stream(
    stream: Option<&GreenContextHandle>,
    policy: OnnxProviderPolicy,
    label: &str,
) -> Result<()> {
    match (policy, stream) {
        (OnnxProviderPolicy::CpuExplicit, None) => Ok(()),
        (OnnxProviderPolicy::CpuExplicit, Some(_)) => {
            Err(crate::runtime::common::gpu_synchronization_failed(
                label,
                "execution_stream_contract",
                "CPU-explicit ONNX session unexpectedly retained a CUDA stream",
            ))
        }
        (OnnxProviderPolicy::CudaFailLoud, Some(stream)) => stream.synchronize(label),
        (OnnxProviderPolicy::CudaFailLoud, None) => {
            Err(crate::runtime::common::gpu_synchronization_failed(
                label,
                "execution_stream_contract",
                "CUDA ONNX session has no retained Astrolabe-owned execution stream",
            ))
        }
    }
}

pub(super) fn synchronize_retained_stream(
    stream: Option<&RetainedCudaStream>,
    policy: OnnxProviderPolicy,
    label: &str,
) -> Result<()> {
    let stream = match (policy, stream) {
        (OnnxProviderPolicy::CpuExplicit, None) => return Ok(()),
        (OnnxProviderPolicy::CpuExplicit, Some(_)) => {
            return Err(crate::runtime::common::gpu_synchronization_failed(
                label,
                "execution_stream_contract",
                "CPU-explicit ONNX model unexpectedly retained a CUDA stream",
            ));
        }
        (OnnxProviderPolicy::CudaFailLoud, Some(stream)) => stream,
        (OnnxProviderPolicy::CudaFailLoud, None) => {
            return Err(crate::runtime::common::gpu_synchronization_failed(
                label,
                "execution_stream_contract",
                "CUDA ONNX model has no retained Astrolabe-owned execution stream",
            ));
        }
    };
    let stream = stream.lock().map_err(|_| {
        crate::runtime::common::gpu_synchronization_failed(
            label,
            "retained_cuda_stream_mutex",
            "retained CUDA stream mutex was poisoned",
        )
    })?;
    stream.synchronize(label)
}

#[cfg(feature = "cuda")]
pub(super) fn attest_selected_stream(
    stream: &GreenContextHandle,
    selected_device: &super::runtime_bundle::OnnxCudaDeviceAttestation,
) -> Result<()> {
    if stream.driver_ordinal() != selected_device.cuda_driver_ordinal
        || stream.physical_identity() != selected_device.identity
    {
        return Err(CalyxError {
            code: "CALYX_ONNX_BOUND_STREAM_IDENTITY_MISMATCH",
            message: format!(
                "bound stream reports driver_ordinal={} identity={}; selected receipt records driver_ordinal={} identity={}",
                stream.driver_ordinal(),
                stream.physical_identity(),
                selected_device.cuda_driver_ordinal,
                selected_device.identity
            ),
            remediation: "terminate the process, preserve both receipts, and repair the CUDA Runtime/Driver mapping",
        });
    }
    stream.attest_identity()?;
    let observed_driver_ordinal =
        calyx_forge::attest_pinned_cuda_driver_identity(selected_device.identity)
            .map_err(crate::runtime::common::forge_runtime_boundary_error)?;
    if observed_driver_ordinal != selected_device.cuda_driver_ordinal {
        return Err(CalyxError {
            code: "CALYX_ONNX_BOUND_STREAM_IDENTITY_MISMATCH",
            message: format!(
                "independent CUDA Driver readback resolved identity {} to ordinal {observed_driver_ordinal}; selected receipt records ordinal {}",
                selected_device.identity, selected_device.cuda_driver_ordinal
            ),
            remediation: "terminate the process, preserve both receipts, and repair the CUDA Runtime/Driver mapping",
        });
    }
    Ok(())
}

#[cfg(not(feature = "cuda"))]
pub(super) fn attest_selected_stream(
    _stream: &GreenContextHandle,
    _selected_device: &super::runtime_bundle::OnnxCudaDeviceAttestation,
) -> Result<()> {
    Err(CalyxError {
        code: "CALYX_ONNX_ATTESTED_STREAM_UNSUPPORTED",
        message: "this binary cannot re-attest an ONNX CUDA execution stream because calyx-registry/cuda is disabled".to_string(),
        remediation: "rebuild native Windows with --features cuda; do not run a GPU model whose physical execution stream cannot be read back",
    })
}

#[cfg(feature = "cuda")]
pub(super) fn create(
    label: &str,
    policy: OnnxProviderPolicy,
    selected_device: Option<&super::runtime_bundle::OnnxCudaDeviceAttestation>,
) -> Result<Option<GreenContextHandle>> {
    let green_sm_count = configured_green_context_sms()?;
    if policy != OnnxProviderPolicy::CudaFailLoud {
        if green_sm_count.is_some() {
            return Err(CalyxError {
                code: "CALYX_ONNX_GREEN_CONTEXT_CPU_POLICY",
                message: format!(
                    "{GREEN_CONTEXT_SMS_ENV} was requested for CPU-policy ONNX session {label}"
                ),
                remediation: "enable green contexts only on CudaFailLoud ONNX sessions, or unset CALYX_ONNX_GREEN_CONTEXT_SMS for CPU sessions",
            });
        }
        return Ok(None);
    }
    let selected_device = selected_device.ok_or_else(|| CalyxError {
        code: "CALYX_ONNX_CUDA_DEVICE_ATTESTATION_MISSING",
        message: format!(
            "CUDA session {label} requires an attested physical device before binding its execution stream"
        ),
        remediation: "terminate the process and restart from the pinned CUDA runtime boundary before constructing the ONNX session",
    })?;
    let stream = if let Some(sm_count) = green_sm_count {
        let stream = calyx_forge::CudaGreenContextStream::create_serving_by_pci_bus_id(
            &selected_device.cuda_runtime_pci_bus_id,
            sm_count,
        )
        .map_err(|err| {
            config_invalid(format!(
                "ONNX green context init failed for {label} ({GREEN_CONTEXT_SMS_ENV}={sm_count} runtime_device_id={} pci={}): {err}",
                selected_device.ordinal, selected_device.cuda_runtime_pci_bus_id
            ))
        })?;
        eprintln!(
            "CALYX_ONNX_RUNTIME phase=green_context_ready label={label} runtime_device_id={} stream_driver_device_id={} stream_identity_attested=true pci={} uuid={} requested_sm_count={} actual_sm_count={} total_sm_count={} green_ctx_id={} workqueue_balanced={}",
            selected_device.ordinal,
            stream.driver_device_idx(),
            selected_device.cuda_runtime_pci_bus_id,
            selected_device.nvml_uuid,
            stream.requested_sm_count(),
            stream.actual_sm_count(),
            stream.total_sm_count(),
            stream.green_ctx_id(),
            stream.workqueue_balanced()
        );
        GreenContextHandle::Green(stream)
    } else {
        let stream = calyx_forge::CudaPrimaryContextStream::create_by_pci_bus_id(
            &selected_device.cuda_runtime_pci_bus_id,
        )
        .map_err(|error| {
            CalyxError::lens_unreachable(format!(
                "ONNX primary CUDA stream init failed for {label} runtime_device_id={} identity={}: {error}",
                selected_device.ordinal, selected_device.identity
            ))
        })?;
        eprintln!(
            "CALYX_ONNX_RUNTIME phase=primary_stream_ready label={label} runtime_device_id={} stream_driver_device_id={} stream_identity_attested=true identity={}",
            selected_device.ordinal,
            stream.driver_ordinal(),
            stream.physical_identity()
        );
        GreenContextHandle::Primary(stream)
    };
    attest_selected_stream(&stream, selected_device)?;
    Ok(Some(stream))
}

#[cfg(not(feature = "cuda"))]
pub(super) fn create(
    label: &str,
    policy: OnnxProviderPolicy,
    _selected_device: Option<&super::runtime_bundle::OnnxCudaDeviceAttestation>,
) -> Result<Option<GreenContextHandle>> {
    if policy == OnnxProviderPolicy::CudaFailLoud {
        return Err(CalyxError {
            code: "CALYX_ONNX_ATTESTED_STREAM_UNSUPPORTED",
            message: format!(
                "CUDA session {label} cannot bind an Astrolabe-owned attested stream because this binary was not built with calyx-registry/cuda"
            ),
            remediation: "rebuild native Windows with --features cuda; do not run a GPU session whose physical execution stream cannot be retained and read back",
        });
    }
    if configured_green_context_sms()?.is_some() {
        return Err(CalyxError {
            code: "CALYX_ONNX_GREEN_CONTEXT_CPU_POLICY",
            message: format!("{GREEN_CONTEXT_SMS_ENV} was requested for CPU session {label}"),
            remediation: "unset CALYX_ONNX_GREEN_CONTEXT_SMS for CPU sessions",
        });
    }
    Ok(None)
}
