use std::path::{Path, PathBuf};

use calyx_core::{CalyxError, Result, SlotVector};
use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use fastembed::{Qwen3Config, Qwen3Model, Qwen3TextEmbedding};
use tokenizers::{PaddingDirection, PaddingParams, PaddingStrategy, Tokenizer, TruncationParams};

use super::{
    DEFAULT_QWEN3_MODEL, config_invalid, qwen3_attested_runtime_context, qwen3_error,
    qwen3_runtime_context,
};
use crate::commission::LensForgeSourceTensorDtypeProfile;
use crate::runtime::candle::{
    CandleCpuAuthorization, CandleDevicePolicy, CandlePrecision, attest_executable_cuda_policy,
    configure_f32_gemm_accumulation, verify_f32_gemm_accumulation,
};
use crate::runtime::common::normalize_unit;
use crate::runtime::common::{LocalModelExecutionAttestation, attest_primary_activation};

pub fn read_config(path: &Path) -> Result<Qwen3Config> {
    let bytes = std::fs::read(path).map_err(|err| {
        CalyxError::lens_unreachable(format!(
            "read Qwen3 config {} failed: {err}",
            path.display()
        ))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|err| config_invalid(format!("parse Qwen3 config failed: {err}")))
}

pub fn read_tokenizer(path: &Path, max_tokens: usize) -> Result<Tokenizer> {
    let mut tokenizer = Tokenizer::from_file(path).map_err(|err| {
        CalyxError::lens_unreachable(format!("load Qwen3 tokenizer failed: {err}"))
    })?;
    tokenizer.with_padding(Some(PaddingParams {
        strategy: PaddingStrategy::BatchLongest,
        direction: PaddingDirection::Left,
        ..Default::default()
    }));
    tokenizer
        .with_truncation(Some(TruncationParams {
            max_length: max_tokens,
            ..Default::default()
        }))
        .map_err(|err| CalyxError::lens_dim_mismatch(format!("set truncation failed: {err}")))?;
    Ok(tokenizer)
}

pub fn read_model(
    weights: &[PathBuf],
    config: Qwen3Config,
    tokenizer: Tokenizer,
    device_policy: CandleDevicePolicy,
    precision: CandlePrecision,
    source_tensor_dtype_profile: &LensForgeSourceTensorDtypeProfile,
    cpu_authorization: Option<&CandleCpuAuthorization>,
) -> Result<(Qwen3TextEmbedding, LocalModelExecutionAttestation)> {
    configure_f32_gemm_accumulation(device_policy, precision).map_err(|error| {
        qwen3_runtime_context(
            error,
            "gemm_accumulation_configure",
            device_policy,
            precision,
            source_tensor_dtype_profile,
        )
    })?;
    let device = qwen3_device(device_policy, cpu_authorization).map_err(|error| {
        qwen3_runtime_context(
            error,
            "device_init",
            device_policy,
            precision,
            source_tensor_dtype_profile,
        )
    })?;
    let vb = unsafe { VarBuilder::from_mmaped_safetensors(weights, precision.dtype(), &device) }
        .map_err(qwen3_error)
        .map_err(|error| {
            qwen3_runtime_context(
                error,
                "weights_mmap",
                device_policy,
                precision,
                source_tensor_dtype_profile,
            )
        })?;
    let model = Qwen3Model::new(config, vb)
        .map_err(qwen3_error)
        .map_err(|error| {
            qwen3_runtime_context(
                error,
                "model_load",
                device_policy,
                precision,
                source_tensor_dtype_profile,
            )
        })?;
    let input_ids = Tensor::zeros((1, 1), DType::U32, &device)
        .map_err(qwen3_error)
        .map_err(|error| {
            qwen3_runtime_context(
                error,
                "dtype_attestation",
                device_policy,
                precision,
                source_tensor_dtype_profile,
            )
        })?;
    let hidden = model
        .forward(&input_ids, None)
        .map_err(qwen3_error)
        .map_err(|error| {
            qwen3_runtime_context(
                error,
                "dtype_attestation",
                device_policy,
                precision,
                source_tensor_dtype_profile,
            )
        })?;
    let attestation = attest_primary_activation(
        "fastembed-qwen3",
        &hidden,
        precision.dtype(),
        &device,
        &device_policy.frozen_token(),
    )
    .map_err(|error| {
        qwen3_runtime_context(
            error,
            "dtype_attestation",
            device_policy,
            precision,
            source_tensor_dtype_profile,
        )
    })?;
    verify_f32_gemm_accumulation(device_policy, precision).map_err(|error| {
        qwen3_attested_runtime_context(
            error,
            "gemm_accumulation_verify",
            device_policy,
            source_tensor_dtype_profile,
            &attestation,
        )
    })?;
    Ok((Qwen3TextEmbedding::new(model, tokenizer), attestation))
}

pub fn dense_batch(dim: u32, rows: Vec<Vec<f32>>, expected: usize) -> Result<Vec<SlotVector>> {
    if rows.len() != expected {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "Qwen3 returned {} vectors for {expected} inputs",
            rows.len()
        )));
    }
    rows.into_iter()
        .map(|mut data| {
            if data.len() != dim as usize {
                return Err(CalyxError::lens_dim_mismatch(format!(
                    "Qwen3 dim {} != expected {dim}",
                    data.len()
                )));
            }
            normalize_unit(&mut data)?;
            Ok(SlotVector::Dense { dim, data })
        })
        .collect()
}

pub fn qwen3_model_id(raw: &str) -> Result<String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "qwen/qwen3-embedding-0.6b" | "qwen3-embedding-0.6b" | "qwen3-0.6b" => {
            Ok(DEFAULT_QWEN3_MODEL.to_string())
        }
        other => Err(CalyxError::lens_unreachable(format!(
            "unsupported fastembed-qwen3 model {other}; expected {DEFAULT_QWEN3_MODEL}"
        ))),
    }
}

fn qwen3_device(
    policy: CandleDevicePolicy,
    cpu_authorization: Option<&CandleCpuAuthorization>,
) -> Result<Device> {
    match policy {
        CandleDevicePolicy::CpuExplicit
        | CandleDevicePolicy::CpuNoCudaFeature
        | CandleDevicePolicy::CpuNoCudaDevice => {
            cpu_authorization.ok_or_else(|| CalyxError {
                code: "CALYX_ONNX_CPU_COMPANION_UNAUTHORIZED",
                message: format!(
                    "Qwen3 CPU device construction for {} has no retained shared dual-zero authorization",
                    policy.detail()
                ),
                remediation: "obtain the opaque CPU capability from authorize_cpu_companion before model construction; never convert a CUDA failure into CPU execution",
            })?;
            Ok(Device::Cpu)
        }
        CandleDevicePolicy::CudaFrozen { identity } => Err(CalyxError::lens_unreachable(format!(
            "Qwen3 physical device {identity} was parsed but not resolved through the pinned CUDA Runtime/Driver boundary"
        ))),
        CandleDevicePolicy::CudaFailLoud { driver_ordinal, .. } => {
            qwen3_cuda_device(policy, driver_ordinal)
        }
    }
}

#[cfg(all(feature = "candle-cuda", windows))]
fn qwen3_cuda_device(policy: CandleDevicePolicy, driver_ordinal: usize) -> Result<Device> {
    crate::runtime::common::initialize_pinned_cuda_dependencies()?;
    let selected = attest_executable_cuda_policy(policy)?;
    let selected_driver = usize::try_from(selected.cuda_driver_ordinal)
        .map_err(|_| CalyxError::lens_unreachable("attested CUDA Driver ordinal exceeds usize"))?;
    if selected_driver != driver_ordinal {
        return Err(CalyxError::lens_frozen_violation(format!(
            "Qwen3 CUDA Driver selector changed from {driver_ordinal} to {selected_driver} before construction"
        )));
    }
    let device = Device::new_cuda(selected_driver).map_err(|err| {
        CalyxError::lens_unreachable(format!(
            "Qwen3 CUDA Driver device {selected_driver} init failed after shared physical-device attestation: {err}"
        ))
    })?;
    crate::runtime::common::attest_candle_cuda_device("qwen3", &device, &selected)?;
    attest_executable_cuda_policy(policy)?;
    Ok(device)
}

#[cfg(not(all(feature = "candle-cuda", windows)))]
fn qwen3_cuda_device(_policy: CandleDevicePolicy, _ordinal: usize) -> Result<Device> {
    Err(CalyxError::lens_unreachable(
        "Qwen3 CUDA execution is unavailable: build native Windows with feature `candle-cuda`; non-Windows support is DEFERRED[ASTRO_PORT_PHASE]",
    ))
}
