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
    CandleDevicePolicy, CandlePrecision, configure_f32_gemm_accumulation,
    verify_f32_gemm_accumulation,
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
    let device = qwen3_device(device_policy).map_err(|error| {
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

fn qwen3_device(policy: CandleDevicePolicy) -> Result<Device> {
    match policy {
        CandleDevicePolicy::CpuExplicit
        | CandleDevicePolicy::CpuNoCudaFeature
        | CandleDevicePolicy::CpuNoCudaDevice => Ok(Device::Cpu),
        CandleDevicePolicy::CudaFailLoud { ordinal } => qwen3_cuda_device(ordinal),
    }
}

#[cfg(feature = "candle-cuda")]
fn qwen3_cuda_device(ordinal: usize) -> Result<Device> {
    Device::new_cuda(ordinal)
        .map_err(|err| CalyxError::lens_unreachable(format!("Qwen3 CUDA init failed: {err}")))
}

#[cfg(not(feature = "candle-cuda"))]
fn qwen3_cuda_device(_ordinal: usize) -> Result<Device> {
    Err(CalyxError::lens_unreachable(
        "Qwen3 CUDA requested but calyx-registry was built without feature `candle-cuda`",
    ))
}
