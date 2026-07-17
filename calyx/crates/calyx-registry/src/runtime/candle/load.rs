use std::path::Path;

use calyx_core::{CalyxError, Result};
use candle_core::Device;
use candle_nn::VarBuilder;
use candle_transformers::models::bert::Config;
use hf_hub::api::sync::ApiBuilder;
use tokenizers::{Tokenizer, TruncationParams};

use super::bert::{CANDLE_BERT_EXECUTION_REVISION, CalyxBertModel};
use super::options::{
    attest_executable_cuda_policy, configure_f32_gemm_accumulation, verify_f32_gemm_accumulation,
};
use super::{CandleDevicePolicy, CandleModelFiles, CandlePrecision};
use crate::commission::LensForgeSourceTensorDtypeProfile;
use crate::runtime::common::{LocalModelExecutionAttestation, attest_primary_activation};

pub(super) fn fetch_files(cache_dir: &Path, model_id: &str) -> Result<CandleModelFiles> {
    let api = ApiBuilder::new()
        .with_cache_dir(cache_dir.to_path_buf())
        .with_progress(false)
        .build()
        .map_err(|err| CalyxError::lens_unreachable(format!("HF API init failed: {err}")))?;
    let repo = api.model(model_id.to_string());
    let config = repo
        .get("config.json")
        .map_err(|err| CalyxError::lens_unreachable(format!("fetch config.json failed: {err}")))?;
    let tokenizer = repo.get("tokenizer.json").map_err(|err| {
        CalyxError::lens_unreachable(format!("fetch tokenizer.json failed: {err}"))
    })?;
    let weights = repo.get("model.safetensors").map_err(|err| {
        CalyxError::lens_unreachable(format!("fetch model.safetensors failed: {err}"))
    })?;
    Ok(CandleModelFiles {
        cache_dir: cache_dir.to_path_buf(),
        model_id: model_id.to_string(),
        config,
        tokenizer,
        weights,
        contract_paths: Vec::new(),
    })
}

pub(super) fn read_config(path: &Path) -> Result<Config> {
    let bytes = std::fs::read(path).map_err(|err| {
        CalyxError::lens_unreachable(format!("read BERT config {} failed: {err}", path.display()))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|err| CalyxError::lens_unreachable(format!("parse BERT config failed: {err}")))
}

pub(super) fn read_tokenizer(path: &Path, max_tokens: usize) -> Result<Tokenizer> {
    let mut tokenizer = Tokenizer::from_file(path)
        .map_err(|err| CalyxError::lens_unreachable(format!("load tokenizer failed: {err}")))?;
    tokenizer
        .with_truncation(Some(TruncationParams {
            max_length: max_tokens,
            ..Default::default()
        }))
        .map_err(|err| CalyxError::lens_dim_mismatch(format!("set truncation failed: {err}")))?;
    Ok(tokenizer)
}

pub(super) fn read_model(
    weights: &Path,
    config: &Config,
    device_policy: CandleDevicePolicy,
    precision: CandlePrecision,
    source_tensor_dtype_profile: &LensForgeSourceTensorDtypeProfile,
) -> Result<(CalyxBertModel, LocalModelExecutionAttestation)> {
    configure_f32_gemm_accumulation(device_policy, precision).map_err(|error| {
        with_runtime_context(
            error,
            "gemm_accumulation_configure",
            device_policy,
            precision,
            source_tensor_dtype_profile,
        )
    })?;
    let device = candle_device(device_policy).map_err(|error| {
        with_runtime_context(
            error,
            "device_init",
            device_policy,
            precision,
            source_tensor_dtype_profile,
        )
    })?;
    let paths = [weights];
    let vb = unsafe { VarBuilder::from_mmaped_safetensors(&paths, precision.dtype(), &device) }
        .map_err(candle_error)
        .map_err(|error| {
            with_runtime_context(
                error,
                "weights_mmap",
                device_policy,
                precision,
                source_tensor_dtype_profile,
            )
        })?;
    let model = CalyxBertModel::load(vb, config)
        .map_err(candle_error)
        .map_err(|error| {
            with_runtime_context(
                error,
                "model_load",
                device_policy,
                precision,
                source_tensor_dtype_profile,
            )
        })?;
    let hidden = model
        .full_forward_dtype_probe()
        .map_err(candle_error)
        .map_err(|error| {
            with_runtime_context(
                error,
                "dtype_attestation",
                device_policy,
                precision,
                source_tensor_dtype_profile,
            )
        })?;
    let attestation = attest_primary_activation(
        "candle",
        &hidden,
        precision.dtype(),
        &device,
        &device_policy.frozen_token(),
    )
    .map_err(|error| {
        with_runtime_context(
            error,
            "dtype_attestation",
            device_policy,
            precision,
            source_tensor_dtype_profile,
        )
    })?;
    verify_f32_gemm_accumulation(device_policy, precision).map_err(|error| {
        with_attested_runtime_context(
            error,
            "gemm_accumulation_verify",
            device_policy,
            source_tensor_dtype_profile,
            &attestation,
        )
    })?;
    Ok((model, attestation))
}

pub(super) fn candle_device(policy: CandleDevicePolicy) -> Result<Device> {
    match policy {
        CandleDevicePolicy::CpuExplicit
        | CandleDevicePolicy::CpuNoCudaFeature
        | CandleDevicePolicy::CpuNoCudaDevice => Ok(Device::Cpu),
        CandleDevicePolicy::CudaFrozen { identity } => Err(CalyxError::lens_unreachable(format!(
            "Candle physical device {identity} was parsed but not resolved through the pinned CUDA Runtime/Driver boundary"
        ))),
        CandleDevicePolicy::CudaFailLoud { driver_ordinal, .. } => {
            candle_cuda_device(policy, driver_ordinal)
        }
    }
}

#[cfg(all(feature = "candle-cuda", windows))]
fn candle_cuda_device(policy: CandleDevicePolicy, driver_ordinal: usize) -> Result<Device> {
    crate::runtime::common::initialize_pinned_cuda_dependencies()?;
    let selected = attest_executable_cuda_policy(policy)?;
    let selected_driver = usize::try_from(selected.cuda_driver_ordinal)
        .map_err(|_| CalyxError::lens_unreachable("attested CUDA Driver ordinal exceeds usize"))?;
    if selected_driver != driver_ordinal {
        return Err(CalyxError::lens_frozen_violation(format!(
            "Candle CUDA Driver selector changed from {driver_ordinal} to {selected_driver} before construction"
        )));
    }
    let device = Device::new_cuda(selected_driver).map_err(|err| {
        CalyxError::lens_unreachable(format!(
            "Candle CUDA Driver device {selected_driver} init failed after shared physical-device attestation: {err}"
        ))
    })?;
    crate::runtime::common::attest_candle_cuda_device("candle", &device, &selected)?;
    attest_executable_cuda_policy(policy)?;
    Ok(device)
}

#[cfg(not(all(feature = "candle-cuda", windows)))]
fn candle_cuda_device(_policy: CandleDevicePolicy, _ordinal: usize) -> Result<Device> {
    Err(CalyxError::lens_unreachable(
        "Candle CUDA execution is unavailable: build native Windows with feature `candle-cuda`; non-Windows support is DEFERRED[ASTRO_PORT_PHASE]",
    ))
}

pub(super) fn candle_error(err: candle_core::Error) -> CalyxError {
    candle_error_message(format!("candle runtime failed: {err}"))
}

pub(super) fn candle_error_message(message: String) -> CalyxError {
    let lower = message.to_ascii_lowercase();
    if lower.contains("out of memory") || lower.contains("memoryallocation") {
        return CalyxError {
            code: "CALYX_VRAM_OOM",
            message,
            remediation: "free VRAM, reduce batch size, or evict lower-priority GPU lenses",
        };
    }
    CalyxError::lens_unreachable(message)
}

pub(super) fn with_runtime_context(
    error: CalyxError,
    stage: &str,
    device_policy: CandleDevicePolicy,
    precision: CandlePrecision,
    source_tensor_dtype_profile: &LensForgeSourceTensorDtypeProfile,
) -> CalyxError {
    CalyxError {
        code: error.code,
        message: format!(
            "candle stage={stage} execution_revision={CANDLE_BERT_EXECUTION_REVISION} device_policy={} source_tensor_dtype_profile={} loader_target_dtype={} observed_primary_activation_dtype=unattested observed_execution_device=unattested dtype_attestation_evidence=unattested gemm_accumulation_dtype=f32 output_dtype=f32: {}",
            device_policy.detail(),
            source_tensor_dtype_profile.summary(),
            precision.as_str(),
            error.message
        ),
        remediation: error.remediation,
    }
}

pub(super) fn with_attested_runtime_context(
    error: CalyxError,
    stage: &str,
    device_policy: CandleDevicePolicy,
    source_tensor_dtype_profile: &LensForgeSourceTensorDtypeProfile,
    attestation: &LocalModelExecutionAttestation,
) -> CalyxError {
    CalyxError {
        code: error.code,
        message: format!(
            "candle stage={stage} execution_revision={CANDLE_BERT_EXECUTION_REVISION} device_policy={} source_tensor_dtype_profile={} loader_target_dtype={} observed_primary_activation_dtype={} observed_execution_device={} dtype_attestation_evidence={} gemm_accumulation_dtype=f32 output_dtype=f32: {}",
            device_policy.detail(),
            source_tensor_dtype_profile.summary(),
            attestation.loader_target_dtype,
            attestation.observed_primary_activation_dtype,
            attestation.observed_device,
            attestation.evidence_kind,
            error.message
        ),
        remediation: error.remediation,
    }
}

pub(super) fn ensure_file(label: &str, path: &Path) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    Err(config_invalid(format!(
        "candle {label} file {} is missing",
        path.display()
    )))
}

pub(super) fn config_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_CONFIG_INVALID",
        message: message.into(),
        remediation: "fix candle model/tokenizer/config or register a supported lens spec",
    }
}
