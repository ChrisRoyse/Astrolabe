use std::path::PathBuf;

use calyx_core::{CalyxError, Placement, Result};
use candle_core::DType;

use super::config_invalid;
use crate::frozen::NormPolicy;

pub const CANDLE_CUDA_DEVICE_ENV: &str = "CALYX_CANDLE_CUDA_DEVICE";
pub const CANDLE_DEVICE_MODE_ENV: &str = "CALYX_CANDLE_DEVICE_MODE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandleDeviceMode {
    Auto,
    Cuda,
    Cpu,
}

impl CandleDeviceMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Cuda => "cuda",
            Self::Cpu => "cpu",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "auto" => Ok(Self::Auto),
            "cuda" | "gpu" => Ok(Self::Cuda),
            "cpu" => Ok(Self::Cpu),
            other => Err(device_mode_invalid(format!(
                "unsupported Candle device mode {other}; expected auto, cuda, or cpu"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandleModelFiles {
    pub cache_dir: PathBuf,
    pub model_id: String,
    pub config: PathBuf,
    pub tokenizer: PathBuf,
    pub weights: PathBuf,
    pub contract_paths: Vec<PathBuf>,
}

impl CandleModelFiles {
    pub fn artifact_paths(&self) -> Vec<PathBuf> {
        if !self.contract_paths.is_empty() {
            return self.contract_paths.clone();
        }
        self.required_paths()
    }

    pub fn required_paths(&self) -> Vec<PathBuf> {
        vec![
            self.weights.clone(),
            self.tokenizer.clone(),
            self.config.clone(),
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandleDevicePolicy {
    CpuExplicit,
    CpuNoCudaFeature,
    CpuNoCudaDevice,
    CudaFailLoud { ordinal: usize },
}

impl CandleDevicePolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CpuExplicit => "cpu_explicit,no_cuda",
            Self::CpuNoCudaFeature => "cpu_no_cuda_feature,no_cuda",
            Self::CpuNoCudaDevice => "cpu_no_cuda_device,no_cuda",
            Self::CudaFailLoud { .. } => "cuda,error_on_failure,no_cpu_fallback",
        }
    }

    pub const fn is_gpu(self) -> bool {
        matches!(self, Self::CudaFailLoud { .. })
    }

    pub const fn placement(self) -> Placement {
        if self.is_gpu() {
            Placement::Gpu
        } else {
            Placement::Cpu
        }
    }

    pub fn detail(self) -> String {
        match self {
            Self::CudaFailLoud { ordinal } => format!("{};device={ordinal}", self.as_str()),
            _ => self.as_str().to_string(),
        }
    }

    pub fn frozen_token(self) -> String {
        match self {
            Self::CpuExplicit | Self::CpuNoCudaFeature | Self::CpuNoCudaDevice => "cpu".to_string(),
            Self::CudaFailLoud { ordinal } => format!("cuda:{ordinal}"),
        }
    }
}

pub fn configured_device_mode() -> Result<CandleDeviceMode> {
    let Ok(raw) = std::env::var(CANDLE_DEVICE_MODE_ENV) else {
        return Ok(CandleDeviceMode::Auto);
    };
    let raw = raw.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return Err(device_mode_invalid(format!(
            "{CANDLE_DEVICE_MODE_ENV} must not be empty; expected auto, cuda, or cpu"
        )));
    }
    CandleDeviceMode::parse(&raw)
}

fn device_mode_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_CONFIG_INVALID",
        message: message.into(),
        remediation: "set CALYX_CANDLE_DEVICE_MODE to auto, cuda, or cpu; unset it to use auto",
    }
}

/// CUDA device ordinal used by default live Candle-family runtimes.
pub fn configured_cuda_device() -> Result<usize> {
    let Ok(raw) = std::env::var(CANDLE_CUDA_DEVICE_ENV) else {
        return Ok(0);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(CalyxError {
            code: "CALYX_CANDLE_CUDA_DEVICE_INVALID",
            message: format!("{CANDLE_CUDA_DEVICE_ENV} must not be empty"),
            remediation: "set CALYX_CANDLE_CUDA_DEVICE to the integer ordinal reported by nvidia-smi, or unset it for device 0",
        });
    }
    raw.parse::<usize>().map_err(|_| CalyxError {
        code: "CALYX_CANDLE_CUDA_DEVICE_INVALID",
        message: format!(
            "{CANDLE_CUDA_DEVICE_ENV}={raw} is not a non-negative CUDA device ordinal"
        ),
        remediation: "set CALYX_CANDLE_CUDA_DEVICE to the integer ordinal reported by nvidia-smi, or unset it for device 0",
    })
}

/// Selects CUDA whenever a usable device exists. CPU is selected automatically only when the
/// binary has no CUDA support or the CUDA driver reports that no CUDA device exists.
pub fn configured_device_policy() -> Result<CandleDevicePolicy> {
    device_policy_for_mode(configured_device_mode()?)
}

pub fn device_policy_for_mode(mode: CandleDeviceMode) -> Result<CandleDevicePolicy> {
    match mode {
        CandleDeviceMode::Cpu => Ok(CandleDevicePolicy::CpuExplicit),
        CandleDeviceMode::Cuda => cuda_policy(false),
        CandleDeviceMode::Auto => cuda_policy(true),
    }
}

pub fn frozen_device_policy(raw: &str) -> Result<CandleDevicePolicy> {
    let raw = raw.trim().to_ascii_lowercase();
    if raw == "cpu" {
        return Ok(CandleDevicePolicy::CpuExplicit);
    }
    let Some(ordinal) = raw.strip_prefix("cuda:") else {
        return Err(device_mode_invalid(format!(
            "unsupported frozen Candle execution device {raw}; expected cpu or cuda:<ordinal>"
        )));
    };
    let ordinal = ordinal.parse::<usize>().map_err(|_| {
        device_mode_invalid(format!(
            "frozen Candle execution device {raw} has an invalid CUDA ordinal"
        ))
    })?;
    cuda_policy_for_ordinal(false, ordinal, "frozen execution_device")
}

#[cfg(feature = "candle-cuda")]
fn cuda_policy(allow_absent: bool) -> Result<CandleDevicePolicy> {
    cuda_policy_for_ordinal(
        allow_absent,
        configured_cuda_device()?,
        CANDLE_CUDA_DEVICE_ENV,
    )
}

#[cfg(feature = "candle-cuda")]
fn cuda_policy_for_ordinal(
    allow_absent: bool,
    ordinal: usize,
    ordinal_source: &str,
) -> Result<CandleDevicePolicy> {
    use candle_core::cuda::cudarc::driver::{result, sys};

    if let Err(error) = result::init() {
        if allow_absent && error.0 == sys::CUresult::CUDA_ERROR_NO_DEVICE {
            return Ok(CandleDevicePolicy::CpuNoCudaDevice);
        }
        return Err(CalyxError::lens_unreachable(format!(
            "Candle CUDA driver initialization failed (mode={}, requested_device={ordinal}, error={error}); fix the CUDA driver/runtime rather than retrying on CPU",
            if allow_absent { "auto" } else { "cuda" }
        )));
    }
    let count = match result::device::get_count() {
        Ok(count) => count,
        Err(error) if allow_absent && error.0 == sys::CUresult::CUDA_ERROR_NO_DEVICE => {
            return Ok(CandleDevicePolicy::CpuNoCudaDevice);
        }
        Err(error) => {
            return Err(CalyxError::lens_unreachable(format!(
                "Candle CUDA device enumeration failed (mode={}, requested_device={ordinal}, error={error}); CPU fallback is disabled after successful CUDA initialization",
                if allow_absent { "auto" } else { "cuda" }
            )));
        }
    };
    if count <= 0 {
        if allow_absent {
            return Ok(CandleDevicePolicy::CpuNoCudaDevice);
        }
        return Err(CalyxError::lens_unreachable(
            "Candle CUDA mode was requested but the CUDA driver reported zero devices",
        ));
    }
    if ordinal >= count as usize {
        return Err(CalyxError {
            code: "CALYX_CANDLE_CUDA_DEVICE_INVALID",
            message: format!(
                "{ordinal_source} ordinal {ordinal} is outside the CUDA device range 0..{}",
                count - 1
            ),
            remediation: if ordinal_source == CANDLE_CUDA_DEVICE_ENV {
                "set CALYX_CANDLE_CUDA_DEVICE to an ordinal reported by nvidia-smi"
            } else {
                "recommission or select a frozen manifest whose execution_device names an ordinal reported by nvidia-smi"
            },
        });
    }
    Ok(CandleDevicePolicy::CudaFailLoud { ordinal })
}

#[cfg(not(feature = "candle-cuda"))]
fn cuda_policy(allow_absent: bool) -> Result<CandleDevicePolicy> {
    cuda_policy_for_ordinal(allow_absent, 0, CANDLE_CUDA_DEVICE_ENV)
}

#[cfg(not(feature = "candle-cuda"))]
fn cuda_policy_for_ordinal(
    allow_absent: bool,
    _ordinal: usize,
    _ordinal_source: &str,
) -> Result<CandleDevicePolicy> {
    if allow_absent {
        return Ok(CandleDevicePolicy::CpuNoCudaFeature);
    }
    Err(CalyxError::lens_unreachable(
        "Candle CUDA mode was requested but calyx-registry was built without feature `candle-cuda`",
    ))
}

pub fn default_cuda_fail_loud_policy() -> Result<CandleDevicePolicy> {
    cuda_policy(false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandlePrecision {
    F32,
    F16,
    BF16,
}

impl CandlePrecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::F32 => "f32",
            Self::F16 => "f16",
            Self::BF16 => "bf16",
        }
    }

    pub(crate) const fn dtype(self) -> DType {
        match self {
            Self::F32 => DType::F32,
            Self::F16 => DType::F16,
            Self::BF16 => DType::BF16,
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "f32" | "float32" => Ok(Self::F32),
            "f16" | "fp16" | "float16" => Ok(Self::F16),
            "bf16" | "bfloat16" => Ok(Self::BF16),
            other => Err(config_invalid(format!("unsupported candle dtype {other}"))),
        }
    }
}

pub const GPU_DEFAULT_CANDLE_PRECISION: CandlePrecision = CandlePrecision::F16;

pub const fn default_precision_for_policy(policy: CandleDevicePolicy) -> CandlePrecision {
    if policy.is_gpu() {
        GPU_DEFAULT_CANDLE_PRECISION
    } else {
        CandlePrecision::F32
    }
}

pub(crate) fn configure_f32_gemm_accumulation(
    device_policy: CandleDevicePolicy,
    precision: CandlePrecision,
) -> Result<()> {
    if !device_policy.is_gpu() {
        return Ok(());
    }
    #[cfg(feature = "candle-cuda")]
    {
        candle_core::cuda::set_gemm_reduced_precision_f32(false);
        candle_core::cuda::set_gemm_reduced_precision_f16(false);
        candle_core::cuda::set_gemm_reduced_precision_bf16(false);
    }
    verify_f32_gemm_accumulation(device_policy, precision)
}

pub(crate) fn verify_f32_gemm_accumulation(
    device_policy: CandleDevicePolicy,
    precision: CandlePrecision,
) -> Result<()> {
    if !device_policy.is_gpu() {
        return Ok(());
    }
    #[cfg(feature = "candle-cuda")]
    if candle_core::cuda::gemm_reduced_precision_f32()
        || candle_core::cuda::gemm_reduced_precision_f16()
        || candle_core::cuda::gemm_reduced_precision_bf16()
    {
        return Err(CalyxError {
            code: "CALYX_LENS_NUMERICAL_INVARIANT",
            message: format!(
                "Candle GEMM accumulation policy drifted from f32 during {} execution on {}",
                precision.as_str(),
                device_policy.detail()
            ),
            remediation: "do not mutate Candle's process-global reduced-precision GEMM switches; Astrolabe owns them and requires f32 GEMM accumulation",
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandlePoolingPolicy {
    Mean,
    Cls,
}

impl CandlePoolingPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mean => "mean",
            Self::Cls => "cls",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "mean" => Ok(Self::Mean),
            "cls" | "first_token" | "first-token" => Ok(Self::Cls),
            other => Err(config_invalid(format!(
                "unsupported candle pooling {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CandleFileSpec {
    pub name: String,
    pub model_id: String,
    pub cache_dir: PathBuf,
    pub config: PathBuf,
    pub tokenizer: PathBuf,
    pub weights: PathBuf,
    pub max_tokens: usize,
    pub device_policy: CandleDevicePolicy,
    pub precision: CandlePrecision,
    pub pooling: CandlePoolingPolicy,
    pub norm_policy: NormPolicy,
    pub expected_dim: Option<u32>,
    pub expected_weights_sha256: Option<[u8; 32]>,
    pub contract_paths: Vec<PathBuf>,
}
