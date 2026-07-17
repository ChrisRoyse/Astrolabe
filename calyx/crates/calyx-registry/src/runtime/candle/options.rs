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
    CudaFrozen {
        identity: calyx_forge::PinnedCudaDeviceIdentity,
    },
    CudaFailLoud {
        runtime_ordinal: usize,
        driver_ordinal: usize,
        identity: calyx_forge::PinnedCudaDeviceIdentity,
    },
}

impl CandleDevicePolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CpuExplicit => "cpu_explicit,no_cuda",
            Self::CpuNoCudaFeature => "cpu_no_cuda_feature,no_cuda",
            Self::CpuNoCudaDevice => "cpu_no_cuda_device,no_cuda",
            Self::CudaFrozen { .. } | Self::CudaFailLoud { .. } => {
                "cuda,error_on_failure,no_cpu_fallback"
            }
        }
    }

    pub const fn is_gpu(self) -> bool {
        matches!(self, Self::CudaFrozen { .. } | Self::CudaFailLoud { .. })
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
            Self::CudaFrozen { identity } => {
                format!("{};identity={identity};selectors=unresolved", self.as_str())
            }
            Self::CudaFailLoud {
                runtime_ordinal,
                driver_ordinal,
                identity,
            } => format!(
                "{};runtime_ordinal={runtime_ordinal};driver_ordinal={driver_ordinal};identity={identity}",
                self.as_str()
            ),
            _ => self.as_str().to_string(),
        }
    }

    pub fn frozen_token(self) -> String {
        match self {
            Self::CpuExplicit | Self::CpuNoCudaFeature | Self::CpuNoCudaDevice => "cpu".to_string(),
            Self::CudaFrozen { identity } | Self::CudaFailLoud { identity, .. } => {
                identity.canonical_execution_token()
            }
        }
    }

    pub fn compact_identity_token(self) -> String {
        match self {
            Self::CpuExplicit | Self::CpuNoCudaFeature | Self::CpuNoCudaDevice => "cpu".to_string(),
            Self::CudaFrozen { identity } | Self::CudaFailLoud { identity, .. } => {
                let pci = identity
                    .canonical_pci_bus_id()
                    .replace(':', "")
                    .replace('.', "");
                let uuid = identity
                    .canonical_uuid()
                    .trim_start_matches("GPU-")
                    .replace('-', "");
                format!("cuda-{pci}-{uuid}")
            }
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

/// CUDA Runtime-visible device ordinal used by default live Candle-family runtimes.
pub fn configured_cuda_device() -> Result<usize> {
    let ordinal = calyx_forge::configured_cuda_runtime_ordinal()
        .map_err(crate::runtime::common::forge_runtime_boundary_error)?;
    usize::try_from(ordinal).map_err(|_| CalyxError {
        code: "CALYX_CANDLE_CUDA_DEVICE_INVALID",
        message: format!("shared CUDA Runtime-visible ordinal {ordinal} exceeds usize"),
        remediation: "set CALYX_CUDA_DEVICE to a valid CUDA Runtime-visible ordinal",
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

/// Parses a frozen execution-device token without querying live CUDA state.
///
/// Manifest, catalog, and identity operations use this boundary because the token is persisted
/// declarative state. Executable runtime construction must call [`frozen_device_policy`] instead,
/// which additionally proves that the declared CUDA device is available.
pub fn parse_frozen_device_policy(raw: &str) -> Result<CandleDevicePolicy> {
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("cpu") {
        return Ok(CandleDevicePolicy::CpuExplicit);
    }
    if raw.eq_ignore_ascii_case("cuda")
        || raw
            .strip_prefix("cuda:")
            .is_some_and(|suffix| suffix.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(frozen_device_invalid(format!(
            "legacy ordinal-only execution device {raw:?} does not identify a physical GPU"
        )));
    }
    let identity = calyx_forge::PinnedCudaDeviceIdentity::parse_execution_token(raw)
        .map_err(frozen_device_invalid)?;
    Ok(CandleDevicePolicy::CudaFrozen { identity })
}

/// Resolves a frozen execution-device token for executable runtime construction.
pub fn frozen_device_policy(raw: &str) -> Result<CandleDevicePolicy> {
    match parse_frozen_device_policy(raw)? {
        CandleDevicePolicy::CudaFrozen { identity } => cuda_policy_for_identity(identity),
        policy => Ok(policy),
    }
}

#[cfg(all(feature = "candle-cuda", windows))]
pub(crate) fn attest_executable_cuda_policy(
    policy: CandleDevicePolicy,
) -> Result<calyx_forge::PinnedCudaDeviceAttestation> {
    let CandleDevicePolicy::CudaFailLoud {
        runtime_ordinal,
        driver_ordinal,
        identity,
    } = policy
    else {
        return Err(CalyxError::lens_unreachable(format!(
            "CUDA execution requires a resolved physical-device policy; observed {}",
            policy.detail()
        )));
    };
    let selected = calyx_forge::select_pinned_cuda_device_by_identity(identity)
        .map_err(crate::runtime::common::forge_runtime_boundary_error)?;
    let selected_runtime = usize::try_from(selected.ordinal)
        .map_err(|_| frozen_device_invalid("attested CUDA Runtime ordinal exceeds usize"))?;
    let selected_driver = usize::try_from(selected.cuda_driver_ordinal)
        .map_err(|_| frozen_device_invalid("attested CUDA Driver ordinal exceeds usize"))?;
    if selected_runtime != runtime_ordinal
        || selected_driver != driver_ordinal
        || selected.identity != identity
    {
        return Err(CalyxError::lens_frozen_violation(format!(
            "resolved CUDA policy selectors drifted: policy runtime_ordinal={runtime_ordinal} driver_ordinal={driver_ordinal} identity={identity}; observed runtime_ordinal={selected_runtime} driver_ordinal={selected_driver} identity={}",
            selected.identity
        )));
    }
    Ok(selected)
}

#[cfg(not(all(feature = "candle-cuda", windows)))]
pub(crate) fn attest_executable_cuda_policy(
    policy: CandleDevicePolicy,
) -> Result<calyx_forge::PinnedCudaDeviceAttestation> {
    Err(CalyxError::lens_unreachable(format!(
        "CUDA execution policy {} cannot be attested by this build",
        policy.detail()
    )))
}

fn frozen_device_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_CONFIG_INVALID",
        message: message.into(),
        remediation: "recommission the frozen manifest so execution_device is cpu or the attested cuda:pci=<PCI>;uuid=GPU-<UUID> physical identity; never infer identity from an old ordinal",
    }
}

#[cfg(feature = "candle-cuda")]
fn cuda_policy(allow_absent: bool) -> Result<CandleDevicePolicy> {
    cuda_policy_for_ordinal(
        allow_absent,
        configured_cuda_device()?,
        CANDLE_CUDA_DEVICE_ENV,
    )
}

#[cfg(all(feature = "candle-cuda", windows))]
fn cuda_policy_for_ordinal(
    allow_absent: bool,
    ordinal: usize,
    ordinal_source: &str,
) -> Result<CandleDevicePolicy> {
    let ordinal = u32::try_from(ordinal).map_err(|_| CalyxError {
        code: "CALYX_CANDLE_CUDA_DEVICE_INVALID",
        message: format!("{ordinal_source} ordinal {ordinal} exceeds u32"),
        remediation: "select a valid CUDA Runtime-visible ordinal",
    })?;
    match calyx_forge::select_pinned_cuda_device(ordinal) {
        Ok(device) => executable_cuda_policy(device),
        Err(error) if allow_absent && error.code() == "CALYX_CUDA_NO_DEVICE" => {
            Ok(CandleDevicePolicy::CpuNoCudaDevice)
        }
        Err(error) => Err(crate::runtime::common::forge_runtime_boundary_error(error)),
    }
}

#[cfg(all(feature = "candle-cuda", windows))]
fn cuda_policy_for_identity(
    identity: calyx_forge::PinnedCudaDeviceIdentity,
) -> Result<CandleDevicePolicy> {
    calyx_forge::select_pinned_cuda_device_by_identity(identity)
        .map_err(crate::runtime::common::forge_runtime_boundary_error)
        .and_then(executable_cuda_policy)
}

#[cfg(all(feature = "candle-cuda", windows))]
fn executable_cuda_policy(
    device: calyx_forge::PinnedCudaDeviceAttestation,
) -> Result<CandleDevicePolicy> {
    Ok(CandleDevicePolicy::CudaFailLoud {
        runtime_ordinal: usize::try_from(device.ordinal)
            .map_err(|_| frozen_device_invalid("attested CUDA Runtime ordinal exceeds usize"))?,
        driver_ordinal: usize::try_from(device.cuda_driver_ordinal)
            .map_err(|_| frozen_device_invalid("attested CUDA Driver ordinal exceeds usize"))?,
        identity: device.identity,
    })
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

#[cfg(not(feature = "candle-cuda"))]
fn cuda_policy_for_identity(
    _identity: calyx_forge::PinnedCudaDeviceIdentity,
) -> Result<CandleDevicePolicy> {
    Err(CalyxError::lens_unreachable(
        "a frozen CUDA lens was selected but calyx-registry was built without feature `candle-cuda`; select its explicit CPU companion LensId instead",
    ))
}

#[cfg(all(feature = "candle-cuda", not(windows)))]
fn cuda_policy_for_ordinal(
    _allow_absent: bool,
    _ordinal: usize,
    _ordinal_source: &str,
) -> Result<CandleDevicePolicy> {
    Err(CalyxError::lens_unreachable(
        "DEFERRED[ASTRO_PORT_PHASE]: the shared physical CUDA device boundary is currently Windows-only",
    ))
}

#[cfg(all(feature = "candle-cuda", not(windows)))]
fn cuda_policy_for_identity(
    _identity: calyx_forge::PinnedCudaDeviceIdentity,
) -> Result<CandleDevicePolicy> {
    Err(CalyxError::lens_unreachable(
        "DEFERRED[ASTRO_PORT_PHASE]: the shared physical CUDA device boundary is currently Windows-only",
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
