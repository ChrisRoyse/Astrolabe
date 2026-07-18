use std::cell::Cell;
use std::collections::BTreeSet;
#[cfg(feature = "ml-runtime")]
use std::env;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use calyx_core::{CalyxError, Result};
#[cfg(feature = "ml-runtime")]
use calyx_core::{Input, Lens, RuntimeExecutionAttestation};
#[cfg(feature = "ml-runtime")]
use candle_core::{DType, Device, Tensor};

use crate::frozen::LengthDelimitedSha256;
#[cfg(feature = "ml-runtime")]
use crate::lens::ensure_input_modality;

#[cfg(all(windows, feature = "candle-cuda"))]
pub(crate) fn initialize_pinned_cuda_dependencies() -> Result<()> {
    calyx_forge::cuda_runtime::initialize_pinned_cuda_dependencies()
        .map(|_| ())
        .map_err(forge_runtime_boundary_error)
}

#[cfg(all(windows, feature = "candle-cuda"))]
pub(crate) fn attest_pinned_cuda_dependencies() -> Result<()> {
    calyx_forge::cuda_runtime::attest_pinned_cuda_dependencies()
        .map(|_| ())
        .map_err(forge_runtime_boundary_error)
}

#[cfg(all(windows, feature = "candle-cuda"))]
pub(crate) fn attest_candle_cuda_device(
    runtime: &str,
    device: &Device,
    selected: &calyx_forge::PinnedCudaDeviceAttestation,
) -> Result<()> {
    let expected_driver = usize::try_from(selected.cuda_driver_ordinal).map_err(|_| {
        CalyxError::lens_frozen_violation(format!(
            "{runtime} attested CUDA Driver ordinal {} exceeds usize",
            selected.cuda_driver_ordinal
        ))
    })?;
    match device.location() {
        candle_core::DeviceLocation::Cuda { gpu_id } if gpu_id == expected_driver => {}
        observed => {
            return Err(CalyxError::lens_frozen_violation(format!(
                "{runtime} constructed device location {observed:?}; expected CUDA Driver ordinal {expected_driver} for {}",
                selected.identity
            )));
        }
    }
    let stream = device
        .as_cuda_device()
        .map_err(|error| {
            CalyxError::lens_frozen_violation(format!(
                "{runtime} constructed device cannot expose its CUDA stream for identity readback: {error}"
            ))
        })?
        .cuda_stream();
    calyx_forge::attest_cudarc_context(
        stream.context().as_ref(),
        selected.cuda_driver_ordinal,
        selected.identity,
    )
    .map_err(forge_runtime_boundary_error)?;
    attest_pinned_cuda_dependencies()
}

#[cfg(feature = "ml-runtime")]
pub(crate) fn forge_runtime_boundary_error(error: calyx_forge::ForgeError) -> CalyxError {
    match error {
        calyx_forge::ForgeError::RuntimeBoundary {
            code,
            detail,
            remediation,
        } => CalyxError {
            code,
            message: detail,
            remediation,
        },
        other => {
            CalyxError::lens_unreachable(format!("pinned CUDA runtime boundary failed: {other}"))
        }
    }
}

#[cfg(feature = "ml-runtime")]
pub const DEFAULT_MAX_TOKENS: usize = 512;
const STREAM_HASH_BUFFER_BYTES: usize = 1024 * 1024;

#[cfg(feature = "ml-runtime")]
#[derive(Clone, Debug)]
pub(crate) struct LocalModelExecutionAttestation {
    pub(crate) loader_target_dtype: &'static str,
    pub(crate) observed_primary_activation_dtype: &'static str,
    pub(crate) observed_device: String,
    pub(crate) evidence_kind: &'static str,
}

#[cfg(feature = "ml-runtime")]
impl LocalModelExecutionAttestation {
    pub(crate) fn runtime_attestation(&self, runtime: &str) -> RuntimeExecutionAttestation {
        let provider = if self.observed_device.starts_with("cuda:") {
            "candle_cuda"
        } else {
            "candle_cpu"
        };
        RuntimeExecutionAttestation {
            runtime: runtime.to_string(),
            provider: provider.to_string(),
            device: self.observed_device.clone(),
            loader_dtype: Some(self.loader_target_dtype.to_string()),
            compute_dtype: Some(self.observed_primary_activation_dtype.to_string()),
            evidence: self.evidence_kind.to_string(),
            total_compute_nodes: None,
            cpu_compute_nodes: None,
        }
    }
}

#[cfg(feature = "ml-runtime")]
pub(crate) fn gpu_synchronization_failed(
    runtime: &str,
    stage: &str,
    error: impl std::fmt::Display,
) -> CalyxError {
    CalyxError {
        code: "CALYX_GPU_SYNCHRONIZATION_FAILED",
        message: format!("{runtime} GPU synchronization failed at {stage}: {error}"),
        remediation: "invalidate and reap the resident GPU worker, inspect the preceding CUDA/ORT logs and physical-device attestation, and repair the GPU runtime; never retry this failure on CPU",
    }
}

#[cfg(feature = "ml-runtime")]
pub(crate) fn synchronize_candle_gpu_after_host_materialization(
    runtime: &str,
    device: &Device,
) -> Result<()> {
    device
        .synchronize()
        .map_err(|error| gpu_synchronization_failed(runtime, "after_host_materialization", error))
}

#[cfg(feature = "ml-runtime")]
pub(crate) fn attest_primary_activation(
    runtime: &str,
    hidden: &Tensor,
    expected_dtype: DType,
    expected_device: &Device,
    expected_device_token: &str,
) -> Result<LocalModelExecutionAttestation> {
    let loader_target_dtype = dtype_token(expected_dtype)?;
    let observed_primary_activation_dtype = dtype_token(hidden.dtype())?;
    if hidden.dtype() != expected_dtype {
        return Err(CalyxError::lens_frozen_violation(format!(
            "{runtime} dtype attestation failed: loader_target_dtype={loader_target_dtype} observed_primary_activation_dtype={observed_primary_activation_dtype}"
        )));
    }
    if !hidden.device().same_device(expected_device) {
        return Err(CalyxError::lens_frozen_violation(format!(
            "{runtime} device attestation failed: expected={expected_device_token} observed={:?}",
            hidden.device().location()
        )));
    }
    let values = hidden
        .flatten_all()
        .and_then(|tensor| tensor.to_dtype(DType::F32))
        .and_then(|tensor| tensor.to_vec1::<f32>())
        .map_err(|error| {
            CalyxError::lens_numerical_invariant(format!(
                "{runtime} full-forward dtype attestation readback failed: {error}"
            ))
        })?;
    if values.is_empty() {
        return Err(CalyxError::lens_numerical_invariant(format!(
            "{runtime} full-forward dtype attestation produced an empty primary activation"
        )));
    }
    if values.iter().any(|value| !value.is_finite()) {
        return Err(CalyxError::lens_numerical_invariant(format!(
            "{runtime} full-forward dtype attestation produced NaN or Inf"
        )));
    }
    Ok(LocalModelExecutionAttestation {
        loader_target_dtype,
        observed_primary_activation_dtype,
        observed_device: expected_device_token.to_string(),
        evidence_kind: "full_forward_hidden_tensor",
    })
}

#[cfg(feature = "ml-runtime")]
fn dtype_token(dtype: DType) -> Result<&'static str> {
    match dtype {
        DType::F16 => Ok("f16"),
        DType::BF16 => Ok("bf16"),
        DType::F32 => Ok("f32"),
        other => Err(CalyxError::lens_frozen_violation(format!(
            "local model dtype attestation does not support {other:?}"
        ))),
    }
}

pub(crate) fn validate_contract_covers_loaded_paths(
    runtime: &str,
    loaded_paths: &[PathBuf],
    contract_paths: &[PathBuf],
) -> Result<()> {
    let mut contract = BTreeSet::new();
    for path in contract_paths {
        let canonical = fs::canonicalize(path).map_err(|error| CalyxError {
            code: "CALYX_LENS_CONFIG_INVALID",
            message: format!(
                "canonicalize {runtime} contract artifact {} failed: {error}",
                path.display()
            ),
            remediation: "commission a complete immutable artifact set and preserve every loaded path in the frozen contract",
        })?;
        if !contract.insert(canonical.clone()) {
            return Err(CalyxError {
                code: "CALYX_LENS_CONFIG_INVALID",
                message: format!(
                    "{runtime} contract contains duplicate artifact {}",
                    canonical.display()
                ),
                remediation: "remove duplicate artifact paths and recommission the frozen lens",
            });
        }
    }
    for path in loaded_paths {
        let canonical = fs::canonicalize(path).map_err(|error| CalyxError {
            code: "CALYX_LENS_CONFIG_INVALID",
            message: format!(
                "canonicalize {runtime} loaded artifact {} failed: {error}",
                path.display()
            ),
            remediation: "restore the exact commissioned artifact and retry",
        })?;
        if !contract.contains(&canonical) {
            return Err(CalyxError {
                code: "CALYX_LENS_CONFIG_INVALID",
                message: format!(
                    "{runtime} loads artifact {} outside its frozen artifact set",
                    canonical.display()
                ),
                remediation: "include every loaded weight, tokenizer, and config artifact in artifact_set_sha256 and recommission",
            });
        }
    }
    Ok(())
}

thread_local! {
    static SCOPED_RUNTIME_BATCH_LIMIT: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Run `run` with a process-wide (per-thread) runtime batch-limit override in
/// scope. Lives here — rather than in the ML-only `onnx` module — so the
/// registry batch-measurement path (`runtime_limit`, `persistence::runtime`)
/// stays available when the `ml-runtime` feature is off (#297). Data-oblivious:
/// pure thread-local swap, no ML dependency.
pub(crate) fn with_runtime_batch_limit<T>(
    limit: Option<usize>,
    run: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if limit == Some(0) {
        return Err(CalyxError::lens_unreachable(
            "runtime batch limit must be > 0 when supplied",
        ));
    }
    SCOPED_RUNTIME_BATCH_LIMIT.with(|slot| {
        let previous = slot.replace(limit);
        let result = run();
        slot.set(previous);
        result
    })
}

/// Current scoped runtime batch limit, if any. Read by the ONNX runtime's
/// `scoped_max_batch` when the `ml-runtime` feature is enabled.
#[cfg(feature = "ml-runtime")]
pub(crate) fn scoped_runtime_batch_limit() -> Option<usize> {
    SCOPED_RUNTIME_BATCH_LIMIT.with(Cell::get)
}

#[cfg(feature = "ml-runtime")]
pub fn default_hf_cache_root() -> PathBuf {
    if let Some(path) = env::var_os("HF_HOME") {
        return PathBuf::from(path);
    }
    if let Some(path) = env::var_os("CALYX_HOME") {
        return PathBuf::from(path).join(".hf-cache");
    }
    PathBuf::from(".hf-cache")
}

#[cfg(feature = "ml-runtime")]
pub fn fastembed_cache_root(default_cache: &Path) -> PathBuf {
    env::var_os("HF_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_cache.to_path_buf())
}

pub fn hash_files(paths: &[PathBuf]) -> Result<[u8; 32]> {
    let mut hasher = LengthDelimitedSha256::new();
    let mut buffer = vec![0_u8; STREAM_HASH_BUFFER_BYTES];
    for path in paths {
        hash_file_into(path, &mut hasher, &mut buffer)?;
    }
    Ok(hasher.finalize())
}

fn hash_file_into(
    path: &Path,
    hasher: &mut LengthDelimitedSha256,
    buffer: &mut [u8],
) -> Result<()> {
    let file = fs::File::open(path).map_err(|err| {
        CalyxError::lens_unreachable(format!(
            "open lens artifact {} for hashing failed: {err}",
            path.display()
        ))
    })?;
    let len = file.metadata().map_err(|err| {
        CalyxError::lens_unreachable(format!(
            "stat lens artifact {} for hashing failed: {err}",
            path.display()
        ))
    })?;
    hasher.begin_part(len.len());
    let mut reader = BufReader::new(file);
    loop {
        let read = reader.read(buffer).map_err(|err| {
            CalyxError::lens_unreachable(format!(
                "read lens artifact {} while hashing failed: {err}",
                path.display()
            ))
        })?;
        if read == 0 {
            return Ok(());
        }
        hasher.update_chunk(&buffer[..read]);
    }
}

#[cfg(feature = "ml-runtime")]
pub fn text_from_input<'a>(lens: &dyn Lens, input: &'a Input) -> Result<&'a str> {
    ensure_input_modality(lens, input)?;
    std::str::from_utf8(&input.bytes).map_err(|err| {
        CalyxError::lens_dim_mismatch(format!("lens {} input is not UTF-8: {err}", lens.id()))
    })
}

pub fn normalize_unit(data: &mut [f32]) -> Result<()> {
    if data.iter().any(|value| !value.is_finite()) {
        return Err(CalyxError::lens_numerical_invariant(
            "local neural lens emitted NaN or Inf",
        ));
    }
    let sum = data
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>();
    let norm = sum.sqrt();
    if !norm.is_finite() || norm <= 0.0 {
        return Err(CalyxError::lens_numerical_invariant(
            "local neural lens emitted zero-norm vector",
        ));
    }
    for value in data {
        *value = (*value as f64 / norm) as f32;
    }
    Ok(())
}
