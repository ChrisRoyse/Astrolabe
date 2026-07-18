use std::fs;
use std::path::{Path, PathBuf};

use calyx_core::{CalyxError, LensId, Modality, QuantPolicy, Result, SlotShape, content_address};
use serde::{Deserialize, Serialize};

use crate::frozen::{LengthDelimitedSha256, NormPolicy, sha256_digest};
use crate::runtime::adapters::{allow_noncommercial_from_env, ensure_license_allowed};
use crate::spec::{LensRuntime, LensSpec};

use super::algorithmic_manifest::{
    frozen_contract as algorithmic_frozen_contract, is_algorithmic_runtime,
    output_shape as algorithmic_output_shape,
};
use super::manifest_identity::spec_from_manifest_identity;
use super::manifest_runtime::{
    requires_artifact_set, runtime_from_manifest, validate_local_model_execution,
};
use super::onnx_int8::{OnnxInt8Attestation, verify_manifest_onnx_int8_attestation};
use super::source_tensor_profile::{
    LensForgeSourceTensorDtypeProfile, validate_manifest_source_tensor_profile,
};
#[cfg(feature = "ml-runtime")]
use super::source_tensor_profile::{profile_safetensors_sources, resolve_safetensors_weight_set};

const CONFIG_INVALID: &str = "CALYX_LENS_CONFIG_INVALID";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LensForgeFile {
    pub role: String,
    pub path: PathBuf,
    pub sha256: String,
    #[serde(default)]
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LensForgeShape {
    Dense { dim: u32 },
    Sparse { dim: u32 },
    Multi { token_dim: u32 },
}

impl LensForgeShape {
    pub fn from_slot_shape(shape: SlotShape) -> Self {
        match shape {
            SlotShape::Dense(dim) => Self::Dense { dim },
            SlotShape::Sparse(dim) => Self::Sparse { dim },
            SlotShape::Multi { token_dim } => Self::Multi { token_dim },
        }
    }

    pub fn to_slot_shape(self) -> SlotShape {
        match self {
            Self::Dense { dim } => SlotShape::Dense(dim),
            Self::Sparse { dim } => SlotShape::Sparse(dim),
            Self::Multi { token_dim } => SlotShape::Multi { token_dim },
        }
    }

    pub fn dim(self) -> u32 {
        match self {
            Self::Dense { dim } | Self::Sparse { dim } => dim,
            Self::Multi { token_dim } => token_dim,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LensForgeManifest {
    pub name: String,
    pub modality: Modality,
    pub runtime: String,
    pub dim: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<LensForgeShape>,
    pub dtype: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tensor_dtype_profile: Option<LensForgeSourceTensorDtypeProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onnx_int8_attestation: Option<OnnxInt8Attestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_device: Option<String>,
    pub weights_sha256: String,
    #[serde(default)]
    pub artifact_set_sha256: Option<String>,
    pub files: Vec<LensForgeFile>,
    pub pooling: String,
    pub norm: String,
    pub source_hf_id: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub non_commercial: bool,
    #[serde(default = "crate::spec::default_quant_default")]
    pub quant_default: QuantPolicy,
    #[serde(default)]
    pub truncate_dim: Option<u32>,
    #[serde(default = "crate::spec::default_recall_delta")]
    pub recall_delta: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_batch: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_policy: Option<LensForgeBatchPolicy>,
}

/// Commission-time batch-limit provenance (#1157). GPU lenses must never be
/// pinned at `max_batch: 1` without evidence: this records where `max_batch`
/// came from (measured preflight vs operator assertion), the per-level probe
/// results, and the explicit operator justification when a batch-1 or an
/// unverified commission was allowed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LensForgeBatchPolicy {
    /// `preflight-measured` (probe ran, max_batch = largest passing level),
    /// `operator-verified` (operator requested max_batch, probe confirmed it),
    /// or `operator-unverified` (preflight explicitly skipped).
    pub max_batch_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_1_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_skip_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_cap: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preflight_levels: Vec<LensForgeBatchProbeLevel>,
}

/// One measured batch level from the commission preflight probe.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LensForgeBatchProbeLevel {
    pub batch: usize,
    pub passed: bool,
    pub elapsed_ms: u64,
    pub ms_per_row: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_cosine_vs_single: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_abs_delta_vs_single: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

impl LensForgeManifest {
    pub fn output_shape(&self) -> Result<SlotShape> {
        let derived = algorithmic_output_shape(&self.runtime, self.dim)?;
        let Some(shape) = self.shape else {
            return Ok(derived);
        };
        if shape.dim() != self.dim {
            return Err(config_invalid(format!(
                "lensforge manifest shape dim {} != dim {}",
                shape.dim(),
                self.dim
            )));
        }
        let declared = shape.to_slot_shape();
        if declared != derived {
            return Err(config_invalid(format!(
                "lensforge manifest shape {declared:?} does not match runtime {} dim {} ({derived:?})",
                self.runtime, self.dim
            )));
        }
        Ok(declared)
    }
}

pub fn lens_spec_from_manifest_path(path: impl AsRef<Path>) -> Result<LensSpec> {
    lens_spec_and_onnx_int8_attestation_from_manifest_path(path).map(|(spec, _)| spec)
}

/// Parses and verifies one manifest snapshot, returning both its lens spec and
/// the semantic ONNX INT8 attestation carried by that same verified snapshot.
pub fn lens_spec_and_onnx_int8_attestation_from_manifest_path(
    path: impl AsRef<Path>,
) -> Result<(LensSpec, Option<OnnxInt8Attestation>)> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|err| {
        config_invalid(format!(
            "read lensforge manifest {} failed: {err}",
            path.display()
        ))
    })?;
    let manifest: LensForgeManifest = serde_json::from_slice(&bytes).map_err(|err| {
        config_invalid(format!(
            "parse lensforge manifest {} failed: {err}",
            path.display()
        ))
    })?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let spec = lens_spec_from_manifest(&manifest, base)?;
    Ok((spec, manifest.onnx_int8_attestation))
}

/// Reconstructs IDs written by the retired spec-side manifest formulas.
///
/// These candidates are diagnostic-only. They must never be registered or
/// persisted as current frozen identities.
pub fn legacy_lensforge_manifest_v1_ids_from_path(path: impl AsRef<Path>) -> Result<Vec<LensId>> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|err| {
        config_invalid(format!(
            "read legacy lensforge manifest {} failed: {err}",
            path.display()
        ))
    })?;
    let manifest: LensForgeManifest = serde_json::from_slice(&bytes).map_err(|err| {
        config_invalid(format!(
            "parse legacy lensforge manifest {} failed: {err}",
            path.display()
        ))
    })?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    legacy_lensforge_manifest_v1_ids(&manifest, base)
}

fn legacy_lensforge_manifest_v1_ids(
    manifest: &LensForgeManifest,
    base_dir: &Path,
) -> Result<Vec<LensId>> {
    let artifacts = read_and_verify_files(manifest, base_dir)?;
    let output = manifest.output_shape()?;
    let (output, weights_sha256, corpus_hash, norm_policy) = if let Some(contract) =
        algorithmic_frozen_contract(&manifest.name, &manifest.runtime, manifest.modality, output)?
    {
        (
            contract.shape(),
            contract.weights_sha256(),
            contract.corpus_hash(),
            contract.norm_policy(),
        )
    } else {
        (
            output,
            spec_weights_sha256(manifest, &artifacts)?,
            sha256_digest(&[
                b"lensforge-manifest-v1",
                manifest.name.as_bytes(),
                manifest.source_hf_id.as_bytes(),
                manifest.runtime.as_bytes(),
                modality_token(manifest.modality).as_bytes(),
                manifest.pooling.as_bytes(),
                manifest.norm.as_bytes(),
            ]),
            norm_policy(&manifest.norm)?,
        )
    };
    let runtime = runtime_from_manifest(manifest, &artifacts)?;
    let mut runtime_debugs = vec![format!("{runtime:?}")];
    let files = artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let pre_gpu_runtime = match &runtime {
        LensRuntime::CandleLocal { .. } => Some(format!(
            "CandleLocal {{ model_id: {:?}, files: {:?}, dtype: {:?}, pooling: {:?} }}",
            manifest.source_hf_id, files, manifest.dtype, manifest.pooling
        )),
        LensRuntime::FastembedQwen3 { .. } => Some(format!(
            "FastembedQwen3 {{ model_id: {:?}, files: {:?}, dtype: {:?} }}",
            manifest.source_hf_id, files, manifest.dtype
        )),
        _ => None,
    };
    if let Some(debug) = pre_gpu_runtime {
        if !runtime_debugs.contains(&debug) {
            runtime_debugs.push(debug);
        }
    }
    Ok(runtime_debugs
        .into_iter()
        .map(|runtime_debug| {
            let output = format!("shape={output:?};norm={norm_policy:?};runtime={runtime_debug}");
            LensId::from_bytes(content_address([
                manifest.name.as_bytes(),
                &weights_sha256,
                &corpus_hash,
                output.as_bytes(),
            ]))
        })
        .collect())
}

pub fn lens_spec_from_manifest(manifest: &LensForgeManifest, base_dir: &Path) -> Result<LensSpec> {
    lens_spec_from_manifest_with_license_override(
        manifest,
        base_dir,
        allow_noncommercial_from_env(),
    )
}

pub fn lens_spec_from_manifest_with_license_override(
    manifest: &LensForgeManifest,
    base_dir: &Path,
    allow_non_commercial: bool,
) -> Result<LensSpec> {
    validate_required(manifest)?;
    verify_manifest_onnx_int8_attestation(manifest, base_dir)?;
    if manifest.max_batch == Some(0) {
        return Err(config_invalid("lensforge manifest max_batch must be > 0"));
    }
    ensure_license_allowed(
        manifest.license.as_deref(),
        manifest.non_commercial,
        allow_non_commercial,
    )?;
    let artifacts = read_and_verify_files(manifest, base_dir)?;
    #[cfg(feature = "ml-runtime")]
    validate_source_tensor_profile_bytes(manifest, &artifacts)?;
    let output = manifest.output_shape()?;
    let weights_sha256 = spec_weights_sha256(manifest, &artifacts)?;
    let norm_policy = norm_policy(&manifest.norm)?;
    let runtime = runtime_from_manifest(manifest, &artifacts)?;
    let spec = spec_from_manifest_identity(manifest, runtime, output, weights_sha256, norm_policy)?;
    crate::validate_quant_policy_for_shape(&spec.name, spec.output, spec.quant_default)?;
    let declared = spec.declared_contract();
    let observed = crate::persistence_contracts::derive_runtime_contract_from_spec(&spec)?;
    if declared != observed {
        return Err(CalyxError::lens_frozen_violation(format!(
            "manifest {} declares lens {} but non-loading artifact inspection derives {}; recommission instead of persisting conflicting identity",
            manifest.name,
            declared.lens_id(),
            observed.lens_id()
        )));
    }
    Ok(spec)
}

fn validate_required(manifest: &LensForgeManifest) -> Result<()> {
    if manifest.name.trim().is_empty() {
        return Err(config_invalid("lensforge manifest name is required"));
    }
    if manifest.source_hf_id.trim().is_empty() {
        return Err(config_invalid(
            "lensforge manifest source_hf_id is required",
        ));
    }
    if manifest.runtime.trim().is_empty() {
        return Err(config_invalid("lensforge manifest runtime is required"));
    }
    validate_local_model_execution(
        &manifest.runtime,
        &manifest.dtype,
        manifest.execution_device.as_deref(),
    )?;
    validate_manifest_source_tensor_profile(
        &manifest.runtime,
        manifest.source_tensor_dtype_profile.as_ref(),
    )?;
    if requires_artifact_set(&manifest.runtime)
        && manifest
            .artifact_set_sha256
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err(config_invalid(
            "artifact-backed manifest requires artifact_set_sha256 covering every executable artifact",
        ));
    }
    if is_tei_runtime(&manifest.runtime)
        && manifest
            .endpoint
            .as_deref()
            .is_none_or(|endpoint| endpoint.trim().is_empty())
    {
        return Err(config_invalid(
            "lensforge TEI manifest endpoint is required",
        ));
    }
    if manifest.dim == 0 {
        return Err(config_invalid("lensforge manifest dim must be > 0"));
    }
    let _ = manifest.output_shape()?;
    if let Some(truncate_dim) = manifest.truncate_dim
        && (truncate_dim == 0 || truncate_dim > manifest.dim)
    {
        return Err(config_invalid(format!(
            "truncate_dim {truncate_dim} must be in 1..={}",
            manifest.dim
        )));
    }
    if !manifest.recall_delta.is_finite() || manifest.recall_delta < 0.0 {
        return Err(config_invalid(
            "recall_delta must be finite and non-negative",
        ));
    }
    if manifest.files.is_empty() && !is_algorithmic_runtime(&manifest.runtime) {
        return Err(config_invalid("lensforge manifest files are required"));
    }
    Ok(())
}

#[cfg(feature = "ml-runtime")]
fn validate_source_tensor_profile_bytes(
    manifest: &LensForgeManifest,
    artifacts: &[VerifiedFile],
) -> Result<()> {
    if !matches!(
        manifest.runtime.as_str(),
        "candle" | "candle-fp16" | "candle-local" | "fastembed-qwen3"
    ) {
        return Ok(());
    }
    let declared = manifest
        .source_tensor_dtype_profile
        .as_ref()
        .ok_or_else(|| {
            config_invalid("local learned manifest source tensor dtype profile is required")
        })?;
    let safetensors = artifacts
        .iter()
        .filter(|file| {
            file.path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("safetensors"))
        })
        .collect::<Vec<_>>();
    if safetensors.is_empty() {
        return Err(config_invalid(
            "local learned manifest has no safetensors model/weights artifacts",
        ));
    }
    if let Some(file) = safetensors
        .iter()
        .find(|file| !matches!(file.role.as_str(), "model" | "weights"))
    {
        return Err(config_invalid(format!(
            "local learned manifest safetensors artifact {} has inert role {}; use model or weights",
            file.path.display(),
            file.role
        )));
    }
    let paths = safetensors
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    let weights = resolve_safetensors_weight_set(&manifest.runtime, &paths)?;
    let observed = profile_safetensors_sources(&weights)?;
    if &observed != declared {
        return Err(CalyxError::lens_frozen_violation(format!(
            "{} source tensor dtype profile does not match verified safetensors artifacts: declared={} observed={}",
            manifest.runtime,
            declared.summary(),
            observed.summary()
        )));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(super) struct VerifiedFile {
    pub(super) role: String,
    pub(super) path: PathBuf,
    sha256: String,
    /// The single immutable byte snapshot every derived view of this artifact
    /// must read from, so the frozen digest, source profile, and any downstream
    /// hashing provably come from one byte set (#524). `sha256` above mirrors
    /// this snapshot's digest for callers that only need the hex.
    snapshot: std::sync::Arc<super::frozen_snapshot::FrozenArtifactSnapshot>,
}

mod artifacts;
pub(super) use artifacts::metadata_fastembed_weights_sha256;
use artifacts::{is_tei_runtime, read_and_verify_files, spec_weights_sha256};

fn norm_policy(raw: &str) -> Result<NormPolicy> {
    match raw {
        "l2" | "unit" => Ok(NormPolicy::unit()),
        "finite" => Ok(NormPolicy::Finite),
        "none" => Ok(NormPolicy::None),
        other => Err(config_invalid(format!(
            "unsupported lensforge norm {other}"
        ))),
    }
}

pub(super) fn modality_token(modality: Modality) -> &'static str {
    match modality {
        Modality::Text => "text",
        Modality::Code => "code",
        Modality::Image => "image",
        Modality::Audio => "audio",
        Modality::Video => "video",
        Modality::Protein => "protein",
        Modality::Dna => "dna",
        Modality::Molecule => "molecule",
        Modality::Structured => "structured",
        Modality::Mixed => "mixed",
    }
}

fn parse_hex_32(raw: &str) -> Result<[u8; 32]> {
    let value = raw.trim();
    if value.len() != 64 {
        return Err(config_invalid(format!(
            "expected 64 hex chars, got {}",
            value.len()
        )));
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|err| config_invalid(format!("invalid hex utf8: {err}")))?;
        out[idx] = u8::from_str_radix(text, 16)
            .map_err(|err| config_invalid(format!("invalid hex digest: {err}")))?;
    }
    Ok(out)
}

fn hex_from_bytes(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right.trim())
}

fn config_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CONFIG_INVALID,
        message: message.into(),
        remediation: "fix the lensforge manifest or regenerated artifacts",
    }
}
