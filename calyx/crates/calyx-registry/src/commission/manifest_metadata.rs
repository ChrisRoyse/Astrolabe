use std::fs;
use std::path::{Path, PathBuf};

use calyx_core::{CalyxError, Result};

use crate::fastembed_execution::canonical_fastembed_execution;
use crate::frozen::{NormPolicy, sha256_digest};
use crate::runtime::adapters::{allow_noncommercial_from_env, ensure_license_allowed};
use crate::spec::{FastembedBgem3Output, LensRuntime, LensSpec};

use super::algorithmic_manifest::{algorithmic_kind, is_algorithmic_runtime};
use super::manifest::{LensForgeFile, LensForgeManifest, metadata_fastembed_weights_sha256};
use super::manifest_identity::spec_from_manifest_identity;
use super::manifest_runtime::{
    canonical_local_model_device, canonical_local_model_dtype, requires_artifact_set,
    validate_local_model_execution,
};
use super::source_tensor_profile::validate_manifest_source_tensor_profile;

const CONFIG_INVALID: &str = "CALYX_LENS_CONFIG_INVALID";

pub fn lens_spec_metadata_from_manifest_path(path: impl AsRef<Path>) -> Result<LensSpec> {
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
    lens_spec_metadata_from_manifest(&manifest, base)
}

pub fn lens_spec_metadata_from_manifest(
    manifest: &LensForgeManifest,
    base_dir: &Path,
) -> Result<LensSpec> {
    validate_required(manifest)?;
    ensure_license_allowed(
        manifest.license.as_deref(),
        manifest.non_commercial,
        allow_noncommercial_from_env(),
    )?;
    let output = manifest.output_shape()?;
    let weights_sha256 = metadata_weights_sha256(manifest, base_dir)?;
    let norm_policy = norm_policy(&manifest.norm)?;
    let runtime = metadata_runtime_from_manifest(manifest, base_dir)?;
    spec_from_manifest_identity(manifest, runtime, output, weights_sha256, norm_policy)
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
    if let Some(max_batch) = manifest.max_batch
        && max_batch == 0
    {
        return Err(config_invalid("lensforge manifest max_batch must be > 0"));
    }
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
    validate_declared_artifact_identity(manifest)?;
    Ok(())
}

fn validate_declared_artifact_identity(manifest: &LensForgeManifest) -> Result<()> {
    if is_algorithmic_runtime(&manifest.runtime) && manifest.files.is_empty() {
        return Ok(());
    }
    let ordered = ordered_manifest_files(&manifest.files);
    let anchor = ordered
        .iter()
        .copied()
        .find(|file| is_model_role(&file.role))
        .or_else(|| {
            is_adapter_runtime(&manifest.runtime)
                .then(|| ordered.iter().copied().find(|file| file.role == "adapter"))
                .flatten()
        })
        .ok_or_else(|| config_invalid("lensforge manifest requires a model file"))?;
    let declared = parse_hex_32(&manifest.weights_sha256)?;
    let anchored = parse_hex_32(&anchor.sha256)?;
    if declared != anchored {
        return Err(CalyxError::lens_frozen_violation(format!(
            "lensforge declared model weights sha256 {} != manifest file {}",
            manifest.weights_sha256, anchor.sha256
        )));
    }
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
    if let Some(artifact_set) = manifest.artifact_set_sha256.as_deref() {
        let _ = parse_hex_32(artifact_set)?;
    }
    Ok(())
}

fn is_adapter_runtime(runtime: &str) -> bool {
    matches!(
        runtime,
        "adapter" | "multimodal-adapter" | "multimodal_adapter"
    )
}

fn metadata_weights_sha256(manifest: &LensForgeManifest, base_dir: &Path) -> Result<[u8; 32]> {
    if is_algorithmic_runtime(&manifest.runtime) && manifest.files.is_empty() {
        return Ok(sha256_digest(&[
            b"lensforge-algorithmic-v1",
            manifest.name.as_bytes(),
            manifest.runtime.as_bytes(),
            &manifest.dim.to_be_bytes(),
            modality_token(manifest.modality).as_bytes(),
        ]));
    }
    if let Some(weights) = metadata_fastembed_weights_sha256(manifest, base_dir)? {
        return Ok(weights);
    }
    parse_hex_32(
        manifest
            .artifact_set_sha256
            .as_deref()
            .unwrap_or(&manifest.weights_sha256),
    )
}

fn metadata_runtime_from_manifest(
    manifest: &LensForgeManifest,
    base_dir: &Path,
) -> Result<LensRuntime> {
    if let Some(kind) = algorithmic_kind(&manifest.runtime) {
        return Ok(LensRuntime::Algorithmic {
            kind: kind.to_string(),
        });
    }
    let files = ordered_manifest_files(&manifest.files)
        .into_iter()
        .map(|file| ManifestFileRef {
            role: file.role.clone(),
            path: resolve_manifest_path(base_dir, &file.path),
        })
        .collect::<Vec<_>>();
    let file_paths = files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    match manifest.runtime.as_str() {
        "onnx" | "onnx-int8" | "onnx-custom" | "onnx-splade" => Ok(LensRuntime::Onnx {
            model_id: manifest.source_hf_id.clone(),
            files: file_paths,
        }),
        "onnx-fastembed" => Ok(LensRuntime::FastembedDensePlaced {
            model_id: manifest.source_hf_id.clone(),
            files: file_paths,
            execution: canonical_fastembed_execution(manifest.execution_device.as_deref())?,
        }),
        "onnx-colbert" => Ok(LensRuntime::OnnxColbert {
            model_id: manifest.source_hf_id.clone(),
            files: file_paths,
        }),
        "fastembed-sparse" => Ok(LensRuntime::FastembedSparsePlaced {
            model_id: manifest.source_hf_id.clone(),
            files: file_paths,
            execution: canonical_fastembed_execution(manifest.execution_device.as_deref())?,
        }),
        "fastembed-bgem3-dense" => Ok(LensRuntime::FastembedBgem3Placed {
            model_id: manifest.source_hf_id.clone(),
            files: file_paths,
            output: FastembedBgem3Output::Dense,
            execution: canonical_fastembed_execution(manifest.execution_device.as_deref())?,
        }),
        "fastembed-bgem3-sparse" => Ok(LensRuntime::FastembedBgem3Placed {
            model_id: manifest.source_hf_id.clone(),
            files: file_paths,
            output: FastembedBgem3Output::Sparse,
            execution: canonical_fastembed_execution(manifest.execution_device.as_deref())?,
        }),
        "fastembed-bgem3-colbert" => Ok(LensRuntime::FastembedBgem3Placed {
            model_id: manifest.source_hf_id.clone(),
            files: file_paths,
            output: FastembedBgem3Output::Colbert,
            execution: canonical_fastembed_execution(manifest.execution_device.as_deref())?,
        }),
        "fastembed-reranker" => Ok(LensRuntime::FastembedRerankerPlaced {
            model_id: manifest.source_hf_id.clone(),
            files: file_paths,
            execution: canonical_fastembed_execution(manifest.execution_device.as_deref())?,
        }),
        "fastembed-qwen3" => Ok(LensRuntime::FastembedQwen3 {
            model_id: manifest.source_hf_id.clone(),
            files: file_paths,
            device: canonical_local_model_device(
                &manifest.runtime,
                manifest.execution_device.as_deref(),
            )?
            .ok_or_else(|| config_invalid("matched Qwen3 runtime produced no execution device"))?,
            dtype: canonical_local_model_dtype(&manifest.runtime, &manifest.dtype)?
                .ok_or_else(|| config_invalid("matched Qwen3 runtime produced no dtype"))?
                .to_string(),
        }),
        "candle" | "candle-fp16" | "candle-local" => Ok(LensRuntime::CandleLocal {
            model_id: manifest.source_hf_id.clone(),
            files: file_paths,
            device: canonical_local_model_device(
                &manifest.runtime,
                manifest.execution_device.as_deref(),
            )?
            .ok_or_else(|| config_invalid("matched Candle runtime produced no execution device"))?,
            dtype: canonical_local_model_dtype(&manifest.runtime, &manifest.dtype)?
                .ok_or_else(|| config_invalid("matched Candle runtime produced no dtype"))?
                .to_string(),
            pooling: manifest.pooling.clone(),
        }),
        "tei" | "tei-http" | "tei_http" => Ok(LensRuntime::TeiHttp {
            endpoint: manifest
                .endpoint
                .clone()
                .ok_or_else(|| config_invalid("lensforge TEI endpoint is required"))?,
        }),
        "model2vec" | "static_lookup" | "static-lookup" => Ok(LensRuntime::StaticLookup {
            embeddings_file: file_by_role(&files, is_model_role)?,
            tokenizer: file_by_role(&files, |role| role == "tokenizer")?,
            dim: manifest.dim,
        }),
        "external-cmd" | "external_cmd" => Ok(LensRuntime::ExternalCmd {
            cmd: manifest.source_hf_id.clone(),
            args: file_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
        }),
        "adapter" | "multimodal-adapter" | "multimodal_adapter" => {
            Ok(LensRuntime::MultimodalAdapter {
                axis: modality_token(manifest.modality).to_string(),
                model_id: manifest.source_hf_id.clone(),
                adapter_config: Some(file_by_role(&files, |role| role == "adapter")?),
                files: file_paths,
            })
        }
        "model2vec-external" => Ok(LensRuntime::ExternalCmd {
            cmd: "model2vec".to_string(),
            args: file_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
        }),
        other => Err(config_invalid(format!(
            "unsupported lensforge runtime {other}"
        ))),
    }
}

#[derive(Clone, Debug)]
struct ManifestFileRef {
    role: String,
    path: PathBuf,
}

fn ordered_manifest_files(files: &[LensForgeFile]) -> Vec<&LensForgeFile> {
    let mut ordered = files.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|file| (role_rank(&file.role), file.path.clone()));
    ordered
}

fn role_rank(role: &str) -> u8 {
    match role {
        "model" | "weights" | "embeddings" => 0,
        "tokenizer" => 1,
        "config" => 2,
        "preprocessor" => 3,
        "tokenizer_config" => 4,
        "special_tokens_map" => 5,
        _ => 9,
    }
}

fn file_by_role(files: &[ManifestFileRef], predicate: impl Fn(&str) -> bool) -> Result<PathBuf> {
    files
        .iter()
        .find(|file| predicate(&file.role))
        .map(|file| file.path.clone())
        .ok_or_else(|| config_invalid("lensforge manifest missing static lookup artifact"))
}

fn is_model_role(role: &str) -> bool {
    matches!(role, "model" | "weights" | "embeddings")
}

fn is_tei_runtime(runtime: &str) -> bool {
    matches!(runtime, "tei" | "tei-http" | "tei_http")
}

fn resolve_manifest_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

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

fn modality_token(modality: calyx_core::Modality) -> &'static str {
    match modality {
        calyx_core::Modality::Text => "text",
        calyx_core::Modality::Code => "code",
        calyx_core::Modality::Image => "image",
        calyx_core::Modality::Audio => "audio",
        calyx_core::Modality::Video => "video",
        calyx_core::Modality::Protein => "protein",
        calyx_core::Modality::Dna => "dna",
        calyx_core::Modality::Molecule => "molecule",
        calyx_core::Modality::Structured => "structured",
        calyx_core::Modality::Mixed => "mixed",
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

fn config_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CONFIG_INVALID,
        message: message.into(),
        remediation: "fix the lensforge manifest or regenerated artifacts",
    }
}
