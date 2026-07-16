use std::path::PathBuf;

use calyx_core::{CalyxError, Result};

use super::algorithmic_manifest::algorithmic_kind;
use super::manifest::{LensForgeManifest, VerifiedFile, modality_token};
use crate::spec::{FastembedBgem3Output, LensRuntime};

pub(super) fn canonical_local_model_dtype(
    runtime: &str,
    dtype: &str,
) -> Result<Option<&'static str>> {
    if !matches!(
        runtime,
        "candle" | "candle-fp16" | "candle-local" | "fastembed-qwen3"
    ) {
        return Ok(None);
    }
    let canonical = match dtype.trim().to_ascii_lowercase().as_str() {
        "f16" | "fp16" | "float16" => "f16",
        "bf16" | "bfloat16" => "bf16",
        "f32" | "fp32" | "float32" => "f32",
        other => {
            return Err(config_invalid(format!(
                "unsupported {runtime} dtype {other}; expected f16, bf16, or f32"
            )));
        }
    };
    if runtime == "candle-fp16" && canonical != "f16" {
        return Err(config_invalid(format!(
            "legacy candle-fp16 runtime conflicts with dtype {canonical}; use runtime candle for bf16 or f32"
        )));
    }
    Ok(Some(canonical))
}

pub(crate) fn canonical_local_model_device(
    runtime: &str,
    device: Option<&str>,
) -> Result<Option<String>> {
    if !matches!(
        runtime,
        "candle" | "candle-fp16" | "candle-local" | "fastembed-qwen3"
    ) {
        return Ok(None);
    }
    let raw = device
        .ok_or_else(|| {
            config_invalid(format!(
                "{runtime} requires an explicit execution_device; migrate legacy manifests from evidence instead of inventing cuda:0"
            ))
        })?
        .trim()
        .to_ascii_lowercase();
    if raw == "cpu" {
        return Ok(Some(raw));
    }
    if raw == "cuda" {
        return Ok(Some("cuda:0".to_string()));
    }
    let Some(ordinal) = raw.strip_prefix("cuda:") else {
        return Err(config_invalid(format!(
            "unsupported {runtime} execution_device {raw}; expected cpu or cuda:<ordinal>"
        )));
    };
    let ordinal = ordinal.parse::<usize>().map_err(|_| {
        config_invalid(format!(
            "{runtime} execution_device {raw} has an invalid CUDA ordinal"
        ))
    })?;
    Ok(Some(format!("cuda:{ordinal}")))
}

pub(super) fn validate_local_model_execution(
    runtime: &str,
    dtype: &str,
    device: Option<&str>,
) -> Result<()> {
    let Some(dtype) = canonical_local_model_dtype(runtime, dtype)? else {
        if device.is_some() {
            return Err(config_invalid(format!(
                "runtime {runtime} does not consume execution_device; remove the inert declaration so the manifest cannot claim unbound placement"
            )));
        }
        return Ok(());
    };
    let device = canonical_local_model_device(runtime, device)?
        .ok_or_else(|| config_invalid("local model runtime produced no execution device"))?;
    if device == "cpu" && dtype != "f32" {
        return Err(config_invalid(format!(
            "{runtime} CPU execution requires f32, but the frozen manifest declares {dtype}; commission a distinct CPU f32 lens"
        )));
    }
    Ok(())
}

pub(super) fn requires_artifact_set(runtime: &str) -> bool {
    matches!(
        runtime,
        "candle"
            | "candle-fp16"
            | "candle-local"
            | "fastembed-qwen3"
            | "onnx"
            | "onnx-int8"
            | "onnx-custom"
            | "onnx-fastembed"
            | "onnx-splade"
            | "onnx-colbert"
            | "fastembed-sparse"
            | "fastembed-bgem3-dense"
            | "fastembed-bgem3-sparse"
            | "fastembed-bgem3-colbert"
            | "fastembed-reranker"
            | "model2vec"
            | "static_lookup"
            | "static-lookup"
            | "adapter"
            | "multimodal-adapter"
            | "multimodal_adapter"
    )
}

pub(super) fn runtime_from_manifest(
    manifest: &LensForgeManifest,
    artifacts: &[VerifiedFile],
) -> Result<LensRuntime> {
    if let Some(kind) = algorithmic_kind(&manifest.runtime) {
        return Ok(LensRuntime::Algorithmic {
            kind: kind.to_string(),
        });
    }
    let files = artifacts
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    match manifest.runtime.as_str() {
        "onnx" | "onnx-int8" | "onnx-custom" | "onnx-fastembed" | "onnx-splade" => {
            Ok(LensRuntime::Onnx {
                model_id: manifest.source_hf_id.clone(),
                files,
            })
        }
        "onnx-colbert" => Ok(LensRuntime::OnnxColbert {
            model_id: manifest.source_hf_id.clone(),
            files,
        }),
        "fastembed-sparse" => Ok(LensRuntime::FastembedSparse {
            model_id: manifest.source_hf_id.clone(),
            files,
        }),
        "fastembed-bgem3-dense" => Ok(fastembed_bgem3_runtime(
            manifest,
            files,
            FastembedBgem3Output::Dense,
        )),
        "fastembed-bgem3-sparse" => Ok(fastembed_bgem3_runtime(
            manifest,
            files,
            FastembedBgem3Output::Sparse,
        )),
        "fastembed-bgem3-colbert" => Ok(fastembed_bgem3_runtime(
            manifest,
            files,
            FastembedBgem3Output::Colbert,
        )),
        "fastembed-reranker" => Ok(LensRuntime::FastembedReranker {
            model_id: manifest.source_hf_id.clone(),
            files,
        }),
        "fastembed-qwen3" => Ok(LensRuntime::FastembedQwen3 {
            model_id: manifest.source_hf_id.clone(),
            files,
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
            files,
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
            embeddings_file: artifact_by_role(artifacts, is_model_role)?,
            tokenizer: artifact_by_role(artifacts, |role| role == "tokenizer")?,
            dim: manifest.dim,
        }),
        "external-cmd" | "external_cmd" => Ok(LensRuntime::ExternalCmd {
            cmd: manifest.source_hf_id.clone(),
            args: artifact_args(artifacts),
        }),
        "adapter" | "multimodal-adapter" | "multimodal_adapter" => {
            let adapter_config = artifact_by_role(artifacts, |role| role == "adapter")?;
            Ok(LensRuntime::MultimodalAdapter {
                axis: modality_token(manifest.modality).to_string(),
                model_id: manifest.source_hf_id.clone(),
                adapter_config: Some(adapter_config),
                files,
            })
        }
        "model2vec-external" => Ok(LensRuntime::ExternalCmd {
            cmd: "model2vec".to_string(),
            args: files
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
        }),
        other => Err(config_invalid(format!(
            "unsupported lensforge runtime {other}"
        ))),
    }
}

fn fastembed_bgem3_runtime(
    manifest: &LensForgeManifest,
    files: Vec<PathBuf>,
    output: FastembedBgem3Output,
) -> LensRuntime {
    LensRuntime::FastembedBgem3 {
        model_id: manifest.source_hf_id.clone(),
        files,
        output,
    }
}

fn artifact_args(artifacts: &[VerifiedFile]) -> Vec<String> {
    artifacts
        .iter()
        .map(|file| file.path.display().to_string())
        .collect()
}

fn artifact_by_role(
    artifacts: &[VerifiedFile],
    predicate: impl Fn(&str) -> bool,
) -> Result<PathBuf> {
    artifacts
        .iter()
        .find(|file| predicate(&file.role))
        .map(|file| file.path.clone())
        .ok_or_else(|| config_invalid("lensforge manifest missing static lookup artifact"))
}

fn is_model_role(role: &str) -> bool {
    matches!(role, "model" | "weights" | "embeddings")
}

fn config_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_CONFIG_INVALID",
        message: message.into(),
        remediation: "fix the lensforge manifest or regenerated artifacts",
    }
}
