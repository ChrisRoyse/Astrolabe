use calyx_core::{Asymmetry, CalyxError, Modality, Result, SlotShape};

use crate::frozen::{FrozenLensContract, NormPolicy};
use crate::identity::{
    CANDLE_DEFAULT_MAX_TOKENS, ContractFacts, QWEN3_DEFAULT_MAX_TOKENS,
    candle_execution_corpus_hash, contract_from_facts, external_command_corpus_hash,
    external_command_weights_hash, fastembed_bgem3_corpus_hash, fastembed_dense_corpus_hash,
    fastembed_reranker_corpus_hash, fastembed_sparse_corpus_hash, multimodal_adapter_corpus_hash,
    onnx_colbert_corpus_hash, onnx_custom_corpus_hash, qwen3_execution_corpus_hash,
    static_lookup_corpus_hash,
};
use crate::spec::{FastembedBgem3Output, LensRuntime, LensSpec};

use super::algorithmic_manifest::frozen_contract as algorithmic_frozen_contract;
use super::manifest::LensForgeManifest;

const CONFIG_INVALID: &str = "CALYX_LENS_CONFIG_INVALID";
const DEFAULT_QWEN3_MODEL: &str = "Qwen/Qwen3-Embedding-0.6B";

fn legacy_unbound_fastembed_identity() -> CalyxError {
    CalyxError {
        code: "CALYX_FASTEMBED_LEGACY_EXECUTION_UNBOUND",
        message: "legacy FastEmbed runtime has no frozen execution-policy identity".into(),
        remediation: "recommission from a manifest so the runtime is placement-bound; never infer CPU or CUDA from legacy persisted bytes",
    }
}

pub(super) fn spec_from_manifest_identity(
    manifest: &LensForgeManifest,
    runtime: LensRuntime,
    output: SlotShape,
    weights_sha256: [u8; 32],
    norm_policy: NormPolicy,
) -> Result<LensSpec> {
    let runtime = canonical_runtime(runtime)?;
    let contract = declared_contract(manifest, &runtime, output, weights_sha256, norm_policy)?;
    ensure_manifest_matches_contract(manifest, output, norm_policy, &contract)?;
    let retrieval_only = matches!(runtime, LensRuntime::FastembedRerankerPlaced { .. });
    Ok(LensSpec {
        name: contract.name().to_string(),
        runtime,
        output: contract.shape(),
        modality: contract.modality(),
        weights_sha256: contract.weights_sha256(),
        corpus_hash: contract.corpus_hash(),
        norm_policy: contract.norm_policy(),
        max_batch: manifest.max_batch,
        axis: Some(manifest.name.clone()),
        asymmetry: Asymmetry::None,
        quant_default: manifest.quant_default,
        truncate_dim: manifest.truncate_dim,
        recall_delta: manifest.recall_delta,
        retrieval_only,
        excluded_from_dedup: retrieval_only,
    })
}

fn canonical_runtime(mut runtime: LensRuntime) -> Result<LensRuntime> {
    match &mut runtime {
        LensRuntime::Algorithmic { kind } => *kind = canonical_algorithmic_kind(kind)?,
        LensRuntime::CandleLocal { pooling, .. } => {
            *pooling = canonical_candle_pooling(pooling)?.to_string();
        }
        LensRuntime::FastembedQwen3 { model_id, .. } => {
            *model_id = canonical_qwen3_model_id(model_id)?.to_string();
        }
        LensRuntime::FastembedSparsePlaced { model_id, .. } => {
            *model_id = canonical_sparse_model_code(model_id)?.to_string();
        }
        LensRuntime::FastembedBgem3Placed { model_id, .. } => {
            *model_id = canonical_bgem3_model_code(model_id)?.to_string();
        }
        LensRuntime::FastembedRerankerPlaced { model_id, .. } => {
            *model_id = canonical_reranker_model_code(model_id)?.to_string();
        }
        LensRuntime::FastembedDensePlaced { model_id, .. } => {
            *model_id = dense_model_identity(model_id)?.to_string();
        }
        LensRuntime::FastembedDense { .. }
        | LensRuntime::FastembedSparse { .. }
        | LensRuntime::FastembedBgem3 { .. }
        | LensRuntime::FastembedReranker { .. } => {
            return Err(legacy_unbound_fastembed_identity());
        }
        LensRuntime::TeiHttp { .. }
        | LensRuntime::Onnx { .. }
        | LensRuntime::OnnxColbert { .. }
        | LensRuntime::StaticLookup { .. }
        | LensRuntime::MultimodalAdapter { .. }
        | LensRuntime::ExternalCmd { .. } => {}
    }
    Ok(runtime)
}

fn canonical_algorithmic_kind(raw: &str) -> Result<String> {
    let canonical = match raw {
        "byte" | "byte-features" | "byte_features" => "byte-features",
        "ast-style" | "ast_style" => "ast-style",
        "gdelt-cameo" | "gdelt_cameo" => "gdelt-cameo",
        "gdelt-actor-geo" | "gdelt_actor_geo" => "gdelt-actor-geo",
        "gdelt-source-domain" | "gdelt_source_domain" => "gdelt-source-domain",
        "gdelt-event-geo" | "gdelt_event_geo" => "gdelt-event-geo",
        "gdelt-actor-pair" | "gdelt_actor_pair" => "gdelt-actor-pair",
        "gdelt-event-actor" | "gdelt_event_actor" => "gdelt-event-actor",
        "gdelt-tone-signal" | "gdelt_tone_signal" => "gdelt-tone-signal",
        "gdelt-source-event" | "gdelt_source_event" => "gdelt-source-event",
        "scalar" => "scalar",
        "sparse" | "sparse-keywords" | "sparse_keywords" => "sparse-keywords",
        "token-hash" | "token_hash" | "multi-hash" | "multi_hash" => "token-hash",
        value
            if value.starts_with("one-hot:")
                || value.starts_with("one_hot:")
                || value.starts_with("sparse-keywords:")
                || value.starts_with("sparse_keywords:")
                || value.starts_with("token-hash:")
                || value.starts_with("token_hash:")
                || value.starts_with("multi-hash:")
                || value.starts_with("multi_hash:") =>
        {
            let (prefix, dim) = value
                .split_once(':')
                .ok_or_else(|| config_invalid(format!("invalid algorithmic kind {value}")))?;
            let prefix = match prefix {
                "one-hot" | "one_hot" => "one-hot",
                "sparse-keywords" | "sparse_keywords" => "sparse-keywords",
                "token-hash" | "token_hash" | "multi-hash" | "multi_hash" => "token-hash",
                _ => {
                    return Err(config_invalid(format!(
                        "unsupported algorithmic kind {value}"
                    )));
                }
            };
            return Ok(format!("{prefix}:{dim}"));
        }
        other => {
            return Err(config_invalid(format!(
                "unsupported algorithmic kind {other}"
            )));
        }
    };
    Ok(canonical.to_string())
}

fn declared_contract(
    manifest: &LensForgeManifest,
    runtime: &LensRuntime,
    output: SlotShape,
    weights_sha256: [u8; 32],
    norm_policy: NormPolicy,
) -> Result<FrozenLensContract> {
    if let Some(contract) =
        algorithmic_frozen_contract(&manifest.name, &manifest.runtime, manifest.modality, output)?
    {
        return Ok(contract);
    }
    let facts = match runtime {
        LensRuntime::TeiHttp { endpoint } => {
            let dim = dense_dim(output, "TEI")?;
            return Ok(FrozenLensContract::tei_http(
                &manifest.name,
                endpoint,
                manifest.modality,
                dim,
            ));
        }
        LensRuntime::CandleLocal {
            model_id,
            device,
            dtype,
            pooling,
            ..
        } => {
            let profile = source_profile_fingerprint(manifest)?;
            let pooling = canonical_candle_pooling(pooling)?;
            ContractFacts {
                name: manifest.name.clone(),
                weights_sha256,
                corpus_hash: candle_execution_corpus_hash(
                    model_id,
                    CANDLE_DEFAULT_MAX_TOKENS,
                    device,
                    dtype,
                    pooling,
                    norm_policy,
                    profile,
                ),
                shape: output,
                modality: Modality::Text,
                norm: norm_policy,
            }
        }
        LensRuntime::FastembedQwen3 {
            model_id,
            device,
            dtype,
            ..
        } => {
            let model_id = canonical_qwen3_model_id(model_id)?;
            let profile = source_profile_fingerprint(manifest)?;
            ContractFacts {
                name: manifest.name.clone(),
                weights_sha256,
                corpus_hash: qwen3_execution_corpus_hash(
                    model_id,
                    device,
                    dtype,
                    QWEN3_DEFAULT_MAX_TOKENS,
                    profile,
                ),
                shape: output,
                modality: Modality::Text,
                norm: NormPolicy::unit(),
            }
        }
        LensRuntime::Onnx { model_id, .. } => ContractFacts {
            name: manifest.name.clone(),
            weights_sha256,
            corpus_hash: onnx_custom_corpus_hash(
                model_id,
                output,
                canonical_onnx_pooling(&manifest.pooling)?,
                norm_policy,
            ),
            shape: output,
            modality: manifest.modality,
            norm: norm_policy,
        },
        LensRuntime::FastembedDensePlaced {
            model_id,
            execution,
            ..
        } => {
            let model_id = dense_model_identity(model_id)?;
            ContractFacts {
                name: manifest.name.clone(),
                weights_sha256,
                corpus_hash: fastembed_dense_corpus_hash(model_id, execution),
                shape: output,
                modality: Modality::Text,
                norm: NormPolicy::unit(),
            }
        }
        LensRuntime::OnnxColbert { model_id, .. } => ContractFacts {
            name: manifest.name.clone(),
            weights_sha256,
            corpus_hash: onnx_colbert_corpus_hash(model_id),
            shape: output,
            modality: Modality::Text,
            norm: NormPolicy::Finite,
        },
        LensRuntime::FastembedSparsePlaced {
            model_id,
            execution,
            ..
        } => ContractFacts {
            name: manifest.name.clone(),
            weights_sha256,
            corpus_hash: fastembed_sparse_corpus_hash(
                canonical_sparse_model_code(model_id)?,
                execution,
            ),
            shape: sparse_shape_for_model(model_id)?,
            modality: Modality::Text,
            norm: NormPolicy::Finite,
        },
        LensRuntime::FastembedBgem3Placed {
            model_id,
            output,
            execution,
            ..
        } => {
            let (shape, norm, token) = match output {
                FastembedBgem3Output::Dense => {
                    (SlotShape::Dense(1024), NormPolicy::unit(), "dense")
                }
                FastembedBgem3Output::Sparse => {
                    (SlotShape::Sparse(250_002), NormPolicy::Finite, "sparse")
                }
                FastembedBgem3Output::Colbert => (
                    SlotShape::Multi { token_dim: 1024 },
                    NormPolicy::Finite,
                    "colbert",
                ),
            };
            ContractFacts {
                name: manifest.name.clone(),
                weights_sha256,
                corpus_hash: fastembed_bgem3_corpus_hash(
                    canonical_bgem3_model_code(model_id)?,
                    token.as_bytes(),
                    execution,
                ),
                shape,
                modality: Modality::Text,
                norm,
            }
        }
        LensRuntime::FastembedRerankerPlaced {
            model_id,
            execution,
            ..
        } => ContractFacts {
            name: manifest.name.clone(),
            weights_sha256,
            corpus_hash: fastembed_reranker_corpus_hash(
                canonical_reranker_model_code(model_id)?,
                execution,
            ),
            shape: SlotShape::Dense(1),
            modality: Modality::Text,
            norm: NormPolicy::Finite,
        },
        LensRuntime::FastembedDense { .. }
        | LensRuntime::FastembedSparse { .. }
        | LensRuntime::FastembedBgem3 { .. }
        | LensRuntime::FastembedReranker { .. } => {
            return Err(legacy_unbound_fastembed_identity());
        }
        LensRuntime::StaticLookup { dim, .. } => ContractFacts {
            name: manifest.name.clone(),
            weights_sha256,
            corpus_hash: static_lookup_corpus_hash(*dim, canonical_static_dtype(&manifest.dtype)?),
            shape: SlotShape::Dense(*dim),
            modality: Modality::Text,
            norm: norm_policy,
        },
        LensRuntime::MultimodalAdapter { axis, model_id, .. } => ContractFacts {
            name: manifest.name.clone(),
            weights_sha256,
            corpus_hash: multimodal_adapter_corpus_hash(&manifest.name, axis, model_id),
            shape: output,
            modality: manifest.modality,
            norm: NormPolicy::unit(),
        },
        LensRuntime::ExternalCmd { cmd, args } => {
            let dim = dense_dim(output, "external command")?;
            ContractFacts {
                name: manifest.name.clone(),
                weights_sha256: external_command_weights_hash(cmd, args),
                corpus_hash: external_command_corpus_hash(),
                shape: SlotShape::Dense(dim),
                modality: manifest.modality,
                norm: NormPolicy::None,
            }
        }
        LensRuntime::Algorithmic { .. } => {
            return Err(config_invalid(
                "algorithmic runtime did not produce its canonical frozen contract",
            ));
        }
    };
    Ok(contract_from_facts(facts))
}

fn ensure_manifest_matches_contract(
    manifest: &LensForgeManifest,
    output: SlotShape,
    norm: NormPolicy,
    contract: &FrozenLensContract,
) -> Result<()> {
    if output != contract.shape() {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "manifest {} declares output {output:?}, but runtime contract requires {:?}",
            manifest.name,
            contract.shape()
        )));
    }
    if manifest.modality != contract.modality() {
        return Err(CalyxError::lens_frozen_violation(format!(
            "manifest {} declares modality {:?}, but runtime contract requires {:?}",
            manifest.name,
            manifest.modality,
            contract.modality()
        )));
    }
    if norm != contract.norm_policy() {
        return Err(CalyxError::lens_frozen_violation(format!(
            "manifest {} declares norm {norm:?}, but runtime contract requires {:?}",
            manifest.name,
            contract.norm_policy()
        )));
    }
    Ok(())
}

fn canonical_candle_pooling(raw: &str) -> Result<&'static str> {
    match raw {
        "mean" => Ok("mean"),
        "cls" | "first_token" | "first-token" => Ok("cls"),
        other => Err(config_invalid(format!(
            "unsupported candle pooling {other}"
        ))),
    }
}

fn canonical_onnx_pooling(raw: &str) -> Result<&'static str> {
    match raw {
        "mean" => Ok("mean"),
        "cls" | "first_token" | "first-token" => Ok("cls"),
        "last_token" | "last-token" => Ok("last_token"),
        other => Err(config_invalid(format!("unsupported ONNX pooling {other}"))),
    }
}

fn canonical_qwen3_model_id(raw: &str) -> Result<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "qwen/qwen3-embedding-0.6b" | "qwen3-embedding-0.6b" | "qwen3-0.6b" => {
            Ok(DEFAULT_QWEN3_MODEL)
        }
        other => Err(config_invalid(format!(
            "unsupported fastembed-qwen3 model {other}; expected {DEFAULT_QWEN3_MODEL}"
        ))),
    }
}

fn dense_model_identity(raw: &str) -> Result<&str> {
    let model_id = raw.trim();
    if model_id.is_empty() {
        return Err(config_invalid("fastembed dense model id is empty"));
    }
    Ok(model_id)
}

fn canonical_sparse_model_code(raw: &str) -> Result<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "qdrant/splade_pp_en_v1" | "prithivida/splade_pp_en_v1" | "splade_pp_en_v1" => {
            Ok("Qdrant/Splade_PP_en_v1")
        }
        "baai/bge-m3" | "bge-m3" => Ok("BAAI/bge-m3"),
        other => Err(config_invalid(format!(
            "unsupported fastembed sparse model {other}"
        ))),
    }
}

fn sparse_shape_for_model(raw: &str) -> Result<SlotShape> {
    match canonical_sparse_model_code(raw)? {
        "Qdrant/Splade_PP_en_v1" => Ok(SlotShape::Sparse(30_522)),
        "BAAI/bge-m3" => Ok(SlotShape::Sparse(250_002)),
        other => Err(config_invalid(format!(
            "canonical sparse model code {other} has no frozen output shape"
        ))),
    }
}

fn canonical_bgem3_model_code(raw: &str) -> Result<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "baai/bge-m3" | "bge-m3" | "gpahal/bge-m3-onnx-int8" => Ok("gpahal/bge-m3-onnx-int8"),
        other => Err(config_invalid(format!(
            "unsupported BGE-M3 fastembed model {other}"
        ))),
    }
}

fn canonical_reranker_model_code(raw: &str) -> Result<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "baai/bge-reranker-base" | "bge-reranker-base" => Ok("BAAI/bge-reranker-base"),
        "baai/bge-reranker-v2-m3" | "bge-reranker-v2-m3" | "rozgo/bge-reranker-v2-m3" => {
            Ok("rozgo/bge-reranker-v2-m3")
        }
        "jinaai/jina-reranker-v1-turbo-en" | "jina-reranker-v1-turbo-en" => {
            Ok("jinaai/jina-reranker-v1-turbo-en")
        }
        "jinaai/jina-reranker-v2-base-multilingual" | "jina-reranker-v2-base-multilingual" => {
            Ok("jinaai/jina-reranker-v2-base-multilingual")
        }
        other => Err(config_invalid(format!(
            "unsupported fastembed reranker model {other}"
        ))),
    }
}

fn canonical_static_dtype(raw: &str) -> Result<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "int8" | "i8" => Ok("int8"),
        "f16" | "fp16" | "float16" => Ok("f16"),
        "f32" | "fp32" | "float32" => Ok("f32"),
        other => Err(config_invalid(format!(
            "unsupported static lookup source dtype {other}"
        ))),
    }
}

fn source_profile_fingerprint(manifest: &LensForgeManifest) -> Result<&str> {
    manifest
        .source_tensor_dtype_profile
        .as_ref()
        .map(|profile| profile.fingerprint_sha256.as_str())
        .ok_or_else(|| {
            config_invalid("local learned manifest requires source_tensor_dtype_profile")
        })
}

fn dense_dim(shape: SlotShape, runtime: &str) -> Result<u32> {
    match shape {
        SlotShape::Dense(dim) => Ok(dim),
        other => Err(config_invalid(format!(
            "{runtime} requires dense output, got {other:?}"
        ))),
    }
}

fn config_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CONFIG_INVALID,
        message: message.into(),
        remediation: "fix the lensforge manifest or recommission the frozen lens",
    }
}
