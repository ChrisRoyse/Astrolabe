use std::path::{Path, PathBuf};
use std::str::FromStr;

use calyx_core::{CalyxError, Modality, Result, SlotShape};
use fastembed::{EmbeddingModel, InitOptionsUserDefined, TextEmbedding, UserDefinedEmbeddingModel};
use hf_hub::api::sync::ApiBuilder;
use ort::ep::{self, ArenaExtendStrategy, cuda::ConvAlgorithmSearch};

use super::cuda_guard::CudaDropGuard;
use super::{OnnxLens, OnnxModelFiles, OnnxProviderPolicy};
use crate::frozen::{FrozenLensContract, LensDType, NormPolicy, sha256_digest};
use crate::runtime::common::{default_hf_cache_root, fastembed_cache_root};

pub fn default_cache_root() -> PathBuf {
    default_hf_cache_root()
}

pub fn from_hf_cache(name: impl Into<String>, cache_dir: PathBuf) -> Result<OnnxLens> {
    from_hf_cache_with_policy(name, cache_dir, OnnxProviderPolicy::CudaFailLoud)
}

pub fn from_hf_cache_with_policy(
    name: impl Into<String>,
    cache_dir: PathBuf,
    provider_policy: OnnxProviderPolicy,
) -> Result<OnnxLens> {
    from_model_with_policy(
        name,
        EmbeddingModel::AllMiniLML6V2,
        cache_dir,
        provider_policy,
    )
}

pub fn from_model_with_policy(
    name: impl Into<String>,
    model_name: EmbeddingModel,
    cache_dir: PathBuf,
    provider_policy: OnnxProviderPolicy,
) -> Result<OnnxLens> {
    let _ort_dylib = super::dynamic_ort::ensure_dynamic_ort(provider_policy)?;
    let name = name.into();
    let info = TextEmbedding::get_model_info(&model_name).map_err(|err| {
        CalyxError::lens_unreachable(format!("fastembed model metadata failed: {err}"))
    })?;
    let effective_cache = fastembed_cache_root(&cache_dir);
    let files = resolve_files(
        &effective_cache,
        &info.model_code,
        &info.model_file,
        &info.additional_files,
    )?;
    let artifacts = super::fastembed_artifacts::FrozenFastembedArtifacts::snapshot(
        &files,
        &info.model_file,
        &info.additional_files,
        provider_policy,
    )?;
    let weights_sha256 = artifacts.receipt().weights_sha256;
    let context = super::fastembed_attestation::FastembedModelContext::new(
        format!("onnx-fastembed:{}", info.model_code),
        &info.model_code,
        &files,
        artifacts.receipt(),
        provider_policy,
    )?;
    super::arena::preflight_gpu_mem_limit_for_bytes(
        &format!("onnx-fastembed:{}", info.model_code),
        provider_policy,
        artifacts.receipt().artifact_bytes,
    )
    .map_err(|error| context.error("vram_preflight", error))?;
    let label = format!("onnx-fastembed:{}", info.model_code);
    let (execution_providers, bound_stream) = execution_providers(&label, provider_policy)
        .map_err(|error| context.error("execution_provider_configuration", error))?;
    let (model_bytes, tokenizer_files, external_initializers) = artifacts.into_parts();
    let mut user_model = UserDefinedEmbeddingModel::new(model_bytes, tokenizer_files)
        .with_quantization(TextEmbedding::get_quantization_mode(&model_name));
    if let Some(pooling) = TextEmbedding::get_default_pooling_method(&model_name) {
        user_model = user_model.with_pooling(pooling);
    }
    if let Some(output_key) = info.output_key.clone() {
        user_model = user_model.with_output_key(output_key);
    }
    for initializer in external_initializers {
        user_model =
            user_model.with_external_initializer(initializer.file_name, initializer.buffer);
    }
    let model = TextEmbedding::try_new_from_user_defined(
        user_model,
        InitOptionsUserDefined::new()
            .with_intra_threads(1)
            .with_session_policy(context.session_policy())
            .with_execution_providers(execution_providers),
    )
    .map_err(|err| context.error("model_constructor", err))?;
    let model = CudaDropGuard::new(model, provider_policy).with_bound_stream(bound_stream);
    super::runtime_bundle::attest_after_model_constructor(provider_policy, model.bound_stream())
        .map_err(|error| context.error("runtime_bundle_attestation", error))?;
    let execution = super::fastembed_attestation::FastembedExecutionState::inspect(
        model.as_ref().session(),
        context,
    )?;
    let corpus_hash = sha256_digest(&[
        b"onnx-fastembed-mean-pool-v1",
        info.model_code.as_bytes(),
        info.model_file.as_bytes(),
    ]);
    let dim = u32::try_from(info.dim)
        .map_err(|_| CalyxError::lens_dim_mismatch(format!("ONNX dim {} exceeds u32", info.dim)))?;
    let contract = FrozenLensContract::new(
        name,
        weights_sha256,
        corpus_hash,
        SlotShape::Dense(dim),
        Modality::Text,
        LensDType::F32,
        NormPolicy::unit(),
    );
    let id = contract.lens_id();
    let (model, bound_stream) = model.into_parts();
    Ok(OnnxLens::from_fastembed_parts(
        id,
        dim,
        contract,
        files,
        provider_policy,
        model,
        execution,
        bound_stream,
    ))
}

pub fn from_model_name_with_policy(
    name: impl Into<String>,
    model_name: &str,
    cache_dir: PathBuf,
    provider_policy: OnnxProviderPolicy,
) -> Result<OnnxLens> {
    let model_name = model_from_name(model_name)?;
    from_model_with_policy(name, model_name, cache_dir, provider_policy)
}

pub fn model_from_name(raw: &str) -> Result<EmbeddingModel> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CalyxError::lens_unreachable(
            "fastembed model name must not be empty",
        ));
    }
    if let Ok(model) = EmbeddingModel::from_str(trimmed) {
        return Ok(model);
    }
    match normalized(trimmed).as_str() {
        "baai/bge-m3" | "bge-m3" => Ok(EmbeddingModel::BGEM3),
        "baai/bge-base-en-v1.5" | "xenova/bge-base-en-v1.5" | "bge-base-en-v1.5" => {
            Ok(EmbeddingModel::BGEBaseENV15)
        }
        "qdrant/bge-base-en-v1.5-onnx-q" | "bge-base-en-v1.5-q" => {
            Ok(EmbeddingModel::BGEBaseENV15Q)
        }
        "nomic-ai/nomic-embed-text-v1.5" | "nomic-embed-text-v1.5" => {
            Ok(EmbeddingModel::NomicEmbedTextV15)
        }
        "nomic-ai/nomic-embed-text-v1.5-q" | "nomic-embed-text-v1.5-q" => {
            Ok(EmbeddingModel::NomicEmbedTextV15Q)
        }
        "intfloat/multilingual-e5-base" | "multilingual-e5-base" => {
            Ok(EmbeddingModel::MultilingualE5Base)
        }
        "jinaai/jina-embeddings-v2-base-en" | "jina-embeddings-v2-base-en" => {
            Ok(EmbeddingModel::JinaEmbeddingsV2BaseEN)
        }
        "jinaai/jina-embeddings-v2-base-code" | "jina-embeddings-v2-base-code" | "jina-code" => {
            Ok(EmbeddingModel::JinaEmbeddingsV2BaseCode)
        }
        "google/embeddinggemma-300m"
        | "onnx-community/embeddinggemma-300m-onnx"
        | "embeddinggemma-300m"
        | "embedding-gemma-300m" => Ok(EmbeddingModel::EmbeddingGemma300M),
        "google/embeddinggemma-300m-q4" | "embeddinggemma-300m-q4" => {
            Ok(EmbeddingModel::EmbeddingGemma300MQ4)
        }
        "google/embeddinggemma-300m-q" | "embeddinggemma-300m-q" => {
            Ok(EmbeddingModel::EmbeddingGemma300MQ)
        }
        "snowflake/snowflake-arctic-embed-m" | "snowflake-arctic-embed-m" => {
            Ok(EmbeddingModel::SnowflakeArcticEmbedM)
        }
        "snowflake/snowflake-arctic-embed-m-q" | "snowflake-arctic-embed-m-q" => {
            Ok(EmbeddingModel::SnowflakeArcticEmbedMQ)
        }
        "alibaba-nlp/gte-base-en-v1.5" | "gte-base-en-v1.5" => Ok(EmbeddingModel::GTEBaseENV15),
        other => Err(CalyxError::lens_unreachable(format!(
            "unsupported fastembed model {other}; use a fastembed EmbeddingModel enum name or a supported HF repo id"
        ))),
    }
}

pub(super) fn execution_providers(
    label: &str,
    policy: OnnxProviderPolicy,
) -> Result<(
    Vec<fastembed::ExecutionProviderDispatch>,
    Option<super::green_context::GreenContextHandle>,
)> {
    let selected_device = super::runtime_bundle::selected_cuda_device(policy)?;
    let bound_stream = super::green_context::create(label, policy, selected_device.as_ref())?;
    let providers = execution_providers_for_attested_device(
        policy,
        selected_device.as_ref(),
        bound_stream.as_ref().map(|stream| stream.stream_ptr()),
    )?;
    Ok((providers, bound_stream))
}

pub(super) fn execution_providers_for_attested_device(
    policy: OnnxProviderPolicy,
    selected_device: Option<&super::runtime_bundle::OnnxCudaDeviceAttestation>,
    compute_stream: Option<*mut ()>,
) -> Result<Vec<fastembed::ExecutionProviderDispatch>> {
    let device_id = selected_device
        .map(|device| i32::try_from(device.ordinal))
        .transpose()
        .map_err(|_| {
            CalyxError::lens_unreachable(
                "attested CUDA Runtime ordinal exceeds the ORT device-id ABI",
            )
        })?
        .unwrap_or(0);
    match policy {
        OnnxProviderPolicy::CudaFailLoud => {
            if selected_device.is_none() {
                return Err(CalyxError::lens_unreachable(
                    "CUDA provider construction requires a process-global attested device",
                ));
            }
            // #1143: the default kNextPowerOfTwo strategy over-reserves the
            // BFC device arena on every extension; dynamic (batch, seq)
            // workloads are our norm, so extend exactly as requested and let
            // the optional limit turn exhaustion into a structured error at
            // a defined budget.
            let mut cuda = ep::CUDA::default()
                .with_device_id(device_id)
                .with_conv_algorithm_search(ConvAlgorithmSearch::Heuristic)
                .with_conv_max_workspace(false)
                .with_arena_extend_strategy(ArenaExtendStrategy::SameAsRequested);
            if super::session::configured_cuda_graphs()? {
                cuda = cuda.with_cuda_graph(true);
            }
            if let Some(stream) = compute_stream {
                cuda = unsafe { cuda.with_compute_stream(stream) };
            }
            if let Some(limit) = super::arena::configured_gpu_mem_limit()? {
                cuda = cuda.with_memory_limit(limit);
            }
            Ok(vec![cuda.build().error_on_failure()])
        }
        OnnxProviderPolicy::CpuExplicit => Ok(vec![ep::CPU::default().build().error_on_failure()]),
    }
}

pub(super) fn resolve_files(
    cache_dir: &Path,
    model_code: &str,
    model_file: &str,
    additional_files: &[String],
) -> Result<OnnxModelFiles> {
    super::fastembed_artifacts::validate_logical_file_set(model_file, additional_files)?;
    let api = ApiBuilder::new()
        .with_cache_dir(cache_dir.to_path_buf())
        .with_progress(false)
        .build()
        .map_err(|err| CalyxError::lens_unreachable(format!("HF API init failed: {err}")))?;
    let repo = api.model(model_code.to_string());
    let model_file = fetch(&repo, model_file)?;
    let tokenizer = fetch(&repo, "tokenizer.json")?;
    let config = fetch(&repo, "config.json")?;
    let special_tokens_map = fetch(&repo, "special_tokens_map.json")?;
    let tokenizer_config = fetch(&repo, "tokenizer_config.json")?;
    let mut contract_paths = vec![
        model_file.clone(),
        tokenizer.clone(),
        config.clone(),
        tokenizer_config.clone(),
        special_tokens_map.clone(),
    ];
    for file in additional_files {
        contract_paths.push(fetch(&repo, file)?);
    }
    Ok(OnnxModelFiles {
        cache_dir: cache_dir.to_path_buf(),
        model_code: model_code.to_string(),
        model_file,
        tokenizer,
        config,
        special_tokens_map,
        tokenizer_config,
        contract_paths,
    })
}

pub(super) fn fetch(repo: &hf_hub::api::sync::ApiRepo, filename: &str) -> Result<PathBuf> {
    repo.get(filename)
        .map_err(|err| CalyxError::lens_unreachable(format!("fetch {filename} failed: {err}")))
}

fn normalized(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}
