use std::path::{Path, PathBuf};
use std::str::FromStr;

use calyx_core::{CalyxError, Modality, Result, SlotShape};
use fastembed::{EmbeddingModel, InitOptionsUserDefined, TextEmbedding, UserDefinedEmbeddingModel};
use hf_hub::api::sync::ApiBuilder;
use ort::ep::{self, ArenaExtendStrategy, cuda::ConvAlgorithmSearch};

use super::cuda_guard::CudaDropGuard;
use super::{OnnxLens, OnnxModelFiles, OnnxProviderPolicy};
use crate::frozen::{FrozenLensContract, LensDType, NormPolicy};
use crate::identity::fastembed_dense_corpus_hash;
use crate::runtime::common::{default_hf_cache_root, fastembed_cache_root};
use crate::spec::{LensRuntime, LensSpec};

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
    from_files_with_policy(name, model_name, files, provider_policy, None)
}

fn from_files_with_policy(
    name: String,
    model_name: EmbeddingModel,
    files: OnnxModelFiles,
    provider_policy: OnnxProviderPolicy,
    expected_spec: Option<&LensSpec>,
) -> Result<OnnxLens> {
    let info = TextEmbedding::get_model_info(&model_name).map_err(|err| {
        CalyxError::lens_unreachable(format!("fastembed model metadata failed: {err}"))
    })?;
    let dim = u32::try_from(info.dim)
        .map_err(|_| CalyxError::lens_dim_mismatch(format!("ONNX dim {} exceeds u32", info.dim)))?;
    let shape = SlotShape::Dense(dim);
    if let Some(spec) = expected_spec
        && spec.output != shape
    {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "persisted dense FastEmbed shape {:?} != model shape {shape:?}",
            spec.output
        )));
    }
    let artifacts = super::fastembed_artifacts::FrozenFastembedArtifacts::snapshot(
        &files,
        &info.model_file,
        &info.additional_files,
        provider_policy.frozen_execution_token(),
        provider_policy,
    )?;
    let weights_sha256 = artifacts.receipt().weights_sha256;
    let corpus_hash =
        fastembed_dense_corpus_hash(&files.model_code, provider_policy.frozen_execution_token());
    if let Some(spec) = expected_spec {
        validate_persisted_contract(spec, weights_sha256, corpus_hash, shape)?;
    }
    super::runtime_bundle::authorize_execution_policy(provider_policy)?;
    let _ort_dylib = super::dynamic_ort::ensure_dynamic_ort(provider_policy)?;
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
        super::green_context::retained_stream_evidence(model.bound_stream()),
    )?;
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
        expected_spec.and_then(|spec| spec.max_batch),
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
    let identity = model_name.trim();
    if identity.is_empty() {
        return Err(CalyxError::lens_unreachable(
            "fastembed model name must not be empty",
        ));
    }
    let model_name = model_from_name(model_name)?;
    let info = TextEmbedding::get_model_info(&model_name).map_err(|err| {
        CalyxError::lens_unreachable(format!("fastembed model metadata failed: {err}"))
    })?;
    let effective_cache = fastembed_cache_root(&cache_dir);
    let mut files = resolve_files(
        &effective_cache,
        &info.model_code,
        &info.model_file,
        &info.additional_files,
    )?;
    files.model_code = identity.to_string();
    from_files_with_policy(name.into(), model_name, files, provider_policy, None)
}

pub(super) fn from_lens_spec(spec: &LensSpec) -> Result<OnnxLens> {
    let (model_id, files, execution) = match &spec.runtime {
        LensRuntime::FastembedDensePlaced {
            model_id,
            files,
            execution,
        } => (model_id, files, execution),
        LensRuntime::FastembedDense { .. } => {
            return Err(CalyxError {
                code: "CALYX_FASTEMBED_LEGACY_EXECUTION_UNBOUND",
                message: "persisted dense FastEmbed runtime predates execution-policy identity"
                    .into(),
                remediation: "recommission this lens from its onnx-fastembed manifest to a placement-bound FastEmbed runtime; never infer CPU or CUDA from legacy persisted bytes",
            });
        }
        _ => {
            return Err(super::config_invalid(
                "LensSpec runtime is not placement-bound fastembed-dense",
            ));
        }
    };
    if spec.max_batch == Some(0) {
        return Err(super::config_invalid("LensSpec max_batch must be > 0"));
    }
    let model_id = model_id.trim();
    let provider_policy = OnnxProviderPolicy::from_frozen_execution_token(execution)?;
    let model_name = model_from_name(model_id)?;
    let info = TextEmbedding::get_model_info(&model_name).map_err(|err| {
        CalyxError::lens_unreachable(format!("fastembed model metadata failed: {err}"))
    })?;
    let files = super::fastembed_artifacts::persisted_model_files(
        model_id,
        files,
        &info.model_file,
        &info.additional_files,
    )?;
    from_files_with_policy(
        spec.name.clone(),
        model_name,
        files,
        provider_policy,
        Some(spec),
    )
}

fn validate_persisted_contract(
    spec: &LensSpec,
    observed_weights: [u8; 32],
    observed_corpus: [u8; 32],
    observed_shape: SlotShape,
) -> Result<()> {
    if spec.modality != Modality::Text {
        return Err(CalyxError::lens_frozen_violation(format!(
            "persisted dense FastEmbed modality {:?} != Text",
            spec.modality
        )));
    }
    if spec.norm_policy != NormPolicy::unit() {
        return Err(CalyxError::lens_frozen_violation(format!(
            "persisted dense FastEmbed norm {:?} != unit",
            spec.norm_policy
        )));
    }
    if spec.output != observed_shape {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "persisted dense FastEmbed shape {:?} != observed {observed_shape:?}",
            spec.output
        )));
    }
    if spec.weights_sha256 != observed_weights {
        return Err(CalyxError::lens_frozen_violation(format!(
            "persisted dense FastEmbed artifact hash {} != observed {}",
            hex_sha256(&spec.weights_sha256),
            hex_sha256(&observed_weights)
        )));
    }
    if spec.corpus_hash != observed_corpus {
        return Err(CalyxError::lens_frozen_violation(format!(
            "persisted dense FastEmbed corpus hash {} != observed {}",
            hex_sha256(&spec.corpus_hash),
            hex_sha256(&observed_corpus)
        )));
    }
    Ok(())
}

pub(super) fn reject_legacy_dense_custom_spec(spec: &LensSpec, model_id: &str) -> Result<()> {
    let Ok(model) = model_from_name(model_id) else {
        return Ok(());
    };
    let info = TextEmbedding::get_model_info(&model).map_err(|error| {
        CalyxError::lens_unreachable(format!(
            "inspect known FastEmbed model metadata during legacy provenance detection failed: {error}"
        ))
    })?;
    let dim = u32::try_from(info.dim).map_err(|_| {
        CalyxError::lens_dim_mismatch(format!("FastEmbed model dim {} exceeds u32", info.dim))
    })?;
    let legacy_identity = crate::identity::legacy_fastembed_dense_corpus_hash(model_id.trim());
    let canonical_legacy_identity =
        crate::identity::legacy_fastembed_dense_corpus_hash(&info.model_code);
    let exact_legacy_contract = spec.output == SlotShape::Dense(dim)
        && spec.modality == Modality::Text
        && spec.norm_policy == NormPolicy::unit()
        && (spec.corpus_hash == legacy_identity || spec.corpus_hash == canonical_legacy_identity);
    if exact_legacy_contract {
        return Err(CalyxError {
            code: "CALYX_FASTEMBED_LEGACY_RUNTIME_MIGRATION_REQUIRED",
            message: format!(
                "persisted LensRuntime::Onnx for {} has the exact historical dense FastEmbed frozen identity and cannot be constructed as a generic custom ONNX runtime",
                model_id.trim()
            ),
            remediation: "recommission this lens from a manifest using runtime onnx-fastembed so logical artifact names and execution placement receive the new frozen identity; never reinterpret or rewrite the old bytes in place",
        });
    }
    Ok(())
}

fn hex_sha256(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
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
