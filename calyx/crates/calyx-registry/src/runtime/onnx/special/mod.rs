use std::path::PathBuf;
use std::sync::Mutex;

use calyx_core::{
    CalyxError, Input, Lens, LensId, Modality, Result, RuntimeExecutionAttestation, SlotShape,
    SlotVector,
};
use fastembed::{
    Bgem3Embedding, Bgem3Model, InitOptionsUserDefined, RerankInitOptionsUserDefined,
    RerankerModel, SparseModel, SparseTextEmbedding, TextRerank, UserDefinedBgem3Model,
    UserDefinedRerankingModel, UserDefinedSparseModel,
};

use super::cuda_guard::CudaDropGuard;
use super::{OnnxModelFiles, OnnxProviderPolicy};
use crate::frozen::{FrozenLensContract, NormPolicy};
use crate::identity::{
    fastembed_bgem3_corpus_hash, fastembed_reranker_corpus_hash, fastembed_sparse_corpus_hash,
};
use crate::spec::{FastembedBgem3Output, LensRuntime, LensSpec};

mod models;
mod vectors;

use models::{
    BGE_M3_DENSE_DIM, BGE_M3_SPARSE_DIM, bgem3_corpus_token, bgem3_model_from_name, bgem3_norm,
    bgem3_runtime_name, bgem3_shape, reranker_model_from_name, sparse_dim, sparse_model_from_name,
};
use vectors::{
    contract, dense_batch, ensure_spec_match, input_texts, leak_cuda_model_and_stream, lock_model,
    multi_batch, rerank_pair, single_vector, sparse_batch, sparse_shape_dim, special_files,
};

fn legacy_unbound_error(family: &str) -> CalyxError {
    CalyxError {
        code: "CALYX_FASTEMBED_LEGACY_EXECUTION_UNBOUND",
        message: format!("persisted {family} FastEmbed runtime predates execution-policy identity"),
        remediation: "recommission this lens from its manifest to a placement-bound FastEmbed runtime; never infer CPU or CUDA from legacy persisted bytes",
    }
}

pub struct FastembedSparseLens {
    id: LensId,
    contract: FrozenLensContract,
    files: OnnxModelFiles,
    provider_policy: OnnxProviderPolicy,
    max_batch: Option<usize>,
    model: Option<Mutex<SparseTextEmbedding>>,
    execution: super::fastembed_attestation::FastembedExecutionState,
    bound_stream: Option<super::green_context::RetainedCudaStream>,
}

pub struct FastembedBgem3Lens {
    id: LensId,
    output: FastembedBgem3Output,
    contract: FrozenLensContract,
    files: OnnxModelFiles,
    provider_policy: OnnxProviderPolicy,
    max_batch: Option<usize>,
    model: Option<Mutex<Bgem3Embedding>>,
    execution: super::fastembed_attestation::FastembedExecutionState,
    bound_stream: Option<super::green_context::RetainedCudaStream>,
}

pub struct FastembedRerankerLens {
    id: LensId,
    contract: FrozenLensContract,
    files: OnnxModelFiles,
    provider_policy: OnnxProviderPolicy,
    max_batch: Option<usize>,
    model: Option<Mutex<TextRerank>>,
    execution: super::fastembed_attestation::FastembedExecutionState,
    bound_stream: Option<super::green_context::RetainedCudaStream>,
}

impl FastembedSparseLens {
    pub fn from_model_name_with_policy(
        name: impl Into<String>,
        model_name: &str,
        cache_dir: PathBuf,
        provider_policy: OnnxProviderPolicy,
    ) -> Result<Self> {
        let model_name = sparse_model_from_name(model_name)?;
        Self::from_model_with_policy(name, model_name, cache_dir, provider_policy)
    }

    pub fn from_model_with_policy(
        name: impl Into<String>,
        model_name: SparseModel,
        cache_dir: PathBuf,
        provider_policy: OnnxProviderPolicy,
    ) -> Result<Self> {
        let info = SparseTextEmbedding::get_model_info(&model_name);
        let files = special_files(
            &cache_dir,
            &info.model_code,
            &info.model_file,
            &info.additional_files,
        )?;
        Self::from_files_with_policy(name, model_name, files, provider_policy, None)
    }

    fn from_files_with_policy(
        name: impl Into<String>,
        model_name: SparseModel,
        files: OnnxModelFiles,
        provider_policy: OnnxProviderPolicy,
        expected_spec: Option<&LensSpec>,
    ) -> Result<Self> {
        let name = name.into();
        let max_batch = expected_spec.and_then(|spec| spec.max_batch);
        super::scoped_max_batch(max_batch)?;
        let info = SparseTextEmbedding::get_model_info(&model_name);
        let label = format!("onnx-fastembed-sparse:{}", info.model_code);
        let artifacts = super::fastembed_artifacts::FrozenFastembedArtifacts::snapshot(
            &files,
            &info.model_file,
            &info.additional_files,
            provider_policy.frozen_execution_token(),
            provider_policy,
        )?;
        let shape = SlotShape::Sparse(sparse_dim(&model_name));
        let corpus_hash = fastembed_sparse_corpus_hash(
            &info.model_code,
            provider_policy.frozen_execution_token(),
        );
        if let Some(spec) = expected_spec {
            ensure_spec_match(
                shape,
                artifacts.receipt().weights_sha256,
                corpus_hash,
                NormPolicy::Finite,
                spec,
            )?;
        }
        super::runtime_bundle::authorize_execution_policy(provider_policy)?;
        super::dynamic_ort::ensure_dynamic_ort(provider_policy)?;
        let contract = contract(
            name,
            artifacts.receipt().weights_sha256,
            shape,
            NormPolicy::Finite,
            corpus_hash,
        )?;
        let context = super::fastembed_attestation::FastembedModelContext::new(
            label.clone(),
            &info.model_code,
            &files,
            artifacts.receipt(),
            provider_policy,
        )?;
        super::arena::preflight_gpu_mem_limit_for_bytes(
            &label,
            provider_policy,
            artifacts.receipt().artifact_bytes,
        )
        .map_err(|error| context.error("vram_preflight", error))?;
        let (execution_providers, bound_stream) =
            super::fastembed_runtime::execution_providers(&label, provider_policy)
                .map_err(|error| context.error("execution_provider_configuration", error))?;
        let (model_bytes, tokenizer_files, external_initializers) = artifacts.into_parts();
        let mut user_model = UserDefinedSparseModel::new(model_bytes, tokenizer_files)
            .with_model(model_name.clone());
        for initializer in external_initializers {
            user_model =
                user_model.with_external_initializer(initializer.file_name, initializer.buffer);
        }
        let model = SparseTextEmbedding::try_new_from_user_defined(
            user_model,
            InitOptionsUserDefined::new()
                .with_intra_threads(1)
                .with_session_policy(context.session_policy()?)
                .with_execution_providers(execution_providers),
        )
        .map_err(|err| context.error("model_constructor", err))?;
        let model = CudaDropGuard::new(model, provider_policy).with_bound_stream(bound_stream);
        super::runtime_bundle::attest_after_model_constructor(
            provider_policy,
            model.bound_stream(),
        )
        .map_err(|error| context.error("runtime_bundle_attestation", error))?;
        let execution = super::fastembed_attestation::FastembedExecutionState::inspect(
            model.as_ref().session(),
            context,
            super::green_context::retained_stream_evidence(model.bound_stream()),
        )?;
        let (model, bound_stream) = model.into_parts();
        Ok(Self::new(
            contract,
            files,
            provider_policy,
            max_batch,
            execution,
            model,
            bound_stream,
        ))
    }

    pub fn from_lens_spec(spec: &LensSpec) -> Result<Self> {
        let (model_id, files, execution) = match &spec.runtime {
            LensRuntime::FastembedSparsePlaced {
                model_id,
                files,
                execution,
            } => (model_id, files, execution),
            LensRuntime::FastembedSparse { .. } => return Err(legacy_unbound_error("sparse")),
            _ => {
                return Err(super::config_invalid(
                    "LensSpec runtime is not placement-bound fastembed-sparse",
                ));
            }
        };
        let provider_policy = OnnxProviderPolicy::from_frozen_execution_token(execution)?;
        let model_name = sparse_model_from_name(model_id)?;
        let info = SparseTextEmbedding::get_model_info(&model_name);
        let files = super::fastembed_artifacts::persisted_model_files(
            &info.model_code,
            files,
            &info.model_file,
            &info.additional_files,
        )?;
        Self::from_files_with_policy(
            spec.name.clone(),
            model_name,
            files,
            provider_policy,
            Some(spec),
        )
    }

    fn new(
        contract: FrozenLensContract,
        files: OnnxModelFiles,
        provider_policy: OnnxProviderPolicy,
        max_batch: Option<usize>,
        execution: super::fastembed_attestation::FastembedExecutionState,
        model: SparseTextEmbedding,
        bound_stream: Option<super::green_context::GreenContextHandle>,
    ) -> Self {
        Self {
            id: contract.lens_id(),
            contract,
            files,
            provider_policy,
            max_batch,
            model: Some(Mutex::new(model)),
            execution,
            bound_stream: super::green_context::retain_for_model(bound_stream),
        }
    }

    pub fn contract(&self) -> &FrozenLensContract {
        &self.contract
    }

    pub fn files(&self) -> &OnnxModelFiles {
        &self.files
    }

    pub fn provider_policy(&self) -> &'static str {
        self.provider_policy.as_str()
    }
}

impl FastembedBgem3Lens {
    pub fn from_model_name_with_policy(
        name: impl Into<String>,
        model_name: &str,
        output: FastembedBgem3Output,
        cache_dir: PathBuf,
        provider_policy: OnnxProviderPolicy,
    ) -> Result<Self> {
        let model_name = bgem3_model_from_name(model_name)?;
        Self::from_model_with_policy(name, model_name, output, cache_dir, provider_policy)
    }

    pub fn from_model_with_policy(
        name: impl Into<String>,
        model_name: Bgem3Model,
        output: FastembedBgem3Output,
        cache_dir: PathBuf,
        provider_policy: OnnxProviderPolicy,
    ) -> Result<Self> {
        let info = Bgem3Embedding::get_model_info(&model_name);
        let files = special_files(
            &cache_dir,
            &info.model_code,
            &info.model_file,
            &info.additional_files,
        )?;
        Self::from_files_with_policy(name, model_name, output, files, provider_policy, None)
    }

    fn from_files_with_policy(
        name: impl Into<String>,
        model_name: Bgem3Model,
        output: FastembedBgem3Output,
        files: OnnxModelFiles,
        provider_policy: OnnxProviderPolicy,
        expected_spec: Option<&LensSpec>,
    ) -> Result<Self> {
        let name = name.into();
        let max_batch = expected_spec.and_then(|spec| spec.max_batch);
        super::scoped_max_batch(max_batch)?;
        let info = Bgem3Embedding::get_model_info(&model_name);
        let label = format!(
            "onnx-fastembed-bgem3:{}:{}",
            info.model_code,
            bgem3_runtime_name(output)
        );
        let artifacts = super::fastembed_artifacts::FrozenFastembedArtifacts::snapshot(
            &files,
            &info.model_file,
            &info.additional_files,
            provider_policy.frozen_execution_token(),
            provider_policy,
        )?;
        let shape = bgem3_shape(output);
        let corpus_hash = fastembed_bgem3_corpus_hash(
            &info.model_code,
            bgem3_corpus_token(output),
            provider_policy.frozen_execution_token(),
        );
        if let Some(spec) = expected_spec {
            ensure_spec_match(
                shape,
                artifacts.receipt().weights_sha256,
                corpus_hash,
                bgem3_norm(output),
                spec,
            )?;
        }
        super::runtime_bundle::authorize_execution_policy(provider_policy)?;
        super::dynamic_ort::ensure_dynamic_ort(provider_policy)?;
        let contract = contract(
            name,
            artifacts.receipt().weights_sha256,
            shape,
            bgem3_norm(output),
            corpus_hash,
        )?;
        let context = super::fastembed_attestation::FastembedModelContext::new(
            label.clone(),
            &info.model_code,
            &files,
            artifacts.receipt(),
            provider_policy,
        )?;
        super::arena::preflight_gpu_mem_limit_for_bytes(
            &label,
            provider_policy,
            artifacts.receipt().artifact_bytes,
        )
        .map_err(|error| context.error("vram_preflight", error))?;
        let (execution_providers, bound_stream) =
            super::fastembed_runtime::execution_providers(&label, provider_policy)
                .map_err(|error| context.error("execution_provider_configuration", error))?;
        let (model_bytes, tokenizer_files, external_initializers) = artifacts.into_parts();
        let mut user_model =
            UserDefinedBgem3Model::new(model_bytes, tokenizer_files).with_model(model_name);
        for initializer in external_initializers {
            user_model =
                user_model.with_external_initializer(initializer.file_name, initializer.buffer);
        }
        let model = Bgem3Embedding::try_new_from_user_defined(
            user_model,
            InitOptionsUserDefined::new()
                .with_intra_threads(1)
                .with_session_policy(context.session_policy()?)
                .with_execution_providers(execution_providers),
        )
        .map_err(|err| context.error("model_constructor", err))?;
        let model = CudaDropGuard::new(model, provider_policy).with_bound_stream(bound_stream);
        super::runtime_bundle::attest_after_model_constructor(
            provider_policy,
            model.bound_stream(),
        )
        .map_err(|error| context.error("runtime_bundle_attestation", error))?;
        let execution = super::fastembed_attestation::FastembedExecutionState::inspect(
            model.as_ref().session(),
            context,
            super::green_context::retained_stream_evidence(model.bound_stream()),
        )?;
        let (model, bound_stream) = model.into_parts();
        Ok(Self::new(
            contract,
            files,
            provider_policy,
            output,
            max_batch,
            execution,
            model,
            bound_stream,
        ))
    }

    pub fn from_lens_spec(spec: &LensSpec) -> Result<Self> {
        let (model_id, files, output, execution) = match &spec.runtime {
            LensRuntime::FastembedBgem3Placed {
                model_id,
                files,
                output,
                execution,
            } => (model_id, files, output, execution),
            LensRuntime::FastembedBgem3 { .. } => return Err(legacy_unbound_error("BGE-M3")),
            _ => {
                return Err(super::config_invalid(
                    "LensSpec runtime is not placement-bound fastembed-bgem3",
                ));
            }
        };
        let provider_policy = OnnxProviderPolicy::from_frozen_execution_token(execution)?;
        let model_name = bgem3_model_from_name(model_id)?;
        let info = Bgem3Embedding::get_model_info(&model_name);
        let files = super::fastembed_artifacts::persisted_model_files(
            &info.model_code,
            files,
            &info.model_file,
            &info.additional_files,
        )?;
        Self::from_files_with_policy(
            spec.name.clone(),
            model_name,
            *output,
            files,
            provider_policy,
            Some(spec),
        )
    }

    fn new(
        contract: FrozenLensContract,
        files: OnnxModelFiles,
        provider_policy: OnnxProviderPolicy,
        output: FastembedBgem3Output,
        max_batch: Option<usize>,
        execution: super::fastembed_attestation::FastembedExecutionState,
        model: Bgem3Embedding,
        bound_stream: Option<super::green_context::GreenContextHandle>,
    ) -> Self {
        Self {
            id: contract.lens_id(),
            output,
            contract,
            files,
            provider_policy,
            max_batch,
            model: Some(Mutex::new(model)),
            execution,
            bound_stream: super::green_context::retain_for_model(bound_stream),
        }
    }

    pub fn contract(&self) -> &FrozenLensContract {
        &self.contract
    }

    pub fn files(&self) -> &OnnxModelFiles {
        &self.files
    }

    pub fn provider_policy(&self) -> &'static str {
        self.provider_policy.as_str()
    }

    pub fn runtime_name(&self) -> &'static str {
        bgem3_runtime_name(self.output)
    }
}

impl FastembedRerankerLens {
    pub fn from_model_name_with_policy(
        name: impl Into<String>,
        model_name: &str,
        cache_dir: PathBuf,
        provider_policy: OnnxProviderPolicy,
    ) -> Result<Self> {
        let model_name = reranker_model_from_name(model_name)?;
        Self::from_model_with_policy(name, model_name, cache_dir, provider_policy)
    }

    pub fn from_model_with_policy(
        name: impl Into<String>,
        model_name: RerankerModel,
        cache_dir: PathBuf,
        provider_policy: OnnxProviderPolicy,
    ) -> Result<Self> {
        let info = TextRerank::get_model_info(&model_name);
        let files = special_files(
            &cache_dir,
            &info.model_code,
            &info.model_file,
            &info.additional_files,
        )?;
        Self::from_files_with_policy(name, model_name, files, provider_policy, None)
    }

    fn from_files_with_policy(
        name: impl Into<String>,
        model_name: RerankerModel,
        files: OnnxModelFiles,
        provider_policy: OnnxProviderPolicy,
        expected_spec: Option<&LensSpec>,
    ) -> Result<Self> {
        let name = name.into();
        let max_batch = expected_spec.and_then(|spec| spec.max_batch);
        super::scoped_max_batch(max_batch)?;
        let info = TextRerank::get_model_info(&model_name);
        let label = format!("onnx-fastembed-reranker:{}", info.model_code);
        let artifacts = super::fastembed_artifacts::FrozenFastembedArtifacts::snapshot(
            &files,
            &info.model_file,
            &info.additional_files,
            provider_policy.frozen_execution_token(),
            provider_policy,
        )?;
        let shape = SlotShape::Dense(1);
        let corpus_hash = fastembed_reranker_corpus_hash(
            &info.model_code,
            provider_policy.frozen_execution_token(),
        );
        if let Some(spec) = expected_spec {
            ensure_spec_match(
                shape,
                artifacts.receipt().weights_sha256,
                corpus_hash,
                NormPolicy::Finite,
                spec,
            )?;
        }
        super::runtime_bundle::authorize_execution_policy(provider_policy)?;
        super::dynamic_ort::ensure_dynamic_ort(provider_policy)?;
        let contract = contract(
            name,
            artifacts.receipt().weights_sha256,
            shape,
            NormPolicy::Finite,
            corpus_hash,
        )?;
        let context = super::fastembed_attestation::FastembedModelContext::new(
            label.clone(),
            &info.model_code,
            &files,
            artifacts.receipt(),
            provider_policy,
        )?;
        super::arena::preflight_gpu_mem_limit_for_bytes(
            &label,
            provider_policy,
            artifacts.receipt().artifact_bytes,
        )
        .map_err(|error| context.error("vram_preflight", error))?;
        let (execution_providers, bound_stream) =
            super::fastembed_runtime::execution_providers(&label, provider_policy)
                .map_err(|error| context.error("execution_provider_configuration", error))?;
        let (model_bytes, tokenizer_files, external_initializers) = artifacts.into_parts();
        let mut user_model = UserDefinedRerankingModel::new(model_bytes, tokenizer_files);
        for initializer in external_initializers {
            user_model =
                user_model.with_external_initializer(initializer.file_name, initializer.buffer);
        }
        let model = TextRerank::try_new_from_user_defined(
            user_model,
            RerankInitOptionsUserDefined::default()
                .with_intra_threads(1)
                .with_session_policy(context.session_policy()?)
                .with_execution_providers(execution_providers),
        )
        .map_err(|err| context.error("model_constructor", err))?;
        let model = CudaDropGuard::new(model, provider_policy).with_bound_stream(bound_stream);
        super::runtime_bundle::attest_after_model_constructor(
            provider_policy,
            model.bound_stream(),
        )
        .map_err(|error| context.error("runtime_bundle_attestation", error))?;
        let execution = super::fastembed_attestation::FastembedExecutionState::inspect(
            model.as_ref().session(),
            context,
            super::green_context::retained_stream_evidence(model.bound_stream()),
        )?;
        let (model, bound_stream) = model.into_parts();
        Ok(Self::new(
            contract,
            files,
            provider_policy,
            max_batch,
            execution,
            model,
            bound_stream,
        ))
    }

    pub fn from_lens_spec(spec: &LensSpec) -> Result<Self> {
        let (model_id, files, execution) = match &spec.runtime {
            LensRuntime::FastembedRerankerPlaced {
                model_id,
                files,
                execution,
            } => (model_id, files, execution),
            LensRuntime::FastembedReranker { .. } => {
                return Err(legacy_unbound_error("reranker"));
            }
            _ => {
                return Err(super::config_invalid(
                    "LensSpec runtime is not placement-bound fastembed-reranker",
                ));
            }
        };
        let provider_policy = OnnxProviderPolicy::from_frozen_execution_token(execution)?;
        let model_name = reranker_model_from_name(model_id)?;
        let info = TextRerank::get_model_info(&model_name);
        let files = super::fastembed_artifacts::persisted_model_files(
            &info.model_code,
            files,
            &info.model_file,
            &info.additional_files,
        )?;
        Self::from_files_with_policy(
            spec.name.clone(),
            model_name,
            files,
            provider_policy,
            Some(spec),
        )
    }

    fn new(
        contract: FrozenLensContract,
        files: OnnxModelFiles,
        provider_policy: OnnxProviderPolicy,
        max_batch: Option<usize>,
        execution: super::fastembed_attestation::FastembedExecutionState,
        model: TextRerank,
        bound_stream: Option<super::green_context::GreenContextHandle>,
    ) -> Self {
        Self {
            id: contract.lens_id(),
            contract,
            files,
            provider_policy,
            max_batch,
            model: Some(Mutex::new(model)),
            execution,
            bound_stream: super::green_context::retain_for_model(bound_stream),
        }
    }

    pub fn contract(&self) -> &FrozenLensContract {
        &self.contract
    }

    pub fn files(&self) -> &OnnxModelFiles {
        &self.files
    }

    pub fn provider_policy(&self) -> &'static str {
        self.provider_policy.as_str()
    }
}

impl Lens for FastembedSparseLens {
    fn id(&self) -> LensId {
        self.id
    }

    fn shape(&self) -> SlotShape {
        self.contract.shape()
    }

    fn modality(&self) -> Modality {
        Modality::Text
    }

    fn measure(&self, input: &Input) -> Result<SlotVector> {
        single_vector(self.id, self.measure_batch(std::slice::from_ref(input))?)
            .map_err(|error| self.execution.fail_terminal("output_validation", error))
    }

    fn measure_batch(&self, inputs: &[Input]) -> Result<Vec<SlotVector>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        self.execution.ensure_usable()?;
        let texts = input_texts(self, inputs)?;
        let mut model = lock_model(&self.model, "sparse")
            .map_err(|error| self.execution.fail_terminal("model_lock", error))?;
        self.execution.ensure_usable()?;
        let max_batch = super::scoped_max_batch(self.max_batch)?;
        if self.execution.requires_single_run_profile()? {
            let mut texts = texts.into_iter();
            let first = texts.next().ok_or_else(|| {
                self.execution.fail_terminal(
                    "first_inference_input",
                    "nonempty sparse FastEmbed measurement lost its first real input",
                )
            })?;
            let first_embeddings = model
                .embed(vec![first], Some(1))
                .map_err(|error| self.execution.fail_terminal("inference", error))?;
            super::green_context::synchronize_retained_stream(
                self.bound_stream.as_ref(),
                self.provider_policy,
                "onnx-fastembed-sparse-first-profiled-run",
            )
            .map_err(|error| self.execution.fail_terminal("cuda_synchronize", error))?;
            let mut vectors = sparse_batch(first_embeddings, sparse_shape_dim(self.shape()), 1)
                .map_err(|error| self.execution.fail_terminal("output_validation", error))?;
            self.execution
                .complete_first_inference(|| model.end_profiling())?;

            let remaining = texts.collect::<Vec<_>>();
            if !remaining.is_empty() {
                self.execution.ensure_usable()?;
                let expected = remaining.len();
                let embeddings = model
                    .embed(remaining, max_batch)
                    .map_err(|error| self.execution.fail_terminal("inference", error))?;
                super::green_context::synchronize_retained_stream(
                    self.bound_stream.as_ref(),
                    self.provider_policy,
                    "onnx-fastembed-sparse-attested-batch-remainder",
                )
                .map_err(|error| self.execution.fail_terminal("cuda_synchronize", error))?;
                vectors.extend(
                    sparse_batch(embeddings, sparse_shape_dim(self.shape()), expected).map_err(
                        |error| self.execution.fail_terminal("output_validation", error),
                    )?,
                );
            }
            return Ok(vectors);
        }
        let embeddings = model
            .embed(texts, max_batch)
            .map_err(|error| self.execution.fail_terminal("inference", error))?;
        super::green_context::synchronize_retained_stream(
            self.bound_stream.as_ref(),
            self.provider_policy,
            "onnx-fastembed-sparse",
        )
        .map_err(|error| self.execution.fail_terminal("cuda_synchronize", error))?;
        let vectors = sparse_batch(embeddings, sparse_shape_dim(self.shape()), inputs.len())
            .map_err(|error| self.execution.fail_terminal("output_validation", error))?;
        self.execution
            .complete_first_inference(|| model.end_profiling())?;
        Ok(vectors)
    }

    fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>> {
        self.execution.execution_attestation()
    }
}

impl Lens for FastembedBgem3Lens {
    fn id(&self) -> LensId {
        self.id
    }

    fn shape(&self) -> SlotShape {
        self.contract.shape()
    }

    fn modality(&self) -> Modality {
        Modality::Text
    }

    fn measure(&self, input: &Input) -> Result<SlotVector> {
        single_vector(self.id, self.measure_batch(std::slice::from_ref(input))?)
            .map_err(|error| self.execution.fail_terminal("output_validation", error))
    }

    fn measure_batch(&self, inputs: &[Input]) -> Result<Vec<SlotVector>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        self.execution.ensure_usable()?;
        let texts = input_texts(self, inputs)?;
        let mut model = lock_model(&self.model, "BGE-M3")
            .map_err(|error| self.execution.fail_terminal("model_lock", error))?;
        self.execution.ensure_usable()?;
        let max_batch = super::scoped_max_batch(self.max_batch)?;
        if self.execution.requires_single_run_profile()? {
            let mut texts = texts.into_iter();
            let first = texts.next().ok_or_else(|| {
                self.execution.fail_terminal(
                    "first_inference_input",
                    "nonempty BGE-M3 FastEmbed measurement lost its first real input",
                )
            })?;
            let first_output = model
                .embed(vec![first], Some(1))
                .map_err(|error| self.execution.fail_terminal("inference", error))?;
            super::green_context::synchronize_retained_stream(
                self.bound_stream.as_ref(),
                self.provider_policy,
                "onnx-fastembed-bgem3-first-profiled-run",
            )
            .map_err(|error| self.execution.fail_terminal("cuda_synchronize", error))?;
            let mut vectors = match self.output {
                FastembedBgem3Output::Dense => dense_batch(first_output.dense, BGE_M3_DENSE_DIM, 1),
                FastembedBgem3Output::Sparse => {
                    sparse_batch(first_output.sparse, BGE_M3_SPARSE_DIM, 1)
                }
                FastembedBgem3Output::Colbert => {
                    multi_batch(first_output.colbert, BGE_M3_DENSE_DIM, 1)
                }
            }
            .map_err(|error| self.execution.fail_terminal("output_validation", error))?;
            self.execution
                .complete_first_inference(|| model.end_profiling())?;

            let remaining = texts.collect::<Vec<_>>();
            if !remaining.is_empty() {
                self.execution.ensure_usable()?;
                let expected = remaining.len();
                let output = model
                    .embed(remaining, max_batch)
                    .map_err(|error| self.execution.fail_terminal("inference", error))?;
                super::green_context::synchronize_retained_stream(
                    self.bound_stream.as_ref(),
                    self.provider_policy,
                    "onnx-fastembed-bgem3-attested-batch-remainder",
                )
                .map_err(|error| self.execution.fail_terminal("cuda_synchronize", error))?;
                vectors.extend(
                    match self.output {
                        FastembedBgem3Output::Dense => {
                            dense_batch(output.dense, BGE_M3_DENSE_DIM, expected)
                        }
                        FastembedBgem3Output::Sparse => {
                            sparse_batch(output.sparse, BGE_M3_SPARSE_DIM, expected)
                        }
                        FastembedBgem3Output::Colbert => {
                            multi_batch(output.colbert, BGE_M3_DENSE_DIM, expected)
                        }
                    }
                    .map_err(|error| self.execution.fail_terminal("output_validation", error))?,
                );
            }
            return Ok(vectors);
        }
        let output = model
            .embed(texts, max_batch)
            .map_err(|error| self.execution.fail_terminal("inference", error))?;
        super::green_context::synchronize_retained_stream(
            self.bound_stream.as_ref(),
            self.provider_policy,
            "onnx-fastembed-bgem3",
        )
        .map_err(|error| self.execution.fail_terminal("cuda_synchronize", error))?;
        let vectors = match self.output {
            FastembedBgem3Output::Dense => {
                dense_batch(output.dense, BGE_M3_DENSE_DIM, inputs.len())
            }
            FastembedBgem3Output::Sparse => {
                sparse_batch(output.sparse, BGE_M3_SPARSE_DIM, inputs.len())
            }
            FastembedBgem3Output::Colbert => {
                multi_batch(output.colbert, BGE_M3_DENSE_DIM, inputs.len())
            }
        }
        .map_err(|error| self.execution.fail_terminal("output_validation", error))?;
        self.execution
            .complete_first_inference(|| model.end_profiling())?;
        Ok(vectors)
    }

    fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>> {
        self.execution.execution_attestation()
    }
}

impl Lens for FastembedRerankerLens {
    fn id(&self) -> LensId {
        self.id
    }

    fn shape(&self) -> SlotShape {
        SlotShape::Dense(1)
    }

    fn modality(&self) -> Modality {
        Modality::Text
    }

    fn measure(&self, input: &Input) -> Result<SlotVector> {
        single_vector(self.id, self.measure_batch(std::slice::from_ref(input))?)
            .map_err(|error| self.execution.fail_terminal("output_validation", error))
    }

    fn measure_batch(&self, inputs: &[Input]) -> Result<Vec<SlotVector>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        self.execution.ensure_usable()?;
        let pairs = inputs
            .iter()
            .map(|input| crate::runtime::common::text_from_input(self, input).map(rerank_pair))
            .collect::<Result<Vec<_>>>()?;
        let mut out = Vec::with_capacity(inputs.len());
        let mut model = lock_model(&self.model, "reranker")
            .map_err(|error| self.execution.fail_terminal("model_lock", error))?;
        self.execution.ensure_usable()?;
        super::scoped_max_batch(self.max_batch)?;
        let requires_single_run_profile = self.execution.requires_single_run_profile()?;
        let mut index = 0usize;
        for (query, doc) in pairs {
            let results = model
                .rerank(query, [doc], false, Some(1))
                .map_err(|error| self.execution.fail_terminal("inference", error))?;
            let score = results
                .first()
                .ok_or_else(|| CalyxError::lens_dim_mismatch("reranker returned no score"))
                .map_err(|error| self.execution.fail_terminal("output_validation", error))?
                .score;
            vectors::ensure_finite("reranker score", &[score])
                .map_err(|error| self.execution.fail_terminal("output_validation", error))?;
            out.push(SlotVector::Dense {
                dim: 1,
                data: vec![score],
            });
            if requires_single_run_profile && index == 0 {
                super::green_context::synchronize_retained_stream(
                    self.bound_stream.as_ref(),
                    self.provider_policy,
                    "onnx-fastembed-reranker-first-profiled-run",
                )
                .map_err(|error| self.execution.fail_terminal("cuda_synchronize", error))?;
                self.execution
                    .complete_first_inference(|| model.end_profiling())?;
            }
            index = index.checked_add(1).ok_or_else(|| {
                self.execution
                    .fail_terminal("batch_accounting", "reranker input index exceeds usize")
            })?;
        }
        if !requires_single_run_profile || out.len() > 1 {
            super::green_context::synchronize_retained_stream(
                self.bound_stream.as_ref(),
                self.provider_policy,
                if requires_single_run_profile {
                    "onnx-fastembed-reranker-attested-batch-remainder"
                } else {
                    "onnx-fastembed-reranker"
                },
            )
            .map_err(|error| self.execution.fail_terminal("cuda_synchronize", error))?;
        }
        if !requires_single_run_profile {
            self.execution
                .complete_first_inference(|| model.end_profiling())?;
        }
        Ok(out)
    }

    fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>> {
        self.execution.execution_attestation()
    }
}

impl Drop for FastembedSparseLens {
    fn drop(&mut self) {
        leak_cuda_model_and_stream(
            &mut self.model,
            &mut self.bound_stream,
            self.provider_policy,
        );
    }
}

impl Drop for FastembedBgem3Lens {
    fn drop(&mut self) {
        leak_cuda_model_and_stream(
            &mut self.model,
            &mut self.bound_stream,
            self.provider_policy,
        );
    }
}

impl Drop for FastembedRerankerLens {
    fn drop(&mut self) {
        leak_cuda_model_and_stream(
            &mut self.model,
            &mut self.bound_stream,
            self.provider_policy,
        );
    }
}
