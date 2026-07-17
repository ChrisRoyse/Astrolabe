use std::path::PathBuf;
use std::sync::Mutex;

use calyx_core::{
    CalyxError, Input, Lens, LensId, Modality, Result, RuntimeExecutionAttestation, SlotShape,
    SlotVector,
};
use fastembed::{
    Bgem3Embedding, Bgem3InitOptions, Bgem3Model, RerankInitOptions, RerankerModel,
    SparseInitOptions, SparseModel, SparseTextEmbedding, TextRerank,
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

pub struct FastembedSparseLens {
    id: LensId,
    contract: FrozenLensContract,
    files: OnnxModelFiles,
    provider_policy: OnnxProviderPolicy,
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
    model: Option<Mutex<Bgem3Embedding>>,
    execution: super::fastembed_attestation::FastembedExecutionState,
    bound_stream: Option<super::green_context::RetainedCudaStream>,
}

pub struct FastembedRerankerLens {
    id: LensId,
    contract: FrozenLensContract,
    files: OnnxModelFiles,
    provider_policy: OnnxProviderPolicy,
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
        super::dynamic_ort::ensure_dynamic_ort(provider_policy)?;
        let name = name.into();
        let info = SparseTextEmbedding::get_model_info(&model_name);
        let label = format!("onnx-fastembed-sparse:{}", info.model_code);
        let files = special_files(
            &cache_dir,
            &info.model_code,
            &info.model_file,
            &info.additional_files,
        )?;
        let shape = SlotShape::Sparse(sparse_dim(&model_name));
        let contract = contract(
            name,
            &files,
            shape,
            NormPolicy::Finite,
            fastembed_sparse_corpus_hash(&info.model_code),
        )?;
        let context = super::fastembed_attestation::FastembedModelContext::new(
            label.clone(),
            &info.model_code,
            &files,
            contract.weights_sha256(),
            provider_policy,
        )?;
        let (execution_providers, bound_stream) =
            super::fastembed_runtime::execution_providers(&label, provider_policy)
                .map_err(|error| context.error("execution_provider_configuration", error))?;
        let model = SparseTextEmbedding::try_new(
            SparseInitOptions::new(model_name.clone())
                .with_cache_dir(cache_dir.clone())
                .with_show_download_progress(false)
                .with_intra_threads(1)
                .with_session_policy(context.session_policy())
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
        )?;
        let (model, bound_stream) = model.into_parts();
        Ok(Self::new(
            contract,
            files,
            provider_policy,
            execution,
            model,
            bound_stream,
        ))
    }

    pub fn from_lens_spec(spec: &LensSpec) -> Result<Self> {
        let LensRuntime::FastembedSparse { model_id, .. } = &spec.runtime else {
            return Err(super::config_invalid(
                "LensSpec runtime is not fastembed-sparse",
            ));
        };
        let lens = Self::from_model_name_with_policy(
            spec.name.clone(),
            model_id,
            super::fastembed_runtime::default_cache_root(),
            OnnxProviderPolicy::CudaFailLoud,
        )?;
        ensure_spec_match(lens.shape(), lens.contract.weights_sha256(), spec)?;
        Ok(lens)
    }

    fn new(
        contract: FrozenLensContract,
        files: OnnxModelFiles,
        provider_policy: OnnxProviderPolicy,
        execution: super::fastembed_attestation::FastembedExecutionState,
        model: SparseTextEmbedding,
        bound_stream: Option<super::green_context::GreenContextHandle>,
    ) -> Self {
        Self {
            id: contract.lens_id(),
            contract,
            files,
            provider_policy,
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
        super::dynamic_ort::ensure_dynamic_ort(provider_policy)?;
        let name = name.into();
        let info = Bgem3Embedding::get_model_info(&model_name);
        let label = format!(
            "onnx-fastembed-bgem3:{}:{}",
            info.model_code,
            bgem3_runtime_name(output)
        );
        let files = special_files(
            &cache_dir,
            &info.model_code,
            &info.model_file,
            &info.additional_files,
        )?;
        let contract = contract(
            name,
            &files,
            bgem3_shape(output),
            bgem3_norm(output),
            fastembed_bgem3_corpus_hash(&info.model_code, bgem3_corpus_token(output)),
        )?;
        let context = super::fastembed_attestation::FastembedModelContext::new(
            label.clone(),
            &info.model_code,
            &files,
            contract.weights_sha256(),
            provider_policy,
        )?;
        let (execution_providers, bound_stream) =
            super::fastembed_runtime::execution_providers(&label, provider_policy)
                .map_err(|error| context.error("execution_provider_configuration", error))?;
        let model = Bgem3Embedding::try_new(
            Bgem3InitOptions::new(model_name)
                .with_cache_dir(cache_dir.clone())
                .with_show_download_progress(false)
                .with_intra_threads(1)
                .with_session_policy(context.session_policy())
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
        )?;
        let (model, bound_stream) = model.into_parts();
        Ok(Self::new(
            contract,
            files,
            provider_policy,
            output,
            execution,
            model,
            bound_stream,
        ))
    }

    pub fn from_lens_spec(spec: &LensSpec) -> Result<Self> {
        let LensRuntime::FastembedBgem3 {
            model_id, output, ..
        } = &spec.runtime
        else {
            return Err(super::config_invalid(
                "LensSpec runtime is not fastembed-bgem3",
            ));
        };
        let lens = Self::from_model_name_with_policy(
            spec.name.clone(),
            model_id,
            *output,
            super::fastembed_runtime::default_cache_root(),
            OnnxProviderPolicy::CudaFailLoud,
        )?;
        ensure_spec_match(lens.shape(), lens.contract.weights_sha256(), spec)?;
        Ok(lens)
    }

    fn new(
        contract: FrozenLensContract,
        files: OnnxModelFiles,
        provider_policy: OnnxProviderPolicy,
        output: FastembedBgem3Output,
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
        super::dynamic_ort::ensure_dynamic_ort(provider_policy)?;
        let name = name.into();
        let info = TextRerank::get_model_info(&model_name);
        let label = format!("onnx-fastembed-reranker:{}", info.model_code);
        let files = special_files(
            &cache_dir,
            &info.model_code,
            &info.model_file,
            &info.additional_files,
        )?;
        let contract = contract(
            name,
            &files,
            SlotShape::Dense(1),
            NormPolicy::Finite,
            fastembed_reranker_corpus_hash(&info.model_code),
        )?;
        let context = super::fastembed_attestation::FastembedModelContext::new(
            label.clone(),
            &info.model_code,
            &files,
            contract.weights_sha256(),
            provider_policy,
        )?;
        let (execution_providers, bound_stream) =
            super::fastembed_runtime::execution_providers(&label, provider_policy)
                .map_err(|error| context.error("execution_provider_configuration", error))?;
        let model = TextRerank::try_new(
            RerankInitOptions::new(model_name)
                .with_cache_dir(cache_dir.clone())
                .with_show_download_progress(false)
                .with_intra_threads(1)
                .with_session_policy(context.session_policy())
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
        )?;
        let (model, bound_stream) = model.into_parts();
        Ok(Self::new(
            contract,
            files,
            provider_policy,
            execution,
            model,
            bound_stream,
        ))
    }

    pub fn from_lens_spec(spec: &LensSpec) -> Result<Self> {
        let LensRuntime::FastembedReranker { model_id, .. } = &spec.runtime else {
            return Err(super::config_invalid(
                "LensSpec runtime is not fastembed-reranker",
            ));
        };
        let lens = Self::from_model_name_with_policy(
            spec.name.clone(),
            model_id,
            super::fastembed_runtime::default_cache_root(),
            OnnxProviderPolicy::CudaFailLoud,
        )?;
        ensure_spec_match(lens.shape(), lens.contract.weights_sha256(), spec)?;
        Ok(lens)
    }

    fn new(
        contract: FrozenLensContract,
        files: OnnxModelFiles,
        provider_policy: OnnxProviderPolicy,
        execution: super::fastembed_attestation::FastembedExecutionState,
        model: TextRerank,
        bound_stream: Option<super::green_context::GreenContextHandle>,
    ) -> Self {
        Self {
            id: contract.lens_id(),
            contract,
            files,
            provider_policy,
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
    }

    fn measure_batch(&self, inputs: &[Input]) -> Result<Vec<SlotVector>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        self.execution.ensure_usable()?;
        let texts = input_texts(self, inputs)?;
        let mut model = lock_model(&self.model, "sparse")?;
        let embeddings = model
            .embed(texts, None)
            .map_err(|error| self.execution.error("inference", error))?;
        super::green_context::synchronize_retained_stream(
            self.bound_stream.as_ref(),
            self.provider_policy,
            "onnx-fastembed-sparse",
        )
        .map_err(|error| self.execution.error("cuda_synchronize", error))?;
        let vectors = sparse_batch(embeddings, sparse_shape_dim(self.shape()), inputs.len())?;
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
    }

    fn measure_batch(&self, inputs: &[Input]) -> Result<Vec<SlotVector>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        self.execution.ensure_usable()?;
        let texts = input_texts(self, inputs)?;
        let mut model = lock_model(&self.model, "BGE-M3")?;
        let output = model
            .embed(texts, None)
            .map_err(|error| self.execution.error("inference", error))?;
        super::green_context::synchronize_retained_stream(
            self.bound_stream.as_ref(),
            self.provider_policy,
            "onnx-fastembed-bgem3",
        )
        .map_err(|error| self.execution.error("cuda_synchronize", error))?;
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
        }?;
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
    }

    fn measure_batch(&self, inputs: &[Input]) -> Result<Vec<SlotVector>> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        self.execution.ensure_usable()?;
        let mut out = Vec::with_capacity(inputs.len());
        let mut model = lock_model(&self.model, "reranker")?;
        for input in inputs {
            let text = crate::runtime::common::text_from_input(self, input)?;
            let (query, doc) = rerank_pair(text);
            let results = model
                .rerank(query, [doc], false, Some(1))
                .map_err(|error| self.execution.error("inference", error))?;
            let score = results
                .first()
                .ok_or_else(|| CalyxError::lens_dim_mismatch("reranker returned no score"))?
                .score;
            vectors::ensure_finite("reranker score", &[score])?;
            out.push(SlotVector::Dense {
                dim: 1,
                data: vec![score],
            });
        }
        super::green_context::synchronize_retained_stream(
            self.bound_stream.as_ref(),
            self.provider_policy,
            "onnx-fastembed-reranker",
        )
        .map_err(|error| self.execution.error("cuda_synchronize", error))?;
        self.execution
            .complete_first_inference(|| model.end_profiling())?;
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
