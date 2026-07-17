//! RoBERTa style lens adapter for PH39 identity slots.

use calyx_core::{
    CalyxError, Input, Lens, LensId, Modality, Result as CalyxResult, RuntimeExecutionAttestation,
    SlotShape, SlotVector,
};
#[cfg(feature = "onnx-lens")]
use ort::session::Session;
#[cfg(feature = "onnx-lens")]
use ort::value::{Tensor, TensorElementType, ValueType};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(feature = "onnx-lens")]
use tokenizers::Tokenizer;

use crate::error::WardError;
#[cfg(feature = "onnx-lens")]
use crate::onnx_session::{
    ManagedWardOnnxSession, WardCpuAuthorization, WardOnnxArtifactBundle,
    WardOnnxExecutionAttestation, build_session, snapshot_cpu_artifacts, snapshot_cuda_artifacts,
};

pub const DEFAULT_STYLE_MODEL_PATH: &str = "/var/lib/calyx/models/style/style-embed-v1.onnx";
pub const DEFAULT_STYLE_TOKENIZER_PATH: &str = "/var/lib/calyx/models/style/tokenizer.json";
pub const STYLE_DIM: usize = 768;
pub const STYLE_MAX_TOKENS: usize = 512;
const STYLE_LENS_NAME: &str = "style-embed-v1";
const STYLE_SOURCE_REPO: &str = "AnnaWegmann/Style-Embedding";
const STYLE_SOURCE_REVISION: &str = "d7d0f5ca829316a8f5695e49dfce80b86db5e76c";
const OUTPUT_SHAPE: &[u8] = b"dense:f32:text:style:768";

/// ONNX execution-provider policy for the style adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StyleProviderPolicy {
    CudaFailLoud,
    CpuExplicit,
}

impl StyleProviderPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CudaFailLoud => crate::CUDA_ONNX_PROVIDER_POLICY,
            Self::CpuExplicit => crate::CPU_ONNX_PROVIDER_POLICY,
        }
    }
}

/// Backend seam used by tests while production uses the pinned ONNX session.
pub trait StyleEmbeddingBackend: Send + Sync {
    fn embed(&self, text: &str) -> Result<Vec<f32>, WardError>;
    fn output_dim(&self) -> usize;

    fn input_names(&self) -> Vec<String> {
        Vec::new()
    }

    fn output_names(&self) -> Vec<String> {
        Vec::new()
    }

    fn provider_policy(&self) -> &'static str {
        "test_backend"
    }

    /// Runtime placement from the exact committed session, available only
    /// after a successful real inference.
    fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>, WardError> {
        Ok(None)
    }

    #[cfg(feature = "onnx-lens")]
    fn durable_execution_attestation(
        &self,
        _lens_id: LensId,
    ) -> Result<Option<WardOnnxExecutionAttestation>, WardError> {
        Ok(None)
    }
}

/// Frozen style/register lens. Runtime state is limited to ORT and tokenizer handles.
pub struct StyleLens {
    model_path: PathBuf,
    tokenizer_path: PathBuf,
    lens_id: LensId,
    dim: usize,
    backend: Box<dyn StyleEmbeddingBackend>,
}

impl fmt::Debug for StyleLens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StyleLens")
            .field("model_path", &self.model_path)
            .field("tokenizer_path", &self.tokenizer_path)
            .field("lens_id", &self.lens_id)
            .field("dim", &self.dim)
            .field("provider_policy", &self.provider_policy())
            .finish()
    }
}

impl StyleLens {
    pub fn new(model_path: &Path) -> Result<Self, WardError> {
        Self::new_with_provider_policy(model_path, StyleProviderPolicy::CudaFailLoud)
    }

    #[cfg(feature = "onnx-lens")]
    pub fn new_cpu_explicit(
        model_path: &Path,
        authorization: &WardCpuAuthorization,
    ) -> Result<Self, WardError> {
        let tokenizer_path = model_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("tokenizer.json");
        Self::new_cpu_explicit_with_tokenizer(model_path, &tokenizer_path, authorization)
    }

    pub fn new_with_provider_policy(
        model_path: &Path,
        policy: StyleProviderPolicy,
    ) -> Result<Self, WardError> {
        if policy == StyleProviderPolicy::CpuExplicit {
            return Err(WardError::CpuCompanionUnauthorized {
                reason: "StyleProviderPolicy::CpuExplicit requires new_cpu_explicit and a WardCpuAuthorization"
                    .to_string(),
            });
        }
        let tokenizer_path = model_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("tokenizer.json");
        Self::new_with_tokenizer_and_provider_policy(model_path, &tokenizer_path, policy)
    }

    #[cfg(feature = "onnx-lens")]
    pub fn new_with_tokenizer_and_provider_policy(
        model_path: &Path,
        tokenizer_path: &Path,
        policy: StyleProviderPolicy,
    ) -> Result<Self, WardError> {
        if policy == StyleProviderPolicy::CpuExplicit {
            return Err(WardError::CpuCompanionUnauthorized {
                reason: "StyleProviderPolicy::CpuExplicit requires new_cpu_explicit_with_tokenizer and a WardCpuAuthorization"
                    .to_string(),
            });
        }
        let artifacts = snapshot_cuda_artifacts("style", model_path, Some(tokenizer_path))?;
        Self::from_artifacts(model_path, tokenizer_path, artifacts)
    }

    #[cfg(feature = "onnx-lens")]
    pub fn new_cpu_explicit_with_tokenizer(
        model_path: &Path,
        tokenizer_path: &Path,
        authorization: &WardCpuAuthorization,
    ) -> Result<Self, WardError> {
        let artifacts =
            snapshot_cpu_artifacts("style", model_path, Some(tokenizer_path), authorization)?;
        Self::from_artifacts(model_path, tokenizer_path, artifacts)
    }

    #[cfg(feature = "onnx-lens")]
    fn from_artifacts(
        model_path: &Path,
        tokenizer_path: &Path,
        artifacts: WardOnnxArtifactBundle,
    ) -> Result<Self, WardError> {
        let weights_hash = artifacts.lens_weights_sha256();
        let backend = OnnxStyleBackend::new(artifacts)?;
        Self::from_backend(
            model_path.to_path_buf(),
            tokenizer_path.to_path_buf(),
            weights_hash,
            backend,
        )
    }

    /// Fail-closed stub: the ONNX style backend is compiled out when the
    /// `onnx-lens` feature is disabled (#191). Callers that need real ONNX
    /// inference must rebuild with `--features onnx-lens`; tests can still
    /// inject a mock backend through [`StyleLens::from_backend`].
    #[cfg(not(feature = "onnx-lens"))]
    pub fn new_with_tokenizer_and_provider_policy(
        _model_path: &Path,
        _tokenizer_path: &Path,
        _policy: StyleProviderPolicy,
    ) -> Result<Self, WardError> {
        Err(WardError::LensFeatureDisabled { lens: "style" })
    }

    pub fn from_backend<B>(
        model_path: PathBuf,
        tokenizer_path: PathBuf,
        weights_sha256: [u8; 32],
        backend: B,
    ) -> Result<Self, WardError>
    where
        B: StyleEmbeddingBackend + 'static,
    {
        let dim = backend.output_dim();
        if dim != STYLE_DIM {
            return Err(WardError::ModelDimMismatch {
                expected: STYLE_DIM,
                actual: dim,
            });
        }
        let corpus_hash = hash_parts(&[
            STYLE_SOURCE_REPO.as_bytes(),
            STYLE_SOURCE_REVISION.as_bytes(),
            b"input_ids",
            b"attention_mask",
            b"last_hidden_state",
            b"mean_pool_attention_mask",
        ]);
        let lens_id =
            LensId::from_parts(STYLE_LENS_NAME, &weights_sha256, &corpus_hash, OUTPUT_SHAPE);

        Ok(Self {
            model_path,
            tokenizer_path,
            lens_id,
            dim,
            backend: Box::new(backend),
        })
    }

    pub fn embed_style(&self, text: &str) -> Result<Vec<f32>, WardError> {
        if text.trim().is_empty() {
            return Err(WardError::InvalidInput {
                reason: "empty style text".to_string(),
            });
        }
        let raw = self.backend.embed(text)?;
        normalize_unit(raw, self.dim)
    }

    pub fn embed_style_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, WardError> {
        texts.iter().map(|text| self.embed_style(text)).collect()
    }

    pub fn model_path(&self) -> &Path {
        &self.model_path
    }

    pub fn tokenizer_path(&self) -> &Path {
        &self.tokenizer_path
    }

    pub fn dim(&self) -> usize {
        self.dim
    }

    pub fn provider_policy(&self) -> &'static str {
        self.backend.provider_policy()
    }

    pub fn input_names(&self) -> Vec<String> {
        self.backend.input_names()
    }

    pub fn output_names(&self) -> Vec<String> {
        self.backend.output_names()
    }

    pub fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>, WardError> {
        self.backend.execution_attestation()
    }

    #[cfg(feature = "onnx-lens")]
    pub fn durable_execution_attestation(
        &self,
    ) -> Result<Option<WardOnnxExecutionAttestation>, WardError> {
        self.backend.durable_execution_attestation(self.lens_id)
    }
}

impl Lens for StyleLens {
    fn id(&self) -> LensId {
        self.lens_id
    }

    fn shape(&self) -> SlotShape {
        SlotShape::Dense(self.dim as u32)
    }

    fn modality(&self) -> Modality {
        Modality::Text
    }

    fn measure(&self, input: &Input) -> CalyxResult<SlotVector> {
        if input.modality != Modality::Text {
            return Err(ward_as_calyx(WardError::InvalidInput {
                reason: format!("style lens expects text, got {:?}", input.modality),
            }));
        }
        let text = std::str::from_utf8(&input.bytes).map_err(|err| {
            ward_as_calyx(WardError::InvalidInput {
                reason: format!("style Input bytes must be UTF-8: {err}"),
            })
        })?;
        let data = self.embed_style(text).map_err(ward_as_calyx)?;
        Ok(SlotVector::Dense {
            dim: self.dim as u32,
            data,
        })
    }

    fn execution_attestation(&self) -> CalyxResult<Option<RuntimeExecutionAttestation>> {
        self.backend.execution_attestation().map_err(ward_as_calyx)
    }
}

#[cfg(feature = "onnx-lens")]
struct OnnxStyleBackend {
    session: ManagedWardOnnxSession,
    tokenizer: Tokenizer,
    input_ids_name: String,
    attention_mask_name: String,
    output_name: String,
    input_names: Vec<String>,
    output_names: Vec<String>,
    output_dim: usize,
}

#[cfg(feature = "onnx-lens")]
impl OnnxStyleBackend {
    fn new(artifacts: WardOnnxArtifactBundle) -> Result<Self, WardError> {
        let tokenizer = Tokenizer::from_bytes(artifacts.tokenizer_bytes()?)
            .map_err(|error| artifacts.error("style", "tokenizer_commit", error))?;
        let session = build_session("style", artifacts)?;
        let (input_names, output_names) = session.inspect_session(|raw| {
            Ok((
                raw.inputs()
                    .iter()
                    .map(|input| input.name().to_string())
                    .collect::<Vec<_>>(),
                raw.outputs()
                    .iter()
                    .map(|output| output.name().to_string())
                    .collect::<Vec<_>>(),
            ))
        })?;
        let input_ids_name = choose_name(&session, &input_names, "input_ids", "input")?;
        let attention_mask_name = choose_name(&session, &input_names, "attention_mask", "input")?;
        let output_name = choose_name(&session, &output_names, "last_hidden_state", "output")?;
        let output_dim = session.inspect_session(|raw| output_dim(&session, raw, &output_name))?;
        if output_dim != STYLE_DIM {
            return Err(session.error(
                "model_metadata",
                format!("model output dim {output_dim} != expected {STYLE_DIM}"),
            ));
        }

        Ok(Self {
            session,
            tokenizer,
            input_ids_name,
            attention_mask_name,
            output_name,
            input_names,
            output_names,
            output_dim,
        })
    }

    fn tokenize(&self, text: &str) -> Result<(Vec<i64>, Vec<i64>), WardError> {
        let encoding = self.tokenizer.encode(text, true).map_err(runtime_error)?;
        let len = encoding.get_ids().len().min(STYLE_MAX_TOKENS);
        if len == 0 {
            return Err(WardError::InvalidInput {
                reason: "style tokenizer emitted no tokens".to_string(),
            });
        }
        let ids = encoding
            .get_ids()
            .iter()
            .take(len)
            .map(|value| i64::from(*value))
            .collect::<Vec<_>>();
        let attention = encoding
            .get_attention_mask()
            .iter()
            .take(len)
            .map(|value| i64::from(*value))
            .collect::<Vec<_>>();
        Ok((ids, attention))
    }
}

#[cfg(feature = "onnx-lens")]
impl StyleEmbeddingBackend for OnnxStyleBackend {
    fn embed(&self, text: &str) -> Result<Vec<f32>, WardError> {
        let (ids, attention) = self.tokenize(text)?;
        let seq_len = ids.len();
        let ids_tensor = Tensor::from_array(([1usize, seq_len], ids))
            .map_err(|error| self.session.error("input_tensor", error))?;
        let mask_tensor = Tensor::from_array(([1usize, seq_len], attention.clone()))
            .map_err(|error| self.session.error("attention_tensor", error))?;
        let pooled = self.session.run_real_inference(|raw| {
            let outputs = raw
                .run(ort::inputs! {
                    self.input_ids_name.as_str() => ids_tensor,
                    self.attention_mask_name.as_str() => mask_tensor
                })
                .map_err(|error| self.session.error("inference", error))?;
            let output = outputs.get(&self.output_name).ok_or_else(|| {
                self.session.error(
                    "output_lookup",
                    format!("ONNX output {} missing", self.output_name),
                )
            })?;
            let (_, data) = output
                .try_extract_tensor::<f32>()
                .map_err(|error| self.session.error("output_extract", error))?;
            let pooled = mean_pool(data, &attention, self.output_dim)
                .map_err(|error| self.session.error("output_validation", error))?;
            normalize_unit(pooled, self.output_dim)
                .map_err(|error| self.session.error("output_semantic_validation", error))
        })?;
        Ok(pooled)
    }

    fn output_dim(&self) -> usize {
        self.output_dim
    }

    fn input_names(&self) -> Vec<String> {
        self.input_names.clone()
    }

    fn output_names(&self) -> Vec<String> {
        self.output_names.clone()
    }

    fn provider_policy(&self) -> &'static str {
        self.session.provider_policy()
    }

    fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>, WardError> {
        self.session.execution_attestation()
    }

    fn durable_execution_attestation(
        &self,
        lens_id: LensId,
    ) -> Result<Option<WardOnnxExecutionAttestation>, WardError> {
        self.session.durable_execution_attestation(lens_id)
    }
}

#[cfg(feature = "onnx-lens")]
fn choose_name(
    session: &ManagedWardOnnxSession,
    names: &[String],
    preferred: &str,
    kind: &str,
) -> Result<String, WardError> {
    names
        .iter()
        .find(|name| name.as_str() == preferred)
        .cloned()
        .ok_or_else(|| {
            session.error(
                "model_metadata",
                format!("ONNX session has no {kind} named {preferred}"),
            )
        })
}

#[cfg(feature = "onnx-lens")]
fn output_dim(
    managed: &ManagedWardOnnxSession,
    session: &Session,
    output_name: &str,
) -> Result<usize, WardError> {
    let outlet = session
        .outputs()
        .iter()
        .find(|output| output.name() == output_name)
        .ok_or_else(|| {
            managed.error(
                "model_metadata",
                format!("ONNX output {output_name} missing from metadata"),
            )
        })?;
    match outlet.dtype() {
        ValueType::Tensor { ty, shape, .. } if *ty == TensorElementType::Float32 => shape
            .iter()
            .rev()
            .copied()
            .find(|dim| *dim > 0)
            .map(|dim| dim as usize)
            .ok_or_else(|| {
                managed.error(
                    "model_metadata",
                    format!("ONNX output {output_name} has no static positive dim"),
                )
            }),
        other => Err(managed.error(
            "model_metadata",
            format!("ONNX output {output_name} is not f32 tensor: {other:?}"),
        )),
    }
}

#[cfg(feature = "onnx-lens")]
fn mean_pool(
    token_embeddings: &[f32],
    attention: &[i64],
    dim: usize,
) -> Result<Vec<f32>, WardError> {
    if token_embeddings.len() != attention.len() * dim {
        return Err(WardError::ModelDimMismatch {
            expected: attention.len() * dim,
            actual: token_embeddings.len(),
        });
    }
    let mut pooled = vec![0.0_f32; dim];
    let mut active = 0.0_f32;
    for (token_idx, mask) in attention.iter().enumerate() {
        if *mask != 0 {
            active += 1.0;
            let start = token_idx * dim;
            for dim_idx in 0..dim {
                pooled[dim_idx] += token_embeddings[start + dim_idx];
            }
        }
    }
    if active <= 0.0 {
        return Err(WardError::InvalidInput {
            reason: "style attention mask has no active tokens".to_string(),
        });
    }
    pooled.iter_mut().for_each(|value| *value /= active);
    Ok(pooled)
}

fn normalize_unit(mut data: Vec<f32>, expected_dim: usize) -> Result<Vec<f32>, WardError> {
    if data.len() != expected_dim {
        return Err(WardError::ModelDimMismatch {
            expected: expected_dim,
            actual: data.len(),
        });
    }
    if data.iter().any(|value| !value.is_finite()) {
        return Err(WardError::InvalidInput {
            reason: "style embedding contains NaN or Inf".to_string(),
        });
    }
    let norm = data.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm <= f32::EPSILON {
        return Err(WardError::InvalidInput {
            reason: "style embedding has zero norm".to_string(),
        });
    }
    data.iter_mut().for_each(|value| *value /= norm);
    Ok(data)
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(feature = "onnx-lens")]
fn runtime_error(error: impl fmt::Display) -> WardError {
    WardError::Runtime {
        reason: error.to_string(),
    }
}

fn ward_as_calyx(error: WardError) -> CalyxError {
    let remediation = error.remediation();
    CalyxError {
        code: error.code(),
        message: error.to_string(),
        remediation,
    }
}
