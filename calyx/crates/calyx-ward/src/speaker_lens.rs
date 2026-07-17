//! WavLM speaker lens adapter for PH39 identity slots.

use std::fmt;
#[cfg(feature = "onnx-lens")]
use std::fs::File;
#[cfg(feature = "onnx-lens")]
use std::io::Read;
use std::path::{Path, PathBuf};

use calyx_core::{
    CalyxError, Input, Lens, LensId, Modality, Result as CalyxResult, RuntimeExecutionAttestation,
    SlotShape, SlotVector,
};
#[cfg(feature = "onnx-lens")]
use ort::session::Session;
#[cfg(feature = "onnx-lens")]
use ort::value::{Tensor, TensorElementType, ValueType};
use sha2::{Digest, Sha256};

use crate::error::WardError;
#[cfg(feature = "onnx-lens")]
use crate::onnx_session::{ManagedWardOnnxSession, build_cpu_session, build_cuda_session};

pub const DEFAULT_WAVLM_MODEL_PATH: &str = "/var/lib/calyx/models/wavlm/wavlm-base-plus-sv.onnx";
pub const WAVLM_SAMPLE_RATE: u32 = 16_000;
pub const WAVLM_DIM: usize = 512;
const SPEAKER_LENS_NAME: &str = "wavlm-base-plus-sv";
const WAVLM_SOURCE_REPO: &str = "Xenova/wavlm-base-plus-sv";
const WAVLM_SOURCE_REVISION: &str = "e61029603001bd11295c36d878698708bf59190f";
const OUTPUT_SHAPE: &[u8] = b"dense:f32:audio:speaker:512";

/// ONNX execution-provider policy for the WavLM speaker adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpeakerProviderPolicy {
    CudaFailLoud,
    CpuExplicit,
}

impl SpeakerProviderPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CudaFailLoud => crate::CUDA_ONNX_PROVIDER_POLICY,
            Self::CpuExplicit => crate::CPU_ONNX_PROVIDER_POLICY,
        }
    }
}

/// Backend seam used by tests while production uses the pinned ONNX session.
pub trait SpeakerEmbeddingBackend: Send + Sync {
    fn embed_16khz(&self, audio_pcm: &[f32]) -> Result<Vec<f32>, WardError>;
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

    fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>, WardError> {
        Ok(None)
    }
}

/// Frozen WavLM speaker lens. Runtime state is limited to ORT's session handle.
pub struct SpeakerLens {
    model_path: PathBuf,
    lens_id: LensId,
    dim: usize,
    backend: Box<dyn SpeakerEmbeddingBackend>,
}

impl fmt::Debug for SpeakerLens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpeakerLens")
            .field("model_path", &self.model_path)
            .field("lens_id", &self.lens_id)
            .field("dim", &self.dim)
            .field("provider_policy", &self.provider_policy())
            .finish()
    }
}

impl SpeakerLens {
    pub fn new(model_path: &Path) -> Result<Self, WardError> {
        Self::new_with_provider_policy(model_path, SpeakerProviderPolicy::CudaFailLoud)
    }

    pub fn new_cpu_explicit(model_path: &Path) -> Result<Self, WardError> {
        Self::new_with_provider_policy(model_path, SpeakerProviderPolicy::CpuExplicit)
    }

    #[cfg(feature = "onnx-lens")]
    pub fn new_with_provider_policy(
        model_path: &Path,
        policy: SpeakerProviderPolicy,
    ) -> Result<Self, WardError> {
        let model_hash = sha256_file(model_path)?;
        let backend = OnnxSpeakerBackend::new(model_path, policy)?;
        Self::from_backend(model_path.to_path_buf(), model_hash, backend)
    }

    /// Fail-closed stub: the ONNX WavLM backend is compiled out when the
    /// `onnx-lens` feature is disabled (#191). Callers needing real ONNX
    /// inference must rebuild with `--features onnx-lens`; tests can still
    /// inject a mock backend through [`SpeakerLens::from_backend`].
    #[cfg(not(feature = "onnx-lens"))]
    pub fn new_with_provider_policy(
        _model_path: &Path,
        _policy: SpeakerProviderPolicy,
    ) -> Result<Self, WardError> {
        Err(WardError::LensFeatureDisabled { lens: "speaker" })
    }

    pub fn from_backend<B>(
        model_path: PathBuf,
        model_sha256: [u8; 32],
        backend: B,
    ) -> Result<Self, WardError>
    where
        B: SpeakerEmbeddingBackend + 'static,
    {
        let dim = backend.output_dim();
        if dim != WAVLM_DIM {
            return Err(WardError::ModelDimMismatch {
                expected: WAVLM_DIM,
                actual: dim,
            });
        }
        let corpus_hash = hash_parts(&[
            WAVLM_SOURCE_REPO.as_bytes(),
            WAVLM_SOURCE_REVISION.as_bytes(),
            b"input_values",
            b"embeddings",
        ]);
        let lens_id =
            LensId::from_parts(SPEAKER_LENS_NAME, &model_sha256, &corpus_hash, OUTPUT_SHAPE);

        Ok(Self {
            model_path,
            lens_id,
            dim,
            backend: Box::new(backend),
        })
    }

    pub fn embed_speaker(
        &self,
        audio_pcm: &[f32],
        sample_rate: u32,
    ) -> Result<Vec<f32>, WardError> {
        let prepared = prepare_audio(audio_pcm, sample_rate)?;
        let raw = self.backend.embed_16khz(&prepared)?;
        normalize_unit(raw, self.dim)
    }

    pub fn model_path(&self) -> &Path {
        &self.model_path
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
}

impl Lens for SpeakerLens {
    fn id(&self) -> LensId {
        self.lens_id
    }

    fn shape(&self) -> SlotShape {
        SlotShape::Dense(self.dim as u32)
    }

    fn modality(&self) -> Modality {
        Modality::Audio
    }

    fn measure(&self, input: &Input) -> CalyxResult<SlotVector> {
        if input.modality != Modality::Audio {
            return Err(ward_as_calyx(WardError::InvalidInput {
                reason: format!("speaker lens expects audio, got {:?}", input.modality),
            }));
        }
        let audio = pcm_f32_le(&input.bytes).map_err(ward_as_calyx)?;
        // Generic Input carries bytes only; this lens expects 16 kHz f32 PCM here.
        let data = self
            .embed_speaker(&audio, WAVLM_SAMPLE_RATE)
            .map_err(ward_as_calyx)?;
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
struct OnnxSpeakerBackend {
    session: ManagedWardOnnxSession,
    input_name: String,
    output_name: String,
    input_names: Vec<String>,
    output_names: Vec<String>,
    output_dim: usize,
}

#[cfg(feature = "onnx-lens")]
impl OnnxSpeakerBackend {
    fn new(model_path: &Path, policy: SpeakerProviderPolicy) -> Result<Self, WardError> {
        let session = match policy {
            SpeakerProviderPolicy::CudaFailLoud => build_cuda_session("speaker", model_path),
            SpeakerProviderPolicy::CpuExplicit => build_cpu_session("speaker", model_path),
        }?;
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
        let input_name = choose_name(&session, &input_names, "input_values", "input")?;
        let output_name = choose_name(&session, &output_names, "embeddings", "output")?;
        let output_dim = session.inspect_session(|raw| output_dim(&session, raw, &output_name))?;
        if output_dim != WAVLM_DIM {
            return Err(session.error(
                "model_metadata",
                format!("model output dim {output_dim} != expected {WAVLM_DIM}"),
            ));
        }

        Ok(Self {
            session,
            input_name,
            output_name,
            input_names,
            output_names,
            output_dim,
        })
    }
}

#[cfg(feature = "onnx-lens")]
impl SpeakerEmbeddingBackend for OnnxSpeakerBackend {
    fn embed_16khz(&self, audio_pcm: &[f32]) -> Result<Vec<f32>, WardError> {
        let tensor = Tensor::from_array(([1usize, audio_pcm.len()], audio_pcm.to_vec()))
            .map_err(|error| self.session.error("input_tensor", error))?;
        let embedding = self.session.run_real_inference(|raw| {
            let outputs = raw
                .run(ort::inputs! { self.input_name.as_str() => tensor })
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
            if data.len() != self.output_dim {
                return Err(self.session.error(
                    "output_validation",
                    format!(
                        "model output dim {} != expected {}",
                        data.len(),
                        self.output_dim
                    ),
                ));
            }
            normalize_unit(data.to_vec(), self.output_dim)
                .map_err(|error| self.session.error("output_semantic_validation", error))
        })?;
        Ok(embedding)
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
        .or_else(|| names.first())
        .cloned()
        .ok_or_else(|| session.error("model_metadata", format!("ONNX session has no {kind}s")))
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

fn prepare_audio(audio_pcm: &[f32], sample_rate: u32) -> Result<Vec<f32>, WardError> {
    if audio_pcm.is_empty() {
        return Err(WardError::InvalidInput {
            reason: "empty speaker audio".to_string(),
        });
    }
    if sample_rate == 0 {
        return Err(WardError::InvalidInput {
            reason: "speaker sample_rate must be non-zero".to_string(),
        });
    }
    if audio_pcm.iter().any(|value| !value.is_finite()) {
        return Err(WardError::InvalidInput {
            reason: "speaker audio contains NaN or Inf".to_string(),
        });
    }
    let trimmed = trim_edge_silence(audio_pcm);
    if sample_rate == WAVLM_SAMPLE_RATE {
        Ok(trimmed.to_vec())
    } else {
        Ok(resample_linear(trimmed, sample_rate, WAVLM_SAMPLE_RATE))
    }
}

fn trim_edge_silence(audio_pcm: &[f32]) -> &[f32] {
    let start = audio_pcm.iter().position(|value| value.abs() > 1.0e-6);
    let end = audio_pcm.iter().rposition(|value| value.abs() > 1.0e-6);
    match (start, end) {
        (Some(first), Some(last)) => &audio_pcm[first..=last],
        _ => audio_pcm,
    }
}

fn resample_linear(audio_pcm: &[f32], in_rate: u32, out_rate: u32) -> Vec<f32> {
    let out_len = ((audio_pcm.len() as f64) * (out_rate as f64) / (in_rate as f64))
        .round()
        .max(1.0) as usize;
    if audio_pcm.len() == 1 {
        return vec![audio_pcm[0]; out_len];
    }
    let scale = in_rate as f64 / out_rate as f64;
    (0..out_len)
        .map(|idx| {
            let pos = idx as f64 * scale;
            let lo = pos.floor() as usize;
            let hi = (lo + 1).min(audio_pcm.len() - 1);
            let frac = (pos - lo as f64) as f32;
            audio_pcm[lo] * (1.0 - frac) + audio_pcm[hi] * frac
        })
        .collect()
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
            reason: "speaker embedding contains NaN or Inf".to_string(),
        });
    }
    let norm = data.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm <= f32::EPSILON {
        return Err(WardError::InvalidInput {
            reason: "speaker embedding has zero norm".to_string(),
        });
    }
    data.iter_mut().for_each(|value| *value /= norm);
    Ok(data)
}

fn pcm_f32_le(bytes: &[u8]) -> Result<Vec<f32>, WardError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(WardError::InvalidInput {
            reason: "audio Input bytes must be little-endian f32 PCM".to_string(),
        });
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes(chunk.try_into().expect("chunk size is four")))
        .collect())
}

#[cfg(feature = "onnx-lens")]
fn sha256_file(path: &Path) -> Result<[u8; 32], WardError> {
    let mut file = File::open(path).map_err(|_| WardError::ModelNotFound {
        path: path.to_path_buf(),
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(runtime_error)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
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
