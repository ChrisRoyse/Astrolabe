#[cfg(feature = "onnx-lens")]
use std::fmt;
#[cfg(feature = "onnx-lens")]
use std::fs::File;
#[cfg(feature = "onnx-lens")]
use std::io::Read;
#[cfg(feature = "onnx-lens")]
use std::path::{Path, PathBuf};

#[cfg(feature = "onnx-lens")]
use ort::session::Session;
#[cfg(feature = "onnx-lens")]
use ort::value::{Tensor, TensorElementType, ValueType};
use sha2::{Digest, Sha256};
#[cfg(feature = "onnx-lens")]
use tokenizers::Tokenizer;

#[cfg(any(feature = "onnx-lens", test))]
use crate::error::WardError;
#[cfg(feature = "onnx-lens")]
use crate::onnx_session::{ManagedWardOnnxSession, build_cpu_session, build_cuda_session};

#[cfg(feature = "onnx-lens")]
use super::{
    BENIGN_LABEL, INJECTION_LABEL, INJECTION_LABELS, INJECTION_MAX_TOKENS, InjectionProviderPolicy,
    InjectionScoreBackend,
};

#[cfg(feature = "onnx-lens")]
pub(super) struct OnnxInjectionBackend {
    session: ManagedWardOnnxSession,
    tokenizer: Tokenizer,
    input_ids_name: String,
    attention_mask_name: String,
    output_name: String,
    input_names: Vec<String>,
    output_names: Vec<String>,
}

#[cfg(feature = "onnx-lens")]
impl OnnxInjectionBackend {
    pub(super) fn new(
        model_path: &Path,
        tokenizer_path: &Path,
        policy: InjectionProviderPolicy,
    ) -> Result<Self, WardError> {
        let tokenizer =
            Tokenizer::from_file(tokenizer_path).map_err(|_| WardError::ModelNotFound {
                path: tokenizer_path.to_path_buf(),
            })?;
        let session = match policy {
            InjectionProviderPolicy::CudaFailLoud => build_cuda_session("injection", model_path),
            InjectionProviderPolicy::CpuExplicit => build_cpu_session("injection", model_path),
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
        let input_ids_name = choose_name(&session, &input_names, "input_ids", "input")?;
        let attention_mask_name = choose_name(&session, &input_names, "attention_mask", "input")?;
        let output_name = choose_name(&session, &output_names, "logits", "output")?;
        session.inspect_session(|raw| assert_logits_shape(&session, raw, &output_name))?;
        Ok(Self {
            session,
            tokenizer,
            input_ids_name,
            attention_mask_name,
            output_name,
            input_names,
            output_names,
        })
    }

    fn tokenize(&self, text: &str) -> Result<(Vec<i64>, Vec<i64>), WardError> {
        let encoding = self.tokenizer.encode(text, true).map_err(runtime_error)?;
        let len = encoding.get_ids().len().min(INJECTION_MAX_TOKENS);
        if len == 0 {
            return Err(WardError::InvalidInput {
                reason: "injection tokenizer emitted no tokens".to_string(),
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
impl InjectionScoreBackend for OnnxInjectionBackend {
    fn benign_score(&self, text: &str) -> Result<f32, WardError> {
        let (ids, attention) = self.tokenize(text)?;
        let seq_len = ids.len();
        let ids_tensor = Tensor::from_array(([1usize, seq_len], ids))
            .map_err(|error| self.session.error("input_tensor", error))?;
        let mask_tensor = Tensor::from_array(([1usize, seq_len], attention))
            .map_err(|error| self.session.error("attention_tensor", error))?;
        let score = self.session.run_real_inference(|raw| {
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
            if data.len() != INJECTION_LABELS {
                return Err(self.session.error(
                    "output_validation",
                    format!(
                        "model output dim {} != expected {}",
                        data.len(),
                        INJECTION_LABELS
                    ),
                ));
            }
            softmax_benign(data[BENIGN_LABEL], data[INJECTION_LABEL])
        })?;
        Ok(score)
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

    fn execution_attestation(
        &self,
    ) -> Result<Option<calyx_core::RuntimeExecutionAttestation>, WardError> {
        self.session.execution_attestation()
    }
}

/// Numerically-stable 2-class softmax, returning `P(benign)`.
#[cfg(any(feature = "onnx-lens", test))]
pub(super) fn softmax_benign(benign_logit: f32, injection_logit: f32) -> Result<f32, WardError> {
    if !benign_logit.is_finite() || !injection_logit.is_finite() {
        return Err(WardError::InvalidInput {
            reason: "injection logits contain NaN or Inf".to_string(),
        });
    }
    let max = benign_logit.max(injection_logit);
    let benign_exp = (benign_logit - max).exp();
    let injection_exp = (injection_logit - max).exp();
    let denom = benign_exp + injection_exp;
    if denom <= f32::EPSILON {
        return Err(WardError::InvalidInput {
            reason: "injection softmax denominator underflow".to_string(),
        });
    }
    Ok(benign_exp / denom)
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

/// The injection head must be an f32 tensor whose last static dim is 2.
#[cfg(feature = "onnx-lens")]
fn assert_logits_shape(
    managed: &ManagedWardOnnxSession,
    session: &Session,
    output_name: &str,
) -> Result<(), WardError> {
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
        ValueType::Tensor { ty, shape, .. } if *ty == TensorElementType::Float32 => {
            match shape.iter().rev().copied().find(|dim| *dim > 0) {
                Some(dim) if dim as usize == INJECTION_LABELS => Ok(()),
                Some(dim) => Err(managed.error(
                    "model_metadata",
                    format!("model output dim {dim} != expected {INJECTION_LABELS}"),
                )),
                // Fully-dynamic logits dim: validated per-call against the
                // extracted tensor length instead.
                None => Ok(()),
            }
        }
        other => Err(managed.error(
            "model_metadata",
            format!("ONNX output {output_name} is not f32 tensor: {other:?}"),
        )),
    }
}

/// ONNX external-data sidecar path for `model.onnx` -> `model.onnx.data`.
#[cfg(feature = "onnx-lens")]
pub(super) fn external_data_path(model_path: &Path) -> PathBuf {
    let mut name = model_path.file_name().unwrap_or_default().to_os_string();
    name.push(".data");
    model_path.with_file_name(name)
}

#[cfg(feature = "onnx-lens")]
pub(super) fn sha256_files(paths: &[&Path]) -> Result<[u8; 32], WardError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    for path in paths {
        let mut file = File::open(path).map_err(|_| WardError::ModelNotFound {
            path: (*path).to_path_buf(),
        })?;
        loop {
            let n = file.read(&mut buf).map_err(runtime_error)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    }
    Ok(hasher.finalize().into())
}

pub(super) fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
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
