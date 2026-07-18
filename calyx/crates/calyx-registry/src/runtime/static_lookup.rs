use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use calyx_core::{
    CalyxError, Input, Lens, LensId, Modality, Result, RuntimeExecutionAttestation, SlotShape,
    SlotVector,
};
use tokenizers::{Encoding, Tokenizer, TruncationParams};

use crate::frozen::{FrozenLensContract, NormPolicy};
use crate::identity::{ContractFacts, contract_from_facts, static_lookup_corpus_hash};
use crate::runtime::common::{DEFAULT_MAX_TOKENS, hash_files, normalize_unit, text_from_input};
use crate::spec::{LensRuntime, LensSpec};

mod backend;
mod matrix;
mod writer;

pub use backend::StaticLookupBackend;
use matrix::StaticLookupMatrix;
pub use writer::{StaticLookupArtifact, StaticLookupWriter};

/// Current authenticated static-lookup matrix magic (format v2).
///
/// Layout (little-endian):
/// `magic "CXLKUP2\0" (8 B) | u32 rows | u32 dim | u8 dtype | 3 B zero pad |
/// u32 vocab_size | u64 body_len | body blake3 digest (32 B)` then the body.
///
/// Body per dtype: int8 = `f32 scale[rows]` (per-row dequantization
/// multipliers) followed by `i8 codes[rows*dim]`; f16/f32 = raw values only.
/// `vocab_size` binds the tokenizer vocabulary identity: it must equal `rows`
/// and the loaded tokenizer's vocabulary size, so token ids and matrix rows can
/// never silently drift apart.
const MAGIC: &[u8; 8] = b"CXLKUP2\0";
/// Legacy global-scale magic — refused fail-closed.
const MAGIC_LEGACY_V1: &[u8; 8] = b"CXLKUP1\0";
const HEADER_LEN: usize = 64;
const DTYPE_I8: u8 = 1;
const DTYPE_F16: u8 = 2;
const DTYPE_F32: u8 = 3;
const UNK_TOKENS: &[&str] = &["[UNK]", "<unk>", "<UNK>"];

#[derive(Debug)]
pub struct StaticLookupLens {
    id: LensId,
    contract: FrozenLensContract,
    files: StaticLookupFiles,
    tokenizer: Tokenizer,
    matrix: StaticLookupMatrix,
    executed: AtomicBool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticLookupFiles {
    pub embeddings_file: PathBuf,
    pub tokenizer: PathBuf,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StaticLookupFileSpec {
    pub name: String,
    pub embeddings_file: PathBuf,
    pub tokenizer: PathBuf,
    pub dim: Option<u32>,
    pub norm_policy: NormPolicy,
    pub expected_weights_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticLookupDType {
    Int8,
    F16,
    F32,
}

impl StaticLookupDType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Int8 => "int8",
            Self::F16 => "f16",
            Self::F32 => "f32",
        }
    }

    pub(crate) const fn width(self) -> usize {
        match self {
            Self::Int8 => 1,
            Self::F16 => 2,
            Self::F32 => 4,
        }
    }
}

impl StaticLookupLens {
    pub fn from_files(spec: StaticLookupFileSpec) -> Result<Self> {
        ensure_file("embeddings_file", &spec.embeddings_file)?;
        ensure_file("tokenizer", &spec.tokenizer)?;
        let matrix = StaticLookupMatrix::open(&spec.embeddings_file)?;
        if let Some(expected_dim) = spec.dim
            && matrix.dim != expected_dim
        {
            return Err(CalyxError::lens_dim_mismatch(format!(
                "static lookup matrix dim {} != expected {expected_dim}",
                matrix.dim
            )));
        }
        let tokenizer = read_tokenizer(&spec.tokenizer)?;
        let tokenizer_vocab = tokenizer.get_vocab_size(true);
        if tokenizer_vocab as u64 != u64::from(matrix.rows) {
            return Err(CalyxError {
                code: "CALYX_LENS_VOCAB_BINDING_MISMATCH",
                message: format!(
                    "tokenizer {} vocabulary size {tokenizer_vocab} != matrix rows {}; the \
                     CXLKUP2 vocab_size binding requires a one-to-one vocabulary",
                    spec.tokenizer.display(),
                    matrix.rows
                ),
                remediation: "commission the static lookup lens with the tokenizer the matrix \
                              was exported against",
            });
        }
        let weights_sha256 = hash_files(&[spec.embeddings_file.clone(), spec.tokenizer.clone()])?;
        if let Some(expected) = spec.expected_weights_sha256
            && weights_sha256 != expected
        {
            return Err(CalyxError::lens_frozen_violation(
                "static lookup matrix/tokenizer hash does not match LensSpec",
            ));
        }
        let contract = contract_from_facts(ContractFacts {
            name: spec.name,
            weights_sha256,
            corpus_hash: static_lookup_corpus_hash(matrix.dim, matrix.dtype.as_str()),
            shape: SlotShape::Dense(matrix.dim),
            modality: Modality::Text,
            norm: spec.norm_policy,
        });
        let id = contract.lens_id();
        Ok(Self {
            id,
            contract,
            files: StaticLookupFiles {
                embeddings_file: spec.embeddings_file,
                tokenizer: spec.tokenizer,
            },
            tokenizer,
            matrix,
            executed: AtomicBool::new(false),
        })
    }

    pub fn from_lens_spec(spec: &LensSpec) -> Result<Self> {
        let LensRuntime::StaticLookup {
            embeddings_file,
            tokenizer,
            dim,
        } = &spec.runtime
        else {
            return Err(config_invalid("LensSpec runtime is not static_lookup"));
        };
        Self::from_files(StaticLookupFileSpec {
            name: spec.name.clone(),
            embeddings_file: embeddings_file.clone(),
            tokenizer: tokenizer.clone(),
            dim: Some(*dim),
            norm_policy: spec.norm_policy,
            expected_weights_sha256: Some(spec.weights_sha256),
        })
    }

    pub fn contract(&self) -> &FrozenLensContract {
        &self.contract
    }

    pub fn files(&self) -> &StaticLookupFiles {
        &self.files
    }

    pub fn dtype(&self) -> StaticLookupDType {
        self.matrix.dtype
    }

    pub fn row_count(&self) -> u32 {
        self.matrix.rows
    }

    /// Returns the CPU backend selected when the matrix mmap was opened.
    pub fn backend(&self) -> StaticLookupBackend {
        self.matrix.backend
    }

    pub fn lens_spec(&self) -> LensSpec {
        LensSpec {
            name: self.contract.name().to_string(),
            runtime: LensRuntime::StaticLookup {
                embeddings_file: self.files.embeddings_file.clone(),
                tokenizer: self.files.tokenizer.clone(),
                dim: self.matrix.dim,
            },
            output: self.contract.shape(),
            modality: self.contract.modality(),
            weights_sha256: self.contract.weights_sha256(),
            corpus_hash: self.contract.corpus_hash(),
            norm_policy: self.contract.norm_policy(),
            max_batch: None,
            axis: None,
            asymmetry: calyx_core::Asymmetry::None,
            quant_default: calyx_core::QuantPolicy::turboquant_default(),
            truncate_dim: None,
            recall_delta: crate::spec::default_recall_delta(),
            retrieval_only: false,
            excluded_from_dedup: false,
        }
    }
}

impl Lens for StaticLookupLens {
    fn id(&self) -> LensId {
        self.id
    }

    fn shape(&self) -> SlotShape {
        SlotShape::Dense(self.matrix.dim)
    }

    fn modality(&self) -> Modality {
        Modality::Text
    }

    fn measure(&self, input: &Input) -> Result<SlotVector> {
        let text = text_from_input(self, input)?;
        if text.trim().is_empty() {
            return Err(empty_projection_refused(
                "input text is empty after trimming",
            ));
        }
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|err| CalyxError::lens_dim_mismatch(format!("tokenize failed: {err}")))?;
        let mut data = self.pool_encoding(&encoding)?;
        apply_norm(self.contract.norm_policy(), &mut data)?;
        let vector = SlotVector::Dense {
            dim: self.matrix.dim,
            data,
        };
        self.contract.verify_vector(self.id, &vector)?;
        self.executed.store(true, Ordering::Release);
        Ok(vector)
    }

    fn execution_attestation(&self) -> Result<Option<RuntimeExecutionAttestation>> {
        if !self.executed.load(Ordering::Acquire) {
            return Ok(None);
        }
        Ok(Some(RuntimeExecutionAttestation {
            runtime: "static-lookup".to_string(),
            provider: "memory-mapped-lookup".to_string(),
            device: "cpu".to_string(),
            loader_dtype: Some(self.matrix.dtype.as_str().to_string()),
            compute_dtype: Some("f32".to_string()),
            evidence: format!(
                "completed_memory_mapped_lookup:{}",
                self.matrix.backend.as_str()
            ),
            total_compute_nodes: None,
            cpu_compute_nodes: None,
        }))
    }
}

impl StaticLookupLens {
    fn pool_encoding(&self, encoding: &Encoding) -> Result<Vec<f32>> {
        let ids = encoding.get_ids();
        let tokens = encoding.get_tokens();
        let mut out = vec![0.0_f32; self.matrix.dim as usize];
        let mut count = 0_u32;
        for (idx, token_id) in ids.iter().copied().enumerate() {
            if tokens.get(idx).is_some_and(|token| is_unknown_token(token)) {
                continue;
            }
            self.matrix.add_row(token_id, &mut out)?;
            count += 1;
        }
        if count == 0 {
            return Err(empty_projection_refused(
                "every token in the input is unknown to the bound vocabulary",
            ));
        }
        let inv = 1.0 / count as f32;
        for value in &mut out {
            *value *= inv;
        }
        Ok(out)
    }
}

fn read_tokenizer(path: &Path) -> Result<Tokenizer> {
    let mut tokenizer = Tokenizer::from_file(path)
        .map_err(|err| config_invalid(format!("load static tokenizer failed: {err}")))?;
    tokenizer
        .with_truncation(Some(TruncationParams {
            max_length: DEFAULT_MAX_TOKENS,
            ..Default::default()
        }))
        .map_err(|err| CalyxError::lens_dim_mismatch(format!("set truncation failed: {err}")))?;
    Ok(tokenizer)
}

fn apply_norm(policy: NormPolicy, data: &mut [f32]) -> Result<()> {
    if data.iter().any(|value| !value.is_finite()) {
        return Err(CalyxError::lens_numerical_invariant(
            "static lookup emitted NaN or Inf",
        ));
    }
    match policy {
        NormPolicy::None | NormPolicy::Finite => Ok(()),
        NormPolicy::L2 { .. } | NormPolicy::Unit { .. } => normalize_unit(data),
        NormPolicy::DeclaredByModel { .. } => Ok(()),
    }
}

/// Fail-closed refusal for inputs that would otherwise become a fabricated
/// vector: a lookup lens must never invent a unit direction for content it
/// cannot see.
fn empty_projection_refused(reason: &str) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_EMPTY_PROJECTION",
        message: format!("static lookup lens cannot measure this input: {reason}"),
        remediation: "skip this input for the static lookup slot or record it as absent; a \
                      fabricated unit vector would poison similarity measurements",
    }
}

fn is_unknown_token(token: &str) -> bool {
    UNK_TOKENS.contains(&token)
}

fn ensure_file(label: &str, path: &Path) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(config_invalid(format!(
            "static lookup {label} {} is not a file",
            path.display()
        )))
    }
}

fn config_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_CONFIG_INVALID",
        message: message.into(),
        remediation: "fix static lookup matrix/tokenizer or register a supported lens spec",
    }
}
