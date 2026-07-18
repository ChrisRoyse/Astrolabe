use std::path::Path;

use calyx_core::Result;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

use super::IDX_MIX;
use crate::index::vecfile::{FbinVectors, I8BinVectors};

const SYNTHETIC_IDENTITY_DOMAIN: &[u8] = b"calyx/partitioned/synthetic-source/v1\0";

/// Persisted identity of the exact vector source that generated a partitioned
/// vault. File-backed sources bind both authenticated payload bytes and their
/// canonical shape/format identity. The deterministic synthetic diagnostic
/// source has no payload file and is labeled explicitly instead of pretending
/// to carry a payload digest.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VectorSourceIdentity {
    pub source_kind: String,
    pub format: String,
    pub storage_contract: String,
    pub dim: usize,
    pub count: u64,
    pub payload_blake3: Option<String>,
    pub source_blake3: String,
}

impl VectorSourceIdentity {
    fn from_file(identity: crate::index::vecfile::VectorFileIdentity) -> Self {
        Self {
            source_kind: "authenticated_vector_file".to_string(),
            format: identity.format.manifest_name().to_string(),
            storage_contract: identity.format.storage_contract().to_string(),
            dim: identity.dim as usize,
            count: identity.count,
            payload_blake3: Some(hex32(&identity.payload_blake3)),
            source_blake3: hex32(&identity.source_blake3),
        }
    }

    fn synthetic(seed: u64, dim: usize, count: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SYNTHETIC_IDENTITY_DOMAIN);
        hasher.update(&seed.to_le_bytes());
        hasher.update(&(dim as u64).to_le_bytes());
        hasher.update(&count.to_le_bytes());
        Self {
            source_kind: "deterministic_synthetic_diagnostic".to_string(),
            format: "CALYXSYN1".to_string(),
            storage_contract: "calyx-synthetic-row-generator-v1-seed-shape-bound".to_string(),
            dim,
            count,
            payload_blake3: None,
            source_blake3: hasher.finalize().to_hex().to_string(),
        }
    }
}

pub fn gen_row(seed: u64, idx: u64, dim: usize) -> Vec<f32> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed ^ idx.wrapping_mul(IDX_MIX));
    let mut v: Vec<f32> = (0..dim)
        .map(|j| rng.gen_range(-1.0_f32..1.0) + ((idx as usize + j) % dim) as f32 * 0.001)
        .collect();
    let spike = (idx as usize) % dim;
    v[spike] += 4.0;
    normalize(&mut v);
    v
}

pub(super) fn normalize(v: &mut [f32]) {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v {
            *x /= norm;
        }
    }
}

/// Source of the vectors a partitioned vault is built from. The real production
/// path reads genuine embeddings from disk. Synthetic rows exist only for
/// builder-logic unit tests and must never back a recall or FSV claim.
pub trait VectorSource: Sync {
    fn dim(&self) -> usize;
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn row(&self, idx: u64) -> Result<Vec<f32>>;
    fn identity(&self) -> VectorSourceIdentity;
}

/// Real float32 embeddings memory-mapped from Calyx `.fbin`.
pub struct FbinSource {
    vectors: FbinVectors,
    identity: VectorSourceIdentity,
}

impl FbinSource {
    pub fn open(path: &Path) -> Result<Self> {
        let vectors = FbinVectors::open(path)?;
        let identity = VectorSourceIdentity::from_file(vectors.identity());
        Ok(Self { vectors, identity })
    }
}

impl VectorSource for FbinSource {
    fn dim(&self) -> usize {
        self.vectors.dim()
    }
    fn len(&self) -> u64 {
        self.vectors.count()
    }
    fn row(&self, idx: u64) -> Result<Vec<f32>> {
        Ok(self.vectors.row(idx)?.to_vec())
    }
    fn identity(&self) -> VectorSourceIdentity {
        self.identity.clone()
    }
}

/// Real signed-int8 BigANN vectors, normalized to Calyx's cosine geometry.
pub struct I8BinSource {
    vectors: I8BinVectors,
    normalize: bool,
    identity: VectorSourceIdentity,
}

impl I8BinSource {
    pub fn open(path: &Path) -> Result<Self> {
        let vectors = I8BinVectors::open(path)?;
        let identity = VectorSourceIdentity::from_file(vectors.identity());
        Ok(Self {
            vectors,
            normalize: true,
            identity,
        })
    }

    pub fn open_raw(path: &Path) -> Result<Self> {
        let vectors = I8BinVectors::open(path)?;
        let identity = VectorSourceIdentity::from_file(vectors.identity());
        Ok(Self {
            vectors,
            normalize: false,
            identity,
        })
    }
}

impl VectorSource for I8BinSource {
    fn dim(&self) -> usize {
        self.vectors.dim()
    }
    fn len(&self) -> u64 {
        self.vectors.count()
    }
    fn row(&self, idx: u64) -> Result<Vec<f32>> {
        if self.normalize {
            self.vectors.row_f32_normalized(idx)
        } else {
            self.vectors.row_f32_raw(idx)
        }
    }
    fn identity(&self) -> VectorSourceIdentity {
        self.identity.clone()
    }
}

/// Deterministic synthetic rows. Builder-logic unit tests only.
pub struct SyntheticSource {
    pub seed: u64,
    pub dim: usize,
    pub n_cx: u64,
}

impl VectorSource for SyntheticSource {
    fn dim(&self) -> usize {
        self.dim
    }
    fn len(&self) -> u64 {
        self.n_cx
    }
    fn row(&self, idx: u64) -> Result<Vec<f32>> {
        if idx >= self.n_cx {
            return Err(crate::error::sextant_error(
                crate::error::CALYX_INDEX_CORRUPT,
                format!("synthetic vector row {idx} >= count {}", self.n_cx),
            ));
        }
        Ok(gen_row(self.seed, idx, self.dim))
    }
    fn identity(&self) -> VectorSourceIdentity {
        VectorSourceIdentity::synthetic(self.seed, self.dim, self.n_cx)
    }
}

fn hex32(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
