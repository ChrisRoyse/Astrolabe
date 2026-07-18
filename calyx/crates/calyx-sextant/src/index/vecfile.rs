//! Flat on-disk vector files of REAL embeddings — the source of truth for
//! partitioned-vault build and search. No vectors are ever synthesised: the builder
//! and bench read genuine embeddings produced by the real embedder from a real
//! corpus.
//!
//! # `CLXVEC02` (`.fbin`) — exact bit-preserving F32 source of truth
//!
//! Layout (little-endian):
//! `magic "CLXVEC02" (8 B) | u32 dim | u64 count | u64 payload_len | payload
//! blake3 digest (32 B) | f32[count*dim] row-major`.
//!
//! Every finite payload bit is preserved exactly as written; the writer refuses
//! non-finite coefficients and the reader independently re-verifies the payload
//! digest and finiteness at open, so a `.fbin` accepted for build/search is
//! authenticated byte-for-byte against its declared header identity.
//!
//! # `CLXI8B02` (`.i8bin`) — per-row-scaled symmetric int8
//!
//! Layout (little-endian):
//! `magic "CLXI8B02" (8 B) | u32 dim | u64 count | u64 payload_len | payload
//! blake3 digest (32 B)` then per row: `f32 scale | i8[dim] codes`.
//!
//! `scale` is the dequantization multiplier (`value ≈ code * scale`), derived by
//! the writer as `max_abs / 127`, so magnitude information is preserved per row
//! instead of being discarded. Canonical rows never contain the encoder-impossible
//! `-128` code and always contain at least one `±127` extremum; the reader refuses
//! non-canonical rows fail-closed.
//!
//! Legacy `CLXVEC01` and headerless BigANN `.i8bin` files are refused fail-closed
//! with structured remediation — they are ambiguous (lossy writer / no integrity
//! binding) and are never silently reinterpreted.

mod format;
mod i32;
mod writer;

use std::path::Path;

use calyx_core::Result;
use memmap2::Mmap;

use crate::error::{
    CALYX_INDEX_CORRUPT, CALYX_INDEX_NONCANONICAL_I8, CALYX_INDEX_NONFINITE, sextant_error,
};

use format::open_verified;
pub use format::{VectorFileFormat, VectorFileIdentity};
pub use i32::I32BinMatrix;
pub use writer::{FbinWriter, I8BinWriter};

/// Current authenticated `.fbin` magic (format v2).
pub const VEC_MAGIC: [u8; 8] = *b"CLXVEC02";
/// Legacy lossy `.fbin` magic — refused fail-closed.
pub const VEC_MAGIC_LEGACY_V1: [u8; 8] = *b"CLXVEC01";
/// Current authenticated `.i8bin` magic (format v2).
pub const I8BIN_MAGIC: [u8; 8] = *b"CLXI8B02";

/// Shared v2 header: magic(8) + dim(4) + count(8) + payload_len(8) + digest(32).
pub const VEC_HEADER_LEN: usize = 60;
/// Bound shared with the real partitioned DiskANN consumer. Rejecting larger
/// rows here prevents hostile headers from forcing unbounded scratch allocation
/// before the index's configured shape gate.
pub const VECTOR_FILE_MAX_DIM: usize = super::diskann::graph::DISKANN_MAX_DIM;

#[derive(Debug)]
pub enum DenseVectorFile {
    Fbin(FbinVectors),
    I8Bin(I8BinVectors),
}

impl DenseVectorFile {
    pub fn open(path: &Path) -> Result<Self> {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("fbin") => Ok(Self::Fbin(FbinVectors::open(path)?)),
            Some("i8bin") => Ok(Self::I8Bin(I8BinVectors::open(path)?)),
            _ => Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("unsupported vector file extension for {}", path.display()),
            )),
        }
    }

    pub fn dim(&self) -> usize {
        match self {
            Self::Fbin(file) => file.dim(),
            Self::I8Bin(file) => file.dim(),
        }
    }

    pub fn count(&self) -> u64 {
        match self {
            Self::Fbin(file) => file.count(),
            Self::I8Bin(file) => file.count(),
        }
    }

    /// Verified blake3 digest of the payload bytes (source identity).
    pub fn payload_blake3(&self) -> [u8; 32] {
        match self {
            Self::Fbin(file) => file.payload_blake3(),
            Self::I8Bin(file) => file.payload_blake3(),
        }
    }

    /// Canonical source identity binding format, shape, row count, payload
    /// length, and authenticated payload bytes.
    pub fn source_blake3(&self) -> [u8; 32] {
        match self {
            Self::Fbin(file) => file.source_blake3(),
            Self::I8Bin(file) => file.source_blake3(),
        }
    }

    pub fn identity(&self) -> VectorFileIdentity {
        match self {
            Self::Fbin(file) => file.identity(),
            Self::I8Bin(file) => file.identity(),
        }
    }

    pub fn row_f32(&self, idx: u64) -> Result<Vec<f32>> {
        match self {
            Self::Fbin(file) => Ok(file.row(idx)?.to_vec()),
            Self::I8Bin(file) => file.row_f32_normalized(idx),
        }
    }

    pub fn row_f32_raw(&self, idx: u64) -> Result<Vec<f32>> {
        match self {
            Self::Fbin(file) => Ok(file.row(idx)?.to_vec()),
            Self::I8Bin(file) => file.row_f32_raw(idx),
        }
    }
}

/// mmap-backed reader over an authenticated `CLXVEC02` `.fbin` of real
/// embeddings. Reads are zero-copy slices into the mapping, so build/search
/// never materialise the whole file in heap. `open` verifies the payload digest
/// and refuses non-finite payloads, so every served row is bit-exact source
/// truth.
#[derive(Debug)]
pub struct FbinVectors {
    mmap: Mmap,
    dim: usize,
    count: u64,
    identity: VectorFileIdentity,
}

impl FbinVectors {
    pub fn open(path: &Path) -> Result<Self> {
        let (mmap, header) = open_verified(path, VectorFileFormat::ExactF32)?;
        // The f32 region begins at byte 60; mmap base is page-aligned and 60 % 4 == 0,
        // so the region is 4-byte aligned for zero-copy f32 reads.
        if !(mmap.as_ptr() as usize + VEC_HEADER_LEN).is_multiple_of(std::mem::align_of::<f32>()) {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                "vecfile f32 region misaligned for zero-copy read",
            ));
        }
        // Authenticated exact source truth must be finite: refuse NaN/Inf payloads.
        let payload = &mmap[VEC_HEADER_LEN..VEC_HEADER_LEN + header.payload_len];
        for (value_idx, chunk) in payload.chunks_exact(4).enumerate() {
            let value = f32::from_le_bytes(chunk.try_into().expect("4B"));
            if !value.is_finite() {
                return Err(sextant_error(
                    CALYX_INDEX_NONFINITE,
                    format!(
                        "vecfile {} contains non-finite value {value} at flat index {value_idx} \
                         (row {}, col {})",
                        path.display(),
                        value_idx / header.dim,
                        value_idx % header.dim
                    ),
                ));
            }
        }
        Ok(Self {
            mmap,
            dim: header.dim,
            count: header.count,
            identity: header.identity,
        })
    }

    pub fn dim(&self) -> usize {
        self.dim
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Verified blake3 digest of the payload bytes (source identity for
    /// downstream build/measurement manifests).
    pub fn payload_blake3(&self) -> [u8; 32] {
        self.identity.payload_blake3
    }

    pub fn source_blake3(&self) -> [u8; 32] {
        self.identity.source_blake3
    }

    pub fn identity(&self) -> VectorFileIdentity {
        self.identity
    }

    /// Bounds-checked, zero-copy row read. Malformed callers receive the same
    /// structured index error contract as malformed files; no public read API
    /// panics on an out-of-range row.
    pub fn row(&self, idx: u64) -> Result<&[f32]> {
        if idx >= self.count {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("vecfile row {idx} >= count {}", self.count),
            ));
        }
        // idx < count and count*dim*4 fits usize (proven at open), so this
        // arithmetic cannot overflow.
        let start = VEC_HEADER_LEN + (idx as usize) * self.dim * 4;
        let bytes = &self.mmap[start..start + self.dim * 4];
        // SAFETY: alignment checked in `open`; length is an exact multiple of 4; f32
        // accepts any bit pattern; lifetime tied to the map.
        Ok(unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<f32>(), self.dim) })
    }

    pub fn try_row(&self, idx: u64) -> Result<&[f32]> {
        self.row(idx)
    }
}

/// mmap-backed reader for authenticated `CLXI8B02` per-row-scaled signed-int8
/// vectors. `open` verifies the payload digest and per-row canonical form
/// (finite positive scale, no `-128` code, `±127` extremum present).
#[derive(Debug)]
pub struct I8BinVectors {
    mmap: Mmap,
    dim: usize,
    count: u64,
    identity: VectorFileIdentity,
}

impl I8BinVectors {
    pub fn open(path: &Path) -> Result<Self> {
        let (mmap, header) = open_verified(path, VectorFileFormat::SymmetricInt8)?;
        let stride = header.dim + 4;
        for row in 0..header.count {
            let start = VEC_HEADER_LEN + (row as usize) * stride;
            let scale = f32::from_le_bytes(mmap[start..start + 4].try_into().expect("4B"));
            if !scale.is_finite() || scale <= 0.0 {
                return Err(sextant_error(
                    CALYX_INDEX_NONCANONICAL_I8,
                    format!(
                        "i8bin {} row {row} scale {scale} is not finite and positive",
                        path.display()
                    ),
                ));
            }
            let codes = &mmap[start + 4..start + stride];
            let mut max_abs_code = 0_u8;
            for (col, code) in codes.iter().enumerate() {
                let code = *code as i8;
                if code == i8::MIN {
                    return Err(sextant_error(
                        CALYX_INDEX_NONCANONICAL_I8,
                        format!(
                            "i8bin {} row {row} col {col} carries encoder-impossible code -128",
                            path.display()
                        ),
                    ));
                }
                max_abs_code = max_abs_code.max(code.unsigned_abs());
            }
            if max_abs_code != 127 {
                return Err(sextant_error(
                    CALYX_INDEX_NONCANONICAL_I8,
                    format!(
                        "i8bin {} row {row} max |code| {max_abs_code} != 127; canonical rows \
                         are scaled to a ±127 extremum",
                        path.display()
                    ),
                ));
            }
        }
        Ok(Self {
            mmap,
            dim: header.dim,
            count: header.count,
            identity: header.identity,
        })
    }

    pub fn dim(&self) -> usize {
        self.dim
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Verified blake3 digest of the payload bytes (source identity for
    /// downstream build/measurement manifests).
    pub fn payload_blake3(&self) -> [u8; 32] {
        self.identity.payload_blake3
    }

    pub fn source_blake3(&self) -> [u8; 32] {
        self.identity.source_blake3
    }

    pub fn identity(&self) -> VectorFileIdentity {
        self.identity
    }

    fn row_start(&self, idx: u64) -> Result<usize> {
        if idx >= self.count {
            return Err(sextant_error(
                CALYX_INDEX_CORRUPT,
                format!("i8bin row {idx} >= count {}", self.count),
            ));
        }
        // idx < count and count*(dim+4) fits usize (proven at open).
        Ok(VEC_HEADER_LEN + (idx as usize) * (self.dim + 4))
    }

    /// Per-row dequantization multiplier (`value ≈ code * scale`).
    pub fn row_scale(&self, idx: u64) -> Result<f32> {
        let start = self.row_start(idx)?;
        Ok(f32::from_le_bytes(
            self.mmap[start..start + 4].try_into().expect("4B"),
        ))
    }

    pub fn row_i8(&self, idx: u64) -> Result<&[i8]> {
        let start = self.row_start(idx)? + 4;
        let bytes = &self.mmap[start..start + self.dim];
        // SAFETY: i8 has alignment 1 and accepts every byte pattern.
        Ok(unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<i8>(), self.dim) })
    }

    pub fn row_f32_normalized(&self, idx: u64) -> Result<Vec<f32>> {
        let mut out = self
            .row_i8(idx)?
            .iter()
            .map(|value| f32::from(*value))
            .collect::<Vec<_>>();
        let norm = out.iter().map(|value| value * value).sum::<f32>().sqrt();
        if norm > 0.0 {
            for value in &mut out {
                *value /= norm;
            }
        }
        Ok(out)
    }

    /// Dequantized row with the per-row scale applied, reconstructing the source
    /// magnitudes within the quantization bound instead of discarding them.
    pub fn row_f32_raw(&self, idx: u64) -> Result<Vec<f32>> {
        let scale = self.row_scale(idx)?;
        Ok(self
            .row_i8(idx)?
            .iter()
            .map(|value| f32::from(*value) * scale)
            .collect())
    }
}
