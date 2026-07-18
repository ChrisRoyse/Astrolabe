pub mod binary;
mod codebook;
mod hadamard;
pub mod int8;
pub mod mxfp4_codec;
pub mod qjl;
pub mod rotation;
pub mod turboquant;

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Result;

pub use binary::{BinaryCodec, binary_prefilter, hamming_dot_estimate};
pub use int8::ScalarInt8Codec;
pub use mxfp4_codec::{
    AssayQuantSafety, MXFP_BODY_ALIGNMENT_BYTES, MXFP_FORMAT_HEADER_BYTES, MXFP_FORMAT_VERSION,
    MxFp4Codec, MxFp8Codec, MxFpStorage, mxfp_payload_len,
};
pub use qjl::QjlResidual;
pub use rotation::{
    CURRENT_SEED_VERSION, RotationSeed, apply_inverse_rotation, apply_rotation,
    apply_rotation_batch, new_seed, seed_id_hex,
};
pub use turboquant::{
    TURBOQUANT_FORMAT_HEADER_BYTES, TURBOQUANT_FORMAT_VERSION, TURBOQUANT_MAX_DIM, TurboQuantCodec,
    TurboQuantGeometryKind, TurboQuantOwnedCandidate, TurboQuantPreparedQuery, TurboQuantStorage,
    TurboQuantV1MigrationVerifier, TurboQuantValidatedCandidate, turboquant_payload_len,
};

pub type SeedId = [u8; 32];

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum QuantLevel {
    F32,
    Bits8,
    Bits8Fp,
    Bits4Fp,
    Bits3p5,
    Bits2p5,
    Bits1,
}

impl QuantLevel {
    pub fn bits_per_channel(self) -> f32 {
        match self {
            Self::F32 => 32.0,
            Self::Bits8 => 8.0,
            Self::Bits8Fp => 8.0,
            Self::Bits4Fp => 4.0,
            Self::Bits3p5 => 3.5,
            Self::Bits2p5 => 2.5,
            Self::Bits1 => 1.0,
        }
    }

    pub fn is_lossy(self) -> bool {
        !matches!(self, Self::F32)
    }
}

impl fmt::Display for QuantLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::F32 => "F32",
            Self::Bits8 => "Bits8",
            Self::Bits8Fp => "Bits8Fp",
            Self::Bits4Fp => "Bits4Fp",
            Self::Bits3p5 => "Bits3p5",
            Self::Bits2p5 => "Bits2p5",
            Self::Bits1 => "Bits1",
        };
        f.write_str(name)
    }
}

pub trait Quantizer: Send + Sync {
    fn encode(&self, vec: &[f32]) -> Result<QuantizedVec>;
    fn decode(&self, qv: &QuantizedVec) -> Result<Vec<f32>>;
    /// Estimates `query dot candidate` without expanding the packed candidate.
    fn dot_estimate(&self, query: &[f32], candidate: &QuantizedVec) -> Result<f32>;
    fn level(&self) -> QuantLevel;
    fn dim(&self) -> usize;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct QuantizedVec {
    pub level: QuantLevel,
    pub dim: usize,
    pub bytes: Vec<u8>,
    pub scale: f32,
    pub seed_id: SeedId,
}
