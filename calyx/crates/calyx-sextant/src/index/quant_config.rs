//! Per-slot quantization policy and physically packed row storage for Sextant.
//!
//! A configured quantizer changes both resident bytes and the scoring kernel.
//! The versioned layout (`SEXTANT_QUANT_LAYOUT_VERSION` = 2) is:
//!
//! - `None`: exact `f32`, four bytes/channel.
//! - `Scalar8`: one signed byte/channel plus frozen scale and row norm.
//! - `Binary`: one sign bit/channel plus the declared dimension.
//! - `TurboQuant{2p5,3p5}`: one canonical TQPR-v2 payload plus its source
//!   norm, validated once at insertion/open. Search uses one prepared
//!   structured-Hadamard LUT/QJL query and never decodes or rehashes rows.

use std::sync::Arc;

use calyx_core::{CalyxError, Result};
use calyx_forge::{
    QuantLevel, Quantizer, RotationSeed, SeedId, TurboQuantCodec, TurboQuantOwnedCandidate,
    TurboQuantPreparedQuery,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::{CALYX_SEXTANT_VECTOR_SHAPE, sextant_error};

/// Version of the packed per-row quantized layout documented in this module.
pub const SEXTANT_QUANT_LAYOUT_VERSION: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantKind {
    None,
    Scalar8,
    Binary,
    TurboQuant2p5,
    TurboQuant3p5,
}

impl QuantKind {
    /// Exact TurboQuant level represented by this codec kind, if any.
    pub const fn turboquant_level(self) -> Option<QuantLevel> {
        match self {
            Self::TurboQuant2p5 => Some(QuantLevel::Bits2p5),
            Self::TurboQuant3p5 => Some(QuantLevel::Bits3p5),
            Self::None | Self::Scalar8 | Self::Binary => None,
        }
    }

    /// Integer storage-budget ceiling used by Anneal's existing index knob.
    /// Exact fractional width remains bound by the codec tag and TQPR header.
    pub const fn quant_bits_ceiling(self) -> u8 {
        match self {
            Self::None => 32,
            Self::Scalar8 => 8,
            Self::Binary => 1,
            Self::TurboQuant2p5 => 3,
            Self::TurboQuant3p5 => 4,
        }
    }
}

#[derive(Clone, Debug)]
pub struct QuantConfig {
    kind: QuantKind,
    scale: f32,
    zero_point: i8,
    turbo_seed: Option<RotationSeed>,
    turbo_geometry_id: SeedId,
    turbo_codec: Option<Arc<TurboQuantCodec>>,
    locked: bool,
}

#[derive(Deserialize, Serialize)]
struct QuantConfigWire {
    kind: QuantKind,
    scale: f32,
    zero_point: i8,
    #[serde(default)]
    turbo_seed: Option<RotationSeed>,
    #[serde(default)]
    turbo_geometry_id: SeedId,
}

impl PartialEq for QuantConfig {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.scale.to_bits() == other.scale.to_bits()
            && self.zero_point == other.zero_point
            && self.turbo_seed == other.turbo_seed
            && self.turbo_geometry_id == other.turbo_geometry_id
            && self.locked == other.locked
    }
}

impl Serialize for QuantConfig {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        QuantConfigWire {
            kind: self.kind,
            scale: self.scale,
            zero_point: self.zero_point,
            turbo_seed: self.turbo_seed.clone(),
            turbo_geometry_id: self.turbo_geometry_id,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for QuantConfig {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = QuantConfigWire::deserialize(deserializer)?;
        let config = match wire.kind {
            QuantKind::None => Self::none(),
            QuantKind::Scalar8 => Self::scalar8(wire.scale),
            QuantKind::Binary => Self::binary(),
            QuantKind::TurboQuant2p5 | QuantKind::TurboQuant3p5 => {
                let seed = wire.turbo_seed.clone().ok_or_else(|| {
                    de::Error::custom("TurboQuant config is missing its frozen rotation seed")
                })?;
                let level = wire.kind.turboquant_level().ok_or_else(|| {
                    de::Error::custom("TurboQuant config has no exact fractional level")
                })?;
                let config = Self::turboquant_structured(seed, level)
                    .map_err(|error| de::Error::custom(error.to_string()))?;
                if wire.turbo_geometry_id != config.turbo_geometry_id {
                    return Err(de::Error::custom(
                        "TurboQuant config geometry identity does not match its frozen seed",
                    ));
                }
                config
            }
        };
        if config.scale.to_bits() != wire.scale.to_bits()
            || config.zero_point != wire.zero_point
            || (!matches!(
                wire.kind,
                QuantKind::TurboQuant2p5 | QuantKind::TurboQuant3p5
            ) && (wire.turbo_seed.is_some() || wire.turbo_geometry_id != [0_u8; 32]))
        {
            return Err(de::Error::custom(
                "quantization config contains non-canonical codec metadata",
            ));
        }
        Ok(config)
    }
}

/// Physically packed per-row storage (layout v2, see module docs).
#[derive(Clone, Debug, PartialEq)]
pub enum PackedVector {
    F32 {
        values: Vec<f32>,
    },
    Scalar8 {
        codes: Vec<u8>,
        scale: f32,
        norm: f32,
    },
    Binary {
        bits: Vec<u8>,
        dim: u32,
    },
    TurboQuant {
        candidate: TurboQuantOwnedCandidate,
    },
}

/// Query prepared once per search for direct packed-row scoring.
#[derive(Clone, Debug)]
pub enum PackedQuery {
    F32 {
        values: Vec<f32>,
        norm: f32,
    },
    Binary {
        bits: Vec<u8>,
        dim: u32,
    },
    TurboQuant {
        codec: Arc<TurboQuantCodec>,
        prepared: TurboQuantPreparedQuery,
        norm: f32,
    },
}

impl QuantConfig {
    pub const fn none() -> Self {
        Self {
            kind: QuantKind::None,
            scale: 1.0,
            zero_point: 0,
            turbo_seed: None,
            turbo_geometry_id: [0_u8; 32],
            turbo_codec: None,
            locked: false,
        }
    }

    pub const fn scalar8(scale: f32) -> Self {
        Self {
            kind: QuantKind::Scalar8,
            scale,
            zero_point: 0,
            turbo_seed: None,
            turbo_geometry_id: [0_u8; 32],
            turbo_codec: None,
            locked: false,
        }
    }

    pub const fn binary() -> Self {
        Self {
            kind: QuantKind::Binary,
            scale: 1.0,
            zero_point: 0,
            turbo_seed: None,
            turbo_geometry_id: [0_u8; 32],
            turbo_codec: None,
            locked: false,
        }
    }

    /// Builds a reusable bit-exact structured TurboQuant codec for one index.
    pub fn turboquant_structured(seed: RotationSeed, level: QuantLevel) -> Result<Self> {
        let kind = match level {
            QuantLevel::Bits2p5 => QuantKind::TurboQuant2p5,
            QuantLevel::Bits3p5 => QuantKind::TurboQuant3p5,
            _ => {
                return Err(sextant_error(
                    CALYX_SEXTANT_VECTOR_SHAPE,
                    format!("Sextant TurboQuant supports only Bits2p5/Bits3p5, not {level}"),
                ));
            }
        };
        let codec = TurboQuantCodec::shared_structured(seed.clone(), level).map_err(forge_error)?;
        Ok(Self {
            kind,
            scale: 1.0,
            zero_point: 0,
            turbo_seed: Some(seed),
            turbo_geometry_id: codec.geometry_id(),
            turbo_codec: Some(codec),
            locked: false,
        })
    }

    pub const fn kind(&self) -> QuantKind {
        self.kind
    }

    pub const fn scale(&self) -> f32 {
        self.scale
    }

    pub const fn zero_point(&self) -> i8 {
        self.zero_point
    }

    /// Frozen geometry identity; zero for codecs without seeded geometry.
    pub const fn geometry_id(&self) -> SeedId {
        self.turbo_geometry_id
    }

    /// Frozen structured TurboQuant seed, if this is a TurboQuant config.
    pub fn turbo_seed(&self) -> Option<&RotationSeed> {
        self.turbo_seed.as_ref()
    }

    pub(crate) fn turbo_codec(&self) -> Option<&Arc<TurboQuantCodec>> {
        self.turbo_codec.as_ref()
    }

    /// Shared codec geometry heap bytes owned by this index configuration.
    pub fn geometry_physical_bytes(&self) -> usize {
        self.turbo_codec
            .as_ref()
            .map_or(0, |codec| codec.geometry_physical_bytes())
    }

    /// Validates the complete frozen codec identity before accepting a row.
    pub fn validate(&self) -> Result<()> {
        let canonical = match self.kind {
            QuantKind::None | QuantKind::Binary => {
                self.scale.to_bits() == 1.0_f32.to_bits()
                    && self.zero_point == 0
                    && self.turbo_seed.is_none()
                    && self.turbo_geometry_id == [0_u8; 32]
                    && self.turbo_codec.is_none()
            }
            QuantKind::Scalar8 => {
                self.scale.is_finite()
                    && self.scale > 0.0
                    && self.zero_point == 0
                    && self.turbo_seed.is_none()
                    && self.turbo_geometry_id == [0_u8; 32]
                    && self.turbo_codec.is_none()
            }
            QuantKind::TurboQuant2p5 | QuantKind::TurboQuant3p5 => {
                let Some(seed) = self.turbo_seed.as_ref() else {
                    return Err(sextant_error(
                        CALYX_SEXTANT_VECTOR_SHAPE,
                        "TurboQuant config is missing its frozen structured seed",
                    ));
                };
                let Some(codec) = self.turbo_codec.as_ref() else {
                    return Err(sextant_error(
                        CALYX_SEXTANT_VECTOR_SHAPE,
                        "TurboQuant config is missing its live shared codec geometry",
                    ));
                };
                seed.dim == codec.dim()
                    && Some(codec.level()) == self.kind.turboquant_level()
                    && codec.geometry_id() == self.turbo_geometry_id
                    && self.scale.to_bits() == 1.0_f32.to_bits()
                    && self.zero_point == 0
            }
        };
        if !canonical {
            return Err(sextant_error(
                CALYX_SEXTANT_VECTOR_SHAPE,
                format!(
                    "non-canonical {:?} quantization config: scale={} zero_point={} geometry={:02x?}",
                    self.kind, self.scale, self.zero_point, self.turbo_geometry_id
                ),
            ));
        }
        Ok(())
    }

    pub fn lock_after_first_insert(&mut self) {
        self.locked = true;
    }

    pub const fn is_locked(&self) -> bool {
        self.locked
    }

    /// Packs one finite raw row into this index's physical representation.
    pub fn pack(&self, values: &[f32]) -> Result<PackedVector> {
        let packed = match self.kind {
            QuantKind::None => PackedVector::F32 {
                values: values.to_vec(),
            },
            QuantKind::Scalar8 => {
                let mut codes = Vec::with_capacity(values.len());
                let mut norm_sq = 0.0_f64;
                for value in values {
                    let code = (value / self.scale).round().clamp(-127.0, 127.0) as i8;
                    codes.push(code as u8);
                    let dequantized = f64::from(code) * f64::from(self.scale);
                    norm_sq += dequantized * dequantized;
                }
                PackedVector::Scalar8 {
                    codes,
                    scale: self.scale,
                    norm: norm_sq.sqrt() as f32,
                }
            }
            QuantKind::Binary => PackedVector::Binary {
                bits: pack_sign_bits(values),
                dim: values.len() as u32,
            },
            QuantKind::TurboQuant2p5 | QuantKind::TurboQuant3p5 => {
                let codec = self.turbo_codec.as_ref().ok_or_else(|| {
                    sextant_error(
                        CALYX_SEXTANT_VECTOR_SHAPE,
                        "TurboQuant row packing requires the owning index codec",
                    )
                })?;
                let quantized = codec.encode(values).map_err(forge_error)?;
                let candidate = codec
                    .validate_owned_candidate(quantized)
                    .map_err(forge_error)?;
                PackedVector::TurboQuant { candidate }
            }
        };
        Ok(packed)
    }

    /// Prepares one query for repeated direct scoring against packed rows.
    pub fn prepare_query(&self, values: &[f32]) -> Result<PackedQuery> {
        let query = match self.kind {
            QuantKind::None | QuantKind::Scalar8 => PackedQuery::F32 {
                values: values.to_vec(),
                norm: l2_norm(values),
            },
            QuantKind::Binary => PackedQuery::Binary {
                bits: pack_sign_bits(values),
                dim: values.len() as u32,
            },
            QuantKind::TurboQuant2p5 | QuantKind::TurboQuant3p5 => {
                let codec = self.turbo_codec.as_ref().ok_or_else(|| {
                    sextant_error(
                        CALYX_SEXTANT_VECTOR_SHAPE,
                        "TurboQuant query preparation requires the owning index codec",
                    )
                })?;
                PackedQuery::TurboQuant {
                    codec: Arc::clone(codec),
                    prepared: codec.prepare_query(values).map_err(forge_error)?,
                    norm: l2_norm(values),
                }
            }
        };
        Ok(query)
    }

    /// Reconstructs one row for explicit readback/reranking, never search.
    pub fn approx_f32(&self, row: &PackedVector) -> Result<Vec<f32>> {
        match (self.kind, row) {
            (QuantKind::None, PackedVector::F32 { values }) => Ok(values.clone()),
            (QuantKind::Scalar8, PackedVector::Scalar8 { codes, scale, .. }) => Ok(codes
                .iter()
                .map(|code| f32::from(*code as i8) * *scale)
                .collect()),
            (QuantKind::Binary, PackedVector::Binary { bits, dim }) => Ok((0..*dim as usize)
                .map(|index| {
                    if bits[index / 8] & (1 << (index % 8)) != 0 {
                        1.0
                    } else {
                        -1.0
                    }
                })
                .collect()),
            (
                QuantKind::TurboQuant2p5 | QuantKind::TurboQuant3p5,
                PackedVector::TurboQuant { candidate },
            ) => self
                .turbo_codec
                .as_ref()
                .ok_or_else(|| {
                    sextant_error(
                        CALYX_SEXTANT_VECTOR_SHAPE,
                        "TurboQuant reconstruction requires the owning index codec",
                    )
                })?
                .decode(candidate.quantized())
                .map_err(forge_error),
            _ => Err(sextant_error(
                CALYX_SEXTANT_VECTOR_SHAPE,
                "packed row kind does not match the owning QuantConfig",
            )),
        }
    }

    pub fn cpu_gpu_delta(&self, _values: &[f32]) -> Result<f32> {
        Err(sextant_error(
            crate::error::CALYX_SEXTANT_GPU_PARITY_UNAVAILABLE,
            "QuantConfig has no wired Forge GPU quantization path; CPU/GPU delta is unavailable",
        ))
    }
}

impl PackedVector {
    /// Physical payload bytes held for this row, excluding Rust bookkeeping.
    pub fn physical_bytes(&self) -> usize {
        match self {
            Self::F32 { values } => values.len() * 4,
            Self::Scalar8 { codes, .. } => codes.len() + 8,
            Self::Binary { bits, .. } => bits.len() + 4,
            Self::TurboQuant { candidate } => candidate.storage().payload_bytes + 4,
        }
    }

    /// Number of source channels represented by this row.
    pub fn dim(&self) -> usize {
        match self {
            Self::F32 { values } => values.len(),
            Self::Scalar8 { codes, .. } => codes.len(),
            Self::Binary { dim, .. } => *dim as usize,
            Self::TurboQuant { candidate } => candidate.quantized().dim,
        }
    }

    /// Stable packed-domain identity for exact-duplicate fingerprinting.
    pub fn identity_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::F32 { values } => {
                bytes.push(0);
                for value in values {
                    bytes.extend_from_slice(&value.to_bits().to_le_bytes());
                }
            }
            Self::Scalar8 { codes, scale, .. } => {
                bytes.push(1);
                bytes.extend_from_slice(&scale.to_bits().to_le_bytes());
                bytes.extend_from_slice(codes);
            }
            Self::Binary { bits, dim } => {
                bytes.push(2);
                bytes.extend_from_slice(&dim.to_le_bytes());
                bytes.extend_from_slice(bits);
            }
            Self::TurboQuant { candidate } => {
                let quantized = candidate.quantized();
                bytes.push(match quantized.level {
                    QuantLevel::Bits2p5 => 3,
                    QuantLevel::Bits3p5 => 4,
                    _ => unreachable!("owned Sextant TurboQuant row has unsupported level"),
                });
                bytes.extend_from_slice(&quantized.scale.to_bits().to_le_bytes());
                bytes.extend_from_slice(&quantized.bytes);
            }
        }
        bytes
    }
}

/// Scores one prepared query against one packed row without candidate decode.
pub fn score_packed(query: &PackedQuery, row: &PackedVector) -> Result<f32> {
    match (query, row) {
        (PackedQuery::F32 { values, .. }, PackedVector::F32 { values: row_values }) => {
            Ok(crate::util::cosine(values, row_values))
        }
        (
            PackedQuery::F32 { values, norm },
            PackedVector::Scalar8 {
                codes,
                scale,
                norm: row_norm,
            },
        ) => {
            if values.len() != codes.len() {
                return Err(dim_mismatch(values.len(), codes.len()));
            }
            if *norm == 0.0 || *row_norm == 0.0 {
                return Ok(0.0);
            }
            let dot = scalar8_dot(values, codes);
            Ok((dot * f64::from(*scale) / (f64::from(*norm) * f64::from(*row_norm))) as f32)
        }
        (
            PackedQuery::Binary { bits, dim },
            PackedVector::Binary {
                bits: row_bits,
                dim: row_dim,
            },
        ) => {
            if dim != row_dim || bits.len() != row_bits.len() {
                return Err(dim_mismatch(*dim as usize, *row_dim as usize));
            }
            let mismatches: u32 = bits
                .iter()
                .zip(row_bits)
                .map(|(left, right)| (left ^ right).count_ones())
                .sum();
            Ok(1.0 - 2.0 * mismatches as f32 / *dim as f32)
        }
        (
            PackedQuery::TurboQuant {
                codec,
                prepared,
                norm,
            },
            PackedVector::TurboQuant { candidate },
        ) => {
            let candidate_norm = candidate.quantized().scale;
            if *norm == 0.0 || candidate_norm == 0.0 {
                return Ok(0.0);
            }
            let dot = codec
                .dot_estimate_owned(prepared, candidate)
                .map_err(forge_error)?;
            Ok((f64::from(dot) / (f64::from(*norm) * f64::from(candidate_norm))) as f32)
        }
        _ => Err(sextant_error(
            CALYX_SEXTANT_VECTOR_SHAPE,
            "prepared query kind does not match the packed row kind; prepare through the owning QuantConfig",
        )),
    }
}

/// Asymmetric query-f32 by candidate-i8 dot product. Candidate bytes remain
/// packed and are sign-extended directly into SIMD lanes; no candidate-wide
/// decode or temporary allocation occurs.
fn scalar8_dot(values: &[f32], codes: &[u8]) -> f64 {
    debug_assert_eq!(values.len(), codes.len());
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx2") {
        // SAFETY: feature detection proves AVX2 support, and the helper only
        // loads within the equal-length slices established by score_packed.
        return unsafe { scalar8_dot_avx2(values, codes) };
    }
    values
        .iter()
        .zip(codes)
        .map(|(value, code)| f64::from(*value) * f64::from(*code as i8))
        .sum()
}

pub(crate) fn scalar8_dot_signed(values: &[f32], codes: &[i8]) -> f64 {
    debug_assert_eq!(values.len(), codes.len());
    // SAFETY: i8/u8 have identical size and alignment; this changes only the
    // slice's element type so the shared SIMD kernel can sign-extend bytes.
    let bytes = unsafe { std::slice::from_raw_parts(codes.as_ptr().cast::<u8>(), codes.len()) };
    scalar8_dot(values, bytes)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scalar8_dot_avx2(values: &[f32], codes: &[u8]) -> f64 {
    use std::arch::x86_64::*;

    unsafe {
        let mut low_acc = _mm256_setzero_pd();
        let mut high_acc = _mm256_setzero_pd();
        let vectorized = values.len() / 8 * 8;
        let mut index = 0_usize;
        while index < vectorized {
            let packed = _mm_loadl_epi64(codes.as_ptr().add(index).cast::<__m128i>());
            let widened = _mm256_cvtepi8_epi32(packed);
            let code_low = _mm256_castsi256_si128(widened);
            let code_high = _mm256_extracti128_si256::<1>(widened);
            let query_low = _mm_loadu_ps(values.as_ptr().add(index));
            let query_high = _mm_loadu_ps(values.as_ptr().add(index + 4));
            low_acc = _mm256_add_pd(
                low_acc,
                _mm256_mul_pd(_mm256_cvtps_pd(query_low), _mm256_cvtepi32_pd(code_low)),
            );
            high_acc = _mm256_add_pd(
                high_acc,
                _mm256_mul_pd(_mm256_cvtps_pd(query_high), _mm256_cvtepi32_pd(code_high)),
            );
            index += 8;
        }
        let mut low = [0.0_f64; 4];
        let mut high = [0.0_f64; 4];
        _mm256_storeu_pd(low.as_mut_ptr(), low_acc);
        _mm256_storeu_pd(high.as_mut_ptr(), high_acc);
        let mut dot = low.into_iter().sum::<f64>() + high.into_iter().sum::<f64>();
        for tail in index..values.len() {
            dot += f64::from(values[tail]) * f64::from(codes[tail] as i8);
        }
        dot
    }
}

fn dim_mismatch(query: usize, row: usize) -> CalyxError {
    sextant_error(
        CALYX_SEXTANT_VECTOR_SHAPE,
        format!("packed scoring dimension mismatch: query={query} row={row}"),
    )
}

fn pack_sign_bits(values: &[f32]) -> Vec<u8> {
    let mut bits = vec![0_u8; values.len().div_ceil(8)];
    for (index, value) in values.iter().enumerate() {
        if *value >= 0.0 {
            bits[index / 8] |= 1 << (index % 8);
        }
    }
    bits
}

fn l2_norm(values: &[f32]) -> f32 {
    values
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>()
        .sqrt() as f32
}

fn forge_error(error: calyx_forge::ForgeError) -> CalyxError {
    CalyxError {
        code: error.code(),
        message: error.to_string(),
        remediation: "rebuild the exact packed index from finite authoritative vectors using the recorded current-version TurboQuant seed and geometry",
    }
}
