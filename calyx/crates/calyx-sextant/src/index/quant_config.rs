//! Per-slot quantization policy and physically packed row storage for Sextant
//! indexes.
//!
//! A configured quantizer changes the bytes an index actually holds and the
//! kernel that scores candidates — inert configuration is impossible. The
//! versioned in-memory layout (`SEXTANT_QUANT_LAYOUT_VERSION` = 1) is:
//!
//! - `None`   — exact `f32` values, 4 bytes/channel.
//! - `Scalar8`— one signed 8-bit code per channel (`(v/scale).round()` clamped
//!   to `[-127, 127]`), 1 byte/channel, plus two `f32` metadata fields (the
//!   frozen scale and the dequantized L2 norm). No `f32` approximation is
//!   retained; scoring reads the codes directly.
//! - `Binary` — one physical bit per sign (bit set iff `v >= 0.0`, LSB-first
//!   within each byte), `ceil(dim/8)` bytes. Scoring is XOR + popcount over
//!   the packed words; no `f32` approximation is retained.
//!
//! The former `QuantizedVector { bytes, approx }` shape — one byte per binary
//! sign plus a retained full-`f32` approximation — was removed under #553.

use calyx_core::Result;
use serde::{Deserialize, Serialize};

use crate::error::{CALYX_SEXTANT_VECTOR_SHAPE, sextant_error};

/// Version of the packed per-row quantized layout documented in this module.
pub const SEXTANT_QUANT_LAYOUT_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantKind {
    None,
    Scalar8,
    Binary,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QuantConfig {
    kind: QuantKind,
    scale: f32,
    zero_point: i8,
    #[serde(skip, default)]
    locked: bool,
}

/// Physically packed per-row storage (layout v1, see module docs).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum PackedVector {
    /// Exact unquantized values.
    F32 { values: Vec<f32> },
    /// Signed 8-bit codes with frozen scale and precomputed dequantized norm.
    Scalar8 {
        codes: Vec<u8>,
        scale: f32,
        norm: f32,
    },
    /// One bit per sign, LSB-first; `dim` disambiguates trailing padding.
    Binary { bits: Vec<u8>, dim: u32 },
}

/// Query prepared once per search for direct packed-row scoring.
#[derive(Clone, Debug)]
pub enum PackedQuery {
    /// Raw query values plus precomputed L2 norm (used for `None`/`Scalar8`).
    F32 { values: Vec<f32>, norm: f32 },
    /// Packed query sign bits (used for `Binary`).
    Binary { bits: Vec<u8>, dim: u32 },
}

impl QuantConfig {
    pub const fn none() -> Self {
        Self {
            kind: QuantKind::None,
            scale: 1.0,
            zero_point: 0,
            locked: false,
        }
    }

    pub const fn scalar8(scale: f32) -> Self {
        Self {
            kind: QuantKind::Scalar8,
            scale,
            zero_point: 0,
            locked: false,
        }
    }

    pub const fn binary() -> Self {
        Self {
            kind: QuantKind::Binary,
            scale: 1.0,
            zero_point: 0,
            locked: false,
        }
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

    /// Validates the frozen codec identity before any row is accepted.
    pub fn validate(&self) -> Result<()> {
        let canonical = match self.kind {
            QuantKind::None | QuantKind::Binary => {
                self.scale.to_bits() == 1.0_f32.to_bits() && self.zero_point == 0
            }
            QuantKind::Scalar8 => {
                self.scale.is_finite() && self.scale > 0.0 && self.zero_point == 0
            }
        };
        if !canonical {
            return Err(sextant_error(
                CALYX_SEXTANT_VECTOR_SHAPE,
                format!(
                    "non-canonical {:?} quantization config: scale={} zero_point={}",
                    self.kind, self.scale, self.zero_point
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

    /// Packs raw values into the physical row representation for this policy.
    pub fn pack(&self, values: &[f32]) -> PackedVector {
        match self.kind {
            QuantKind::None => PackedVector::F32 {
                values: values.to_vec(),
            },
            QuantKind::Scalar8 => {
                let scale = self.scale.max(1e-6);
                let mut codes = Vec::with_capacity(values.len());
                let mut norm_sq = 0.0_f64;
                for value in values {
                    let code = (value / scale).round().clamp(-127.0, 127.0) as i8;
                    codes.push(code as u8);
                    let dequantized = f64::from(code) * f64::from(scale);
                    norm_sq += dequantized * dequantized;
                }
                PackedVector::Scalar8 {
                    codes,
                    scale,
                    norm: norm_sq.sqrt() as f32,
                }
            }
            QuantKind::Binary => PackedVector::Binary {
                bits: pack_sign_bits(values),
                dim: values.len() as u32,
            },
        }
    }

    /// Prepares one query for repeated direct scoring against packed rows.
    pub fn prepare_query(&self, values: &[f32]) -> PackedQuery {
        match self.kind {
            QuantKind::None | QuantKind::Scalar8 => PackedQuery::F32 {
                values: values.to_vec(),
                norm: l2_norm(values),
            },
            QuantKind::Binary => PackedQuery::Binary {
                bits: pack_sign_bits(values),
                dim: values.len() as u32,
            },
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
    /// Physical payload bytes actually held for this row (excluding the enum
    /// discriminant and `Vec` bookkeeping).
    pub fn physical_bytes(&self) -> usize {
        match self {
            Self::F32 { values } => values.len() * 4,
            Self::Scalar8 { codes, .. } => codes.len() + 8,
            Self::Binary { bits, .. } => bits.len() + 4,
        }
    }

    /// Number of channels this row represents.
    pub fn dim(&self) -> usize {
        match self {
            Self::F32 { values } => values.len(),
            Self::Scalar8 { codes, .. } => codes.len(),
            Self::Binary { dim, .. } => *dim as usize,
        }
    }

    /// Reconstructs the representable approximation from the packed codes.
    ///
    /// This is a labeled reconstruction (exact only for `F32`); it is the
    /// read-back/decode path, never the scoring path.
    pub fn approx_f32(&self) -> Vec<f32> {
        match self {
            Self::F32 { values } => values.clone(),
            Self::Scalar8 { codes, scale, .. } => codes
                .iter()
                .map(|code| f32::from(*code as i8) * *scale)
                .collect(),
            Self::Binary { bits, dim } => (0..*dim as usize)
                .map(|index| {
                    if bits[index / 8] & (1 << (index % 8)) != 0 {
                        1.0
                    } else {
                        -1.0
                    }
                })
                .collect(),
        }
    }

    /// Stable byte identity of the packed representation, for exact-duplicate
    /// fingerprinting in the quantized domain.
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
        }
        bytes
    }
}

/// Scores one prepared query against one packed row on the packed
/// representation directly — no candidate decode, no `f32` reconstruction.
///
/// - `F32` query vs `F32` row: exact cosine.
/// - `F32` query vs `Scalar8` row: asymmetric cosine — the dot walks the
///   signed codes once (`sum q[i]·code[i]`, scaled after the loop) against the
///   precomputed dequantized row norm.
/// - `Binary` query vs `Binary` row: XOR + popcount Hamming sign agreement,
///   mapped to the cosine-like estimate `1 − 2·mismatches/dim`.
///
/// A kind pairing that the owning index cannot produce is refused fail-closed.
pub fn score_packed(query: &PackedQuery, row: &PackedVector) -> Result<f32> {
    match (query, row) {
        // Exact cosine, computed identically to the historical unquantized
        // path (bit-for-bit — weave's deterministic similarity plans depend
        // on unchanged QuantKind::None scores).
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
            let mut dot = 0.0_f64;
            for (value, code) in values.iter().zip(codes) {
                dot += f64::from(*value) * f64::from(*code as i8);
            }
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
        _ => Err(sextant_error(
            CALYX_SEXTANT_VECTOR_SHAPE,
            "prepared query kind does not match the packed row kind; prepare queries through the owning index's QuantConfig",
        )),
    }
}

fn dim_mismatch(query: usize, row: usize) -> calyx_core::CalyxError {
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
