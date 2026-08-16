use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use wide::f32x8;

use crate::quant::SeedId;
use crate::{ForgeError, Result};

/// Persisted seed contract used by the implicit Haar transform.
pub const CURRENT_SEED_VERSION: u8 = 2;
const ROTATION_MAX_DIM: usize = 4096;
const SEED_DOMAIN: &[u8] = b"calyx/rotation-seed/v2\0";
const HAAR_DOMAIN: &[u8] = b"calyx/haar-householder/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HaarWorkShape {
    pub(crate) factor_coefficients: u64,
    pub(crate) geometry_physical_bytes: u64,
    pub(crate) geometry_retained_entries: u64,
    pub(crate) transform_coefficient_visits: u64,
}

/// Structural Haar cardinalities shared by Binary and TurboQuant planning.
///
/// These checked values describe retained buffer contents and a nonzero
/// transform's admission bound. They are not runtime, allocator, or RSS
/// measurements.
pub(crate) fn haar_work_shape(dim: usize) -> Result<HaarWorkShape> {
    if dim == 0 || dim > ROTATION_MAX_DIM {
        return Err(rotation_error(
            "haar_work_shape",
            format!("dimension must be in 1..={ROTATION_MAX_DIM}, got {dim}"),
        ));
    }
    let dim = u64::try_from(dim)
        .map_err(|_| rotation_error("haar_work_shape", "dimension exceeds u64"))?;
    let factor_starts = dim
        .checked_sub(1)
        .ok_or_else(|| rotation_error("haar_work_shape", "factor offset count underflow"))?;
    let factor_coefficients = dim
        .checked_mul(
            dim.checked_add(1)
                .ok_or_else(|| rotation_error("haar_work_shape", "dimension overflow"))?,
        )
        .and_then(|value| value.checked_div(2))
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| rotation_error("haar_work_shape", "factor count overflow"))?;
    let column_signs = dim;
    let geometry_retained_entries = factor_starts
        .checked_add(factor_coefficients)
        .and_then(|value| value.checked_add(column_signs))
        .ok_or_else(|| rotation_error("haar_work_shape", "retained entry count overflow"))?;
    let usize_bytes = u64::try_from(std::mem::size_of::<usize>())
        .map_err(|_| rotation_error("haar_work_shape", "usize byte width exceeds u64"))?;
    let f32_bytes = u64::try_from(std::mem::size_of::<f32>())
        .map_err(|_| rotation_error("haar_work_shape", "f32 byte width exceeds u64"))?;
    let geometry_physical_bytes = factor_starts
        .checked_mul(usize_bytes)
        .and_then(|value| {
            factor_coefficients
                .checked_add(column_signs)
                .and_then(|coefficients| coefficients.checked_mul(f32_bytes))
                .and_then(|coefficient_bytes| value.checked_add(coefficient_bytes))
        })
        .ok_or_else(|| rotation_error("haar_work_shape", "geometry byte count overflow"))?;
    let transform_coefficient_visits = factor_coefficients
        .checked_mul(2)
        .and_then(|value| value.checked_add(column_signs))
        .ok_or_else(|| rotation_error("haar_work_shape", "transform visit count overflow"))?;
    Ok(HaarWorkShape {
        factor_coefficients,
        geometry_physical_bytes,
        geometry_retained_entries,
        transform_coefficient_visits,
    })
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
/// Content-addressed deterministic geometry seed.
pub struct RotationSeed {
    #[serde(with = "seed_id_hex_serde")]
    pub id: SeedId,
    pub version: u8,
    pub dim: usize,
    #[serde(with = "seed_id_hex_serde")]
    pub entropy: SeedId,
}

impl RotationSeed {
    pub fn verify_current_version(&self) -> Result<()> {
        if self.version != CURRENT_SEED_VERSION {
            return Err(ForgeError::SeedVersionMismatch {
                expected: CURRENT_SEED_VERSION,
                got: self.version,
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.verify_current_version()?;
        if self.dim == 0 || self.dim > ROTATION_MAX_DIM {
            return Err(rotation_error(
                "validate_seed",
                format!(
                    "dimension must be in 1..={ROTATION_MAX_DIM}, got {}",
                    self.dim
                ),
            ));
        }
        let expected_id = content_id(&self.entropy, self.version, self.dim);
        if self.id != expected_id {
            return Err(rotation_error(
                "validate_seed",
                "rotation seed content ID does not match its persisted material",
            ));
        }
        Ok(())
    }
}

pub fn new_seed(dim: usize, entropy: &[u8]) -> RotationSeed {
    let entropy = domain_seed(SEED_DOMAIN, entropy, dim);
    let id = content_id(&entropy, CURRENT_SEED_VERSION, dim);
    RotationSeed {
        id,
        version: CURRENT_SEED_VERSION,
        dim,
        entropy,
    }
}

/// Compact implicit Haar-orthogonal transform built from Gaussian Householder factors.
pub(crate) struct HaarRotation {
    dim: usize,
    seed_id: SeedId,
    factor_starts: Vec<usize>,
    factors: Vec<f32>,
    column_signs: Vec<f32>,
}

impl HaarRotation {
    pub(crate) fn new(seed: &RotationSeed) -> Result<Self> {
        seed.validate()?;
        let rng_seed = domain_seed(HAAR_DOMAIN, &seed.id, seed.dim);
        let mut normal = DeterministicNormal::new(rng_seed);
        let factor_capacity = usize::try_from(haar_work_shape(seed.dim)?.factor_coefficients)
            .map_err(|_| rotation_error("haar_setup", "Householder geometry size exceeds usize"))?;
        let mut factors = Vec::new();
        factors
            .try_reserve_exact(factor_capacity)
            .map_err(|error| {
                rotation_error(
                    "haar_setup",
                    format!("cannot allocate {factor_capacity} Householder coefficients: {error}"),
                )
            })?;
        let mut factor_starts = Vec::new();
        factor_starts
            .try_reserve_exact(seed.dim.saturating_sub(1))
            .map_err(|error| {
                rotation_error(
                    "haar_setup",
                    format!("cannot allocate Householder offsets: {error}"),
                )
            })?;
        let mut column_signs = Vec::new();
        column_signs.try_reserve_exact(seed.dim).map_err(|error| {
            rotation_error(
                "haar_setup",
                format!("cannot allocate column signs: {error}"),
            )
        })?;
        let mut column = Vec::new();
        column.try_reserve_exact(seed.dim).map_err(|error| {
            rotation_error(
                "haar_setup",
                format!("cannot allocate Gaussian work column: {error}"),
            )
        })?;

        for offset in 0..seed.dim {
            let len = seed.dim - offset;
            column.clear();
            let mut norm_sq = 0.0_f64;
            for _ in 0..len {
                let value = normal.next_f32();
                norm_sq += f64::from(value) * f64::from(value);
                column.push(value);
            }
            let norm = norm_sq.sqrt();
            if !norm.is_finite() || norm == 0.0 {
                return Err(rotation_error(
                    "haar_setup",
                    format!("degenerate Gaussian column at offset {offset}"),
                ));
            }
            let alpha = if column[0].is_sign_negative() {
                norm
            } else {
                -norm
            };
            column_signs.push(if alpha.is_sign_negative() { -1.0 } else { 1.0 });
            if len == 1 {
                continue;
            }
            column[0] -= alpha as f32;
            let factor_norm = column
                .iter()
                .map(|value| f64::from(*value) * f64::from(*value))
                .sum::<f64>()
                .sqrt();
            if !factor_norm.is_finite() || factor_norm == 0.0 {
                return Err(rotation_error(
                    "haar_setup",
                    format!("degenerate Householder factor at offset {offset}"),
                ));
            }
            factor_starts.push(factors.len());
            factors.extend(
                column
                    .iter()
                    .map(|value| (f64::from(*value) / factor_norm) as f32),
            );
        }

        Ok(Self {
            dim: seed.dim,
            seed_id: seed.id,
            factor_starts,
            factors,
            column_signs,
        })
    }

    pub(crate) fn apply(&self, vec: &mut [f32]) -> Result<()> {
        self.validate_input(vec, "apply_rotation")?;
        for (value, sign) in vec.iter_mut().zip(&self.column_signs) {
            *value *= *sign;
        }
        for offset in (0..self.factor_starts.len()).rev() {
            self.apply_factor(offset, vec)?;
        }
        validate_finite_output(vec, "apply_rotation")
    }

    pub(crate) fn geometry_parts(&self) -> (&[usize], &[f32], &[f32]) {
        (&self.factor_starts, &self.factors, &self.column_signs)
    }

    pub(crate) fn apply_inverse(&self, vec: &mut [f32]) -> Result<()> {
        self.validate_input(vec, "apply_inverse_rotation")?;
        for offset in 0..self.factor_starts.len() {
            self.apply_factor(offset, vec)?;
        }
        for (value, sign) in vec.iter_mut().zip(&self.column_signs) {
            *value *= *sign;
        }
        validate_finite_output(vec, "apply_inverse_rotation")
    }

    fn validate_input(&self, vec: &[f32], op: &str) -> Result<()> {
        if vec.len() != self.dim {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![self.dim],
                got: vec![vec.len()],
                remediation: "Apply the rotation to vectors with the seed dimension".to_string(),
            });
        }
        if let Some(index) = vec.iter().position(|value| !value.is_finite()) {
            return Err(rotation_error(
                op,
                format!("non-finite coefficient at index {index}"),
            ));
        }
        Ok(())
    }

    fn apply_factor(&self, offset: usize, vec: &mut [f32]) -> Result<()> {
        let start = self.factor_starts[offset];
        let len = self.dim - offset;
        let end = start + len;
        let factor = self.factors.get(start..end).ok_or_else(|| {
            rotation_error(
                "apply_householder",
                format!("factor bounds invalid for offset {offset}"),
            )
        })?;
        let tail = &mut vec[offset..];
        let dot = simd_dot(factor, tail);
        let twice_dot = 2.0 * dot;
        for (value, normal) in tail.iter_mut().zip(factor) {
            *value -= twice_dot * *normal;
        }
        Ok(())
    }

    pub(crate) fn seed_id(&self) -> SeedId {
        self.seed_id
    }
}

pub fn apply_rotation(seed: &RotationSeed, vec: &mut [f32]) -> Result<()> {
    HaarRotation::new(seed)?.apply(vec)
}

pub fn apply_inverse_rotation(seed: &RotationSeed, vec: &mut [f32]) -> Result<()> {
    HaarRotation::new(seed)?.apply_inverse(vec)
}

pub fn apply_rotation_batch(seed: &RotationSeed, vecs: &mut [f32], n: usize) -> Result<()> {
    let expected = n
        .checked_mul(seed.dim)
        .ok_or_else(|| ForgeError::ShapeMismatch {
            expected: vec![n, seed.dim],
            got: vec![vecs.len()],
            remediation: "Use a batch shape whose row count times dimension fits usize".to_string(),
        })?;
    if vecs.len() != expected {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![expected],
            got: vec![vecs.len()],
            remediation: "Provide exactly n contiguous rows of the seed dimension".to_string(),
        });
    }
    let rotation = HaarRotation::new(seed)?;
    for row in vecs.chunks_exact_mut(seed.dim) {
        rotation.apply(row)?;
    }
    Ok(())
}

pub fn seed_id_hex(id: &SeedId) -> String {
    let mut hex = String::with_capacity(id.len() * 2);
    for byte in id {
        hex.push(nibble_hex(byte >> 4));
        hex.push(nibble_hex(byte & 0x0f));
    }
    hex
}

pub(crate) struct DeterministicNormal {
    rng: ChaCha8Rng,
    spare: Option<f32>,
}

impl DeterministicNormal {
    pub(crate) fn new(seed: SeedId) -> Self {
        Self {
            rng: ChaCha8Rng::from_seed(seed),
            spare: None,
        }
    }

    pub(crate) fn next_f32(&mut self) -> f32 {
        if let Some(value) = self.spare.take() {
            return value;
        }
        let u1 = open_unit_f64(self.rng.next_u64());
        let u2 = open_unit_f64(self.rng.next_u64());
        let radius = (-2.0 * u1.ln()).sqrt();
        let angle = std::f64::consts::TAU * u2;
        let (sine, cosine) = angle.sin_cos();
        let first = (radius * cosine) as f32;
        self.spare = Some((radius * sine) as f32);
        first
    }
}

pub(crate) fn domain_seed(domain: &[u8], entropy: &[u8], dim: usize) -> SeedId {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((entropy.len() as u64).to_le_bytes());
    hasher.update(entropy);
    hasher.update((dim as u64).to_le_bytes());
    hasher.finalize().into()
}

fn content_id(entropy: &SeedId, version: u8, dim: usize) -> SeedId {
    let mut hasher = Sha256::new();
    hasher.update(SEED_DOMAIN);
    hasher.update([version]);
    hasher.update((dim as u64).to_le_bytes());
    hasher.update(entropy);
    hasher.finalize().into()
}

fn open_unit_f64(value: u64) -> f64 {
    const DENOMINATOR: f64 = (1_u64 << 53) as f64;
    (((value >> 11) as f64) + 0.5) / DENOMINATOR
}

fn simd_dot(left: &[f32], right: &[f32]) -> f32 {
    let mut sum = 0.0_f32;
    let mut offset = 0;
    while offset + 8 <= left.len() {
        let mut lhs = [0.0; 8];
        let mut rhs = [0.0; 8];
        lhs.copy_from_slice(&left[offset..offset + 8]);
        rhs.copy_from_slice(&right[offset..offset + 8]);
        sum += (f32x8::from(lhs) * f32x8::from(rhs)).reduce_add();
        offset += 8;
    }
    while offset < left.len() {
        sum += left[offset] * right[offset];
        offset += 1;
    }
    sum
}

fn validate_finite_output(vec: &[f32], op: &str) -> Result<()> {
    if let Some(index) = vec.iter().position(|value| !value.is_finite()) {
        return Err(rotation_error(
            op,
            format!("rotation produced a non-finite coefficient at index {index}"),
        ));
    }
    Ok(())
}

fn rotation_error(op: &str, detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: op.to_string(),
        level: "rotation".to_string(),
        detail: detail.into(),
        remediation:
            "Use an intact current-version seed and finite vectors with dimension 1..=4096"
                .to_string(),
    }
}

fn nibble_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => '?',
    }
}

fn decode_hex_seed_id(text: &str) -> std::result::Result<SeedId, String> {
    if text.len() != 64 {
        return Err(format!("seed id hex length must be 64, got {}", text.len()));
    }
    let mut id = [0u8; 32];
    for (idx, slot) in id.iter_mut().enumerate() {
        let hi = hex_value(text.as_bytes()[idx * 2])?;
        let lo = hex_value(text.as_bytes()[idx * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(id)
}

fn hex_value(byte: u8) -> std::result::Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid seed id hex byte: {byte}")),
    }
}

mod seed_id_hex_serde {
    use super::*;

    pub fn serialize<S>(id: &SeedId, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&seed_id_hex(id))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<SeedId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        decode_hex_seed_id(&text).map_err(serde::de::Error::custom)
    }
}
