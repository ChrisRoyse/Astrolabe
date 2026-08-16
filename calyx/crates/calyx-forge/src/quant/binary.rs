use crate::cpu::check_finite;
use crate::quant::rotation::{HaarRotation, haar_work_shape};
use crate::quant::{QuantLevel, QuantizedVec, Quantizer, RotationSeed, SeedId};
use crate::{ForgeError, Result};

const BINARY_LEVEL_DETAIL: &str = "BinaryCodec only supports Bits1";
const BINARY_REMEDIATION: &str =
    "Use finite vectors, matching seeds, and Bits1 binary quantized vectors";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Cache-independent admission cardinalities for one Binary codec dimension.
///
/// `dim` is invariant across the plan. The fields describe retained buffer
/// contents and conservative operation bounds; they are not elapsed-work,
/// allocator, or RSS measurements.
pub struct BinaryWorkShape {
    /// Source dimension.
    pub dim: u64,
    /// Retained Haar `Vec` content bytes.
    pub geometry_physical_bytes: u64,
    /// Retained Haar offsets, factors, and column signs.
    pub geometry_retained_entries: u64,
    /// Retained Householder factor coefficients.
    pub haar_factor_coefficients: u64,
    /// Coefficients retained by one prepared query.
    pub prepared_query_coefficients: u64,
    /// Retained `f32` bytes in one prepared query.
    pub prepared_query_physical_bytes: u64,
    /// Planned arithmetic coefficient-visit bound for one encode rotation.
    pub encode_transform_coefficient_visits: u64,
    /// Planned arithmetic coefficient-visit bound for one decode rotation.
    pub decode_transform_coefficient_visits: u64,
    /// Planned arithmetic coefficient-visit bound for one query rotation.
    pub query_prepare_transform_coefficient_visits: u64,
    /// Planned sign-visit bound for one prepared packed-candidate score.
    pub packed_score_coefficient_visits: u64,
}

/// Derives a Binary admission plan without constructing or caching geometry.
///
/// The valid-input path performs checked arithmetic and does not consult a
/// geometry cache.
pub fn binary_work_shape(dim: usize) -> Result<BinaryWorkShape> {
    let haar = haar_work_shape(dim)?;
    let dim = u64::try_from(dim)
        .map_err(|_| binary_error("work_shape", QuantLevel::Bits1, "dimension exceeds u64"))?;
    let f32_bytes = u64::try_from(std::mem::size_of::<f32>()).map_err(|_| {
        binary_error(
            "work_shape",
            QuantLevel::Bits1,
            "f32 byte width exceeds u64",
        )
    })?;
    let prepared_query_physical_bytes = dim.checked_mul(f32_bytes).ok_or_else(|| {
        binary_error(
            "work_shape",
            QuantLevel::Bits1,
            "prepared query byte count overflow",
        )
    })?;
    Ok(BinaryWorkShape {
        dim,
        geometry_physical_bytes: haar.geometry_physical_bytes,
        geometry_retained_entries: haar.geometry_retained_entries,
        haar_factor_coefficients: haar.factor_coefficients,
        prepared_query_coefficients: dim,
        prepared_query_physical_bytes,
        encode_transform_coefficient_visits: haar.transform_coefficient_visits,
        decode_transform_coefficient_visits: haar.transform_coefficient_visits,
        query_prepare_transform_coefficient_visits: haar.transform_coefficient_visits,
        packed_score_coefficient_visits: dim,
    })
}

#[derive(Clone, Debug)]
/// Query rotated once for repeated Binary packed-candidate scans.
pub struct BinaryPreparedQuery {
    dim: usize,
    seed_id: SeedId,
    rotated: Vec<f32>,
}

impl BinaryPreparedQuery {
    /// Prepared query dimension.
    pub fn dim(&self) -> usize {
        self.dim
    }

    /// Rotation identity used to prepare this query.
    pub fn seed_id(&self) -> SeedId {
        self.seed_id
    }
}

pub struct BinaryCodec {
    seed: RotationSeed,
    rotation: HaarRotation,
}

impl std::fmt::Debug for BinaryCodec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BinaryCodec")
            .field("dim", &self.seed.dim)
            .field("seed_id", &self.seed.id)
            .finish_non_exhaustive()
    }
}

impl BinaryCodec {
    pub fn new(seed: RotationSeed) -> Result<Self> {
        validate_seed(&seed)?;
        let rotation = HaarRotation::new(&seed)?;
        Ok(Self { seed, rotation })
    }

    pub fn seed(&self) -> &RotationSeed {
        &self.seed
    }

    /// Retained Haar buffer-content bytes in this live codec geometry.
    ///
    /// This reads the constructed buffers directly and performs no allocation.
    pub fn geometry_physical_bytes(&self) -> usize {
        let (starts, factors, signs) = self.rotation.geometry_parts();
        std::mem::size_of_val(starts)
            + std::mem::size_of_val(factors)
            + std::mem::size_of_val(signs)
    }

    /// Rotates one finite raw query for reuse across a candidate scan.
    pub fn prepare_query(&self, query: &[f32]) -> Result<BinaryPreparedQuery> {
        self.prepare_query_with_op(query, "binary_prepare_query")
    }

    /// Scores one packed candidate without repeating the query rotation.
    pub fn score_prepared(
        &self,
        query: &BinaryPreparedQuery,
        candidate: &QuantizedVec,
    ) -> Result<f32> {
        self.score_prepared_with_op(query, candidate, "score_prepared")
    }

    fn prepare_query_with_op(&self, query: &[f32], op: &str) -> Result<BinaryPreparedQuery> {
        self.validate_raw_query(query, op)?;
        self.prepare_validated_query(query)
    }

    fn validate_raw_query(&self, query: &[f32], op: &str) -> Result<()> {
        self.seed.verify_current_version()?;
        if query.len() != self.seed.dim {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![self.seed.dim],
                got: vec![query.len()],
                remediation: "Score binary vectors with a raw query of the codec dimension"
                    .to_string(),
            });
        }
        check_finite(query, op)?;
        Ok(())
    }

    fn prepare_validated_query(&self, query: &[f32]) -> Result<BinaryPreparedQuery> {
        let mut rotated = query.to_vec();
        self.rotation.apply(&mut rotated)?;
        Ok(BinaryPreparedQuery {
            dim: self.seed.dim,
            seed_id: self.seed.id,
            rotated,
        })
    }

    fn score_prepared_with_op(
        &self,
        query: &BinaryPreparedQuery,
        candidate: &QuantizedVec,
        op: &str,
    ) -> Result<f32> {
        self.validate_prepared_query(query, op)?;
        self.validate_scoring_candidate(candidate, op)?;
        self.score_validated(query, candidate, op)
    }

    fn validate_prepared_query(&self, query: &BinaryPreparedQuery, op: &str) -> Result<()> {
        if query.dim != self.seed.dim {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![self.seed.dim],
                got: vec![query.dim],
                remediation: "Score with a binary query prepared by this codec".to_string(),
            });
        }
        if query.seed_id != self.seed.id {
            return Err(binary_error(
                op,
                QuantLevel::Bits1,
                "prepared query geometry does not match the binary codec",
            ));
        }
        Ok(())
    }

    fn validate_scoring_candidate(&self, candidate: &QuantizedVec, op: &str) -> Result<()> {
        validate_quantized(candidate, op)?;
        if candidate.dim != self.seed.dim || candidate.seed_id != self.seed.id {
            return Err(binary_error(
                op,
                candidate.level,
                "packed candidate geometry does not match the binary codec",
            ));
        }
        Ok(())
    }

    fn score_validated(
        &self,
        query: &BinaryPreparedQuery,
        candidate: &QuantizedVec,
        op: &str,
    ) -> Result<f32> {
        let sum = query
            .rotated
            .iter()
            .enumerate()
            .map(|(index, value)| {
                if read_bit(&candidate.bytes, index) {
                    f64::from(*value)
                } else {
                    -f64::from(*value)
                }
            })
            .sum::<f64>()
            * f64::from(candidate.scale);
        if !sum.is_finite() || sum.abs() > f64::from(f32::MAX) {
            return Err(binary_error(
                op,
                candidate.level,
                "dot estimate cannot be represented as finite f32",
            ));
        }
        Ok(sum as f32)
    }
}

impl Quantizer for BinaryCodec {
    fn encode(&self, vec: &[f32]) -> Result<QuantizedVec> {
        self.seed.verify_current_version()?;
        if vec.len() != self.seed.dim {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![self.seed.dim],
                got: vec![vec.len()],
                remediation: "Encode vectors with the same dim as the rotation seed".to_string(),
            });
        }
        check_finite(vec, "binary_encode")?;
        let mut rotated = vec.to_vec();
        self.rotation.apply(&mut rotated)?;
        Ok(QuantizedVec {
            level: QuantLevel::Bits1,
            dim: self.seed.dim,
            bytes: pack_sign_bits(&rotated),
            scale: binary_amplitude(self.seed.dim),
            seed_id: self.seed.id,
        })
    }

    fn decode(&self, qv: &QuantizedVec) -> Result<Vec<f32>> {
        validate_quantized(qv, "decode")?;
        if qv.dim != self.seed.dim {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![self.seed.dim],
                got: vec![qv.dim],
                remediation: "Decode with the binary codec seed used for encode".to_string(),
            });
        }
        if qv.seed_id != self.seed.id {
            return Err(binary_error("decode", qv.level, "seed_id mismatch"));
        }
        let amplitude = binary_amplitude(qv.dim);
        let mut approx = (0..qv.dim)
            .map(|idx| {
                if read_bit(&qv.bytes, idx) {
                    amplitude
                } else {
                    -amplitude
                }
            })
            .collect::<Vec<_>>();
        self.rotation.apply_inverse(&mut approx)?;
        Ok(approx)
    }

    fn dot_estimate(&self, query: &[f32], candidate: &QuantizedVec) -> Result<f32> {
        self.validate_raw_query(query, "binary_dot_estimate")?;
        self.validate_scoring_candidate(candidate, "dot_estimate")?;
        let prepared = self.prepare_validated_query(query)?;
        self.score_validated(&prepared, candidate, "dot_estimate")
    }

    fn level(&self) -> QuantLevel {
        QuantLevel::Bits1
    }

    fn dim(&self) -> usize {
        self.seed.dim
    }
}

pub fn hamming_dot_estimate(a: &QuantizedVec, b: &QuantizedVec) -> Result<f32> {
    validate_quantized(a, "hamming_dot_estimate")?;
    validate_quantized(b, "hamming_dot_estimate")?;
    if a.dim != b.dim {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![a.dim],
            got: vec![b.dim],
            remediation: "Compare binary vectors with the same dimension".to_string(),
        });
    }
    if a.seed_id != b.seed_id {
        return Err(binary_error(
            "hamming_dot_estimate",
            a.level,
            "seed_id mismatch in hamming_dot_estimate",
        ));
    }
    let mismatches = (0..a.dim)
        .filter(|idx| read_bit(&a.bytes, *idx) != read_bit(&b.bytes, *idx))
        .count();
    Ok(1.0 - 2.0 * mismatches as f32 / a.dim as f32)
}

pub fn binary_prefilter(
    query: &QuantizedVec,
    candidates: &[QuantizedVec],
    keep: usize,
) -> Result<Vec<usize>> {
    validate_quantized(query, "binary_prefilter")?;
    if keep == 0 || candidates.is_empty() {
        return Ok(Vec::new());
    }
    let mut scored = candidates
        .iter()
        .enumerate()
        .map(|(idx, candidate)| hamming_dot_estimate(query, candidate).map(|score| (idx, score)))
        .collect::<Result<Vec<_>>>()?;
    scored.sort_by(|(left_idx, left_score), (right_idx, right_score)| {
        right_score
            .total_cmp(left_score)
            .then_with(|| left_idx.cmp(right_idx))
    });
    Ok(scored
        .into_iter()
        .take(keep.min(candidates.len()))
        .map(|(idx, _)| idx)
        .collect())
}

fn validate_seed(seed: &RotationSeed) -> Result<()> {
    seed.validate()
}

fn validate_quantized(qv: &QuantizedVec, op: &str) -> Result<()> {
    if qv.level != QuantLevel::Bits1 {
        return Err(binary_error(op, qv.level, BINARY_LEVEL_DETAIL));
    }
    if qv.dim == 0 {
        return Err(binary_error(op, qv.level, "dim must be non-zero"));
    }
    let expected_len = packed_len(qv.dim);
    if qv.bytes.len() != expected_len {
        return Err(binary_error(
            op,
            qv.level,
            format!(
                "encoded byte length mismatch: expected {expected_len} got {}",
                qv.bytes.len()
            ),
        ));
    }
    if !qv.scale.is_finite() || qv.scale < 0.0 {
        return Err(binary_error(
            op,
            qv.level,
            "scale must be finite and non-negative",
        ));
    }
    if qv.scale.to_bits() != binary_amplitude(qv.dim).to_bits() {
        return Err(binary_error(
            op,
            qv.level,
            "binary amplitude is not canonical for the encoded dimension",
        ));
    }
    if has_nonzero_padding(&qv.bytes, qv.dim) {
        return Err(binary_error(op, qv.level, "non-zero padding bits"));
    }
    Ok(())
}

fn pack_sign_bits(rotated: &[f32]) -> Vec<u8> {
    let mut bytes = vec![0; packed_len(rotated.len())];
    for (idx, value) in rotated.iter().enumerate() {
        if *value > 0.0 {
            bytes[idx / 8] |= 1 << (idx % 8);
        }
    }
    bytes
}

fn read_bit(bytes: &[u8], idx: usize) -> bool {
    ((bytes[idx / 8] >> (idx % 8)) & 1) == 1
}

fn packed_len(dim: usize) -> usize {
    dim.div_ceil(8)
}

fn binary_amplitude(dim: usize) -> f32 {
    1.0 / (dim as f32).sqrt()
}

fn has_nonzero_padding(bytes: &[u8], dim: usize) -> bool {
    let padding_bits = bytes.len() * 8 - dim;
    if padding_bits == 0 {
        return false;
    }
    let used_bits = 8 - padding_bits;
    let padding_mask = !((1u16 << used_bits) - 1) as u8;
    bytes.last().is_some_and(|last| (*last & padding_mask) != 0)
}

fn binary_error(op: &str, level: QuantLevel, detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: op.to_string(),
        level: format!("{level:?}"),
        detail: detail.into(),
        remediation: BINARY_REMEDIATION.to_string(),
    }
}
