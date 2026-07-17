use std::fmt;

use sha2::{Digest, Sha256};

use crate::quant::codebook::LloydMaxCodebook;
use crate::quant::qjl::{GaussianProjection, QjlResidual, bitstream_len, has_nonzero_padding};
use crate::quant::rotation::HaarRotation;
use crate::quant::{QuantLevel, QuantizedVec, Quantizer, RotationSeed, SeedId};
use crate::{ForgeError, Result};

/// Maximum geometry dimension admitted by the dense Gaussian product format.
pub const TURBOQUANT_MAX_DIM: usize = 4096;
/// Current persisted `TQPR` product-format version.
pub const TURBOQUANT_FORMAT_VERSION: u8 = 2;
/// Fixed bytes preceding the scalar and QJL data bitstreams.
pub const TURBOQUANT_FORMAT_HEADER_BYTES: usize = 88;

const MAGIC: &[u8; 4] = b"TQPR";
const FLAGS: u16 = 0;
const DIGEST_DOMAIN: &[u8] = b"calyx/turboquant/tqpr/payload/v2\0";
const LEGACY_V1_DIGEST_DOMAIN: &[u8] = b"calyx/turboquant/tqpr/payload/v1\0";
const LEGACY_V1_FORMAT_VERSION: u8 = 1;
const GEOMETRY_DOMAIN: &[u8] = b"calyx/turboquant/geometry/v2\0";
const HEADER_PREFIX_BYTES: usize = 56;
const DIGEST_OFFSET: usize = HEADER_PREFIX_BYTES;
const BODY_OFFSET: usize = TURBOQUANT_FORMAT_HEADER_BYTES;
const BITS2P5_LEVEL_CODE: u8 = 1;
const BITS3P5_LEVEL_CODE: u8 = 2;
const REMEDIATION: &str = "Use a canonical TQPR v2 payload, matching current-version geometry, supported level, and finite vector with dimension 1..=4096";

#[derive(Clone, Copy, Debug, PartialEq)]
/// Physical and logical storage accounting for a validated TQPR payload.
pub struct TurboQuantStorage {
    /// Scalar plus QJL information bits, excluding byte padding and headers.
    pub data_bits: usize,
    /// Mixed-width Lloyd-Max scalar information bits.
    pub scalar_bits: usize,
    /// One QJL sign bit per coordinate.
    pub qjl_bits: usize,
    /// Fixed TQPR header size.
    pub format_header_bytes: usize,
    /// Complete TQPR payload size, including header and byte padding.
    pub payload_bytes: usize,
    /// Logical data bits divided by the source dimension.
    pub logical_bits_per_channel: f64,
}

#[derive(Clone, Debug)]
/// Query geometry prepared once for repeated packed-candidate scans.
pub struct TurboQuantPreparedQuery {
    dim: usize,
    seed_id: SeedId,
    rotated: Vec<f32>,
    projected: Vec<f32>,
}

/// Borrowed TQPR candidate whose digest, canonical bits, and codec geometry
/// were validated exactly once for a hot read/search operation.
pub struct TurboQuantValidatedCandidate<'a> {
    level: QuantLevel,
    dim: usize,
    geometry_id: SeedId,
    scale: f32,
    scalar: &'a [u8],
    qjl: &'a [u8],
    gamma: f32,
    storage: TurboQuantStorage,
}

impl TurboQuantPreparedQuery {
    /// Prepared query dimension.
    pub fn dim(&self) -> usize {
        self.dim
    }

    /// Shared transform identity used to prepare the query.
    pub fn seed_id(&self) -> SeedId {
        self.seed_id
    }
}

/// TurboQuant product codec with dense random rotation and asymmetric QJL scoring.
///
/// The fractional levels use a data-oblivious alternating-width specialization
/// of the paper's core estimator. They are not the model-calibrated outlier
/// channel split used by the paper's KV-cache experiments.
pub struct TurboQuantCodec {
    seed: RotationSeed,
    geometry_id: SeedId,
    level: QuantLevel,
    rotation: HaarRotation,
    projection: GaussianProjection,
    low_codebook: LloydMaxCodebook,
    high_codebook: LloydMaxCodebook,
}

/// Exact, read-only verifier for upgrading committed TQPR-v1 payloads.
///
/// V1 used a different Lloyd-Max numerical solver and identified geometry by
/// the rotation seed alone. This type exists only to prove that a legacy row
/// was deterministically emitted from its persisted raw sidecar before an
/// atomic rewrite to the current format.
pub struct TurboQuantV1MigrationVerifier {
    seed: RotationSeed,
    level: QuantLevel,
    rotation: HaarRotation,
    projection: GaussianProjection,
    low_codebook: LloydMaxCodebook,
    high_codebook: LloydMaxCodebook,
}

impl fmt::Debug for TurboQuantCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurboQuantCodec")
            .field("level", &self.level)
            .field("dim", &self.seed.dim)
            .field("seed_id", &self.seed.id)
            .field("geometry_id", &self.geometry_id)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for TurboQuantV1MigrationVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurboQuantV1MigrationVerifier")
            .field("level", &self.level)
            .field("dim", &self.seed.dim)
            .field("seed_id", &self.seed.id)
            .finish_non_exhaustive()
    }
}

impl TurboQuantV1MigrationVerifier {
    /// Reconstructs the exact committed v1 geometry once for a whole column.
    pub fn new(seed: RotationSeed, level: QuantLevel) -> Result<Self> {
        validate_level(level, "legacy_v1_migration_new")?;
        if seed.dim == 0 || seed.dim > TURBOQUANT_MAX_DIM {
            return Err(quant_error(
                "legacy_v1_migration_new",
                level,
                format!(
                    "dimension must be in 1..={TURBOQUANT_MAX_DIM}, got {}",
                    seed.dim
                ),
            ));
        }
        seed.validate()?;
        let (low_bits, high_bits) = scalar_widths(level)?;
        let rotation = HaarRotation::new(&seed)?;
        if rotation.seed_id() != seed.id {
            return Err(quant_error(
                "legacy_v1_migration_new",
                level,
                "legacy Haar rotation seed identity mismatch",
            ));
        }
        let projection = GaussianProjection::new(&seed, level)?;
        let low_codebook = LloydMaxCodebook::new_legacy_v1(seed.dim, low_bits, level)?;
        let high_codebook = LloydMaxCodebook::new_legacy_v1(seed.dim, high_bits, level)?;
        Ok(Self {
            seed,
            level,
            rotation,
            projection,
            low_codebook,
            high_codebook,
        })
    }

    /// Verifies every persisted metadata field and byte against a fresh v1
    /// encoding of the independently read raw source.
    pub fn verify(&self, source: &[f32], persisted: &QuantizedVec) -> Result<()> {
        let expected = self.reconstruct_expected(source)?;
        if persisted.level != expected.level {
            return Err(quant_error(
                "legacy_v1_migration_verify",
                persisted.level,
                format!(
                    "legacy level mismatch: expected={} got={}",
                    expected.level, persisted.level
                ),
            ));
        }
        if persisted.dim != expected.dim {
            return Err(quant_error(
                "legacy_v1_migration_verify",
                persisted.level,
                format!(
                    "legacy dimension mismatch: expected={} got={}",
                    expected.dim, persisted.dim
                ),
            ));
        }
        if persisted.scale.to_bits() != expected.scale.to_bits() {
            return Err(quant_error(
                "legacy_v1_migration_verify",
                persisted.level,
                format!(
                    "legacy source norm mismatch: expected_bits=0x{:08x} got_bits=0x{:08x}",
                    expected.scale.to_bits(),
                    persisted.scale.to_bits()
                ),
            ));
        }
        if persisted.seed_id != expected.seed_id {
            return Err(quant_error(
                "legacy_v1_migration_verify",
                persisted.level,
                format!(
                    "legacy seed mismatch: expected={:02x?} got={:02x?}",
                    expected.seed_id, persisted.seed_id
                ),
            ));
        }
        if persisted.bytes != expected.bytes {
            let first_difference = persisted
                .bytes
                .iter()
                .zip(&expected.bytes)
                .position(|(actual, expected)| actual != expected)
                .unwrap_or_else(|| persisted.bytes.len().min(expected.bytes.len()));
            return Err(quant_error(
                "legacy_v1_migration_verify",
                persisted.level,
                format!(
                    "legacy TQPR-v1 bytes do not match deterministic raw-source re-encoding: first_difference={first_difference} expected_bytes={} got_bytes={}",
                    expected.bytes.len(),
                    persisted.bytes.len()
                ),
            ));
        }
        Ok(())
    }

    /// Reconstructs the bytes that the committed v1 writer emitted for source.
    ///
    /// This is exposed for migration inspection and historical fixture
    /// construction only. Production persistence accepts current-format bytes
    /// exclusively.
    pub fn reconstruct_expected(&self, source: &[f32]) -> Result<QuantizedVec> {
        self.encode_expected(source)
    }

    /// Produces legacy bytes only inside the migration verifier. Callers can
    /// verify old state but cannot use this type as a general write codec.
    fn encode_expected(&self, source: &[f32]) -> Result<QuantizedVec> {
        validate_raw(
            source,
            self.seed.dim,
            "legacy_v1_migration_encode",
            self.level,
        )?;
        let norm = source
            .iter()
            .map(|value| f64::from(*value) * f64::from(*value))
            .sum::<f64>()
            .sqrt();
        if !norm.is_finite() || norm > f64::from(f32::MAX) {
            return Err(quant_error(
                "legacy_v1_migration_encode",
                self.level,
                "source norm cannot be represented as finite f32",
            ));
        }
        let source_norm = norm as f32;
        let scalar_bit_count = scalar_bits(self.seed.dim, self.level)?;
        if source_norm == 0.0 {
            let scalar = vec![0_u8; scalar_bit_count.div_ceil(8)];
            let qjl = QjlResidual {
                bits: vec![0_u8; bitstream_len(self.seed.dim)],
                gamma: 0.0,
            };
            let bytes = build_payload_with_contract(
                LEGACY_V1_FORMAT_VERSION,
                LEGACY_V1_DIGEST_DOMAIN,
                self.level,
                self.seed.dim,
                self.seed.id,
                source_norm,
                scalar_bit_count,
                &scalar,
                &qjl,
            )?;
            return Ok(QuantizedVec {
                level: self.level,
                dim: self.seed.dim,
                bytes,
                scale: source_norm,
                seed_id: self.seed.id,
            });
        }

        let mut rotated = source
            .iter()
            .map(|value| (f64::from(*value) / f64::from(source_norm)) as f32)
            .collect::<Vec<_>>();
        self.rotation.apply(&mut rotated)?;
        let mut scalar = vec![0_u8; scalar_bit_count.div_ceil(8)];
        let mut residual = Vec::with_capacity(self.seed.dim);
        let mut bit_offset = 0_usize;
        for (index, value) in rotated.iter().enumerate() {
            let codebook = if index % 2 == 0 {
                &self.high_codebook
            } else {
                &self.low_codebook
            };
            let code = codebook.quantize(*value);
            write_bits(&mut scalar, bit_offset, codebook.bits(), code);
            bit_offset += codebook.bits();
            let centroid = codebook.centroid(code).ok_or_else(|| {
                quant_error(
                    "legacy_v1_migration_encode",
                    self.level,
                    format!("legacy scalar code {code} is invalid at coordinate {index}"),
                )
            })?;
            residual.push(*value - centroid);
        }
        let qjl = self.projection.encode_residual(&residual, source_norm)?;
        let bytes = build_payload_with_contract(
            LEGACY_V1_FORMAT_VERSION,
            LEGACY_V1_DIGEST_DOMAIN,
            self.level,
            self.seed.dim,
            self.seed.id,
            source_norm,
            scalar_bit_count,
            &scalar,
            &qjl,
        )?;
        Ok(QuantizedVec {
            level: self.level,
            dim: self.seed.dim,
            bytes,
            scale: source_norm,
            seed_id: self.seed.id,
        })
    }
}

impl TurboQuantCodec {
    /// Constructs one reusable lens/slot geometry for the requested level.
    pub fn new(seed: RotationSeed, level: QuantLevel) -> Result<Self> {
        validate_level(level, "new")?;
        if seed.dim == 0 || seed.dim > TURBOQUANT_MAX_DIM {
            return Err(quant_error(
                "new",
                level,
                format!(
                    "dimension must be in 1..={TURBOQUANT_MAX_DIM}, got {}",
                    seed.dim
                ),
            ));
        }
        seed.validate()?;
        let (low_bits, high_bits) = scalar_widths(level)?;
        let rotation = HaarRotation::new(&seed)?;
        if rotation.seed_id() != seed.id {
            return Err(quant_error(
                "new",
                level,
                "Haar rotation seed identity mismatch",
            ));
        }
        let projection = GaussianProjection::new(&seed, level)?;
        let low_codebook = LloydMaxCodebook::new(seed.dim, low_bits, level)?;
        let high_codebook = LloydMaxCodebook::new(seed.dim, high_bits, level)?;
        let geometry_id = geometry_id(
            &seed,
            level,
            &rotation,
            &projection,
            &low_codebook,
            &high_codebook,
        );
        Ok(Self {
            seed,
            geometry_id,
            level,
            rotation,
            projection,
            low_codebook,
            high_codebook,
        })
    }

    /// Validates the complete persisted TQPR payload without constructing codec geometry.
    pub fn inspect(qv: &QuantizedVec) -> Result<TurboQuantStorage> {
        let parsed = ParsedPayload::parse(qv, "inspect")?;
        Ok(parsed.storage())
    }

    /// Canonical identity of every generated f32 geometry coefficient.
    pub fn geometry_id(&self) -> SeedId {
        self.geometry_id
    }

    /// Validates storage structure and verifies this codec owns the payload geometry.
    pub fn storage(&self, qv: &QuantizedVec) -> Result<TurboQuantStorage> {
        Ok(self.validate_candidate(qv)?.storage)
    }

    /// Validates a packed candidate once and returns a borrowed hot-path view.
    pub fn validate_candidate<'a>(
        &self,
        qv: &'a QuantizedVec,
    ) -> Result<TurboQuantValidatedCandidate<'a>> {
        let parsed = self.parse_owned(qv, "validate_candidate")?;
        Ok(TurboQuantValidatedCandidate {
            level: qv.level,
            dim: qv.dim,
            geometry_id: qv.seed_id,
            scale: qv.scale,
            scalar: parsed.scalar,
            qjl: parsed.qjl,
            gamma: parsed.gamma,
            storage: parsed.storage(),
        })
    }

    /// Applies the shared Haar rotation and Gaussian projection once per raw query.
    pub fn prepare_query(&self, query: &[f32]) -> Result<TurboQuantPreparedQuery> {
        validate_raw(query, self.seed.dim, "prepare_query", self.level)?;
        let mut rotated = query.to_vec();
        self.rotation.apply(&mut rotated)?;
        let projected = self.projection.project(&rotated)?;
        Ok(TurboQuantPreparedQuery {
            dim: self.seed.dim,
            seed_id: self.geometry_id,
            rotated,
            projected,
        })
    }

    /// Scores a validated packed candidate without reconstructing candidate coordinates.
    pub fn dot_estimate_prepared(
        &self,
        query: &TurboQuantPreparedQuery,
        candidate: &QuantizedVec,
    ) -> Result<f32> {
        let candidate = self.validate_candidate(candidate)?;
        self.dot_estimate_validated(query, &candidate)
    }

    /// Scores a candidate view without rehashing or reparsing its TQPR bytes.
    pub fn dot_estimate_validated(
        &self,
        query: &TurboQuantPreparedQuery,
        candidate: &TurboQuantValidatedCandidate<'_>,
    ) -> Result<f32> {
        if query.dim != self.seed.dim || query.seed_id != self.geometry_id {
            return Err(quant_error(
                "score_prepared",
                self.level,
                "prepared query was produced by different codec geometry",
            ));
        }
        if candidate.level != self.level
            || candidate.dim != self.seed.dim
            || candidate.geometry_id != self.geometry_id
        {
            return Err(quant_error(
                "score_validated",
                self.level,
                "validated candidate belongs to different codec geometry",
            ));
        }
        if candidate.scale == 0.0 {
            return Ok(0.0);
        }
        let scalar_dot = self.scalar_dot(&query.rotated, candidate.scalar, "score_prepared")?;
        let correction =
            self.projection
                .correction_parts(&query.projected, candidate.qjl, candidate.gamma)?;
        finite_f32(
            f64::from(candidate.scale) * scalar_dot + correction,
            "score_prepared",
            self.level,
        )
    }

    fn scalar_dot(&self, query: &[f32], scalar: &[u8], op: &str) -> Result<f64> {
        let high_bits = self.high_codebook.bits();
        let low_bits = self.low_codebook.bits();
        let pair_bits = high_bits + low_bits;
        let mut sum = 0.0_f64;
        for pair in 0..self.seed.dim.div_ceil(2) {
            let index = pair * 2;
            let (high_code, low_code) =
                read_code_pair(scalar, pair * pair_bits, high_bits, low_bits);
            let high = self.checked_centroid(&self.high_codebook, high_code, index, op)?;
            sum += f64::from(query[index]) * f64::from(high);
            if index + 1 < self.seed.dim {
                let low = self.checked_centroid(&self.low_codebook, low_code, index + 1, op)?;
                sum += f64::from(query[index + 1]) * f64::from(low);
            }
        }
        if !sum.is_finite() {
            return Err(quant_error(
                op,
                self.level,
                "scalar dot product is non-finite",
            ));
        }
        Ok(sum)
    }

    fn decode_scalar(&self, scalar: &[u8], scale: f32) -> Result<Vec<f32>> {
        let mut decoded = Vec::new();
        decoded.try_reserve_exact(self.seed.dim).map_err(|error| {
            quant_error(
                "decode",
                self.level,
                format!(
                    "cannot allocate {} decoded coefficients: {error}",
                    self.seed.dim
                ),
            )
        })?;
        let high_bits = self.high_codebook.bits();
        let low_bits = self.low_codebook.bits();
        let pair_bits = high_bits + low_bits;
        for pair in 0..self.seed.dim.div_ceil(2) {
            let index = pair * 2;
            let (high_code, low_code) =
                read_code_pair(scalar, pair * pair_bits, high_bits, low_bits);
            decoded.push(
                scale * self.checked_centroid(&self.high_codebook, high_code, index, "decode")?,
            );
            if index + 1 < self.seed.dim {
                decoded.push(
                    scale
                        * self.checked_centroid(
                            &self.low_codebook,
                            low_code,
                            index + 1,
                            "decode",
                        )?,
                );
            }
        }
        Ok(decoded)
    }

    fn checked_centroid(
        &self,
        codebook: &LloydMaxCodebook,
        code: u8,
        index: usize,
        op: &str,
    ) -> Result<f32> {
        if !codebook.is_canonical_code(code) {
            return Err(quant_error(
                op,
                self.level,
                format!("scalar code {code} is non-canonical at coordinate {index}"),
            ));
        }
        codebook.centroid(code).ok_or_else(|| {
            quant_error(
                op,
                self.level,
                format!("scalar code {code} is invalid at coordinate {index}"),
            )
        })
    }

    fn parse_owned<'a>(&self, qv: &'a QuantizedVec, op: &str) -> Result<ParsedPayload<'a>> {
        let parsed = ParsedPayload::parse(qv, op)?;
        if qv.level != self.level || qv.dim != self.seed.dim || qv.seed_id != self.geometry_id {
            return Err(quant_error(
                op,
                qv.level,
                format!(
                    "payload geometry mismatch: codec level={} dim={} seed={:02x?}",
                    self.level, self.seed.dim, self.geometry_id
                ),
            ));
        }
        Ok(parsed)
    }

    fn codebook_for_index(&self, index: usize) -> &LloydMaxCodebook {
        if index % 2 == 0 {
            &self.high_codebook
        } else {
            &self.low_codebook
        }
    }

    fn encode_nonzero(&self, vec: &[f32], source_norm: f32) -> Result<QuantizedVec> {
        let mut rotated = vec
            .iter()
            .map(|value| (f64::from(*value) / f64::from(source_norm)) as f32)
            .collect::<Vec<_>>();
        self.rotation.apply(&mut rotated)?;
        let scalar_bit_count = scalar_bits(self.seed.dim, self.level)?;
        let mut scalar = vec![0u8; scalar_bit_count.div_ceil(8)];
        let mut residual = Vec::with_capacity(self.seed.dim);
        let mut bit_offset = 0usize;
        for (index, value) in rotated.iter().enumerate() {
            let codebook = self.codebook_for_index(index);
            let code = codebook.quantize(*value);
            write_bits(&mut scalar, bit_offset, codebook.bits(), code);
            bit_offset += codebook.bits();
            let centroid = codebook.centroid(code).ok_or_else(|| {
                quant_error(
                    "encode",
                    self.level,
                    format!("generated scalar code {code} is invalid at coordinate {index}"),
                )
            })?;
            residual.push(*value - centroid);
        }
        let qjl = self.projection.encode_residual(&residual, source_norm)?;
        let bytes = build_payload(
            self.level,
            self.seed.dim,
            self.geometry_id,
            source_norm,
            scalar_bit_count,
            &scalar,
            &qjl,
        )?;
        Ok(QuantizedVec {
            level: self.level,
            dim: self.seed.dim,
            bytes,
            scale: source_norm,
            seed_id: self.geometry_id,
        })
    }
}

impl Quantizer for TurboQuantCodec {
    fn encode(&self, vec: &[f32]) -> Result<QuantizedVec> {
        validate_raw(vec, self.seed.dim, "encode", self.level)?;
        let norm = vec
            .iter()
            .map(|value| f64::from(*value) * f64::from(*value))
            .sum::<f64>()
            .sqrt();
        if !norm.is_finite() || norm > f64::from(f32::MAX) {
            return Err(quant_error(
                "encode",
                self.level,
                "source norm cannot be represented as finite f32",
            ));
        }
        let source_norm = norm as f32;
        if source_norm == 0.0 {
            let scalar_bit_count = scalar_bits(self.seed.dim, self.level)?;
            let scalar = vec![0u8; scalar_bit_count.div_ceil(8)];
            let qjl = QjlResidual {
                bits: vec![0u8; bitstream_len(self.seed.dim)],
                gamma: 0.0,
            };
            let bytes = build_payload(
                self.level,
                self.seed.dim,
                self.geometry_id,
                0.0,
                scalar_bit_count,
                &scalar,
                &qjl,
            )?;
            return Ok(QuantizedVec {
                level: self.level,
                dim: self.seed.dim,
                bytes,
                scale: 0.0,
                seed_id: self.geometry_id,
            });
        }
        self.encode_nonzero(vec, source_norm)
    }

    fn decode(&self, qv: &QuantizedVec) -> Result<Vec<f32>> {
        let parsed = self.parse_owned(qv, "decode")?;
        if qv.scale == 0.0 {
            return Ok(vec![0.0; self.seed.dim]);
        }
        let mut scalar = self.decode_scalar(parsed.scalar, qv.scale)?;
        let inverse = self.projection.inverse_parts(parsed.qjl, parsed.gamma)?;
        for (value, correction) in scalar.iter_mut().zip(inverse) {
            *value += correction;
        }
        self.rotation.apply_inverse(&mut scalar)?;
        Ok(scalar)
    }

    fn dot_estimate(&self, query: &[f32], candidate: &QuantizedVec) -> Result<f32> {
        let prepared = self.prepare_query(query)?;
        self.dot_estimate_prepared(&prepared, candidate)
    }

    fn level(&self) -> QuantLevel {
        self.level
    }

    fn dim(&self) -> usize {
        self.seed.dim
    }
}

struct ParsedPayload<'a> {
    scalar: &'a [u8],
    qjl: &'a [u8],
    gamma: f32,
    scalar_bits: usize,
    qjl_bits: usize,
    payload_bytes: usize,
    dim: usize,
}

impl<'a> ParsedPayload<'a> {
    fn parse(qv: &'a QuantizedVec, op: &str) -> Result<Self> {
        validate_level(qv.level, op)?;
        if qv.dim == 0 || qv.dim > TURBOQUANT_MAX_DIM {
            return Err(quant_error(
                op,
                qv.level,
                format!(
                    "dimension must be in 1..={TURBOQUANT_MAX_DIM}, got {}",
                    qv.dim
                ),
            ));
        }
        if !qv.scale.is_finite() || qv.scale.is_sign_negative() {
            return Err(quant_error(
                op,
                qv.level,
                "source norm must be finite, non-negative, and canonical +0.0 when zero",
            ));
        }
        if qv.bytes.len() < TURBOQUANT_FORMAT_HEADER_BYTES {
            return Err(quant_error(
                op,
                qv.level,
                format!(
                    "TQPR payload shorter than {TURBOQUANT_FORMAT_HEADER_BYTES}-byte header: {}",
                    qv.bytes.len()
                ),
            ));
        }
        if &qv.bytes[0..4] != MAGIC.as_slice() {
            return Err(quant_error(op, qv.level, "TQPR magic mismatch"));
        }
        if qv.bytes[4] != TURBOQUANT_FORMAT_VERSION {
            return Err(quant_error(
                op,
                qv.level,
                format!(
                    "TQPR version mismatch: expected {TURBOQUANT_FORMAT_VERSION} got {}",
                    qv.bytes[4]
                ),
            ));
        }
        let header_level = decode_level(qv.bytes[5], op)?;
        if header_level != qv.level {
            return Err(quant_error(
                op,
                qv.level,
                "TQPR level does not match QuantizedVec",
            ));
        }
        if read_u16(&qv.bytes, 6) != FLAGS {
            return Err(quant_error(
                op,
                qv.level,
                "TQPR reserved flags must be zero",
            ));
        }
        let header_dim = read_u32(&qv.bytes, 8) as usize;
        if header_dim != qv.dim {
            return Err(quant_error(
                op,
                qv.level,
                "TQPR dimension does not match QuantizedVec",
            ));
        }
        let header_scalar_bits = read_u32(&qv.bytes, 12) as usize;
        let expected_scalar_bits = scalar_bits(qv.dim, qv.level)?;
        if header_scalar_bits != expected_scalar_bits {
            return Err(quant_error(
                op,
                qv.level,
                format!(
                    "TQPR scalar bit count mismatch: expected {expected_scalar_bits} got {header_scalar_bits}"
                ),
            ));
        }
        let header_qjl_bits = read_u32(&qv.bytes, 16) as usize;
        if header_qjl_bits != qv.dim {
            return Err(quant_error(
                op,
                qv.level,
                format!(
                    "TQPR QJL bit count mismatch: expected {} got {header_qjl_bits}",
                    qv.dim
                ),
            ));
        }
        let gamma = f32::from_bits(read_u32(&qv.bytes, 20));
        if !gamma.is_finite() || gamma.is_sign_negative() {
            return Err(quant_error(
                op,
                qv.level,
                "TQPR gamma must be finite, non-negative, and canonical +0.0 when zero",
            ));
        }
        let mut header_seed = [0u8; 32];
        header_seed.copy_from_slice(&qv.bytes[24..56]);
        if header_seed != qv.seed_id {
            return Err(quant_error(
                op,
                qv.level,
                "TQPR seed ID does not match QuantizedVec",
            ));
        }
        let scalar_len = expected_scalar_bits.div_ceil(8);
        let qjl_len = header_qjl_bits.div_ceil(8);
        let expected_len = BODY_OFFSET
            .checked_add(scalar_len)
            .and_then(|value| value.checked_add(qjl_len))
            .ok_or_else(|| quant_error(op, qv.level, "TQPR payload length overflow"))?;
        if qv.bytes.len() != expected_len {
            return Err(quant_error(
                op,
                qv.level,
                format!(
                    "TQPR length mismatch: expected {expected_len} got {}",
                    qv.bytes.len()
                ),
            ));
        }
        let scalar_end = BODY_OFFSET + scalar_len;
        let scalar = &qv.bytes[BODY_OFFSET..scalar_end];
        let qjl = &qv.bytes[scalar_end..];
        if qv.dim == 1 {
            let (_, high_bits) = scalar_widths(qv.level)?;
            let code = read_bits(scalar, 0, high_bits);
            let positive_code = 1_u8 << (high_bits - 1);
            if code != 0 && code != positive_code {
                return Err(quant_error(
                    op,
                    qv.level,
                    format!("dimension-one scalar code {code} is non-canonical"),
                ));
            }
        }
        if has_nonzero_padding(scalar, expected_scalar_bits) {
            return Err(quant_error(
                op,
                qv.level,
                "TQPR scalar bitstream has non-zero padding",
            ));
        }
        if has_nonzero_padding(qjl, header_qjl_bits) {
            return Err(quant_error(
                op,
                qv.level,
                "TQPR QJL bitstream has non-zero padding",
            ));
        }
        let expected_digest = payload_digest(
            &qv.bytes[..HEADER_PREFIX_BYTES],
            &qv.bytes[BODY_OFFSET..],
            qv.scale,
        );
        if &qv.bytes[DIGEST_OFFSET..BODY_OFFSET] != expected_digest.as_slice() {
            return Err(quant_error(
                op,
                qv.level,
                "TQPR SHA-256 payload digest mismatch",
            ));
        }
        if qv.scale == 0.0
            && (gamma != 0.0
                || scalar.iter().any(|byte| *byte != 0)
                || qjl.iter().any(|byte| *byte != 0))
        {
            return Err(quant_error(
                op,
                qv.level,
                "zero source norm requires canonical all-zero scalar, QJL, and gamma state",
            ));
        }
        if gamma == 0.0 && qjl.iter().any(|byte| *byte != 0) {
            return Err(quant_error(
                op,
                qv.level,
                "zero residual norm requires canonical all-zero QJL signs",
            ));
        }
        Ok(Self {
            scalar,
            qjl,
            gamma,
            scalar_bits: expected_scalar_bits,
            qjl_bits: header_qjl_bits,
            payload_bytes: expected_len,
            dim: qv.dim,
        })
    }

    fn storage(&self) -> TurboQuantStorage {
        let data_bits = self.scalar_bits + self.qjl_bits;
        TurboQuantStorage {
            data_bits,
            scalar_bits: self.scalar_bits,
            qjl_bits: self.qjl_bits,
            format_header_bytes: TURBOQUANT_FORMAT_HEADER_BYTES,
            payload_bytes: self.payload_bytes,
            logical_bits_per_channel: data_bits as f64 / self.dim as f64,
        }
    }
}

fn build_payload(
    level: QuantLevel,
    dim: usize,
    seed_id: SeedId,
    source_norm: f32,
    scalar_bit_count: usize,
    scalar: &[u8],
    qjl: &QjlResidual,
) -> Result<Vec<u8>> {
    build_payload_with_contract(
        TURBOQUANT_FORMAT_VERSION,
        DIGEST_DOMAIN,
        level,
        dim,
        seed_id,
        source_norm,
        scalar_bit_count,
        scalar,
        qjl,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_payload_with_contract(
    format_version: u8,
    digest_domain: &[u8],
    level: QuantLevel,
    dim: usize,
    seed_id: SeedId,
    source_norm: f32,
    scalar_bit_count: usize,
    scalar: &[u8],
    qjl: &QjlResidual,
) -> Result<Vec<u8>> {
    if !source_norm.is_finite() || source_norm.is_sign_negative() {
        return Err(quant_error(
            "build_payload",
            level,
            "source norm must be finite, non-negative, and canonical +0.0 when zero",
        ));
    }
    if scalar.len() != scalar_bit_count.div_ceil(8) || qjl.bits.len() != bitstream_len(dim) {
        return Err(quant_error(
            "build_payload",
            level,
            "internal scalar or QJL bitstream length mismatch",
        ));
    }
    if !qjl.gamma.is_finite() || qjl.gamma.is_sign_negative() {
        return Err(quant_error(
            "build_payload",
            level,
            "gamma must be finite, non-negative, and canonical +0.0 when zero",
        ));
    }
    let dim_u32 = u32::try_from(dim).map_err(|_| {
        quant_error(
            "build_payload",
            level,
            "dimension cannot be represented as u32",
        )
    })?;
    let scalar_bits_u32 = u32::try_from(scalar_bit_count).map_err(|_| {
        quant_error(
            "build_payload",
            level,
            "scalar bit count cannot be represented as u32",
        )
    })?;
    let qjl_bits_u32 = u32::try_from(dim).map_err(|_| {
        quant_error(
            "build_payload",
            level,
            "QJL bit count cannot be represented as u32",
        )
    })?;
    let payload_len = BODY_OFFSET
        .checked_add(scalar.len())
        .and_then(|value| value.checked_add(qjl.bits.len()))
        .ok_or_else(|| quant_error("build_payload", level, "payload length overflow"))?;
    let mut bytes = Vec::with_capacity(payload_len);
    bytes.extend_from_slice(MAGIC);
    bytes.push(format_version);
    bytes.push(encode_level(level)?);
    bytes.extend_from_slice(&FLAGS.to_le_bytes());
    bytes.extend_from_slice(&dim_u32.to_le_bytes());
    bytes.extend_from_slice(&scalar_bits_u32.to_le_bytes());
    bytes.extend_from_slice(&qjl_bits_u32.to_le_bytes());
    bytes.extend_from_slice(&qjl.gamma.to_le_bytes());
    bytes.extend_from_slice(&seed_id);
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(scalar);
    bytes.extend_from_slice(&qjl.bits);
    let digest = payload_digest_with_domain(
        digest_domain,
        &bytes[..HEADER_PREFIX_BYTES],
        &bytes[BODY_OFFSET..],
        source_norm,
    );
    bytes[DIGEST_OFFSET..BODY_OFFSET].copy_from_slice(&digest);
    Ok(bytes)
}

fn geometry_id(
    seed: &RotationSeed,
    level: QuantLevel,
    rotation: &HaarRotation,
    projection: &GaussianProjection,
    low_codebook: &LloydMaxCodebook,
    high_codebook: &LloydMaxCodebook,
) -> SeedId {
    let mut hasher = Sha256::new();
    hasher.update(GEOMETRY_DOMAIN);
    hasher.update([TURBOQUANT_FORMAT_VERSION, encode_level_code(level)]);
    hasher.update((seed.dim as u64).to_le_bytes());
    hasher.update(seed.id);
    let (factor_starts, factors, column_signs) = rotation.geometry_parts();
    hasher.update((factor_starts.len() as u64).to_le_bytes());
    for offset in factor_starts {
        hasher.update((*offset as u64).to_le_bytes());
    }
    hash_f32_slice(&mut hasher, factors);
    hash_f32_slice(&mut hasher, column_signs);
    hash_f32_slice(&mut hasher, projection.values());
    hash_f32_slice(&mut hasher, low_codebook.centroids());
    hash_f32_slice(&mut hasher, high_codebook.centroids());
    hasher.finalize().into()
}

fn hash_f32_slice(hasher: &mut Sha256, values: &[f32]) {
    hasher.update((values.len() as u64).to_le_bytes());
    for value in values {
        hasher.update(value.to_bits().to_le_bytes());
    }
}

const fn encode_level_code(level: QuantLevel) -> u8 {
    match level {
        QuantLevel::Bits2p5 => BITS2P5_LEVEL_CODE,
        QuantLevel::Bits3p5 => BITS3P5_LEVEL_CODE,
        _ => 0,
    }
}

fn scalar_widths(level: QuantLevel) -> Result<(usize, usize)> {
    match level {
        QuantLevel::Bits2p5 => Ok((1, 2)),
        QuantLevel::Bits3p5 => Ok((2, 3)),
        _ => Err(quant_error(
            "scalar_widths",
            level,
            "TurboQuant supports only Bits2p5 and Bits3p5",
        )),
    }
}

fn scalar_bits(dim: usize, level: QuantLevel) -> Result<usize> {
    let (low, _) = scalar_widths(level)?;
    dim.checked_mul(low)
        .and_then(|base| base.checked_add(dim.div_ceil(2)))
        .ok_or_else(|| quant_error("scalar_bits", level, "scalar bit count overflow"))
}

fn validate_level(level: QuantLevel, op: &str) -> Result<()> {
    if matches!(level, QuantLevel::Bits2p5 | QuantLevel::Bits3p5) {
        return Ok(());
    }
    Err(quant_error(
        op,
        level,
        "TurboQuant supports only Bits2p5 and Bits3p5",
    ))
}

fn validate_raw(query: &[f32], dim: usize, op: &str, level: QuantLevel) -> Result<()> {
    if query.len() != dim {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![dim],
            got: vec![query.len()],
            remediation: "Use vectors with the TurboQuant codec dimension".to_string(),
        });
    }
    if let Some(index) = query.iter().position(|value| !value.is_finite()) {
        return Err(quant_error(
            op,
            level,
            format!("non-finite coefficient at index {index}"),
        ));
    }
    Ok(())
}

fn encode_level(level: QuantLevel) -> Result<u8> {
    match level {
        QuantLevel::Bits2p5 => Ok(BITS2P5_LEVEL_CODE),
        QuantLevel::Bits3p5 => Ok(BITS3P5_LEVEL_CODE),
        _ => Err(quant_error(
            "encode_level",
            level,
            "unsupported TurboQuant level",
        )),
    }
}

fn decode_level(value: u8, op: &str) -> Result<QuantLevel> {
    match value {
        BITS2P5_LEVEL_CODE => Ok(QuantLevel::Bits2p5),
        BITS3P5_LEVEL_CODE => Ok(QuantLevel::Bits3p5),
        _ => Err(ForgeError::QuantError {
            op: format!("turboquant_{op}"),
            level: format!("unknown({value})"),
            detail: format!("unknown TQPR level code {value}"),
            remediation: REMEDIATION.to_string(),
        }),
    }
}

fn write_bits(bytes: &mut [u8], offset: usize, width: usize, value: u8) {
    for bit in 0..width {
        if value & (1 << bit) != 0 {
            let absolute = offset + bit;
            bytes[absolute / 8] |= 1 << (absolute % 8);
        }
    }
}

fn read_bits(bytes: &[u8], offset: usize, width: usize) -> u8 {
    let mut value = 0u8;
    for bit in 0..width {
        let absolute = offset + bit;
        if bytes[absolute / 8] & (1 << (absolute % 8)) != 0 {
            value |= 1 << bit;
        }
    }
    value
}

fn read_code_pair(bytes: &[u8], offset: usize, high_width: usize, low_width: usize) -> (u8, u8) {
    let byte_offset = offset / 8;
    let shift = offset % 8;
    let low_byte = u16::from(bytes.get(byte_offset).copied().unwrap_or(0));
    let high_byte = u16::from(bytes.get(byte_offset + 1).copied().unwrap_or(0));
    let packed = (low_byte | (high_byte << 8)) >> shift;
    let high_mask = (1_u16 << high_width) - 1;
    let low_mask = (1_u16 << low_width) - 1;
    (
        (packed & high_mask) as u8,
        ((packed >> high_width) & low_mask) as u8,
    )
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn payload_digest(prefix: &[u8], body: &[u8], source_norm: f32) -> [u8; 32] {
    payload_digest_with_domain(DIGEST_DOMAIN, prefix, body, source_norm)
}

fn payload_digest_with_domain(
    domain: &[u8],
    prefix: &[u8],
    body: &[u8],
    source_norm: f32,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((prefix.len() as u64).to_le_bytes());
    hasher.update(prefix);
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
    hasher.update(source_norm.to_bits().to_le_bytes());
    hasher.finalize().into()
}

fn finite_f32(value: f64, op: &str, level: QuantLevel) -> Result<f32> {
    if !value.is_finite() || value.abs() > f64::from(f32::MAX) {
        return Err(quant_error(
            op,
            level,
            "dot estimate cannot be represented as finite f32",
        ));
    }
    Ok(value as f32)
}

fn quant_error(op: &str, level: QuantLevel, detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: format!("turboquant_{op}"),
        level: level.to_string(),
        detail: detail.into(),
        remediation: REMEDIATION.to_string(),
    }
}
