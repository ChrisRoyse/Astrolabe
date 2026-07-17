use std::fmt;

use sha2::{Digest, Sha256};

use crate::quant::codebook::LloydMaxCodebook;
use crate::quant::qjl::{
    GaussianProjection, QjlResidual, bitstream_len, has_nonzero_padding,
};
use crate::quant::rotation::HaarRotation;
use crate::quant::{QuantLevel, QuantizedVec, Quantizer, RotationSeed, SeedId};
use crate::{ForgeError, Result};

/// Maximum geometry dimension admitted by the dense Gaussian product format.
pub const TURBOQUANT_MAX_DIM: usize = 4096;
/// Current persisted `TQPR` product-format version.
pub const TURBOQUANT_FORMAT_VERSION: u8 = 1;
/// Fixed bytes preceding the scalar and QJL data bitstreams.
pub const TURBOQUANT_FORMAT_HEADER_BYTES: usize = 88;

const MAGIC: &[u8; 4] = b"TQPR";
const FLAGS: u16 = 0;
const DIGEST_DOMAIN: &[u8] = b"calyx/turboquant/tqpr/payload/v1\0";
const HEADER_PREFIX_BYTES: usize = 56;
const DIGEST_OFFSET: usize = HEADER_PREFIX_BYTES;
const BODY_OFFSET: usize = TURBOQUANT_FORMAT_HEADER_BYTES;
const BITS2P5_LEVEL_CODE: u8 = 1;
const BITS3P5_LEVEL_CODE: u8 = 2;
const REMEDIATION: &str = "Use a canonical TQPR v1 payload, matching current-version seed, supported level, and finite vector with dimension 1..=4096";

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

/// Paper-conformant TurboQuant product codec with asymmetric QJL scoring.
pub struct TurboQuantCodec {
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
            .finish_non_exhaustive()
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
        let projection = GaussianProjection::new(&seed)?;
        let low_codebook = LloydMaxCodebook::new(seed.dim, low_bits, level)?;
        let high_codebook = LloydMaxCodebook::new(seed.dim, high_bits, level)?;
        Ok(Self {
            seed,
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

    /// Validates storage structure and verifies this codec owns the payload geometry.
    pub fn storage(&self, qv: &QuantizedVec) -> Result<TurboQuantStorage> {
        let parsed = self.parse_owned(qv, "storage")?;
        Ok(parsed.storage())
    }

    /// Applies the shared Haar rotation and Gaussian projection once per raw query.
    pub fn prepare_query(&self, query: &[f32]) -> Result<TurboQuantPreparedQuery> {
        validate_raw(query, self.seed.dim, "prepare_query", self.level)?;
        let mut rotated = query.to_vec();
        self.rotation.apply(&mut rotated)?;
        let projected = self.projection.project(&rotated)?;
        Ok(TurboQuantPreparedQuery {
            dim: self.seed.dim,
            seed_id: self.seed.id,
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
        if query.dim != self.seed.dim || query.seed_id != self.seed.id {
            return Err(quant_error(
                "score_prepared",
                self.level,
                "prepared query was produced by different codec geometry",
            ));
        }
        let parsed = self.parse_owned(candidate, "score_prepared")?;
        if candidate.scale == 0.0 {
            return Ok(0.0);
        }
        let mut scalar_dot = 0.0_f64;
        let mut bit_offset = 0usize;
        for index in 0..self.seed.dim {
            let codebook = self.codebook_for_index(index);
            let code = read_bits(parsed.scalar, bit_offset, codebook.bits());
            bit_offset += codebook.bits();
            let centroid = codebook.centroid(code).ok_or_else(|| {
                quant_error(
                    "score_prepared",
                    self.level,
                    format!("scalar code {code} is invalid at coordinate {index}"),
                )
            })?;
            scalar_dot += f64::from(query.rotated[index]) * f64::from(centroid);
        }
        let correction =
            self.projection
                .correction_parts(&query.projected, parsed.qjl, parsed.gamma)?;
        finite_f32(
            f64::from(candidate.scale) * scalar_dot + f64::from(correction),
            "score_prepared",
            self.level,
        )
    }

    fn parse_owned<'a>(&self, qv: &'a QuantizedVec, op: &str) -> Result<ParsedPayload<'a>> {
        let parsed = ParsedPayload::parse(qv, op)?;
        if qv.level != self.level || qv.dim != self.seed.dim || qv.seed_id != self.seed.id {
            return Err(quant_error(
                op,
                qv.level,
                format!(
                    "payload geometry mismatch: codec level={} dim={} seed={:02x?}",
                    self.level, self.seed.dim, self.seed.id
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
                self.seed.id,
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
                seed_id: self.seed.id,
            });
        }
        self.encode_nonzero(vec, source_norm)
    }

    fn decode(&self, qv: &QuantizedVec) -> Result<Vec<f32>> {
        let parsed = self.parse_owned(qv, "decode")?;
        if qv.scale == 0.0 {
            return Ok(vec![0.0; self.seed.dim]);
        }
        let mut scalar = Vec::with_capacity(self.seed.dim);
        let mut bit_offset = 0usize;
        for index in 0..self.seed.dim {
            let codebook = self.codebook_for_index(index);
            let code = read_bits(parsed.scalar, bit_offset, codebook.bits());
            bit_offset += codebook.bits();
            let centroid = codebook.centroid(code).ok_or_else(|| {
                quant_error(
                    "decode",
                    self.level,
                    format!("scalar code {code} is invalid at coordinate {index}"),
                )
            })?;
            scalar.push(qv.scale * centroid);
        }
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
                format!("dimension must be in 1..={TURBOQUANT_MAX_DIM}, got {}", qv.dim),
            ));
        }
        if !qv.scale.is_finite() || qv.scale < 0.0 {
            return Err(quant_error(op, qv.level, "source norm must be finite and non-negative"));
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
            return Err(quant_error(op, qv.level, "TQPR level does not match QuantizedVec"));
        }
        if read_u16(&qv.bytes, 6) != FLAGS {
            return Err(quant_error(op, qv.level, "TQPR reserved flags must be zero"));
        }
        let header_dim = read_u32(&qv.bytes, 8) as usize;
        if header_dim != qv.dim {
            return Err(quant_error(op, qv.level, "TQPR dimension does not match QuantizedVec"));
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
                format!("TQPR QJL bit count mismatch: expected {} got {header_qjl_bits}", qv.dim),
            ));
        }
        let gamma = f32::from_bits(read_u32(&qv.bytes, 20));
        if !gamma.is_finite() || gamma < 0.0 {
            return Err(quant_error(op, qv.level, "TQPR gamma must be finite and non-negative"));
        }
        let mut header_seed = [0u8; 32];
        header_seed.copy_from_slice(&qv.bytes[24..56]);
        if header_seed != qv.seed_id {
            return Err(quant_error(op, qv.level, "TQPR seed ID does not match QuantizedVec"));
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
                format!("TQPR length mismatch: expected {expected_len} got {}", qv.bytes.len()),
            ));
        }
        let scalar_end = BODY_OFFSET + scalar_len;
        let scalar = &qv.bytes[BODY_OFFSET..scalar_end];
        let qjl = &qv.bytes[scalar_end..];
        if has_nonzero_padding(scalar, expected_scalar_bits) {
            return Err(quant_error(op, qv.level, "TQPR scalar bitstream has non-zero padding"));
        }
        if has_nonzero_padding(qjl, header_qjl_bits) {
            return Err(quant_error(op, qv.level, "TQPR QJL bitstream has non-zero padding"));
        }
        let expected_digest = payload_digest(
            &qv.bytes[..HEADER_PREFIX_BYTES],
            &qv.bytes[BODY_OFFSET..],
            qv.scale,
        );
        if &qv.bytes[DIGEST_OFFSET..BODY_OFFSET] != expected_digest.as_slice() {
            return Err(quant_error(op, qv.level, "TQPR SHA-256 payload digest mismatch"));
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
    if !source_norm.is_finite() || source_norm < 0.0 {
        return Err(quant_error(
            "build_payload",
            level,
            "source norm must be finite and non-negative",
        ));
    }
    if scalar.len() != scalar_bit_count.div_ceil(8) || qjl.bits.len() != bitstream_len(dim) {
        return Err(quant_error(
            "build_payload",
            level,
            "internal scalar or QJL bitstream length mismatch",
        ));
    }
    if !qjl.gamma.is_finite() || qjl.gamma < 0.0 {
        return Err(quant_error(
            "build_payload",
            level,
            "gamma must be finite and non-negative",
        ));
    }
    let dim_u32 = u32::try_from(dim).map_err(|_| {
        quant_error("build_payload", level, "dimension cannot be represented as u32")
    })?;
    let scalar_bits_u32 = u32::try_from(scalar_bit_count).map_err(|_| {
        quant_error("build_payload", level, "scalar bit count cannot be represented as u32")
    })?;
    let qjl_bits_u32 = u32::try_from(dim).map_err(|_| {
        quant_error("build_payload", level, "QJL bit count cannot be represented as u32")
    })?;
    let payload_len = BODY_OFFSET
        .checked_add(scalar.len())
        .and_then(|value| value.checked_add(qjl.bits.len()))
        .ok_or_else(|| quant_error("build_payload", level, "payload length overflow"))?;
    let mut bytes = Vec::with_capacity(payload_len);
    bytes.extend_from_slice(MAGIC);
    bytes.push(TURBOQUANT_FORMAT_VERSION);
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
    let digest = payload_digest(
        &bytes[..HEADER_PREFIX_BYTES],
        &bytes[BODY_OFFSET..],
        source_norm,
    );
    bytes[DIGEST_OFFSET..BODY_OFFSET].copy_from_slice(&digest);
    Ok(bytes)
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
        _ => Err(quant_error(
            op,
            QuantLevel::Bits3p5,
            format!("unknown TQPR level code {value}"),
        )),
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
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
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
