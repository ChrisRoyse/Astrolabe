use crate::mxfp4::{
    MXFP4_BLOCK_BYTES, MXFP4_BLOCK_SIZE, MXFP4_MAX_DIM, MXFP4_PACKED_BYTES, MxFp4Block,
    decode_e2m1, decode_e8m0, decode_mxfp4, encode_mxfp4, nibble_at, validate_mxfp4_block,
    validate_mxfp4_blocks,
};
use crate::mxfp8::{
    MXFP8_BLOCK_BYTES, MXFP8_BLOCK_SIZE, MXFP8_MAX_DIM, MxFp8Block, decode_e4m3, decode_mxfp8,
    encode_mxfp8, validate_mxfp8_block, validate_mxfp8_blocks,
};
use crate::quant::{QuantLevel, QuantizedVec, Quantizer, SeedId};
use crate::{ForgeError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MXFP_FORMAT_VERSION: u8 = 1;
pub const MXFP_FORMAT_HEADER_BYTES: usize = 56;
pub const MXFP_BODY_ALIGNMENT_BYTES: usize = 1;

const MXFP_MAGIC: &[u8; 4] = b"MXOC";
const MXFP_PREFIX_BYTES: usize = 24;
const MXFP_DIGEST_OFFSET: usize = MXFP_PREFIX_BYTES;
const MXFP_DIGEST_DOMAIN: &[u8] = b"calyx/forge/ocp-mx/payload/v1\0";
const MXFP_FLAGS: u8 = 0b0000_0111; // RNE | saturate | little-endian header fields.
const MXFP_SCALE_E8M0: u8 = 1;
const MXFP4_E2M1: u8 = 1;
const MXFP8_E4M3: u8 = 2;
const ZERO_SEED: SeedId = [0; 32];
const MXFP_REMEDIATION: &str = "Re-encode with the OCP MX v1 codec for the exact dimension; legacy unversioned MX bytes are incompatible and must be explicitly rewritten";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MxElement {
    E2M1,
    E4M3,
}

impl MxElement {
    const fn code(self) -> u8 {
        match self {
            Self::E2M1 => MXFP4_E2M1,
            Self::E4M3 => MXFP8_E4M3,
        }
    }

    const fn block_bytes(self) -> usize {
        match self {
            Self::E2M1 => MXFP4_BLOCK_BYTES,
            Self::E4M3 => MXFP8_BLOCK_BYTES,
        }
    }

    const fn max_dim(self) -> usize {
        match self {
            Self::E2M1 => MXFP4_MAX_DIM,
            Self::E4M3 => MXFP8_MAX_DIM,
        }
    }

    const fn level(self) -> QuantLevel {
        match self {
            Self::E2M1 => QuantLevel::Bits4Fp,
            Self::E4M3 => QuantLevel::Bits8Fp,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::E2M1 => "OcpMxFp4E2M1",
            Self::E4M3 => "OcpMxFp8E4M3",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MxFpStorage {
    pub format_header_bytes: usize,
    pub element_bytes: usize,
    pub scale_bytes: usize,
    pub total_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct MxFp4Codec {
    dim: usize,
}

#[derive(Clone, Debug)]
pub struct MxFp8Codec {
    dim: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssayQuantSafety {
    pub baseline_bits: f32,
    pub quantized_bits: f32,
    pub cosine: f32,
    pub far_delta: f32,
}

impl AssayQuantSafety {
    pub const MIN_RETAINED_FRACTION: f32 = 0.95;
    pub const MIN_COSINE: f32 = 0.99;
    pub const MAX_FAR_DELTA: f32 = 0.01;

    pub fn passes(&self) -> bool {
        let retained = if self.baseline_bits <= 0.0 {
            self.quantized_bits >= 0.0
        } else {
            self.quantized_bits / self.baseline_bits >= Self::MIN_RETAINED_FRACTION
        };
        retained
            && self.cosine >= Self::MIN_COSINE
            && self.far_delta <= Self::MAX_FAR_DELTA
            && self.values_are_finite()
    }

    fn values_are_finite(&self) -> bool {
        self.baseline_bits.is_finite()
            && self.quantized_bits.is_finite()
            && self.cosine.is_finite()
            && self.far_delta.is_finite()
    }
}

impl MxFp4Codec {
    pub fn new(dim: usize) -> Self {
        Self { dim }
    }

    pub fn encode_assay_checked(
        &self,
        slot_id: &str,
        vec: &[f32],
        safety: &AssayQuantSafety,
        assay_attestation_id: SeedId,
    ) -> Result<QuantizedVec> {
        validate_input(vec, self.dim, MxElement::E2M1)?;
        if slot_id.trim().is_empty() || !safety.passes() || assay_attestation_id == ZERO_SEED {
            return Err(ForgeError::QuantIntelligenceLoss {
                slot: slot_id.to_string(),
                detail: "MXFP4 requires current persisted Assay safety evidence bound to the real slot, lens, dimension, and vault sequence".to_string(),
                remediation: "Persist and read back passing Assay evidence, then encode the same frozen slot context; do not substitute a placeholder identity or fallback codec".to_string(),
            });
        }
        let blocks = encode_mxfp4(vec)?;
        let bytes = serialize_mxfp4(&blocks, self.dim)?;
        Ok(quantized(
            MxElement::E2M1,
            self.dim,
            bytes,
            assay_attestation_id,
        ))
    }

    pub fn inspect(&self, qv: &QuantizedVec) -> Result<MxFpStorage> {
        validate_outer(qv, self.dim, MxElement::E2M1)?;
        let payload = parse_payload(&qv.bytes, MxElement::E2M1, self.dim)?;
        validate_mxfp4_body(payload.body, self.dim)?;
        Ok(payload.storage)
    }

    pub fn dot_and_norm(&self, query: &[f32], qv: &QuantizedVec) -> Result<(f32, f64)> {
        validate_input(query, self.dim, MxElement::E2M1)?;
        self.inspect(qv)?;
        let body = &qv.bytes[MXFP_FORMAT_HEADER_BYTES..];
        let mut dot = 0.0_f32;
        let mut norm_sq = 0.0_f64;
        let mut coordinate = 0_usize;
        for chunk in body.chunks_exact(MXFP4_BLOCK_BYTES) {
            let mut codes = [0_u8; MXFP4_PACKED_BYTES];
            codes.copy_from_slice(&chunk[..MXFP4_PACKED_BYTES]);
            let scale = decode_e8m0(chunk[MXFP4_PACKED_BYTES])?;
            let valid = (self.dim - coordinate).min(MXFP4_BLOCK_SIZE);
            for lane in 0..valid {
                let value = decode_e2m1(nibble_at(&codes, lane)) * scale;
                dot = query[coordinate].mul_add(value, dot);
                norm_sq += f64::from(value) * f64::from(value);
                coordinate += 1;
            }
        }
        validate_dot_norm(dot, norm_sq, MxElement::E2M1)?;
        Ok((dot, norm_sq))
    }

    fn decode_inner(&self, qv: &QuantizedVec) -> Result<Vec<f32>> {
        self.inspect(qv)?;
        decode_mxfp4(
            &deserialize_mxfp4(&qv.bytes[MXFP_FORMAT_HEADER_BYTES..]),
            self.dim,
        )
    }
}

impl MxFp8Codec {
    pub fn new(dim: usize) -> Self {
        Self { dim }
    }

    pub fn inspect(&self, qv: &QuantizedVec) -> Result<MxFpStorage> {
        validate_outer(qv, self.dim, MxElement::E4M3)?;
        let payload = parse_payload(&qv.bytes, MxElement::E4M3, self.dim)?;
        validate_mxfp8_body(payload.body, self.dim)?;
        Ok(payload.storage)
    }

    pub fn dot_and_norm(&self, query: &[f32], qv: &QuantizedVec) -> Result<(f32, f64)> {
        validate_input(query, self.dim, MxElement::E4M3)?;
        self.inspect(qv)?;
        let body = &qv.bytes[MXFP_FORMAT_HEADER_BYTES..];
        let mut dot = 0.0_f32;
        let mut norm_sq = 0.0_f64;
        let mut coordinate = 0_usize;
        for chunk in body.chunks_exact(MXFP8_BLOCK_BYTES) {
            let scale = decode_e8m0(chunk[MXFP8_BLOCK_SIZE])?;
            let valid = (self.dim - coordinate).min(MXFP8_BLOCK_SIZE);
            for code in &chunk[..valid] {
                let value = decode_e4m3(*code)? * scale;
                dot = query[coordinate].mul_add(value, dot);
                norm_sq += f64::from(value) * f64::from(value);
                coordinate += 1;
            }
        }
        validate_dot_norm(dot, norm_sq, MxElement::E4M3)?;
        Ok((dot, norm_sq))
    }

    fn decode_inner(&self, qv: &QuantizedVec) -> Result<Vec<f32>> {
        self.inspect(qv)?;
        decode_mxfp8(
            &deserialize_mxfp8(&qv.bytes[MXFP_FORMAT_HEADER_BYTES..]),
            self.dim,
        )
    }
}

impl Quantizer for MxFp4Codec {
    fn encode(&self, _vec: &[f32]) -> Result<QuantizedVec> {
        Err(ForgeError::QuantIntelligenceLoss {
            slot: "unbound".to_string(),
            detail: "generic MXFP4 encode has no attested slot identity or persisted Assay evidence".to_string(),
            remediation: "Use encode_assay_checked with evidence read from the Assay source of truth for the exact frozen slot; do not use a placeholder identity".to_string(),
        })
    }

    fn decode(&self, qv: &QuantizedVec) -> Result<Vec<f32>> {
        self.decode_inner(qv)
    }

    fn dot_estimate(&self, query: &[f32], candidate: &QuantizedVec) -> Result<f32> {
        self.dot_and_norm(query, candidate).map(|(dot, _)| dot)
    }

    fn level(&self) -> QuantLevel {
        QuantLevel::Bits4Fp
    }

    fn dim(&self) -> usize {
        self.dim
    }
}

impl Quantizer for MxFp8Codec {
    fn encode(&self, vec: &[f32]) -> Result<QuantizedVec> {
        validate_input(vec, self.dim, MxElement::E4M3)?;
        let blocks = encode_mxfp8(vec)?;
        let bytes = serialize_mxfp8(&blocks, self.dim)?;
        Ok(quantized(MxElement::E4M3, self.dim, bytes, ZERO_SEED))
    }

    fn decode(&self, qv: &QuantizedVec) -> Result<Vec<f32>> {
        self.decode_inner(qv)
    }

    fn dot_estimate(&self, query: &[f32], candidate: &QuantizedVec) -> Result<f32> {
        self.dot_and_norm(query, candidate).map(|(dot, _)| dot)
    }

    fn level(&self) -> QuantLevel {
        QuantLevel::Bits8Fp
    }

    fn dim(&self) -> usize {
        self.dim
    }
}

pub fn mxfp_payload_len(level: QuantLevel, dim: usize) -> Result<usize> {
    let element = element_for_level(level)?;
    validate_dim(dim, element)?;
    let body = dim
        .div_ceil(MXFP4_BLOCK_SIZE)
        .checked_mul(element.block_bytes())
        .ok_or_else(|| quant_error("payload_layout", element, "payload length overflow"))?;
    MXFP_FORMAT_HEADER_BYTES
        .checked_add(body)
        .ok_or_else(|| quant_error("payload_layout", element, "payload length overflow"))
}

fn serialize_mxfp4(blocks: &[MxFp4Block], dim: usize) -> Result<Vec<u8>> {
    validate_mxfp4_blocks(blocks, dim)?;
    let mut body = Vec::with_capacity(blocks.len() * MXFP4_BLOCK_BYTES);
    for block in blocks {
        body.extend_from_slice(&block.codes);
        body.push(block.scale_e8m0);
    }
    serialize_payload(MxElement::E2M1, dim, &body)
}

fn serialize_mxfp8(blocks: &[MxFp8Block], dim: usize) -> Result<Vec<u8>> {
    validate_mxfp8_blocks(blocks, dim)?;
    let mut body = Vec::with_capacity(blocks.len() * MXFP8_BLOCK_BYTES);
    for block in blocks {
        body.extend_from_slice(&block.codes);
        body.push(block.scale_e8m0);
    }
    serialize_payload(MxElement::E4M3, dim, &body)
}

fn serialize_payload(element: MxElement, dim: usize, body: &[u8]) -> Result<Vec<u8>> {
    let expected = mxfp_payload_len(element.level(), dim)? - MXFP_FORMAT_HEADER_BYTES;
    if body.len() != expected {
        return Err(quant_error(
            "serialize",
            element,
            format!(
                "body length mismatch: expected {expected} got {}",
                body.len()
            ),
        ));
    }
    let block_count = dim.div_ceil(MXFP4_BLOCK_SIZE);
    let mut prefix = Vec::with_capacity(MXFP_PREFIX_BYTES);
    prefix.extend_from_slice(MXFP_MAGIC);
    prefix.push(MXFP_FORMAT_VERSION);
    prefix.push(element.code());
    prefix.push(MXFP4_BLOCK_SIZE as u8);
    prefix.push(MXFP_FLAGS);
    prefix.extend_from_slice(&u32_field(dim, "dimension", element)?.to_le_bytes());
    prefix.extend_from_slice(&u32_field(block_count, "block count", element)?.to_le_bytes());
    prefix.extend_from_slice(&u32_field(body.len(), "body length", element)?.to_le_bytes());
    prefix.extend_from_slice(&(element.block_bytes() as u16).to_le_bytes());
    prefix.push(MXFP_SCALE_E8M0);
    prefix.push(0);
    debug_assert_eq!(prefix.len(), MXFP_PREFIX_BYTES);
    let digest = payload_digest(&prefix, body);
    let mut bytes = Vec::with_capacity(MXFP_FORMAT_HEADER_BYTES + body.len());
    bytes.extend_from_slice(&prefix);
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(body);
    Ok(bytes)
}

struct ParsedPayload<'a> {
    body: &'a [u8],
    storage: MxFpStorage,
}

fn parse_payload<'a>(bytes: &'a [u8], element: MxElement, dim: usize) -> Result<ParsedPayload<'a>> {
    let exact_len = mxfp_payload_len(element.level(), dim)?;
    if bytes.len() != exact_len {
        return Err(quant_error(
            "inspect",
            element,
            format!(
                "payload length mismatch: expected {exact_len} got {}",
                bytes.len()
            ),
        ));
    }
    if &bytes[..4] != MXFP_MAGIC {
        return Err(quant_error(
            "inspect",
            element,
            "missing OCP MX payload magic; legacy unversioned MX bytes are refused",
        ));
    }
    if bytes[4] != MXFP_FORMAT_VERSION
        || bytes[5] != element.code()
        || bytes[6] != MXFP4_BLOCK_SIZE as u8
        || bytes[7] != MXFP_FLAGS
    {
        return Err(quant_error(
            "inspect",
            element,
            format!(
                "format contract mismatch: version={} element={} block={} flags=0x{:02x}",
                bytes[4], bytes[5], bytes[6], bytes[7]
            ),
        ));
    }
    let header_dim = read_u32(bytes, 8, element, "dimension")? as usize;
    let blocks = read_u32(bytes, 12, element, "block count")? as usize;
    let body_len = read_u32(bytes, 16, element, "body length")? as usize;
    let block_bytes = read_u16(bytes, 20, element, "block bytes")? as usize;
    if bytes[22] != MXFP_SCALE_E8M0 || bytes[23] != 0 {
        return Err(quant_error(
            "inspect",
            element,
            format!(
                "scale/reserved contract mismatch: scale={} reserved={}",
                bytes[22], bytes[23]
            ),
        ));
    }
    let expected_blocks = dim.div_ceil(MXFP4_BLOCK_SIZE);
    let expected_body = expected_blocks * element.block_bytes();
    if header_dim != dim
        || blocks != expected_blocks
        || body_len != expected_body
        || block_bytes != element.block_bytes()
    {
        return Err(quant_error(
            "inspect",
            element,
            format!(
                "geometry mismatch: dim={header_dim}/{dim} blocks={blocks}/{expected_blocks} body={body_len}/{expected_body} block_bytes={block_bytes}/{}",
                element.block_bytes()
            ),
        ));
    }
    let body = &bytes[MXFP_FORMAT_HEADER_BYTES..];
    let computed = payload_digest(&bytes[..MXFP_PREFIX_BYTES], body);
    if bytes[MXFP_DIGEST_OFFSET..MXFP_FORMAT_HEADER_BYTES] != computed {
        return Err(quant_error(
            "inspect",
            element,
            format!(
                "payload SHA-256 mismatch: recorded={} computed={}",
                hex(&bytes[MXFP_DIGEST_OFFSET..MXFP_FORMAT_HEADER_BYTES]),
                hex(&computed)
            ),
        ));
    }
    let scale_bytes = expected_blocks;
    let element_bytes = expected_body - scale_bytes;
    Ok(ParsedPayload {
        body,
        storage: MxFpStorage {
            format_header_bytes: MXFP_FORMAT_HEADER_BYTES,
            element_bytes,
            scale_bytes,
            total_bytes: bytes.len(),
        },
    })
}

fn validate_mxfp4_body(body: &[u8], dim: usize) -> Result<()> {
    let block_count = dim.div_ceil(MXFP4_BLOCK_SIZE);
    for (index, chunk) in body.chunks_exact(MXFP4_BLOCK_BYTES).enumerate() {
        let mut codes = [0_u8; MXFP4_PACKED_BYTES];
        codes.copy_from_slice(&chunk[..MXFP4_PACKED_BYTES]);
        let block = MxFp4Block {
            codes,
            scale_e8m0: chunk[MXFP4_PACKED_BYTES],
        };
        let valid = (dim - index * MXFP4_BLOCK_SIZE).min(MXFP4_BLOCK_SIZE);
        validate_mxfp4_block(&block, valid, index + 1 == block_count)?;
    }
    Ok(())
}

fn validate_mxfp8_body(body: &[u8], dim: usize) -> Result<()> {
    let block_count = dim.div_ceil(MXFP8_BLOCK_SIZE);
    for (index, chunk) in body.chunks_exact(MXFP8_BLOCK_BYTES).enumerate() {
        let mut codes = [0_u8; MXFP8_BLOCK_SIZE];
        codes.copy_from_slice(&chunk[..MXFP8_BLOCK_SIZE]);
        let block = MxFp8Block {
            codes,
            scale_e8m0: chunk[MXFP8_BLOCK_SIZE],
        };
        let valid = (dim - index * MXFP8_BLOCK_SIZE).min(MXFP8_BLOCK_SIZE);
        validate_mxfp8_block(&block, valid, index + 1 == block_count)?;
    }
    Ok(())
}

fn deserialize_mxfp4(body: &[u8]) -> Vec<MxFp4Block> {
    body.chunks_exact(MXFP4_BLOCK_BYTES)
        .map(|chunk| {
            let mut codes = [0_u8; MXFP4_PACKED_BYTES];
            codes.copy_from_slice(&chunk[..MXFP4_PACKED_BYTES]);
            MxFp4Block {
                codes,
                scale_e8m0: chunk[MXFP4_PACKED_BYTES],
            }
        })
        .collect()
}

fn deserialize_mxfp8(body: &[u8]) -> Vec<MxFp8Block> {
    body.chunks_exact(MXFP8_BLOCK_BYTES)
        .map(|chunk| {
            let mut codes = [0_u8; MXFP8_BLOCK_SIZE];
            codes.copy_from_slice(&chunk[..MXFP8_BLOCK_SIZE]);
            MxFp8Block {
                codes,
                scale_e8m0: chunk[MXFP8_BLOCK_SIZE],
            }
        })
        .collect()
}

fn validate_outer(qv: &QuantizedVec, dim: usize, element: MxElement) -> Result<()> {
    if qv.level != element.level() {
        return Err(quant_error(
            "inspect",
            element,
            format!(
                "quant level mismatch: expected {:?} got {:?}",
                element.level(),
                qv.level
            ),
        ));
    }
    if qv.dim != dim {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![dim],
            got: vec![qv.dim],
            remediation: MXFP_REMEDIATION.to_string(),
        });
    }
    let identity_is_valid = match element {
        MxElement::E2M1 => qv.seed_id != ZERO_SEED,
        MxElement::E4M3 => qv.seed_id == ZERO_SEED,
    };
    if qv.scale.to_bits() != 0 || !identity_is_valid {
        return Err(quant_error(
            "inspect",
            element,
            "MX payload requires canonical +0.0 outer scale; MXFP4 requires a non-zero persisted Assay attestation identity and MXFP8 requires a zero seed identity",
        ));
    }
    Ok(())
}

fn validate_input(values: &[f32], dim: usize, element: MxElement) -> Result<()> {
    validate_dim(dim, element)?;
    if values.len() != dim {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![dim],
            got: vec![values.len()],
            remediation: MXFP_REMEDIATION.to_string(),
        });
    }
    if let Some(index) = values.iter().position(|value| !value.is_finite()) {
        return Err(quant_error(
            "encode_or_score",
            element,
            format!("non-finite coefficient at index {index}"),
        ));
    }
    Ok(())
}

fn validate_dim(dim: usize, element: MxElement) -> Result<()> {
    if (1..=element.max_dim()).contains(&dim) {
        Ok(())
    } else {
        Err(quant_error(
            "dimension",
            element,
            format!("dimension must be in 1..={}, got {dim}", element.max_dim()),
        ))
    }
}

fn validate_dot_norm(dot: f32, norm_sq: f64, element: MxElement) -> Result<()> {
    if dot.is_finite() && norm_sq.is_finite() {
        Ok(())
    } else {
        Err(quant_error(
            "packed_dot",
            element,
            "packed dot or candidate norm overflowed",
        ))
    }
}

fn quantized(element: MxElement, dim: usize, bytes: Vec<u8>, seed_id: SeedId) -> QuantizedVec {
    QuantizedVec {
        level: element.level(),
        dim,
        bytes,
        scale: 0.0,
        seed_id,
    }
}

fn element_for_level(level: QuantLevel) -> Result<MxElement> {
    match level {
        QuantLevel::Bits4Fp => Ok(MxElement::E2M1),
        QuantLevel::Bits8Fp => Ok(MxElement::E4M3),
        _ => Err(ForgeError::QuantError {
            op: "payload_layout".to_string(),
            level: level.to_string(),
            detail: "OCP MX payload supports only Bits4Fp/E2M1 and Bits8Fp/E4M3".to_string(),
            remediation: MXFP_REMEDIATION.to_string(),
        }),
    }
}

fn u32_field(value: usize, field: &str, element: MxElement) -> Result<u32> {
    u32::try_from(value).map_err(|_| {
        quant_error(
            "serialize",
            element,
            format!("{field} exceeds the u32 format limit"),
        )
    })
}

fn read_u32(bytes: &[u8], offset: usize, element: MxElement, field: &str) -> Result<u32> {
    let chunk = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| quant_error("inspect", element, format!("payload is missing {field}")))?;
    Ok(u32::from_le_bytes(chunk.try_into().unwrap()))
}

fn read_u16(bytes: &[u8], offset: usize, element: MxElement, field: &str) -> Result<u16> {
    let chunk = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| quant_error("inspect", element, format!("payload is missing {field}")))?;
    Ok(u16::from_le_bytes(chunk.try_into().unwrap()))
}

fn payload_digest(prefix: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MXFP_DIGEST_DOMAIN);
    hasher.update((prefix.len() as u64).to_le_bytes());
    hasher.update(prefix);
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

fn quant_error(op: &str, element: MxElement, detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: op.to_string(),
        level: element.name().to_string(),
        detail: detail.into(),
        remediation: MXFP_REMEDIATION.to_string(),
    }
}
