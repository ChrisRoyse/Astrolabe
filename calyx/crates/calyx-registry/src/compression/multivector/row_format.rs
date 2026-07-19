use calyx_aster::cf::COMPRESSED_SLOT_VALUE_TAG;
use calyx_core::{CxId, LensId, Result};

use super::format::PackedMultiVectorManifest;
use super::simd;
use super::wire::{
    CENTROID_CODE_BYTES, CODEC_TAG_RESIDUAL_2BIT, DIGEST_BYTES, DTYPE_TAG_F32,
    METRIC_TAG_COSINE_MAXSIM, RESIDUAL_BITS, append_digest, array_16, array_32, as_u32, invalid,
    read_u16, read_u32, require_digest, require_tag, require_u16, require_u32, require_u64,
};
use super::{CALYX_MULTIVECTOR_CONTEXT_MISMATCH, multivector_error};

/// Four-byte magic inside every packed primary row.
pub const MULTIVECTOR_ROW_MAGIC: &[u8; 4] = b"CMVR";
/// Packed primary-row wire version.
pub const MULTIVECTOR_ROW_VERSION: u16 = 1;
/// Fixed bytes before a row's centroid-code block.
pub const MULTIVECTOR_ROW_HEADER_BYTES: usize = 153;

const ROW_HASH_DOMAIN: &[u8] = b"calyx-colbert-residual-row-v1";

/// Fully validated packed primary row.
#[derive(Clone, Debug)]
pub struct ParsedPackedMultiVectorRow {
    bytes: Vec<u8>,
    cx_id: CxId,
    token_count: u32,
    codes_offset: usize,
    residual_offset: usize,
    payload_end: usize,
}

impl ParsedPackedMultiVectorRow {
    pub fn cx_id(&self) -> CxId {
        self.cx_id
    }

    pub fn token_count(&self) -> u32 {
        self.token_count
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn decode_token_into(
        &self,
        manifest: &PackedMultiVectorManifest,
        token_index: u32,
        scratch: &mut Vec<f32>,
    ) -> Result<()> {
        if token_index >= self.token_count {
            return Err(invalid(format!(
                "token index {token_index} is outside token_count {}",
                self.token_count
            )));
        }
        let code_at = self.codes_offset + token_index as usize * 4;
        let code = read_u32(&self.bytes, code_at)?;
        if code >= manifest.config.centroid_count {
            return Err(invalid(format!(
                "token {token_index} centroid code {code} exceeds centroid_count {}",
                manifest.config.centroid_count
            )));
        }
        let dim = manifest.token_dim as usize;
        let centroid_at = code as usize * dim;
        scratch.clear();
        scratch.extend_from_slice(&manifest.centroids[centroid_at..centroid_at + dim]);
        let packed_dim = dim / 4;
        let residual_at = self.residual_offset + token_index as usize * packed_dim;
        for packed_index in 0..packed_dim {
            let packed = self.bytes[residual_at + packed_index];
            for lane in 0..4 {
                let bucket = ((packed >> (6 - lane * 2)) & 0x03) as usize;
                scratch[packed_index * 4 + lane] += manifest.bucket_weights[bucket];
            }
        }
        simd::normalize(scratch)
    }

    pub(super) fn code_bytes(&self) -> usize {
        self.residual_offset - self.codes_offset
    }

    pub(super) fn residual_bytes(&self) -> usize {
        self.payload_end - self.residual_offset
    }

    pub(super) fn payload(&self) -> &[u8] {
        &self.bytes[self.codes_offset..self.payload_end]
    }
}

pub(super) struct PendingPackedRow {
    pub cx_id: CxId,
    pub token_count: u32,
    pub raw_bytes: Vec<u8>,
    pub payload: Vec<u8>,
}

pub(super) fn encode_packed_row(
    manifest: &PackedMultiVectorManifest,
    pending: &PendingPackedRow,
) -> Result<Vec<u8>> {
    let code_bytes = pending.token_count as usize * 4;
    let residual_bytes = pending.token_count as usize * (manifest.token_dim as usize / 4);
    if pending.payload.len() != code_bytes + residual_bytes {
        return Err(invalid(
            "pending packed row payload length does not match geometry",
        ));
    }
    let codes_offset = MULTIVECTOR_ROW_HEADER_BYTES;
    let residual_offset = codes_offset
        .checked_add(code_bytes)
        .ok_or_else(|| invalid("row residual offset overflow"))?;
    let payload_end = residual_offset
        .checked_add(residual_bytes)
        .ok_or_else(|| invalid("row payload end overflow"))?;
    let mut bytes = Vec::with_capacity(payload_end + DIGEST_BYTES);
    bytes.push(COMPRESSED_SLOT_VALUE_TAG);
    bytes.extend_from_slice(MULTIVECTOR_ROW_MAGIC);
    bytes.extend_from_slice(&MULTIVECTOR_ROW_VERSION.to_be_bytes());
    bytes.push(CODEC_TAG_RESIDUAL_2BIT);
    bytes.push(METRIC_TAG_COSINE_MAXSIM);
    bytes.push(DTYPE_TAG_F32);
    bytes.push(RESIDUAL_BITS);
    bytes.push(CENTROID_CODE_BYTES);
    bytes.push(0);
    bytes.extend_from_slice(&manifest.token_dim.to_be_bytes());
    bytes.extend_from_slice(&pending.token_count.to_be_bytes());
    bytes.extend_from_slice(&manifest.config.max_tokens.to_be_bytes());
    bytes.extend_from_slice(&manifest.config.centroid_count.to_be_bytes());
    bytes.extend_from_slice(&as_u32(codes_offset, "codes offset")?.to_be_bytes());
    bytes.extend_from_slice(&as_u32(residual_offset, "residual offset")?.to_be_bytes());
    bytes.extend_from_slice(&as_u32(payload_end, "payload end")?.to_be_bytes());
    bytes.extend_from_slice(&manifest.generation_rows.to_be_bytes());
    bytes.extend_from_slice(&manifest.generation_seq.to_be_bytes());
    bytes.extend_from_slice(&manifest.slot_id.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(manifest.lens_id.as_bytes());
    bytes.extend_from_slice(pending.cx_id.as_bytes());
    bytes.extend_from_slice(&manifest.codec_context_id);
    bytes.extend_from_slice(&manifest.generation_root);
    debug_assert_eq!(bytes.len(), MULTIVECTOR_ROW_HEADER_BYTES);
    bytes.extend_from_slice(&pending.payload);
    append_digest(&mut bytes, ROW_HASH_DOMAIN);
    Ok(bytes)
}

/// Parses a packed row against its exact manifest and CF-key identity.
pub fn parse_packed_multivector_row(
    bytes: &[u8],
    manifest: &PackedMultiVectorManifest,
    expected_cx_id: CxId,
) -> Result<ParsedPackedMultiVectorRow> {
    if bytes.len() < MULTIVECTOR_ROW_HEADER_BYTES + DIGEST_BYTES {
        return Err(invalid(format!(
            "packed row is {} bytes; minimum is {}",
            bytes.len(),
            MULTIVECTOR_ROW_HEADER_BYTES + DIGEST_BYTES
        )));
    }
    require_digest(bytes, ROW_HASH_DOMAIN, "packed row")?;
    if bytes[0] != COMPRESSED_SLOT_VALUE_TAG || &bytes[1..5] != MULTIVECTOR_ROW_MAGIC {
        return Err(invalid(
            "primary row is not a CMVR compressed envelope (legacy raw-F32/INT8 bytes are refused)",
        ));
    }
    require_u16(bytes, 5, MULTIVECTOR_ROW_VERSION, "row version")?;
    require_tag(bytes[7], CODEC_TAG_RESIDUAL_2BIT, "row codec")?;
    require_tag(bytes[8], METRIC_TAG_COSINE_MAXSIM, "row metric")?;
    require_tag(bytes[9], DTYPE_TAG_F32, "row dtype")?;
    require_tag(bytes[10], RESIDUAL_BITS, "row residual bits")?;
    require_tag(bytes[11], CENTROID_CODE_BYTES, "row centroid-code width")?;
    if bytes[12] != 0 || read_u16(bytes, 55)? != 0 {
        return Err(invalid("packed row reserved fields are non-zero"));
    }
    require_u32(bytes, 13, manifest.token_dim, "row token_dim")?;
    let token_count = read_u32(bytes, 17)?;
    if token_count == 0 || token_count > manifest.config.max_tokens {
        return Err(invalid(format!(
            "row token_count {token_count} is outside 1..={}",
            manifest.config.max_tokens
        )));
    }
    require_u32(bytes, 21, manifest.config.max_tokens, "row max_tokens")?;
    require_u32(
        bytes,
        25,
        manifest.config.centroid_count,
        "row centroid_count",
    )?;
    let codes_offset = read_u32(bytes, 29)? as usize;
    let residual_offset = read_u32(bytes, 33)? as usize;
    let payload_end = read_u32(bytes, 37)? as usize;
    require_u32(bytes, 41, manifest.generation_rows, "row generation_rows")?;
    require_u64(bytes, 45, manifest.generation_seq, "row generation_seq")?;
    require_u16(bytes, 53, manifest.slot_id, "row slot_id")?;
    let lens_id = LensId::from_bytes(array_16(bytes, 57)?);
    let cx_id = CxId::from_bytes(array_16(bytes, 73)?);
    let context = array_32(bytes, 89)?;
    let generation_root = array_32(bytes, 121)?;
    if lens_id != manifest.lens_id
        || cx_id != expected_cx_id
        || context != manifest.codec_context_id
        || generation_root != manifest.generation_root
    {
        return Err(multivector_error(
            CALYX_MULTIVECTOR_CONTEXT_MISMATCH,
            format!(
                "packed row context mismatch: lens={lens_id}, cx={cx_id}, expected_cx={expected_cx_id}"
            ),
        ));
    }
    let expected_codes = MULTIVECTOR_ROW_HEADER_BYTES;
    let expected_residual = expected_codes
        .checked_add(token_count as usize * 4)
        .ok_or_else(|| invalid("row code block length overflow"))?;
    let expected_end = expected_residual
        .checked_add(token_count as usize * (manifest.token_dim as usize / 4))
        .ok_or_else(|| invalid("row residual block length overflow"))?;
    if codes_offset != expected_codes
        || residual_offset != expected_residual
        || payload_end != expected_end
        || bytes.len() != expected_end + DIGEST_BYTES
    {
        return Err(invalid(format!(
            "row offsets/counts are non-canonical: codes={codes_offset}/{expected_codes}, residual={residual_offset}/{expected_residual}, end={payload_end}/{expected_end}, bytes={}",
            bytes.len()
        )));
    }
    for token in 0..token_count as usize {
        let code = read_u32(bytes, codes_offset + token * 4)?;
        if code >= manifest.config.centroid_count {
            return Err(invalid(format!(
                "row token {token} centroid code {code} is outside centroid_count {}",
                manifest.config.centroid_count
            )));
        }
    }
    Ok(ParsedPackedMultiVectorRow {
        bytes: bytes.to_vec(),
        cx_id,
        token_count,
        codes_offset,
        residual_offset,
        payload_end,
    })
}
