use calyx_aster::vault::encode;
use calyx_core::{CalyxError, QuantPolicy, Result, Slot, SlotShape, SlotVector};
use calyx_forge::{
    BinaryCodec, MxFp4Codec, QuantLevel, QuantizedVec, Quantizer, ScalarInt8Codec,
    TurboQuantCodec, TurboQuantPreparedQuery, new_seed, seed_id_hex,
};
use sha2::{Digest, Sha256};

use super::recall::prepare_dense;
use super::{
    CALYX_VECTOR_COMPRESSION_INVALID, COMPRESSED_SLOT_TAG, COMPRESSED_SLOT_VERSION,
    MxFp4AssayEvidence, REGISTRY_ENVELOPE_HEADER_BYTES, StoredSlotCodec, StoredSlotEnvelope,
    compression_error,
};
use crate::spec::LensSpec;

const ENVELOPE_HASH_DOMAIN: &[u8] = b"calyx-registry-slot-envelope-v2";
const ZERO_SEED: [u8; 32] = [0; 32];

pub(super) struct EncodedBatch {
    pub(super) codec: CodecContext,
    pub(super) rows: Vec<EncodedRow>,
}

#[derive(Clone)]
pub(super) struct EncodedRow {
    pub(super) cx_id: calyx_core::CxId,
    pub(super) prepared: Vec<f32>,
    pub(super) raw_bytes: Vec<u8>,
    pub(super) stored_bytes: Vec<u8>,
    pub(super) codec: StoredSlotCodec,
    pub(super) payload_bytes: usize,
    pub(super) codec_header_bytes: usize,
    pub(super) logical_data_bits: u64,
}

pub(super) struct ParsedStoredSlot {
    pub(super) envelope: StoredSlotEnvelope,
    pub(super) qv: QuantizedVec,
}

pub(super) enum CodecContext {
    RawF32 { dim: usize },
    TurboQuant(TurboQuantCodec),
    ScalarInt8(ScalarInt8Codec),
    MxFp4 {
        codec: MxFp4Codec,
        slot_key: String,
        safety: Option<calyx_forge::AssayQuantSafety>,
    },
    MxFp8(MxFp4Codec),
    Binary(BinaryCodec),
}

pub(super) enum PreparedSlotQuery {
    TurboQuant {
        query: TurboQuantPreparedQuery,
        norm: f32,
    },
    Dense {
        values: Vec<f32>,
        norm: f32,
    },
}

pub(super) fn encode_rows(
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(calyx_core::CxId, Vec<f32>)],
    policy: QuantPolicy,
    mxfp4_evidence: Option<&MxFp4AssayEvidence>,
) -> Result<EncodedBatch> {
    let codec = CodecContext::for_write(slot, lens, policy, mxfp4_evidence)?;
    let mut encoded_rows = Vec::with_capacity(rows.len());
    for (cx_id, raw) in rows {
        let prepared = prepare_dense(raw, lens.truncate_dim)?;
        let raw_bytes = raw_bytes(raw)?;
        let qv = codec.encode(&prepared)?;
        let metrics = codec.storage_metrics(&qv)?;
        let stored_bytes = encode_envelope(codec.stored_codec(), &qv, raw.len() as u32)?;
        encoded_rows.push(EncodedRow {
            cx_id: *cx_id,
            prepared,
            raw_bytes,
            stored_bytes,
            codec: codec.stored_codec(),
            payload_bytes: qv.bytes.len(),
            codec_header_bytes: metrics.codec_header_bytes,
            logical_data_bits: metrics.logical_data_bits,
        });
    }
    Ok(EncodedBatch {
        codec,
        rows: encoded_rows,
    })
}

pub fn decode_stored_slot_envelope(bytes: &[u8]) -> Result<StoredSlotEnvelope> {
    Ok(parse_stored_slot(bytes)?.envelope)
}

pub(super) fn parse_stored_slot(bytes: &[u8]) -> Result<ParsedStoredSlot> {
    if bytes.first().copied() != Some(COMPRESSED_SLOT_TAG) {
        return Err(invalid("stored slot bytes are missing compressed slot envelope tag"));
    }
    if bytes.len() < REGISTRY_ENVELOPE_HEADER_BYTES {
        return Err(invalid(format!(
            "compressed slot envelope too short: expected at least {REGISTRY_ENVELOPE_HEADER_BYTES} bytes, got {}",
            bytes.len()
        )));
    }
    let version = bytes[1];
    if version != COMPRESSED_SLOT_VERSION {
        return Err(invalid(format!(
            "unsupported compressed slot version {version}; expected {COMPRESSED_SLOT_VERSION}"
        )));
    }
    let codec = decode_codec(bytes[2])?;
    let level = decode_level(bytes[3])?;
    validate_codec_level(codec, level)?;
    let raw_dim = read_u32(bytes, 4, "raw_dim")?;
    let stored_dim = read_u32(bytes, 8, "stored_dim")?;
    if raw_dim == 0 || stored_dim == 0 || stored_dim > raw_dim {
        return Err(invalid(format!(
            "invalid envelope dimensions raw_dim={raw_dim} stored_dim={stored_dim}"
        )));
    }
    let flags = bytes[12];
    if flags & !0b10 != 0 {
        return Err(invalid(format!(
            "unsupported compressed slot flags 0x{flags:02x}; fallback and reserved flags are forbidden"
        )));
    }
    let truncated = flags & 0b10 != 0;
    if truncated != (stored_dim < raw_dim) {
        return Err(invalid(format!(
            "truncation flag disagrees with raw_dim={raw_dim} stored_dim={stored_dim}"
        )));
    }
    let quant_scale = f32::from_bits(read_u32(bytes, 13, "quant_scale")?);
    if !quant_scale.is_finite() || quant_scale < 0.0 {
        return Err(invalid("quant scale must be finite and non-negative"));
    }
    let mut seed_id = [0_u8; 32];
    seed_id.copy_from_slice(&bytes[17..49]);
    let payload_len = read_u32(bytes, 49, "payload_len")? as usize;
    let expected_len = REGISTRY_ENVELOPE_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| invalid("compressed slot payload length overflow"))?;
    if bytes.len() != expected_len {
        return Err(invalid(format!(
            "compressed slot payload length mismatch: header={payload_len} actual={}",
            bytes.len() - REGISTRY_ENVELOPE_HEADER_BYTES
        )));
    }
    let recorded_digest = &bytes[53..85];
    let payload = &bytes[REGISTRY_ENVELOPE_HEADER_BYTES..];
    let computed_digest = envelope_digest(&bytes[..53], payload);
    if recorded_digest != computed_digest {
        return Err(invalid(format!(
            "compressed slot SHA-256 mismatch: recorded={} computed={}",
            hex(recorded_digest),
            hex(&computed_digest)
        )));
    }
    let qv = QuantizedVec {
        level,
        dim: stored_dim as usize,
        bytes: payload.to_vec(),
        scale: quant_scale,
        seed_id,
    };
    validate_payload_without_context(codec, &qv)?;
    Ok(ParsedStoredSlot {
        envelope: StoredSlotEnvelope {
            format_version: version,
            codec,
            level: format!("{level:?}"),
            raw_dim,
            stored_dim,
            truncated,
            quant_scale,
            seed_id: seed_id_hex(&seed_id),
            payload_bytes: payload_len,
            payload_sha256: hex(&computed_digest),
        },
        qv,
    })
}

impl CodecContext {
    pub(super) fn for_read(slot: &Slot, lens: &LensSpec) -> Result<Self> {
        Self::build(slot, lens, lens.quant_default, None, false)
    }

    fn for_write(
        slot: &Slot,
        lens: &LensSpec,
        policy: QuantPolicy,
        evidence: Option<&MxFp4AssayEvidence>,
    ) -> Result<Self> {
        Self::build(slot, lens, policy, evidence, true)
    }

    fn build(
        slot: &Slot,
        lens: &LensSpec,
        policy: QuantPolicy,
        evidence: Option<&MxFp4AssayEvidence>,
        writing: bool,
    ) -> Result<Self> {
        let dim = validate_context(slot, lens, policy)?;
        match policy {
            QuantPolicy::None => Ok(Self::RawF32 { dim }),
            QuantPolicy::TurboQuant {
                bits_per_channel_x2: 16,
            } => Ok(Self::ScalarInt8(ScalarInt8Codec::new(dim))),
            QuantPolicy::TurboQuant {
                bits_per_channel_x2,
            } => {
                let level = match bits_per_channel_x2 {
                    7 => QuantLevel::Bits3p5,
                    5 => QuantLevel::Bits2p5,
                    other => {
                        return Err(invalid(format!(
                            "unsupported TurboQuant bits_per_channel_x2 {other}; expected 5, 7, or 16"
                        )));
                    }
                };
                let seed = shared_seed(slot, lens, dim, level, b"turboquant");
                Ok(Self::TurboQuant(
                    TurboQuantCodec::new(seed, level).map_err(forge_error)?,
                ))
            }
            QuantPolicy::MxFp4 => {
                let safety = if writing {
                    Some(
                        evidence
                            .ok_or_else(|| {
                                invalid(format!(
                                    "MXFP4 requires current assay evidence for slot={} lens={} dim={dim}; no fallback codec was written",
                                    slot.slot_key.key(),
                                    lens.lens_id()
                                ))
                            })?
                            .validate(slot, lens, dim as u32)?
                            .clone(),
                    )
                } else {
                    None
                };
                Ok(Self::MxFp4 {
                    codec: MxFp4Codec::new(dim),
                    slot_key: slot.slot_key.key().to_string(),
                    safety,
                })
            }
            QuantPolicy::Float8 => Ok(Self::MxFp8(MxFp4Codec::new(dim))),
            QuantPolicy::Binary => {
                let seed = shared_seed(slot, lens, dim, QuantLevel::Bits1, b"binary");
                Ok(Self::Binary(BinaryCodec::new(seed).map_err(forge_error)?))
            }
            QuantPolicy::Pq { m, nbits } => Err(invalid(format!(
                "PQ codec is not implemented for m={m} nbits={nbits}; refusing codec substitution"
            ))),
        }
    }

    pub(super) fn dim(&self) -> usize {
        match self {
            Self::RawF32 { dim } => *dim,
            Self::TurboQuant(codec) => codec.dim(),
            Self::ScalarInt8(codec) => codec.dim(),
            Self::MxFp4 { codec, .. } | Self::MxFp8(codec) => codec.dim(),
            Self::Binary(codec) => codec.dim(),
        }
    }

    pub(super) fn stored_codec(&self) -> StoredSlotCodec {
        match self {
            Self::RawF32 { .. } => StoredSlotCodec::RawF32,
            Self::TurboQuant(codec) if codec.level() == QuantLevel::Bits2p5 => {
                StoredSlotCodec::TurboQuantBits2p5
            }
            Self::TurboQuant(_) => StoredSlotCodec::TurboQuantBits3p5,
            Self::ScalarInt8(_) => StoredSlotCodec::ScalarInt8,
            Self::MxFp4 { .. } => StoredSlotCodec::MxFp4,
            Self::MxFp8(_) => StoredSlotCodec::MxFp8,
            Self::Binary(_) => StoredSlotCodec::Binary,
        }
    }

    pub(super) fn level(&self) -> QuantLevel {
        match self {
            Self::RawF32 { .. } => QuantLevel::F32,
            Self::TurboQuant(codec) => codec.level(),
            Self::ScalarInt8(_) => QuantLevel::Bits8,
            Self::MxFp4 { .. } => QuantLevel::Bits4Fp,
            Self::MxFp8(_) => QuantLevel::Bits8Fp,
            Self::Binary(_) => QuantLevel::Bits1,
        }
    }

    fn encode(&self, prepared: &[f32]) -> Result<QuantizedVec> {
        match self {
            Self::RawF32 { dim } => {
                validate_dense(prepared, *dim, "raw encode")?;
                Ok(QuantizedVec {
                    level: QuantLevel::F32,
                    dim: *dim,
                    bytes: raw_f32_payload(prepared),
                    scale: l2_norm(prepared)?,
                    seed_id: ZERO_SEED,
                })
            }
            Self::TurboQuant(codec) => codec.encode(prepared).map_err(forge_error),
            Self::ScalarInt8(codec) => codec.encode(prepared).map_err(forge_error),
            Self::MxFp4 {
                codec,
                slot_key,
                safety,
            } => codec
                .encode_assay_checked(
                    slot_key,
                    prepared,
                    safety.as_ref().ok_or_else(|| {
                        invalid("MXFP4 write context is missing validated assay evidence")
                    })?,
                )
                .map_err(forge_error),
            Self::MxFp8(codec) => codec.encode_mxfp8(prepared).map_err(forge_error),
            Self::Binary(codec) => {
                if l2_norm(prepared)? == 0.0 {
                    return Err(invalid(
                        "binary compression cannot represent a zero vector; choose an explicit non-binary policy",
                    ));
                }
                codec.encode(prepared).map_err(forge_error)
            }
        }
    }

    pub(super) fn decode_parsed(&self, parsed: &ParsedStoredSlot) -> Result<Vec<f32>> {
        self.validate_parsed(parsed)?;
        match self {
            Self::RawF32 { .. } => decode_raw_f32(&parsed.qv.bytes, parsed.qv.dim),
            Self::TurboQuant(codec) => codec.decode(&parsed.qv).map_err(forge_error),
            Self::ScalarInt8(codec) => codec.decode(&parsed.qv).map_err(forge_error),
            Self::MxFp4 { codec, .. } | Self::MxFp8(codec) => {
                codec.decode(&parsed.qv).map_err(forge_error)
            }
            Self::Binary(codec) => codec.decode(&parsed.qv).map_err(forge_error),
        }
    }

    pub(super) fn prepare_query(&self, query: &[f32]) -> Result<PreparedSlotQuery> {
        validate_dense(query, self.dim(), "compressed slot query")?;
        let norm = l2_norm(query)?;
        match self {
            Self::TurboQuant(codec) => Ok(PreparedSlotQuery::TurboQuant {
                query: codec.prepare_query(query).map_err(forge_error)?,
                norm,
            }),
            _ => Ok(PreparedSlotQuery::Dense {
                values: query.to_vec(),
                norm,
            }),
        }
    }

    pub(super) fn score_parsed(
        &self,
        query: &PreparedSlotQuery,
        parsed: &ParsedStoredSlot,
    ) -> Result<f32> {
        self.validate_parsed(parsed)?;
        match (self, query) {
            (
                Self::TurboQuant(codec),
                PreparedSlotQuery::TurboQuant { query, norm },
            ) => {
                if *norm == 0.0 || parsed.qv.scale == 0.0 {
                    return Ok(0.0);
                }
                let dot = codec
                    .dot_estimate_prepared(query, &parsed.qv)
                    .map_err(forge_error)?;
                Ok(dot / (*norm * parsed.qv.scale))
            }
            (Self::RawF32 { .. }, PreparedSlotQuery::Dense { values, .. }) => {
                let candidate = decode_raw_f32(&parsed.qv.bytes, parsed.qv.dim)?;
                cosine(values, &candidate)
            }
            (Self::ScalarInt8(codec), PreparedSlotQuery::Dense { values, norm }) => {
                score_decoded(codec, values, *norm, &parsed.qv)
            }
            (Self::MxFp4 { codec, .. }, PreparedSlotQuery::Dense { values, norm })
            | (Self::MxFp8(codec), PreparedSlotQuery::Dense { values, norm }) => {
                score_decoded(codec, values, *norm, &parsed.qv)
            }
            (Self::Binary(codec), PreparedSlotQuery::Dense { values, norm }) => {
                if *norm == 0.0 {
                    return Ok(0.0);
                }
                Ok(codec.dot_estimate(values, &parsed.qv).map_err(forge_error)? / *norm)
            }
            _ => Err(invalid("prepared query does not belong to this codec context")),
        }
    }

    pub(super) fn validate_parsed(&self, parsed: &ParsedStoredSlot) -> Result<()> {
        if parsed.envelope.codec != self.stored_codec()
            || parsed.qv.level != self.level()
            || parsed.qv.dim != self.dim()
        {
            return Err(invalid(format!(
                "persisted codec context mismatch: expected codec={:?} level={:?} dim={} got codec={:?} level={:?} dim={}",
                self.stored_codec(),
                self.level(),
                self.dim(),
                parsed.envelope.codec,
                parsed.qv.level,
                parsed.qv.dim
            )));
        }
        match self {
            Self::TurboQuant(codec) => {
                codec.storage(&parsed.qv).map_err(forge_error)?;
            }
            Self::Binary(codec) => {
                if parsed.qv.seed_id != codec.seed().id {
                    return Err(invalid("persisted binary seed does not match frozen slot/lens"));
                }
                let expected_scale = 1.0 / (parsed.qv.dim as f32).sqrt();
                if parsed.qv.scale.to_bits() != expected_scale.to_bits() {
                    return Err(invalid("persisted binary amplitude is not canonical"));
                }
            }
            Self::RawF32 { .. } | Self::ScalarInt8(_) | Self::MxFp4 { .. } | Self::MxFp8(_) => {
                if parsed.qv.seed_id != ZERO_SEED {
                    return Err(invalid("persisted non-rotating codec requires a zero seed id"));
                }
            }
        }
        Ok(())
    }

    fn storage_metrics(&self, qv: &QuantizedVec) -> Result<StorageMetrics> {
        if let Self::TurboQuant(codec) = self {
            let metrics = codec.storage(qv).map_err(forge_error)?;
            return Ok(StorageMetrics {
                logical_data_bits: metrics.data_bits as u64,
                codec_header_bytes: metrics.format_header_bytes,
            });
        }
        Ok(StorageMetrics {
            logical_data_bits: ((self.level().bits_per_channel() as f64) * qv.dim as f64).ceil()
                as u64,
            codec_header_bytes: 0,
        })
    }
}

struct StorageMetrics {
    logical_data_bits: u64,
    codec_header_bytes: usize,
}

fn score_decoded<Q: Quantizer>(
    codec: &Q,
    query: &[f32],
    query_norm: f32,
    candidate: &QuantizedVec,
) -> Result<f32> {
    if query_norm == 0.0 {
        return Ok(0.0);
    }
    let dot = codec.dot_estimate(query, candidate).map_err(forge_error)?;
    let decoded = codec.decode(candidate).map_err(forge_error)?;
    let candidate_norm = l2_norm(&decoded)?;
    if candidate_norm == 0.0 {
        return Ok(0.0);
    }
    Ok(dot / (query_norm * candidate_norm))
}

fn validate_context(slot: &Slot, lens: &LensSpec, policy: QuantPolicy) -> Result<usize> {
    if lens.output != slot.shape {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "lens output {:?} does not match slot shape {:?}",
            lens.output, slot.shape
        )));
    }
    if lens.lens_id() != slot.lens_id {
        return Err(invalid(format!(
            "slot lens id {} does not match frozen lens id {}",
            slot.lens_id,
            lens.lens_id()
        )));
    }
    if slot.quant != policy || lens.quant_default != policy {
        return Err(invalid(format!(
            "quant policy mismatch: slot={:?} lens={:?} requested={policy:?}",
            slot.quant, lens.quant_default
        )));
    }
    let SlotShape::Dense(raw_dim) = slot.shape else {
        return Err(invalid("slot compression requires a dense slot"));
    };
    let stored_dim = lens.truncate_dim.unwrap_or(raw_dim);
    if stored_dim == 0 || stored_dim > raw_dim {
        return Err(invalid(format!(
            "truncate_dim {stored_dim} is invalid for raw dimension {raw_dim}"
        )));
    }
    Ok(stored_dim as usize)
}

fn shared_seed(
    slot: &Slot,
    lens: &LensSpec,
    dim: usize,
    level: QuantLevel,
    codec_domain: &[u8],
) -> calyx_forge::RotationSeed {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"calyx-registry-shared-codec-v2");
    hasher.update(&(codec_domain.len() as u64).to_be_bytes());
    hasher.update(codec_domain);
    hasher.update(lens.lens_id().as_bytes());
    hasher.update(&slot.slot_id.get().to_be_bytes());
    hasher.update(&(slot.slot_key.key().len() as u64).to_be_bytes());
    hasher.update(slot.slot_key.key().as_bytes());
    hasher.update(&(dim as u64).to_be_bytes());
    hasher.update(&[level_code(level)]);
    new_seed(dim, hasher.finalize().as_bytes())
}

fn encode_envelope(
    codec: StoredSlotCodec,
    qv: &QuantizedVec,
    raw_dim: u32,
) -> Result<Vec<u8>> {
    validate_codec_level(codec, qv.level)?;
    if qv.dim == 0 || qv.dim > raw_dim as usize {
        return Err(invalid(format!(
            "cannot envelope raw_dim={raw_dim} stored_dim={}",
            qv.dim
        )));
    }
    if !qv.scale.is_finite() || qv.scale < 0.0 {
        return Err(invalid("encoded quant scale must be finite and non-negative"));
    }
    let stored_dim = u32::try_from(qv.dim)
        .map_err(|_| invalid(format!("stored dimension {} exceeds u32", qv.dim)))?;
    let payload_len = u32::try_from(qv.bytes.len())
        .map_err(|_| invalid(format!("codec payload {} bytes exceeds u32", qv.bytes.len())))?;
    let mut prefix = Vec::with_capacity(53);
    prefix.push(COMPRESSED_SLOT_TAG);
    prefix.push(COMPRESSED_SLOT_VERSION);
    prefix.push(codec_code(codec));
    prefix.push(level_code(qv.level));
    prefix.extend_from_slice(&raw_dim.to_be_bytes());
    prefix.extend_from_slice(&stored_dim.to_be_bytes());
    prefix.push(u8::from(stored_dim < raw_dim) << 1);
    prefix.extend_from_slice(&qv.scale.to_bits().to_be_bytes());
    prefix.extend_from_slice(&qv.seed_id);
    prefix.extend_from_slice(&payload_len.to_be_bytes());
    let digest = envelope_digest(&prefix, &qv.bytes);
    let capacity = REGISTRY_ENVELOPE_HEADER_BYTES
        .checked_add(qv.bytes.len())
        .ok_or_else(|| invalid("compressed envelope capacity overflow"))?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(&digest);
    out.extend_from_slice(&qv.bytes);
    Ok(out)
}

fn validate_payload_without_context(codec: StoredSlotCodec, qv: &QuantizedVec) -> Result<()> {
    match codec {
        StoredSlotCodec::RawF32 => {
            decode_raw_f32(&qv.bytes, qv.dim)?;
        }
        StoredSlotCodec::TurboQuantBits3p5 | StoredSlotCodec::TurboQuantBits2p5 => {
            TurboQuantCodec::inspect(qv).map_err(forge_error)?;
        }
        StoredSlotCodec::ScalarInt8 => {
            if qv.bytes.len() != qv.dim || qv.seed_id != ZERO_SEED {
                return Err(invalid(format!(
                    "invalid scalar INT8 payload: bytes={} dim={} zero_seed={}",
                    qv.bytes.len(),
                    qv.dim,
                    qv.seed_id == ZERO_SEED
                )));
            }
        }
        StoredSlotCodec::MxFp4 | StoredSlotCodec::MxFp8 => {
            MxFp4Codec::new(qv.dim)
                .decode(qv)
                .map_err(forge_error)?;
        }
        StoredSlotCodec::Binary => {
            let expected = qv.dim.div_ceil(8);
            if qv.bytes.len() != expected {
                return Err(invalid(format!(
                    "binary payload length mismatch: expected {expected} got {}",
                    qv.bytes.len()
                )));
            }
            let used = qv.dim % 8;
            if used != 0 {
                let padding_mask = !((1_u16 << used) - 1) as u8;
                if qv
                    .bytes
                    .last()
                    .is_some_and(|last| last & padding_mask != 0)
                {
                    return Err(invalid("binary payload has non-zero padding bits"));
                }
            }
        }
    }
    Ok(())
}

fn raw_bytes(raw: &[f32]) -> Result<Vec<u8>> {
    encode::encode_slot_vector(&SlotVector::Dense {
        dim: raw.len() as u32,
        data: raw.to_vec(),
    })
}

fn raw_f32_payload(values: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(std::mem::size_of_val(values));
    for value in values {
        bytes.extend_from_slice(&value.to_bits().to_be_bytes());
    }
    bytes
}

fn decode_raw_f32(payload: &[u8], dim: usize) -> Result<Vec<f32>> {
    let expected = dim
        .checked_mul(std::mem::size_of::<f32>())
        .ok_or_else(|| invalid("raw f32 payload size overflow"))?;
    if payload.len() != expected {
        return Err(invalid(format!(
            "raw f32 payload length {} does not match dimension {dim}",
            payload.len()
        )));
    }
    let mut values = Vec::with_capacity(dim);
    for (idx, chunk) in payload.chunks_exact(4).enumerate() {
        let bits = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let value = f32::from_bits(bits);
        if !value.is_finite() {
            return Err(invalid(format!(
                "raw f32 payload contains non-finite coefficient at index {idx}"
            )));
        }
        values.push(value);
    }
    Ok(values)
}

fn validate_dense(values: &[f32], dim: usize, op: &str) -> Result<()> {
    if values.len() != dim {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "{op} dimension {} does not match codec dimension {dim}",
            values.len()
        )));
    }
    if let Some(idx) = values.iter().position(|value| !value.is_finite()) {
        return Err(invalid(format!(
            "{op} contains non-finite coefficient at index {idx}"
        )));
    }
    Ok(())
}

fn l2_norm(values: &[f32]) -> Result<f32> {
    let sum = values
        .iter()
        .try_fold(0.0_f64, |sum, value| {
            let next = sum + f64::from(*value) * f64::from(*value);
            next.is_finite().then_some(next)
        })
        .ok_or_else(|| invalid("vector L2 norm overflowed"))?;
    let norm = sum.sqrt() as f32;
    if !norm.is_finite() {
        return Err(invalid("vector L2 norm is non-finite"));
    }
    Ok(norm)
}

fn cosine(left: &[f32], right: &[f32]) -> Result<f32> {
    if left.len() != right.len() {
        return Err(CalyxError::lens_dim_mismatch(format!(
            "cosine dimension {} does not match {}",
            left.len(),
            right.len()
        )));
    }
    let lhs_norm = l2_norm(left)?;
    let rhs_norm = l2_norm(right)?;
    if lhs_norm == 0.0 || rhs_norm == 0.0 {
        return Ok(0.0);
    }
    let dot = left
        .iter()
        .zip(right)
        .map(|(lhs, rhs)| f64::from(*lhs) * f64::from(*rhs))
        .sum::<f64>();
    Ok((dot / (f64::from(lhs_norm) * f64::from(rhs_norm))) as f32)
}

fn envelope_digest(prefix: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ENVELOPE_HASH_DOMAIN);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn read_u32(bytes: &[u8], offset: usize, field: &str) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| invalid(format!("{field} offset overflow")))?;
    let chunk = bytes
        .get(offset..end)
        .ok_or_else(|| invalid(format!("compressed envelope is missing {field}")))?;
    Ok(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
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

fn codec_code(codec: StoredSlotCodec) -> u8 {
    match codec {
        StoredSlotCodec::RawF32 => 0,
        StoredSlotCodec::TurboQuantBits3p5 => 1,
        StoredSlotCodec::TurboQuantBits2p5 => 2,
        StoredSlotCodec::ScalarInt8 => 3,
        StoredSlotCodec::MxFp4 => 4,
        StoredSlotCodec::MxFp8 => 5,
        StoredSlotCodec::Binary => 6,
    }
}

fn decode_codec(code: u8) -> Result<StoredSlotCodec> {
    match code {
        0 => Ok(StoredSlotCodec::RawF32),
        1 => Ok(StoredSlotCodec::TurboQuantBits3p5),
        2 => Ok(StoredSlotCodec::TurboQuantBits2p5),
        3 => Ok(StoredSlotCodec::ScalarInt8),
        4 => Ok(StoredSlotCodec::MxFp4),
        5 => Ok(StoredSlotCodec::MxFp8),
        6 => Ok(StoredSlotCodec::Binary),
        _ => Err(invalid(format!("unknown stored slot codec code {code}"))),
    }
}

fn validate_codec_level(codec: StoredSlotCodec, level: QuantLevel) -> Result<()> {
    let valid = matches!(
        (codec, level),
        (StoredSlotCodec::RawF32, QuantLevel::F32)
            | (StoredSlotCodec::TurboQuantBits3p5, QuantLevel::Bits3p5)
            | (StoredSlotCodec::TurboQuantBits2p5, QuantLevel::Bits2p5)
            | (StoredSlotCodec::ScalarInt8, QuantLevel::Bits8)
            | (StoredSlotCodec::MxFp4, QuantLevel::Bits4Fp)
            | (StoredSlotCodec::MxFp8, QuantLevel::Bits8Fp)
            | (StoredSlotCodec::Binary, QuantLevel::Bits1)
    );
    if valid {
        Ok(())
    } else {
        Err(invalid(format!(
            "stored slot codec/level mismatch: codec={codec:?} level={level:?}"
        )))
    }
}

fn level_code(level: QuantLevel) -> u8 {
    match level {
        QuantLevel::F32 => 0,
        QuantLevel::Bits8 => 1,
        QuantLevel::Bits8Fp => 2,
        QuantLevel::Bits4Fp => 3,
        QuantLevel::Bits3p5 => 4,
        QuantLevel::Bits2p5 => 5,
        QuantLevel::Bits1 => 6,
    }
}

fn decode_level(code: u8) -> Result<QuantLevel> {
    match code {
        0 => Ok(QuantLevel::F32),
        1 => Ok(QuantLevel::Bits8),
        2 => Ok(QuantLevel::Bits8Fp),
        3 => Ok(QuantLevel::Bits4Fp),
        4 => Ok(QuantLevel::Bits3p5),
        5 => Ok(QuantLevel::Bits2p5),
        6 => Ok(QuantLevel::Bits1),
        _ => Err(invalid(format!("unknown quant level code {code}"))),
    }
}

fn forge_error(error: calyx_forge::ForgeError) -> CalyxError {
    CalyxError {
        code: error.code(),
        message: error.to_string(),
        remediation: super::COMPRESSION_REMEDIATION,
    }
}

fn invalid(message: impl Into<String>) -> CalyxError {
    compression_error(CALYX_VECTOR_COMPRESSION_INVALID, message)
}
