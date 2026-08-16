use calyx_aster::vault::encode;
use calyx_core::{
    Asymmetry, CalyxError, Modality, QuantPolicy, Result, Slot, SlotShape, SlotVector,
};
use calyx_forge::quant::BinaryPreparedQuery;
use calyx_forge::{
    BinaryCodec, MXFP_FORMAT_HEADER_BYTES, MxFp4Codec, MxFp8Codec, QuantLevel, QuantizedVec,
    Quantizer, ScalarInt8Codec, TURBOQUANT_FORMAT_HEADER_BYTES, TURBOQUANT_MAX_DIM,
    TurboQuantCodec, TurboQuantPreparedQuery, TurboQuantV1MigrationVerifier, mxfp_payload_len,
    new_seed, seed_id_hex,
};
use sha2::{Digest, Sha256};

use super::membership::{COMPRESSION_MEMBERSHIP_VERSION, build_membership};
use super::recall::prepare_dense;
use super::{
    CALYX_VECTOR_COMPRESSION_INVALID, COMPRESSED_SLOT_TAG, COMPRESSED_SLOT_VERSION,
    LEGACY_COMPRESSED_SLOT_VERSION, LEGACY_REGISTRY_ENVELOPE_HEADER_BYTES, MxFp4AssayEvidence,
    REGISTRY_ENVELOPE_HEADER_BYTES, StoredSlotCodec, StoredSlotEnvelope, compression_error,
};
use crate::spec::LensSpec;

const ENVELOPE_HASH_DOMAIN: &[u8] = b"calyx-registry-slot-envelope-v3";
const LEGACY_ENVELOPE_HASH_DOMAIN: &[u8] = b"calyx-registry-slot-envelope-v2";
const CODEC_CONTEXT_DOMAIN: &[u8] = b"calyx-registry-codec-context-v3";
const GENERATION_ROOT_DOMAIN: &[u8] = b"calyx-registry-compression-generation-v1";
const RAW_GENERATION_ROOT_DOMAIN: &[u8] = b"calyx-registry-compression-raw-generation-v1";
const MANIFEST_HASH_DOMAIN: &[u8] = b"calyx-registry-compression-manifest-v3";
const ZERO_SEED: [u8; 32] = [0; 32];
const ENVELOPE_PREFIX_BYTES: usize = 137;
const ENVELOPE_DIGEST_OFFSET: usize = ENVELOPE_PREFIX_BYTES;
const MANIFEST_MAGIC: &[u8; 4] = b"CSMF";
const MANIFEST_VERSION: u8 = 3;
const MANIFEST_PREFIX_BYTES: usize = 184;
const MANIFEST_BYTES: usize = MANIFEST_PREFIX_BYTES + 32;
const LEGACY_TQPR_MAGIC: &[u8; 4] = b"TQPR";
const LEGACY_TQPR_VERSION: u8 = 1;
const LEGACY_TQPR_HEADER_BYTES: usize = 88;
const LEGACY_TQPR_PREFIX_BYTES: usize = 56;
const LEGACY_TQPR_DIGEST_DOMAIN: &[u8] = b"calyx/turboquant/tqpr/payload/v1\0";

pub(super) struct EncodedBatch {
    pub(super) codec: CodecContext,
    pub(super) rows: Vec<EncodedRow>,
    pub(super) manifest_bytes: Vec<u8>,
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
    pub(super) membership_proof_bytes: Vec<u8>,
}

struct PendingEncodedRow {
    cx_id: calyx_core::CxId,
    prepared: Vec<f32>,
    raw_bytes: Vec<u8>,
    qv: QuantizedVec,
    codec_header_bytes: usize,
    logical_data_bits: u64,
}

pub(super) struct ParsedStoredSlot {
    pub(super) envelope: StoredSlotEnvelope,
    pub(super) qv: QuantizedVec,
    pub(super) codec_context_id: [u8; 32],
    pub(super) cx_id: calyx_core::CxId,
    pub(super) generation_root: [u8; 32],
    pub(super) generation_rows: u32,
}

pub(super) struct CompressionManifest {
    pub(super) codec: StoredSlotCodec,
    pub(super) level: QuantLevel,
    pub(super) raw_dim: u32,
    pub(super) stored_dim: u32,
    pub(super) codec_context_id: [u8; 32],
    pub(super) generation_root: [u8; 32],
    pub(super) raw_generation_root: [u8; 32],
    pub(super) generation_rows: u32,
    pub(super) membership_version: u8,
    pub(super) membership_root: [u8; 32],
    /// Exact Assay record identity required by this immutable generation.
    /// Non-MXFP4 manifests carry the canonical all-zero value.
    pub(super) assay_attestation_id: [u8; 32],
}

/// Pure frozen codec identity. Constructing this descriptor validates the
/// slot/lens/policy contract but never materializes codec geometry (issue #1064
/// PC-03/04/43).
#[derive(Clone, Copy)]
pub(super) struct CodecDescriptor {
    dim: usize,
    stored_codec: StoredSlotCodec,
    level: QuantLevel,
}

impl CodecDescriptor {
    pub(super) fn for_read(slot: &Slot, lens: &LensSpec) -> Result<Self> {
        let dim = validate_context(slot, lens, lens.quant_default)?;
        let (stored_codec, level) = current_policy_identity(lens.quant_default)?;
        Ok(Self {
            dim,
            stored_codec,
            level,
        })
    }

    pub(super) fn dim(self) -> usize {
        self.dim
    }

    pub(super) fn stored_codec(self) -> StoredSlotCodec {
        self.stored_codec
    }

    pub(super) fn level(self) -> QuantLevel {
        self.level
    }
}

pub(super) struct LegacyV2EnvelopeVerifier {
    slot: Slot,
    lens: LensSpec,
    codec: TurboQuantV1MigrationVerifier,
}

impl LegacyV2EnvelopeVerifier {
    pub(super) fn new(slot: &Slot, lens: &LensSpec) -> Result<Self> {
        let stored_dim = validate_context(slot, lens, lens.quant_default)?;
        let (stored_codec, level) = legacy_policy_identity(lens.quant_default)?;
        if !matches!(
            stored_codec,
            StoredSlotCodec::TurboQuantBits2p5 | StoredSlotCodec::TurboQuantBits3p5
        ) {
            return Err(invalid(format!(
                "legacy v2 migration is implemented only for exact TQPR-v1 TurboQuant rows; codec {stored_codec:?} requires its separately versioned codec migration and will not be guessed"
            )));
        }
        let seed = shared_seed(slot, lens, stored_dim, level, b"turboquant");
        let codec = TurboQuantV1MigrationVerifier::new(seed, level).map_err(forge_error)?;
        Ok(Self {
            slot: slot.clone(),
            lens: lens.clone(),
            codec,
        })
    }

    pub(super) fn verify(&self, bytes: &[u8], raw: &[f32]) -> Result<()> {
        let qv = parse_legacy_v2_envelope(bytes, &self.slot, &self.lens)?;
        let prepared = prepare_dense(raw, self.lens.truncate_dim)?;
        self.codec.verify(&prepared, &qv).map_err(forge_error)
    }
}

pub(super) enum CodecContext {
    RawF32 {
        dim: usize,
    },
    /// One shared frozen geometry per (slot/lens seed, level); repeated codec
    /// opens for the same registered slot reuse it via the process-wide
    /// bounded (live-usage-weak) forge geometry cache.
    TurboQuant(std::sync::Arc<TurboQuantCodec>),
    ScalarInt8(ScalarInt8Codec),
    MxFp4 {
        codec: MxFp4Codec,
        slot_key: String,
        safety: Option<calyx_forge::AssayQuantSafety>,
        attestation_id: Option<[u8; 32]>,
    },
    MxFp8(MxFp8Codec),
    Binary(BinaryCodec),
}

pub(super) enum PreparedSlotQuery {
    TurboQuant {
        query: TurboQuantPreparedQuery,
        norm: f64,
    },
    Binary {
        query: BinaryPreparedQuery,
        norm: f64,
    },
    Dense {
        values: Vec<f32>,
        norm: f64,
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
    let codec_context_id = codec_context_id(slot, lens, &codec)?;
    let mut pending = Vec::with_capacity(rows.len());
    for (cx_id, raw) in rows {
        let prepared = prepare_dense(raw, lens.truncate_dim)?;
        let raw_bytes = raw_bytes(raw)?;
        let qv = codec.encode(&prepared)?;
        let metrics = codec.storage_metrics(&qv)?;
        pending.push(PendingEncodedRow {
            cx_id: *cx_id,
            prepared,
            raw_bytes,
            qv,
            codec_header_bytes: metrics.codec_header_bytes,
            logical_data_bits: metrics.logical_data_bits,
        });
    }
    let generation_rows = u32::try_from(pending.len())
        .map_err(|_| invalid("compressed generation row count exceeds u32"))?;
    let generation_root = generation_root(
        &codec_context_id,
        generation_rows,
        pending.iter().map(|row| (row.cx_id, &row.qv)),
    )?;
    let raw_generation_root = raw_generation_root(
        &codec_context_id,
        generation_rows,
        pending
            .iter()
            .map(|row| (row.cx_id, row.raw_bytes.as_slice())),
    )?;
    let raw_dim = match slot.shape {
        SlotShape::Dense(dim) => dim,
        _ => return Err(invalid("slot compression requires a dense slot")),
    };
    let mut encoded_rows = Vec::with_capacity(pending.len());
    for row in pending {
        let payload_bytes = row.qv.bytes.len();
        let stored_bytes = encode_envelope(
            codec.stored_codec(),
            &row.qv,
            raw_dim,
            codec_context_id,
            row.cx_id,
            generation_root,
            generation_rows,
        )?;
        encoded_rows.push(EncodedRow {
            cx_id: row.cx_id,
            prepared: row.prepared,
            raw_bytes: row.raw_bytes,
            stored_bytes,
            codec: codec.stored_codec(),
            payload_bytes,
            codec_header_bytes: row.codec_header_bytes,
            logical_data_bits: row.logical_data_bits,
            membership_proof_bytes: Vec::new(),
        });
    }
    let mut membership = build_membership(
        encoded_rows
            .iter()
            .map(|row| (row.cx_id, row.stored_bytes.as_slice())),
    )?;
    for row in &mut encoded_rows {
        row.membership_proof_bytes = membership.proofs.remove(&row.cx_id).ok_or_else(|| {
            invalid(format!(
                "membership builder omitted proof for compressed row {}",
                row.cx_id
            ))
        })?;
    }
    if !membership.proofs.is_empty() {
        return Err(invalid(
            "membership builder produced proofs without compressed rows",
        ));
    }
    let assay_attestation_id = match &codec {
        CodecContext::MxFp4 {
            attestation_id: Some(attestation_id),
            ..
        } => *attestation_id,
        CodecContext::MxFp4 {
            attestation_id: None,
            ..
        } => {
            return Err(invalid(
                "MXFP4 encoder omitted the exact Assay attestation identity",
            ));
        }
        _ => [0; 32],
    };
    let manifest = CompressionManifest {
        codec: codec.stored_codec(),
        level: codec.level(),
        raw_dim,
        stored_dim: u32::try_from(codec.dim())
            .map_err(|_| invalid("stored dimension exceeds u32"))?,
        codec_context_id,
        generation_root,
        raw_generation_root,
        generation_rows,
        membership_version: COMPRESSION_MEMBERSHIP_VERSION,
        membership_root: membership.root,
        assay_attestation_id,
    };
    let manifest_bytes = encode_manifest(&manifest)?;
    Ok(EncodedBatch {
        codec,
        rows: encoded_rows,
        manifest_bytes,
    })
}

/// Inspects one self-contained compressed envelope without binding it to storage.
///
/// This validates the envelope digest and standalone codec-payload canonicality.
/// It does not authenticate the column-family key/CxId, registered slot or lens,
/// derived codec context, generation manifest/root, snapshot, or raw sidecar.
/// Trusted persisted reads must use `Registry::compressed_slot_index` followed
/// by `envelope_at`, `read_at`, or `verify_at`.
pub fn inspect_unbound_stored_slot_envelope(bytes: &[u8]) -> Result<StoredSlotEnvelope> {
    Ok(parse_stored_slot_inner(bytes, true)?.envelope)
}

pub(super) fn parse_stored_slot(bytes: &[u8]) -> Result<ParsedStoredSlot> {
    parse_stored_slot_inner(bytes, false)
}

fn parse_legacy_v2_envelope(bytes: &[u8], slot: &Slot, lens: &LensSpec) -> Result<QuantizedVec> {
    if bytes.first().copied() != Some(COMPRESSED_SLOT_TAG) {
        return Err(invalid(
            "legacy slot bytes are missing the compressed slot envelope tag",
        ));
    }
    if bytes.len() < LEGACY_REGISTRY_ENVELOPE_HEADER_BYTES {
        return Err(invalid(format!(
            "legacy v2 compressed envelope is shorter than {LEGACY_REGISTRY_ENVELOPE_HEADER_BYTES} bytes: {}",
            bytes.len()
        )));
    }
    if bytes[1] != LEGACY_COMPRESSED_SLOT_VERSION {
        return Err(invalid(format!(
            "unmanifested compressed generation has unsupported envelope version {}; only exact legacy v2 generations can be upgraded",
            bytes[1]
        )));
    }
    let codec = decode_codec(bytes[2])?;
    let level = decode_level(bytes[3])?;
    validate_codec_level(codec, level)?;
    let (expected_codec, expected_level) = legacy_policy_identity(lens.quant_default)?;
    if codec != expected_codec || level != expected_level {
        return Err(invalid(format!(
            "legacy v2 codec identity does not match frozen slot/lens: expected codec={expected_codec:?} level={expected_level:?}, got codec={codec:?} level={level:?}"
        )));
    }
    let stored_dim = validate_context(slot, lens, lens.quant_default)?;
    let SlotShape::Dense(raw_dim) = slot.shape else {
        return Err(invalid("legacy v2 migration requires a dense slot"));
    };
    let encoded_raw_dim = read_u32(bytes, 4, "legacy_raw_dim")?;
    let encoded_stored_dim = read_u32(bytes, 8, "legacy_stored_dim")?;
    if encoded_raw_dim != raw_dim || encoded_stored_dim as usize != stored_dim {
        return Err(invalid(format!(
            "legacy v2 dimensions do not match frozen slot/lens: expected raw={raw_dim} stored={stored_dim}, got raw={encoded_raw_dim} stored={encoded_stored_dim}"
        )));
    }
    let flags = bytes[12];
    if flags & !0b10 != 0 || (flags & 0b10 != 0) != (encoded_stored_dim < encoded_raw_dim) {
        return Err(invalid(
            "legacy v2 truncation or reserved flags are non-canonical",
        ));
    }
    let scale = f32::from_bits(read_u32(bytes, 13, "legacy_quant_scale")?);
    if !scale.is_finite() || scale.is_sign_negative() {
        return Err(invalid(
            "legacy v2 quant scale must be finite, non-negative, and canonical +0.0 when zero",
        ));
    }
    let payload_len = read_u32(bytes, 49, "legacy_payload_len")? as usize;
    let (_, _, exact_payload_len) = legacy_tqpr_layout(encoded_stored_dim as usize, level)?;
    if payload_len != exact_payload_len {
        return Err(invalid(format!(
            "legacy v2 payload length is not canonical for its declared TQPR-v1 geometry: header={payload_len} exact={exact_payload_len} dim={encoded_stored_dim} level={level:?}"
        )));
    }
    let expected_len = LEGACY_REGISTRY_ENVELOPE_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| invalid("legacy v2 payload length overflow"))?;
    if bytes.len() != expected_len {
        return Err(invalid(format!(
            "legacy v2 payload length mismatch: header={payload_len} actual={}",
            bytes.len() - LEGACY_REGISTRY_ENVELOPE_HEADER_BYTES
        )));
    }
    let prefix = &bytes[..53];
    let recorded = &bytes[53..LEGACY_REGISTRY_ENVELOPE_HEADER_BYTES];
    let payload = &bytes[LEGACY_REGISTRY_ENVELOPE_HEADER_BYTES..];
    let computed = envelope_digest_with_domain(LEGACY_ENVELOPE_HASH_DOMAIN, prefix, payload);
    if recorded != computed {
        return Err(invalid(format!(
            "legacy v2 compressed slot SHA-256 mismatch: recorded={} computed={}",
            hex(recorded),
            hex(&computed)
        )));
    }
    let mut seed_id = [0_u8; 32];
    seed_id.copy_from_slice(&bytes[17..49]);
    let qv = QuantizedVec {
        level,
        dim: encoded_stored_dim as usize,
        bytes: payload.to_vec(),
        scale,
        seed_id,
    };
    validate_legacy_v2_payload(codec, &qv, slot, lens)?;
    Ok(qv)
}

fn validate_legacy_v2_payload(
    codec: StoredSlotCodec,
    qv: &QuantizedVec,
    slot: &Slot,
    lens: &LensSpec,
) -> Result<()> {
    if !matches!(
        codec,
        StoredSlotCodec::TurboQuantBits2p5 | StoredSlotCodec::TurboQuantBits3p5
    ) {
        return Err(invalid(format!(
            "legacy v2 migration is implemented only for exact TQPR-v1 TurboQuant rows; codec {codec:?} requires its separately versioned codec migration and will not be guessed"
        )));
    }
    let expected_seed = shared_seed(slot, lens, qv.dim, qv.level, b"turboquant");
    if qv.seed_id != expected_seed.id {
        // Distinguish an identity-version mismatch from generic corruption. The
        // TurboQuant rotation seed binds `lens.lens_id()`, which #570 versioned
        // to a modality-bound v2 identity. A real pre-#570 vault envelope carries
        // a seed derived from the legacy (v1, modality-blind) LensId, so recompute
        // that legacy seed: if the persisted seed matches it, this is not a
        // corrupt row — it is a legacy-identity envelope that must be migrated by
        // re-commission/re-ingest under the current v2 identity (there is no
        // silent reinterpretation). Report that precisely instead of a bare
        // "seed does not match the frozen slot/lens geometry".
        let legacy_seed = shared_seed_for_lens_id(
            lens.legacy_v1_lens_id(),
            slot,
            qv.dim,
            qv.level,
            b"turboquant",
        );
        if qv.seed_id == legacy_seed.id {
            return Err(CalyxError::lens_frozen_violation(format!(
                "legacy v2 TurboQuant envelope seed derives from the pre-#570 (v1, modality-blind) lens identity, not the current modality-bound v2 identity: \
                 persisted_seed={} matches legacy_v1_seed for legacy_lens_id={}, but current_v2_lens_id={} derives current_seed={}. \
                 The frozen LensId now binds modality (#570); legacy identities are refused rather than silently reinterpreted. \
                 Migrate by re-commissioning/re-ingesting this slot under the current v2 lens identity.",
                seed_id_hex(&qv.seed_id),
                lens.legacy_v1_lens_id(),
                lens.lens_id(),
                seed_id_hex(&expected_seed.id),
            )));
        }
        return Err(invalid(format!(
            "legacy v2 TurboQuant seed does not match the frozen slot/lens geometry: expected={} got={}",
            seed_id_hex(&expected_seed.id),
            seed_id_hex(&qv.seed_id)
        )));
    }
    validate_legacy_tqpr_v1(qv)
}

fn validate_legacy_tqpr_v1(qv: &QuantizedVec) -> Result<()> {
    let (high_bits, level_code) = match qv.level {
        QuantLevel::Bits2p5 => (2_usize, 1_u8),
        QuantLevel::Bits3p5 => (3_usize, 2_u8),
        other => {
            return Err(invalid(format!(
                "legacy TQPR-v1 supports only Bits2p5/Bits3p5, got {other:?}"
            )));
        }
    };
    let (scalar_bits, scalar_len, expected_len) = legacy_tqpr_layout(qv.dim, qv.level)?;
    if !qv.scale.is_finite() || qv.scale.is_sign_negative() {
        return Err(invalid(
            "legacy TQPR-v1 source norm must be finite, non-negative, and canonical +0.0 when zero",
        ));
    }
    if qv.bytes.len() < LEGACY_TQPR_HEADER_BYTES {
        return Err(invalid(format!(
            "legacy TQPR-v1 payload is shorter than its {LEGACY_TQPR_HEADER_BYTES}-byte header"
        )));
    }
    if &qv.bytes[..4] != LEGACY_TQPR_MAGIC
        || qv.bytes[4] != LEGACY_TQPR_VERSION
        || qv.bytes[5] != level_code
    {
        return Err(invalid(
            "legacy TQPR-v1 magic, version, or level does not match the committed format",
        ));
    }
    if u16::from_le_bytes([qv.bytes[6], qv.bytes[7]]) != 0 {
        return Err(invalid("legacy TQPR-v1 reserved flags must be zero"));
    }
    let header_dim = legacy_tqpr_u32(&qv.bytes, 8, "dimension")? as usize;
    let header_scalar_bits = legacy_tqpr_u32(&qv.bytes, 12, "scalar_bits")? as usize;
    let header_qjl_bits = legacy_tqpr_u32(&qv.bytes, 16, "qjl_bits")? as usize;
    if header_dim != qv.dim || header_scalar_bits != scalar_bits || header_qjl_bits != qv.dim {
        return Err(invalid(format!(
            "legacy TQPR-v1 geometry mismatch: outer_dim={} header_dim={header_dim} scalar_bits={header_scalar_bits}/{scalar_bits} qjl_bits={header_qjl_bits}/{}",
            qv.dim, qv.dim
        )));
    }
    let gamma = f32::from_bits(legacy_tqpr_u32(&qv.bytes, 20, "gamma")?);
    if !gamma.is_finite() || gamma.is_sign_negative() {
        return Err(invalid(
            "legacy TQPR-v1 gamma must be finite, non-negative, and canonical +0.0 when zero",
        ));
    }
    if qv.bytes[24..56] != qv.seed_id {
        return Err(invalid(
            "legacy TQPR-v1 seed ID does not match its v2 registry envelope",
        ));
    }
    if qv.bytes.len() != expected_len {
        return Err(invalid(format!(
            "legacy TQPR-v1 payload length mismatch: expected={expected_len} got={}",
            qv.bytes.len()
        )));
    }
    let scalar_end = LEGACY_TQPR_HEADER_BYTES + scalar_len;
    let scalar = &qv.bytes[LEGACY_TQPR_HEADER_BYTES..scalar_end];
    let qjl = &qv.bytes[scalar_end..];
    if legacy_has_nonzero_padding(scalar, scalar_bits) || legacy_has_nonzero_padding(qjl, qv.dim) {
        return Err(invalid(
            "legacy TQPR-v1 scalar or QJL bitstream has non-zero padding",
        ));
    }
    if qv.dim == 1 {
        let code = legacy_read_bits(scalar, 0, high_bits);
        let positive_code = 1_u8 << (high_bits - 1);
        if code != 0 && code != positive_code {
            return Err(invalid(format!(
                "legacy TQPR-v1 dimension-one scalar code {code} was never emitted canonically"
            )));
        }
    }
    let computed_digest = legacy_tqpr_digest(
        &qv.bytes[..LEGACY_TQPR_PREFIX_BYTES],
        &qv.bytes[LEGACY_TQPR_HEADER_BYTES..],
        qv.scale,
    );
    if qv.bytes[LEGACY_TQPR_PREFIX_BYTES..LEGACY_TQPR_HEADER_BYTES] != computed_digest {
        return Err(invalid("legacy TQPR-v1 SHA-256 payload digest mismatch"));
    }
    if qv.scale == 0.0
        && (gamma != 0.0
            || scalar.iter().any(|byte| *byte != 0)
            || qjl.iter().any(|byte| *byte != 0))
    {
        return Err(invalid(
            "legacy TQPR-v1 zero source norm requires all-zero scalar, QJL, and gamma state",
        ));
    }
    if gamma == 0.0 && qjl.iter().any(|byte| *byte != 0) {
        return Err(invalid(
            "legacy TQPR-v1 zero residual norm requires all-zero QJL signs",
        ));
    }
    Ok(())
}

fn legacy_tqpr_layout(dim: usize, level: QuantLevel) -> Result<(usize, usize, usize)> {
    if dim == 0 || dim > calyx_forge::TURBOQUANT_MAX_DIM {
        return Err(invalid(format!(
            "legacy TQPR-v1 dimension must be in 1..={}, got {dim}",
            calyx_forge::TURBOQUANT_MAX_DIM
        )));
    }
    let low_bits = match level {
        QuantLevel::Bits2p5 => 1_usize,
        QuantLevel::Bits3p5 => 2_usize,
        other => {
            return Err(invalid(format!(
                "legacy TQPR-v1 supports only Bits2p5/Bits3p5, got {other:?}"
            )));
        }
    };
    let scalar_bits = dim
        .checked_mul(low_bits)
        .and_then(|base| base.checked_add(dim.div_ceil(2)))
        .ok_or_else(|| invalid("legacy TQPR-v1 scalar bit count overflow"))?;
    let scalar_len = scalar_bits.div_ceil(8);
    let expected_len = LEGACY_TQPR_HEADER_BYTES
        .checked_add(scalar_len)
        .and_then(|value| value.checked_add(dim.div_ceil(8)))
        .ok_or_else(|| invalid("legacy TQPR-v1 payload length overflow"))?;
    Ok((scalar_bits, scalar_len, expected_len))
}

fn legacy_tqpr_u32(bytes: &[u8], offset: usize, field: &str) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| invalid(format!("legacy TQPR-v1 {field} offset overflow")))?;
    let chunk = bytes
        .get(offset..end)
        .ok_or_else(|| invalid(format!("legacy TQPR-v1 is missing {field}")))?;
    Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

fn legacy_read_bits(bytes: &[u8], offset: usize, width: usize) -> u8 {
    let mut value = 0_u8;
    for bit in 0..width {
        let absolute = offset + bit;
        if bytes[absolute / 8] & (1 << (absolute % 8)) != 0 {
            value |= 1 << bit;
        }
    }
    value
}

fn legacy_has_nonzero_padding(bytes: &[u8], bits: usize) -> bool {
    let used = bits % 8;
    if used == 0 || bytes.is_empty() {
        return false;
    }
    let mask = !((1_u16 << used) - 1) as u8;
    bytes.last().is_some_and(|last| last & mask != 0)
}

fn legacy_tqpr_digest(prefix: &[u8], body: &[u8], scale: f32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LEGACY_TQPR_DIGEST_DOMAIN);
    hasher.update((prefix.len() as u64).to_le_bytes());
    hasher.update(prefix);
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(body);
    hasher.update(scale.to_bits().to_le_bytes());
    hasher.finalize().into()
}

fn legacy_policy_identity(policy: QuantPolicy) -> Result<(StoredSlotCodec, QuantLevel)> {
    match policy {
        QuantPolicy::None => Ok((StoredSlotCodec::RawF32, QuantLevel::F32)),
        QuantPolicy::ScalarInt8 => Ok((StoredSlotCodec::ScalarInt8, QuantLevel::Bits8)),
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 16,
        } => Err(invalid(
            "legacy TurboQuant bits_per_channel_x2=16 state was written by the removed Scalar INT8 policy substitution; its intended semantics cannot be inferred from a TurboQuant identity, so migration is refused: re-commission the lens/slot with the explicit QuantPolicy::ScalarInt8 identity and rewrite the column through the versioned compression generation API",
        )),
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 7,
        } => Ok((StoredSlotCodec::TurboQuantBits3p5, QuantLevel::Bits3p5)),
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 5,
        } => Ok((StoredSlotCodec::TurboQuantBits2p5, QuantLevel::Bits2p5)),
        QuantPolicy::TurboQuant {
            bits_per_channel_x2,
        } => Err(invalid(format!(
            "unsupported legacy TurboQuant bits_per_channel_x2 {bits_per_channel_x2}"
        ))),
        QuantPolicy::TurboQuantHadamard {
            bits_per_channel_x2,
        } => Err(invalid(format!(
            "legacy unmanifested structured-Hadamard TurboQuant state cannot be inferred for bits_per_channel_x2={bits_per_channel_x2}; rewrite it through the versioned compression generation API"
        ))),
        QuantPolicy::MxFp4 => Ok((StoredSlotCodec::MxFp4, QuantLevel::Bits4Fp)),
        QuantPolicy::Float8 => Ok((StoredSlotCodec::MxFp8, QuantLevel::Bits8Fp)),
        QuantPolicy::Binary => Ok((StoredSlotCodec::Binary, QuantLevel::Bits1)),
        QuantPolicy::Pq { m, nbits } => Err(invalid(format!(
            "legacy PQ codec is not implemented for m={m} nbits={nbits}; refusing migration"
        ))),
        QuantPolicy::ColbertResidual2Bit => Err(invalid(
            "ColbertResidual2Bit uses the separately versioned Multi generation format and cannot be inferred as a legacy dense envelope",
        )),
    }
}

fn parse_stored_slot_inner(bytes: &[u8], validate_turboquant: bool) -> Result<ParsedStoredSlot> {
    if bytes.first().copied() != Some(COMPRESSED_SLOT_TAG) {
        return Err(invalid(
            "stored slot bytes are missing compressed slot envelope tag",
        ));
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
    if !quant_scale.is_finite() || quant_scale.is_sign_negative() {
        return Err(invalid("quant scale must be finite and non-negative"));
    }
    let mut seed_id = [0_u8; 32];
    seed_id.copy_from_slice(&bytes[17..49]);
    let mut codec_context_id = [0_u8; 32];
    codec_context_id.copy_from_slice(&bytes[49..81]);
    let mut cx_id_bytes = [0_u8; 16];
    cx_id_bytes.copy_from_slice(&bytes[81..97]);
    let cx_id = calyx_core::CxId::from_bytes(cx_id_bytes);
    let mut generation_root = [0_u8; 32];
    generation_root.copy_from_slice(&bytes[97..129]);
    let generation_rows = read_u32(bytes, 129, "generation_rows")?;
    if generation_rows == 0 {
        return Err(invalid("compressed generation row count must be non-zero"));
    }
    let payload_len = read_u32(bytes, 133, "payload_len")? as usize;
    let expected_len = REGISTRY_ENVELOPE_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| invalid("compressed slot payload length overflow"))?;
    if bytes.len() != expected_len {
        return Err(invalid(format!(
            "compressed slot payload length mismatch: header={payload_len} actual={}",
            bytes.len() - REGISTRY_ENVELOPE_HEADER_BYTES
        )));
    }
    validate_payload_layout_before_clone(codec, level, stored_dim as usize, payload_len)?;
    let recorded_digest = &bytes[ENVELOPE_DIGEST_OFFSET..REGISTRY_ENVELOPE_HEADER_BYTES];
    let payload = &bytes[REGISTRY_ENVELOPE_HEADER_BYTES..];
    let computed_digest = envelope_digest(&bytes[..ENVELOPE_PREFIX_BYTES], payload);
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
    validate_payload_without_context(codec, &qv, validate_turboquant)?;
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
            codec_context_id: hex(&codec_context_id),
            cx_id,
            generation_root: hex(&generation_root),
            generation_rows,
            payload_bytes: payload_len,
            record_digest_sha256: hex(&computed_digest),
        },
        qv,
        codec_context_id,
        cx_id,
        generation_root,
        generation_rows,
    })
}

fn validate_payload_layout_before_clone(
    codec: StoredSlotCodec,
    level: QuantLevel,
    dim: usize,
    payload_len: usize,
) -> Result<()> {
    if matches!(codec, StoredSlotCodec::MxFp4 | StoredSlotCodec::MxFp8) {
        let max_dim = match codec {
            StoredSlotCodec::MxFp4 => calyx_forge::MXFP4_MAX_DIM,
            StoredSlotCodec::MxFp8 => calyx_forge::MXFP8_MAX_DIM,
            _ => unreachable!(),
        };
        if dim == 0 || dim > max_dim {
            return Err(invalid(format!(
                "OCP MX dimension must be in 1..={max_dim} before payload allocation, got {dim}"
            )));
        }
        let exact_payload_len = mxfp_payload_len(level, dim).map_err(forge_error)?;
        if payload_len != exact_payload_len {
            return Err(invalid(format!(
                "OCP MX payload length is not canonical for its declared geometry before allocation: header={payload_len} exact={exact_payload_len} dim={dim} level={level:?} format_header={MXFP_FORMAT_HEADER_BYTES}"
            )));
        }
        return Ok(());
    }
    if !matches!(
        codec,
        StoredSlotCodec::TurboQuantBits2p5 | StoredSlotCodec::TurboQuantBits3p5
    ) {
        return Ok(());
    }
    if dim > TURBOQUANT_MAX_DIM {
        return Err(invalid(format!(
            "TurboQuant dimension must be in 1..={TURBOQUANT_MAX_DIM} before payload allocation, got {dim}"
        )));
    }
    let scalar_low_bits = match level {
        QuantLevel::Bits2p5 => 1_usize,
        QuantLevel::Bits3p5 => 2_usize,
        _ => {
            return Err(invalid(format!(
                "TurboQuant envelope has unsupported level {level:?}"
            )));
        }
    };
    let scalar_bits = dim
        .checked_mul(scalar_low_bits)
        .and_then(|base| base.checked_add(dim.div_ceil(2)))
        .ok_or_else(|| invalid("TurboQuant scalar bit count overflow before payload allocation"))?;
    let exact_payload_len = TURBOQUANT_FORMAT_HEADER_BYTES
        .checked_add(scalar_bits.div_ceil(8))
        .and_then(|bytes| bytes.checked_add(dim.div_ceil(8)))
        .ok_or_else(|| invalid("TurboQuant payload length overflow before allocation"))?;
    if payload_len != exact_payload_len {
        return Err(invalid(format!(
            "TurboQuant payload length is not canonical for its declared geometry before allocation: header={payload_len} exact={exact_payload_len} dim={dim} level={level:?}"
        )));
    }
    Ok(())
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
            QuantPolicy::ScalarInt8 => Ok(Self::ScalarInt8(ScalarInt8Codec::new(dim))),
            QuantPolicy::TurboQuant {
                bits_per_channel_x2: 16,
            } => Err(invalid(
                "TurboQuant bits_per_channel_x2=16 was a removed policy substitution that silently selected Scalar INT8; request QuantPolicy::ScalarInt8 explicitly (its own frozen serialized identity) or a real TurboQuant operating point (5 or 7); no codec substitution is performed",
            )),
            QuantPolicy::TurboQuant {
                bits_per_channel_x2,
            } => {
                let level = match bits_per_channel_x2 {
                    7 => QuantLevel::Bits3p5,
                    5 => QuantLevel::Bits2p5,
                    other => {
                        return Err(invalid(format!(
                            "unsupported TurboQuant bits_per_channel_x2 {other}; the only TurboQuant operating points are 5 (2.5 bpc) and 7 (3.5 bpc)"
                        )));
                    }
                };
                let seed = shared_seed(slot, lens, dim, level, b"turboquant-tqpr-v2");
                Ok(Self::TurboQuant(
                    TurboQuantCodec::shared(seed, level).map_err(forge_error)?,
                ))
            }
            QuantPolicy::TurboQuantHadamard {
                bits_per_channel_x2,
            } => {
                let level = match bits_per_channel_x2 {
                    7 => QuantLevel::Bits3p5,
                    5 => QuantLevel::Bits2p5,
                    other => {
                        return Err(invalid(format!(
                            "unsupported structured-Hadamard TurboQuant bits_per_channel_x2 {other}; expected 5 or 7"
                        )));
                    }
                };
                let seed =
                    shared_seed(slot, lens, dim, level, b"turboquant-structured-hadamard-v1");
                Ok(Self::TurboQuant(
                    TurboQuantCodec::shared_structured(seed, level).map_err(forge_error)?,
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
                    attestation_id: evidence.map(MxFp4AssayEvidence::attestation_id),
                })
            }
            QuantPolicy::Float8 => Ok(Self::MxFp8(MxFp8Codec::new(dim))),
            QuantPolicy::Binary => {
                let seed = shared_seed(slot, lens, dim, QuantLevel::Bits1, b"binary");
                Ok(Self::Binary(BinaryCodec::new(seed).map_err(forge_error)?))
            }
            QuantPolicy::Pq { m, nbits } => Err(invalid(format!(
                "PQ codec is not implemented for m={m} nbits={nbits}; refusing codec substitution"
            ))),
            QuantPolicy::ColbertResidual2Bit => Err(invalid(
                "ColbertResidual2Bit is a Multi-only codec; route it through the packed multi-vector generation API",
            )),
        }
    }

    pub(super) fn dim(&self) -> usize {
        match self {
            Self::RawF32 { dim } => *dim,
            Self::TurboQuant(codec) => codec.dim(),
            Self::ScalarInt8(codec) => codec.dim(),
            Self::MxFp4 { codec, .. } => codec.dim(),
            Self::MxFp8(codec) => codec.dim(),
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

    /// Recounts retained codec geometry from the live slice lengths. This is
    /// independent runtime readback for the allocation-free admission planner
    /// and does not include enum/`Arc`/allocator bookkeeping (#1064 PC-37).
    pub(super) fn geometry_physical_bytes(&self) -> Result<u64> {
        let bytes = match self {
            Self::TurboQuant(codec) => codec.geometry_physical_bytes(),
            Self::Binary(codec) => codec.geometry_physical_bytes(),
            Self::RawF32 { .. } | Self::ScalarInt8(_) | Self::MxFp4 { .. } | Self::MxFp8(_) => {
                return Ok(0);
            }
        };
        u64::try_from(bytes).map_err(|_| invalid("live codec geometry byte count exceeds u64"))
    }

    pub(super) fn validate_descriptor(&self, descriptor: CodecDescriptor) -> Result<()> {
        if self.dim() != descriptor.dim()
            || self.stored_codec() != descriptor.stored_codec()
            || self.level() != descriptor.level()
        {
            return Err(invalid(format!(
                "materialized codec does not match pure frozen descriptor: actual codec={:?} level={:?} dim={} descriptor codec={:?} level={:?} dim={}",
                self.stored_codec(),
                self.level(),
                self.dim(),
                descriptor.stored_codec(),
                descriptor.level(),
                descriptor.dim()
            )));
        }
        Ok(())
    }

    fn encode(&self, prepared: &[f32]) -> Result<QuantizedVec> {
        match self {
            Self::RawF32 { dim } => {
                validate_dense(prepared, *dim, "raw encode")?;
                Ok(QuantizedVec {
                    level: QuantLevel::F32,
                    dim: *dim,
                    bytes: raw_f32_payload(prepared),
                    scale: norm_as_f32(l2_norm(prepared)?, "raw source norm")?,
                    seed_id: ZERO_SEED,
                })
            }
            Self::TurboQuant(codec) => codec.encode(prepared).map_err(forge_error),
            Self::ScalarInt8(codec) => codec.encode(prepared).map_err(forge_error),
            Self::MxFp4 {
                codec,
                slot_key,
                safety,
                attestation_id,
            } => codec
                .encode_assay_checked(
                    slot_key,
                    prepared,
                    safety.as_ref().ok_or_else(|| {
                        invalid("MXFP4 write context is missing validated assay evidence")
                    })?,
                    attestation_id.ok_or_else(|| {
                        invalid("MXFP4 write context is missing Assay attestation identity")
                    })?,
                )
                .map_err(forge_error),
            Self::MxFp8(codec) => codec.encode(prepared).map_err(forge_error),
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
            Self::MxFp4 { codec, .. } => codec.decode(&parsed.qv).map_err(forge_error),
            Self::MxFp8(codec) => codec.decode(&parsed.qv).map_err(forge_error),
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
            Self::Binary(codec) => Ok(PreparedSlotQuery::Binary {
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
            (Self::TurboQuant(codec), PreparedSlotQuery::TurboQuant { query, norm }) => {
                if *norm == 0.0 || parsed.qv.scale == 0.0 {
                    return Ok(0.0);
                }
                let candidate = codec.validate_candidate(&parsed.qv).map_err(forge_error)?;
                let dot = codec
                    .dot_estimate_validated(query, &candidate)
                    .map_err(forge_error)?;
                finite_score(
                    f64::from(dot) / (*norm * f64::from(parsed.qv.scale)),
                    "TurboQuant cosine score",
                )
            }
            (Self::RawF32 { .. }, PreparedSlotQuery::Dense { values, .. }) => {
                let candidate = decode_raw_f32(&parsed.qv.bytes, parsed.qv.dim)?;
                cosine(values, &candidate)
            }
            (Self::ScalarInt8(codec), PreparedSlotQuery::Dense { values, norm }) => {
                score_decoded(codec, values, *norm, &parsed.qv)
            }
            (Self::MxFp4 { codec, .. }, PreparedSlotQuery::Dense { values, norm }) => {
                score_mxfp(codec.dot_and_norm(values, &parsed.qv), *norm)
            }
            (Self::MxFp8(codec), PreparedSlotQuery::Dense { values, norm }) => {
                score_mxfp(codec.dot_and_norm(values, &parsed.qv), *norm)
            }
            (Self::Binary(codec), PreparedSlotQuery::Binary { query, norm }) => {
                if *norm == 0.0 {
                    return Ok(0.0);
                }
                finite_score(
                    f64::from(
                        codec
                            .score_prepared(query, &parsed.qv)
                            .map_err(forge_error)?,
                    ) / *norm,
                    "binary cosine score",
                )
            }
            _ => Err(invalid(
                "prepared query does not belong to this codec context",
            )),
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
                if parsed.qv.seed_id != codec.geometry_id() {
                    return Err(invalid(
                        "persisted TurboQuant geometry identity does not match frozen slot/lens",
                    ));
                }
            }
            Self::Binary(codec) => {
                if parsed.qv.seed_id != codec.seed().id {
                    return Err(invalid(
                        "persisted binary seed does not match frozen slot/lens",
                    ));
                }
                let expected_scale = 1.0 / (parsed.qv.dim as f32).sqrt();
                if parsed.qv.scale.to_bits() != expected_scale.to_bits() {
                    return Err(invalid("persisted binary amplitude is not canonical"));
                }
            }
            Self::MxFp4 { .. } => {
                if parsed.qv.seed_id == ZERO_SEED {
                    return Err(invalid(
                        "persisted MXFP4 payload is missing its Assay attestation identity",
                    ));
                }
            }
            Self::RawF32 { .. } | Self::ScalarInt8(_) | Self::MxFp8(_) => {
                if parsed.qv.seed_id != ZERO_SEED {
                    return Err(invalid(
                        "persisted non-rotating codec requires a zero seed id",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn validate_payload(&self, parsed: &ParsedStoredSlot) -> Result<()> {
        self.validate_parsed(parsed)?;
        match self {
            Self::TurboQuant(codec) => {
                codec.storage(&parsed.qv).map_err(forge_error)?;
            }
            Self::MxFp4 { codec, .. } => {
                codec.inspect(&parsed.qv).map_err(forge_error)?;
            }
            Self::MxFp8(codec) => {
                codec.inspect(&parsed.qv).map_err(forge_error)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn storage_metrics(&self, qv: &QuantizedVec) -> Result<StorageMetrics> {
        match self {
            Self::TurboQuant(codec) => {
                let metrics = codec.storage(qv).map_err(forge_error)?;
                return Ok(StorageMetrics {
                    logical_data_bits: metrics.data_bits as u64,
                    codec_header_bytes: metrics.format_header_bytes,
                });
            }
            Self::MxFp4 { codec, .. } => {
                let metrics = codec.inspect(qv).map_err(forge_error)?;
                return Ok(StorageMetrics {
                    logical_data_bits: (qv.dim as u64) * 4,
                    codec_header_bytes: metrics.format_header_bytes + metrics.scale_bytes,
                });
            }
            Self::MxFp8(codec) => {
                let metrics = codec.inspect(qv).map_err(forge_error)?;
                return Ok(StorageMetrics {
                    logical_data_bits: (qv.dim as u64) * 8,
                    codec_header_bytes: metrics.format_header_bytes + metrics.scale_bytes,
                });
            }
            _ => {}
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
    query_norm: f64,
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
    finite_score(
        f64::from(dot) / (query_norm * candidate_norm),
        "decoded cosine score",
    )
}

fn score_mxfp(packed: calyx_forge::Result<(f32, f64)>, query_norm: f64) -> Result<f32> {
    if query_norm == 0.0 {
        return Ok(0.0);
    }
    let (dot, candidate_norm_sq) = packed.map_err(forge_error)?;
    if candidate_norm_sq == 0.0 {
        return Ok(0.0);
    }
    finite_score(
        f64::from(dot) / (query_norm * candidate_norm_sq.sqrt()),
        "packed OCP MX cosine score",
    )
}

pub(super) fn validate_context(slot: &Slot, lens: &LensSpec, policy: QuantPolicy) -> Result<usize> {
    if slot.slot_key.id() != slot.slot_id {
        return Err(invalid(format!(
            "slot key id {} does not match slot id {}",
            slot.slot_key.id(),
            slot.slot_id
        )));
    }
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
    if slot.modality != lens.modality {
        return Err(invalid(format!(
            "slot modality {:?} does not match frozen lens modality {:?}",
            slot.modality, lens.modality
        )));
    }
    if slot.asymmetry != lens.asymmetry {
        return Err(invalid(format!(
            "slot asymmetry {:?} does not match frozen lens asymmetry {:?}",
            slot.asymmetry, lens.asymmetry
        )));
    }
    if slot.axis != lens.axis {
        return Err(invalid(format!(
            "slot axis {:?} does not match frozen lens axis {:?}",
            slot.axis, lens.axis
        )));
    }
    if slot.retrieval_only != lens.retrieval_only {
        return Err(invalid(format!(
            "slot retrieval_only={} does not match frozen lens retrieval_only={}",
            slot.retrieval_only, lens.retrieval_only
        )));
    }
    if slot.excluded_from_dedup != lens.excluded_from_dedup {
        return Err(invalid(format!(
            "slot excluded_from_dedup={} does not match frozen lens excluded_from_dedup={}",
            slot.excluded_from_dedup, lens.excluded_from_dedup
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
    if !lens.recall_delta.is_finite()
        || !(0.0..=1.0).contains(&lens.recall_delta)
        || (lens.recall_delta == 0.0 && lens.recall_delta.is_sign_negative())
    {
        return Err(invalid(format!(
            "lens recall_delta must be finite, within [0,1], and canonical +0.0 when zero; got {}",
            lens.recall_delta
        )));
    }
    let stored_dim = lens.truncate_dim.unwrap_or(raw_dim);
    if stored_dim == 0
        || stored_dim > raw_dim
        || lens.truncate_dim.is_some_and(|dim| dim == raw_dim)
    {
        return Err(invalid(format!(
            "truncate_dim {:?} is invalid for raw dimension {raw_dim}; omit it when no strict prefix reduction is intended",
            lens.truncate_dim
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
    shared_seed_for_lens_id(lens.lens_id(), slot, dim, level, codec_domain)
}

fn shared_seed_for_lens_id(
    lens_id: calyx_core::LensId,
    slot: &Slot,
    dim: usize,
    level: QuantLevel,
    codec_domain: &[u8],
) -> calyx_forge::RotationSeed {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"calyx-registry-shared-codec-v2");
    hasher.update(&(codec_domain.len() as u64).to_be_bytes());
    hasher.update(codec_domain);
    hasher.update(lens_id.as_bytes());
    hasher.update(&slot.slot_id.get().to_be_bytes());
    hasher.update(&(slot.slot_key.key().len() as u64).to_be_bytes());
    hasher.update(slot.slot_key.key().as_bytes());
    hasher.update(&(dim as u64).to_be_bytes());
    hasher.update(&[level_code(level)]);
    new_seed(dim, hasher.finalize().as_bytes())
}

pub(super) fn codec_context_id(
    slot: &Slot,
    lens: &LensSpec,
    codec: &CodecContext,
) -> Result<[u8; 32]> {
    let descriptor = CodecDescriptor::for_read(slot, lens)?;
    codec.validate_descriptor(descriptor)?;
    codec_context_id_for_descriptor(slot, lens, descriptor)
}

pub(super) fn codec_context_id_for_descriptor(
    slot: &Slot,
    lens: &LensSpec,
    descriptor: CodecDescriptor,
) -> Result<[u8; 32]> {
    let SlotShape::Dense(raw_dim) = slot.shape else {
        return Err(invalid("codec context requires a dense slot"));
    };
    let mut hasher = Sha256::new();
    hasher.update(CODEC_CONTEXT_DOMAIN);
    hasher.update([COMPRESSED_SLOT_VERSION]);
    hasher.update(lens.lens_id().as_bytes());
    hasher.update(slot.slot_id.get().to_be_bytes());
    hasher.update(slot.slot_key.id().get().to_be_bytes());
    hasher.update((slot.slot_key.key().len() as u64).to_be_bytes());
    hasher.update(slot.slot_key.key().as_bytes());
    hasher.update(raw_dim.to_be_bytes());
    hasher.update((descriptor.dim() as u64).to_be_bytes());
    hasher.update([
        codec_code(descriptor.stored_codec()),
        level_code(descriptor.level()),
    ]);
    hasher.update([modality_code(slot.modality)]);
    match slot.asymmetry {
        Asymmetry::None => {
            hasher.update([0]);
        }
        Asymmetry::Dual { a, b } => {
            hasher.update([1]);
            hasher.update(a.get().to_be_bytes());
            hasher.update(b.get().to_be_bytes());
        }
    };
    match &slot.axis {
        None => {
            hasher.update([0]);
        }
        Some(axis) => {
            hasher.update([1]);
            hasher.update((axis.len() as u64).to_be_bytes());
            hasher.update(axis.as_bytes());
        }
    };
    hasher.update([u8::from(slot.retrieval_only)]);
    hasher.update([u8::from(slot.excluded_from_dedup)]);
    match lens.truncate_dim {
        None => {
            hasher.update([0]);
        }
        Some(dim) => {
            hasher.update([1]);
            hasher.update(dim.to_be_bytes());
        }
    };
    hasher.update(lens.recall_delta.to_bits().to_be_bytes());
    Ok(hasher.finalize().into())
}

fn current_policy_identity(policy: QuantPolicy) -> Result<(StoredSlotCodec, QuantLevel)> {
    match policy {
        QuantPolicy::None => Ok((StoredSlotCodec::RawF32, QuantLevel::F32)),
        QuantPolicy::ScalarInt8 => Ok((StoredSlotCodec::ScalarInt8, QuantLevel::Bits8)),
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 7,
        }
        | QuantPolicy::TurboQuantHadamard {
            bits_per_channel_x2: 7,
        } => Ok((StoredSlotCodec::TurboQuantBits3p5, QuantLevel::Bits3p5)),
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 5,
        }
        | QuantPolicy::TurboQuantHadamard {
            bits_per_channel_x2: 5,
        } => Ok((StoredSlotCodec::TurboQuantBits2p5, QuantLevel::Bits2p5)),
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 16,
        } => Err(invalid(
            "TurboQuant bits_per_channel_x2=16 was a removed policy substitution; request ScalarInt8 or a real TurboQuant operating point",
        )),
        QuantPolicy::TurboQuant {
            bits_per_channel_x2,
        } => Err(invalid(format!(
            "unsupported TurboQuant bits_per_channel_x2 {bits_per_channel_x2}; expected 5 or 7"
        ))),
        QuantPolicy::TurboQuantHadamard {
            bits_per_channel_x2,
        } => Err(invalid(format!(
            "unsupported structured-Hadamard TurboQuant bits_per_channel_x2 {bits_per_channel_x2}; expected 5 or 7"
        ))),
        QuantPolicy::MxFp4 => Ok((StoredSlotCodec::MxFp4, QuantLevel::Bits4Fp)),
        QuantPolicy::Float8 => Ok((StoredSlotCodec::MxFp8, QuantLevel::Bits8Fp)),
        QuantPolicy::Binary => Ok((StoredSlotCodec::Binary, QuantLevel::Bits1)),
        QuantPolicy::Pq { m, nbits } => Err(invalid(format!(
            "PQ codec is not implemented for m={m} nbits={nbits}; refusing codec substitution"
        ))),
        QuantPolicy::ColbertResidual2Bit => Err(invalid(
            "ColbertResidual2Bit is a Multi-only codec; route it through the packed multi-vector generation API",
        )),
    }
}

const fn modality_code(modality: Modality) -> u8 {
    match modality {
        Modality::Text => 0,
        Modality::Code => 1,
        Modality::Image => 2,
        Modality::Audio => 3,
        Modality::Video => 4,
        Modality::Protein => 5,
        Modality::Dna => 6,
        Modality::Molecule => 7,
        Modality::Structured => 8,
        Modality::Mixed => 9,
    }
}

pub(super) fn generation_root<'a>(
    codec_context_id: &[u8; 32],
    generation_rows: u32,
    rows: impl IntoIterator<Item = (calyx_core::CxId, &'a QuantizedVec)>,
) -> Result<[u8; 32]> {
    let mut rows = rows.into_iter().collect::<Vec<_>>();
    rows.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    if rows.len() != generation_rows as usize {
        return Err(invalid(format!(
            "generation root row count mismatch: declared={generation_rows} actual={}",
            rows.len()
        )));
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].0.as_bytes() == pair[1].0.as_bytes())
    {
        return Err(invalid("generation root contains duplicate CxId keys"));
    }
    let mut hasher = Sha256::new();
    hasher.update(GENERATION_ROOT_DOMAIN);
    hasher.update(codec_context_id);
    hasher.update(generation_rows.to_be_bytes());
    for (cx_id, qv) in rows {
        hasher.update(cx_id.as_bytes());
        hasher.update([level_code(qv.level)]);
        hasher.update((qv.dim as u64).to_be_bytes());
        hasher.update(qv.scale.to_bits().to_be_bytes());
        hasher.update(qv.seed_id);
        hasher.update((qv.bytes.len() as u64).to_be_bytes());
        hasher.update(&qv.bytes);
    }
    Ok(hasher.finalize().into())
}

pub(super) fn raw_generation_root<'a>(
    codec_context_id: &[u8; 32],
    generation_rows: u32,
    rows: impl IntoIterator<Item = (calyx_core::CxId, &'a [u8])>,
) -> Result<[u8; 32]> {
    let mut rows = rows.into_iter().collect::<Vec<_>>();
    rows.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    if rows.len() != generation_rows as usize {
        return Err(invalid(format!(
            "raw generation root row count mismatch: declared={generation_rows} actual={}",
            rows.len()
        )));
    }
    if rows
        .windows(2)
        .any(|pair| pair[0].0.as_bytes() == pair[1].0.as_bytes())
    {
        return Err(invalid("raw generation root contains duplicate CxId keys"));
    }
    let mut hasher = Sha256::new();
    hasher.update(RAW_GENERATION_ROOT_DOMAIN);
    hasher.update(codec_context_id);
    hasher.update(generation_rows.to_be_bytes());
    for (cx_id, raw) in rows {
        hasher.update(cx_id.as_bytes());
        hasher.update((raw.len() as u64).to_be_bytes());
        hasher.update(raw);
    }
    Ok(hasher.finalize().into())
}

fn encode_manifest(manifest: &CompressionManifest) -> Result<Vec<u8>> {
    validate_codec_level(manifest.codec, manifest.level)?;
    if manifest.raw_dim == 0
        || manifest.stored_dim == 0
        || manifest.stored_dim > manifest.raw_dim
        || manifest.generation_rows == 0
    {
        return Err(invalid(format!(
            "invalid compression manifest geometry raw_dim={} stored_dim={} rows={}",
            manifest.raw_dim, manifest.stored_dim, manifest.generation_rows
        )));
    }
    if manifest.membership_version != COMPRESSION_MEMBERSHIP_VERSION {
        return Err(invalid(format!(
            "unsupported compression membership version {}; expected {COMPRESSION_MEMBERSHIP_VERSION}",
            manifest.membership_version
        )));
    }
    if manifest.codec == StoredSlotCodec::MxFp4 {
        if manifest.assay_attestation_id == [0; 32] {
            return Err(invalid(
                "MXFP4 compression manifest is missing its Assay attestation identity",
            ));
        }
    } else if manifest.assay_attestation_id != [0; 32] {
        return Err(invalid(
            "non-MXFP4 compression manifest carries an Assay attestation identity",
        ));
    }
    let mut bytes = Vec::with_capacity(MANIFEST_BYTES);
    bytes.extend_from_slice(MANIFEST_MAGIC);
    bytes.push(MANIFEST_VERSION);
    bytes.push(codec_code(manifest.codec));
    bytes.push(level_code(manifest.level));
    bytes.push(0);
    bytes.extend_from_slice(&manifest.raw_dim.to_be_bytes());
    bytes.extend_from_slice(&manifest.stored_dim.to_be_bytes());
    bytes.extend_from_slice(&manifest.codec_context_id);
    bytes.extend_from_slice(&manifest.generation_root);
    bytes.extend_from_slice(&manifest.raw_generation_root);
    bytes.extend_from_slice(&manifest.generation_rows.to_be_bytes());
    bytes.push(manifest.membership_version);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&manifest.membership_root);
    bytes.extend_from_slice(&manifest.assay_attestation_id);
    if bytes.len() != MANIFEST_PREFIX_BYTES {
        return Err(invalid(
            "internal compression manifest prefix length mismatch",
        ));
    }
    let digest = manifest_digest(&bytes);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

pub(super) fn parse_compression_manifest(bytes: &[u8]) -> Result<CompressionManifest> {
    if bytes.len() < 5 {
        return Err(invalid(format!(
            "compression manifest is too short to carry its magic and version: got {} bytes",
            bytes.len()
        )));
    }
    if &bytes[..4] != MANIFEST_MAGIC {
        return Err(invalid("compression manifest magic mismatch"));
    }
    if bytes[4] != MANIFEST_VERSION {
        return Err(invalid(format!(
            "unsupported compression manifest version {}; expected {MANIFEST_VERSION}; re-commission or re-ingest the generation to bind authenticated point reads to their exact Assay attestation",
            bytes[4]
        )));
    }
    if bytes.len() != MANIFEST_BYTES {
        return Err(invalid(format!(
            "compression manifest length must be {MANIFEST_BYTES} bytes, got {}",
            bytes.len()
        )));
    }
    let codec = decode_codec(bytes[5])?;
    let level = decode_level(bytes[6])?;
    validate_codec_level(codec, level)?;
    if bytes[7] != 0 {
        return Err(invalid("compression manifest reserved flags must be zero"));
    }
    let raw_dim = read_u32(bytes, 8, "manifest_raw_dim")?;
    let stored_dim = read_u32(bytes, 12, "manifest_stored_dim")?;
    let generation_rows = read_u32(bytes, 112, "manifest_generation_rows")?;
    let membership_version = bytes[116];
    if raw_dim == 0 || stored_dim == 0 || stored_dim > raw_dim || generation_rows == 0 {
        return Err(invalid(format!(
            "invalid compression manifest geometry raw_dim={raw_dim} stored_dim={stored_dim} rows={generation_rows}"
        )));
    }
    if membership_version != COMPRESSION_MEMBERSHIP_VERSION {
        return Err(invalid(format!(
            "unsupported compression membership version {membership_version}; expected {COMPRESSION_MEMBERSHIP_VERSION}"
        )));
    }
    if bytes[117..120].iter().any(|byte| *byte != 0) {
        return Err(invalid(
            "compression manifest membership reserved bytes must be zero",
        ));
    }
    let computed = manifest_digest(&bytes[..MANIFEST_PREFIX_BYTES]);
    if bytes[MANIFEST_PREFIX_BYTES..] != computed {
        return Err(invalid(format!(
            "compression manifest SHA-256 mismatch: recorded={} computed={}",
            hex(&bytes[MANIFEST_PREFIX_BYTES..]),
            hex(&computed)
        )));
    }
    let mut codec_context_id = [0_u8; 32];
    codec_context_id.copy_from_slice(&bytes[16..48]);
    let mut generation_root = [0_u8; 32];
    generation_root.copy_from_slice(&bytes[48..80]);
    let mut raw_generation_root = [0_u8; 32];
    raw_generation_root.copy_from_slice(&bytes[80..112]);
    let mut membership_root = [0_u8; 32];
    membership_root.copy_from_slice(&bytes[120..152]);
    let mut assay_attestation_id = [0_u8; 32];
    assay_attestation_id.copy_from_slice(&bytes[152..184]);
    if codec == StoredSlotCodec::MxFp4 {
        if assay_attestation_id == [0; 32] {
            return Err(invalid(
                "MXFP4 compression manifest is missing its Assay attestation identity",
            ));
        }
    } else if assay_attestation_id != [0; 32] {
        return Err(invalid(
            "non-MXFP4 compression manifest carries an Assay attestation identity",
        ));
    }
    Ok(CompressionManifest {
        codec,
        level,
        raw_dim,
        stored_dim,
        codec_context_id,
        generation_root,
        raw_generation_root,
        generation_rows,
        membership_version,
        membership_root,
        assay_attestation_id,
    })
}

fn encode_envelope(
    codec: StoredSlotCodec,
    qv: &QuantizedVec,
    raw_dim: u32,
    codec_context_id: [u8; 32],
    cx_id: calyx_core::CxId,
    generation_root: [u8; 32],
    generation_rows: u32,
) -> Result<Vec<u8>> {
    validate_codec_level(codec, qv.level)?;
    if qv.dim == 0 || qv.dim > raw_dim as usize {
        return Err(invalid(format!(
            "cannot envelope raw_dim={raw_dim} stored_dim={}",
            qv.dim
        )));
    }
    if !qv.scale.is_finite() || qv.scale.is_sign_negative() {
        return Err(invalid(
            "encoded quant scale must be finite and non-negative",
        ));
    }
    if generation_rows == 0 {
        return Err(invalid("compressed generation row count must be non-zero"));
    }
    let stored_dim = u32::try_from(qv.dim)
        .map_err(|_| invalid(format!("stored dimension {} exceeds u32", qv.dim)))?;
    let payload_len = u32::try_from(qv.bytes.len()).map_err(|_| {
        invalid(format!(
            "codec payload {} bytes exceeds u32",
            qv.bytes.len()
        ))
    })?;
    let mut prefix = Vec::with_capacity(ENVELOPE_PREFIX_BYTES);
    prefix.push(COMPRESSED_SLOT_TAG);
    prefix.push(COMPRESSED_SLOT_VERSION);
    prefix.push(codec_code(codec));
    prefix.push(level_code(qv.level));
    prefix.extend_from_slice(&raw_dim.to_be_bytes());
    prefix.extend_from_slice(&stored_dim.to_be_bytes());
    prefix.push(u8::from(stored_dim < raw_dim) << 1);
    prefix.extend_from_slice(&qv.scale.to_bits().to_be_bytes());
    prefix.extend_from_slice(&qv.seed_id);
    prefix.extend_from_slice(&codec_context_id);
    prefix.extend_from_slice(cx_id.as_bytes());
    prefix.extend_from_slice(&generation_root);
    prefix.extend_from_slice(&generation_rows.to_be_bytes());
    prefix.extend_from_slice(&payload_len.to_be_bytes());
    if prefix.len() != ENVELOPE_PREFIX_BYTES {
        return Err(invalid(
            "internal compressed envelope prefix length mismatch",
        ));
    }
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

fn validate_payload_without_context(
    codec: StoredSlotCodec,
    qv: &QuantizedVec,
    validate_turboquant: bool,
) -> Result<()> {
    match codec {
        StoredSlotCodec::RawF32 => {
            if qv.seed_id != ZERO_SEED {
                return Err(invalid("raw f32 payload requires a zero seed id"));
            }
            let decoded = decode_raw_f32(&qv.bytes, qv.dim)?;
            let expected = norm_as_f32(l2_norm(&decoded)?, "raw payload norm")?;
            if qv.scale.to_bits() != expected.to_bits() {
                return Err(invalid(format!(
                    "raw f32 payload norm is not canonical: recorded_bits=0x{:08x} expected_bits=0x{:08x}",
                    qv.scale.to_bits(),
                    expected.to_bits()
                )));
            }
        }
        StoredSlotCodec::TurboQuantBits3p5 | StoredSlotCodec::TurboQuantBits2p5 => {
            if validate_turboquant {
                TurboQuantCodec::inspect(qv).map_err(forge_error)?;
            }
        }
        StoredSlotCodec::ScalarInt8 => {
            ScalarInt8Codec::new(qv.dim)
                .decode(qv)
                .map_err(forge_error)?;
        }
        StoredSlotCodec::MxFp4 => {
            MxFp4Codec::new(qv.dim).decode(qv).map_err(forge_error)?;
        }
        StoredSlotCodec::MxFp8 => {
            MxFp8Codec::new(qv.dim).decode(qv).map_err(forge_error)?;
        }
        StoredSlotCodec::Binary => {
            let expected = qv.dim.div_ceil(8);
            if qv.bytes.len() != expected {
                return Err(invalid(format!(
                    "binary payload length mismatch: expected {expected} got {}",
                    qv.bytes.len()
                )));
            }
            let expected_scale = 1.0 / (qv.dim as f32).sqrt();
            if qv.scale.to_bits() != expected_scale.to_bits() {
                return Err(invalid("binary payload amplitude is not canonical"));
            }
            let used = qv.dim % 8;
            if used != 0 {
                let padding_mask = !((1_u16 << used) - 1) as u8;
                if qv.bytes.last().is_some_and(|last| last & padding_mask != 0) {
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

fn l2_norm(values: &[f32]) -> Result<f64> {
    let sum = values
        .iter()
        .try_fold(0.0_f64, |sum, value| {
            let next = sum + f64::from(*value) * f64::from(*value);
            next.is_finite().then_some(next)
        })
        .ok_or_else(|| invalid("vector L2 norm overflowed"))?;
    let norm = sum.sqrt();
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
        .try_fold(0.0_f64, |sum, (lhs, rhs)| {
            let next = sum + f64::from(*lhs) * f64::from(*rhs);
            next.is_finite().then_some(next)
        })
        .ok_or_else(|| invalid("cosine dot product overflowed"))?;
    finite_score(dot / (lhs_norm * rhs_norm), "raw cosine score")
}

fn norm_as_f32(norm: f64, field: &str) -> Result<f32> {
    if !norm.is_finite() || norm > f64::from(f32::MAX) {
        return Err(invalid(format!(
            "{field} cannot be represented as a finite f32"
        )));
    }
    Ok(norm as f32)
}

fn finite_score(score: f64, field: &str) -> Result<f32> {
    if !score.is_finite() || score.abs() > f64::from(f32::MAX) {
        return Err(invalid(format!(
            "{field} cannot be represented as a finite f32"
        )));
    }
    Ok(score as f32)
}

fn envelope_digest(prefix: &[u8], payload: &[u8]) -> [u8; 32] {
    envelope_digest_with_domain(ENVELOPE_HASH_DOMAIN, prefix, payload)
}

fn envelope_digest_with_domain(domain: &[u8], prefix: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn manifest_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_HASH_DOMAIN);
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
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
