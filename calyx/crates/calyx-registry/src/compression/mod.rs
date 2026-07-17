mod codec;
mod index;
mod recall;

use calyx_aster::cf::{
    COMPRESSED_SLOT_VALUE_TAG, ColumnFamily, base_key, compression_manifest_key, slot_key,
};
use calyx_aster::vault::{AsterVault, encode};
use calyx_core::{Clock, CxId, LensId, QuantPolicy, Result, Seq, Slot, SlotVector};
use calyx_forge::AssayQuantSafety;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::spec::LensSpec;
pub use codec::inspect_unbound_stored_slot_envelope;
use codec::{EncodedBatch, LegacyV2EnvelopeVerifier, encode_rows};
pub use index::{CompressedSlotHit, CompressedSlotIndex};
pub use recall::matryoshka_truncate_renormalize;
use recall::{recall_at_k, recall_drop, validate_batch};

pub const CALYX_VECTOR_COMPRESSION_EMPTY: &str = "CALYX_VECTOR_COMPRESSION_EMPTY";
pub const CALYX_VECTOR_COMPRESSION_INVALID: &str = "CALYX_VECTOR_COMPRESSION_INVALID";
pub const COMPRESSED_SLOT_TAG: u8 = COMPRESSED_SLOT_VALUE_TAG;
pub const COMPRESSED_SLOT_VERSION: u8 = 3;
pub const REGISTRY_ENVELOPE_HEADER_BYTES: usize = 169;
pub(super) const LEGACY_COMPRESSED_SLOT_VERSION: u8 = 2;
pub(super) const LEGACY_REGISTRY_ENVELOPE_HEADER_BYTES: usize = 85;
const COMPRESSION_REMEDIATION: &str = "Re-encode finite dense vectors with the exact lens/slot codec context and inspect the reported envelope field";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredSlotCodec {
    RawF32,
    TurboQuantBits3p5,
    TurboQuantBits2p5,
    ScalarInt8,
    MxFp4,
    MxFp8,
    Binary,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlotCompressionRow {
    pub cx_id: CxId,
    pub raw_bytes: Vec<u8>,
    pub compressed_bytes: Vec<u8>,
    pub stored_dim: u32,
    pub codec: StoredSlotCodec,
}

/// Independently identified query used for recall admission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressionQuery {
    pub cx_id: CxId,
    pub values: Vec<f32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlotCompressionReport {
    pub slot_id: u16,
    pub slot_key: String,
    pub requested_quant: QuantPolicy,
    pub stored_codec: StoredSlotCodec,
    pub fallback_reason: Option<String>,
    /// Independently encoded original SlotVector rows retained in `slot_*.raw`.
    pub raw_bytes_total: usize,
    /// Complete compressed rows, including the registry envelope.
    pub stored_bytes_total: usize,
    /// Codec payload bytes inside the registry envelope.
    pub codec_payload_bytes_total: usize,
    /// Fixed registry envelope bytes across all rows.
    pub registry_envelope_bytes_total: usize,
    /// Atomic whole-column generation manifest bytes.
    pub generation_manifest_bytes_total: usize,
    /// Codec-format headers inside the payload (for TurboQuant, TQPR headers).
    pub codec_header_bytes_total: usize,
    /// Scalar-index plus QJL data bits, excluding every fixed header and norm.
    pub logical_data_bits_total: u64,
    /// Raw-sidecar and compressed-envelope value bytes submitted to the vault.
    /// This excludes keys and storage-engine/WAL framing, which must be measured
    /// from the durable vault when physical storage is reported.
    pub written_value_bytes_total: usize,
    /// Logical product-code bits per stored coefficient.
    pub logical_data_bits_per_channel: f32,
    /// Complete codec payload bits per stored coefficient.
    pub codec_payload_bits_per_channel: f32,
    /// Written value bits per stored coefficient, excluding keys and engine framing.
    pub written_value_bits_per_channel: f32,
    pub recall_at_k_raw: f32,
    pub recall_at_k_compressed: f32,
    /// Positive means recall was lost relative to the raw vectors.
    pub recall_drop: f32,
    pub truncate_dim: Option<u32>,
    pub rows: Vec<SlotCompressionRow>,
    /// Exact manifest value committed with the compressed and raw columns.
    pub generation_manifest_bytes: Vec<u8>,
    pub snapshot: Option<Seq>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredSlotEnvelope {
    pub format_version: u8,
    pub codec: StoredSlotCodec,
    pub level: String,
    pub raw_dim: u32,
    pub stored_dim: u32,
    pub truncated: bool,
    /// Codec scale field; TurboQuant defines this as the original L2 norm.
    pub quant_scale: f32,
    pub seed_id: String,
    pub codec_context_id: String,
    pub cx_id: CxId,
    pub generation_root: String,
    pub generation_rows: u32,
    pub payload_bytes: usize,
    /// Domain-separated digest of the envelope prefix and codec payload.
    pub record_digest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MxFp4AssayEvidence {
    pub slot_id: u16,
    pub slot_key: String,
    pub lens_id: LensId,
    pub dim: u32,
    pub written_at_seq: Seq,
    pub current_seq: Seq,
    pub safety: AssayQuantSafety,
}

impl MxFp4AssayEvidence {
    pub fn validate<'a>(
        &'a self,
        slot: &Slot,
        lens: &LensSpec,
        stored_dim: u32,
    ) -> Result<&'a AssayQuantSafety> {
        let lens_id = lens.lens_id();
        if self.slot_id != slot.slot_id.get() {
            return Err(mxfp4_evidence_error(format!(
                "wrong slot id: evidence={} requested={}",
                self.slot_id,
                slot.slot_id.get()
            )));
        }
        if self.slot_key != slot.slot_key.key() {
            return Err(mxfp4_evidence_error(format!(
                "wrong slot key: evidence={} requested={}",
                self.slot_key,
                slot.slot_key.key()
            )));
        }
        if self.lens_id != lens_id {
            return Err(mxfp4_evidence_error(format!(
                "wrong lens id: evidence={} requested={lens_id}",
                self.lens_id
            )));
        }
        if self.dim != stored_dim {
            return Err(mxfp4_evidence_error(format!(
                "wrong dim: evidence={} requested={stored_dim}",
                self.dim
            )));
        }
        if self.written_at_seq != self.current_seq {
            return Err(mxfp4_evidence_error(format!(
                "stale assay evidence: written_at_seq={} current_seq={}",
                self.written_at_seq, self.current_seq
            )));
        }
        if !self.safety.passes() {
            return Err(mxfp4_evidence_error(
                "assay safety metrics failed MXFP4 thresholds",
            ));
        }
        Ok(&self.safety)
    }
}

pub(crate) fn write_compressed_slot_batch<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[CompressionQuery],
    k: usize,
) -> Result<SlotCompressionReport> {
    write_compressed_slot_batch_with_assay_evidence(vault, slot, lens, rows, queries, k, None)
}

pub(crate) fn write_compressed_slot_batch_with_assay_evidence<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[CompressionQuery],
    k: usize,
    mxfp4_evidence: Option<&MxFp4AssayEvidence>,
) -> Result<SlotCompressionReport> {
    let expected_seq = validate_full_column_rewrite(vault, slot, lens, rows)?;
    if lens.quant_default == QuantPolicy::MxFp4
        && let Some(evidence) = mxfp4_evidence
        && evidence.current_seq != expected_seq
    {
        return Err(mxfp4_evidence_error(format!(
            "assay evidence current_seq={} does not match vault seq={expected_seq}",
            evidence.current_seq
        )));
    }
    let mut report =
        compress_slot_batch_with_assay_evidence(slot, lens, rows, queries, k, mxfp4_evidence)?;
    let write_capacity = report
        .rows
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed write batch row-count overflow",
            )
        })?;
    let mut writes = Vec::with_capacity(write_capacity);
    for row in &report.rows {
        let key = slot_key(row.cx_id);
        writes.push((
            ColumnFamily::slot_raw(slot.slot_id),
            key.clone(),
            row.raw_bytes.clone(),
        ));
        writes.push((
            ColumnFamily::slot(slot.slot_id),
            key,
            row.compressed_bytes.clone(),
        ));
    }
    writes.push((
        ColumnFamily::Compression,
        compression_manifest_key(slot.slot_id),
        report.generation_manifest_bytes.clone(),
    ));
    report.snapshot = Some(vault.write_cf_batch_if_seq(expected_seq, writes)?);
    Ok(report)
}

fn validate_full_column_rewrite<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
) -> Result<Seq> {
    let snapshot = vault.latest_seq();
    let mut incoming = std::collections::BTreeMap::new();
    let mut incoming_values = std::collections::BTreeMap::new();
    for (cx_id, values) in rows {
        let dim = u32::try_from(values.len()).map_err(|_| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "incoming raw vector dimension exceeds u32",
            )
        })?;
        let key = slot_key(*cx_id);
        let value = encode::encode_slot_vector(&SlotVector::Dense {
            dim,
            data: values.clone(),
        })?;
        let actual_hash = blake3::hash(&value);
        if incoming.insert(key.clone(), value).is_some() {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed full-column rewrite contains duplicate CxId keys",
            ));
        }
        incoming_values.insert(key.clone(), values.as_slice());
        let base_bytes = vault
            .read_cf_at(snapshot, ColumnFamily::Base, &base_key(*cx_id))?
            .ok_or_else(|| {
                compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    format!(
                        "compressed slot source {cx_id} has no Base constellation at seq={snapshot}"
                    ),
                )
            })?;
        let base_identity = encode::decode_constellation_base_identity(&base_bytes)?;
        if base_identity.cx_id != *cx_id {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "compressed slot source Base identity mismatch at seq={snapshot}: key_cx_id={cx_id} embedded_cx_id={}",
                    base_identity.cx_id
                ),
            ));
        }
        let expected_hash = base_identity
            .slot_hashes
            .get(&slot.slot_id)
            .ok_or_else(|| {
                compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    format!(
                        "compressed slot source {cx_id} Base constellation does not declare slot {} at seq={snapshot}",
                        slot.slot_id.get()
                    ),
                )
            })?;
        if actual_hash.as_bytes() != expected_hash {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "compressed slot source {cx_id} slot {} does not match the immutable Base slot hash at seq={snapshot}: expected={} actual={}",
                    slot.slot_id.get(),
                    blake3::Hash::from_bytes(*expected_hash).to_hex(),
                    actual_hash.to_hex()
                ),
            ));
        }
    }
    if incoming.is_empty() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            "compressed full-column rewrite requires persisted source rows",
        ));
    }
    let stored_rows = vault.scan_cf_at(snapshot, ColumnFamily::slot(slot.slot_id))?;
    if stored_rows.is_empty() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            "compression requires a complete persisted source slot column; arbitrary new slot rows are refused",
        ));
    }
    let stored_keys = stored_rows
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    let incoming_keys = incoming.keys().cloned().collect::<BTreeSet<_>>();
    if stored_keys != incoming_keys {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "slot compression requires an atomic full-column rewrite: persisted_rows={} incoming_rows={}; partial or orphan replacement was refused",
                stored_keys.len(),
                incoming_keys.len()
            ),
        ));
    }
    let manifest = vault.read_cf_at(
        snapshot,
        ColumnFamily::Compression,
        &compression_manifest_key(slot.slot_id),
    )?;
    let raw_rows = vault.scan_cf_at(snapshot, ColumnFamily::slot_raw(slot.slot_id))?;
    if manifest.is_none() {
        if !raw_rows.is_empty() {
            let legacy_raw = raw_rows
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>();
            if legacy_raw.keys().cloned().collect::<BTreeSet<_>>() != stored_keys {
                return Err(compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    "legacy unmanifested compressed/raw slot columns have different keysets",
                ));
            }
            for (key, raw_value) in &legacy_raw {
                if incoming.get(key) != Some(raw_value) {
                    return Err(compression_error(
                        CALYX_VECTOR_COMPRESSION_INVALID,
                        "legacy raw sidecar does not exactly match the requested full-column source vectors",
                    ));
                }
            }
            let verifier = LegacyV2EnvelopeVerifier::new(slot, lens)?;
            for (key, stored_value) in &stored_rows {
                let raw = incoming_values.get(key).copied().ok_or_else(|| {
                    compression_error(
                        CALYX_VECTOR_COMPRESSION_INVALID,
                        "legacy primary row has no matching incoming raw vector",
                    )
                })?;
                verifier.verify(stored_value, raw)?;
            }
            return Ok(snapshot);
        }
        for (key, value) in &stored_rows {
            if value.first().copied() == Some(COMPRESSED_SLOT_TAG) {
                return Err(compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    "compressed slot envelope exists without a generation manifest",
                ));
            }
            if incoming.get(key) != Some(value) {
                return Err(compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    "incoming vector bytes do not match the persisted source SlotVector",
                ));
            }
        }
        return Ok(snapshot);
    }

    let raw = raw_rows
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    if raw.keys().cloned().collect::<BTreeSet<_>>() != stored_keys {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "manifested compressed/raw slot columns have different keysets",
        ));
    }
    for (key, value) in &raw {
        if incoming.get(key) != Some(value) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "incoming vector bytes do not match the persisted raw sidecar source of truth",
            ));
        }
    }
    CompressedSlotIndex::open(vault, slot, lens)?.verify_at(snapshot)?;
    Ok(snapshot)
}

pub fn compress_slot_batch(
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[CompressionQuery],
    k: usize,
) -> Result<SlotCompressionReport> {
    compress_slot_batch_with_assay_evidence(slot, lens, rows, queries, k, None)
}

pub fn compress_slot_batch_with_assay_evidence(
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[CompressionQuery],
    k: usize,
    mxfp4_evidence: Option<&MxFp4AssayEvidence>,
) -> Result<SlotCompressionReport> {
    validate_batch(slot, lens, rows, queries, k)?;
    let initial = encode_rows(slot, lens, rows, lens.quant_default, mxfp4_evidence)?;
    let report = build_report(slot, lens, rows, queries, k, initial, None)?;
    if recall_drop(&report) <= lens.recall_delta {
        return Ok(report);
    }

    Err(compression_error(
        CALYX_VECTOR_COMPRESSION_INVALID,
        format!(
            "requested quant policy {:?} failed recall contract: recall drop {:.6} exceeded declared delta {:.6}; no fallback codec was written",
            lens.quant_default,
            recall_drop(&report),
            lens.recall_delta
        ),
    ))
}

fn build_report(
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[CompressionQuery],
    k: usize,
    encoded: EncodedBatch,
    fallback_reason: Option<String>,
) -> Result<SlotCompressionReport> {
    let raw_bytes_total = encoded.rows.iter().try_fold(0_usize, |sum, row| {
        sum.checked_add(row.raw_bytes.len()).ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "raw-sidecar byte accounting overflow",
            )
        })
    })?;
    let stored_bytes_total = encoded.rows.iter().try_fold(0_usize, |sum, row| {
        sum.checked_add(row.stored_bytes.len()).ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "stored-envelope byte accounting overflow",
            )
        })
    })?;
    let codec_payload_bytes_total = encoded.rows.iter().try_fold(0_usize, |sum, row| {
        sum.checked_add(row.payload_bytes).ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "codec-payload byte accounting overflow",
            )
        })
    })?;
    let registry_envelope_bytes_total = encoded
        .rows
        .len()
        .checked_mul(REGISTRY_ENVELOPE_HEADER_BYTES)
        .ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "registry envelope byte accounting overflow",
            )
        })?;
    let generation_manifest_bytes_total = encoded.manifest_bytes.len();
    let codec_header_bytes_total = encoded.rows.iter().try_fold(0_usize, |sum, row| {
        sum.checked_add(row.codec_header_bytes).ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "codec-header byte accounting overflow",
            )
        })
    })?;
    let logical_data_bits_total = encoded.rows.iter().try_fold(0_u64, |sum, row| {
        sum.checked_add(row.logical_data_bits).ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "logical compression bit accounting overflow",
            )
        })
    })?;
    let written_value_bytes_total = raw_bytes_total
        .checked_add(stored_bytes_total)
        .and_then(|total| total.checked_add(generation_manifest_bytes_total))
        .ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "written compression value-byte accounting overflow",
            )
        })?;
    let stored_channels = encoded.rows.iter().try_fold(0_u64, |sum, row| {
        let row_channels = u64::try_from(row.prepared.len()).map_err(|_| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "stored row channel count exceeds u64",
            )
        })?;
        sum.checked_add(row_channels).ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "stored channel accounting overflow",
            )
        })
    })?;
    if stored_channels == 0 {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            "compression report has no stored coefficients",
        ));
    }
    let channels = stored_channels as f64;
    let recall_at_k_raw = 1.0;
    let recall_at_k_compressed = recall_at_k(
        rows,
        queries,
        &encoded.rows,
        &encoded.codec,
        k,
        lens.truncate_dim,
    )?;
    let stored_codec = encoded
        .rows
        .first()
        .map(|row| row.codec)
        .unwrap_or(StoredSlotCodec::RawF32);
    Ok(SlotCompressionReport {
        slot_id: slot.slot_id.get(),
        slot_key: slot.slot_key.key().to_string(),
        requested_quant: lens.quant_default,
        stored_codec,
        fallback_reason,
        raw_bytes_total,
        stored_bytes_total,
        codec_payload_bytes_total,
        registry_envelope_bytes_total,
        generation_manifest_bytes_total,
        codec_header_bytes_total,
        logical_data_bits_total,
        written_value_bytes_total,
        logical_data_bits_per_channel: (logical_data_bits_total as f64 / channels) as f32,
        codec_payload_bits_per_channel: (codec_payload_bytes_total as f64 * 8.0 / channels) as f32,
        written_value_bits_per_channel: (written_value_bytes_total as f64 * 8.0 / channels) as f32,
        recall_at_k_raw,
        recall_at_k_compressed,
        recall_drop: recall_at_k_raw - recall_at_k_compressed,
        truncate_dim: lens.truncate_dim,
        rows: encoded
            .rows
            .into_iter()
            .map(|row| SlotCompressionRow {
                cx_id: row.cx_id,
                raw_bytes: row.raw_bytes,
                compressed_bytes: row.stored_bytes,
                stored_dim: row.prepared.len() as u32,
                codec: row.codec,
            })
            .collect(),
        generation_manifest_bytes: encoded.manifest_bytes,
        snapshot: None,
    })
}

fn compression_error(code: &'static str, message: impl Into<String>) -> calyx_core::CalyxError {
    calyx_core::CalyxError {
        code,
        message: message.into(),
        remediation: COMPRESSION_REMEDIATION,
    }
}

fn mxfp4_evidence_error(message: impl Into<String>) -> calyx_core::CalyxError {
    compression_error(
        CALYX_VECTOR_COMPRESSION_INVALID,
        format!(
            "MXFP4 requires current assay safety evidence for exact slot/lens/dim; {}; no fallback codec was written",
            message.into()
        ),
    )
}
