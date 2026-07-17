mod codec;
mod index;
mod recall;

use calyx_aster::cf::{ColumnFamily, slot_key};
use calyx_aster::vault::AsterVault;
use calyx_core::{Clock, CxId, LensId, QuantPolicy, Result, Seq, Slot};
use calyx_forge::AssayQuantSafety;
use serde::{Deserialize, Serialize};

use crate::spec::LensSpec;
pub use codec::decode_stored_slot_envelope;
use codec::{EncodedBatch, encode_rows};
pub use index::{CompressedSlotHit, CompressedSlotIndex};
pub use recall::matryoshka_truncate_renormalize;
use recall::{recall_at_k, recall_drop, validate_batch};

pub const CALYX_VECTOR_COMPRESSION_EMPTY: &str = "CALYX_VECTOR_COMPRESSION_EMPTY";
pub const CALYX_VECTOR_COMPRESSION_INVALID: &str = "CALYX_VECTOR_COMPRESSION_INVALID";
pub const COMPRESSED_SLOT_TAG: u8 = 16;
pub const COMPRESSED_SLOT_VERSION: u8 = 2;
pub const REGISTRY_ENVELOPE_HEADER_BYTES: usize = 85;
const COMPRESSION_REMEDIATION: &str =
    "Re-encode finite dense vectors with the exact lens/slot codec context and inspect the reported envelope field";

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
    /// Codec-format headers inside the payload (for TurboQuant, TQPR headers).
    pub codec_header_bytes_total: usize,
    /// Scalar-index plus QJL data bits, excluding every fixed header and norm.
    pub logical_data_bits_total: u64,
    /// Raw sidecars plus compressed envelopes actually written to the vault.
    pub physical_bytes_total: usize,
    /// Logical product-code bits per stored coefficient.
    pub logical_data_bits_per_channel: f32,
    /// Complete codec payload bits per stored coefficient.
    pub codec_payload_bits_per_channel: f32,
    /// Raw sidecar plus compressed envelope bits per stored coefficient.
    pub physical_bits_per_channel: f32,
    pub recall_at_k_raw: f32,
    pub recall_at_k_compressed: f32,
    pub recall_delta: f32,
    pub truncate_dim: Option<u32>,
    pub rows: Vec<SlotCompressionRow>,
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
    pub payload_bytes: usize,
    pub payload_sha256: String,
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

pub fn write_compressed_slot_batch<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[Vec<f32>],
    k: usize,
) -> Result<SlotCompressionReport> {
    write_compressed_slot_batch_with_assay_evidence(vault, slot, lens, rows, queries, k, None)
}

pub fn write_compressed_slot_batch_with_assay_evidence<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[Vec<f32>],
    k: usize,
    mxfp4_evidence: Option<&MxFp4AssayEvidence>,
) -> Result<SlotCompressionReport> {
    let mut report =
        compress_slot_batch_with_assay_evidence(slot, lens, rows, queries, k, mxfp4_evidence)?;
    let mut writes = Vec::with_capacity(report.rows.len() * 2);
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
    report.snapshot = Some(vault.write_cf_batch(writes)?);
    Ok(report)
}

pub fn compress_slot_batch(
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[Vec<f32>],
    k: usize,
) -> Result<SlotCompressionReport> {
    compress_slot_batch_with_assay_evidence(slot, lens, rows, queries, k, None)
}

pub fn compress_slot_batch_with_assay_evidence(
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[Vec<f32>],
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
    queries: &[Vec<f32>],
    k: usize,
    encoded: EncodedBatch,
    fallback_reason: Option<String>,
) -> Result<SlotCompressionReport> {
    let raw_bytes_total = encoded.rows.iter().map(|row| row.raw_bytes.len()).sum();
    let stored_bytes_total = encoded.rows.iter().map(|row| row.stored_bytes.len()).sum();
    let codec_payload_bytes_total = encoded.rows.iter().map(|row| row.payload_bytes).sum();
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
    let codec_header_bytes_total = encoded
        .rows
        .iter()
        .map(|row| row.codec_header_bytes)
        .sum();
    let logical_data_bits_total = encoded.rows.iter().try_fold(0_u64, |sum, row| {
        sum.checked_add(row.logical_data_bits).ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "logical compression bit accounting overflow",
            )
        })
    })?;
    let physical_bytes_total = raw_bytes_total
        .checked_add(stored_bytes_total)
        .ok_or_else(|| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "physical compression byte accounting overflow",
            )
        })?;
    let stored_channels = encoded.rows.iter().try_fold(0_u64, |sum, row| {
        sum.checked_add(row.prepared.len() as u64).ok_or_else(|| {
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
        codec_header_bytes_total,
        logical_data_bits_total,
        physical_bytes_total,
        logical_data_bits_per_channel: (logical_data_bits_total as f64 / channels) as f32,
        codec_payload_bits_per_channel: (codec_payload_bytes_total as f64 * 8.0 / channels) as f32,
        physical_bits_per_channel: (physical_bytes_total as f64 * 8.0 / channels) as f32,
        recall_at_k_raw,
        recall_at_k_compressed,
        recall_delta: recall_at_k_compressed - recall_at_k_raw,
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
