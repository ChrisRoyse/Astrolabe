mod codec;
mod index;
mod recall;

use calyx_assay::{AssayCacheKey, AssayStore, AssaySubject, MiEstimate, TrustTag};
use calyx_aster::cf::{
    COMPRESSED_SLOT_VALUE_TAG, ColumnFamily, base_key, compression_manifest_key, slot_key,
};
use calyx_aster::vault::{AsterVault, encode};
use calyx_core::{Clock, CxId, LedgerRef, LensId, QuantPolicy, Result, Seq, Slot, SlotVector};
use calyx_forge::AssayQuantSafety;
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::spec::LensSpec;
pub use codec::inspect_unbound_stored_slot_envelope;
use codec::{EncodedBatch, LegacyV2EnvelopeVerifier, encode_rows, parse_compression_manifest};
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
    /// Ledger transition committed atomically with the generation write.
    ///
    /// `Some` exactly when `snapshot` is `Some`: the durable write path commits
    /// the envelopes, raw sidecars, generation manifest, and this hash-chained
    /// ledger entry in one group commit. Pure (non-writing) compression reports
    /// carry `None`.
    pub ledger: Option<LedgerRef>,
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

const MXFP4_ASSAY_SCHEMA: &str = "calyx.assay.mxfp4_safety.v1";
const MXFP4_ASSAY_PROVENANCE: &str = "calyx_assay::mxfp4_quantization_safety/v1";
const MXFP4_SOURCE_DOMAIN: &[u8] = b"calyx-registry-mxfp4-source-column-v1";

#[derive(Clone, Debug, PartialEq)]
pub struct MxFp4AssayEvidence {
    slot_id: u16,
    slot_key: String,
    lens_id: LensId,
    dim: u32,
    written_at_seq: Seq,
    current_seq: Seq,
    source_column_sha256: [u8; 32],
    assay_row_sha256: [u8; 32],
    safety: AssayQuantSafety,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MxFp4AssayPayload {
    schema: String,
    slot_key: String,
    lens_id: String,
    dim: u32,
    source_rows: u32,
    source_slot_column_sha256: String,
    safety: AssayQuantSafety,
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

    fn attestation_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"calyx-registry-mxfp4-assay-attestation-v1");
        hasher.update(self.assay_row_sha256);
        hasher.update(self.source_column_sha256);
        hasher.finalize().into()
    }
}

/// Persists a measured MXFP4 safety card into the Assay source of truth and
/// independently reads the exact row back before returning its MVCC sequence.
pub fn persist_mxfp4_assay_evidence<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    cache_key: AssayCacheKey,
    estimate: MiEstimate,
    safety: AssayQuantSafety,
) -> Result<Seq> {
    cache_key.require_scoped()?;
    if cache_key.vault_id != Some(vault.vault_id()) || cache_key.corpus_shard.trim().is_empty() {
        return Err(mxfp4_evidence_error(
            "MXFP4 Assay cache key must name this vault and a non-blank corpus shard",
        ));
    }
    if estimate.trust != TrustTag::Trusted
        || estimate.n_samples < calyx_assay::MIN_ASSAY_SAMPLES
        || !estimate.bits.is_finite()
        || !estimate.ci_low.is_finite()
        || !estimate.ci_high.is_finite()
        || estimate.bits.to_bits() != safety.quantized_bits.to_bits()
        || !safety.passes()
    {
        return Err(mxfp4_evidence_error(
            "MXFP4 evidence requires a trusted, finite, sufficiently sampled Assay estimate whose bits equal passing quantized safety bits",
        ));
    }
    let current_seq = vault.latest_seq();
    let (source_column_sha256, source_rows) =
        source_slot_column_attestation(vault, slot, ColumnFamily::slot(slot.slot_id), current_seq)?;
    let dim = match slot.shape {
        calyx_core::SlotShape::Dense(raw_dim) => lens.truncate_dim.unwrap_or(raw_dim),
        _ => return Err(mxfp4_evidence_error("MXFP4 evidence requires a dense slot")),
    };
    let subject = AssaySubject::Lens { slot: slot.slot_id };
    let payload = MxFp4AssayPayload {
        schema: MXFP4_ASSAY_SCHEMA.to_string(),
        slot_key: slot.slot_key.key().to_string(),
        lens_id: lens.lens_id().to_string(),
        dim,
        source_rows,
        source_slot_column_sha256: encode_sha256(source_column_sha256),
        safety,
    };
    let payload_value = serde_json::to_value(&payload).map_err(|error| {
        mxfp4_evidence_error(format!("failed to encode MXFP4 Assay payload: {error}"))
    })?;
    let expected_seq = current_seq.checked_add(1).ok_or_else(|| {
        mxfp4_evidence_error("vault sequence overflow while persisting MXFP4 evidence")
    })?;
    let mut store = AssayStore::default();
    store.put_with_payload(
        cache_key.clone(),
        subject.clone(),
        estimate,
        MXFP4_ASSAY_PROVENANCE,
        expected_seq,
        payload_value.clone(),
    );
    store.persist_to_vault(vault)?;
    let observed_seq = vault.latest_seq();
    if observed_seq != expected_seq {
        return Err(mxfp4_evidence_error(format!(
            "MXFP4 Assay persistence sequence mismatch: expected {expected_seq}, observed {observed_seq}"
        )));
    }
    let observed = AssayStore::read_row_from_vault_at(vault, observed_seq, &cache_key, &subject)?
        .ok_or_else(|| {
        mxfp4_evidence_error("persisted MXFP4 Assay row was absent on independent readback")
    })?;
    if observed.written_at_seq != expected_seq
        || observed.provenance != MXFP4_ASSAY_PROVENANCE
        || observed.payload.as_ref() != Some(&payload_value)
    {
        return Err(mxfp4_evidence_error(
            "persisted MXFP4 Assay row did not match the independently read source-of-truth bytes",
        ));
    }
    Ok(observed_seq)
}

/// Loads MXFP4 admission evidence from the real Assay CF and binds it to the
/// exact persisted source slot generation. The returned type has no public
/// constructor or mutable fields, so compression cannot accept caller-crafted
/// evidence in place of a read-back Assay row.
pub fn load_mxfp4_assay_evidence<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
) -> Result<MxFp4AssayEvidence> {
    let current_seq = vault.latest_seq();
    let (source_column_sha256, source_rows) =
        source_slot_column_attestation(vault, slot, ColumnFamily::slot(slot.slot_id), current_seq)?;
    let expected_dim = match slot.shape {
        calyx_core::SlotShape::Dense(raw_dim) => lens.truncate_dim.unwrap_or(raw_dim),
        _ => return Err(mxfp4_evidence_error("MXFP4 evidence requires a dense slot")),
    };
    let (store, _skipped_non_assay_rows) =
        AssayStore::load_from_shared_vault_at(vault, current_seq)?;
    let mut matches = Vec::new();
    for row in store.rows() {
        if row.cache_key.vault_id != Some(vault.vault_id())
            || row.subject != (AssaySubject::Lens { slot: slot.slot_id })
        {
            continue;
        }
        let Some(payload_value) = &row.payload else {
            continue;
        };
        let Ok(payload) = serde_json::from_value::<MxFp4AssayPayload>(payload_value.clone()) else {
            continue;
        };
        if payload.schema != MXFP4_ASSAY_SCHEMA {
            continue;
        }
        if row.provenance != MXFP4_ASSAY_PROVENANCE
            || row.written_at_seq != current_seq
            || row.estimate.trust != TrustTag::Trusted
            || row.estimate.n_samples < calyx_assay::MIN_ASSAY_SAMPLES
            || row.estimate.bits.to_bits() != payload.safety.quantized_bits.to_bits()
        {
            return Err(mxfp4_evidence_error(format!(
                "MXFP4 Assay row is stale, provisional, under-sampled, or internally inconsistent: written_at_seq={} current_seq={current_seq} trust={:?} n_samples={} estimate_bits={} payload_bits={}",
                row.written_at_seq,
                row.estimate.trust,
                row.estimate.n_samples,
                row.estimate.bits,
                payload.safety.quantized_bits
            )));
        }
        if payload.slot_key != slot.slot_key.key()
            || payload.lens_id != lens.lens_id().to_string()
            || payload.dim != expected_dim
            || payload.source_rows != source_rows
            || decode_sha256(&payload.source_slot_column_sha256)? != source_column_sha256
            || !payload.safety.passes()
        {
            return Err(mxfp4_evidence_error(
                "MXFP4 Assay row does not bind the current slot key, lens, dimension, source generation, or passing safety metrics",
            ));
        }
        let row_bytes = serde_json::to_vec(&row).map_err(|error| {
            mxfp4_evidence_error(format!(
                "failed to canonicalize Assay evidence row: {error}"
            ))
        })?;
        matches.push(MxFp4AssayEvidence {
            slot_id: slot.slot_id.get(),
            slot_key: slot.slot_key.key().to_string(),
            lens_id: lens.lens_id(),
            dim: expected_dim,
            written_at_seq: row.written_at_seq,
            current_seq,
            source_column_sha256,
            assay_row_sha256: Sha256::digest(row_bytes).into(),
            safety: payload.safety,
        });
    }
    if matches.len() != 1 {
        return Err(mxfp4_evidence_error(format!(
            "expected exactly one current persisted MXFP4 Assay evidence row, found {}",
            matches.len()
        )));
    }
    Ok(matches.remove(0))
}

pub(super) fn verify_mxfp4_assay_attestation_at<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    stored_dim: u32,
    snapshot: Seq,
    expected_attestation_id: [u8; 32],
) -> Result<()> {
    if expected_attestation_id == [0; 32] {
        return Err(mxfp4_evidence_error(
            "persisted row carries a zero Assay attestation identity",
        ));
    }
    let (source_column_sha256, source_rows) = source_slot_column_attestation(
        vault,
        slot,
        ColumnFamily::slot_raw(slot.slot_id),
        snapshot,
    )?;
    let (store, _skipped_non_assay_rows) = AssayStore::load_from_shared_vault_at(vault, snapshot)?;
    let mut matched = 0_usize;
    for row in store.rows() {
        if row.cache_key.vault_id != Some(vault.vault_id())
            || row.subject != (AssaySubject::Lens { slot: slot.slot_id })
        {
            continue;
        }
        let Some(payload_value) = &row.payload else {
            continue;
        };
        let Ok(payload) = serde_json::from_value::<MxFp4AssayPayload>(payload_value.clone()) else {
            continue;
        };
        if payload.schema != MXFP4_ASSAY_SCHEMA {
            continue;
        }
        if row.provenance != MXFP4_ASSAY_PROVENANCE
            || row.written_at_seq > snapshot
            || row.estimate.trust != TrustTag::Trusted
            || row.estimate.n_samples < calyx_assay::MIN_ASSAY_SAMPLES
            || row.estimate.bits.to_bits() != payload.safety.quantized_bits.to_bits()
            || payload.slot_key != slot.slot_key.key()
            || payload.lens_id != lens.lens_id().to_string()
            || payload.dim != stored_dim
            || payload.source_rows != source_rows
            || decode_sha256(&payload.source_slot_column_sha256)? != source_column_sha256
            || !payload.safety.passes()
        {
            continue;
        }
        let row_bytes = serde_json::to_vec(&row).map_err(|error| {
            mxfp4_evidence_error(format!(
                "failed to canonicalize Assay evidence row: {error}"
            ))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(b"calyx-registry-mxfp4-assay-attestation-v1");
        hasher.update(Sha256::digest(row_bytes));
        hasher.update(source_column_sha256);
        let candidate_id: [u8; 32] = hasher.finalize().into();
        if candidate_id == expected_attestation_id {
            matched += 1;
        }
    }
    if matched != 1 {
        return Err(mxfp4_evidence_error(format!(
            "persisted MXFP4 attestation identity matched {matched} Assay rows at snapshot={snapshot}; expected exactly one"
        )));
    }
    Ok(())
}

pub(crate) fn write_compressed_slot_batch<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[CompressionQuery],
    k: usize,
) -> Result<SlotCompressionReport> {
    let evidence = if lens.quant_default == QuantPolicy::MxFp4 {
        Some(load_mxfp4_assay_evidence(vault, slot, lens)?)
    } else {
        None
    };
    write_compressed_slot_batch_with_assay_evidence(
        vault,
        slot,
        lens,
        rows,
        queries,
        k,
        evidence.as_ref(),
    )
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
    let ledger_payload = generation_ledger_payload(&report)?;
    let (snapshot, ledger_ref) = vault.write_cf_batch_with_ledger_entry_if_seq(
        expected_seq,
        writes,
        EntryKind::Migrate,
        SubjectId::Query(compression_generation_subject(slot)),
        ledger_payload,
        ActorId::Service("calyx-registry".to_string()),
    )?;
    report.snapshot = Some(snapshot);
    report.ledger = Some(ledger_ref);
    Ok(report)
}

/// Marker embedded in every compression-generation ledger subject.
pub const COMPRESSION_GENERATION_MARKER: &str = "SLOT_COMPRESSION_GENERATION";

fn compression_generation_subject(slot: &Slot) -> Vec<u8> {
    let mut subject = COMPRESSION_GENERATION_MARKER.as_bytes().to_vec();
    subject.push(b':');
    subject.extend_from_slice(&slot.slot_id.get().to_be_bytes());
    subject
}

fn generation_ledger_payload(report: &SlotCompressionReport) -> Result<Vec<u8>> {
    let manifest = parse_compression_manifest(&report.generation_manifest_bytes)?;
    serde_json::to_vec(&serde_json::json!({
        "marker": COMPRESSION_GENERATION_MARKER,
        "slot_id": report.slot_id,
        "codec": report.stored_codec,
        "rows": manifest.generation_rows,
        "codec_context_id_sha256": hex_bytes(&manifest.codec_context_id),
        "generation_root_sha256": hex_bytes(&manifest.generation_root),
        "raw_generation_root_sha256": hex_bytes(&manifest.raw_generation_root),
    }))
    .map_err(|error| {
        compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!("compression generation ledger payload encoding failed: {error}"),
        )
    })
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Compresses the complete persisted raw slot column that a streaming ingest
/// session wrote, as one registry-owned versioned generation transition.
///
/// Reads every persisted row of `slot`'s column at the current sequence,
/// requires each to be an uncompressed dense `SlotVector` (a column that
/// already carries a compressed generation, or any non-dense row, is a
/// structured refusal — never a guess), and routes the exact persisted vectors
/// through [`write_compressed_slot_batch`]. The write persists the contextual
/// envelopes, raw source binding, generation manifest roots, and the ledger
/// transition in one atomic seq-guarded commit under the single frozen
/// slot/lens geometry. There is no per-row codec and no raw fallback.
pub(crate) fn compress_streamed_column<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    queries: &[CompressionQuery],
    k: usize,
) -> Result<SlotCompressionReport> {
    let snapshot = vault.latest_seq();
    let stored = vault.scan_cf_at(snapshot, ColumnFamily::slot(slot.slot_id))?;
    if stored.is_empty() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            format!(
                "streamed slot column {} has no persisted rows at seq={snapshot}; stream ingest must persist raw dense rows before compression",
                slot.slot_id.get()
            ),
        ));
    }
    let mut rows = Vec::with_capacity(stored.len());
    for (key, value) in stored {
        if value.first().copied() == Some(COMPRESSED_SLOT_TAG) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "slot column {} already carries a compressed envelope at seq={snapshot}; streamed-column compression only converts a complete raw column and will not re-guess an existing generation",
                    slot.slot_id.get()
                ),
            ));
        }
        let cx_bytes: [u8; 16] = key.as_slice().try_into().map_err(|_| {
            compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "slot column {} row key length {} is not a 16-byte CxId",
                    slot.slot_id.get(),
                    key.len()
                ),
            )
        })?;
        let cx_id = CxId::from_bytes(cx_bytes);
        let vector = encode::decode_slot_vector(&value)?;
        let SlotVector::Dense { data, .. } = vector else {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "slot column {} row {cx_id} is not a dense vector; streamed-column compression requires a dense raw source column",
                    slot.slot_id.get()
                ),
            ));
        };
        rows.push((cx_id, data));
    }
    write_compressed_slot_batch(vault, slot, lens, &rows, queries, k)
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
    let stored_codec = encoded.rows.first().map(|row| row.codec).ok_or_else(|| {
        compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            "compression report has no physically encoded row from which to read the stored codec",
        )
    })?;
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
        ledger: None,
    })
}

fn compression_error(code: &'static str, message: impl Into<String>) -> calyx_core::CalyxError {
    calyx_core::CalyxError {
        code,
        message: message.into(),
        remediation: COMPRESSION_REMEDIATION,
    }
}

fn source_slot_column_attestation<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    column_family: ColumnFamily,
    snapshot: Seq,
) -> Result<([u8; 32], u32)> {
    let mut rows = vault.scan_cf_at(snapshot, column_family)?;
    if rows.is_empty() {
        return Err(mxfp4_evidence_error(
            "source slot column is empty and cannot be attested",
        ));
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let row_count = u32::try_from(rows.len())
        .map_err(|_| mxfp4_evidence_error("source slot row count exceeds u32"))?;
    let mut hasher = Sha256::new();
    hasher.update(MXFP4_SOURCE_DOMAIN);
    hasher.update(vault.vault_id().as_ulid().to_bytes());
    hasher.update(slot.slot_id.get().to_be_bytes());
    hasher.update(row_count.to_be_bytes());
    for (key, value) in rows {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key);
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    Ok((hasher.finalize().into(), row_count))
}

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(mxfp4_evidence_error(
            "source slot column SHA-256 must contain exactly 64 hexadecimal characters",
        ));
    }
    let mut out = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair)
            .map_err(|_| mxfp4_evidence_error("source slot column SHA-256 is not UTF-8"))?;
        out[index] = u8::from_str_radix(text, 16)
            .map_err(|_| mxfp4_evidence_error("source slot column SHA-256 is not hexadecimal"))?;
    }
    Ok(out)
}

fn encode_sha256(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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
