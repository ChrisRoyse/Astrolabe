use std::collections::{BTreeMap, BTreeSet};

use calyx_aster::cf::{
    COMPRESSED_SLOT_VALUE_TAG, ColumnFamily, base_key, compression_lifecycle_key,
    compression_manifest_key, ledger_key, slot_key,
};
use calyx_aster::compression_lifecycle::{GenerationTransition, compression_generation_subject};
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::{AsterVault, encode};
use calyx_core::{Clock, CxId, Result, Seq, Slot, SlotVector};
use calyx_ledger::{ActorId, EntryKind};

use super::codec::{PreparedGeneration, prepare_generation, validate_token_matrix};
use super::generation_record::{finalize_byte_accounting, ledger_payload, lifecycle_record};
use super::{
    CALYX_MULTIVECTOR_CONTEXT_MISMATCH, CALYX_MULTIVECTOR_PACK_INVALID,
    MultiVectorCompressionConfig, MultiVectorCompressionQuery, MultiVectorCompressionReport,
    MultiVectorCompressionRow, PackedMultiVectorIndex, multivector_error,
    parse_packed_multivector_manifest, validate_multivector_context,
};
use crate::spec::LensSpec;

/// Atomically creates or reseals a complete residual-packed Multi generation.
pub fn write_packed_multivector_generation<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    rows: &[MultiVectorCompressionRow],
    queries: &[MultiVectorCompressionQuery],
    config: MultiVectorCompressionConfig,
    k: usize,
) -> Result<MultiVectorCompressionReport> {
    let (expected_seq, transition) = validate_full_rewrite(vault, slot, lens, rows, config)?;
    let prepared = prepare_generation(slot, lens, rows, queries, config, k, expected_seq)?;
    let affected = prepared.report.rows.iter().map(|row| row.cx_id).collect();
    commit_generation(
        vault,
        slot,
        prepared,
        expected_seq,
        transition,
        affected,
        Vec::new(),
        EntryKind::Migrate,
    )
}

/// Reads the exact raw Multi column written by streaming ingest and converts it
/// into one atomic residual-packed generation.
pub fn compress_streamed_multivector_column<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    queries: &[MultiVectorCompressionQuery],
    config: MultiVectorCompressionConfig,
    k: usize,
) -> Result<MultiVectorCompressionReport> {
    let token_dim = validate_multivector_context(slot, lens)?;
    config.validate(token_dim)?;
    let snapshot = vault.latest_seq();
    let stored = vault.scan_cf_at(snapshot, ColumnFamily::slot(slot.slot_id))?;
    if stored.is_empty() {
        return Err(invalid(format!(
            "streamed Multi slot {} has no persisted rows at seq={snapshot}",
            slot.slot_id.get()
        )));
    }
    let mut rows = Vec::with_capacity(stored.len());
    for (key, value) in stored {
        if value.first().copied() == Some(COMPRESSED_SLOT_VALUE_TAG) {
            return Err(invalid(format!(
                "streamed Multi slot {} already carries compressed envelopes; use the exact reseal API",
                slot.slot_id.get()
            )));
        }
        let cx_id = cx_id_from_key(&key)?;
        let SlotVector::Multi {
            token_dim: stored_dim,
            tokens,
        } = encode::decode_slot_vector(&value)?
        else {
            return Err(invalid(format!(
                "streamed slot row {cx_id} is not a Multi SlotVector"
            )));
        };
        if stored_dim != token_dim {
            return Err(context_mismatch(format!(
                "streamed row {cx_id} token_dim {stored_dim} != slot token_dim {token_dim}"
            )));
        }
        rows.push(MultiVectorCompressionRow { cx_id, tokens });
    }
    write_packed_multivector_generation(vault, slot, lens, &rows, queries, config, k)
}

/// Adds new exact rows and atomically reseals every row/codebook/root.
pub fn append_reseal_packed_multivector_rows<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    new_rows: &[MultiVectorCompressionRow],
    queries: &[MultiVectorCompressionQuery],
    k: usize,
) -> Result<MultiVectorCompressionReport> {
    if new_rows.is_empty() {
        return Err(invalid(
            "packed append-reseal requires at least one new row",
        ));
    }
    let index = PackedMultiVectorIndex::open(vault, slot, lens)?;
    let expected_seq = index.opened_at();
    let config = index.manifest().config;
    let existing = load_raw_rows(vault, slot, expected_seq)?;
    let mut union = existing.clone();
    let mut affected = Vec::with_capacity(new_rows.len());
    for row in new_rows {
        if union.contains_key(&row.cx_id) {
            return Err(invalid(format!(
                "packed append row {} already exists",
                row.cx_id
            )));
        }
        verify_base_binding(
            vault,
            slot,
            expected_seq,
            row.cx_id,
            &encode_multi_row(index.manifest().token_dim, &row.tokens)?,
        )?;
        union.insert(row.cx_id, row.tokens.clone());
        affected.push(row.cx_id);
    }
    let rows = map_rows(union);
    let prepared = prepare_generation(slot, lens, &rows, queries, config, k, expected_seq)?;
    commit_generation(
        vault,
        slot,
        prepared,
        expected_seq,
        GenerationTransition::AppendReseal,
        affected,
        Vec::new(),
        EntryKind::Migrate,
    )
}

/// Removes a strict subset and atomically reseals the survivors.
pub fn erase_packed_multivector_rows<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    erase_ids: &[CxId],
    queries: &[MultiVectorCompressionQuery],
    k: usize,
) -> Result<MultiVectorCompressionReport> {
    if erase_ids.is_empty() {
        return Err(invalid("packed erase-reseal requires at least one CxId"));
    }
    let erase_set = erase_ids.iter().copied().collect::<BTreeSet<_>>();
    if erase_set.len() != erase_ids.len() {
        return Err(invalid("packed erase-reseal contains duplicate CxIds"));
    }
    let index = PackedMultiVectorIndex::open(vault, slot, lens)?;
    let expected_seq = index.opened_at();
    let config = index.manifest().config;
    let mut existing = load_raw_rows(vault, slot, expected_seq)?;
    for cx_id in &erase_set {
        if existing.remove(cx_id).is_none() {
            return Err(invalid(format!(
                "packed erase target {cx_id} is not in the live generation"
            )));
        }
    }
    if existing.is_empty() {
        return Err(invalid(
            "packed erase-reseal cannot remove every row; use delete_compressed_generation",
        ));
    }
    let rows = map_rows(existing);
    let prepared = prepare_generation(slot, lens, &rows, queries, config, k, expected_seq)?;
    let mut tombstones = Vec::with_capacity(erase_set.len() * 2);
    for cx_id in &erase_set {
        let key = slot_key(*cx_id);
        tombstones.push((ColumnFamily::slot(slot.slot_id), key.clone()));
        tombstones.push((ColumnFamily::slot_raw(slot.slot_id), key));
    }
    commit_generation(
        vault,
        slot,
        prepared,
        expected_seq,
        GenerationTransition::EraseReseal,
        erase_set.into_iter().collect(),
        tombstones,
        EntryKind::Erase,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_generation<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    mut prepared: PreparedGeneration,
    expected_seq: Seq,
    transition: GenerationTransition,
    affected: Vec<CxId>,
    tombstones: Vec<(ColumnFamily, Vec<u8>)>,
    ledger_kind: EntryKind,
) -> Result<MultiVectorCompressionReport> {
    let mut writes = Vec::with_capacity(prepared.report.rows.len() * 2 + tombstones.len() + 2);
    for row in &prepared.report.rows {
        let key = slot_key(row.cx_id);
        writes.push((
            ColumnFamily::slot_raw(slot.slot_id),
            key.clone(),
            row.raw_bytes.clone(),
        ));
        writes.push((
            ColumnFamily::slot(slot.slot_id),
            key,
            row.packed_bytes.clone(),
        ));
    }
    for (cf, key) in tombstones {
        writes.push((cf, key, tombstone_value()));
    }
    writes.push((
        ColumnFamily::Compression,
        compression_manifest_key(slot.slot_id),
        prepared.report.generation_manifest_bytes.clone(),
    ));
    let lifecycle = lifecycle_record(
        transition,
        slot,
        expected_seq,
        &prepared.manifest,
        &affected,
    )?;
    let lifecycle_bytes = lifecycle.encode()?;
    writes.push((
        ColumnFamily::Compression,
        compression_lifecycle_key(slot.slot_id, expected_seq),
        lifecycle_bytes.clone(),
    ));
    let payload = ledger_payload(transition, &prepared.manifest, &affected)?;
    let (snapshot, ledger) = vault.write_cf_batch_with_ledger_entry_if_seq(
        expected_seq,
        writes,
        ledger_kind,
        compression_generation_subject(slot.slot_id),
        payload,
        ActorId::Service("calyx-registry".to_string()),
    )?;
    prepared.report.snapshot = Some(snapshot);
    prepared.report.ledger = Some(ledger.clone());
    let ledger_bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Ledger, &ledger_key(ledger.seq))?
        .ok_or_else(|| invalid("committed compression Ledger row could not be read back"))?;
    finalize_byte_accounting(
        &mut prepared.report,
        lifecycle_bytes.len(),
        ledger_bytes.len(),
    )?;
    Ok(prepared.report)
}

fn validate_full_rewrite<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    rows: &[MultiVectorCompressionRow],
    config: MultiVectorCompressionConfig,
) -> Result<(Seq, GenerationTransition)> {
    let token_dim = validate_multivector_context(slot, lens)?;
    config.validate(token_dim)?;
    let snapshot = vault.latest_seq();
    let mut incoming = BTreeMap::new();
    for row in rows {
        validate_token_matrix(&row.tokens, token_dim, config.max_tokens, "document")?;
        let raw = encode_multi_row(token_dim, &row.tokens)?;
        let key = slot_key(row.cx_id);
        if incoming.insert(key, raw.clone()).is_some() {
            return Err(invalid("full Multi rewrite contains duplicate CxIds"));
        }
        verify_base_binding(vault, slot, snapshot, row.cx_id, &raw)?;
    }
    if incoming.is_empty() {
        return Err(invalid("full Multi rewrite requires at least one row"));
    }
    let stored = vault
        .scan_cf_at(snapshot, ColumnFamily::slot(slot.slot_id))?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    if stored.keys().collect::<BTreeSet<_>>() != incoming.keys().collect::<BTreeSet<_>>() {
        return Err(invalid(format!(
            "full Multi rewrite keyset differs: persisted={} incoming={}",
            stored.len(),
            incoming.len()
        )));
    }
    let manifest_bytes = vault.read_cf_at(
        snapshot,
        ColumnFamily::Compression,
        &compression_manifest_key(slot.slot_id),
    )?;
    let raw = vault
        .scan_cf_at(snapshot, ColumnFamily::slot_raw(slot.slot_id))?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    match manifest_bytes {
        None => {
            if !raw.is_empty() {
                return Err(invalid(
                    "unmanifested Multi slot has raw sidecars; legacy state is refused rather than guessed",
                ));
            }
            for (key, value) in &stored {
                if value.first().copied() == Some(COMPRESSED_SLOT_VALUE_TAG) {
                    return Err(invalid(
                        "unmanifested compressed Multi bytes are legacy/foreign and require an explicit migration",
                    ));
                }
                if incoming.get(key) != Some(value) {
                    return Err(invalid(
                        "incoming Multi bytes do not match persisted raw source",
                    ));
                }
            }
            Ok((snapshot, GenerationTransition::Create))
        }
        Some(bytes) => {
            if raw != incoming {
                return Err(invalid(
                    "manifested Multi raw sidecars do not exactly match the requested reseal source",
                ));
            }
            let manifest = parse_packed_multivector_manifest(&bytes)?;
            if manifest.config != config {
                return Err(context_mismatch(format!(
                    "reseal config {:?} does not match persisted config {:?}",
                    config, manifest.config
                )));
            }
            PackedMultiVectorIndex::open(vault, slot, lens)?;
            Ok((snapshot, GenerationTransition::Reseal))
        }
    }
}

fn load_raw_rows<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    at: Seq,
) -> Result<BTreeMap<CxId, Vec<Vec<f32>>>> {
    let mut rows = BTreeMap::new();
    for (key, bytes) in vault.scan_cf_at(at, ColumnFamily::slot_raw(slot.slot_id))? {
        let cx_id = cx_id_from_key(&key)?;
        let SlotVector::Multi { tokens, .. } = encode::decode_slot_vector(&bytes)? else {
            return Err(invalid(format!(
                "packed raw sidecar {cx_id} is not a Multi SlotVector"
            )));
        };
        if rows.insert(cx_id, tokens).is_some() {
            return Err(invalid("packed raw sidecars contain duplicate CxIds"));
        }
    }
    if rows.is_empty() {
        return Err(invalid("live packed generation has no raw sidecars"));
    }
    Ok(rows)
}

fn map_rows(rows: BTreeMap<CxId, Vec<Vec<f32>>>) -> Vec<MultiVectorCompressionRow> {
    rows.into_iter()
        .map(|(cx_id, tokens)| MultiVectorCompressionRow { cx_id, tokens })
        .collect()
}

fn encode_multi_row(token_dim: u32, tokens: &[Vec<f32>]) -> Result<Vec<u8>> {
    encode::encode_slot_vector(&SlotVector::Multi {
        token_dim,
        tokens: tokens.to_vec(),
    })
}

fn verify_base_binding<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    at: Seq,
    cx_id: CxId,
    raw: &[u8],
) -> Result<()> {
    let base = vault
        .read_cf_at(at, ColumnFamily::Base, &base_key(cx_id))?
        .ok_or_else(|| invalid(format!("Multi source {cx_id} has no Base constellation")))?;
    let identity = encode::decode_constellation_base_identity(&base)?;
    let expected = identity.slot_hashes.get(&slot.slot_id).ok_or_else(|| {
        invalid(format!(
            "Base constellation {cx_id} does not declare slot {}",
            slot.slot_id.get()
        ))
    })?;
    if identity.cx_id != cx_id || blake3::hash(raw).as_bytes() != expected {
        return Err(invalid(format!(
            "Multi source {cx_id} does not match its immutable Base slot hash"
        )));
    }
    Ok(())
}

fn cx_id_from_key(key: &[u8]) -> Result<CxId> {
    let bytes: [u8; 16] = key.try_into().map_err(|_| {
        invalid(format!(
            "Multi slot key length {} is not a 16-byte CxId",
            key.len()
        ))
    })?;
    Ok(CxId::from_bytes(bytes))
}

fn invalid(message: impl Into<String>) -> calyx_core::CalyxError {
    multivector_error(CALYX_MULTIVECTOR_PACK_INVALID, message)
}

fn context_mismatch(message: impl Into<String>) -> calyx_core::CalyxError {
    multivector_error(CALYX_MULTIVECTOR_CONTEXT_MISMATCH, message)
}
