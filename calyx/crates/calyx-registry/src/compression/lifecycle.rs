//! Lawful generation transitions for compressed slot columns (issue #562).
//!
//! The initial `Create`/`Migrate`/`Reseal` rewrite lives in the parent module.
//! This module adds the three transitions that a durable, orphan-free lifecycle
//! requires:
//!
//! * [`append_reseal_compressed_rows`] — add new rows to a manifested
//!   generation, resealing every row under a new generation root.
//! * [`erase_compressed_slot_rows`] — remove a strict subset of rows, resealing
//!   the survivors.
//! * [`delete_compressed_generation`] — remove an entire generation (manifest,
//!   primary rows, and raw sidecars) in one coordinated, ledgered batch.
//!
//! Every transition commits in a single seq-guarded conditional batch that
//! carries its manifest mutation, resealed rows, one append-only
//! [`GenerationLifecycleRecord`], and a paired ledger entry, so the commit-time
//! guard in `calyx-aster` admits it and no orphaned generation can be produced.

use std::collections::{BTreeMap, BTreeSet};

use calyx_aster::cf::{
    ColumnFamily, compression_lifecycle_key, compression_lifecycle_prefix_range,
    compression_manifest_key, slot_key,
};
use calyx_aster::compression_lifecycle::{
    GenerationLifecycleRecord, GenerationTransition, compression_generation_subject,
};
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::{AsterVault, encode};
use calyx_core::{Clock, CxId, LedgerRef, Result, Seq, Slot, SlotVector};
use calyx_ledger::{ActorId, EntryKind};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    CALYX_VECTOR_COMPRESSION_EMPTY, CALYX_VECTOR_COMPRESSION_INVALID,
    COMPRESSION_GENERATION_MARKER, CompressedSlotIndex, CompressionQuery, SlotCompressionReport,
    compress_slot_batch_with_assay_evidence, compression_error, generation_ledger_payload,
    hex_bytes, parse_compression_manifest, validate_row_base_binding,
};
use crate::spec::LensSpec;

/// Result of a full-generation delete.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GenerationDeleteReport {
    pub slot_id: u16,
    /// Distinct `CxId`s whose primary and raw-sidecar rows were tombstoned.
    pub deleted_rows: usize,
    /// Sequence at which the coordinated delete committed.
    pub snapshot: Seq,
    /// Hash-chained ledger transition committed atomically with the delete.
    pub ledger: LedgerRef,
}

/// Adds `new_rows` to an already-manifested generation, resealing the whole
/// column under a fresh generation root (`AppendReseal`).
///
/// Fails closed if the slot has no live generation (use the create path), if any
/// new `CxId` already exists in the generation, or if a new row does not bind to
/// its immutable `Base` slot hash. The recall contract is re-checked over the
/// full resealed set before the atomic commit.
pub fn append_reseal_compressed_rows<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    new_rows: &[(CxId, Vec<f32>)],
    queries: &[CompressionQuery],
    k: usize,
) -> Result<SlotCompressionReport> {
    if new_rows.is_empty() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            "append-reseal requires at least one new row",
        ));
    }
    let snapshot = require_live_generation(vault, slot, lens)?;
    let existing = decode_raw_sidecar(vault, slot, snapshot)?;
    let mut union = existing.clone();
    for (cx_id, values) in new_rows {
        if existing.contains_key(cx_id) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "append-reseal row {cx_id} already exists in slot {} generation; reseal or erase it before re-adding",
                    slot.slot_id.get()
                ),
            ));
        }
        if union.insert(*cx_id, values.clone()).is_some() {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "append-reseal new rows contain duplicate CxIds",
            ));
        }
        validate_row_base_binding(vault, slot, snapshot, *cx_id, values)?;
    }
    let union_rows: Vec<(CxId, Vec<f32>)> = union.into_iter().collect();
    let affected: Vec<CxId> = new_rows.iter().map(|(cx_id, _)| *cx_id).collect();
    commit_reseal(
        vault,
        slot,
        lens,
        &union_rows,
        queries,
        k,
        snapshot,
        GenerationTransition::AppendReseal,
        affected,
        Vec::new(),
        EntryKind::Migrate,
    )
}

/// Removes a strict subset of a manifested generation's rows, resealing the
/// survivors under a fresh generation root (`EraseReseal`).
///
/// Fails closed if the slot has no live generation, if the target set is empty,
/// contains duplicates, names a row that is not in the generation, or names
/// every row (a full-generation delete must use [`delete_compressed_generation`]).
pub fn erase_compressed_slot_rows<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    erase_ids: &[CxId],
    queries: &[CompressionQuery],
    k: usize,
) -> Result<SlotCompressionReport> {
    if erase_ids.is_empty() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            "erase-reseal requires at least one CxId to erase",
        ));
    }
    let snapshot = require_live_generation(vault, slot, lens)?;
    let existing = decode_raw_sidecar(vault, slot, snapshot)?;
    let erase_set: BTreeSet<CxId> = erase_ids.iter().copied().collect();
    if erase_set.len() != erase_ids.len() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            "erase-reseal target set contains duplicate CxIds",
        ));
    }
    for cx_id in &erase_set {
        if !existing.contains_key(cx_id) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "erase-reseal target {cx_id} is not a row of slot {} generation at seq={snapshot}",
                    slot.slot_id.get()
                ),
            ));
        }
    }
    if erase_set.len() == existing.len() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "erase-reseal cannot remove every row of slot {} generation; use delete_compressed_generation for a full-generation delete",
                slot.slot_id.get()
            ),
        ));
    }
    let survivors: Vec<(CxId, Vec<f32>)> = existing
        .iter()
        .filter(|(cx_id, _)| !erase_set.contains(cx_id))
        .map(|(cx_id, values)| (*cx_id, values.clone()))
        .collect();
    let mut extra_tombstones = Vec::with_capacity(erase_set.len() * 2);
    for cx_id in &erase_set {
        let key = slot_key(*cx_id);
        extra_tombstones.push((ColumnFamily::slot(slot.slot_id), key.clone()));
        extra_tombstones.push((ColumnFamily::slot_raw(slot.slot_id), key));
    }
    let affected: Vec<CxId> = erase_set.iter().copied().collect();
    commit_reseal(
        vault,
        slot,
        lens,
        &survivors,
        queries,
        k,
        snapshot,
        GenerationTransition::EraseReseal,
        affected,
        extra_tombstones,
        EntryKind::Erase,
    )
}

/// Removes an entire compressed generation — its manifest, every compressed
/// primary row, and every raw sidecar — in one coordinated, ledgered batch
/// (`DeleteGeneration`). No orphaned rows or manifest can remain.
///
/// Fails closed if the slot has no live generation manifest.
pub fn delete_compressed_generation<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
) -> Result<GenerationDeleteReport> {
    let snapshot = vault.latest_seq();
    if vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_manifest_key(slot.slot_id),
        )?
        .is_none()
    {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "slot {} has no live compressed generation manifest at seq={snapshot}; nothing to delete",
                slot.slot_id.get()
            ),
        ));
    }
    let primary_keys: Vec<Vec<u8>> = vault
        .scan_cf_at(snapshot, ColumnFamily::slot(slot.slot_id))?
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    let raw_keys: Vec<Vec<u8>> = vault
        .scan_cf_at(snapshot, ColumnFamily::slot_raw(slot.slot_id))?
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    let mut writes: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)> =
        Vec::with_capacity(primary_keys.len() + raw_keys.len() + 2);
    let mut deleted: Vec<CxId> = Vec::new();
    let mut deleted_set: BTreeSet<CxId> = BTreeSet::new();
    for key in &primary_keys {
        let cx_id = cx_id_from_slot_key(key)?;
        if deleted_set.insert(cx_id) {
            deleted.push(cx_id);
        }
        writes.push((
            ColumnFamily::slot(slot.slot_id),
            key.clone(),
            tombstone_value(),
        ));
    }
    for key in &raw_keys {
        let cx_id = cx_id_from_slot_key(key)?;
        if deleted_set.insert(cx_id) {
            deleted.push(cx_id);
        }
        writes.push((
            ColumnFamily::slot_raw(slot.slot_id),
            key.clone(),
            tombstone_value(),
        ));
    }
    writes.push((
        ColumnFamily::Compression,
        compression_manifest_key(slot.slot_id),
        tombstone_value(),
    ));
    let record = GenerationLifecycleRecord::new(
        GenerationTransition::DeleteGeneration,
        slot.slot_id.get(),
        snapshot,
        0,
        String::new(),
        String::new(),
        deleted
            .iter()
            .map(|cx_id| hex_bytes(cx_id.as_bytes()))
            .collect(),
    )?;
    writes.push((
        ColumnFamily::Compression,
        compression_lifecycle_key(slot.slot_id, snapshot),
        record.encode()?,
    ));
    let ledger_payload = delete_ledger_payload(slot, &deleted)?;
    let (committed, ledger_ref) = vault.write_cf_batch_with_ledger_entry_if_seq(
        snapshot,
        writes,
        EntryKind::Erase,
        compression_generation_subject(slot.slot_id),
        ledger_payload,
        ActorId::Service("calyx-registry".to_string()),
    )?;
    Ok(GenerationDeleteReport {
        slot_id: slot.slot_id.get(),
        deleted_rows: deleted.len(),
        snapshot: committed,
        ledger: ledger_ref,
    })
}

/// Reads back the append-only lifecycle records for one slot at `at_seq`, in key
/// order (ascending `prior_seq`).
pub fn generation_lifecycle<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    at_seq: Seq,
) -> Result<Vec<GenerationLifecycleRecord>> {
    let range = compression_lifecycle_prefix_range(slot.slot_id);
    let rows = vault.scan_cf_range_at(at_seq, ColumnFamily::Compression, &range)?;
    let mut records = Vec::with_capacity(rows.len());
    for (_key, value) in rows {
        records.push(GenerationLifecycleRecord::parse(&value)?);
    }
    Ok(records)
}

/// Builds the lifecycle-record CF row for a manifest-writing transition from a
/// freshly built generation report. Shared with the parent module's create path.
pub(super) fn lifecycle_record_row_from_report(
    transition: GenerationTransition,
    slot: &Slot,
    prior_seq: Seq,
    report: &SlotCompressionReport,
    affected: &[CxId],
) -> Result<(ColumnFamily, Vec<u8>, Vec<u8>)> {
    let manifest = parse_compression_manifest(&report.generation_manifest_bytes)?;
    let record = GenerationLifecycleRecord::new(
        transition,
        slot.slot_id.get(),
        prior_seq,
        manifest.generation_rows,
        hex_bytes(&manifest.generation_root),
        hex_bytes(&manifest.raw_generation_root),
        affected
            .iter()
            .map(|cx_id| hex_bytes(cx_id.as_bytes()))
            .collect(),
    )?;
    Ok((
        ColumnFamily::Compression,
        compression_lifecycle_key(slot.slot_id, prior_seq),
        record.encode()?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn commit_reseal<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
    rows: &[(CxId, Vec<f32>)],
    queries: &[CompressionQuery],
    k: usize,
    expected_seq: Seq,
    transition: GenerationTransition,
    affected: Vec<CxId>,
    extra_tombstones: Vec<(ColumnFamily, Vec<u8>)>,
    ledger_kind: EntryKind,
) -> Result<SlotCompressionReport> {
    let mut report = compress_slot_batch_with_assay_evidence(slot, lens, rows, queries, k, None)?;
    let mut writes = generation_column_writes(slot, &report);
    for (cf, key) in extra_tombstones {
        writes.push((cf, key, tombstone_value()));
    }
    writes.push(lifecycle_record_row_from_report(
        transition,
        slot,
        expected_seq,
        &report,
        &affected,
    )?);
    let ledger_payload = generation_ledger_payload(&report, transition, &affected)?;
    let (committed, ledger_ref) = vault.write_cf_batch_with_ledger_entry_if_seq(
        expected_seq,
        writes,
        ledger_kind,
        compression_generation_subject(slot.slot_id),
        ledger_payload,
        ActorId::Service("calyx-registry".to_string()),
    )?;
    report.snapshot = Some(committed);
    report.ledger = Some(ledger_ref);
    Ok(report)
}

fn generation_column_writes(
    slot: &Slot,
    report: &SlotCompressionReport,
) -> Vec<(ColumnFamily, Vec<u8>, Vec<u8>)> {
    let mut writes = Vec::with_capacity(report.rows.len() * 2 + 1);
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
    writes
}

fn require_live_generation<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    lens: &LensSpec,
) -> Result<Seq> {
    let snapshot = vault.latest_seq();
    if vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_manifest_key(slot.slot_id),
        )?
        .is_none()
    {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "slot {} has no live compressed generation manifest at seq={snapshot}; create a generation with write_compressed_slot_batch before appending or erasing",
                slot.slot_id.get()
            ),
        ));
    }
    CompressedSlotIndex::open(vault, slot, lens)?.verify_at(snapshot)?;
    Ok(snapshot)
}

fn decode_raw_sidecar<C: Clock>(
    vault: &AsterVault<C>,
    slot: &Slot,
    snapshot: Seq,
) -> Result<BTreeMap<CxId, Vec<f32>>> {
    let raw = vault.scan_cf_at(snapshot, ColumnFamily::slot_raw(slot.slot_id))?;
    if raw.is_empty() {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_EMPTY,
            format!(
                "slot {} compressed generation has no raw sidecar rows at seq={snapshot}",
                slot.slot_id.get()
            ),
        ));
    }
    let mut out = BTreeMap::new();
    for (key, value) in raw {
        let cx_id = cx_id_from_slot_key(&key)?;
        let SlotVector::Dense { data, .. } = encode::decode_slot_vector(&value)? else {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "slot {} raw sidecar row {cx_id} is not a dense vector",
                    slot.slot_id.get()
                ),
            ));
        };
        if out.insert(cx_id, data).is_some() {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed generation raw sidecar has duplicate CxId keys",
            ));
        }
    }
    Ok(out)
}

fn cx_id_from_slot_key(key: &[u8]) -> Result<CxId> {
    let bytes: [u8; 16] = key.try_into().map_err(|_| {
        compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!("slot key length {} is not a 16-byte CxId", key.len()),
        )
    })?;
    Ok(CxId::from_bytes(bytes))
}

fn delete_ledger_payload(slot: &Slot, deleted: &[CxId]) -> Result<Vec<u8>> {
    serde_json::to_vec(&json!({
        "marker": COMPRESSION_GENERATION_MARKER,
        "transition": GenerationTransition::DeleteGeneration.as_str(),
        "slot_id": slot.slot_id.get(),
        "rows": 0,
        "affected_cx_ids": deleted.iter().map(|cx_id| hex_bytes(cx_id.as_bytes())).collect::<Vec<_>>(),
    }))
    .map_err(|error| {
        compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!("delete generation ledger payload encoding failed: {error}"),
        )
    })
}
