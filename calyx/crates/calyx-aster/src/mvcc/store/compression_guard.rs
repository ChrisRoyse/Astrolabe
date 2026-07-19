//! Commit-time compression-generation lifecycle guard (issue #562): the
//! fail-closed state machine that admits a manifest mutation only inside a
//! coordinated, lifecycle-recorded, ledgered batch, plus its post-batch keyset
//! projection and error builders.

use super::{CompressionGuardRow, RowTable, is_tombstone_value};
use crate::cf::{
    COMPRESSED_SLOT_VALUE_TAG, ColumnFamily, SlotFamilyKind, compression_manifest_key,
    parse_compression_lifecycle_key,
};
use crate::compression_lifecycle::{
    CALYX_COMPRESSION_LIFECYCLE_INVALID, COMPRESSION_GENERATION_MARKER, GenerationLifecycleRecord,
    compression_generation_slot_from_subject,
};
use calyx_core::{CalyxError, Result, Seq};
use calyx_ledger::{LedgerEntry, decode};
use std::collections::{BTreeMap, BTreeSet};

/// Commit-time state machine enforcing the lawful lifecycle of compressed slot
/// generations (issue #562).
///
/// Every manifest mutation — a manifest put (`Create`/`Migrate`/`Reseal`/
/// `AppendReseal`/`EraseReseal`) or a manifest tombstone (`DeleteGeneration`) —
/// must arrive in one seq-guarded batch alongside (a) exactly one append-only
/// [`GenerationLifecycleRecord`] for the slot whose `prior_seq` equals the
/// committing sequence, (b) exactly one hash-valid [`ColumnFamily::Ledger`] row
/// whose reserved subject and payload identify that same slot and transition,
/// (c) a transition kind matching the batch shape, and (d)/(e) primary and raw
/// keysets that reconcile with the declared generation geometry. Isolated
/// manifest tombstones, isolated slot-row tombstones under a live manifest,
/// isolated lifecycle records, and orphaning deletes are all fail-closed
/// refusals — the exact "orphaned generation" states this guard exists to reject.
pub(super) fn validate_compression_writes(
    table: &RowTable,
    current: Seq,
    rows: &[CompressionGuardRow<'_>],
) -> Result<()> {
    let mut manifest_puts: BTreeSet<u16> = BTreeSet::new();
    let mut manifest_tombstones: BTreeSet<u16> = BTreeSet::new();
    let mut lifecycle_by_slot: BTreeMap<u16, Vec<GenerationLifecycleRecord>> = BTreeMap::new();
    let mut ledger_rows: Vec<(&[u8], &[u8])> = Vec::new();

    for &(cf, key, value) in rows {
        match cf {
            ColumnFamily::Ledger => ledger_rows.push((key, value)),
            ColumnFamily::Compression => {
                if key.len() == 2 {
                    let slot = u16::from_be_bytes([key[0], key[1]]);
                    if is_tombstone_value(value) {
                        manifest_tombstones.insert(slot);
                    } else {
                        manifest_puts.insert(slot);
                    }
                } else if let Some((slot_id, prior_seq)) = parse_compression_lifecycle_key(key) {
                    if is_tombstone_value(value) {
                        return Err(lifecycle_guard_error(format!(
                            "compression lifecycle records are append-only; slot {} cannot tombstone a lifecycle record",
                            slot_id.get()
                        )));
                    }
                    let record = GenerationLifecycleRecord::parse(value)?;
                    if record.slot_id != slot_id.get() {
                        return Err(lifecycle_guard_error(format!(
                            "lifecycle record slot id {} does not match its CF key slot id {}",
                            record.slot_id,
                            slot_id.get()
                        )));
                    }
                    if record.prior_seq != prior_seq {
                        return Err(lifecycle_guard_error(format!(
                            "lifecycle record prior_seq {} does not match its CF key prior_seq {prior_seq}",
                            record.prior_seq
                        )));
                    }
                    lifecycle_by_slot
                        .entry(slot_id.get())
                        .or_default()
                        .push(record);
                } else {
                    return Err(compression_write_error(format!(
                        "compression CF key must be a two-byte slot manifest key or an eleven-byte lifecycle-record key, got {} bytes",
                        key.len()
                    )));
                }
            }
            _ => {}
        }
    }

    let mut transition_slots: BTreeSet<u16> = BTreeSet::new();
    transition_slots.extend(manifest_puts.iter().copied());
    transition_slots.extend(manifest_tombstones.iter().copied());
    transition_slots.extend(lifecycle_by_slot.keys().copied());

    // Decode and hash-check Ledger bytes whenever a compression transition is
    // present, or when a row contains the reserved compression marker. The
    // latter catches orphaned/malformed reserved subjects without imposing a
    // decode on unrelated high-throughput ingest batches.
    let marker = COMPRESSION_GENERATION_MARKER.as_bytes();
    let transition_in_batch = !transition_slots.is_empty();
    let mut ledger_by_slot: BTreeMap<u16, Vec<LedgerEntry>> = BTreeMap::new();
    for (key, value) in ledger_rows {
        if !transition_in_batch && !value.windows(marker.len()).any(|window| window == marker) {
            continue;
        }
        let entry = decode(value)?;
        let key_seq = u64::from_be_bytes(key.try_into().map_err(|_| {
            lifecycle_guard_error(format!(
                "compression transition Ledger key must be eight-byte big-endian sequence, got {} bytes",
                key.len()
            ))
        })?);
        if entry.seq != key_seq {
            return Err(lifecycle_guard_error(format!(
                "compression transition Ledger key seq {key_seq} does not match encoded seq {}",
                entry.seq
            )));
        }
        if let Some(slot) = compression_generation_slot_from_subject(&entry.subject)? {
            ledger_by_slot.entry(slot.get()).or_default().push(entry);
        }
    }
    for (&slot, entries) in &ledger_by_slot {
        if !manifest_puts.contains(&slot) && !manifest_tombstones.contains(&slot) {
            return Err(lifecycle_guard_error(format!(
                "slot {slot} has {} compression-generation Ledger entr{} but no manifest mutation in the same batch",
                entries.len(),
                if entries.len() == 1 { "y" } else { "ies" }
            )));
        }
    }

    for slot in transition_slots.iter().copied() {
        let has_put = manifest_puts.contains(&slot);
        let has_tombstone = manifest_tombstones.contains(&slot);
        let records = lifecycle_by_slot
            .get(&slot)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        if has_put && has_tombstone {
            return Err(lifecycle_guard_error(format!(
                "slot {slot} batch both puts and tombstones its compression manifest"
            )));
        }
        // (b) A lifecycle record is never committed without its manifest mutation.
        if !records.is_empty() && !has_put && !has_tombstone {
            return Err(lifecycle_guard_error(format!(
                "slot {slot} carries a lifecycle record with no manifest put or tombstone in the same batch"
            )));
        }
        if !has_put && !has_tombstone {
            continue;
        }
        // (a) A manifest mutation requires exactly one lifecycle record.
        if records.len() != 1 {
            return Err(lifecycle_guard_error(format!(
                "slot {slot} manifest mutation requires exactly one lifecycle record in the same batch, found {}",
                records.len()
            )));
        }
        let record = &records[0];
        // (a) Bound to the committing sequence and to a ledger row in this batch.
        if record.prior_seq != current {
            return Err(lifecycle_guard_error(format!(
                "slot {slot} lifecycle record prior_seq {} does not match the committing sequence {current}",
                record.prior_seq
            )));
        }
        let ledger_entries = ledger_by_slot.get(&slot).map(Vec::as_slice).unwrap_or(&[]);
        if ledger_entries.len() != 1 {
            return Err(lifecycle_guard_error(format!(
                "slot {slot} manifest mutation requires exactly one slot-matched compression-generation Ledger entry in the same batch, found {}",
                ledger_entries.len()
            )));
        }
        record.validate_ledger_payload(&ledger_entries[0].payload)?;
        // (c) The transition kind must match the batch shape.
        if record.transition.writes_manifest() != has_put {
            return Err(lifecycle_guard_error(format!(
                "slot {slot} lifecycle transition {} does not match its batch shape (manifest {})",
                record.transition.as_str(),
                if has_put { "put" } else { "tombstone" }
            )));
        }

        let slot_id = calyx_core::SlotId::new(slot);
        let primary_keys = post_batch_keyset(table, current, ColumnFamily::slot(slot_id), rows);
        let raw_keys = post_batch_keyset(table, current, ColumnFamily::slot_raw(slot_id), rows);
        if has_put {
            // (d) A live generation is a non-empty, coordinated primary+raw column.
            if primary_keys.is_empty() {
                return Err(lifecycle_guard_error(format!(
                    "slot {slot} manifest put leaves no compressed primary rows"
                )));
            }
            if primary_keys != raw_keys {
                return Err(lifecycle_guard_error(format!(
                    "slot {slot} manifest put leaves divergent primary ({}) and raw-sidecar ({}) keysets",
                    primary_keys.len(),
                    raw_keys.len()
                )));
            }
            let row_count = u32::try_from(primary_keys.len()).map_err(|_| {
                lifecycle_guard_error(format!(
                    "slot {slot} generation row count {} exceeds u32",
                    primary_keys.len()
                ))
            })?;
            if row_count != record.generation_rows {
                return Err(lifecycle_guard_error(format!(
                    "slot {slot} lifecycle record declares {} rows but the batch leaves {row_count} compressed rows",
                    record.generation_rows
                )));
            }
        } else {
            // (e) A delete removes the whole generation; no orphans may remain.
            if !primary_keys.is_empty() || !raw_keys.is_empty() {
                return Err(lifecycle_guard_error(format!(
                    "slot {slot} manifest tombstone leaves {} primary and {} raw-sidecar rows; a delete must remove the entire generation",
                    primary_keys.len(),
                    raw_keys.len()
                )));
            }
        }
    }

    // Per-row rules: compressed slot columns may only move inside a transition
    // batch, compressed-tagged rows require a manifest, and a manifest put may
    // not carry an uncompressed primary row.
    for &(cf, _key, value) in rows {
        let ColumnFamily::Slot { slot, kind } = cf else {
            continue;
        };
        let slot_u16 = slot.get();
        let manifest_mutated =
            manifest_puts.contains(&slot_u16) || manifest_tombstones.contains(&slot_u16);
        let manifest_exists = visible_value(
            table,
            current,
            ColumnFamily::Compression,
            &compression_manifest_key(slot),
        )
        .is_some_and(|bytes| !is_tombstone_value(bytes));
        // (f) A manifested (compressed) slot's rows may only move inside a batch
        // that also mutates the manifest and records the transition.
        if manifest_exists && !manifest_mutated {
            return Err(compression_write_error(format!(
                "slot {slot_u16} belongs to a compressed generation; update its rows, compression manifest, and lifecycle record in one conditional batch"
            )));
        }
        if kind == SlotFamilyKind::Quantized {
            let is_compressed_value = value.first().copied() == Some(COMPRESSED_SLOT_VALUE_TAG);
            if is_compressed_value {
                if !manifest_exists && !manifest_mutated {
                    return Err(compression_write_error(format!(
                        "compressed slot {slot_u16} row has no atomic generation manifest"
                    )));
                }
            } else if !is_tombstone_value(value) && manifest_puts.contains(&slot_u16) {
                return Err(compression_write_error(format!(
                    "compression manifest put for slot {slot_u16} contains a non-compressed primary row"
                )));
            }
        }
    }
    Ok(())
}

/// Visible (non-tombstone) keyset of `cf` at `current`, after applying `rows`'
/// puts and tombstones in batch order — the state the batch would leave behind.
fn post_batch_keyset(
    table: &RowTable,
    current: Seq,
    cf: ColumnFamily,
    rows: &[CompressionGuardRow<'_>],
) -> BTreeSet<Vec<u8>> {
    let mut keys = BTreeSet::new();
    for ((row_cf, key), versions) in table {
        if *row_cf != cf {
            continue;
        }
        if let Some(version) = versions.iter().rev().find(|version| version.seq <= current)
            && !is_tombstone_value(&version.value)
        {
            keys.insert(key.clone());
        }
    }
    for &(row_cf, key, value) in rows {
        if row_cf != cf {
            continue;
        }
        if is_tombstone_value(value) {
            keys.remove(key);
        } else {
            keys.insert(key.to_vec());
        }
    }
    keys
}

fn lifecycle_guard_error(message: String) -> CalyxError {
    CalyxError {
        code: CALYX_COMPRESSION_LIFECYCLE_INVALID,
        message,
        remediation: "commit compressed slot generation transitions through the registry lifecycle API: one seq-guarded batch carrying each manifest mutation, its resealed rows, one append-only lifecycle record, and exactly one canonical slot-matched Ledger entry",
    }
}

fn visible_value<'a>(
    table: &'a RowTable,
    current: Seq,
    cf: ColumnFamily,
    key: &[u8],
) -> Option<&'a [u8]> {
    table
        .get(&(cf, key.to_vec()))?
        .iter()
        .rev()
        .find(|value| value.seq <= current)
        .map(|value| value.value.as_slice())
}

fn compression_write_error(message: String) -> CalyxError {
    CalyxError {
        code: "CALYX_ASTER_COMPRESSED_SLOT_WRITE_REQUIRES_MANIFEST",
        message,
        remediation: "use the registry compression writer to replace the complete slot column and generation manifest atomically",
    }
}
