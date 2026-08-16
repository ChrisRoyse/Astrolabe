//! Commit-time compression-generation lifecycle guard (issue #562): the
//! fail-closed state machine that admits a manifest mutation only inside a
//! coordinated, lifecycle-recorded, ledgered batch, plus its post-batch keyset
//! projection and error builders.

use super::{CompressionGuardRow, RowTable, is_tombstone_value};
use crate::cf::{
    COMPRESSED_SLOT_VALUE_TAG, ColumnFamily, SlotFamilyKind,
    compression_admission_evaluation_pointer_key, compression_admission_pointer_key,
    compression_admission_receipt_key, compression_manifest_key,
    parse_compression_admission_evaluation_pointer_key, parse_compression_admission_pointer_key,
    parse_compression_admission_receipt_key, parse_compression_lifecycle_key,
    parse_compression_membership_proof_key,
};
use crate::compression_lifecycle::{
    CALYX_COMPRESSION_LIFECYCLE_INVALID, COMPRESSION_GENERATION_MARKER, GenerationLifecycleRecord,
    compression_generation_slot_from_subject,
};
use calyx_core::{CalyxError, Result, Seq};
use calyx_ledger::{EntryKind, LedgerEntry, decode};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const COMPRESSION_ADMISSION_SCHEMA: &str = "calyx.registry.compression_admission.v2";
const COMPRESSION_ADMISSION_SUBJECT_PREFIX: &str = "compression-admission:slot:";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompressionAdmissionLedgerPayload {
    marker: String,
    slot_id: u16,
    receipt_sha256: String,
    phase: String,
    verdict: String,
}

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
/// keysets that reconcile with the declared generation geometry and the exact
/// membership-proof keyset. Isolated manifest tombstones, proof mutations,
/// slot-row tombstones under a live manifest, lifecycle records, and orphaning
/// deletes are all fail-closed refusals — the exact "orphaned generation" states
/// this guard exists to reject.
pub(super) fn validate_compression_writes(
    table: &RowTable,
    current: Seq,
    rows: &[CompressionGuardRow<'_>],
) -> Result<()> {
    let mut manifest_puts: BTreeSet<u16> = BTreeSet::new();
    let mut manifest_tombstones: BTreeSet<u16> = BTreeSet::new();
    let mut proof_mutation_slots: BTreeSet<u16> = BTreeSet::new();
    let mut lifecycle_by_slot: BTreeMap<u16, Vec<GenerationLifecycleRecord>> = BTreeMap::new();
    let mut ledger_rows: Vec<(&[u8], &[u8])> = Vec::new();
    let mut admission_receipts: BTreeMap<(u16, [u8; 32]), String> = BTreeMap::new();
    let mut evaluation_pointer_puts: Vec<(u16, [u8; 32])> = Vec::new();
    let mut evaluation_pointer_tombstones: BTreeSet<u16> = BTreeSet::new();
    let mut admission_pointer_puts: Vec<(u16, [u8; 32])> = Vec::new();
    let mut admission_pointer_tombstones: BTreeSet<u16> = BTreeSet::new();

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
                } else if let Some((slot_id, _cx_id)) = parse_compression_membership_proof_key(key)
                {
                    proof_mutation_slots.insert(slot_id.get());
                } else if let Some((slot_id, receipt_sha256)) =
                    parse_compression_admission_receipt_key(key)
                {
                    if is_tombstone_value(value) {
                        return Err(compression_write_error(format!(
                            "compression admission receipts are immutable; slot {} cannot tombstone receipt {}",
                            slot_id.get(),
                            hex(&receipt_sha256)
                        )));
                    }
                    let observed: [u8; 32] = Sha256::digest(value).into();
                    if observed != receipt_sha256 {
                        return Err(compression_write_error(format!(
                            "compression admission receipt key hash {} does not match value hash {} for slot {}",
                            hex(&receipt_sha256),
                            hex(&observed),
                            slot_id.get()
                        )));
                    }
                    if visible_value(table, current, ColumnFamily::Compression, key)
                        .is_some_and(|bytes| !is_tombstone_value(bytes))
                    {
                        return Err(compression_write_error(format!(
                            "compression admission receipt {} for slot {} already exists and cannot be overwritten",
                            hex(&receipt_sha256),
                            slot_id.get()
                        )));
                    }
                    let receipt_value: serde_json::Value =
                        serde_json::from_slice(value).map_err(|error| {
                            compression_write_error(format!(
                                "compression admission receipt {} for slot {} is not JSON: {error}",
                                hex(&receipt_sha256),
                                slot_id.get()
                            ))
                        })?;
                    let receipt_schema =
                        receipt_value.get("schema").and_then(|value| value.as_str());
                    let receipt_slot = receipt_value
                        .get("slot_id")
                        .and_then(|value| value.as_u64());
                    let receipt_verdict = receipt_value
                        .get("verdict")
                        .and_then(|value| value.as_str())
                        .filter(|value| matches!(*value, "admitted" | "refused"))
                        .ok_or_else(|| {
                            compression_write_error(format!(
                                "compression admission receipt {} for slot {} has no supported verdict",
                                hex(&receipt_sha256),
                                slot_id.get()
                            ))
                        })?;
                    if receipt_schema != Some(COMPRESSION_ADMISSION_SCHEMA)
                        || receipt_slot != Some(u64::from(slot_id.get()))
                    {
                        return Err(compression_write_error(format!(
                            "compression admission receipt {} key does not match its schema/slot identity for slot {}",
                            hex(&receipt_sha256),
                            slot_id.get()
                        )));
                    }
                    if admission_receipts
                        .insert((slot_id.get(), receipt_sha256), receipt_verdict.to_string())
                        .is_some()
                    {
                        return Err(compression_write_error(format!(
                            "compression admission batch repeats receipt {} for slot {}",
                            hex(&receipt_sha256),
                            slot_id.get()
                        )));
                    }
                } else if let Some(slot_id) =
                    parse_compression_admission_evaluation_pointer_key(key)
                {
                    if is_tombstone_value(value) {
                        if !evaluation_pointer_tombstones.insert(slot_id.get()) {
                            return Err(compression_write_error(format!(
                                "compression generation batch repeats latest-evaluation pointer tombstone for slot {}",
                                slot_id.get()
                            )));
                        }
                    } else if value.len() != 32 {
                        return Err(compression_write_error(format!(
                            "latest compression-evaluation pointer for slot {} must be one 32-byte receipt hash",
                            slot_id.get()
                        )));
                    } else {
                        let mut receipt_sha256 = [0_u8; 32];
                        receipt_sha256.copy_from_slice(value);
                        evaluation_pointer_puts.push((slot_id.get(), receipt_sha256));
                    }
                } else if let Some(slot_id) = parse_compression_admission_pointer_key(key) {
                    if is_tombstone_value(value) {
                        if !admission_pointer_tombstones.insert(slot_id.get()) {
                            return Err(compression_write_error(format!(
                                "compression generation batch repeats current-admission pointer tombstone for slot {}",
                                slot_id.get()
                            )));
                        }
                    } else if value.len() != 32 {
                        return Err(compression_write_error(format!(
                            "current compression-admission pointer for slot {} must be one 32-byte receipt hash",
                            slot_id.get()
                        )));
                    } else {
                        let mut receipt_sha256 = [0_u8; 32];
                        receipt_sha256.copy_from_slice(value);
                        admission_pointer_puts.push((slot_id.get(), receipt_sha256));
                    }
                } else {
                    return Err(compression_write_error(format!(
                        "compression CF key must be a manifest, lifecycle record, membership proof, immutable admission receipt, latest-evaluation pointer, or current-admission pointer, got {} bytes",
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
    for slot in proof_mutation_slots {
        if !manifest_puts.contains(&slot) && !manifest_tombstones.contains(&slot) {
            return Err(lifecycle_guard_error(format!(
                "slot {slot} mutates compression membership proofs without mutating the same slot manifest in the batch"
            )));
        }
    }

    // Decode and hash-check Ledger bytes whenever a compression transition is
    // present, or when a row contains the reserved compression marker. The
    // latter catches orphaned/malformed reserved subjects without imposing a
    // decode on unrelated high-throughput ingest batches.
    let marker = COMPRESSION_GENERATION_MARKER.as_bytes();
    let transition_in_batch = !transition_slots.is_empty();
    let admission_in_batch = !admission_receipts.is_empty()
        || !evaluation_pointer_puts.is_empty()
        || !admission_pointer_puts.is_empty();
    if admission_in_batch && transition_in_batch {
        return Err(compression_write_error(
            "compression admission publication and generation mutation must be distinct durable transactions"
                .to_string(),
        ));
    }
    for slot in evaluation_pointer_tombstones
        .iter()
        .chain(&admission_pointer_tombstones)
    {
        if !transition_slots.contains(slot) {
            return Err(compression_write_error(format!(
                "compression admission pointer tombstone for slot {slot} requires the same slot generation mutation"
            )));
        }
    }
    let mut ledger_by_slot: BTreeMap<u16, Vec<LedgerEntry>> = BTreeMap::new();
    let mut admission_ledger_entries = Vec::new();
    for (key, value) in ledger_rows {
        if !transition_in_batch
            && !admission_in_batch
            && !value.windows(marker.len()).any(|window| window == marker)
        {
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
        } else if entry.kind == EntryKind::Admission {
            admission_ledger_entries.push(entry);
        }
    }
    if admission_in_batch && admission_ledger_entries.len() != 1 {
        return Err(compression_write_error(format!(
            "compression admission mutation requires exactly one EntryKind::Admission ledger row in the same batch, found {}",
            admission_ledger_entries.len()
        )));
    }
    if admission_in_batch {
        validate_admission_publication(
            table,
            current,
            &admission_receipts,
            &evaluation_pointer_puts,
            &admission_pointer_puts,
            &admission_ledger_entries[0],
        )?;
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

    // Project all transitioned slots in one table pass. Re-running a complete
    // keyset verifier per slot would multiply the same work (#1064 PC-05/09).
    let post_batch_keysets = if transition_slots.is_empty() {
        BTreeMap::new()
    } else {
        post_batch_generation_keysets(table, current, &transition_slots, rows)
    };

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
        let slot_id = calyx_core::SlotId::new(slot);
        let live_evaluation_pointer = visible_value(
            table,
            current,
            ColumnFamily::Compression,
            &compression_admission_evaluation_pointer_key(slot_id),
        )
        .is_some_and(|bytes| !is_tombstone_value(bytes));
        if live_evaluation_pointer && !evaluation_pointer_tombstones.contains(&slot) {
            return Err(lifecycle_guard_error(format!(
                "slot {slot} generation mutation must tombstone its live latest-evaluation pointer in the same batch"
            )));
        }
        let live_admission_pointer = visible_value(
            table,
            current,
            ColumnFamily::Compression,
            &compression_admission_pointer_key(slot_id),
        )
        .is_some_and(|bytes| !is_tombstone_value(bytes));
        if live_admission_pointer && !admission_pointer_tombstones.contains(&slot) {
            return Err(lifecycle_guard_error(format!(
                "slot {slot} generation mutation must tombstone its live current-admission pointer in the same batch"
            )));
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

        let keysets = post_batch_keysets
            .get(&slot)
            .expect("every transition slot has a projected keyset");
        let primary_keys = &keysets.primary;
        let raw_keys = &keysets.raw;
        let proof_keys = &keysets.proofs;
        if has_put {
            // (d) Every live primary row has one proof consumed by bounded
            // authenticated point reads (#564/#1064 PC-35).
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
            if primary_keys != proof_keys {
                return Err(lifecycle_guard_error(format!(
                    "slot {slot} manifest put leaves divergent primary ({}) and membership-proof ({}) keysets",
                    primary_keys.len(),
                    proof_keys.len()
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
            if !primary_keys.is_empty() || !raw_keys.is_empty() || !proof_keys.is_empty() {
                return Err(lifecycle_guard_error(format!(
                    "slot {slot} manifest tombstone leaves {} primary, {} raw-sidecar, and {} membership-proof rows; a delete must remove the entire generation",
                    primary_keys.len(),
                    raw_keys.len(),
                    proof_keys.len()
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

fn validate_admission_publication(
    table: &RowTable,
    current: Seq,
    receipts: &BTreeMap<(u16, [u8; 32]), String>,
    evaluation_pointers: &[(u16, [u8; 32])],
    admission_pointers: &[(u16, [u8; 32])],
    ledger: &LedgerEntry,
) -> Result<()> {
    let (slot, receipt_sha256, phase, verdict) = match (
        receipts.len(),
        evaluation_pointers,
        admission_pointers,
    ) {
        (1, [(pointer_slot, pointer_digest)], []) => {
            let (&(receipt_slot, receipt_digest), receipt_verdict) = receipts
                .first_key_value()
                .expect("receipt length was checked");
            if receipt_slot != *pointer_slot || receipt_digest != *pointer_digest {
                return Err(compression_write_error(
                    "latest compression-evaluation pointer must reference the exact immutable receipt staged in the same batch"
                        .to_string(),
                ));
            }
            (
                receipt_slot,
                receipt_digest,
                "evaluation",
                receipt_verdict.as_str(),
            )
        }
        (0, [], [(pointer_slot, pointer_digest)]) => {
            let receipt_verdict = persisted_admission_receipt_verdict(
                table,
                current,
                *pointer_slot,
                *pointer_digest,
            )?;
            if receipt_verdict != "admitted" {
                return Err(compression_write_error(format!(
                    "current compression-admission pointer for slot {pointer_slot} references a {receipt_verdict} receipt"
                )));
            }
            let latest_key = compression_admission_evaluation_pointer_key(calyx_core::SlotId::new(
                *pointer_slot,
            ));
            let latest = visible_value(table, current, ColumnFamily::Compression, &latest_key)
                .filter(|value| !is_tombstone_value(value))
                .ok_or_else(|| {
                    compression_write_error(format!(
                        "current compression-admission pointer for slot {pointer_slot} has no live latest-evaluation pointer"
                    ))
                })?;
            if latest != pointer_digest {
                return Err(compression_write_error(format!(
                    "current compression-admission pointer for slot {pointer_slot} does not reference the latest evaluated receipt {}",
                    hex(pointer_digest)
                )));
            }
            (*pointer_slot, *pointer_digest, "publish", "admitted")
        }
        _ => {
            return Err(compression_write_error(format!(
                "compression admission transaction has an invalid shape: receipts={} latest_evaluation_pointers={} current_admission_pointers={}",
                receipts.len(),
                evaluation_pointers.len(),
                admission_pointers.len()
            )));
        }
    };

    let expected_subject = format!("{COMPRESSION_ADMISSION_SUBJECT_PREFIX}{slot}").into_bytes();
    if ledger.kind != EntryKind::Admission
        || ledger.subject != calyx_ledger::SubjectId::Query(expected_subject)
    {
        return Err(compression_write_error(format!(
            "compression admission {phase} for slot {slot} requires the exact reserved Admission ledger subject"
        )));
    }
    let payload: CompressionAdmissionLedgerPayload = serde_json::from_slice(&ledger.payload)
        .map_err(|error| {
            compression_write_error(format!(
                "compression admission {phase} ledger payload for slot {slot} is malformed: {error}"
            ))
        })?;
    if payload.marker != COMPRESSION_ADMISSION_SCHEMA
        || payload.slot_id != slot
        || payload.receipt_sha256 != hex(&receipt_sha256)
        || payload.phase != phase
        || payload.verdict != verdict
    {
        return Err(compression_write_error(format!(
            "compression admission {phase} ledger payload does not bind slot {slot}, receipt {}, and verdict {verdict}",
            hex(&receipt_sha256)
        )));
    }
    Ok(())
}

fn persisted_admission_receipt_verdict(
    table: &RowTable,
    current: Seq,
    slot: u16,
    receipt_sha256: [u8; 32],
) -> Result<String> {
    let receipt_key =
        compression_admission_receipt_key(calyx_core::SlotId::new(slot), receipt_sha256);
    let receipt = visible_value(table, current, ColumnFamily::Compression, &receipt_key)
        .filter(|value| !is_tombstone_value(value))
        .ok_or_else(|| {
            compression_write_error(format!(
                "compression admission pointer for slot {slot} references absent immutable receipt {}",
                hex(&receipt_sha256)
            ))
        })?;
    let observed: [u8; 32] = Sha256::digest(receipt).into();
    if observed != receipt_sha256 {
        return Err(compression_write_error(format!(
            "persisted compression admission receipt for slot {slot} has hash {} instead of key hash {}",
            hex(&observed),
            hex(&receipt_sha256)
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(receipt).map_err(|error| {
        compression_write_error(format!(
            "persisted compression admission receipt for slot {slot} is malformed: {error}"
        ))
    })?;
    if value.get("schema").and_then(|field| field.as_str()) != Some(COMPRESSION_ADMISSION_SCHEMA)
        || value.get("slot_id").and_then(|field| field.as_u64()) != Some(u64::from(slot))
    {
        return Err(compression_write_error(format!(
            "persisted compression admission receipt for slot {slot} has mismatched schema/slot identity"
        )));
    }
    value
        .get("verdict")
        .and_then(|field| field.as_str())
        .filter(|value| matches!(*value, "admitted" | "refused"))
        .map(ToString::to_string)
        .ok_or_else(|| {
            compression_write_error(format!(
                "persisted compression admission receipt for slot {slot} has no supported verdict"
            ))
        })
}

#[derive(Default)]
struct GenerationKeysets {
    primary: BTreeSet<Vec<u8>>,
    raw: BTreeSet<Vec<u8>>,
    proofs: BTreeSet<Vec<u8>>,
}

/// Visible generation keysets at `current`, after applying `rows` in batch
/// order. Proof addresses are projected to their embedded `CxId`, so all three
/// sets compare in the primary-column key domain.
fn post_batch_generation_keysets(
    table: &RowTable,
    current: Seq,
    transition_slots: &BTreeSet<u16>,
    rows: &[CompressionGuardRow<'_>],
) -> BTreeMap<u16, GenerationKeysets> {
    let mut keysets = transition_slots
        .iter()
        .copied()
        .map(|slot| (slot, GenerationKeysets::default()))
        .collect::<BTreeMap<_, _>>();
    for ((row_cf, key), versions) in table {
        let Some(version) = versions.iter().rev().find(|version| version.seq <= current) else {
            continue;
        };
        if is_tombstone_value(&version.value) {
            continue;
        }
        match row_cf {
            ColumnFamily::Slot { slot, kind } if transition_slots.contains(&slot.get()) => {
                let projected = keysets
                    .get_mut(&slot.get())
                    .expect("transition slot was pre-initialized");
                match kind {
                    SlotFamilyKind::Quantized => {
                        projected.primary.insert(key.clone());
                    }
                    SlotFamilyKind::Raw => {
                        projected.raw.insert(key.clone());
                    }
                }
            }
            ColumnFamily::Compression => {
                if let Some((slot, cx_id)) = parse_compression_membership_proof_key(key)
                    && let Some(projected) = keysets.get_mut(&slot.get())
                {
                    projected.proofs.insert(cx_id.as_bytes().to_vec());
                }
            }
            _ => {}
        }
    }
    for &(row_cf, key, value) in rows {
        match row_cf {
            ColumnFamily::Slot { slot, kind } if transition_slots.contains(&slot.get()) => {
                let projected = keysets
                    .get_mut(&slot.get())
                    .expect("transition slot was pre-initialized");
                let keys = match kind {
                    SlotFamilyKind::Quantized => &mut projected.primary,
                    SlotFamilyKind::Raw => &mut projected.raw,
                };
                apply_batch_value(keys, key, value);
            }
            ColumnFamily::Compression => {
                if let Some((slot, cx_id)) = parse_compression_membership_proof_key(key)
                    && let Some(projected) = keysets.get_mut(&slot.get())
                {
                    apply_batch_value(&mut projected.proofs, cx_id.as_bytes(), value);
                }
            }
            _ => {}
        }
    }
    keysets
}

fn apply_batch_value(keys: &mut BTreeSet<Vec<u8>>, key: &[u8], value: &[u8]) {
    if is_tombstone_value(value) {
        keys.remove(key);
    } else {
        keys.insert(key.to_vec());
    }
}

fn lifecycle_guard_error(message: String) -> CalyxError {
    CalyxError {
        code: CALYX_COMPRESSION_LIFECYCLE_INVALID,
        message,
        remediation: "commit compressed slot generation transitions through the registry lifecycle API: one seq-guarded batch carrying each manifest mutation, its resealed rows and membership proofs, one append-only lifecycle record, and exactly one canonical slot-matched Ledger entry",
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
