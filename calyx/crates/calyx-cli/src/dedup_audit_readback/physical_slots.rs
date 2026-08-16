//! Physical slot-CF readback for `cx-list --include-slots`.
//!
//! Base rows persist only slot ids plus payload hashes, so
//! [`decode_constellation_base`] always yields `Absent` placeholders that carry
//! no payload state. The primary slot CF is the only payload source this command
//! reports. Compressed primaries are interpreted by the persisted Registry
//! context; `slot_raw` is checked only as a required lifecycle sidecar and is
//! never decoded or substituted. Split out of the parent module to keep each
//! file within the modularization line budget (issue #1098).

use std::collections::BTreeMap;
use std::path::Path;

use calyx_aster::cf::{ColumnFamily, compression_manifest_key, slot_key};
use calyx_aster::mvcc::is_tombstone_value;
use calyx_aster::vault::encode::decode_slot_vector;
use calyx_core::{CalyxError, Constellation, CxId, QuantPolicy, Slot, SlotId, SlotVector};
use calyx_registry::{COMPRESSED_SLOT_TAG, VaultPanelState, load_vault_panel_state};
use serde_json::json;

use super::check_deadline;
use crate::bounded_progress::{Deadline, ProgressSink};
use crate::cf_read::hex_bytes;
use crate::error::{CliError, CliResult};
use crate::provenance_read::{ResolvedRow, RowSource, VaultReadContext};

mod compressed;

use compressed::{CompressedCandidate, resolve_compressed_slots};

pub(super) fn slot_row_json(slot: SlotId, state: &PhysicalSlotState) -> serde_json::Value {
    match state {
        PhysicalSlotState::Tombstoned { payload_source } => json!({
            "slot": slot.get(),
            "kind": "tombstoned",
            "payload_source": payload_source,
        }),
        PhysicalSlotState::Vector {
            vector,
            payload_source,
        } => match vector {
            SlotVector::Dense { dim, data } => json!({
                "slot": slot.get(),
                "kind": "dense",
                "payload_source": payload_source,
                "dim": dim,
                "values": data.len(),
            }),
            SlotVector::Sparse { dim, entries } => json!({
                "slot": slot.get(),
                "kind": "sparse",
                "payload_source": payload_source,
                "dim": dim,
                "entries": entries.len(),
            }),
            SlotVector::Multi { token_dim, tokens } => json!({
                "slot": slot.get(),
                "kind": "multi",
                "payload_source": payload_source,
                "token_dim": token_dim,
                "tokens": tokens.len(),
            }),
            SlotVector::Absent { reason } => json!({
                "slot": slot.get(),
                "kind": "absent",
                "payload_source": payload_source,
                "reason": reason,
            }),
        },
        PhysicalSlotState::Compressed {
            dim,
            values,
            payload_source,
        } => json!({
            "slot": slot.get(),
            "kind": "compressed",
            "payload_source": payload_source,
            "interpretation_source": "registry_compressed_slot_index",
            "validation": "frozen_context_and_membership_proof",
            "dim": dim,
            "values": values,
        }),
    }
}

pub(super) fn tombstone_row(key: &[u8]) -> serde_json::Value {
    json!({
        "key_hex": hex_bytes(key),
        "cx_id": cx_id_from_base_key(key).map(|id| id.to_string()),
        "base_visible": false,
        "tombstoned": true,
        "slot_payloads_decoded": false,
        "slot_payload_decode_mode": "mvcc_tombstone",
    })
}

fn cx_id_from_base_key(key: &[u8]) -> Option<CxId> {
    let bytes: [u8; 16] = key.try_into().ok()?;
    Some(CxId::from_bytes(bytes))
}

/// Physical state of one slot resolved from the slot column families.
#[derive(Debug)]
pub(super) enum PhysicalSlotState {
    Vector {
        vector: SlotVector,
        payload_source: &'static str,
    },
    Compressed {
        dim: u32,
        values: usize,
        payload_source: &'static str,
    },
    Tombstoned {
        payload_source: &'static str,
    },
}

enum LocatedSlotState {
    Resolved(PhysicalSlotState),
    Compressed(CompressedCandidate),
}

/// Reads the current physical slot CF rows for every base-listed slot of every
/// live constellation, grouped per slot CF. Compression create/reseal mutates
/// slot keys after their Base rows were committed, so the Base Ledger sequence
/// remains diagnostic context and must not select the original pre-compression
/// commit. A base-listed slot with no current physical
/// `slot_XX`/`slot_raw_XX` row fails closed as `CALYX_ASTER_CORRUPT_SHARD`
/// instead of being reported as absent.
pub(super) fn physical_slot_states(
    vault: &Path,
    constellations: &[&Constellation],
    deadline: &Deadline,
    progress: &mut ProgressSink,
) -> CliResult<BTreeMap<(CxId, SlotId), PhysicalSlotState>> {
    let panel_state = load_vault_panel_state(vault)?;
    let panel_slots = validated_panel_slots(vault, &panel_state, constellations)?;
    let mut per_slot: BTreeMap<SlotId, Vec<(CxId, Vec<u8>, u64)>> = BTreeMap::new();
    for cx in constellations {
        for slot in cx.slots.keys() {
            per_slot.entry(*slot).or_default().push((
                cx.cx_id,
                slot_key(cx.cx_id),
                cx.provenance.seq,
            ));
        }
    }
    let mut read_context = VaultReadContext::new(vault);
    let manifest_keys = per_slot
        .keys()
        .map(|slot| compression_manifest_key(*slot))
        .collect::<Vec<_>>();
    let manifests =
        read_context.latest_cf_rows_for_current_state(ColumnFamily::Compression, &manifest_keys)?;
    let mut out = BTreeMap::new();
    let mut compressed = BTreeMap::<SlotId, Vec<CompressedCandidate>>::new();
    for (slot, members) in &per_slot {
        check_deadline(deadline, progress, "slot_lookup", out.len() as u64)?;
        progress.emit(json!({
            "event": "cx_list.progress",
            "phase": "slot_lookup",
            "slot": slot.get(),
            "rows": members.len(),
            "elapsed_ms": deadline.elapsed_ms(),
        }))?;
        let keys = members
            .iter()
            .map(|(_, key, _)| key.clone())
            .collect::<Vec<_>>();
        let batch =
            read_context.latest_cf_rows_for_current_state(ColumnFamily::slot(*slot), &keys)?;
        let raw_batch =
            read_context.latest_cf_rows_for_current_state(ColumnFamily::slot_raw(*slot), &keys)?;
        progress.emit(json!({
            "event": "cx_list.progress",
            "phase": "slot_lookup_resolved",
            "slot": slot.get(),
            "read_stats": batch.stats,
            "primary_read_stats": batch.stats,
            "raw_sidecar_read_stats": raw_batch.stats,
            "elapsed_ms": deadline.elapsed_ms(),
        }))?;
        let panel_slot = panel_slots.get(slot).copied().ok_or_else(|| {
            missing_panel_slot_error(vault, *slot, "slot disappeared from validated panel map")
        })?;
        let manifest_key = compression_manifest_key(*slot);
        let has_live_compression_manifest = manifests
            .rows
            .get(&manifest_key)
            .and_then(Option::as_ref)
            .is_some_and(|row| !is_tombstone_value(&row.value));
        for (cx_id, key, seq) in members {
            let primary = batch.rows.get(key).and_then(Option::as_ref);
            let raw = raw_batch.rows.get(key).and_then(Option::as_ref);
            match resolve_located_slot(
                vault,
                panel_slot,
                has_live_compression_manifest,
                *cx_id,
                key,
                *seq,
                primary,
                raw,
            )? {
                LocatedSlotState::Resolved(state) => {
                    out.insert((*cx_id, *slot), state);
                }
                LocatedSlotState::Compressed(candidate) => {
                    compressed.entry(*slot).or_default().push(candidate);
                }
            }
        }
    }
    resolve_compressed_slots(
        vault,
        &panel_state,
        &panel_slots,
        constellations,
        compressed,
        deadline,
        progress,
        &mut out,
    )?;
    Ok(out)
}

fn validated_panel_slots<'a>(
    vault: &Path,
    state: &'a VaultPanelState,
    constellations: &[&Constellation],
) -> CliResult<BTreeMap<SlotId, &'a Slot>> {
    let mut slots = BTreeMap::new();
    for slot in &state.panel.slots {
        if slot.slot_key.id() != slot.slot_id {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "cx-list --include-slots registry context in {} has slot id {} paired with slot-key id {}",
                vault.display(),
                slot.slot_id.get(),
                slot.slot_key.id().get()
            ))
            .into());
        }
        if slots.insert(slot.slot_id, slot).is_some() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "cx-list --include-slots registry context in {} contains duplicate slot id {}",
                vault.display(),
                slot.slot_id.get()
            ))
            .into());
        }
    }
    let expected_vault_id = constellations.first().map(|cx| cx.vault_id);
    for cx in constellations {
        if Some(cx.vault_id) != expected_vault_id {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "cx-list --include-slots loaded mixed vault ids from {}",
                vault.display()
            ))
            .into());
        }
        if cx.panel_version > state.panel.version {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "cx-list --include-slots base row {} requires panel version {}, but persisted VaultPanelState is version {}",
                cx.cx_id, cx.panel_version, state.panel.version
            ))
            .into());
        }
        for slot in cx.slots.keys() {
            if !slots.contains_key(slot) {
                return Err(missing_panel_slot_error(
                    vault,
                    *slot,
                    &format!("base row {} lists the slot", cx.cx_id),
                ));
            }
        }
    }
    Ok(slots)
}

/// `payload_source` label for a slot-CF row by resolution stage. Commit-batch
/// and WAL-tail reads keep the historical `slot_cf` label; full-level reads
/// keep the `slot_cf_full_set` label introduced by issue #1060.
fn slot_cf_payload_source(row: &ResolvedRow) -> &'static str {
    match row.source {
        RowSource::CommitBatch | RowSource::WalTail => "slot_cf",
        RowSource::FullSet => "slot_cf_full_set",
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_located_slot(
    vault: &Path,
    panel_slot: &Slot,
    has_live_compression_manifest: bool,
    cx_id: CxId,
    key: &[u8],
    seq: u64,
    primary: Option<&ResolvedRow>,
    raw: Option<&ResolvedRow>,
) -> CliResult<LocatedSlotState> {
    let slot = panel_slot.slot_id;
    let Some(primary) = primary else {
        let detail = raw.map_or_else(
            || "no primary or raw-sidecar row exists".to_string(),
            |row| {
                format!(
                    "orphan raw-sidecar row exists at {} (tombstone={}); it was not decoded or substituted",
                    raw_cf_payload_source(row),
                    is_tombstone_value(&row.value)
                )
            },
        );
        return Err(missing_slot_row_error(vault, cx_id, slot, seq, &detail));
    };
    let bytes = &primary.value;
    let payload_source = slot_cf_payload_source(primary);
    if is_tombstone_value(bytes) {
        if has_live_compression_manifest {
            return Err(undecodable_slot_row_error(
                vault,
                cx_id,
                slot,
                seq,
                "active compression manifest names a generation whose requested primary is tombstoned",
            ));
        }
        if raw.is_some_and(|row| !is_tombstone_value(&row.value)) {
            return Err(undecodable_slot_row_error(
                vault,
                cx_id,
                slot,
                seq,
                "primary is tombstoned but a live raw sidecar remains; sidecar was not substituted",
            ));
        }
        return Ok(LocatedSlotState::Resolved(PhysicalSlotState::Tombstoned {
            payload_source: match payload_source {
                "slot_cf" => "slot_cf_tombstone",
                _ => "slot_cf_full_set_tombstone",
            },
        }));
    }
    let expects_compressed = has_live_compression_manifest
        || bytes.first() == Some(&COMPRESSED_SLOT_TAG)
        || !matches!(&panel_slot.quant, QuantPolicy::None);
    if expects_compressed {
        let raw = raw.ok_or_else(|| {
            undecodable_slot_row_error(
                vault,
                cx_id,
                slot,
                seq,
                "compressed primary has no raw sidecar; Registry decode was not attempted against an incomplete generation",
            )
        })?;
        if is_tombstone_value(&raw.value) {
            return Err(undecodable_slot_row_error(
                vault,
                cx_id,
                slot,
                seq,
                "compressed primary is live but its raw sidecar is tombstoned; sidecar was not decoded or substituted",
            ));
        }
        return Ok(LocatedSlotState::Compressed(CompressedCandidate {
            cx_id,
            slot,
            provenance_seq: seq,
            key: key.to_vec(),
            primary_bytes: bytes.clone(),
            raw_bytes: raw.value.clone(),
            primary_source: payload_source,
            raw_source: raw_cf_payload_source(raw),
        }));
    }
    if let Some(raw) = raw {
        return Err(undecodable_slot_row_error(
            vault,
            cx_id,
            slot,
            seq,
            &format!(
                "plain primary has an orphan raw-sidecar row at {} (tombstone={}); sidecar was not decoded or substituted",
                raw_cf_payload_source(raw),
                is_tombstone_value(&raw.value)
            ),
        ));
    }
    decode_slot_vector(bytes)
        .map(|vector| {
            LocatedSlotState::Resolved(PhysicalSlotState::Vector {
                vector,
                payload_source,
            })
        })
        .map_err(|decode_error| {
            undecodable_slot_row_error(
                vault,
                cx_id,
                slot,
                seq,
                &format!(
                    "primary decode failed ({decode_error}); raw sidecars are never substituted"
                ),
            )
        })
}

fn raw_cf_payload_source(row: &ResolvedRow) -> &'static str {
    match row.source {
        RowSource::CommitBatch | RowSource::WalTail => "slot_raw_cf",
        RowSource::FullSet => "slot_raw_cf_full_set",
    }
}

fn missing_panel_slot_error(vault: &Path, slot: SlotId, detail: &str) -> CliError {
    CalyxError::aster_corrupt_shard(format!(
        "cx-list --include-slots cannot interpret slot {} in {} from the persisted VaultPanelState: {detail}",
        slot.get(),
        vault.display()
    ))
    .into()
}

fn missing_slot_row_error(
    vault: &Path,
    cx_id: CxId,
    slot: SlotId,
    seq: u64,
    detail: &str,
) -> CliError {
    CalyxError::aster_corrupt_shard(format!(
        "cx-list --include-slots fail-closed: base row for cx {cx_id} in {} lists slot {} \
         (provenance seq {seq}) but no physical slot payload row exists: {detail}",
        vault.display(),
        slot.get()
    ))
    .into()
}

fn undecodable_slot_row_error(
    vault: &Path,
    cx_id: CxId,
    slot: SlotId,
    seq: u64,
    detail: &str,
) -> CliError {
    CalyxError::aster_corrupt_shard(format!(
        "cx-list --include-slots fail-closed: physical slot row for cx {cx_id} slot {} \
         (provenance seq {seq}) in {} is not decodable: {detail}",
        slot.get(),
        vault.display()
    ))
    .into()
}

pub(super) fn slot_summary<'a>(
    states: impl Iterator<Item = &'a PhysicalSlotState>,
) -> serde_json::Value {
    let mut dense_slots = 0usize;
    let mut sparse_slots = 0usize;
    let mut multi_slots = 0usize;
    let mut compressed_slots = 0usize;
    let mut tombstoned_slots = 0usize;
    let mut absent_reasons = BTreeMap::<String, usize>::new();
    for state in states {
        match state {
            PhysicalSlotState::Tombstoned { .. } => tombstoned_slots += 1,
            PhysicalSlotState::Compressed { .. } => compressed_slots += 1,
            PhysicalSlotState::Vector { vector, .. } => match vector {
                SlotVector::Dense { .. } => dense_slots += 1,
                SlotVector::Sparse { .. } => sparse_slots += 1,
                SlotVector::Multi { .. } => multi_slots += 1,
                SlotVector::Absent { reason } => {
                    let key = serde_json::to_value(reason)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_else(|| format!("{reason:?}"));
                    *absent_reasons.entry(key).or_insert(0) += 1;
                }
            },
        }
    }
    let absent_slots = absent_reasons.values().sum::<usize>();
    json!({
        "slot_count": dense_slots + sparse_slots + multi_slots + compressed_slots + tombstoned_slots + absent_slots,
        "dense_slots": dense_slots,
        "sparse_slots": sparse_slots,
        "multi_slots": multi_slots,
        "compressed_slots": compressed_slots,
        "tombstoned_slots": tombstoned_slots,
        "absent_slots": absent_slots,
        "absent_reasons": absent_reasons,
    })
}
