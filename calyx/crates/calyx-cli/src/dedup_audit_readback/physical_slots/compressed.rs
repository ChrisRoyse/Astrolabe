use std::collections::BTreeMap;
use std::path::Path;

use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{CalyxError, Constellation, CxId, QuantPolicy, Slot, SlotId, SlotVector};
use calyx_registry::VaultPanelState;
use serde_json::json;

use super::{PhysicalSlotState, missing_panel_slot_error};
use crate::bounded_progress::{Deadline, ProgressSink};
use crate::error::{CliError, CliResult};

#[derive(Debug)]
pub(super) struct CompressedCandidate {
    pub(super) cx_id: CxId,
    pub(super) slot: SlotId,
    pub(super) provenance_seq: u64,
    pub(super) key: Vec<u8>,
    pub(super) primary_bytes: Vec<u8>,
    pub(super) raw_bytes: Vec<u8>,
    pub(super) primary_source: &'static str,
    pub(super) raw_source: &'static str,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_compressed_slots(
    vault: &Path,
    panel_state: &VaultPanelState,
    panel_slots: &BTreeMap<SlotId, &Slot>,
    constellations: &[&Constellation],
    compressed: BTreeMap<SlotId, Vec<CompressedCandidate>>,
    deadline: &Deadline,
    progress: &mut ProgressSink,
    out: &mut BTreeMap<(CxId, SlotId), PhysicalSlotState>,
) -> CliResult {
    if compressed.is_empty() {
        return Ok(());
    }
    if panel_state.registry_snapshot.is_none() {
        return Err(CalyxError {
            code: "CALYX_REGISTRY_CONTEXT_MISSING",
            message: format!(
                "cx-list --include-slots found compressed primaries in {}, but its manifest has no persisted registry snapshot",
                vault.display()
            ),
            remediation: "persist the exact panel/registry lens contracts used to encode the generation, then re-commission the compressed slot; never decode from slot_raw",
        }
        .into());
    }
    let vault_id = constellations
        .first()
        .map(|cx| cx.vault_id)
        .ok_or_else(|| {
            CliError::runtime("compressed slot candidates have no owning constellation")
        })?;
    let mut selected_cfs = vec![ColumnFamily::Compression];
    for slot in compressed.keys() {
        selected_cfs.push(ColumnFamily::slot(*slot));
        selected_cfs.push(ColumnFamily::slot_raw(*slot));
        if panel_slots
            .get(slot)
            .is_some_and(|slot| matches!(slot.quant, QuantPolicy::MxFp4))
        {
            selected_cfs.push(ColumnFamily::Assay);
        }
    }
    selected_cfs.sort();
    selected_cfs.dedup();
    let read_vault = AsterVault::open(
        vault,
        vault_id,
        b"calyx-cx-list-registry-readback-v1".to_vec(),
        VaultOptions {
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(selected_cfs),
            ..VaultOptions::default()
        },
    )?;
    let snapshot = read_vault.latest_seq();
    progress.emit(json!({
        "event": "cx_list.progress",
        "phase": "compressed_registry_snapshot",
        "snapshot": snapshot,
        "slots": compressed.len(),
        "elapsed_ms": deadline.elapsed_ms(),
    }))?;
    for (slot, candidates) in compressed {
        super::check_deadline(
            deadline,
            progress,
            "compressed_registry_read",
            out.len() as u64,
        )?;
        let panel_slot = panel_slots.get(&slot).copied().ok_or_else(|| {
            missing_panel_slot_error(vault, slot, "slot disappeared from validated panel map")
        })?;
        let index = panel_state
            .registry
            .compressed_slot_index(&read_vault, panel_slot)?;
        let cx_ids = candidates
            .iter()
            .map(|candidate| candidate.cx_id)
            .collect::<Vec<_>>();
        let decoded = index.read_many_at(&cx_ids, snapshot)?;
        let mut decoded = decoded.into_iter().collect::<BTreeMap<_, _>>();
        if decoded.len() != candidates.len() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "registry compressed batch for slot {} returned {} distinct rows for {} requested rows",
                slot.get(),
                decoded.len(),
                candidates.len()
            ))
            .into());
        }
        for candidate in candidates {
            require_independent_bytes(vault, &read_vault, snapshot, &candidate)?;
            let vector = decoded.remove(&candidate.cx_id).ok_or_else(|| {
                CalyxError::aster_corrupt_shard(format!(
                    "registry compressed batch omitted cx {} from slot {}",
                    candidate.cx_id,
                    slot.get()
                ))
            })?;
            let SlotVector::Dense { dim, data } = vector else {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "Registry compressed index returned a non-dense vector for dense slot {} cx {}",
                    slot.get(),
                    candidate.cx_id
                ))
                .into());
            };
            out.insert(
                (candidate.cx_id, slot),
                PhysicalSlotState::Compressed {
                    dim,
                    values: data.len(),
                    payload_source: candidate.primary_source,
                },
            );
        }
        progress.emit(json!({
            "event": "cx_list.progress",
            "phase": "compressed_registry_resolved",
            "slot": slot.get(),
            "snapshot": snapshot,
            "rows": cx_ids.len(),
            "elapsed_ms": deadline.elapsed_ms(),
        }))?;
    }
    Ok(())
}

fn require_independent_bytes(
    vault: &Path,
    read_vault: &AsterVault,
    snapshot: u64,
    candidate: &CompressedCandidate,
) -> CliResult {
    let current_primary = read_vault
        .read_cf_at(snapshot, ColumnFamily::slot(candidate.slot), &candidate.key)?
        .ok_or_else(|| {
            provenance_divergence_error(
                vault,
                candidate,
                snapshot,
                "Registry-authenticated primary disappeared on independent readback",
            )
        })?;
    if current_primary != candidate.primary_bytes {
        return Err(provenance_divergence_error(
            vault,
            candidate,
            snapshot,
            "Registry-authenticated latest primary bytes differ from the provenance-resolved physical primary",
        ));
    }
    let current_raw = read_vault
        .read_cf_at(
            snapshot,
            ColumnFamily::slot_raw(candidate.slot),
            &candidate.key,
        )?
        .ok_or_else(|| {
            provenance_divergence_error(
                vault,
                candidate,
                snapshot,
                "compressed raw sidecar is absent on independent current-state readback",
            )
        })?;
    if current_raw != candidate.raw_bytes {
        return Err(provenance_divergence_error(
            vault,
            candidate,
            snapshot,
            "current raw-sidecar bytes differ from the provenance-resolved sidecar; sidecar was not decoded or substituted",
        ));
    }
    Ok(())
}

fn provenance_divergence_error(
    vault: &Path,
    candidate: &CompressedCandidate,
    snapshot: u64,
    detail: &str,
) -> CliError {
    CalyxError::aster_corrupt_shard(format!(
        "cx-list --include-slots fail-closed: compressed cx {} slot {} in {} diverged between \
         the CLI current-state physical resolver (Base ledger seq {}, primary source {}, raw \
         source {}) and the Registry/Aster current-state snapshot {snapshot}: {detail}",
        candidate.cx_id,
        candidate.slot.get(),
        vault.display(),
        candidate.provenance_seq,
        candidate.primary_source,
        candidate.raw_source,
    ))
    .into()
}
