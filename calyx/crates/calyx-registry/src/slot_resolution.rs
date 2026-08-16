use calyx_aster::cf::{ColumnFamily, compression_manifest_key};
use calyx_aster::vault::{AsterVault, SlotVectorResolver, StrictRawSlotResolver};
use calyx_core::{CalyxError, Clock, CxId, Panel, Result, Seq, Slot, SlotId, SlotVector};
use std::collections::BTreeSet;

use crate::{VaultPanelState, ensure_vector_shape};

/// Narrow read-only CF set required by complete resolved-corpus hydration for
/// a known panel. Base declares membership, Compression selects and attests the
/// immutable representation, and each registered slot contributes its primary.
/// Assay and recovery-only raw sidecars are whole-generation audit inputs, not
/// serving inputs.
pub fn resolved_constellation_read_cfs(panel: &Panel) -> Vec<ColumnFamily> {
    let slot_ids = panel
        .slots
        .iter()
        .map(|slot| slot.slot_id)
        .collect::<BTreeSet<_>>();
    let mut selected = Vec::with_capacity(2_usize.saturating_add(slot_ids.len()));
    selected.extend([ColumnFamily::Base, ColumnFamily::Compression]);
    for slot_id in slot_ids {
        selected.push(ColumnFamily::slot(slot_id));
    }
    selected
}

impl VaultPanelState {
    fn exact_slot(&self, slot_id: SlotId) -> Result<&Slot> {
        let mut matching = self
            .panel
            .slots
            .iter()
            .filter(|slot| slot.slot_id == slot_id);
        let slot = matching.next().ok_or_else(|| {
            CalyxError::lens_unreachable(format!(
                "persisted panel version {} has no slot {}",
                self.panel.version,
                slot_id.get()
            ))
        })?;
        if matching.next().is_some() {
            return Err(CalyxError::lens_frozen_violation(format!(
                "persisted panel version {} contains duplicate slot id {}",
                self.panel.version,
                slot_id.get()
            )));
        }
        let contract = self.registry.frozen_contract(slot.lens_id).ok_or_else(|| {
            CalyxError::lens_unreachable(format!(
                "persisted slot {} references lens {} absent from the loaded registry snapshot",
                slot.slot_key.key(),
                slot.lens_id
            ))
        })?;
        if contract.lens_id() != slot.lens_id {
            return Err(CalyxError::lens_frozen_violation(format!(
                "persisted slot {} lens id {} differs from frozen contract id {}",
                slot.slot_key.key(),
                slot.lens_id,
                contract.lens_id()
            )));
        }
        if let Some(spec) = self.registry.lens_spec(slot.lens_id) {
            if spec.lens_id() != slot.lens_id
                || spec.output != slot.shape
                || spec.quant_default != slot.quant
            {
                return Err(CalyxError::lens_frozen_violation(format!(
                    "persisted slot {} does not match its exact LensSpec identity/shape/quant policy",
                    slot.slot_key.key()
                )));
            }
        }
        Ok(slot)
    }

    fn compressed_manifest<C>(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot_id: SlotId,
    ) -> Result<Option<Vec<u8>>>
    where
        C: Clock,
    {
        vault.read_cf_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_manifest_key(slot_id),
        )
    }

    fn require_compressed_registry_snapshot(&self, slot: &Slot) -> Result<()> {
        if self.registry_snapshot.is_some() {
            return Ok(());
        }
        Err(CalyxError::lens_frozen_violation(format!(
            "compressed slot {} requires the manifest-backed registry snapshot that owns its LensSpec",
            slot.slot_key.key()
        )))
    }

    fn validate_raw_vector(&self, slot: &Slot, vector: &SlotVector) -> Result<()> {
        if matches!(vector, SlotVector::Absent { .. }) {
            return Ok(());
        }
        ensure_vector_shape(slot.lens_id, slot.shape, vector)?;
        self.registry
            .frozen_contract(slot.lens_id)
            .ok_or_else(|| {
                CalyxError::lens_unreachable(format!(
                    "slot {} lens {} is absent from the registry",
                    slot.slot_key.key(),
                    slot.lens_id
                ))
            })?
            .verify_vector(slot.lens_id, vector)
    }
}

/// Resolves Aster slot rows from the exact manifest-backed panel/registry
/// interpretation. A present compression manifest selects the packed path;
/// manifest absence selects strict primary-row decoding. No decode error can
/// switch paths, and the raw sidecar is never read or substituted.
impl<C> SlotVectorResolver<C> for VaultPanelState
where
    C: Clock,
{
    fn resolve_slot_vector_at(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        cx_id: CxId,
        slot_id: SlotId,
    ) -> Result<Option<SlotVector>> {
        let slot = self.exact_slot(slot_id)?;
        let snapshot_lease = vault.retain_snapshot_at(snapshot);
        let manifest = self.compressed_manifest(vault, snapshot, slot_id)?;
        snapshot_lease.record_progress();
        if let Some(manifest) = manifest {
            self.require_compressed_registry_snapshot(slot)?;
            let mut rows = self
                .registry
                .compressed_slot_index(vault, slot)?
                .read_many_optional_with_manifest_at(&[cx_id], snapshot, &manifest)?;
            let (resolved_cx_id, vector) = rows.pop().ok_or_else(|| {
                CalyxError::aster_corrupt_shard(
                    "compressed point resolver returned no result ordinal",
                )
            })?;
            if !rows.is_empty() || resolved_cx_id != cx_id {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "compressed point resolver changed identity {cx_id} to {resolved_cx_id} or returned extra ordinals"
                )));
            }
            return Ok(vector);
        }
        let vector =
            StrictRawSlotResolver.resolve_slot_vector_at(vault, snapshot, cx_id, slot_id)?;
        if let Some(vector) = &vector {
            self.validate_raw_vector(slot, vector)?;
        }
        Ok(vector)
    }

    fn resolve_slot_vectors_at(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot_id: SlotId,
        cx_ids: &[CxId],
    ) -> Result<Vec<(CxId, Option<SlotVector>)>> {
        if cx_ids.is_empty() {
            return Ok(Vec::new());
        }
        let slot = self.exact_slot(slot_id)?;
        let snapshot_lease = vault.retain_snapshot_at(snapshot);
        let manifest = self.compressed_manifest(vault, snapshot, slot_id)?;
        snapshot_lease.record_progress();
        if let Some(manifest) = manifest {
            self.require_compressed_registry_snapshot(slot)?;
            return self
                .registry
                .compressed_slot_index(vault, slot)?
                .read_many_optional_with_manifest_at(cx_ids, snapshot, &manifest);
        }
        let rows =
            StrictRawSlotResolver.resolve_slot_vectors_at(vault, snapshot, slot_id, cx_ids)?;
        for (_, vector) in &rows {
            if let Some(vector) = vector {
                self.validate_raw_vector(slot, vector)?;
            }
        }
        Ok(rows)
    }

    fn resolve_slot_column_at(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot_id: SlotId,
    ) -> Result<Vec<(CxId, SlotVector)>> {
        let slot = self.exact_slot(slot_id)?;
        let snapshot_lease = vault.retain_snapshot_at(snapshot);
        let manifest = self.compressed_manifest(vault, snapshot, slot_id)?;
        snapshot_lease.record_progress();
        if let Some(manifest) = manifest {
            self.require_compressed_registry_snapshot(slot)?;
            return self
                .registry
                .compressed_slot_index(vault, slot)?
                .read_all_with_manifest_at(snapshot, &manifest);
        }
        let rows = StrictRawSlotResolver.resolve_slot_column_at(vault, snapshot, slot_id)?;
        for (_, vector) in &rows {
            self.validate_raw_vector(slot, vector)?;
        }
        Ok(rows)
    }
}
