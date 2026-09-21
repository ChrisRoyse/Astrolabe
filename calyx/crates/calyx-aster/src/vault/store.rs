use crate::cf::{ColumnFamily, anchor_key, base_key, ledger_key, slot_key};
use crate::mvcc::{CfRead, Snapshot};
use calyx_core::{Anchor, CalyxError, Clock, Constellation, CxId, Result, Seq, SlotId, VaultStore};
use std::collections::{BTreeMap, BTreeSet};

use super::{
    AsterVault, SlotVectorResolver, StrictRawSlotResolver, anchor_merge,
    decode_strict_raw_slot_value, encode, ledger_hook, ledger_stub,
};

fn cx_id_from_base_key(key: &[u8]) -> Result<CxId> {
    if key.len() != 16 {
        return Err(CalyxError::aster_corrupt_shard(
            "Base row key is not a CxId",
        ));
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(key);
    Ok(CxId::from_bytes(bytes))
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Reads a duplicate-free requested roster using ordinary Aster slot
    /// encodings. A compressed primary row is a context refusal.
    pub fn get_many_at(&self, snapshot: Seq, cx_ids: &[CxId]) -> Result<Vec<Constellation>> {
        self.get_many_resolved_at(snapshot, cx_ids, &StrictRawSlotResolver)
    }

    /// Reads a duplicate-free requested roster through one explicit slot
    /// interpretation owner while preserving input order.
    ///
    /// Base is read in one batch. Candidate IDs are grouped by declared slot,
    /// and each distinct slot is resolved once for its exact requested roster.
    pub fn get_many_resolved_at<R>(
        &self,
        snapshot: Seq,
        cx_ids: &[CxId],
        resolver: &R,
    ) -> Result<Vec<Constellation>>
    where
        R: SlotVectorResolver<C> + ?Sized,
    {
        let unique = cx_ids.iter().copied().collect::<BTreeSet<_>>();
        if unique.len() != cx_ids.len() {
            return Err(CalyxError::aster_corrupt_shard(
                "constellation batch request contains a duplicate CxId",
            ));
        }
        let snapshot_lease = self.retain_snapshot_at(snapshot);
        let base_reads = cx_ids
            .iter()
            .map(|cx_id| (ColumnFamily::Base, base_key(*cx_id)))
            .collect::<Vec<_>>();
        let base_values = self.read_cf_batch_at(snapshot, base_reads)?;
        snapshot_lease.record_progress();
        let mut constellations = Vec::with_capacity(cx_ids.len());
        let mut expected_by_slot = BTreeMap::<SlotId, Vec<(CxId, usize)>>::new();
        for (index, (cx_id, value)) in cx_ids.iter().copied().zip(base_values).enumerate() {
            let value = value.ok_or_else(|| {
                CalyxError::stale_derived(format!(
                    "constellation {cx_id} missing from Base at snapshot {snapshot}"
                ))
            })?;
            let constellation = encode::decode_constellation_base(&value)?;
            if constellation.cx_id != cx_id {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "Base key {cx_id} differs from embedded CxId {}",
                    constellation.cx_id
                )));
            }
            for slot in constellation.slots.keys() {
                expected_by_slot
                    .entry(*slot)
                    .or_default()
                    .push((cx_id, index));
            }
            constellations.push(constellation);
        }
        for (slot, expected) in expected_by_slot {
            snapshot_lease.record_progress();
            let expected_ids = expected.iter().map(|(cx_id, _)| *cx_id).collect::<Vec<_>>();
            let resolved = resolver.resolve_slot_vectors_at(self, snapshot, slot, &expected_ids)?;
            if resolved.len() != expected_ids.len() {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "slot {} resolved {} rows for {} requested constellations",
                    slot.get(),
                    resolved.len(),
                    expected_ids.len()
                )));
            }
            for ((expected_id, index), (resolved_id, vector)) in expected.into_iter().zip(resolved)
            {
                if expected_id != resolved_id {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "slot {} resolved CxId {resolved_id} where {expected_id} was requested",
                        slot.get()
                    )));
                }
                let vector = vector.ok_or_else(|| {
                    CalyxError::aster_corrupt_shard(format!(
                        "slot {} row missing for Base-declared constellation {resolved_id}",
                        slot.get()
                    ))
                })?;
                constellations[index].slots.insert(slot, vector);
            }
        }
        Ok(constellations)
    }

    /// Loads the complete visible constellation corpus using only ordinary
    /// Aster slot encodings. A compressed primary row is a context refusal.
    pub fn load_constellations_at(&self, snapshot: Seq) -> Result<Vec<Constellation>> {
        self.load_constellations_resolved_at(snapshot, &StrictRawSlotResolver)
    }

    /// Loads and hydrates the complete visible constellation corpus through an
    /// explicit slot interpretation owner.
    ///
    /// Base is scanned once. Each distinct slot declared by Base is then
    /// resolved exactly once as a complete column; no resolver operation occurs
    /// inside the constellation loop. The resolved column must have exactly the
    /// same ordered CxId roster as Base declares for that slot.
    pub fn load_constellations_resolved_at<R>(
        &self,
        snapshot: Seq,
        resolver: &R,
    ) -> Result<Vec<Constellation>>
    where
        R: SlotVectorResolver<C> + ?Sized,
    {
        let snapshot_lease = self.retain_snapshot_at(snapshot);
        let base_rows = self.scan_cf_at(snapshot, ColumnFamily::Base)?;
        snapshot_lease.record_progress();
        let mut constellations = BTreeMap::<CxId, Constellation>::new();
        let mut expected_by_slot = BTreeMap::<SlotId, BTreeSet<CxId>>::new();

        for (key, bytes) in base_rows {
            let cx_id = cx_id_from_base_key(&key)?;
            let constellation = encode::decode_constellation_base(&bytes)?;
            if constellation.cx_id != cx_id {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "Base row key {cx_id} differs from embedded CxId {}",
                    constellation.cx_id
                )));
            }
            for slot_id in constellation.slots.keys() {
                expected_by_slot.entry(*slot_id).or_default().insert(cx_id);
            }
            if constellations.insert(cx_id, constellation).is_some() {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "Base scan returned duplicate CxId {cx_id}"
                )));
            }
        }

        for (slot_id, expected_cx_ids) in expected_by_slot {
            snapshot_lease.record_progress();
            let resolved = resolver.resolve_slot_column_at(self, snapshot, slot_id)?;
            if resolved.len() != expected_cx_ids.len() {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "slot {} resolved {} rows but Base declares {}",
                    slot_id.get(),
                    resolved.len(),
                    expected_cx_ids.len()
                )));
            }
            for (expected_cx_id, (resolved_cx_id, vector)) in
                expected_cx_ids.into_iter().zip(resolved)
            {
                if expected_cx_id != resolved_cx_id {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "slot {} resolved CxId {resolved_cx_id} where Base declares {expected_cx_id}",
                        slot_id.get()
                    )));
                }
                let constellation = constellations.get_mut(&resolved_cx_id).ok_or_else(|| {
                    CalyxError::aster_corrupt_shard(format!(
                        "slot {} resolved orphan CxId {resolved_cx_id}",
                        slot_id.get()
                    ))
                })?;
                if !constellation.slots.contains_key(&slot_id) {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "slot {} resolved row {resolved_cx_id} absent from its Base declaration",
                        slot_id.get()
                    )));
                }
                constellation.slots.insert(slot_id, vector);
            }
        }

        Ok(constellations.into_values().collect())
    }

    /// Reads one stored constellation through an already-pinned snapshot lease.
    pub fn get_at_snapshot(&self, id: CxId, snapshot: Snapshot) -> Result<Constellation> {
        let constellation = self.read_base_at_snapshot(id, snapshot)?;
        let slot_ids: Vec<SlotId> = constellation.slots.keys().copied().collect();
        self.hydrate_slots_at_snapshot(id, snapshot, constellation, slot_ids)
    }

    /// Reads one stored constellation at `snapshot` through an explicit slot
    /// interpretation owner, pinning and releasing the MVCC lease internally.
    pub fn get_resolved_at<R>(&self, id: CxId, snapshot: Seq, resolver: &R) -> Result<Constellation>
    where
        R: SlotVectorResolver<C> + ?Sized,
    {
        let snapshot = self.snapshot_handle(snapshot);
        self.get_at_snapshot_resolved(id, snapshot.snapshot(), resolver)
    }

    /// Reads one stored constellation through an explicit slot interpretation
    /// owner. The Base row and every resolved slot remain bound to `snapshot`.
    pub fn get_at_snapshot_resolved<R>(
        &self,
        id: CxId,
        snapshot: Snapshot,
        resolver: &R,
    ) -> Result<Constellation>
    where
        R: SlotVectorResolver<C> + ?Sized,
    {
        let constellation = self.read_base_at_snapshot(id, snapshot)?;
        let slot_ids = constellation.slots.keys().copied().collect::<Vec<_>>();
        self.hydrate_slots_at_snapshot_resolved(id, snapshot, constellation, slot_ids, resolver)
    }

    /// Reads one stored constellation through an already-pinned snapshot lease,
    /// hydrating only the requested slots. The requested slots must be present
    /// in the Base CF row, otherwise the derived caller state is stale.
    pub fn get_selected_slots_at_snapshot<I>(
        &self,
        id: CxId,
        snapshot: Snapshot,
        selected_slots: I,
    ) -> Result<Constellation>
    where
        I: IntoIterator<Item = SlotId>,
    {
        let constellation = self.read_base_at_snapshot(id, snapshot)?;
        let available_slots = constellation.slots.keys().copied().collect::<BTreeSet<_>>();
        let slot_ids = selected_slots.into_iter().collect::<BTreeSet<_>>();
        for slot in &slot_ids {
            if !available_slots.contains(slot) {
                return Err(CalyxError::stale_derived(format!(
                    "selected slot {slot} is absent from Base row for {id}"
                )));
            }
        }
        self.hydrate_slots_at_snapshot(id, snapshot, constellation, slot_ids)
    }

    /// Reads caller-selected slots at `snapshot` through an explicit slot
    /// interpretation owner, pinning and releasing the MVCC lease internally.
    pub fn get_selected_slots_resolved_at<I, R>(
        &self,
        id: CxId,
        snapshot: Seq,
        selected_slots: I,
        resolver: &R,
    ) -> Result<Constellation>
    where
        I: IntoIterator<Item = SlotId>,
        R: SlotVectorResolver<C> + ?Sized,
    {
        let snapshot = self.snapshot_handle(snapshot);
        self.get_selected_slots_at_snapshot_resolved(
            id,
            snapshot.snapshot(),
            selected_slots,
            resolver,
        )
    }

    /// Hydrates only caller-selected slots through an explicit interpretation
    /// owner. A selected slot absent from the Base row is stale derived state.
    pub fn get_selected_slots_at_snapshot_resolved<I, R>(
        &self,
        id: CxId,
        snapshot: Snapshot,
        selected_slots: I,
        resolver: &R,
    ) -> Result<Constellation>
    where
        I: IntoIterator<Item = SlotId>,
        R: SlotVectorResolver<C> + ?Sized,
    {
        let constellation = self.read_base_at_snapshot(id, snapshot)?;
        let available_slots = constellation.slots.keys().copied().collect::<BTreeSet<_>>();
        let slot_ids = selected_slots.into_iter().collect::<BTreeSet<_>>();
        for slot in &slot_ids {
            if !available_slots.contains(slot) {
                return Err(CalyxError::stale_derived(format!(
                    "selected slot {slot} is absent from Base row for {id}"
                )));
            }
        }
        self.hydrate_slots_at_snapshot_resolved(id, snapshot, constellation, slot_ids, resolver)
    }

    fn hydrate_slots_at_snapshot<I>(
        &self,
        id: CxId,
        snapshot: Snapshot,
        mut constellation: Constellation,
        slot_ids: I,
    ) -> Result<Constellation>
    where
        I: IntoIterator<Item = SlotId>,
    {
        let slot_ids: Vec<SlotId> = slot_ids.into_iter().collect();
        if slot_ids.is_empty() {
            constellation.slots.clear();
            return Ok(constellation);
        }
        let reads: Vec<_> = slot_ids
            .iter()
            .map(|slot| CfRead::new(ColumnFamily::slot(*slot), slot_key(id)))
            .collect();
        let values = self.rows.read_batch(snapshot, &reads, &self.clock)?;
        let mut slots = BTreeMap::new();
        for (slot, value) in slot_ids.into_iter().zip(values) {
            let value =
                value.ok_or_else(|| CalyxError::aster_corrupt_shard("slot CF row missing"))?;
            let vector = decode_strict_raw_slot_value(slot, id, &value)?;
            slots.insert(slot, vector);
        }
        constellation.slots = slots;
        Ok(constellation)
    }

    fn hydrate_slots_at_snapshot_resolved<I, R>(
        &self,
        id: CxId,
        snapshot: Snapshot,
        mut constellation: Constellation,
        slot_ids: I,
        resolver: &R,
    ) -> Result<Constellation>
    where
        I: IntoIterator<Item = SlotId>,
        R: SlotVectorResolver<C> + ?Sized,
    {
        let slot_ids = slot_ids.into_iter().collect::<Vec<_>>();
        if slot_ids.is_empty() {
            constellation.slots.clear();
            return Ok(constellation);
        }
        let mut slots = BTreeMap::new();
        for slot in slot_ids {
            let vector = resolver
                .resolve_slot_vector_at(self, snapshot.seq(), id, slot)?
                .ok_or_else(|| CalyxError::aster_corrupt_shard("slot CF row missing"))?;
            slots.insert(slot, vector);
        }
        constellation.slots = slots;
        Ok(constellation)
    }

    /// Reads the Base CF row only, preserving metadata, anchors, and stored
    /// provenance without hydrating slot vectors.
    pub fn get_base_at(&self, id: CxId, snapshot: Seq) -> Result<Constellation> {
        let snapshot = self.snapshot_handle(snapshot);
        self.get_base_at_snapshot(id, snapshot.snapshot())
    }

    /// Reads the Base CF row only through an already-pinned snapshot lease,
    /// preserving metadata, anchors, and stored provenance without hydrating
    /// slot vectors.
    pub fn get_base_at_snapshot(&self, id: CxId, snapshot: Snapshot) -> Result<Constellation> {
        let mut constellation = self.read_base_at_snapshot(id, snapshot)?;
        constellation.slots.clear();
        Ok(constellation)
    }

    fn read_base_at_snapshot(&self, id: CxId, snapshot: Snapshot) -> Result<Constellation> {
        let base = self
            .rows
            .read_at(snapshot, ColumnFamily::Base, &base_key(id), &self.clock)?
            .ok_or_else(|| CalyxError::stale_derived("constellation missing at snapshot"))?;
        let constellation = encode::decode_constellation_base(&base)?;
        if constellation.cx_id != id {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "Base key {id} differs from embedded CxId {}",
                constellation.cx_id
            )));
        }
        Ok(constellation)
    }
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Persists `constellation` together with `input_rows` in the SAME atomic
    /// group commit as the base record (issue #446): the content-addressed
    /// input-store rows produced by
    /// [`crate::vault::input_store::encode_input_rows`] join the staged base,
    /// slot, anchor, and ledger rows in one batch, so a constellation is never
    /// durable without its retained input bytes and vice versa. Pass an empty
    /// vec for the plain [`VaultStore::put`] behavior.
    ///
    /// Idempotent: if the base row already exists (identical bytes, or an
    /// anchor-merge), the `input_rows` are not re-staged — the input store is
    /// content-addressed, so the first ingest already committed byte-identical
    /// rows under the same keys.
    pub fn put_with_input_rows(
        &self,
        constellation: Constellation,
        input_rows: Vec<encode::WriteRow>,
    ) -> Result<CxId> {
        if constellation.vault_id != self.vault_id {
            return Err(CalyxError::vault_access_denied(
                "constellation belongs to another vault",
            ));
        }
        constellation.validate_schema()?;

        self.with_durable_commit_lock(|| {
            let mut constellation = constellation;
            let id = constellation.cx_id;
            let base_key = base_key(id);
            let latest = self.snapshot();
            let snapshot = self.snapshot_handle(latest);
            if let Some(existing) = self.rows.read_at(
                snapshot.snapshot(),
                ColumnFamily::Base,
                &base_key,
                &self.clock,
            )? {
                let base_bytes = encode::encode_constellation_base(&constellation)?;
                if existing == base_bytes {
                    return Ok(id);
                }
                let mut merged = encode::BaseRecord::decode_for_key(id, &existing)?;
                if merged.vault_id() != self.vault_id {
                    return Err(CalyxError::vault_access_denied(format!(
                        "persisted Base row for cx {id} belongs to another vault"
                    )));
                }
                let added =
                    anchor_merge::merge_duplicate_anchors_base(&mut merged, &constellation)?;
                if !added.is_empty() {
                    let rows = anchor_merge::stage_anchor_merge_base_rows(id, &merged, &added)?;
                    self.commit_rows_locked(&rows)?;
                }
                return Ok(id);
            }

            let mut rows = Vec::new();
            let mut hook_guard = match &self.ledger_hook {
                Some(hook) => Some(ledger_hook::lock_hook(hook)?),
                None => None,
            };
            let staged_ledger = if let Some(hook) = hook_guard.as_deref() {
                let staged = ledger_hook::stage_ingest(hook, &mut rows, &constellation)?;
                constellation.provenance = staged
                    .first()
                    .ok_or_else(|| CalyxError::ledger_group_commit_failed("no staged ledger rows"))?
                    .ledger_ref();
                Some(staged)
            } else {
                rows.push(encode::WriteRow {
                    cf: ColumnFamily::Ledger,
                    key: ledger_key(constellation.provenance.seq),
                    value: ledger_stub::encode(constellation.provenance.seq),
                });
                None
            };
            let base_bytes = encode::encode_constellation_base(&constellation)?;
            rows.push(encode::WriteRow {
                cf: ColumnFamily::Base,
                key: base_key,
                value: base_bytes,
            });
            for (slot, vector) in &constellation.slots {
                rows.push(encode::WriteRow {
                    cf: ColumnFamily::slot(*slot),
                    key: slot_key(id),
                    value: encode::encode_slot_vector(vector)?,
                });
            }
            for anchor in &constellation.anchors {
                rows.push(encode::WriteRow {
                    cf: ColumnFamily::Anchors,
                    key: anchor_key(id, &anchor.kind),
                    value: encode::encode_anchor(anchor)?,
                });
            }
            // Input-store rows ride the same atomic batch as the base record.
            rows.extend(input_rows);
            let committed_seq = self.commit_rows_locked(&rows)?;
            if let (Some(hook), Some(staged)) = (hook_guard.as_deref_mut(), staged_ledger.as_ref())
            {
                ledger_hook::commit_staged(hook, staged).map_err(|error| {
                    self.reconcile_post_commit_ledger_hook_failure(committed_seq, &error)
                })?;
            }
            Ok(id)
        })
    }

    /// Commits input-store rows for `bytes` (addressed by `input_hash`) as a
    /// standalone atomic batch, independent of any constellation. Idempotent:
    /// if a matching manifest already exists, this is a no-op that returns the
    /// current latest seq (content-address dedup). Used by the CLI `input-write`
    /// surface and available to Astrolabe's shadow-import row sink.
    pub fn commit_input_bytes(&self, input_hash: &[u8; 32], bytes: &[u8]) -> Result<Seq> {
        if let Some(existing) = crate::vault::input_store::input_manifest(self, input_hash)?
            && &existing.content_hash == input_hash
        {
            return Ok(self.latest_seq());
        }
        let rows = crate::vault::input_store::encode_input_rows(input_hash, bytes)?;
        self.write_cf_batch(rows.into_iter().map(|row| (row.cf, row.key, row.value)))
    }
}

impl<C> VaultStore for AsterVault<C>
where
    C: Clock,
{
    fn put(&self, constellation: Constellation) -> Result<CxId> {
        self.put_with_input_rows(constellation, Vec::new())
    }

    fn get(&self, id: CxId, snapshot: Seq) -> Result<Constellation> {
        let snapshot = self.snapshot_handle(snapshot);
        self.get_at_snapshot(id, snapshot.snapshot())
    }

    fn anchor(&self, id: CxId, anchor: Anchor) -> Result<()> {
        anchor.validate_schema()?;
        self.with_recurrence_write_lock(|| {
            let evaluation_seq = self.snapshot();
            let snapshot = self.snapshot_handle(evaluation_seq);
            let base = self
                .rows
                .read_at(
                    snapshot.snapshot(),
                    ColumnFamily::Base,
                    &base_key(id),
                    &self.clock,
                )?
                .ok_or_else(|| CalyxError::stale_derived("constellation missing at snapshot"))?;
            let mut record = encode::BaseRecord::decode_for_key(id, &base)?;
            if record.vault_id() != self.vault_id {
                return Err(CalyxError::vault_access_denied(format!(
                    "Base row for cx {id} belongs to another vault"
                )));
            }
            record.anchors_mut().push(anchor.clone());
            let ungrounded = record.constellation().anchors.is_empty();
            record.flags_mut().ungrounded = ungrounded;
            record.constellation().validate_schema()?;
            let rows = [
                (ColumnFamily::Base, base_key(id), record.encode()?),
                (
                    ColumnFamily::Anchors,
                    anchor_key(id, &anchor.kind),
                    encode::encode_anchor(&anchor)?,
                ),
            ];
            let rows = rows
                .into_iter()
                .map(|(cf, key, value)| encode::WriteRow { cf, key, value })
                .collect::<Vec<_>>();
            self.commit_rows_if_seq(evaluation_seq, rows, "anchor append")?;
            Ok(())
        })
    }

    fn snapshot(&self) -> Seq {
        self.latest_seq()
    }
}
