use super::{AsterVault, SlotVectorResolver, StrictRawSlotResolver, encode};
use crate::cf::{ColumnFamily, base_key, slot_key};
use calyx_core::{CalyxError, Clock, CxId, Result, Seq, SlotId, SlotVector};

impl<C> AsterVault<C>
where
    C: Clock,
{
    pub fn put_slot_vector(
        &self,
        cx_id: CxId,
        slot_id: SlotId,
        vector: &SlotVector,
    ) -> Result<Seq> {
        self.ensure_base_exists(cx_id)?;
        let row = encode::WriteRow {
            cf: ColumnFamily::slot(slot_id),
            key: slot_key(cx_id),
            value: encode::encode_slot_vector(vector)?,
        };
        self.commit_rows(&[row])
    }

    pub fn read_slot_vector_at(
        &self,
        snapshot: Seq,
        cx_id: CxId,
        slot_id: SlotId,
    ) -> Result<Option<SlotVector>> {
        StrictRawSlotResolver.resolve_slot_vector_at(self, snapshot, cx_id, slot_id)
    }

    /// Reads one slot value through an explicit interpretation owner.
    pub fn read_slot_vector_resolved_at<R>(
        &self,
        snapshot: Seq,
        cx_id: CxId,
        slot_id: SlotId,
        resolver: &R,
    ) -> Result<Option<SlotVector>>
    where
        R: SlotVectorResolver<C> + ?Sized,
    {
        resolver.resolve_slot_vector_at(self, snapshot, cx_id, slot_id)
    }

    /// Reads a duplicate-free roster through one resolver-owned batch path.
    pub fn read_slot_vectors_resolved_at<R>(
        &self,
        snapshot: Seq,
        slot_id: SlotId,
        cx_ids: &[CxId],
        resolver: &R,
    ) -> Result<Vec<(CxId, Option<SlotVector>)>>
    where
        R: SlotVectorResolver<C> + ?Sized,
    {
        resolver.resolve_slot_vectors_at(self, snapshot, slot_id, cx_ids)
    }

    fn ensure_base_exists(&self, cx_id: CxId) -> Result<()> {
        if self
            .read_cf_at(self.latest_seq(), ColumnFamily::Base, &base_key(cx_id))?
            .is_some()
        {
            return Ok(());
        }
        Err(CalyxError::stale_derived(format!(
            "constellation {cx_id} missing for slot backfill"
        )))
    }
}
