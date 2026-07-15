use super::{AsterVault, encode};
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
        self.read_cf_at(snapshot, ColumnFamily::slot(slot_id), &slot_key(cx_id))?
            .map(|bytes| encode::decode_slot_vector(&bytes))
            .transpose()
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
