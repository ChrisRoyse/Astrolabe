use super::{AsterVault, encode};
use crate::cf::{COMPRESSED_SLOT_VALUE_TAG, ColumnFamily, slot_key};
use calyx_core::{CalyxError, Clock, CxId, Result, Seq, SlotId, SlotVector};
use std::collections::BTreeSet;

/// A raw slot reader encountered a registry-owned compressed envelope.
pub const CALYX_ASTER_SLOT_CONTEXT_REQUIRED: &str = "CALYX_ASTER_SLOT_CONTEXT_REQUIRED";

/// Aster-owned interpretation boundary for slot values.
///
/// Aster deliberately cannot know a compressed row's frozen lens contract.
/// Callers that may encounter registry-owned compressed generations therefore
/// supply an implementation from the layer that owns that context. All three
/// operations are required explicitly: there is no whole-column default hiding
/// behind a point-read loop, and no point-read default hiding behind a scan.
pub trait SlotVectorResolver<C>
where
    C: Clock,
{
    /// Resolves one exact `(slot, CxId)` at one MVCC sequence.
    fn resolve_slot_vector_at(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        cx_id: CxId,
        slot_id: SlotId,
    ) -> Result<Option<SlotVector>>;

    /// Resolves a caller-declared, duplicate-free CxId roster in input order.
    fn resolve_slot_vectors_at(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot_id: SlotId,
        cx_ids: &[CxId],
    ) -> Result<Vec<(CxId, Option<SlotVector>)>>;

    /// Resolves the complete visible slot column in ascending CxId order.
    fn resolve_slot_column_at(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot_id: SlotId,
    ) -> Result<Vec<(CxId, SlotVector)>>;
}

/// Strict interpretation of ordinary Aster `SlotVector` rows.
///
/// This reader never consults `slot_*.raw`. A registry-owned compressed tag is
/// a typed context refusal, not a decode failure and never a sidecar trigger.
#[derive(Clone, Copy, Debug, Default)]
pub struct StrictRawSlotResolver;

impl<C> SlotVectorResolver<C> for StrictRawSlotResolver
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
        vault
            .read_cf_at(snapshot, ColumnFamily::slot(slot_id), &slot_key(cx_id))?
            .map(|bytes| decode_strict_raw_slot_value(slot_id, cx_id, &bytes))
            .transpose()
    }

    fn resolve_slot_vectors_at(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot_id: SlotId,
        cx_ids: &[CxId],
    ) -> Result<Vec<(CxId, Option<SlotVector>)>> {
        require_unique_cx_ids(cx_ids)?;
        let reads = cx_ids
            .iter()
            .map(|cx_id| (ColumnFamily::slot(slot_id), slot_key(*cx_id)))
            .collect::<Vec<_>>();
        let values = vault.read_cf_batch_at(snapshot, reads)?;
        cx_ids
            .iter()
            .copied()
            .zip(values)
            .map(|(cx_id, value)| {
                let vector = value
                    .map(|bytes| decode_strict_raw_slot_value(slot_id, cx_id, &bytes))
                    .transpose()?;
                Ok((cx_id, vector))
            })
            .collect()
    }

    fn resolve_slot_column_at(
        &self,
        vault: &AsterVault<C>,
        snapshot: Seq,
        slot_id: SlotId,
    ) -> Result<Vec<(CxId, SlotVector)>> {
        vault
            .scan_cf_at(snapshot, ColumnFamily::slot(slot_id))?
            .into_iter()
            .map(|(key, bytes)| {
                let cx_id = cx_id_from_slot_key(&key)?;
                let vector = decode_strict_raw_slot_value(slot_id, cx_id, &bytes)?;
                Ok((cx_id, vector))
            })
            .collect()
    }
}

/// Decodes only the ordinary Aster slot encoding.
///
/// The discriminator is checked before the generic decoder so a compressed
/// envelope can never be reclassified as a corrupt raw row or cause a sidecar
/// substitution in a caller.
pub fn decode_strict_raw_slot_value(
    slot_id: SlotId,
    cx_id: CxId,
    bytes: &[u8],
) -> Result<SlotVector> {
    if bytes.first().copied() == Some(COMPRESSED_SLOT_VALUE_TAG) {
        return Err(CalyxError {
            code: CALYX_ASTER_SLOT_CONTEXT_REQUIRED,
            message: format!(
                "slot {} row {cx_id} is a registry-owned compressed envelope; raw Aster decoding was refused",
                slot_id.get()
            ),
            remediation: "load the exact manifest-backed VaultPanelState and use a SlotVectorResolver that verifies the registered Slot/Lens context and compressed generation membership proof",
        });
    }
    encode::decode_slot_vector(bytes)
}

fn require_unique_cx_ids(cx_ids: &[CxId]) -> Result<()> {
    let unique = cx_ids.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() == cx_ids.len() {
        return Ok(());
    }
    Err(CalyxError::aster_corrupt_shard(
        "slot batch read contains a duplicate CxId",
    ))
}

fn cx_id_from_slot_key(key: &[u8]) -> Result<CxId> {
    if key.len() != 16 {
        return Err(CalyxError::aster_corrupt_shard(
            "slot column row key is not a CxId",
        ));
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(key);
    Ok(CxId::from_bytes(bytes))
}
