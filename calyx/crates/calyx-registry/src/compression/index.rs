use calyx_aster::cf::{ColumnFamily, slot_key};
use calyx_aster::vault::AsterVault;
use calyx_core::{Clock, CxId, Result, Seq, Slot, SlotShape, SlotVector};
use serde::{Deserialize, Serialize};

use super::codec::{CodecContext, ParsedStoredSlot, parse_stored_slot};
use super::recall::prepare_dense;
use super::{
    CALYX_VECTOR_COMPRESSION_EMPTY, CALYX_VECTOR_COMPRESSION_INVALID, StoredSlotEnvelope,
    compression_error,
};
use crate::spec::LensSpec;

/// One hit scored directly from a persisted compressed slot row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompressedSlotHit {
    pub cx_id: CxId,
    pub score: f32,
}

/// Compression-aware view over one frozen lens/slot column.
///
/// The lens and slot are mandatory because codec seeds and dimensions are part
/// of the frozen interpretation contract. This type never consults the raw
/// sidecar when decoding or scoring a compressed row.
pub struct CompressedSlotIndex<'a, C: Clock> {
    vault: &'a AsterVault<C>,
    slot: &'a Slot,
    lens: &'a LensSpec,
    codec: CodecContext,
}

impl<'a, C: Clock> CompressedSlotIndex<'a, C> {
    pub fn open(
        vault: &'a AsterVault<C>,
        slot: &'a Slot,
        lens: &'a LensSpec,
    ) -> Result<Self> {
        let codec = CodecContext::for_read(slot, lens)?;
        Ok(Self {
            vault,
            slot,
            lens,
            codec,
        })
    }

    /// Reads and reconstructs one persisted compressed row at `snapshot`.
    pub fn read_at(&self, cx_id: CxId, snapshot: Seq) -> Result<SlotVector> {
        let bytes = self
            .vault
            .read_cf_at(
                snapshot,
                ColumnFamily::slot(self.slot.slot_id),
                &slot_key(cx_id),
            )?
            .ok_or_else(|| {
                compression_error(
                    CALYX_VECTOR_COMPRESSION_EMPTY,
                    format!(
                        "compressed slot row is missing: slot={} cx_id={cx_id} snapshot={snapshot}",
                        self.slot.slot_key.key()
                    ),
                )
            })?;
        let parsed = self.parse_contextual(&bytes)?;
        let data = self.codec.decode_parsed(&parsed)?;
        let vector = SlotVector::Dense {
            dim: parsed.envelope.stored_dim,
            data,
        };
        vector.validate_schema()?;
        Ok(vector)
    }

    /// Returns validated envelope metadata from the actual persisted CF row.
    pub fn envelope_at(&self, cx_id: CxId, snapshot: Seq) -> Result<StoredSlotEnvelope> {
        let bytes = self
            .vault
            .read_cf_at(
                snapshot,
                ColumnFamily::slot(self.slot.slot_id),
                &slot_key(cx_id),
            )?
            .ok_or_else(|| {
                compression_error(
                    CALYX_VECTOR_COMPRESSION_EMPTY,
                    format!(
                        "compressed slot envelope is missing: slot={} cx_id={cx_id} snapshot={snapshot}",
                        self.slot.slot_key.key()
                    ),
                )
            })?;
        Ok(self.parse_contextual(&bytes)?.envelope)
    }

    /// Scores every visible compressed row with one prepared query and retains
    /// only the requested top-k candidates.
    pub fn search_at(
        &self,
        query: &[f32],
        k: usize,
        snapshot: Seq,
    ) -> Result<Vec<CompressedSlotHit>> {
        if k == 0 {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed slot search requires k > 0",
            ));
        }
        let SlotShape::Dense(raw_dim) = self.slot.shape else {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed slot search requires a dense slot",
            ));
        };
        if query.len() != raw_dim as usize {
            return Err(calyx_core::CalyxError::lens_dim_mismatch(format!(
                "compressed query dimension {} does not match slot dimension {raw_dim}",
                query.len()
            )));
        }
        if let Some(index) = query.iter().position(|value| !value.is_finite()) {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!("compressed query contains non-finite coefficient at index {index}"),
            ));
        }
        let prepared_values = prepare_dense(query, self.lens.truncate_dim)?;
        let prepared_query = self.codec.prepare_query(&prepared_values)?;
        let rows = self
            .vault
            .scan_cf_at(snapshot, ColumnFamily::slot(self.slot.slot_id))?;
        if rows.is_empty() {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_EMPTY,
                format!(
                    "compressed slot column is empty: slot={} snapshot={snapshot}",
                    self.slot.slot_key.key()
                ),
            ));
        }
        let mut best = Vec::with_capacity(k.min(rows.len()));
        for (key, bytes) in rows {
            let cx_id = decode_cx_id_key(&key)?;
            let parsed = self.parse_contextual(&bytes)?;
            let score = self.codec.score_parsed(&prepared_query, &parsed)?;
            if !score.is_finite() {
                return Err(compression_error(
                    CALYX_VECTOR_COMPRESSION_INVALID,
                    format!("compressed score is non-finite for cx_id={cx_id}"),
                ));
            }
            retain_top_k(&mut best, CompressedSlotHit { cx_id, score }, k);
        }
        best.sort_by(compare_hits);
        Ok(best)
    }

    fn parse_contextual(&self, bytes: &[u8]) -> Result<ParsedStoredSlot> {
        let parsed = parse_stored_slot(bytes)?;
        let SlotShape::Dense(raw_dim) = self.slot.shape else {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                "compressed row belongs to a non-dense slot",
            ));
        };
        if parsed.envelope.raw_dim != raw_dim
            || parsed.envelope.stored_dim as usize != self.codec.dim()
        {
            return Err(compression_error(
                CALYX_VECTOR_COMPRESSION_INVALID,
                format!(
                    "persisted envelope dimensions do not match frozen slot/lens: expected raw={} stored={} got raw={} stored={}",
                    raw_dim,
                    self.codec.dim(),
                    parsed.envelope.raw_dim,
                    parsed.envelope.stored_dim
                ),
            ));
        }
        self.codec.validate_parsed(&parsed)?;
        Ok(parsed)
    }
}

fn decode_cx_id_key(key: &[u8]) -> Result<CxId> {
    if key.len() != 16 {
        return Err(compression_error(
            CALYX_VECTOR_COMPRESSION_INVALID,
            format!(
                "compressed slot key length must be 16-byte CxId, got {}",
                key.len()
            ),
        ));
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(key);
    Ok(CxId::from_bytes(bytes))
}

fn retain_top_k(best: &mut Vec<CompressedSlotHit>, hit: CompressedSlotHit, k: usize) {
    if best.len() < k {
        best.push(hit);
        return;
    }
    let Some((worst_index, worst)) = best
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| compare_hits(left, right))
    else {
        return;
    };
    if compare_hits(&hit, worst).is_lt() {
        best[worst_index] = hit;
    }
}

fn compare_hits(left: &CompressedSlotHit, right: &CompressedSlotHit) -> std::cmp::Ordering {
    right
        .score
        .total_cmp(&left.score)
        .then_with(|| left.cx_id.as_bytes().cmp(right.cx_id.as_bytes()))
}
