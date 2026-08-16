//! PH53 HTAP — serve one slot as BOTH a transactional row store (point reads via
//! `read_cf_at`) and an analytical column (Arrow materialization + OLAP scan), at a
//! single MVCC snapshot.
//!
//! `htap_dual_read_at` runs both independent access paths at one `seq` and proves
//! they return identical data — the HTAP contract from PRD `20 §1/§2`: OLTP and
//! OLAP served from one core with no ETL, and snapshot-consistent (a write at a
//! later seq cannot leak into an earlier snapshot on either path).

use std::path::Path;

use super::slot_column::read_materialized_slot_column;
use super::{AsterVault, SlotColumnMaterialization, SlotVectorResolver, StrictRawSlotResolver};
use crate::olap::{OlapScanPlan, OlapScanResult, scan_materialized_slot_column_aggregate};
use calyx_core::{CalyxError, Clock, Result, Seq, SlotId, SlotVector};

/// Result of an HTAP dual read: the analytical column path, the transactional
/// row path, and the identity verdicts between them at one snapshot.
#[derive(Debug, Clone)]
pub struct HtapDualRead {
    pub snapshot: Seq,
    pub slot: SlotId,
    pub value_column: usize,
    pub row_count: usize,
    pub dim: u32,
    /// Analytical path: the materialized Arrow column.
    pub column: SlotColumnMaterialization,
    /// Analytical path: the OLAP aggregate over `value_column`.
    pub olap: OlapScanResult,
    /// Transactional path: aggregate recomputed from independent point reads.
    pub row_path_count: usize,
    pub row_path_sum: f64,
    pub row_path_min: f32,
    pub row_path_max: f32,
    /// Every cx's row-CF point-read bytes equal the column-path row bytes.
    pub per_row_bit_identical: bool,
    /// The transactional and analytical aggregates are bit-identical.
    pub aggregates_identical: bool,
}

impl HtapDualRead {
    /// True iff the transactional (row) and analytical (column) access paths
    /// returned identical data at the same snapshot — the HTAP guarantee.
    pub fn paths_identical(&self) -> bool {
        self.per_row_bit_identical && self.aggregates_identical
    }
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// HTAP dual read of `slot` at `snapshot`: materialize the analytical Arrow
    /// column + OLAP-aggregate `value_column`, then INDEPENDENTLY point-read every
    /// cx through the transactional row CF and recompute the same aggregate. Both
    /// paths read the one MVCC snapshot, so they must agree bit-for-bit. The
    /// recomputation mirrors the OLAP accumulator (`sum += f64::from(v)`, f32
    /// min/max, same row order) so equality is bit-exact, not merely approximate.
    pub fn htap_dual_read_at(
        &self,
        snapshot: Seq,
        slot: SlotId,
        value_column: usize,
        output_dir: impl AsRef<Path>,
    ) -> Result<HtapDualRead> {
        self.htap_dual_read_resolved_at(
            snapshot,
            slot,
            value_column,
            output_dir,
            &StrictRawSlotResolver,
        )
    }

    /// HTAP dual read through an explicit slot interpretation owner. The full
    /// column and declared point roster are separate resolver operations at the
    /// same sequence; the batch method prevents per-row snapshot/manifest setup.
    pub fn htap_dual_read_resolved_at<R>(
        &self,
        snapshot: Seq,
        slot: SlotId,
        value_column: usize,
        output_dir: impl AsRef<Path>,
        resolver: &R,
    ) -> Result<HtapDualRead>
    where
        R: SlotVectorResolver<C> + ?Sized,
    {
        let snapshot_lease = self.retain_snapshot_at(snapshot);
        // --- Analytical (column) path ---
        let column =
            self.materialize_slot_column_resolved_at(snapshot, slot, &output_dir, resolver)?;
        snapshot_lease.record_progress();
        let plan = OlapScanPlan::new(value_column);
        let olap = scan_materialized_slot_column_aggregate(&column.manifest_path, plan)?;
        let readback = read_materialized_slot_column(&column.manifest_path)?;
        snapshot_lease.record_progress();

        // --- Transactional (row) path: independent point reads at the same seq ---
        let point_rows =
            resolver.resolve_slot_vectors_at(self, snapshot, slot, column.cx_ids.as_slice())?;
        if point_rows.len() != column.cx_ids.len() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "htap resolver returned {} point rows for {} requested CxIds",
                point_rows.len(),
                column.cx_ids.len()
            )));
        }
        let mut per_row_bit_identical = readback.rows.len() == column.cx_ids.len();
        let mut count = 0usize;
        let mut sum = 0.0f64;
        let mut min = 0.0f32;
        let mut max = 0.0f32;
        for (idx, ((expected_cx, (resolved_cx, vector)), column_row)) in column
            .cx_ids
            .iter()
            .zip(point_rows.into_iter())
            .zip(readback.rows.iter())
            .enumerate()
        {
            if *expected_cx != resolved_cx || column_row.cx_id != *expected_cx {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "htap resolver/order mismatch at ordinal {idx}: requested={expected_cx} resolved={resolved_cx} column={}",
                    column_row.cx_id
                )));
            }
            let vector = vector.ok_or_else(|| {
                CalyxError::stale_derived(format!(
                    "htap point read missing cx {expected_cx} at snapshot {snapshot}"
                ))
            })?;
            let SlotVector::Dense { data, .. } = vector else {
                return Err(CalyxError::stale_derived(
                    "htap dual read requires dense slot vectors",
                ));
            };
            if value_column >= data.len() {
                return Err(CalyxError::stale_derived(format!(
                    "htap value_column {value_column} outside dim {}",
                    data.len()
                )));
            }
            // Independent access paths must yield bit-identical row bytes.
            if column_row.values != data {
                per_row_bit_identical = false;
            }
            let value = data[value_column];
            if count == 0 {
                min = value;
                max = value;
            } else {
                min = min.min(value);
                max = max.max(value);
            }
            count += 1;
            sum += f64::from(value);
        }

        let aggregates_identical = count == olap.aggregate.count
            && sum.to_bits() == olap.aggregate.sum.to_bits()
            && min.to_bits() == olap.aggregate.min.to_bits()
            && max.to_bits() == olap.aggregate.max.to_bits();

        Ok(HtapDualRead {
            snapshot,
            slot,
            value_column,
            row_count: count,
            dim: column.dim,
            column,
            olap,
            row_path_count: count,
            row_path_sum: sum,
            row_path_min: min,
            row_path_max: max,
            per_row_bit_identical,
            aggregates_identical,
        })
    }
}
