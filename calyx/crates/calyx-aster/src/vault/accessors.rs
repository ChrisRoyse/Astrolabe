//! Snapshot-scoped raw CF read and scan accessors on [`AsterVault`]. These pin a
//! vault-internal snapshot handle (or accept an already-pinned lease) and defer
//! to the MVCC store's visibility-filtered readers.

use super::{AsterVault, OrderedCfRead, encode};
use crate::cf::{ColumnFamily, KeyRange};
use crate::mvcc::{OrderedReadbackMetrics, Snapshot};
use calyx_core::{Clock, Result, Seq};

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Writes raw CF rows through the same WAL/MVCC commit path as vault puts.
    pub fn write_cf_batch(
        &self,
        rows: impl IntoIterator<Item = (ColumnFamily, Vec<u8>, Vec<u8>)>,
    ) -> Result<Seq> {
        let rows = rows
            .into_iter()
            .map(|(cf, key, value)| encode::WriteRow { cf, key, value })
            .collect::<Vec<_>>();
        if rows.is_empty() {
            return Ok(self.latest_seq());
        }
        self.commit_rows(&rows)
    }

    /// Writes a raw CF batch only if the vault is still at `expected_seq`.
    ///
    /// The sequence comparison and commit share the durable commit lock or the
    /// volatile store's MVCC row lock, allowing fail-closed replace workflows.
    pub fn write_cf_batch_if_seq(
        &self,
        expected_seq: Seq,
        rows: impl IntoIterator<Item = (ColumnFamily, Vec<u8>, Vec<u8>)>,
    ) -> Result<Seq> {
        let rows = rows
            .into_iter()
            .map(|(cf, key, value)| encode::WriteRow { cf, key, value })
            .collect::<Vec<_>>();
        if self.durable.is_none() {
            return self.commit_rows_if_current_volatile(expected_seq, rows);
        }
        self.with_durable_commit_lock(|| {
            let current_seq = self.latest_seq();
            if current_seq != expected_seq {
                return Err(calyx_core::CalyxError {
                    code: "CALYX_ASTER_SEQUENCE_CONFLICT",
                    message: format!(
                        "conditional CF batch expected seq {expected_seq}, current seq is {current_seq}; no rows were written"
                    ),
                    remediation: "re-read the current snapshot, revalidate the complete replacement, and retry with that exact sequence",
                });
            }
            if rows.is_empty() {
                return Ok(current_seq);
            }
            self.commit_rows_locked(&rows)
        })
    }

    /// Writes one raw CF row through the WAL-backed batch path.
    pub fn write_cf(&self, cf: ColumnFamily, key: Vec<u8>, value: Vec<u8>) -> Result<Seq> {
        self.write_cf_batch([(cf, key, value)])
    }

    /// Reads one raw CF row at `snapshot`.
    pub fn read_cf_at(
        &self,
        snapshot: Seq,
        cf: ColumnFamily,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let snapshot = self.snapshot_handle(snapshot);
        self.rows.read_at(snapshot.snapshot(), cf, key, &self.clock)
    }

    /// Reads one raw CF row using an already-pinned snapshot lease.
    pub fn read_cf_snapshot(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        self.rows.read_at(snapshot, cf, key, &self.clock)
    }

    /// Re-reads an exact CF/key plan under one pinned snapshot while grouping
    /// the physical work by CF and key. Values are borrowed only for the
    /// callback duration; the complete value corpus is never materialized.
    ///
    /// The callback receives each input row's stable `ordinal` exactly once,
    /// even though physical reads occur in `(CF,key)` order. Tombstone bytes are
    /// deliberately exposed so a full-state verifier can hash the actual
    /// persisted marker instead of treating logical absence as sufficient.
    pub fn visit_ordered_cf_plan_at<E, F>(
        &self,
        snapshot: Seq,
        reads: &[OrderedCfRead<'_>],
        mut on_row: F,
    ) -> std::result::Result<OrderedReadbackMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, ColumnFamily, &[u8], Option<&[u8]>) -> std::result::Result<(), E>,
    {
        let snapshot = self.snapshot_handle(snapshot);
        if let Some((position, read)) = reads
            .iter()
            .enumerate()
            .find(|(position, read)| read.ordinal != *position)
        {
            return Err(E::from(calyx_core::CalyxError::aster_corrupt_shard(
                format!(
                    "ordered readback input position {position} carries ordinal {} instead of its stable input position",
                    read.ordinal
                ),
            )));
        }
        let mut ordered = reads.to_vec();
        ordered.sort_unstable_by(|left, right| {
            left.cf
                .cmp(&right.cf)
                .then_with(|| left.key.cmp(right.key))
                .then_with(|| left.ordinal.cmp(&right.ordinal))
        });
        let index_bytes = ordered
            .capacity()
            .checked_mul(std::mem::size_of::<OrderedCfRead<'_>>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback plan-index byte count overflow",
                ))
            })?;
        let mut metrics = OrderedReadbackMetrics {
            plan_index_bytes: index_bytes,
            ..OrderedReadbackMetrics::default()
        };
        let mut start = 0;
        while start < ordered.len() {
            let cf = ordered[start].cf;
            let mut end = start + 1;
            while end < ordered.len() && ordered[end].cf == cf {
                end += 1;
            }
            let keys = ordered[start..end]
                .iter()
                .map(|read| (read.ordinal, read.key))
                .collect::<Vec<_>>();
            let key_index_bytes = keys
                .capacity()
                .checked_mul(std::mem::size_of::<(usize, &[u8])>())
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(|| {
                    E::from(calyx_core::CalyxError::aster_corrupt_shard(
                        "ordered readback CF-key index byte count overflow",
                    ))
                })?;
            let mut group_metrics = self.rows.visit_cf_key_plan(
                snapshot.snapshot(),
                cf,
                &keys,
                &self.clock,
                &mut |ordinal, value| {
                    let read = reads.get(ordinal).ok_or_else(|| {
                        E::from(calyx_core::CalyxError::aster_corrupt_shard(format!(
                            "ordered readback ordinal {ordinal} is outside the {}-row input plan",
                            reads.len()
                        )))
                    })?;
                    if read.cf != cf {
                        return Err(E::from(calyx_core::CalyxError::aster_corrupt_shard(
                            format!(
                                "ordered readback ordinal {ordinal} changed CF from {} to {}",
                                read.cf.name(),
                                cf.name()
                            ),
                        )));
                    }
                    on_row(ordinal, cf, read.key, value)
                },
            )?;
            group_metrics.plan_index_bytes = index_bytes
                .checked_add(key_index_bytes)
                .and_then(|bytes| bytes.checked_add(group_metrics.plan_index_bytes))
                .ok_or_else(|| {
                    E::from(calyx_core::CalyxError::aster_corrupt_shard(
                        "ordered readback peak plan-index byte count overflow",
                    ))
                })?;
            metrics.checked_merge(group_metrics).map_err(E::from)?;
            start = end;
        }
        Ok(metrics)
    }

    /// Scans visible raw CF rows at `snapshot`.
    pub fn scan_cf_at(&self, snapshot: Seq, cf: ColumnFamily) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let snapshot = self.snapshot_handle(snapshot);
        self.rows.scan_cf_at(snapshot.snapshot(), cf, &self.clock)
    }

    /// Scans visible raw CF rows using an already-pinned snapshot lease.
    pub fn scan_cf_snapshot(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.rows.scan_cf_at(snapshot, cf, &self.clock)
    }

    /// Scans visible raw CF rows in a key range at `snapshot`.
    pub fn scan_cf_range_at(
        &self,
        snapshot: Seq,
        cf: ColumnFamily,
        range: &KeyRange,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let snapshot = self.snapshot_handle(snapshot);
        self.rows
            .scan_cf_range_at(snapshot.snapshot(), cf, range, &self.clock)
    }

    /// Scans visible raw CF rows in a key range using an already-pinned snapshot lease.
    pub fn scan_cf_range_snapshot(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        range: &KeyRange,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.rows.scan_cf_range_at(snapshot, cf, range, &self.clock)
    }

    /// Scans visible raw CF row keys in a key range at `snapshot`.
    pub fn scan_cf_range_keys_at(
        &self,
        snapshot: Seq,
        cf: ColumnFamily,
        range: &KeyRange,
    ) -> Result<Vec<Vec<u8>>> {
        let snapshot = self.snapshot_handle(snapshot);
        self.rows
            .scan_cf_range_keys_at(snapshot.snapshot(), cf, range, &self.clock)
    }

    /// Scans at most `limit` visible raw CF rows in key order after `after_key`.
    pub fn scan_cf_range_page_at(
        &self,
        snapshot: Seq,
        cf: ColumnFamily,
        range: &KeyRange,
        after_key: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let snapshot = self.snapshot_handle(snapshot);
        self.rows.scan_cf_range_page_at(
            snapshot.snapshot(),
            cf,
            range,
            after_key,
            limit,
            &self.clock,
        )
    }
}
