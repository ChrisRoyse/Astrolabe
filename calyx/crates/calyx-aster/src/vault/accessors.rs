//! Snapshot-scoped raw CF read and scan accessors on [`AsterVault`]. These pin a
//! vault-internal snapshot handle (or accept an already-pinned lease) and defer
//! to the MVCC store's visibility-filtered readers.

use super::{AsterVault, OrderedCfRead, SstReadSession, encode};
use crate::cf::{ColumnFamily, KeyRange};
use crate::mvcc::{CfRead, OrderedReadbackMetrics, Snapshot, SstReadGeneration};
use calyx_core::{Clock, Result, Seq};
use std::path::Path;

/// Pin-independent part of one ordered readback plan (#980 g25).
///
/// Validating ordinals, cloning the plan, sorting it into `(CF, key, ordinal)`
/// order, and sizing the publication buffers are pure functions of `reads`: they
/// touch no vault state and cannot resolve a row. At corpus scale that setup
/// runs longer than the whole base stall window, so performing it under a pinned
/// reader lease both blocked version GC for no reason and made the holder's own
/// preparation look like a stall. Preparing before the pin removes the window
/// entirely for [`AsterVault::visit_ordered_cf_plan_at`].
struct PreparedOrderedPlan<'a> {
    ordered: Vec<OrderedCfRead<'a>>,
    buffered_values: Vec<Option<Vec<u8>>>,
    buffered_seen: Vec<bool>,
    index_bytes: u64,
}

impl<'a> PreparedOrderedPlan<'a> {
    fn prepare<E>(reads: &[OrderedCfRead<'a>]) -> std::result::Result<Self, E>
    where
        E: From<calyx_core::CalyxError>,
    {
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
        let mut index_bytes = ordered
            .capacity()
            .checked_mul(std::mem::size_of::<OrderedCfRead<'_>>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback plan-index byte count overflow",
                ))
            })?;
        let buffered_values: Vec<Option<Vec<u8>>> = vec![None; reads.len()];
        let buffered_seen = vec![false; reads.len()];
        let publication_index_bytes = buffered_values
            .capacity()
            .checked_mul(std::mem::size_of::<Option<Vec<u8>>>())
            .and_then(|bytes| bytes.checked_add(buffered_seen.capacity()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback publication-buffer byte count overflow",
                ))
            })?;
        index_bytes = index_bytes
            .checked_add(publication_index_bytes)
            .ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback retained-index byte count overflow",
                ))
            })?;
        Ok(Self {
            ordered,
            buffered_values,
            buffered_seen,
            index_bytes,
        })
    }
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Exact durable root retained by this vault handle, or `None` for an
    /// in-memory/router-backed vault.
    pub fn durable_vault_root(&self) -> Option<&Path> {
        self.durable_root.as_deref()
    }

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
        self.commit_rows_if_seq(expected_seq, rows, "conditional CF batch")
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

    /// Reads a caller-declared raw CF plan under one scoped snapshot lease.
    /// Results preserve the plan's exact input order.
    pub fn read_cf_batch_at(
        &self,
        snapshot: Seq,
        reads: impl IntoIterator<Item = (ColumnFamily, Vec<u8>)>,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        let reads = reads
            .into_iter()
            .map(|(cf, key)| CfRead::new(cf, key))
            .collect::<Vec<_>>();
        if reads.is_empty() {
            return Ok(Vec::new());
        }
        let snapshot = self.snapshot_handle(snapshot);
        self.rows
            .read_batch(snapshot.snapshot(), &reads, &self.clock)
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
    /// the physical work by CF and key. Values are retained only until every
    /// requested CF/generation has passed validation, then published in caller
    /// order. A storage failure therefore invokes no consumer callback.
    ///
    /// The callback receives each input row's stable `ordinal` exactly once,
    /// even though physical reads occur in `(CF,key)` order. Tombstone bytes are
    /// deliberately exposed so a full-state verifier can hash the actual
    /// persisted marker instead of treating logical absence as sufficient.
    pub fn visit_ordered_cf_plan_at<E, F>(
        &self,
        snapshot: Seq,
        reads: &[OrderedCfRead<'_>],
        on_row: F,
    ) -> std::result::Result<OrderedReadbackMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, ColumnFamily, &[u8], Option<&[u8]>) -> std::result::Result<(), E>,
    {
        // Prepare before pinning: see `PreparedOrderedPlan`. No corpus-
        // proportional work may run between the pin and the first read (#980 g25).
        let plan = PreparedOrderedPlan::prepare(reads)?;
        self.sst_read_session_at(snapshot)
            .map_err(E::from)?
            .visit_prepared_ordered_plan(plan, reads, on_row)
    }

    /// Opens one retained-snapshot session for a complete logical multi-get.
    pub fn sst_read_session(&self) -> calyx_core::Result<SstReadSession<'_, C>> {
        self.sst_read_session_at(self.latest_seq())
    }

    fn visit_ordered_cf_plan_snapshot<E, F>(
        &self,
        generation: &SstReadGeneration<'_>,
        snapshot: Snapshot,
        plan: PreparedOrderedPlan<'_>,
        reads: &[OrderedCfRead<'_>],
        mut on_row: F,
    ) -> std::result::Result<OrderedReadbackMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, ColumnFamily, &[u8], Option<&[u8]>) -> std::result::Result<(), E>,
    {
        let PreparedOrderedPlan {
            ordered,
            mut buffered_values,
            mut buffered_seen,
            index_bytes,
        } = plan;
        let mut metrics = OrderedReadbackMetrics {
            session_snapshot_seq: snapshot.seq(),
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
            let mut group_metrics = self.rows.visit_cf_key_plan_in_generation(
                generation,
                snapshot,
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
                    if buffered_seen[ordinal] {
                        return Err(E::from(calyx_core::CalyxError::aster_corrupt_shard(
                            format!(
                                "ordered readback ordinal {ordinal} was resolved more than once"
                            ),
                        )));
                    }
                    buffered_values[ordinal] = value.map(ToOwned::to_owned);
                    buffered_seen[ordinal] = true;
                    Ok(())
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
            // A fully resolved CF group is demonstrated forward progress (#980).
            self.rows.record_reader_progress(snapshot, &self.clock);
        }
        if let Some(missing) = buffered_seen.iter().position(|seen| !seen) {
            return Err(E::from(calyx_core::CalyxError::aster_corrupt_shard(
                format!("ordered readback ordinal {missing} was never resolved"),
            )));
        }
        let buffered_bytes = buffered_values.iter().try_fold(0_u64, |total, value| {
            let len = value.as_ref().map_or(0, Vec::len);
            let len = u64::try_from(len).map_err(|_| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback buffered value exceeds u64",
                ))
            })?;
            total.checked_add(len).ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback buffered-byte count overflow",
                ))
            })
        })?;
        metrics.max_readback_batch_bytes = metrics.max_readback_batch_bytes.max(buffered_bytes);
        for (ordinal, read) in reads.iter().enumerate() {
            // Publishing one row is demonstrated forward progress. At corpus
            // scale this loop alone runs for minutes while the caller digests
            // every row, so it must keep the reader's registry lease alive (#980).
            self.rows.record_reader_progress(snapshot, &self.clock);
            on_row(
                ordinal,
                read.cf,
                read.key,
                buffered_values[ordinal].as_deref(),
            )?;
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

impl<C> SstReadSession<'_, C>
where
    C: Clock,
{
    /// Executes an ordered physical plan under this session's retained snapshot.
    /// Each required SST is mapped at most once for the plan and all mappings
    /// are dropped before this method returns.
    pub fn visit_ordered_cf_plan<E, F>(
        &self,
        reads: &[OrderedCfRead<'_>],
        on_row: F,
    ) -> std::result::Result<OrderedReadbackMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, ColumnFamily, &[u8], Option<&[u8]>) -> std::result::Result<(), E>,
    {
        // Reached with the session already pinned, so the caller's plan
        // preparation necessarily runs under the lease — which is exactly why a
        // session is a session-class holder (#1038, and the session stall window
        // in `sst_read_session_at`).
        let plan = PreparedOrderedPlan::prepare(reads)?;
        self.visit_prepared_ordered_plan(plan, reads, on_row)
    }

    fn visit_prepared_ordered_plan<E, F>(
        &self,
        plan: PreparedOrderedPlan<'_>,
        reads: &[OrderedCfRead<'_>],
        on_row: F,
    ) -> std::result::Result<OrderedReadbackMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, ColumnFamily, &[u8], Option<&[u8]>) -> std::result::Result<(), E>,
    {
        self.vault.visit_ordered_cf_plan_snapshot(
            &self.generation,
            self.snapshot.snapshot(),
            plan,
            reads,
            on_row,
        )
    }
}
