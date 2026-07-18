//! Snapshot-scoped raw CF read and scan accessors on [`AsterVault`]. These pin a
//! vault-internal snapshot handle (or accept an already-pinned lease) and defer
//! to the MVCC store's visibility-filtered readers.

use super::{AsterVault, encode};
use crate::cf::{ColumnFamily, KeyRange};
use crate::mvcc::Snapshot;
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
