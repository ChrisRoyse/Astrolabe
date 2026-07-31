use super::AsterVault;
use crate::cf::{ColumnFamily, ledger_key};
use crate::ledger_view::{LedgerPointReadTierStats, LedgerPointReadTrace};
use calyx_core::{Clock, Result, Seq};
use calyx_ledger::LedgerRow;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Returns the visible MVCC sequence for one CF/key at `snapshot`.
    pub fn seq_for_key_at(
        &self,
        snapshot: Seq,
        cf: ColumnFamily,
        key: &[u8],
    ) -> Result<Option<Seq>> {
        let snapshot = self.snapshot_handle(snapshot);
        self.rows
            .seq_for_key_at(snapshot.snapshot(), cf, key, &self.clock)
    }

    /// Returns the visible MVCC sequence for one CF/key at the latest snapshot.
    pub fn seq_for_key(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Seq>> {
        self.seq_for_key_at(self.latest_seq(), cf, key)
    }

    /// Independently reads exact Ledger rows from their physical durable home.
    ///
    /// Durable vaults route through the manifest/WAL-aware physical point reader;
    /// volatile vaults point-read the live router at one exact snapshot and label
    /// that storage mode explicitly. No write receipt or in-memory ledger hook is
    /// trusted as readback evidence.
    pub fn read_physical_ledger_seqs(
        &self,
        seqs: &BTreeSet<u64>,
    ) -> Result<(BTreeMap<u64, LedgerRow>, LedgerPointReadTrace)> {
        if seqs.is_empty() {
            return Ok((BTreeMap::new(), LedgerPointReadTrace::default()));
        }
        if let Some(root) = self.durable_root() {
            return crate::ledger_view::read_ledger_seqs_traced(root, seqs);
        }

        let started = Instant::now();
        let snapshot = self.latest_seq();
        let mut rows = BTreeMap::new();
        for seq in seqs {
            if let Some(bytes) =
                self.read_cf_at(snapshot, ColumnFamily::Ledger, &ledger_key(*seq))?
            {
                rows.insert(*seq, LedgerRow { seq: *seq, bytes });
            }
        }
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let resolved = seqs.iter().filter(|seq| rows.contains_key(seq)).count();
        Ok((
            rows,
            LedgerPointReadTrace {
                tiers: vec![LedgerPointReadTierStats {
                    tier: "volatile_router",
                    wanted: seqs.len(),
                    resolved,
                    files_opened: 0,
                    elapsed_ms,
                }],
            },
        ))
    }
}
