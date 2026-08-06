use super::AsterVault;
use crate::cf::{ColumnFamily, ledger_key};
use crate::ledger_view::{AsterLedgerCfStore, LedgerPointReadTierStats, LedgerPointReadTrace};
use calyx_core::{CalyxError, Clock, Result, Seq};
use calyx_ledger::{LedgerCfStore, LedgerHeadAnchor, LedgerRow};
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
        if let Some(root) = self.durable_root.as_deref() {
            if self.read_only {
                self.ensure_retained_ledger_snapshot()?;
                return crate::ledger_view::read_ledger_seqs_unlocked_traced(
                    root,
                    seqs,
                    self.durable_tiering_policy.as_ref(),
                );
            }
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

    /// Copies the physical Ledger CF plus its external head anchor while this
    /// handle's retained shared commit lock still defines the read snapshot.
    ///
    /// This deliberately refuses volatile, writable, unguarded, and
    /// Ledger-unselected handles. Reopening the path here would attempt an
    /// exclusive lock acquisition while this handle owns the shared lock and
    /// would destroy the single-snapshot guarantee by splitting the reads.
    pub fn retained_read_only_ledger_store(&self) -> Result<AsterLedgerCfStore> {
        self.ensure_retained_ledger_snapshot()?;
        let root = self.durable_root.as_deref().ok_or_else(|| CalyxError {
            code: "CALYX_RETAINED_LEDGER_SNAPSHOT_NOT_DURABLE",
            message: "retained Ledger snapshot requires a durable vault root".to_string(),
            remediation: "open the durable vault read-only with the Ledger column family selected",
        })?;
        AsterLedgerCfStore::open_unlocked_with_tiering(root, self.durable_tiering_policy.as_ref())
    }

    /// Returns the physical head anchor from the same retained read snapshot.
    pub fn retained_read_only_ledger_head(&self) -> Result<Option<LedgerHeadAnchor>> {
        self.retained_read_only_ledger_store()?.head_anchor()
    }

    fn ensure_retained_ledger_snapshot(&self) -> Result<()> {
        if self.durable_root.is_none() {
            return Err(CalyxError {
                code: "CALYX_RETAINED_LEDGER_SNAPSHOT_NOT_DURABLE",
                message: "retained Ledger snapshot requires a durable vault root".to_string(),
                remediation: "open the durable vault read-only with the Ledger column family selected",
            });
        }
        if !self.read_only {
            return Err(CalyxError {
                code: "CALYX_RETAINED_LEDGER_SNAPSHOT_WRITABLE",
                message: "retained Ledger snapshot rejected a write-capable vault handle"
                    .to_string(),
                remediation: "open a dedicated read-only vault handle and retain it for the complete read transaction",
            });
        }
        if self._read_snapshot_guard.is_none() {
            return Err(CalyxError {
                code: "CALYX_RETAINED_LEDGER_SNAPSHOT_LOCK_MISSING",
                message: "read-only durable vault has no retained shared commit lock".to_string(),
                remediation: "discard this handle and reopen the durable vault read-only before reading Ledger state",
            });
        }

        // A physical reader addresses files directly, so first force the live
        // router to enforce this selected-CF handle's exact Ledger capability.
        // Sequence zero is only a capability probe; its value is not trusted.
        let _ = self.read_cf_at(self.latest_seq(), ColumnFamily::Ledger, &ledger_key(0))?;
        Ok(())
    }
}
