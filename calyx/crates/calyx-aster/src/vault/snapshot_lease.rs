use super::{AsterVault, DEFAULT_LEASE_MS};
use crate::mvcc::{Freshness, Snapshot, SstReadGeneration, VersionedCfStore};
use calyx_core::{Clock, Result, Seq};

pub(super) struct ScopedSnapshot<'a> {
    rows: &'a VersionedCfStore,
    snapshot: Snapshot,
}

/// Operation-scoped immutable-SST read session bound to one retained MVCC
/// snapshot. Reusing this handle across related read plans avoids repeatedly
/// registering and releasing the same lease while every individual plan still
/// opens each required immutable generation at most once and drops its mappings
/// before returning.
pub struct SstReadSession<'a, C>
where
    C: Clock,
{
    // Drop the retained physical generation before releasing the MVCC lease so
    // compaction cannot observe an unpinned sequence between those events.
    pub(super) generation: SstReadGeneration<'a>,
    pub(super) vault: &'a AsterVault<C>,
    pub(super) snapshot: ScopedSnapshot<'a>,
}

impl<C> SstReadSession<'_, C>
where
    C: Clock,
{
    /// Exact MVCC sequence retained for the complete logical operation.
    pub const fn snapshot_seq(&self) -> Seq {
        self.snapshot.snapshot().seq()
    }
}

impl ScopedSnapshot<'_> {
    pub(super) const fn snapshot(&self) -> Snapshot {
        self.snapshot
    }
}

impl Drop for ScopedSnapshot<'_> {
    fn drop(&mut self) {
        self.rows.release_lease(self.snapshot.lease().id());
    }
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    pub(super) fn snapshot_handle(&self, seq: Seq) -> ScopedSnapshot<'_> {
        let snapshot =
            self.rows
                .pin_snapshot_at(seq, Freshness::FreshDerived, &self.clock, DEFAULT_LEASE_MS);
        ScopedSnapshot {
            rows: &self.rows,
            snapshot,
        }
    }

    /// Pins one snapshot lease for a complete logical multi-get operation.
    pub fn sst_read_session_at(&self, seq: Seq) -> Result<SstReadSession<'_, C>> {
        let snapshot = self.snapshot_handle(seq);
        let generation = self
            .rows
            .retain_sst_read_generation(snapshot.snapshot(), &self.clock)?;
        Ok(SstReadSession {
            generation,
            vault: self,
            snapshot,
        })
    }
}
