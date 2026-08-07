use super::AsterVault;
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
        self.snapshot_handle_with_stall_window(
            seq,
            crate::knobs::SNAPSHOT_PIN_STALL_WINDOW_MS.default,
        )
    }

    /// Pins a scoped snapshot under an explicitly chosen stall window.
    ///
    /// The window classifies the *holder*, not the read. A scoped vault
    /// operation resolves rows continuously and reaches a progress point within
    /// microseconds of pinning, so it uses the base window. A retained session
    /// hands control back to a caller that may run for minutes between reads, so
    /// it uses the session window (#1038).
    fn snapshot_handle_with_stall_window(
        &self,
        seq: Seq,
        stall_window_ms: u64,
    ) -> ScopedSnapshot<'_> {
        let snapshot =
            self.rows
                .pin_snapshot_at(seq, Freshness::FreshDerived, &self.clock, stall_window_ms);
        ScopedSnapshot {
            rows: &self.rows,
            snapshot,
        }
    }

    /// Pins one snapshot lease for a complete logical multi-get operation.
    ///
    /// A session is a **session-class** holder: the `SstReadSession` is returned
    /// to the caller, which routinely builds a corpus-proportional key plan,
    /// ranks, or audits between reads, so it reaches a progress point far less
    /// often than a scoped operation. Pinning it under the base window made a
    /// legitimate holder's own preparation indistinguishable from a stall and
    /// reaped the pin before its first read (#980 g25: 5,165 ms of plan setup
    /// against a 5,000 ms window, zero progress recorded). The pin is still
    /// released on `Drop`, so the wider window bounds only an abandoned handle.
    pub fn sst_read_session_at(&self, seq: Seq) -> Result<SstReadSession<'_, C>> {
        let snapshot = self.snapshot_handle_with_stall_window(
            seq,
            crate::knobs::SNAPSHOT_PIN_SESSION_STALL_WINDOW_MS.default,
        );
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
