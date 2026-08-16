use super::AsterVault;
use crate::mvcc::{Freshness, Snapshot, SstReadGeneration, VersionedCfStore};
use calyx_core::{Clock, Result, Seq};

/// Opaque operation-scoped lease that keeps one MVCC sequence reclaim-safe.
///
/// Registry-owned interpretation layers retain this guard while a logical
/// read spans more than one Aster plan (for example manifest discrimination
/// followed by primary/proof reads). The guard exposes no row access and does
/// not request a full MVCC restore; dropping it releases the exact sequence.
pub struct RetainedSnapshot<'a> {
    rows: &'a VersionedCfStore,
    snapshot: Snapshot,
    clock: &'a dyn Clock,
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
    pub(super) snapshot: RetainedSnapshot<'a>,
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

impl RetainedSnapshot<'_> {
    pub(super) const fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    /// Exact sequence protected for the guard's lifetime.
    pub const fn seq(&self) -> Seq {
        self.snapshot.seq()
    }

    /// Records a phase boundary for a progressing multi-plan operation.
    pub fn record_progress(&self) {
        self.rows.record_reader_progress(self.snapshot, self.clock);
    }
}

impl Drop for RetainedSnapshot<'_> {
    fn drop(&mut self) {
        self.rows.release_lease(self.snapshot.lease().id());
    }
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    pub(super) fn snapshot_handle(&self, seq: Seq) -> RetainedSnapshot<'_> {
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
    ) -> RetainedSnapshot<'_> {
        let snapshot =
            self.rows
                .pin_snapshot_at(seq, Freshness::FreshDerived, &self.clock, stall_window_ms);
        RetainedSnapshot {
            rows: &self.rows,
            snapshot,
            clock: &self.clock,
        }
    }

    /// Retains one MVCC sequence across a caller-owned logical operation.
    ///
    /// This is the narrow cross-crate continuity primitive: it neither opens a
    /// column family nor restores rows. Callers continue to issue explicit,
    /// narrow read plans while this opaque guard prevents snapshot GC from
    /// reclaiming the sequence between those plans.
    pub fn retain_snapshot_at(&self, seq: Seq) -> RetainedSnapshot<'_> {
        self.snapshot_handle_with_stall_window(
            seq,
            crate::knobs::SNAPSHOT_PIN_SESSION_STALL_WINDOW_MS.default,
        )
    }

    /// Atomically retains the latest MVCC sequence for a caller-owned logical
    /// operation.
    ///
    /// Unlike `retain_snapshot_at(self.latest_seq())`, the sequence observation
    /// and lease registration are one store operation, so a concurrent commit
    /// cannot create an unpinned gap between them.
    pub fn retain_latest_snapshot(&self) -> RetainedSnapshot<'_> {
        let snapshot = self.rows.pin_snapshot(
            Freshness::FreshDerived,
            &self.clock,
            crate::knobs::SNAPSHOT_PIN_SESSION_STALL_WINDOW_MS.default,
        );
        RetainedSnapshot {
            rows: &self.rows,
            snapshot,
            clock: &self.clock,
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
