//! Sequence allocation, freshness, and reader lease handles.

use calyx_core::{CalyxError, Clock, Result, Seq, Ts};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Vault-wide monotonic sequence allocator.
#[derive(Debug)]
pub struct SeqAllocator {
    current: AtomicU64,
    allocated: AtomicBool,
}

impl SeqAllocator {
    /// Creates an allocator whose next committed write is `start + 1`.
    pub const fn new(start: Seq) -> Self {
        Self {
            current: AtomicU64::new(start),
            allocated: AtomicBool::new(false),
        }
    }

    /// Allocates the next write sequence.
    pub fn allocate(&self) -> Seq {
        self.allocated.store(true, Ordering::Release);
        self.current.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Returns the latest committed sequence.
    pub fn current(&self) -> Seq {
        self.current.load(Ordering::Acquire)
    }

    /// Resets the recovered start sequence before any allocation in this process.
    pub fn set_start_seq(&self, seq: Seq) -> Result<()> {
        if self.allocated.load(Ordering::Acquire) {
            return Err(CalyxError::backpressure(
                "cannot reset MVCC start seq after allocation",
            ));
        }
        self.current.store(seq, Ordering::Release);
        Ok(())
    }

    /// Advances a live allocator after reading externally committed durable rows.
    pub fn advance_to_at_least(&self, seq: Seq) {
        let mut current = self.current();
        while current < seq {
            match self
                .current
                .compare_exchange(current, seq, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(next_current) => current = next_current,
            }
        }
    }
}

impl Default for SeqAllocator {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Derived-index freshness policy for reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Derived structures must be built at or after the pinned base sequence.
    FreshDerived,
    /// Derived structures may lag the pinned base sequence by at most `max_lag`.
    StaleOk { max_lag: Seq },
}

impl Freshness {
    /// Verifies a derived structure is acceptable for the pinned snapshot.
    pub fn ensure(self, pinned_seq: Seq, derived_seq: Seq) -> Result<()> {
        if derived_seq >= pinned_seq {
            return Ok(());
        }
        let lag = pinned_seq - derived_seq;
        match self {
            Self::FreshDerived => Err(CalyxError::stale_derived(format!(
                "derived seq {derived_seq} is behind pinned seq {pinned_seq}"
            ))),
            Self::StaleOk { max_lag } if lag <= max_lag => Ok(()),
            Self::StaleOk { max_lag } => Err(CalyxError::stale_derived(format!(
                "derived lag {lag} exceeds allowed lag {max_lag}"
            ))),
        }
    }
}

/// A bounded reader lease that pins one MVCC sequence.
///
/// The lease is a *liveness* bound on version GC, not a correctness lock: while
/// it is registered, snapshot GC may not reclaim versions at or below
/// `pinned_seq`. `max_age_ms` therefore bounds how long a reader may hold that
/// pin **without demonstrating forward progress** — it is deliberately NOT a
/// budget for how long a legitimate operation may run, because no fixed
/// duration can be a correct budget for a corpus-sized readback.
///
/// This value is an immutable `Copy` handed to every read call, so it carries
/// the lease's *issue-time identity*, not its authoritative deadline. The live
/// deadline is owned by the lease registry, which a progressing holder refreshes
/// in place (#980); see `VersionedCfStore::record_reader_progress`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderLease {
    id: u64,
    pinned_seq: Seq,
    issued_at: Ts,
    max_age_ms: u64,
}

impl ReaderLease {
    pub const fn new(id: u64, pinned_seq: Seq, issued_at: Ts, max_age_ms: u64) -> Self {
        Self {
            id,
            pinned_seq,
            issued_at,
            max_age_ms,
        }
    }

    pub const fn id(self) -> u64 {
        self.id
    }

    pub const fn pinned_seq(self) -> Seq {
        self.pinned_seq
    }

    pub const fn issued_at(self) -> Ts {
        self.issued_at
    }

    /// Stall window: the maximum time this lease may go without its holder
    /// demonstrating forward progress before version GC may reclaim its pin.
    pub const fn max_age_ms(self) -> u64 {
        self.max_age_ms
    }

    /// Milliseconds since this lease was issued, measured from the immutable
    /// copy. The registry tracks the authoritative time since last progress.
    pub const fn age_at(self, now: Ts) -> u64 {
        now.saturating_sub(self.issued_at)
    }

    pub fn expires_at(self) -> Ts {
        self.issued_at.saturating_add(self.max_age_ms)
    }

    pub fn is_expired_at(self, now: Ts) -> bool {
        now >= self.expires_at()
    }

    pub fn is_expired(self, clock: &dyn Clock) -> bool {
        self.is_expired_at(clock.now())
    }

    /// Fail-closed liveness check against this immutable copy's own window.
    ///
    /// Callers that hold a registered lease should go through
    /// `VersionedCfStore::ensure_snapshot_live`, which consults the registry's
    /// authoritative progress deadline first (#980). This copy-local check is
    /// the fallback for a lease that is no longer registered at all.
    pub fn ensure_live_at(self, now: Ts) -> Result<()> {
        if self.is_expired_at(now) {
            return Err(CalyxError::reader_lease_expired(format!(
                "reader lease {} for seq {} expired at {}: unregistered holder made no \
                 observable progress for {} ms (issued at {}, stall window max_age_ms={}, \
                 observed at {})",
                self.id,
                self.pinned_seq,
                self.expires_at(),
                self.age_at(now),
                self.issued_at,
                self.max_age_ms,
                now
            )));
        }
        Ok(())
    }

    pub fn ensure_live(self, clock: &dyn Clock) -> Result<()> {
        self.ensure_live_at(clock.now())
    }
}

/// Snapshot handle pinned to one sequence and guarded by a lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    seq: Seq,
    freshness: Freshness,
    lease: ReaderLease,
    derived_content_seq: Seq,
}

impl Snapshot {
    /// Builds a snapshot whose derived-content watermark defaults to `seq`
    /// itself — the fail-closed assumption that every committed seq up to the
    /// pin changed derived-search inputs (pre-#1100 exact-equality behavior).
    /// Store-backed pins override it via [`Self::with_derived_content_seq`].
    pub const fn new(seq: Seq, freshness: Freshness, lease: ReaderLease) -> Self {
        Self {
            seq,
            freshness,
            lease,
            derived_content_seq: seq,
        }
    }

    /// Attaches the vault's derived-content watermark observed at pin time.
    /// Callers must clamp it to `seq` (the store pin paths do); a watermark
    /// above the pinned seq would claim knowledge of commits after the pin.
    pub const fn with_derived_content_seq(mut self, derived_content_seq: Seq) -> Self {
        self.derived_content_seq = derived_content_seq;
        self
    }

    pub const fn seq(self) -> Seq {
        self.seq
    }

    /// Max seq at or below [`Self::seq`] whose commit wrote at least one row
    /// in a CF that feeds derived search content (issue #1100). Content-neutral
    /// commits (idempotency-ledger appends, time-index sentinels) advance
    /// [`Self::seq`] but not this watermark.
    pub const fn derived_content_seq(self) -> Seq {
        self.derived_content_seq
    }

    pub const fn freshness(self) -> Freshness {
        self.freshness
    }

    pub const fn lease(self) -> ReaderLease {
        self.lease
    }

    pub fn ensure_live(self, clock: &dyn Clock) -> Result<()> {
        self.lease.ensure_live(clock)
    }
}
