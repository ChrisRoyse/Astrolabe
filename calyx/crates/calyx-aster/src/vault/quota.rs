//! Per-vault resource quotas with backpressure (PH60 · T04).
//!
//! [`QuotaGuard`] enforces per-vault rate limits — ingest (CXs/s), query
//! (queries/s), and IO (bytes/s) — so one heavy tenant cannot starve the
//! others (noisy-neighbor / DoS defense, PRD `30 §1`, `30 §3`). When a quota is
//! exceeded the charge is rejected with [`CALYX_QUOTA_EXCEEDED`] and the window
//! stays tripped (backpressure) until it rolls over — the caller must retry
//! after the window, never silently drop (A16, A26).
//!
//! ## Why one `Mutex`, not lock-free atomics
//!
//! A fixed-window limiter must reset `{window_start, ingest, query, io}` *and*
//! read-modify-write a counter as one indivisible step. Doing that across
//! several independent atomics is a TOCTOU race: two threads can both observe
//! the old window, both reset, and lose each other's increments — silently
//! **over-admitting** past the limit, the exact failure the guard exists to
//! prevent. A single `Mutex` around the whole window makes check-reset-charge
//! atomic, so the "quota is never exceeded" invariant holds under real
//! concurrency (proven by `concurrent_charges_never_over_admit`). Contention is
//! per-vault and each charge is O(1), so the lock is effectively free.

use calyx_core::{CalyxError, Result, VaultId};
use std::sync::Mutex;

/// A per-vault quota was exceeded; the operation is denied and backpressured.
pub const CALYX_QUOTA_EXCEEDED: &str = "CALYX_QUOTA_EXCEEDED";

/// Quota window length: one second, in nanoseconds.
pub const WINDOW_NS: u64 = 1_000_000_000;

/// Per-vault rate limits. `Default` is generous but finite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaConfig {
    /// Max constellations ingested per 1-second window.
    pub max_ingest_cx_per_sec: u32,
    /// Max queries per 1-second window.
    pub max_query_per_sec: u32,
    /// Max IO bytes per 1-second window.
    pub max_io_bytes_per_sec: u64,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_ingest_cx_per_sec: 1_000,
            max_query_per_sec: 500,
            max_io_bytes_per_sec: 256 * 1024 * 1024, // 256 MiB/s
        }
    }
}

/// Which counter a charge applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Resource {
    Ingest,
    Query,
    Io,
}

/// The mutable window state, guarded as one unit so check-reset-charge is atomic.
#[derive(Debug)]
struct Window {
    start_ns: u64,
    ingest_cx: u64,
    query: u64,
    io_bytes: u64,
    /// Config in force for the current window. Refreshed from `pending` only on
    /// window rollover, so a mid-window `update_config` applies next window.
    active: QuotaConfig,
    /// Staged config; becomes `active` at the next window boundary.
    pending: QuotaConfig,
}

impl Window {
    /// Rolls the window over if `now_ns` is at/after the next boundary, applying
    /// any pending config. Boundary is inclusive: a delta of exactly `WINDOW_NS`
    /// starts a fresh window (no off-by-one).
    fn advance(&mut self, now_ns: u64) {
        if now_ns.saturating_sub(self.start_ns) >= WINDOW_NS {
            self.start_ns = now_ns;
            self.ingest_cx = 0;
            self.query = 0;
            self.io_bytes = 0;
            self.active = self.pending;
        }
    }
}

/// Per-vault quota tracker. Share across request handlers via `Arc<QuotaGuard>`.
#[derive(Debug)]
pub struct QuotaGuard {
    vault_id: VaultId,
    window: Mutex<Window>,
}

impl QuotaGuard {
    /// Builds a guard for `vault_id` with `config` active from the first charge.
    pub fn new(vault_id: VaultId, config: QuotaConfig) -> Self {
        Self {
            vault_id,
            window: Mutex::new(Window {
                start_ns: 0,
                ingest_cx: 0,
                query: 0,
                io_bytes: 0,
                active: config,
                pending: config,
            }),
        }
    }

    /// The vault this guard meters.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Charges `cx_count` constellations against the ingest quota at `now_ns`.
    ///
    /// # Errors
    /// [`CALYX_QUOTA_EXCEEDED`] if the window total would exceed
    /// `max_ingest_cx_per_sec`. Backpressure: retry after the window rolls over.
    pub fn charge_ingest(&self, cx_count: u32, now_ns: u64) -> Result<()> {
        self.charge(Resource::Ingest, u64::from(cx_count), now_ns)
    }

    /// Charges `count` queries against the query quota at `now_ns`.
    pub fn charge_query(&self, count: u32, now_ns: u64) -> Result<()> {
        self.charge(Resource::Query, u64::from(count), now_ns)
    }

    /// Charges `bytes` against the IO-bytes quota at `now_ns`.
    pub fn charge_io(&self, bytes: u64, now_ns: u64) -> Result<()> {
        self.charge(Resource::Io, bytes, now_ns)
    }

    /// Stages a new config; it takes effect at the next window boundary (not the
    /// current window), so an in-flight window keeps its admitted budget stable.
    pub fn update_config(&self, config: QuotaConfig) {
        let mut w = self.lock();
        w.pending = config;
    }

    /// Snapshot of `(ingest_cx, query, io_bytes)` charged in the current window —
    /// the Source-of-Truth read for FSV.
    pub fn counters(&self) -> (u64, u64, u64) {
        let w = self.lock();
        (w.ingest_cx, w.query, w.io_bytes)
    }

    /// The config currently in force (after any pending rollover already applied).
    pub fn active_config(&self) -> QuotaConfig {
        self.lock().active
    }

    fn charge(&self, resource: Resource, amount: u64, now_ns: u64) -> Result<()> {
        // A zero-cost charge consumes nothing and can never exceed a quota,
        // even on an already-tripped window.
        if amount == 0 {
            return Ok(());
        }
        let mut w = self.lock();
        w.advance(now_ns);
        // Read the limit (a copy) before taking the mutable counter borrow.
        let (limit, name) = match resource {
            Resource::Ingest => (u64::from(w.active.max_ingest_cx_per_sec), "ingest_cx"),
            Resource::Query => (u64::from(w.active.max_query_per_sec), "query"),
            Resource::Io => (w.active.max_io_bytes_per_sec, "io_bytes"),
        };
        let counter = match resource {
            Resource::Ingest => &mut w.ingest_cx,
            Resource::Query => &mut w.query,
            Resource::Io => &mut w.io_bytes,
        };
        // Add-then-check: the tripping charge is counted, so the window stays
        // tripped (every later same-window charge also fails — fail closed).
        let new_total = counter.saturating_add(amount);
        *counter = new_total;
        if new_total > limit {
            return Err(quota_exceeded(format!(
                "vault {} {name} quota exceeded: {new_total} > {limit} per 1s window",
                self.vault_id,
            )));
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Window> {
        self.window
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn quota_exceeded(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_QUOTA_EXCEEDED,
        message: message.into(),
        remediation: "retry after the current 1-second quota window expires",
    }
}
