//! Env-gated sub-phase timing for the Aster group-commit path (issue #444).
//!
//! Wave-20 (#433) attributed 88–89% of Astrolabe's `write_import_rows` to
//! Calyx's single atomic `group_commit`, growing linearly with rows. That
//! measurement stopped at the `group_commit` boundary; this module opens it up
//! so a measurement-first lever choice can name *which* internal phase grows:
//! ledger-bind (decode/re-encode provenance per Base/Graph row), WAL payload
//! serialization, WAL page-write, the WAL fsync, the ledger-head anchor fsync,
//! the MVCC memtable apply, and checkpoint staging.
//!
//! Permanent, not test-only. Zero-cost when unset: the enable flag is resolved
//! once into a process-global `OnceLock<bool>`, so a disabled build pays one
//! relaxed atomic load per commit phase and nothing else. Enable with
//! `CALYX_COMMIT_TIMING=1` (or `=true`); output goes to stderr, one line per
//! phase, mirroring the existing `astro.shadow.timing`/libcbm `CBM_PROFILE`
//! convention so a single stderr capture carries both layers of the breakdown.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

static ENABLED: OnceLock<bool> = OnceLock::new();

/// True when `CALYX_COMMIT_TIMING` selects the commit-phase breakdown. Resolved
/// once per process; later env mutations do not change an already-observed
/// verdict (deterministic within a run, which is what FSV compares).
#[inline]
pub(crate) fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var_os("CALYX_COMMIT_TIMING").is_some_and(|value| value == "1" || value == "true")
    })
}

/// Emits one labelled phase line when timing is enabled. `rows`/`bytes` are the
/// phase's scale inputs (pass `0` where a dimension does not apply) so the
/// reader can see linear-in-rows vs per-commit-constant behaviour directly.
#[inline]
pub(crate) fn record(phase: &str, elapsed: Duration, rows: usize, bytes: usize) {
    if !enabled() {
        return;
    }
    eprintln!(
        "calyx.commit.timing phase={phase} us={} rows={rows} bytes={bytes}",
        elapsed.as_micros()
    );
}

/// Start a phase timer. `stop`/`Drop` is a no-op cost when timing is disabled;
/// the `Instant::now()` here is only taken when enabled to keep the off-path
/// free of clock syscalls.
#[inline]
pub(crate) fn start() -> PhaseTimer {
    PhaseTimer {
        at: enabled().then(Instant::now),
    }
}

/// A single-phase stopwatch. Only ticks a real clock when timing is enabled.
pub(crate) struct PhaseTimer {
    at: Option<Instant>,
}

impl PhaseTimer {
    /// Records `phase` with this timer's elapsed span and its scale inputs.
    #[inline]
    pub(crate) fn stop(self, phase: &str, rows: usize, bytes: usize) {
        if let Some(at) = self.at {
            record(phase, at.elapsed(), rows, bytes);
        }
    }
}
