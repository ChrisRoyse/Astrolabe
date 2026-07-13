//! Debounced lowered-SQLite regeneration coordinator (#225).
//!
//! A production-path weave run mutates vault state the lowered SQLite artifact
//! derives from. Regenerating the artifact after *every* mutation would rewrite
//! it once per weave commit in a burst; instead this coordinator coalesces a
//! burst into one regeneration, using the registry-declared debounce window
//! ([`astrolabe_domain::knobs::LOWER_DEBOUNCE_WINDOW_MS_KNOB`], standing
//! invariant 4 — no bare constant).
//!
//! # Mechanism
//!
//! The coordinator implements [`astrolabe_domain::LoweringTrigger`]: the weave
//! plumbing calls [`LoweringTrigger::request_regeneration`] after each mutating
//! commit, which arms a trailing-edge timer (records the request time and bumps a
//! pending generation counter). A driver — the server tick, or the next status
//! call — periodically calls [`LowerDebouncer::run_due`]. `run_due` performs the
//! actual regeneration exactly once the window has elapsed quietly since the last
//! request, capturing every mutation that arrived during the window in one
//! rewrite.
//!
//! The regeneration action is supplied by the caller (a closure that calls
//! [`crate::lower_cbm_sqlite`] under the server's `.astrolabe-lowered.lock`), so
//! this crate stays free of the OS-lock and server surface. Cross-process safety
//! is provided by that OS file lock plus the idempotent lowering manifest: two
//! processes racing to regenerate the same post-weave vault serialize on the lock
//! and the second observes a byte-identical manifest, so the net effect is one
//! regeneration.
//!
//! # Fail-closed
//!
//! If the regeneration action returns an error, the pending generation is *not*
//! marked fired: the coordinator stays armed and a later `run_due` retries. A
//! failed regeneration never silently drops the pending work.

use std::sync::Mutex;

use astrolabe_domain::LoweringTrigger;
use astrolabe_domain::knobs::{
    LOWER_DEBOUNCE_DEFAULT_WINDOW_MS, LOWER_DEBOUNCE_WINDOW_MS_KNOB, lower_debounce_knob,
};
use calyx_core::{Clock, Ts};

use crate::{LowerError, LowerResult};

/// Stable refusal code: the requested debounce window is outside the registry
/// bounds declared for [`LOWER_DEBOUNCE_WINDOW_MS_KNOB`].
pub const ASTRO_LOWER_DEBOUNCE_WINDOW_OUT_OF_RANGE: &str =
    "ASTRO_LOWER_DEBOUNCE_WINDOW_OUT_OF_RANGE";

const WINDOW_REMEDIATION: &str = "Set the lowered-SQLite debounce window to a value inside the registry-declared bounds for lower_debounce_window_ms, or use LowerDebouncer::with_default_window.";

/// Outcome of one [`LowerDebouncer::run_due`] call.
#[derive(Debug)]
pub enum RunOutcome<T> {
    /// No regeneration is pending — no weave mutation has been signalled since
    /// the last one fired. The regeneration action was not invoked.
    Idle,
    /// A regeneration is pending but the debounce window has not elapsed quietly
    /// yet. The action was not invoked; call again after the window.
    Waiting,
    /// The regeneration action ran and its result is carried here.
    Regenerated(T),
}

impl<T> RunOutcome<T> {
    /// True only when the regeneration action actually ran this call.
    pub fn regenerated(&self) -> bool {
        matches!(self, Self::Regenerated(_))
    }
}

#[derive(Debug)]
struct DebounceState {
    /// Monotonic count of regeneration requests received.
    pending_gen: u64,
    /// Highest request generation a completed regeneration has covered.
    fired_gen: u64,
    /// Server timestamp (Unix ms) of the most recent request, arming the timer.
    last_request_ts: Option<Ts>,
}

/// Coalesces a burst of weave-mutation regeneration requests into one lowered
/// SQLite regeneration, gated by the registry-declared debounce window.
#[derive(Debug)]
pub struct LowerDebouncer<C: Clock> {
    window_ms: u64,
    clock: C,
    state: Mutex<DebounceState>,
}

impl<C: Clock> LowerDebouncer<C> {
    /// Builds a coordinator with an explicit window, validated against the
    /// registry bounds for [`LOWER_DEBOUNCE_WINDOW_MS_KNOB`]. A window outside
    /// the bounds is refused fail-closed.
    pub fn new(clock: C, window_ms: u64) -> LowerResult<Self> {
        let knob = lower_debounce_knob(LOWER_DEBOUNCE_WINDOW_MS_KNOB).ok_or_else(|| {
            LowerError::refused(
                ASTRO_LOWER_DEBOUNCE_WINDOW_OUT_OF_RANGE,
                "lower_debounce_window_ms knob is not declared in the registry.",
                WINDOW_REMEDIATION,
            )
        })?;
        if !knob.accepts(window_ms) {
            return Err(LowerError::refused(
                ASTRO_LOWER_DEBOUNCE_WINDOW_OUT_OF_RANGE,
                format!(
                    "debounce window {window_ms} {} is outside the declared bounds [{}, {}] for {}.",
                    knob.unit, knob.min, knob.max, knob.name
                ),
                WINDOW_REMEDIATION,
            ));
        }
        Ok(Self {
            window_ms,
            clock,
            state: Mutex::new(DebounceState {
                pending_gen: 0,
                fired_gen: 0,
                last_request_ts: None,
            }),
        })
    }

    /// Builds a coordinator using the registry-declared default window.
    ///
    /// The default is in-bounds by the knob-registry invariant (proven in
    /// `astrolabe_domain::knobs`), so this never fails.
    pub fn with_default_window(clock: C) -> Self {
        Self::new(clock, LOWER_DEBOUNCE_DEFAULT_WINDOW_MS)
            .expect("registry-declared default debounce window is in-bounds")
    }

    /// The debounce window in milliseconds this coordinator enforces.
    pub fn window_ms(&self) -> u64 {
        self.window_ms
    }

    /// True when a weave mutation has been signalled that no regeneration has yet
    /// covered — i.e. a regeneration is owed (though perhaps not yet due).
    pub fn pending(&self) -> bool {
        let state = self.state.lock().expect("debounce state mutex poisoned");
        state.pending_gen > state.fired_gen
    }

    /// True when a regeneration is pending *and* the debounce window has elapsed
    /// quietly since the most recent request, so [`Self::run_due`] would fire.
    pub fn is_due(&self, now: Ts) -> bool {
        let state = self.state.lock().expect("debounce state mutex poisoned");
        Self::due_locked(&state, now, self.window_ms)
    }

    fn due_locked(state: &DebounceState, now: Ts, window_ms: u64) -> bool {
        if state.pending_gen <= state.fired_gen {
            return false;
        }
        match state.last_request_ts {
            Some(ts) => now.saturating_sub(ts) >= window_ms,
            None => false,
        }
    }

    /// Runs the regeneration action iff a regeneration is pending and its
    /// debounce window has elapsed quietly.
    ///
    /// Returns [`RunOutcome::Idle`] when nothing is pending, [`RunOutcome::Waiting`]
    /// when the window has not yet elapsed, and [`RunOutcome::Regenerated`] with
    /// the action's result when it fired. The action is invoked at most once per
    /// call, and it captures every request that arrived up to the moment the
    /// window check passed — so a burst coalesces into one regeneration.
    ///
    /// The state lock is released while the action runs, so a mutation arriving
    /// during a regeneration re-arms the coordinator and is picked up by the next
    /// `run_due` rather than being lost. If the action returns `Err`, the pending
    /// generation is left un-fired (fail-closed retry) and the error propagates.
    pub fn run_due<F, T, E>(&self, regen: F) -> Result<RunOutcome<T>, E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let now = self.clock.now();
        let target_gen = {
            let state = self.state.lock().expect("debounce state mutex poisoned");
            if state.pending_gen <= state.fired_gen {
                return Ok(RunOutcome::Idle);
            }
            if !Self::due_locked(&state, now, self.window_ms) {
                return Ok(RunOutcome::Waiting);
            }
            state.pending_gen
        };

        // Lock released: a weave mutation during the regeneration bumps
        // pending_gen past target_gen and stays owed for the next run_due.
        let value = regen()?;

        let mut state = self.state.lock().expect("debounce state mutex poisoned");
        if state.fired_gen < target_gen {
            state.fired_gen = target_gen;
        }
        Ok(RunOutcome::Regenerated(value))
    }
}

impl<C: Clock> LoweringTrigger for LowerDebouncer<C> {
    fn request_regeneration(&self) {
        let now = self.clock.now();
        let mut state = self.state.lock().expect("debounce state mutex poisoned");
        state.pending_gen += 1;
        state.last_request_ts = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use astrolabe_domain::LoweringTrigger;
    use astrolabe_domain::knobs::{LOWER_DEBOUNCE_DEFAULT_WINDOW_MS, LOWER_DEBOUNCE_MAX_WINDOW_MS};
    use calyx_core::{Clock, Ts};

    use super::*;

    /// A manually advanceable clock so debounce timing is deterministic without
    /// real sleeps (astro-test doctrine: fast, no flaky wall-clock waits).
    #[derive(Clone, Default, Debug)]
    struct AdvancingClock {
        now: Arc<AtomicU64>,
    }

    impl AdvancingClock {
        fn new(start: Ts) -> Self {
            Self {
                now: Arc::new(AtomicU64::new(start)),
            }
        }
        fn advance(&self, delta_ms: u64) {
            self.now.fetch_add(delta_ms, Ordering::SeqCst);
        }
    }

    impl Clock for AdvancingClock {
        fn now(&self) -> Ts {
            self.now.load(Ordering::SeqCst)
        }
    }

    fn ok_regen(counter: &AtomicU64) -> Result<(), &'static str> {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    #[test]
    fn window_outside_registry_bounds_is_refused_fail_closed() {
        let clock = AdvancingClock::new(0);
        let err = LowerDebouncer::new(clock.clone(), 0).expect_err("zero window is illegal");
        assert_eq!(err.code(), Some(ASTRO_LOWER_DEBOUNCE_WINDOW_OUT_OF_RANGE));
        assert!(err.remediation().is_some());
        let too_big = LowerDebouncer::new(clock, LOWER_DEBOUNCE_MAX_WINDOW_MS + 1)
            .expect_err("over-max window is illegal");
        assert_eq!(
            too_big.code(),
            Some(ASTRO_LOWER_DEBOUNCE_WINDOW_OUT_OF_RANGE)
        );
    }

    #[test]
    fn default_window_matches_registry_default() {
        let debouncer = LowerDebouncer::with_default_window(AdvancingClock::new(0));
        assert_eq!(debouncer.window_ms(), LOWER_DEBOUNCE_DEFAULT_WINDOW_MS);
    }

    #[test]
    fn zero_mutations_never_regenerates() {
        // Edge triad #1: no signal -> run_due is idle and never touches the
        // regeneration action.
        let clock = AdvancingClock::new(1_000);
        let debouncer = LowerDebouncer::new(clock.clone(), 500).expect("valid window");
        let calls = AtomicU64::new(0);
        clock.advance(10_000);
        let outcome = debouncer
            .run_due(|| ok_regen(&calls))
            .expect("idle run_due");
        assert!(matches!(outcome, RunOutcome::Idle));
        assert!(!debouncer.pending());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn run_before_window_waits_and_after_window_fires_once() {
        let clock = AdvancingClock::new(0);
        let debouncer = LowerDebouncer::new(clock.clone(), 500).expect("valid window");
        let calls = AtomicU64::new(0);

        debouncer.request_regeneration();
        assert!(debouncer.pending());

        // Window not elapsed: waiting, action untouched.
        clock.advance(200);
        assert!(!debouncer.is_due(clock.now()));
        let waiting = debouncer.run_due(|| ok_regen(&calls)).expect("waiting");
        assert!(matches!(waiting, RunOutcome::Waiting));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // Window elapsed quietly: fires exactly once.
        clock.advance(400); // now 600ms >= 500 since the single request
        assert!(debouncer.is_due(clock.now()));
        let fired = debouncer.run_due(|| ok_regen(&calls)).expect("fire");
        assert!(fired.regenerated());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!debouncer.pending(), "fired generation clears the debt");

        // Nothing owed now: idle, still one call.
        let idle = debouncer.run_due(|| ok_regen(&calls)).expect("idle");
        assert!(matches!(idle, RunOutcome::Idle));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn burst_of_mutations_coalesces_into_one_regeneration() {
        // Coalescing DoD: N rapid signals -> one regeneration.
        let clock = AdvancingClock::new(0);
        let debouncer = LowerDebouncer::new(clock.clone(), 500).expect("valid window");
        let calls = AtomicU64::new(0);

        for _ in 0..8 {
            debouncer.request_regeneration();
            clock.advance(10); // each within the window of the previous
        }
        // Before the window elapses since the last signal: waiting.
        let waiting = debouncer.run_due(|| ok_regen(&calls)).expect("waiting");
        assert!(matches!(waiting, RunOutcome::Waiting));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // Quiet for the full window since the last of the 8 signals: one fire.
        clock.advance(500);
        let fired = debouncer.run_due(|| ok_regen(&calls)).expect("fire once");
        assert!(fired.regenerated());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "8 coalesced mutations regenerate exactly once"
        );
        assert!(!debouncer.pending());
    }

    #[test]
    fn mutation_arriving_during_regeneration_rearms_for_next_run() {
        // Edge triad #2: a signal delivered while the regeneration action runs is
        // not lost — the coordinator stays owed and the next run_due fires again.
        let clock = AdvancingClock::new(0);
        let debouncer = Arc::new(LowerDebouncer::new(clock.clone(), 500).expect("valid window"));
        let calls = AtomicU64::new(0);

        debouncer.request_regeneration();
        clock.advance(500);

        let during = debouncer.clone();
        let inner_clock = clock.clone();
        let first = debouncer
            .run_due(|| {
                // A weave mutation lands mid-regeneration.
                during.request_regeneration();
                inner_clock.advance(500);
                ok_regen(&calls)
            })
            .expect("first fire");
        assert!(first.regenerated());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            debouncer.pending(),
            "the mid-regeneration signal is still owed"
        );

        // The mid-flight signal's window has elapsed -> a second fire.
        let second = debouncer.run_due(|| ok_regen(&calls)).expect("second fire");
        assert!(second.regenerated());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!debouncer.pending());
    }

    #[test]
    fn regeneration_failure_stays_owed_and_retries_fail_closed() {
        // Edge triad #3: a failing regeneration must not mark the pending work as
        // done; the error propagates and a later run_due retries it.
        let clock = AdvancingClock::new(0);
        let debouncer = LowerDebouncer::new(clock.clone(), 500).expect("valid window");

        debouncer.request_regeneration();
        clock.advance(500);

        let err = debouncer
            .run_due(|| Err::<(), &'static str>("disk full"))
            .expect_err("regeneration error propagates");
        assert_eq!(err, "disk full");
        assert!(
            debouncer.pending(),
            "a failed regeneration leaves the work owed (fail-closed retry)"
        );

        let calls = AtomicU64::new(0);
        let retry = debouncer
            .run_due(|| ok_regen(&calls))
            .expect("retry succeeds");
        assert!(retry.regenerated());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!debouncer.pending());
    }
}
