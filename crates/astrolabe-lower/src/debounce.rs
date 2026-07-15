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
