//! Advisory `PostToolUse` hook (P7.4, blueprint `10_GUARD.md` §5, CBM
//! `hook_augment` contract).
//!
//! After an agent tool edits code, an **advisory** quick guard check runs on a
//! strict wall-clock budget ([`ADVISORY_HOOK_BUDGET_MS`], 300ms). It scores only
//! the two cheapest, highest-signal slots — S18 code-semantic
//! ([`GuardSlot::CodeSemantic`]) and S4 API-callees ([`GuardSlot::ApiCallees`]) —
//! and is **strictly advisory**: it never blocks the agent flow and never
//! refuses. If it cannot finish within the budget it goes **silent** (the skip is
//! labeled and counted, per the honest-degradation invariant), returning no
//! advisory rather than stalling the tool.
//!
//! The budget is enforced by running the quick check on a worker thread and
//! waiting at most the budget on the caller: on timeout the caller returns
//! [`AdvisoryOutcome::SilentTimeout`] immediately (bounding the agent's wait),
//! while the worker is left to finish and drop in the background. This is the
//! faithful realization of "never blocks, silent on timeout" — the agent-facing
//! wait is bounded by the budget regardless of how slow the check turns out to be.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::calibration::CalibrationError;
use crate::check::{ComparisonRegion, Exemplar, MeasuredSymbol, cosine, resolve_region};
use crate::profile::{ADVISORY_HOOK_BUDGET_MS, GuardProfile, GuardSlot, SlotVerdict};

/// The two slots the advisory hook scores (S18 code-semantic, S4 API-callees).
/// Registry-declared (a fixed set, not a tunable) so the quick check's cost is
/// bounded and stable.
pub const ADVISORY_HOOK_SLOTS: [GuardSlot; 2] = [GuardSlot::CodeSemantic, GuardSlot::ApiCallees];

/// Schema tag for the advisory signal payload.
pub const ADVISORY_HOOK_SCHEMA: &str = "astro.guard.advisory_hook.v1";

/// The advisory signal produced by a completed quick check: the per-slot outcomes
/// on the two advisory slots and whether any fell below its calibrated tau.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvisorySignal {
    pub schema: &'static str,
    pub slots: Vec<SlotVerdict>,
    /// `true` when at least one advisory slot is below tau (a soft heads-up, not
    /// a block).
    pub any_below: bool,
    pub note: &'static str,
}

impl AdvisorySignal {
    fn from_slots(slots: Vec<SlotVerdict>) -> Self {
        let any_below = slots.iter().any(|sv| !sv.pass());
        Self {
            schema: ADVISORY_HOOK_SCHEMA,
            slots,
            any_below,
            note: "advisory only; never blocks the agent flow",
        }
    }
}

/// The outcome of the advisory hook: either an advisory signal computed within
/// the budget, or a labeled/counted silent skip because the budget elapsed or the
/// quick check faulted. **Never a blocking verdict.**
#[derive(Debug, Clone, PartialEq)]
pub enum AdvisoryOutcome {
    /// The quick check completed within the budget.
    Advisory(AdvisorySignal),
    /// The budget elapsed before the check finished: silent, counted skip.
    SilentTimeout { budget_ms: u64, elapsed_ms: u64 },
    /// The quick check faulted (e.g. a degenerate vector): silent, counted skip
    /// carrying the deficit code for observability. Still never blocks.
    SilentError { code: String },
}

impl AdvisoryOutcome {
    /// Whether this outcome carries an advisory signal.
    pub fn is_advisory(&self) -> bool {
        matches!(self, AdvisoryOutcome::Advisory(_))
    }

    /// Whether this outcome is a (labeled, counted) silent skip.
    pub fn is_silent(&self) -> bool {
        !self.is_advisory()
    }
}

/// Score the two advisory slots of a measured candidate against its region and
/// the profile's calibrated taus. This is the pure, owned quick check the hook
/// runs on its worker thread; it takes ownership of its inputs so it is
/// `'static`-safe to move onto a thread.
///
/// Resolves the region internally (kernel-near first) and scores only
/// [`ADVISORY_HOOK_SLOTS`]. Fails closed on a missing slot / degenerate vector.
pub fn quick_signal_owned(
    candidate: MeasuredSymbol,
    profile: GuardProfile,
    exemplars: Vec<Exemplar>,
) -> Result<AdvisorySignal, CalibrationError> {
    let region = resolve_region(&exemplars)?;
    quick_signal(&candidate, &profile, &region)
}

/// Score the two advisory slots of a measured candidate against a resolved region.
pub fn quick_signal(
    candidate: &MeasuredSymbol,
    profile: &GuardProfile,
    region: &ComparisonRegion<'_>,
) -> Result<AdvisorySignal, CalibrationError> {
    let mut slots = Vec::with_capacity(ADVISORY_HOOK_SLOTS.len());
    for slot in ADVISORY_HOOK_SLOTS {
        let Some(calibration) = profile.slot(slot) else {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_HOOK_PROFILE_SLOT_MISSING",
                format!("advisory profile is missing slot `{}`", slot.as_str()),
                "Recalibrate the domain profile so the advisory slots have a tau.",
            ));
        };
        let Some(candidate_slot) = candidate.slot(slot) else {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_HOOK_SLOT_MISSING",
                format!("candidate is missing advisory slot `{}`", slot.as_str()),
                "Measure the advisory slots before the quick check.",
            ));
        };
        let mut best = f32::NEG_INFINITY;
        for exemplar in &region.exemplars {
            let Some(exemplar_slot) = exemplar.measured.slot(slot) else {
                return Err(CalibrationError::new(
                    "ASTRO_GUARD_HOOK_EXEMPLAR_SLOT_MISSING",
                    format!(
                        "exemplar {} missing advisory slot `{}`",
                        exemplar.cx_id_hex,
                        slot.as_str()
                    ),
                    "Measure exemplars on the advisory slots.",
                ));
            };
            let cos = cosine(&candidate_slot.unit, &exemplar_slot.unit)?;
            if cos > best {
                best = cos;
            }
        }
        slots.push(SlotVerdict {
            slot,
            cos: best,
            tau: calibration.tau,
        });
    }
    Ok(AdvisorySignal::from_slots(slots))
}

/// Deficit code: a per-call advisory-hook `budget_ms` override that would
/// **widen** the deadline beyond the registry-declared product cadence is
/// refused. Only tightening (a shorter-or-equal deadline) is permitted (#368).
pub const ASTRO_GUARD_HOOK_BUDGET_WIDENED: &str = "ASTRO_GUARD_HOOK_BUDGET_WIDENED";

/// Govern a per-call advisory-hook `budget_ms` override: **tightening-only**
/// (`min(call, knob)` semantics, #368). The advisory hook's whole contract is that
/// the agent-facing wait is bounded by the registry-declared product cadence
/// ([`ADVISORY_HOOK_BUDGET_MS`]); an ungoverned override that *widens* the deadline
/// defeats that bound, so it is refused fail-closed rather than silently honored.
/// A shorter deadline (down to and including `0`, the extreme "never wait, always
/// go silent" tightening) only makes the hook faster to yield, so it is always
/// permitted.
///
/// - `None` → the registry-declared default budget.
/// - `Some(ms)` with `ms <= default` → the tightened budget `ms` (OK, incl. `0`).
/// - `Some(ms)` with `ms > default` → refuse ([`ASTRO_GUARD_HOOK_BUDGET_WIDENED`]).
pub fn governed_advisory_budget_ms(override_ms: Option<u64>) -> Result<u64, CalibrationError> {
    match override_ms {
        None => Ok(ADVISORY_HOOK_BUDGET_MS),
        Some(ms) if ms <= ADVISORY_HOOK_BUDGET_MS => Ok(ms),
        Some(ms) => Err(CalibrationError::new_owned(
            ASTRO_GUARD_HOOK_BUDGET_WIDENED,
            format!(
                "advisory-hook budget_ms override {ms} widens the deadline beyond the \
                 registry-declared {ADVISORY_HOOK_BUDGET_MS}ms product cadence; the advisory hook \
                 permits tightening (<= {ADVISORY_HOOK_BUDGET_MS}ms) only"
            ),
            "Pass a budget_ms <= the registry default to tighten the deadline, or omit it to use \
             the default. Widening the advisory wait past the product cadence is refused.",
        )),
    }
}

/// Run an advisory quick check under the registry-declared budget
/// ([`ADVISORY_HOOK_BUDGET_MS`]). The agent-facing wait is bounded by the budget:
/// on timeout the caller returns [`AdvisoryOutcome::SilentTimeout`] and does not
/// wait for the worker. See [`run_advisory_hook_with_budget`].
pub fn run_advisory_hook<F>(quick: F) -> AdvisoryOutcome
where
    F: FnOnce() -> Result<AdvisorySignal, CalibrationError> + Send + 'static,
{
    run_advisory_hook_with_budget(ADVISORY_HOOK_BUDGET_MS, quick)
}

/// Budget-parameterized advisory hook runner. Runs `quick` on a worker thread and
/// waits at most `budget_ms` on the caller. Returns:
/// - [`AdvisoryOutcome::Advisory`] if the check completed in time,
/// - [`AdvisoryOutcome::SilentError`] if it faulted (still never blocks),
/// - [`AdvisoryOutcome::SilentTimeout`] if the budget elapsed first.
///
/// On timeout the worker thread is detached (not joined), so the caller's wall
/// clock is bounded by `budget_ms` regardless of how slow the check is — the
/// agent flow is never blocked past the budget.
pub fn run_advisory_hook_with_budget<F>(budget_ms: u64, quick: F) -> AdvisoryOutcome
where
    F: FnOnce() -> Result<AdvisorySignal, CalibrationError> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    // Detached worker: if it outlives the budget we never join it, so a slow
    // check cannot stall the caller. A send on a dropped receiver is ignored.
    std::thread::spawn(move || {
        let _ = tx.send(quick());
    });
    let start = Instant::now();
    match rx.recv_timeout(Duration::from_millis(budget_ms)) {
        Ok(Ok(signal)) => AdvisoryOutcome::Advisory(signal),
        Ok(Err(error)) => AdvisoryOutcome::SilentError {
            code: error.code().to_string(),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => AdvisoryOutcome::SilentTimeout {
            budget_ms,
            elapsed_ms: start.elapsed().as_millis() as u64,
        },
        Err(mpsc::RecvTimeoutError::Disconnected) => AdvisoryOutcome::SilentError {
            code: "ASTRO_GUARD_HOOK_WORKER_LOST".to_string(),
        },
    }
}
