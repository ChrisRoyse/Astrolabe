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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibration::{CalibrationDomain, CalibrationLanguage};
    use crate::check::{SlotFeature, SymbolSlotInput, measure_symbol_slots};
    use crate::profile::{SlotCalibration, default_content_policy};

    fn domain() -> CalibrationDomain {
        CalibrationDomain::new(CalibrationLanguage::Rust, "core").expect("valid domain")
    }

    fn symbol_input(seed: f32, dim: usize) -> SymbolSlotInput {
        let slots = GuardSlot::ALL
            .iter()
            .enumerate()
            .map(|(ordinal, slot)| {
                let vector: Vec<f32> = (0..dim)
                    .map(|i| (seed * (i as f32 + 1.0) + ordinal as f32 * 0.001).sin())
                    .collect();
                SlotFeature {
                    slot: *slot,
                    vector,
                }
            })
            .collect();
        SymbolSlotInput { slots }
    }

    fn measured(seed: f32, dim: usize) -> MeasuredSymbol {
        measure_symbol_slots(&symbol_input(seed, dim)).expect("measures")
    }

    fn exemplar(seed: f32, dim: usize) -> Exemplar {
        Exemplar {
            cx_id_hex: "cx:kernel".to_string(),
            kernel_near: true,
            measured: measured(seed, dim),
        }
    }

    fn profile_with_tau(tau: f32) -> GuardProfile {
        let slots: Vec<SlotCalibration> = GuardSlot::ALL
            .iter()
            .map(|slot| {
                let mut cal = SlotCalibration::cold_start(*slot);
                cal.tau = tau;
                cal.provisional = false;
                cal
            })
            .collect();
        GuardProfile {
            domain: domain(),
            slots,
            content_policy: default_content_policy(),
            provisional: false,
            corpus_hash: [0u8; 32],
            calibrated_ledger_seq: Some(1),
        }
    }

    #[test]
    fn quick_signal_scores_only_the_two_advisory_slots() {
        let candidate = measured(0.5, 16);
        let profile = profile_with_tau(0.8);
        let exemplars = vec![exemplar(0.5, 16)];
        let region = resolve_region(&exemplars).unwrap();
        let signal = quick_signal(&candidate, &profile, &region).unwrap();
        assert_eq!(signal.slots.len(), 2, "only S18 + S4 are scored");
        let scored: Vec<GuardSlot> = signal.slots.iter().map(|sv| sv.slot).collect();
        assert!(scored.contains(&GuardSlot::CodeSemantic));
        assert!(scored.contains(&GuardSlot::ApiCallees));
        // Candidate == exemplar => cosine ~1.0 >= 0.8 => not below.
        assert!(!signal.any_below);
    }

    // -- DoD #4: hook completes or goes silent within budget, never blocks ----

    #[test]
    fn advisory_hook_completes_within_budget_when_fast() {
        let candidate = measured(0.5, 16);
        let profile = profile_with_tau(0.8);
        let exemplars = vec![exemplar(0.5, 16)];
        let start = Instant::now();
        let outcome = run_advisory_hook_with_budget(ADVISORY_HOOK_BUDGET_MS, move || {
            quick_signal_owned(candidate, profile, exemplars)
        });
        let elapsed = start.elapsed();
        assert!(outcome.is_advisory(), "a fast check returns an advisory");
        assert!(
            elapsed < Duration::from_millis(ADVISORY_HOOK_BUDGET_MS),
            "a fast check returns well within the budget ({elapsed:?})"
        );
    }

    #[test]
    fn advisory_hook_goes_silent_within_budget_under_injected_slowness() {
        // Inject slowness far beyond the budget: the worker sleeps 4x the budget.
        // The caller must return a silent timeout at ~budget, never blocking for
        // the full slow duration — the agent flow is bounded by the budget.
        let candidate = measured(0.5, 16);
        let profile = profile_with_tau(0.8);
        let exemplars = vec![exemplar(0.5, 16)];
        let budget = ADVISORY_HOOK_BUDGET_MS;
        let slow = Duration::from_millis(budget * 4);

        let start = Instant::now();
        let outcome = run_advisory_hook_with_budget(budget, move || {
            std::thread::sleep(slow);
            quick_signal_owned(candidate, profile, exemplars)
        });
        let elapsed = start.elapsed();

        // Silent, labeled, counted — never a blocking verdict.
        assert!(outcome.is_silent(), "an over-budget check goes silent");
        match outcome {
            AdvisoryOutcome::SilentTimeout { budget_ms, .. } => {
                assert_eq!(budget_ms, budget);
            }
            other => panic!("expected SilentTimeout, got {other:?}"),
        }
        // The agent-facing wait is bounded by the budget (plus scheduling slack),
        // NOT the full 4x-budget slow duration. This is the never-blocks proof.
        assert!(
            elapsed < slow,
            "caller returned at ~budget ({elapsed:?}), not the full slow duration ({slow:?})"
        );
        assert!(
            elapsed < Duration::from_millis(budget * 3),
            "caller wait {elapsed:?} must be bounded near the budget, not the injected slowness"
        );
    }

    #[test]
    fn advisory_hook_is_silent_on_fault_never_blocks() {
        // Drop an advisory slot from the candidate to force the scoring-time
        // fault path: the hook goes silent with the deficit code rather than
        // surfacing a block.
        let mut candidate = measured(0.5, 16);
        candidate.slots.retain(|s| s.slot != GuardSlot::ApiCallees);
        let profile = profile_with_tau(0.8);
        let exemplars = vec![exemplar(0.5, 16)];
        let outcome = run_advisory_hook_with_budget(ADVISORY_HOOK_BUDGET_MS, move || {
            quick_signal_owned(candidate, profile, exemplars)
        });
        assert!(outcome.is_silent());
        assert!(
            matches!(outcome, AdvisoryOutcome::SilentError { .. }),
            "a faulted quick check is a silent error, never a block"
        );
    }
}
