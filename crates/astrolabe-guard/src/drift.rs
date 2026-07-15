//! Guard drift monitoring (P7.4, blueprint `10_GUARD.md` §4, capability 6.9).
//!
//! Each `guard_check` produces a per-slot pass/fail. This module tracks a
//! **rolling per-slot rejection rate** over the most recent
//! [`DRIFT_REJECTION_WINDOW`] outcomes and compares it to the slot's calibrated
//! `drift_bound` (`DRIFT_ALARM_MULTIPLIER × achieved_far`, the registry-declared
//! 1.5× multiplier). When the rolling rejection rate crosses **above** the bound
//! the domain distribution has shifted and recalibration is due, so the monitor
//! emits a [`DriftProposal`] — a recalibration proposal for the Anneal hook
//! (lands P8) and the `optimizer_status` / `get_readiness` surfaces.
//!
//! The proposal fires **exactly once per window crossing** (hysteresis): once
//! above the bound the monitor is latched and will not re-fire until the rate
//! falls back to/below the bound and crosses again. This makes the drift-event
//! stream a stream of genuine transitions, not one event per sample while
//! elevated.
//!
//! # No silent fallback / registry knobs
//!
//! The window and multiplier are registry-declared knobs
//! ([`DRIFT_REJECTION_WINDOW`], [`DRIFT_ALARM_MULTIPLIER`]); the drift bound is a
//! measured value carried on the calibration. The monitor never invents a
//! threshold.

use std::collections::VecDeque;

use crate::check::CheckReport;
use crate::profile::{
    DRIFT_ALARM_MULTIPLIER, DRIFT_REJECTION_WINDOW, GUARD_PROFILE_KNOB_REGISTRY_VERSION,
    GuardProfile, GuardSlot, SlotCalibration,
};

/// Schema tag for a canonical drift recalibration proposal (ledgered / surfaced
/// on `optimizer_status`).
pub const DRIFT_PROPOSAL_SCHEMA: &str = "astro.guard.drift_proposal.v1";

/// A recalibration proposal emitted when a slot's rolling rejection rate crosses
/// above its calibrated drift bound.
#[derive(Debug, Clone, PartialEq)]
pub struct DriftProposal {
    pub schema: &'static str,
    pub knob_registry: &'static str,
    pub slot: GuardSlot,
    /// The rolling window size the rate was measured over.
    pub window: usize,
    /// Number of samples currently in the window (may be < `window` early on).
    pub sample_count: usize,
    /// The rolling rejection rate that triggered the crossing.
    pub rejection_rate: f32,
    /// The calibrated drift bound (`DRIFT_ALARM_MULTIPLIER × calibrated_far`).
    pub drift_bound: f32,
    /// The slot's calibrated achieved FAR (the drift bound's basis).
    pub calibrated_far: f32,
    /// The proposed action.
    pub proposal: &'static str,
}

impl DriftProposal {
    /// Canonical UTF-8 JSON bytes (stable key order, finite floats) so the server
    /// can hash it and read it back byte-for-byte from `optimizer_status`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{{\"schema\":\"{}\",\"knob_registry\":\"{}\",\"slot\":\"{}\",\"panel_source\":\"{}\",\
             \"window\":{},\"sample_count\":{},\"rejection_rate\":{},\"drift_bound\":{},\
             \"calibrated_far\":{},\"proposal\":\"{}\"}}",
            DRIFT_PROPOSAL_SCHEMA,
            self.knob_registry,
            self.slot.as_str(),
            self.slot.panel_source(),
            self.window,
            self.sample_count,
            json_f32(self.rejection_rate),
            json_f32(self.drift_bound),
            json_f32(self.calibrated_far),
            self.proposal,
        )
        .into_bytes()
    }
}

/// A rolling rejection-rate drift monitor for one guard slot.
#[derive(Debug, Clone)]
pub struct SlotDriftMonitor {
    slot: GuardSlot,
    window: usize,
    drift_bound: f32,
    calibrated_far: f32,
    /// Most-recent outcomes (true = rejection); front is oldest.
    samples: VecDeque<bool>,
    rejections: usize,
    /// Hysteresis latch: `true` once the rate is above the bound, cleared when it
    /// returns to/below the bound. Prevents re-firing while elevated.
    above: bool,
}

impl SlotDriftMonitor {
    /// A monitor for `slot` with an explicit calibrated FAR and window. The drift
    /// bound is `DRIFT_ALARM_MULTIPLIER × calibrated_far` (the registry knob).
    pub fn new(slot: GuardSlot, calibrated_far: f32, window: usize) -> Self {
        let window = window.max(1);
        Self {
            slot,
            window,
            drift_bound: DRIFT_ALARM_MULTIPLIER * calibrated_far,
            calibrated_far,
            samples: VecDeque::with_capacity(window),
            rejections: 0,
            above: false,
        }
    }

    /// A monitor built from a slot's calibration, using its measured `drift_bound`
    /// and `achieved_far` and the registry-declared window.
    pub fn from_calibration(calibration: &SlotCalibration, window: usize) -> Self {
        let window = window.max(1);
        Self {
            slot: calibration.slot,
            window,
            drift_bound: calibration.drift_bound,
            calibrated_far: calibration.achieved_far,
            samples: VecDeque::with_capacity(window),
            rejections: 0,
            above: false,
        }
    }

    /// The guard slot this monitor tracks.
    pub fn slot(&self) -> GuardSlot {
        self.slot
    }

    /// The current rolling rejection rate (rejections / samples in window).
    pub fn rejection_rate(&self) -> f32 {
        if self.samples.is_empty() {
            0.0
        } else {
            self.rejections as f32 / self.samples.len() as f32
        }
    }

    /// Whether the monitor is currently latched above its drift bound.
    pub fn is_above(&self) -> bool {
        self.above
    }

    /// Number of samples currently in the rolling window.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// The calibrated drift bound (`multiplier × calibrated_far`).
    pub fn drift_bound(&self) -> f32 {
        self.drift_bound
    }

    /// Record one per-slot outcome (`rejected = true` when the slot failed its
    /// calibrated tau). Returns a [`DriftProposal`] **only on the crossing** from
    /// at/below the bound to above it — exactly once per window crossing.
    ///
    /// The monitor stays silent until the rolling window is **full** (it has seen
    /// `window` outcomes): a rolling rejection rate over a thin, partially-filled
    /// window is not evidence of drift, and firing on the first rejection would be
    /// a false alarm. Once full it evaluates every outcome.
    pub fn observe(&mut self, rejected: bool) -> Option<DriftProposal> {
        if self.samples.len() == self.window
            && let Some(oldest) = self.samples.pop_front()
            && oldest
        {
            self.rejections -= 1;
        }
        self.samples.push_back(rejected);
        if rejected {
            self.rejections += 1;
        }

        // Not enough evidence yet: never judge drift on a partial window.
        if self.samples.len() < self.window {
            return None;
        }

        let rate = self.rejection_rate();
        if rate > self.drift_bound {
            if self.above {
                // Already latched above the bound: no re-fire.
                None
            } else {
                self.above = true;
                Some(DriftProposal {
                    schema: DRIFT_PROPOSAL_SCHEMA,
                    knob_registry: GUARD_PROFILE_KNOB_REGISTRY_VERSION,
                    slot: self.slot,
                    window: self.window,
                    sample_count: self.samples.len(),
                    rejection_rate: rate,
                    drift_bound: self.drift_bound,
                    calibrated_far: self.calibrated_far,
                    proposal: "recalibrate",
                })
            }
        } else {
            // Back at/below the bound: clear the latch so a later crossing fires.
            self.above = false;
            None
        }
    }
}

/// A serializable snapshot of a [`SlotDriftMonitor`] — the persisted image the
/// server round-trips so the rolling window **and its hysteresis latch** survive
/// across `guard_check` calls (each check is a separate process/request). The slot
/// is stored by its stable str key ([`GuardSlot::as_str`]); restoring an unknown
/// key fails closed (`from_snapshot` returns `None`) rather than inventing a slot.
///
/// This is a plain data image (public fields, no `serde` — the crate's non-test
/// code is serde-free by convention; see [`crate::profile`] / [`crate::lock`]).
/// The JSON persistence mapping lives in the server layer, which owns `serde_json`.
#[derive(Debug, Clone, PartialEq)]
pub struct SlotDriftSnapshot {
    /// Stable slot key.
    pub slot: String,
    /// Rolling window size.
    pub window: usize,
    /// Calibrated drift bound (`multiplier x calibrated_far`).
    pub drift_bound: f32,
    /// The slot's calibrated achieved FAR (the drift bound's basis).
    pub calibrated_far: f32,
    /// Most-recent outcomes (true = rejection); front is oldest.
    pub samples: Vec<bool>,
    /// Hysteresis latch state (whether currently latched above the bound).
    pub above: bool,
}

impl SlotDriftMonitor {
    /// A serializable snapshot of the monitor's full state (window + latch).
    pub fn snapshot(&self) -> SlotDriftSnapshot {
        SlotDriftSnapshot {
            slot: self.slot.as_str().to_string(),
            window: self.window,
            drift_bound: self.drift_bound,
            calibrated_far: self.calibrated_far,
            samples: self.samples.iter().copied().collect(),
            above: self.above,
        }
    }

    /// Rebuild a monitor from a snapshot. Returns `None` for an unknown slot key so
    /// a corrupt/incompatible persisted image fails closed rather than restoring a
    /// bogus monitor. The rejection count is recomputed from the samples so it is
    /// always consistent with the restored window.
    pub fn from_snapshot(snapshot: &SlotDriftSnapshot) -> Option<Self> {
        let slot = GuardSlot::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == snapshot.slot)?;
        let window = snapshot.window.max(1);
        let samples: VecDeque<bool> = snapshot.samples.iter().copied().collect();
        let rejections = samples.iter().filter(|&&rejected| rejected).count();
        Some(Self {
            slot,
            window,
            drift_bound: snapshot.drift_bound,
            calibrated_far: snapshot.calibrated_far,
            samples,
            rejections,
            above: snapshot.above,
        })
    }
}

/// A whole-profile drift monitor: one [`SlotDriftMonitor`] per guard slot for a
/// domain. Feeds a stream of [`guard_check`](crate::check::check_candidate)
/// reports and yields the recalibration proposals as slots cross their bounds.
#[derive(Debug, Clone)]
pub struct ProfileDriftMonitor {
    monitors: Vec<SlotDriftMonitor>,
}

impl ProfileDriftMonitor {
    /// Build a per-slot monitor set from a calibrated profile, using the
    /// registry-declared [`DRIFT_REJECTION_WINDOW`].
    pub fn from_profile(profile: &GuardProfile) -> Self {
        Self::from_profile_with_window(profile, DRIFT_REJECTION_WINDOW)
    }

    /// Build a per-slot monitor set with an explicit window (used by tests to
    /// exercise crossings without feeding 500 samples).
    pub fn from_profile_with_window(profile: &GuardProfile, window: usize) -> Self {
        let monitors = profile
            .slots
            .iter()
            .map(|calibration| SlotDriftMonitor::from_calibration(calibration, window))
            .collect();
        Self { monitors }
    }

    /// The monitor for `slot`, if present.
    pub fn monitor(&self, slot: GuardSlot) -> Option<&SlotDriftMonitor> {
        self.monitors.iter().find(|m| m.slot() == slot)
    }

    /// Record one slot outcome, returning a proposal on a fresh crossing.
    pub fn observe_slot(&mut self, slot: GuardSlot, rejected: bool) -> Option<DriftProposal> {
        self.monitors
            .iter_mut()
            .find(|m| m.slot() == slot)
            .and_then(|m| m.observe(rejected))
    }

    /// Serializable snapshots for every slot monitor (the persisted image).
    pub fn snapshots(&self) -> Vec<SlotDriftSnapshot> {
        self.monitors
            .iter()
            .map(SlotDriftMonitor::snapshot)
            .collect()
    }

    /// Rebuild a profile monitor from per-slot snapshots. Snapshots with an unknown
    /// slot key are dropped (fail-closed on that slot); the rest restore exactly.
    pub fn from_snapshots(snapshots: &[SlotDriftSnapshot]) -> Self {
        let monitors = snapshots
            .iter()
            .filter_map(SlotDriftMonitor::from_snapshot)
            .collect();
        Self { monitors }
    }

    /// Feed a whole `guard_check` report: each slot's `!pass()` is one outcome.
    /// Returns every fresh-crossing proposal produced by this report.
    pub fn observe_report(&mut self, report: &CheckReport) -> Vec<DriftProposal> {
        let mut proposals = Vec::new();
        for slot_verdict in &report.combined.per_slot {
            if let Some(proposal) = self.observe_slot(slot_verdict.slot, !slot_verdict.pass()) {
                proposals.push(proposal);
            }
        }
        proposals
    }
}

/// Emit an `f32` as a finite JSON number (never `NaN`/`Infinity`).
fn json_f32(value: f32) -> String {
    if value.is_nan() {
        "0".to_string()
    } else if value.is_infinite() {
        if value > 0.0 {
            "1e38".to_string()
        } else {
            "-1e38".to_string()
        }
    } else {
        let text = format!("{value}");
        if text.contains('.') || text.contains('e') || text.contains('E') {
            text
        } else {
            format!("{text}.0")
        }
    }
}
