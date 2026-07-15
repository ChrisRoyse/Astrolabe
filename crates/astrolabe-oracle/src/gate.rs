//! The honesty gate and the oracle failure-mode catalog (issue #52, blueprint
//! `11_ORACLE.md` §7 capability 7.3, `15_MCP_SURFACE.md` §1).
//!
//! The oracle's product property is that it *never emits an ungated confident
//! answer*. This module is the single enforcement point for HONEST invariants 1
//! and 2:
//!
//! * **No unlabeled claim (invariant 1).** Every served confidence is carried by
//!   [`GatedConfidence`], a type whose only constructor refuses — fail-closed —
//!   any value that is not accompanied by a ceiling strictly below `1.0` and a
//!   [`TrustTag`]. A bare `f64` confidence is unrepresentable on the served
//!   surface, so "no unlabeled claim" is a type-level guarantee where possible.
//! * **No ungated confidence (invariant 2).** When a prediction cannot be
//!   grounded — the panel carries fewer bits than the outcome entropy, the
//!   evidence contradicts itself, the outcome never recurred, or grounded mode
//!   has not beaten the structural baseline — [`honesty_gate`] refuses with a
//!   structured [`GateRefusal`] naming the deficit and a concrete bootstrap
//!   command, rather than guessing.
//!
//! ## Failure-mode catalog
//!
//! The refusal reasons are a catalog of [`FailureMode`] entries — *structured
//! data with detection predicates*, never free prose. Each entry pairs a stable
//! `ASTRO_ORACLE_*` code with a pure detection predicate over an
//! [`EvidenceSnapshot`] and the degraded mode it drops to. [`honesty_gate`]
//! evaluates the catalog in declared precedence order and returns the first
//! firing mode's refusal.

use astrolabe_assay::{DeficitSuggestedAction, SufficiencyCard};
use astrolabe_domain::TrustTag;
use astrolabe_domain::knobs::U64KnobDeclaration;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::corpus::{OccurrenceRecord, OracleError};

// ---------------------------------------------------------------------------
// Stable failure codes (the oracle failure-mode catalog)
// ---------------------------------------------------------------------------

/// The panel carries fewer grounded bits than the outcome entropy (or the seed
/// has fewer grounded occurrences than the floor): there is not enough evidence
/// to ground a claim, so the oracle refuses with a per-lens deficit.
pub const ASTRO_ORACLE_INSUFFICIENT: &str = "ASTRO_ORACLE_INSUFFICIENT";
/// The failing outcome was observed on too few distinct changes to be a pattern:
/// a one-off is not a recurrence, so no grounded probability is served.
pub const ASTRO_ORACLE_NO_RECURRENCE: &str = "ASTRO_ORACLE_NO_RECURRENCE";
/// The grounded evidence contradicts itself (pairwise outcome agreement below the
/// flakiness floor): a flaky signal cannot ground a confident claim.
pub const ASTRO_ORACLE_FLAKY_EVIDENCE: &str = "ASTRO_ORACLE_FLAKY_EVIDENCE";
/// Grounded mode did not beat the structural (hop-distance) baseline on the
/// backtest, so grounded confidence is disabled and only the structural view is
/// offered (a labeled degradation, not silent).
pub const ASTRO_ORACLE_BACKTEST_NOT_BEATEN: &str = "ASTRO_ORACLE_BACKTEST_NOT_BEATEN";
/// A served confidence was constructed without the ceiling metadata + trust tag
/// HONEST invariant 1 requires (ceiling `≥ 1.0`, a non-finite value, or a value
/// above its ceiling): an ungated confidence is refused fail-closed.
pub const ASTRO_ORACLE_UNGATED_CONFIDENCE: &str = "ASTRO_ORACLE_UNGATED_CONFIDENCE";

const GATE_REMEDIATION: &str = "ground this module before asking the oracle to speak: record real outcomes with \
     anchor_outcome (ingest_outcome_anchors), re-mine the change→outcome corpus with mine_corpus, \
     and re-measure panel sufficiency with the assay bits pipeline";

// ---------------------------------------------------------------------------
// Registry-declared gate knobs (standing invariant 4)
// ---------------------------------------------------------------------------

/// Registry version tag for the honesty-gate knobs (#52).
pub const ORACLE_GATE_KNOB_REGISTRY_VERSION: &str = "astrolabe-oracle-gate-knobs-v1";

/// Name of the minimum grounded-occurrence floor knob (occurrences).
pub const ORACLE_GATE_MIN_GROUNDED_OCCURRENCES_KNOB: &str = "oracle_gate_min_grounded_occurrences";
/// Name of the recurrence floor knob (distinct failing changes).
pub const ORACLE_GATE_RECURRENCE_FLOOR_KNOB: &str = "oracle_gate_recurrence_floor";
/// Name of the flaky-evidence self-consistency floor knob (permille).
pub const ORACLE_GATE_FLAKY_SELF_CONSISTENCY_PERMILLE_KNOB: &str =
    "oracle_gate_flaky_self_consistency_permille";

/// The honesty-gate knob registry (#52).
///
/// The grounded-occurrence floor mirrors the #49 corpus min-edge-support floor
/// (3) reused by `predict_impact`, so the gate and the predictor agree on when a
/// module has spoken enough to ground on. The recurrence floor (2 distinct
/// failing changes) is the smallest count that distinguishes a *pattern* from a
/// single incident. The flakiness floor (0.5 pairwise agreement) is the coin-flip
/// point below which the outcomes disagree more than they agree — a flaky signal.
/// Every default is a seed to be replaced by a measured value once refusal
/// precision is backtested per repo.
pub const ORACLE_GATE_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: ORACLE_GATE_KNOB_REGISTRY_VERSION,
        name: ORACLE_GATE_MIN_GROUNDED_OCCURRENCES_KNOB,
        default: 3,
        min: 1,
        max: 1_000_000,
        unit: "occurrences",
        source: "ASTROLABE #49 corpus min-edge-support floor (3), reused as the gate's grounded-speech floor",
        rationale: "the honesty gate refuses (ASTRO_ORACLE_INSUFFICIENT) unless a module carries at least this many grounded occurrences, matching the corpus edge-support floor and predict_impact's evidence floor so the gate and predictor agree; replace with a measured value once refusal precision is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_GATE_KNOB_REGISTRY_VERSION,
        name: ORACLE_GATE_RECURRENCE_FLOOR_KNOB,
        default: 2,
        min: 1,
        max: 1_000_000,
        unit: "changes",
        source: "ASTROLABE blueprint 11_ORACLE §7: a one-off outcome is not a recurring pattern",
        rationale: "the gate refuses (ASTRO_ORACLE_NO_RECURRENCE) when the failing outcome was seen on fewer than this many distinct changes; 2 is the smallest count that distinguishes a repeated pattern from a single incident, so the oracle never sells a coincidence as a trend; replace with a measured recurrence threshold once available",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_GATE_KNOB_REGISTRY_VERSION,
        name: ORACLE_GATE_FLAKY_SELF_CONSISTENCY_PERMILLE_KNOB,
        default: 500,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §5 oracle self-consistency (flakiness = pairwise outcome disagreement)",
        rationale: "the gate refuses (ASTRO_ORACLE_FLAKY_EVIDENCE) when pairwise outcome agreement falls below 0.5 (500 permille) — the coin-flip point below which the evidence disagrees with itself more than it agrees; capped below 1000 so a demand for perfect agreement can never be configured; replace with the blueprint's Beta-Bernoulli small-sample posterior once wired",
    },
];

/// Returns the gate knob declaration for `name`, or `None`.
pub fn oracle_gate_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ORACLE_GATE_KNOBS.iter().find(|knob| knob.name == name)
}

fn gate_knob(name: &str) -> &'static U64KnobDeclaration {
    oracle_gate_knob(name).expect("oracle gate knob is declared")
}

/// Validated honesty-gate policy (raw knob values; resolved through accessors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateConfig {
    /// Grounded occurrences a module must carry before the gate lets it speak.
    pub min_grounded_occurrences: u64,
    /// Distinct failing changes required before an outcome counts as recurring.
    pub recurrence_floor: u64,
    /// Pairwise self-consistency floor, in permille, below which evidence is flaky.
    pub flaky_self_consistency_permille: u64,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_grounded_occurrences: gate_knob(ORACLE_GATE_MIN_GROUNDED_OCCURRENCES_KNOB).default,
            recurrence_floor: gate_knob(ORACLE_GATE_RECURRENCE_FLOOR_KNOB).default,
            flaky_self_consistency_permille: gate_knob(
                ORACLE_GATE_FLAKY_SELF_CONSISTENCY_PERMILLE_KNOB,
            )
            .default,
        }
    }
}

impl GateConfig {
    /// Fails closed when any field is outside its declared knob bounds.
    pub fn validate(&self) -> Result<(), OracleError> {
        check_gate_knob(
            ORACLE_GATE_MIN_GROUNDED_OCCURRENCES_KNOB,
            self.min_grounded_occurrences,
        )?;
        check_gate_knob(ORACLE_GATE_RECURRENCE_FLOOR_KNOB, self.recurrence_floor)?;
        check_gate_knob(
            ORACLE_GATE_FLAKY_SELF_CONSISTENCY_PERMILLE_KNOB,
            self.flaky_self_consistency_permille,
        )?;
        Ok(())
    }

    fn flaky_self_consistency(&self) -> f64 {
        self.flaky_self_consistency_permille as f64 / 1000.0
    }
}

fn check_gate_knob(name: &str, value: u64) -> Result<(), OracleError> {
    let declared = gate_knob(name);
    if declared.accepts(value) {
        Ok(())
    } else {
        Err(OracleError {
            code: ASTRO_ORACLE_INSUFFICIENT,
            message: format!(
                "gate knob {name} value {value} is outside declared bounds [{}, {}]",
                declared.min, declared.max
            ),
            remediation: GATE_REMEDIATION,
        })
    }
}

// ---------------------------------------------------------------------------
// Evidence snapshot — the structured input every detection predicate reads
// ---------------------------------------------------------------------------

/// The structured evidence context a [`FailureMode`] detection predicate reads.
///
/// It is a *pure summary* of what grounding exists for one served claim: the
/// grounded-occurrence counts on the subject, how the failing outcomes are spread
/// across distinct changes (recurrence), the pairwise outcome agreement
/// (flakiness), the optional panel sufficiency card (`I(panel;axis)` vs
/// `H(axis)`), and the optional backtest verdict. Detection predicates read this
/// snapshot and nothing else, so a refusal is reproducible from the snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceSnapshot {
    /// Total grounded occurrences on the subject(s) under test.
    pub direct_occurrences: usize,
    /// Failing grounded occurrences.
    pub failing_occurrences: usize,
    /// Passing grounded occurrences.
    pub passing_occurrences: usize,
    /// Distinct changes that produced a *failing* outcome (recurrence spread).
    pub distinct_failing_changes: usize,
    /// Pairwise outcome agreement in `[0, 1]`; `1.0` when unmeasurable (< 2 obs).
    pub self_consistency: f64,
    /// The panel sufficiency card, when a panel measurement exists for this axis.
    pub sufficiency: Option<SufficiencyCard>,
    /// The backtest verdict (`Some(false)` = grounded did not beat the baseline).
    pub beats_baseline: Option<bool>,
}

impl EvidenceSnapshot {
    /// Summarizes the grounded occurrence records for one subject into a snapshot.
    ///
    /// `self_consistency` is the pairwise agreement `(C(f,2)+C(p,2))/C(n,2)`; with
    /// fewer than two occurrences flakiness is unmeasurable and it is held at
    /// `1.0` (the INSUFFICIENT mode fires first in that regime).
    pub fn from_records(records: &[OccurrenceRecord]) -> Self {
        let mut failing = 0usize;
        let mut passing = 0usize;
        let mut failing_changes: BTreeSet<&str> = BTreeSet::new();
        for record in records {
            if record.passed {
                passing += 1;
            } else {
                failing += 1;
                failing_changes.insert(record.change_id.as_str());
            }
        }
        let n = records.len();
        let pairs = choose2(n);
        let self_consistency = if pairs == 0 {
            1.0
        } else {
            (choose2(failing) + choose2(passing)) as f64 / pairs as f64
        };
        EvidenceSnapshot {
            direct_occurrences: n,
            failing_occurrences: failing,
            passing_occurrences: passing,
            distinct_failing_changes: failing_changes.len(),
            self_consistency,
            sufficiency: None,
            beats_baseline: None,
        }
    }

    /// Attaches a panel sufficiency card (the `panel_bits < H(axis)` measurement).
    pub fn with_sufficiency(mut self, card: SufficiencyCard) -> Self {
        self.sufficiency = Some(card);
        self
    }

    /// Attaches a backtest verdict.
    pub fn with_backtest(mut self, beats_baseline: bool) -> Self {
        self.beats_baseline = Some(beats_baseline);
        self
    }
}

fn choose2(k: usize) -> usize {
    k.saturating_mul(k.saturating_sub(1)) / 2
}

// ---------------------------------------------------------------------------
// Failure-mode catalog
// ---------------------------------------------------------------------------

/// The degraded mode a failing detection predicate drops the oracle to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradedMode {
    /// No answer can be served: the claim is withheld entirely.
    Refuse,
    /// Grounded confidence is disabled; the structural (topology) view is offered
    /// as a labeled, provisional degradation.
    OfferStructural,
}

/// One entry of the oracle failure-mode catalog: structured data plus a pure
/// detection predicate over an [`EvidenceSnapshot`].
///
/// The predicate is the machine-checkable definition of the failure mode; the
/// `summary`/`remediation` are the operator-facing text. Because the predicate is
/// a plain function of the snapshot, a refusal is reproducible and testable
/// (positive: the mode fires on planted-deficient evidence; negative: it does not
/// fire on grounded evidence).
pub struct FailureMode {
    /// Stable machine-readable failure code.
    pub code: &'static str,
    /// One-line operator-facing summary of the failure.
    pub summary: &'static str,
    /// Operator remediation.
    pub remediation: &'static str,
    /// The degraded mode this failure drops to.
    pub degraded_mode: DegradedMode,
    /// Pure detection predicate over the evidence snapshot.
    pub detect: fn(&EvidenceSnapshot, &GateConfig) -> bool,
}

fn detect_insufficient(snap: &EvidenceSnapshot, cfg: &GateConfig) -> bool {
    if snap.direct_occurrences < cfg.min_grounded_occurrences as usize {
        return true;
    }
    // A measured panel that does not clear H(axis) is insufficient regardless of
    // raw occurrence counts: it carries fewer bits than the outcome demands.
    matches!(&snap.sufficiency, Some(card) if !card.sufficient)
}

fn detect_flaky(snap: &EvidenceSnapshot, cfg: &GateConfig) -> bool {
    // Flakiness needs at least one pair; below the floor it is INSUFFICIENT, not
    // flaky, so this predicate is only reached with enough evidence to measure.
    snap.direct_occurrences >= 2 && snap.self_consistency < cfg.flaky_self_consistency()
}

fn detect_no_recurrence(snap: &EvidenceSnapshot, cfg: &GateConfig) -> bool {
    // There is a failing signal, but it was observed on too few distinct changes
    // to be a recurring pattern.
    snap.failing_occurrences > 0 && snap.distinct_failing_changes < cfg.recurrence_floor as usize
}

fn detect_backtest_not_beaten(snap: &EvidenceSnapshot, _cfg: &GateConfig) -> bool {
    matches!(snap.beats_baseline, Some(false))
}

/// The oracle failure-mode catalog, in detection precedence order.
///
/// Precedence matters: INSUFFICIENT (no evidence at all) is diagnosed before
/// FLAKY (evidence that contradicts itself), which is diagnosed before
/// NO_RECURRENCE (evidence too concentrated on one change), which is diagnosed
/// before BACKTEST_NOT_BEATEN (grounded mode not validated against the baseline).
/// The first mode whose predicate fires wins.
pub static ORACLE_FAILURE_MODES: &[FailureMode] = &[
    FailureMode {
        code: ASTRO_ORACLE_INSUFFICIENT,
        summary: "the panel carries fewer grounded bits than the outcome entropy; there is not enough evidence to ground a claim",
        remediation: GATE_REMEDIATION,
        degraded_mode: DegradedMode::Refuse,
        detect: detect_insufficient,
    },
    FailureMode {
        code: ASTRO_ORACLE_FLAKY_EVIDENCE,
        summary: "the grounded evidence contradicts itself (pairwise outcome agreement below the flakiness floor); a flaky signal cannot ground a confident claim",
        remediation: "stabilize the outcome source before grounding on it: quarantine or de-flake the failing test/CI signal, then re-mine the corpus so the evidence agrees with itself",
        degraded_mode: DegradedMode::Refuse,
        detect: detect_flaky,
    },
    FailureMode {
        code: ASTRO_ORACLE_NO_RECURRENCE,
        summary: "the failing outcome was observed on too few distinct changes to be a pattern; a one-off is not a recurrence",
        remediation: "wait for the outcome to recur across distinct changes, or lower oracle_gate_recurrence_floor deliberately; the oracle will not sell a single incident as a trend",
        degraded_mode: DegradedMode::Refuse,
        detect: detect_no_recurrence,
    },
    FailureMode {
        code: ASTRO_ORACLE_BACKTEST_NOT_BEATEN,
        summary: "grounded mode did not beat the structural hop-distance baseline on the backtest; grounded confidence is disabled and only the structural view is offered",
        remediation: "grounded prediction is offered in structural mode only until it beats the hop-distance baseline on >=2 of 3 backtest corpora; add grounded history and re-run the backtest gate",
        degraded_mode: DegradedMode::OfferStructural,
        detect: detect_backtest_not_beaten,
    },
];

/// Returns the catalog entry for `code`, or `None`.
pub fn oracle_failure_mode(code: &str) -> Option<&'static FailureMode> {
    ORACLE_FAILURE_MODES.iter().find(|mode| mode.code == code)
}

// ---------------------------------------------------------------------------
// Refusal payload
// ---------------------------------------------------------------------------

/// One lens's contribution to a gate refusal: what it has, what it needs, and the
/// concrete command that would close the gap (deficit actionability).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LensDeficit {
    /// The outcome axis the deficit was measured against.
    pub axis: String,
    /// The lens/slot (or evidence sensor) that is short.
    pub lens: String,
    /// Bits the lens currently carries about the axis.
    pub have_bits: f64,
    /// Bits the lens must carry before the gate opens.
    pub need_bits: f64,
    /// Information shortfall in bits (`need − have`, clamped at 0).
    pub missing_bits: f64,
    /// A concrete bootstrap command that would close this lens's deficit.
    pub bootstrap: String,
}

/// A structured, fail-closed gate refusal (HONEST invariant 2).
///
/// Serialize-only: the stable code/summary/remediation are `&'static str` borrows
/// of the catalog, so a refusal is emitted to the response envelope, never parsed
/// back into borrowed statics.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateRefusal {
    /// The catalog failure code that fired.
    pub code: &'static str,
    /// The operator-facing summary of the failure.
    pub summary: &'static str,
    /// The operator remediation.
    pub remediation: &'static str,
    /// The degraded mode the oracle drops to.
    pub degraded_mode: DegradedMode,
    /// Per-lens deficits, each naming the axis, the missing bits, and a command.
    pub deficits: Vec<LensDeficit>,
}

/// The verdict of the honesty gate for one served claim.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum GateVerdict {
    /// The panel is sufficient; the caller may serve grounded confidence.
    Grounded,
    /// The claim is refused; the payload names the deficit and remediation.
    Refused(GateRefusal),
}

impl GateVerdict {
    /// Whether the gate opened (grounded confidence may be served).
    pub fn is_grounded(&self) -> bool {
        matches!(self, GateVerdict::Grounded)
    }

    /// The refusal payload, when refused.
    pub fn refusal(&self) -> Option<&GateRefusal> {
        match self {
            GateVerdict::Refused(refusal) => Some(refusal),
            GateVerdict::Grounded => None,
        }
    }
}

/// Evaluates the honesty gate against an evidence snapshot.
///
/// Runs the failure-mode catalog in precedence order and returns the first firing
/// mode's [`GateRefusal`]; if none fire the panel is grounded. The refusal's
/// per-lens deficits are built from the panel sufficiency card when one is present
/// (naming each slot, its missing bits, and a routed bootstrap command), and from
/// the direct change-history sensor otherwise.
pub fn honesty_gate(
    snapshot: &EvidenceSnapshot,
    config: &GateConfig,
) -> Result<GateVerdict, OracleError> {
    config.validate()?;
    for mode in ORACLE_FAILURE_MODES {
        if (mode.detect)(snapshot, config) {
            let deficits = build_deficits(mode.code, snapshot, config);
            return Ok(GateVerdict::Refused(GateRefusal {
                code: mode.code,
                summary: mode.summary,
                remediation: mode.remediation,
                degraded_mode: mode.degraded_mode,
                deficits,
            }));
        }
    }
    Ok(GateVerdict::Grounded)
}

/// The evidence-sensor name used when a refusal has no panel card to itemize.
pub const ORACLE_GATE_SENSOR_DIRECT_CHANGE_HISTORY: &str = "direct_change_history";

fn build_deficits(
    code: &str,
    snapshot: &EvidenceSnapshot,
    config: &GateConfig,
) -> Vec<LensDeficit> {
    // Prefer an itemized per-lens breakdown from the panel sufficiency card.
    if code == ASTRO_ORACLE_INSUFFICIENT
        && let Some(card) = &snapshot.sufficiency
        && !card.sufficient
    {
        return card
            .deficits
            .iter()
            .map(|slot| {
                let missing = slot.deficit_bits.max(0.0);
                let bootstrap = bootstrap_command(&card.axis, &slot.slot, slot.action, missing);
                LensDeficit {
                    axis: card.axis.clone(),
                    lens: slot.slot.clone(),
                    have_bits: slot.marginal_bits,
                    need_bits: slot.marginal_bits + missing,
                    missing_bits: missing,
                    bootstrap,
                }
            })
            .collect();
    }

    // Otherwise itemize the direct change-history sensor in bits: the information
    // shortfall between the grounded occurrences the module has and the floor.
    let have = snapshot.direct_occurrences;
    let need = config.min_grounded_occurrences as usize;
    let have_bits = (have as f64 + 1.0).log2();
    let need_bits = (need as f64 + 1.0).log2();
    let missing_bits = (need_bits - have_bits).max(0.0);
    vec![LensDeficit {
        axis: "change_outcome".to_string(),
        lens: ORACLE_GATE_SENSOR_DIRECT_CHANGE_HISTORY.to_string(),
        have_bits,
        need_bits,
        missing_bits,
        bootstrap: format!(
            "anchor_outcome then mine_corpus: record {} more grounded outcome(s) on this module (have {have}, need {need}) so the change→outcome corpus can ground a prediction",
            need.saturating_sub(have)
        ),
    }]
}

/// Builds the concrete bootstrap command a per-slot deficit routes to.
fn bootstrap_command(
    axis: &str,
    slot: &str,
    action: DeficitSuggestedAction,
    missing_bits: f64,
) -> String {
    match action {
        DeficitSuggestedAction::IncreaseSamples => format!(
            "increase_samples axis={axis} slot={slot}: raise the sample above the measurement floor to close ~{missing_bits:.3} bits"
        ),
        DeficitSuggestedAction::ProposeLens => format!(
            "propose_lens axis={axis} slot={slot}: the existing lens carries no usable signal (~{missing_bits:.3} bits short); add a new lens"
        ),
        DeficitSuggestedAction::AddOutcomeAnchor => format!(
            "anchor_outcome axis={axis} slot={slot}: add grounded outcomes to close ~{missing_bits:.3} bits of the sufficiency deficit"
        ),
    }
}

// ---------------------------------------------------------------------------
// GatedConfidence — the type-level no-ungated-confidence guarantee
// ---------------------------------------------------------------------------

/// A served confidence that is, by construction, accompanied by its ceiling and a
/// trust tag (HONEST invariant 1: no unlabeled claim).
///
/// The fields are private and the only constructor, [`GatedConfidence::new`],
/// refuses fail-closed any value that is not gated: a non-finite value, a ceiling
/// that is not strictly below `1.0`, or a value above its ceiling. A bare `f64`
/// confidence therefore cannot appear on the served surface — "every served
/// confidence carries ceiling metadata and a trust tag" is a type invariant.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GatedConfidence {
    value: f64,
    ceiling: f64,
    trust: TrustTag,
}

impl GatedConfidence {
    /// Small tolerance so a value that equals its ceiling within float error is
    /// accepted; anything meaningfully above the ceiling is refused.
    const CEILING_EPSILON: f64 = 1e-9;

    /// Builds a gated confidence, refusing any ungated claim fail-closed.
    pub fn new(value: f64, ceiling: f64, trust: TrustTag) -> Result<Self, OracleError> {
        if !value.is_finite() || !ceiling.is_finite() {
            return Err(GatedConfidence::ungated(format!(
                "confidence value {value} or ceiling {ceiling} is not finite"
            )));
        }
        if ceiling >= 1.0 {
            return Err(GatedConfidence::ungated(format!(
                "confidence ceiling {ceiling} is not strictly below 1.0; no served claim may be certified certain"
            )));
        }
        if value < 0.0 {
            return Err(GatedConfidence::ungated(format!(
                "confidence value {value} is negative"
            )));
        }
        if value > ceiling + Self::CEILING_EPSILON {
            return Err(GatedConfidence::ungated(format!(
                "confidence value {value} exceeds its ceiling {ceiling}; the claim is ungated"
            )));
        }
        Ok(GatedConfidence {
            value,
            ceiling,
            trust,
        })
    }

    fn ungated(message: String) -> OracleError {
        OracleError {
            code: ASTRO_ORACLE_UNGATED_CONFIDENCE,
            message,
            remediation: "serve confidence only through GatedConfidence with a ceiling strictly below 1.0 and a trust tag; cap the value at its DPI/abundance ceiling",
        }
    }

    /// The gated confidence value.
    pub fn value(&self) -> f64 {
        self.value
    }

    /// The ceiling this value is gated below (always strictly `< 1.0`).
    pub fn ceiling(&self) -> f64 {
        self.ceiling
    }

    /// The trust tag accompanying the value.
    pub fn trust(&self) -> TrustTag {
        self.trust
    }
}

// ---------------------------------------------------------------------------
// Served-surface adapter for predict_impact
// ---------------------------------------------------------------------------

impl crate::predict::ImpactPrediction {
    /// Wraps every served consequence probability as a [`GatedConfidence`].
    ///
    /// This is the no-ungated-confidence adapter for the `predict_impact` surface:
    /// each consequence's `p` is re-served through the gated type with the config's
    /// [`served_ceiling`](crate::predict::PredictConfig::served_ceiling) (the hard
    /// DPI cap, `< 1.0`) and the consequence's own trust tag. It fails closed if
    /// any consequence somehow carries a value at or above the ceiling — which the
    /// walk's ceilings make impossible — so the guarantee is enforced, not assumed.
    pub fn gated_confidences(
        &self,
        config: &crate::predict::PredictConfig,
    ) -> Result<Vec<(calyx_core::CxId, GatedConfidence)>, OracleError> {
        let ceiling = config.served_ceiling();
        self.consequences
            .iter()
            .map(|c| GatedConfidence::new(c.p, ceiling, c.trust).map(|g| (c.target, g)))
            .collect()
    }
}

impl crate::predict::GroundedRisk {
    /// Wraps the served `detect_changes` risk as a [`GatedConfidence`].
    ///
    /// The no-ungated-confidence adapter for the risk surface: the risk value is
    /// re-served through the gated type with the risk's own ceiling (`< 1.0`) and
    /// trust tag, so a `detect_changes` risk can never be emitted as a bare number.
    pub fn gated(&self) -> Result<GatedConfidence, OracleError> {
        GatedConfidence::new(self.risk, self.ceiling, self.trust)
    }
}
