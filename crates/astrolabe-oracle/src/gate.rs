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
use calyx_core::{CxId, Ts};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::corpus::{
    ASTRO_ORACLE_ROW_CORRUPT, ORACLE_ATTRIBUTION_SCALE, OccurrenceRecord, OracleError, OutcomeId,
};

// ---------------------------------------------------------------------------
// Stable failure codes (the oracle failure-mode catalog)
// ---------------------------------------------------------------------------

/// The panel carries fewer grounded bits than the outcome entropy (or the seed
/// has fewer distinct grounded outcomes than the floor): there is not enough evidence
/// to ground a claim, so the oracle refuses with a per-lens deficit.
pub const ASTRO_ORACLE_INSUFFICIENT: &str = "ASTRO_ORACLE_INSUFFICIENT";
/// The failing signal was observed in too few distinct outcomes to be a pattern:
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
pub const ORACLE_GATE_KNOB_REGISTRY_VERSION: &str = "astrolabe-oracle-gate-knobs-v2";

/// Name of the minimum grounded-occurrence floor knob (distinct outcomes).
pub const ORACLE_GATE_MIN_GROUNDED_OCCURRENCES_KNOB: &str = "oracle_gate_min_grounded_occurrences";
/// Name of the recurrence floor knob (distinct failing outcomes).
pub const ORACLE_GATE_RECURRENCE_FLOOR_KNOB: &str = "oracle_gate_recurrence_floor";
/// Name of the flaky-evidence self-consistency floor knob (permille).
pub const ORACLE_GATE_FLAKY_SELF_CONSISTENCY_PERMILLE_KNOB: &str =
    "oracle_gate_flaky_self_consistency_permille";

/// The honesty-gate knob registry (#52).
///
/// The grounded-occurrence floor mirrors the #49 corpus min-edge-support floor
/// (3) reused by `predict_impact`, so the gate and the predictor agree on when a
/// module has spoken enough to ground on. The recurrence floor (2 distinct
/// failing outcomes) is the smallest count that distinguishes a *pattern* from a
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
        unit: "distinct_outcomes",
        source: "ASTROLABE #49 corpus distinct-outcome min-edge-support floor (3), reused as the gate's grounded-speech floor",
        rationale: "the honesty gate refuses (ASTRO_ORACLE_INSUFFICIENT) unless a module carries at least this many distinct source-backed outcomes; candidate-pair fan-out never increases the count, matching the corpus edge-support floor and predict_impact's evidence floor; replace with a measured value once refusal precision is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_GATE_KNOB_REGISTRY_VERSION,
        name: ORACLE_GATE_RECURRENCE_FLOOR_KNOB,
        default: 2,
        min: 1,
        max: 1_000_000,
        unit: "distinct_outcomes",
        source: "ASTROLABE blueprint 11_ORACLE §7: a one-off outcome is not a recurring pattern",
        rationale: "the gate refuses (ASTRO_ORACLE_NO_RECURRENCE) when there are fewer than this many distinct source-backed failing outcomes; candidate-pair fan-out never creates recurrence, and 2 is the smallest count that distinguishes a repeated pattern from a single incident; replace with a measured recurrence threshold once available",
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateConfig {
    /// Distinct grounded outcomes a module must carry before the gate lets it speak.
    pub min_grounded_occurrences: u64,
    /// Distinct failing outcomes required before a signal counts as recurring.
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
// Canonical distinct-outcome grouping shared by Oracle consumers
// ---------------------------------------------------------------------------

/// One complete, validated set of candidate rows for a single real outcome.
///
/// `OccurrenceRecord` is a candidate-pair row, not an independent observation.
/// Consumers must count this group once and may only use its candidate credits
/// after [`validated_outcome_groups`] proves that the group is complete and its
/// exact fixed-point credits sum to [`ORACLE_ATTRIBUTION_SCALE`].
pub(crate) struct ValidatedOutcomeGroup {
    pub(crate) outcome_id: OutcomeId,
    pub(crate) subject: CxId,
    pub(crate) outcome_subject: CxId,
    pub(crate) outcome_kind: calyx_core::AnchorKind,
    pub(crate) test_identity: Option<CxId>,
    pub(crate) source: String,
    pub(crate) change_id: String,
    pub(crate) change_ts: Ts,
    pub(crate) candidate_count: usize,
    pub(crate) outcome_ts: Ts,
    pub(crate) passed: bool,
    pub(crate) trust: TrustTag,
}

/// Validates and canonically groups candidate-pair rows by exact
/// `(changed subject, source-backed outcome)` identity in
/// `O(K log G + sum(k_g log k_g))`, bounded by
/// `O(K log K)` for `K` rows and `G` outcomes (PC-04/PC-16/PC-38).
///
/// The same exact source outcome may legitimately cover several subjects. Each
/// subject must retain a complete candidate partition whose credit sums to one;
/// no source identity is synthesized and no outcome is counted twice within a
/// subject. Duplicate, incomplete, or metadata-drifted groups refuse.
pub(crate) fn validated_outcome_groups(
    records: &[OccurrenceRecord],
) -> Result<Vec<ValidatedOutcomeGroup>, OracleError> {
    let mut groups: BTreeMap<(CxId, OutcomeId), Vec<&OccurrenceRecord>> = BTreeMap::new();
    let mut source_outcomes: BTreeMap<
        OutcomeId,
        (
            CxId,
            calyx_core::AnchorKind,
            Option<CxId>,
            String,
            u64,
            bool,
            astrolabe_anchors::TrustTag,
        ),
    > = BTreeMap::new();
    for record in records {
        validate_consumer_occurrence(record)?;
        let source_metadata = (
            record.outcome_subject,
            record.outcome_kind.clone(),
            record.test_identity,
            record.source.clone(),
            record.outcome_ts,
            record.passed,
            record.trust,
        );
        if let Some(previous) =
            source_outcomes.insert(record.outcome_id.clone(), source_metadata.clone())
            && previous != source_metadata
        {
            return Err(OracleError::new(
                ASTRO_ORACLE_ROW_CORRUPT,
                format!(
                    "source outcome {} carries inconsistent anchor/test/source/time/pass/trust metadata across attributed subjects",
                    record.outcome_id.as_str()
                ),
            ));
        }
        groups
            .entry((record.subject, record.outcome_id.clone()))
            .or_default()
            .push(record);
    }

    let mut validated = Vec::with_capacity(groups.len());
    for ((subject, outcome_id), mut candidates) in groups {
        candidates.sort_by(|a, b| {
            (a.lag_s, a.change_id.as_str(), a.change_ts).cmp(&(
                b.lag_s,
                b.change_id.as_str(),
                b.change_ts,
            ))
        });
        let first = candidates[0];
        if candidates.iter().any(|row| {
            row.subject != first.subject
                || row.source != first.source
                || row.outcome_subject != first.outcome_subject
                || row.outcome_kind != first.outcome_kind
                || row.test_identity != first.test_identity
                || row.outcome_ts != first.outcome_ts
                || row.passed != first.passed
                || row.candidate_count != first.candidate_count
                || row.trust != first.trust
        }) {
            return Err(OracleError::new(
                ASTRO_ORACLE_ROW_CORRUPT,
                format!(
                    "Oracle outcome group {}/{} carries inconsistent source/test/time/pass/count/trust metadata",
                    subject,
                    outcome_id.as_str()
                ),
            ));
        }
        if candidates.len() != first.candidate_count {
            return Err(OracleError::new(
                ASTRO_ORACLE_ROW_CORRUPT,
                format!(
                    "Oracle outcome group {} has {} candidate rows but declares {}",
                    outcome_id.as_str(),
                    candidates.len(),
                    first.candidate_count
                ),
            ));
        }

        let mut change_ids = BTreeSet::new();
        let mut credit_sum = 0u64;
        for row in &candidates {
            if !change_ids.insert(row.change_id.as_str()) {
                return Err(OracleError::new(
                    ASTRO_ORACLE_ROW_CORRUPT,
                    format!(
                        "Oracle outcome group {} repeats change identity {:?}",
                        outcome_id.as_str(),
                        row.change_id
                    ),
                ));
            }
            credit_sum = credit_sum.checked_add(row.credit.units()).ok_or_else(|| {
                OracleError::new(
                    ASTRO_ORACLE_ROW_CORRUPT,
                    format!(
                        "Oracle outcome group {} credit sum overflowed u64",
                        outcome_id.as_str()
                    ),
                )
            })?;
        }
        if credit_sum != ORACLE_ATTRIBUTION_SCALE {
            return Err(OracleError::new(
                ASTRO_ORACLE_ROW_CORRUPT,
                format!(
                    "Oracle outcome group {} credit sum {credit_sum} differs from exact scale {ORACLE_ATTRIBUTION_SCALE}",
                    outcome_id.as_str()
                ),
            ));
        }
        let expected_credits = expected_consumer_credit_units(
            &candidates
                .iter()
                .map(|row| row.decay_weight.units())
                .collect::<Vec<_>>(),
            &outcome_id,
        )?;
        if candidates
            .iter()
            .zip(expected_credits)
            .any(|(row, expected)| row.credit.units() != expected)
        {
            return Err(OracleError::new(
                ASTRO_ORACLE_ROW_CORRUPT,
                format!(
                    "Oracle outcome group {} credits do not match the declared positive-largest-remainder fixed-point apportionment",
                    outcome_id.as_str()
                ),
            ));
        }

        validated.push(ValidatedOutcomeGroup {
            outcome_id,
            subject,
            outcome_subject: first.outcome_subject,
            outcome_kind: first.outcome_kind.clone(),
            test_identity: first.test_identity,
            source: first.source.clone(),
            change_id: first.change_id.clone(),
            change_ts: first.change_ts,
            candidate_count: first.candidate_count,
            outcome_ts: first.outcome_ts,
            passed: first.passed,
            trust: first.trust,
        });
    }
    Ok(validated)
}

fn expected_consumer_credit_units(
    weights: &[u64],
    outcome_id: &OutcomeId,
) -> Result<Vec<u64>, OracleError> {
    let candidate_count = u64::try_from(weights.len()).map_err(|_| {
        OracleError::new(
            ASTRO_ORACLE_ROW_CORRUPT,
            format!(
                "Oracle outcome group {} candidate count exceeds u64",
                outcome_id.as_str()
            ),
        )
    })?;
    if candidate_count == 0 || candidate_count > ORACLE_ATTRIBUTION_SCALE {
        return Err(OracleError::new(
            ASTRO_ORACLE_ROW_CORRUPT,
            format!(
                "Oracle outcome group {} candidate count {candidate_count} is outside [1, {ORACLE_ATTRIBUTION_SCALE}]",
                outcome_id.as_str()
            ),
        ));
    }
    let weight_sum = weights.iter().try_fold(0u128, |sum, &weight| {
        sum.checked_add(u128::from(weight)).ok_or_else(|| {
            OracleError::new(
                ASTRO_ORACLE_ROW_CORRUPT,
                format!(
                    "Oracle outcome group {} weight sum overflowed u128",
                    outcome_id.as_str()
                ),
            )
        })
    })?;
    let distributable = ORACLE_ATTRIBUTION_SCALE - candidate_count;
    let mut assigned = 0u64;
    let mut credits = Vec::with_capacity(weights.len());
    let mut remainders = Vec::with_capacity(weights.len());
    for (index, &weight) in weights.iter().enumerate() {
        let numerator = u128::from(distributable)
            .checked_mul(u128::from(weight))
            .ok_or_else(|| {
                OracleError::new(
                    ASTRO_ORACLE_ROW_CORRUPT,
                    format!(
                        "Oracle outcome group {} credit numerator overflowed u128",
                        outcome_id.as_str()
                    ),
                )
            })?;
        let quotient = u64::try_from(numerator / weight_sum).map_err(|_| {
            OracleError::new(
                ASTRO_ORACLE_ROW_CORRUPT,
                format!(
                    "Oracle outcome group {} credit quotient exceeds u64",
                    outcome_id.as_str()
                ),
            )
        })?;
        assigned = assigned.checked_add(quotient).ok_or_else(|| {
            OracleError::new(
                ASTRO_ORACLE_ROW_CORRUPT,
                format!(
                    "Oracle outcome group {} assigned credit overflowed u64",
                    outcome_id.as_str()
                ),
            )
        })?;
        credits.push(1 + quotient);
        remainders.push((numerator % weight_sum, index));
    }
    let residual = distributable.checked_sub(assigned).ok_or_else(|| {
        OracleError::new(
            ASTRO_ORACLE_ROW_CORRUPT,
            format!(
                "Oracle outcome group {} apportioned credit exceeds the exact scale",
                outcome_id.as_str()
            ),
        )
    })?;
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let residual = usize::try_from(residual).map_err(|_| {
        OracleError::new(
            ASTRO_ORACLE_ROW_CORRUPT,
            format!(
                "Oracle outcome group {} residual credit exceeds usize",
                outcome_id.as_str()
            ),
        )
    })?;
    for (_, index) in remainders.into_iter().take(residual) {
        credits[index] += 1;
    }
    Ok(credits)
}

fn validate_consumer_occurrence(record: &OccurrenceRecord) -> Result<(), OracleError> {
    let outcome_id = record.outcome_id.as_str();
    if outcome_id.len() != 64
        || !outcome_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OracleError::new(
            ASTRO_ORACLE_ROW_CORRUPT,
            format!("Oracle outcome identity {outcome_id:?} is not canonical lowercase BLAKE3 hex"),
        ));
    }
    if record.change_id.trim().is_empty() || record.source.trim().is_empty() {
        return Err(OracleError::new(
            ASTRO_ORACLE_ROW_CORRUPT,
            format!("Oracle outcome group {outcome_id} carries an empty change or source identity"),
        ));
    }
    if record.test_identity.is_some_and(|test| {
        test != record.outcome_subject || record.outcome_kind != calyx_core::AnchorKind::TestPass
    }) {
        return Err(OracleError::new(
            ASTRO_ORACLE_ROW_CORRUPT,
            format!(
                "Oracle outcome group {outcome_id} carries an invalid source-test identity binding"
            ),
        ));
    }
    if record.change_ts == 0
        || record.outcome_ts == 0
        || record.outcome_ts < record.change_ts
        || record.lag_s != record.outcome_ts - record.change_ts
    {
        return Err(OracleError::new(
            ASTRO_ORACLE_ROW_CORRUPT,
            format!(
                "Oracle outcome group {outcome_id} carries invalid change/outcome/lag timestamps"
            ),
        ));
    }
    if record.candidate_count == 0
        || record.decay_weight.units() == 0
        || record.decay_weight.units() > ORACLE_ATTRIBUTION_SCALE
        || record.credit.units() == 0
        || record.credit.units() > ORACLE_ATTRIBUTION_SCALE
    {
        return Err(OracleError::new(
            ASTRO_ORACLE_ROW_CORRUPT,
            format!(
                "Oracle outcome group {outcome_id} carries an invalid candidate count, decay weight, or credit"
            ),
        ));
    }
    let expected_trust = astrolabe_anchors::trust_for_source(&record.source).map_err(|error| {
        OracleError::new(
            ASTRO_ORACLE_ROW_CORRUPT,
            format!(
                "Oracle outcome group {outcome_id} carries invalid source {:?}: {}",
                record.source,
                error.message()
            ),
        )
    })?;
    if record.trust != expected_trust {
        return Err(OracleError::new(
            ASTRO_ORACLE_ROW_CORRUPT,
            format!(
                "Oracle outcome group {outcome_id} trust {:?} differs from catalog-derived {expected_trust:?}",
                record.trust
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Evidence snapshot — the structured input every detection predicate reads
// ---------------------------------------------------------------------------

/// The structured evidence context a [`FailureMode`] detection predicate reads.
///
/// It is a *pure summary* of what grounding exists for one served claim: the
/// distinct grounded-outcome counts on the subject, the failing outcome count
/// (recurrence), the pairwise outcome agreement
/// (flakiness), the optional panel sufficiency card (`I(panel;axis)` vs
/// `H(axis)`), and the optional backtest verdict. Detection predicates read this
/// snapshot and nothing else, so a refusal is reproducible from the snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceSnapshot {
    /// Total distinct grounded outcomes on the subject(s) under test.
    direct_outcomes: usize,
    /// Distinct failing grounded outcomes.
    failing_outcomes: usize,
    /// Distinct passing grounded outcomes.
    passing_outcomes: usize,
    /// Pairwise outcome agreement in `[0, 1]`; `1.0` when unmeasurable (< 2 obs).
    self_consistency: f64,
    /// The panel sufficiency card, when a panel measurement exists for this axis.
    sufficiency: Option<SufficiencyCard>,
    /// The backtest verdict (`Some(false)` = grounded did not beat the baseline).
    beats_baseline: Option<bool>,
}

impl EvidenceSnapshot {
    /// Summarizes complete grounded outcome groups for one subject into a snapshot.
    ///
    /// `self_consistency` is the pairwise agreement `(C(f,2)+C(p,2))/C(n,2)`; with
    /// fewer than two outcomes flakiness is unmeasurable and it is held at
    /// `1.0` (the INSUFFICIENT mode fires first in that regime).
    pub fn from_records(records: &[OccurrenceRecord]) -> Result<Self, OracleError> {
        let outcomes = validated_outcome_groups(records)?;
        let mut failing = 0usize;
        let mut passing = 0usize;
        for outcome in &outcomes {
            if outcome.passed {
                passing += 1;
            } else {
                failing += 1;
            }
        }
        let n = outcomes.len();
        let pairs = choose2(n);
        let self_consistency = if pairs == 0 {
            1.0
        } else {
            (choose2(failing) + choose2(passing)) as f64 / pairs as f64
        };
        Ok(EvidenceSnapshot {
            direct_outcomes: n,
            failing_outcomes: failing,
            passing_outcomes: passing,
            self_consistency,
            sufficiency: None,
            beats_baseline: None,
        })
    }

    /// Number of distinct source-backed grounded outcomes in the snapshot.
    pub const fn direct_outcome_count(&self) -> usize {
        self.direct_outcomes
    }

    /// Number of distinct source-backed failing outcomes in the snapshot.
    pub const fn failing_outcome_count(&self) -> usize {
        self.failing_outcomes
    }

    /// Number of distinct source-backed passing outcomes in the snapshot.
    pub const fn passing_outcome_count(&self) -> usize {
        self.passing_outcomes
    }

    /// Pairwise pass/fail agreement over distinct source-backed outcomes.
    pub const fn self_consistency(&self) -> f64 {
        self.self_consistency
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

fn choose2(k: usize) -> u128 {
    let k = k as u128;
    k * k.saturating_sub(1) / 2
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
    if snap.direct_outcomes < cfg.min_grounded_occurrences as usize {
        return true;
    }
    // A measured panel that does not clear H(axis) is insufficient regardless of
    // raw occurrence counts: it carries fewer bits than the outcome demands.
    matches!(&snap.sufficiency, Some(card) if !card.sufficient)
}

fn detect_flaky(snap: &EvidenceSnapshot, cfg: &GateConfig) -> bool {
    // Flakiness needs at least one pair; below the floor it is INSUFFICIENT, not
    // flaky, so this predicate is only reached with enough evidence to measure.
    snap.direct_outcomes >= 2 && snap.self_consistency < cfg.flaky_self_consistency()
}

fn detect_no_recurrence(snap: &EvidenceSnapshot, cfg: &GateConfig) -> bool {
    // There is a failing signal, but too few distinct source outcomes support it
    // as a recurring pattern. Candidate-pair fan-out never changes this count.
    snap.failing_outcomes > 0 && snap.failing_outcomes < cfg.recurrence_floor as usize
}

fn detect_backtest_not_beaten(snap: &EvidenceSnapshot, _cfg: &GateConfig) -> bool {
    matches!(snap.beats_baseline, Some(false))
}

/// The oracle failure-mode catalog, in detection precedence order.
///
/// Precedence matters: INSUFFICIENT (no evidence at all) is diagnosed before
/// FLAKY (evidence that contradicts itself), which is diagnosed before
/// NO_RECURRENCE (fewer than two distinct failing outcomes), which is diagnosed
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
        summary: "the failing signal was observed in too few distinct outcomes to be a pattern; a one-off is not a recurrence",
        remediation: "wait for another distinct source-backed failing outcome, or lower oracle_gate_recurrence_floor deliberately; the oracle will not sell one outcome with many candidate changes as a trend",
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

    if code == ASTRO_ORACLE_NO_RECURRENCE {
        let have = snapshot.failing_outcomes;
        let need = config.recurrence_floor as usize;
        let have_bits = (have as f64 + 1.0).log2();
        let need_bits = (need as f64 + 1.0).log2();
        return vec![LensDeficit {
            axis: "change_outcome".to_string(),
            lens: "failure_recurrence".to_string(),
            have_bits,
            need_bits,
            missing_bits: (need_bits - have_bits).max(0.0),
            bootstrap: format!(
                "anchor_outcome then mine_corpus: record {} more distinct failing outcome(s) on this module (have {have}, need {need}); additional candidate changes for an existing outcome do not count",
                need.saturating_sub(have)
            ),
        }];
    }

    // Otherwise itemize the direct change-history sensor in bits: the information
    // shortfall between the distinct grounded outcomes the module has and the floor.
    let have = snapshot.direct_outcomes;
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
