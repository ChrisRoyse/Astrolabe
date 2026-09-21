//! Change-impact prediction (`predict_impact`, blueprint 11_ORACLE §2).
//!
//! "If I change X, what breaks?" — answered from the grounded change→outcome
//! corpus mined in [`crate::corpus`], not from raw topology. A seed symbol's
//! historical outcomes are bucketed into a direct-evidence confidence; a
//! cycle-guarded butterfly walk over the composite structural graph (calls +
//! DATA_FLOWS + DRIVES + service edges) expands it into a consequence tree,
//! attenuating per hop and pruning weak branches; every branch confidence is
//! capped by three independent ceilings so no prediction ever reaches certainty;
//! and the consequences that intersect TESTS edges become a ranked
//! test-selection set. When a module has no grounded history the tool refuses
//! with a per-sensor deficit rather than guessing (HONEST invariant 2).
//!
//! ## Grounding model (design correction, #50)
//!
//! The #49 corpus links a *change* on a subject to a later *outcome* anchored to
//! the **same** subject (`mine_occurrences` groups by subject). Cross-subject
//! consequence edges are therefore not carried per-edge in the corpus; instead a
//! structural edge `A → B` is treated as *evidence-observed* (it **expands**,
//! grounded) exactly when the child `B` itself carries grounded outcome evidence
//! in the corpus, and as *structural-only* (it emits a **provisional leaf**, no
//! further expansion) when `B` has no evidence. This is the faithful reading of
//! the blueprint's "only consequence edges observed in the evidence corpus
//! expand" against the same-subject corpus we build on, and it keeps every
//! emitted probability traceable to persisted occurrence rows.
//!
//! ## Confidence
//!
//! For a node `B` with occurrence evidence:
//! * `support`        = credit-weighted failure rate `F / (F + P)`;
//! * `separation`     = class separation `|2·failrate − 1|` (0 at a coin-flip,
//!   1 when the outcomes point cleanly one way);
//! * `sample_support` = `n / (n + smoothing)`, discounting thin evidence;
//! * `raw`            = `support · separation · sample_support`;
//! * `self_consistency` = pairwise outcome agreement (the flaky-test ceiling,
//!   blueprint §5); a single observation cannot measure flakiness so it is held
//!   at the neutral prior knob;
//! * `dpi_ceiling`    = `min(C/(C+1), max_confidence)` over the credit mass `C`
//!   — an abundance-honest information ceiling that is *always* strictly below
//!   1.0, so no prediction is ever certain.
//!
//! A branch at hop `h` has confidence `attenuation^h · min(raw, self_consistency,
//! dpi_ceiling)`; because `dpi_ceiling < 1` the product is `< 1` at every hop
//! including the seed. Branches below the prune floor are dropped and never
//! expanded; a node already on the current path is never revisited (cycle guard);
//! the walk never exceeds `max_depth` hops.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::TrustTag;
use astrolabe_domain::knobs::U64KnobDeclaration;
use astrolabe_domain::rollup_trust;
use calyx_aster::vault::AsterVault;
use calyx_core::{AnchorKind, Clock, CxId, Ts};
use serde::{Deserialize, Serialize};

use crate::corpus::{
    ASTRO_ORACLE_ROW_CORRUPT, ORACLE_ATTRIBUTION_SCALE, OccurrenceRecord, OracleError, OutcomeId,
    read_occurrence_rows, read_occurrence_rows_at, read_occurrence_rows_for_subjects_at,
};

// ---------------------------------------------------------------------------
// Stable failure codes
// ---------------------------------------------------------------------------

/// Stable failure code for an out-of-bounds prediction configuration.
pub const ASTRO_ORACLE_PREDICT_CONFIG_INVALID: &str = "ASTRO_ORACLE_PREDICT_CONFIG_INVALID";
/// Stable failure code for a structurally invalid consequence-graph edge.
pub const ASTRO_ORACLE_GRAPH_INVALID: &str = "ASTRO_ORACLE_GRAPH_INVALID";
/// Stable failure code for an empty or malformed predict request.
pub const ASTRO_ORACLE_PREDICT_REQUEST_INVALID: &str = "ASTRO_ORACLE_PREDICT_REQUEST_INVALID";
/// Stable failure code when an exact subject has no persisted measured outcome
/// evidence and the caller requires a grounded result.
pub const ASTRO_ORACLE_GROUNDING_REQUIRED: &str = "ASTRO_ORACLE_GROUNDING_REQUIRED";
/// Stable refusal when the persisted sources cannot form any real held-out
/// `(Git change, CI run, test identity)` case.
pub const ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED: &str =
    "ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED";

const PREDICT_REMEDIATION: &str = "supply a validated PredictConfig, a well-formed ConsequenceGraph, and at least one seed \
     symbol; bootstrap grounded history with ingest_outcome_anchors + mine_corpus when the \
     module has no change→outcome evidence";

/// Operator-facing bootstrap text emitted with an `Insufficient` refusal.
pub const ORACLE_INSUFFICIENT_REMEDIATION: &str = "No grounded change history for this module. Run its test/CI suite once and record the \
     outcome via anchor_outcome (ingest_outcome_anchors), then re-mine the change→outcome \
     corpus with mine_corpus so predict_impact has evidence to ground on.";

/// Stable deficit-sensor name: direct change→outcome history on the seed itself.
pub const ORACLE_SENSOR_DIRECT_CHANGE_HISTORY: &str = "direct_change_history";

// ---------------------------------------------------------------------------
// Registry-declared prediction knobs (standing invariant 4)
// ---------------------------------------------------------------------------

/// Registry version tag for the change-impact prediction knobs (#50).
pub const ORACLE_PREDICT_KNOB_REGISTRY_VERSION: &str = "astrolabe-oracle-predict-knobs-v2";

/// Name of the per-hop attenuation knob (permille).
pub const ORACLE_IMPACT_ATTENUATION_PERMILLE_KNOB: &str = "oracle_impact_attenuation_permille";
/// Name of the prune-floor knob (permille).
pub const ORACLE_IMPACT_PRUNE_FLOOR_PERMILLE_KNOB: &str = "oracle_impact_prune_floor_permille";
/// Name of the max butterfly depth knob (hops).
pub const ORACLE_IMPACT_MAX_DEPTH_KNOB: &str = "oracle_impact_max_depth";
/// Name of the sample-support Laplace smoothing knob (distinct outcomes).
pub const ORACLE_IMPACT_SAMPLE_SMOOTHING_KNOB: &str = "oracle_impact_sample_smoothing";
/// Name of the single-observation self-consistency prior knob (permille).
pub const ORACLE_IMPACT_SINGLE_OBS_SELF_CONSISTENCY_PERMILLE_KNOB: &str =
    "oracle_impact_single_obs_self_consistency_permille";
/// Name of the structural-only provisional-confidence knob (permille).
pub const ORACLE_IMPACT_PROVISIONAL_CONFIDENCE_PERMILLE_KNOB: &str =
    "oracle_impact_provisional_confidence_permille";
/// Name of the hard max-confidence (DPI) cap knob (permille).
pub const ORACLE_IMPACT_MAX_CONFIDENCE_PERMILLE_KNOB: &str =
    "oracle_impact_max_confidence_permille";
/// Name of the grounded-evidence floor knob (distinct outcomes).
pub const ORACLE_IMPACT_EVIDENCE_FLOOR_KNOB: &str = "oracle_impact_evidence_floor";
/// Name of the cohort-thinness threshold knob (distinct outcomes).
pub const ORACLE_IMPACT_COHORT_THIN_THRESHOLD_KNOB: &str = "oracle_impact_cohort_thin_threshold";
/// Name of the backtest top-k selection knob (tests).
pub const ORACLE_IMPACT_BACKTEST_TOP_K_KNOB: &str = "oracle_impact_backtest_top_k";

/// The change-impact prediction knob registry (#50).
///
/// The attenuation and prune floor are pinned to the blueprint's ×0.7 / <0.05
/// butterfly constants (expressed in permille so they stay declared knobs, not
/// bare float literals); depth ≤4 is the blueprint hop bound; the DPI cap keeps
/// the abundance ceiling strictly below certainty; the provisional default of
/// 0.35 mirrors the abduction structural-only default (blueprint §3); and the
/// evidence floor is the same support floor the corpus uses before it will speak.
/// Every default is a seed to be replaced by a measured value once
/// prediction lift is backtested per repo.
pub const ORACLE_PREDICT_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
        name: ORACLE_IMPACT_ATTENUATION_PERMILLE_KNOB,
        default: 700,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §2 butterfly per-hop ×0.7 attenuation",
        rationale: "each butterfly hop multiplies confidence by 0.7 (700 permille): a consequence two calls away is inherently less certain than a direct one; capped below 1000 so attenuation is strictly contractive and the tree terminates in confidence as well as depth; replace with a measured decay once cross-hop causality strength is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
        name: ORACLE_IMPACT_PRUNE_FLOOR_PERMILLE_KNOB,
        default: 50,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §2 butterfly prune < 0.05",
        rationale: "a branch whose attenuated, ceiling-capped confidence falls below 0.05 (50 permille) is dropped and never expanded, so the tree stays a small ranked set of load-bearing consequences rather than an exponential fan-out of vanishing probabilities; replace with a measured precision/recall-tuned floor once prediction lift is backtested",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
        name: ORACLE_IMPACT_MAX_DEPTH_KNOB,
        default: 4,
        min: 1,
        max: 8,
        unit: "hops",
        source: "ASTROLABE blueprint 11_ORACLE §2 butterfly depth ≤ 4",
        rationale: "the butterfly walk expands at most 4 hops from a seed; combined with ×0.7 attenuation and the prune floor this bounds the tree; a hard hop cap also guarantees termination independently of the confidence pruning; replace with a measured horizon once consequence-chain lengths are benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
        name: ORACLE_IMPACT_SAMPLE_SMOOTHING_KNOB,
        default: 1,
        min: 1,
        max: 1_000,
        unit: "distinct_outcomes",
        source: "Laplace/additive smoothing (add-k) applied to the sample-support factor n/(n+k)",
        rationale: "discounts thin evidence: with k=1 a single independent outcome yields sample_support 0.5 and the factor saturates toward 1 as outcomes accumulate; candidate-pair fan-out never increases n; replace with a measured value once the count-to-reliability curve is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
        name: ORACLE_IMPACT_SINGLE_OBS_SELF_CONSISTENCY_PERMILLE_KNOB,
        default: 500,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §5 oracle self-consistency (flakiness unmeasurable below the pair floor)",
        rationale: "flakiness is pairwise outcome agreement and needs at least one pair; a single observation cannot measure it, so self-consistency is held at the neutral 0.5 prior, which caps a one-shot node's confidence until a second outcome arrives; capped below 1000 so it never certifies certainty; replace with the blueprint's Beta-Bernoulli small-sample posterior once wired",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
        name: ORACLE_IMPACT_PROVISIONAL_CONFIDENCE_PERMILLE_KNOB,
        default: 350,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §3 structural-only candidate default (0.35)",
        rationale: "a structural-only leaf (a node reachable by an edge but with no grounded outcome evidence) is emitted at the 0.35 provisional default before attenuation, and never expanded further; this matches the abduction structural-only default so grounded and structural evidence are scored on one scale; replace with a measured structural-prior once available",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
        name: ORACLE_IMPACT_MAX_CONFIDENCE_PERMILLE_KNOB,
        default: 990,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §2 ceilings: confidence never reaches 1.0",
        rationale: "hard upper bound on the DPI/abundance ceiling so that even with unbounded evidence no prediction is ever certified at 1.0; combined with the n_eff/(n_eff+1) abundance term this guarantees min(...) < 1 at every hop; capped below 1000 by construction; replace with a measured I(panel;outcome) ceiling once the panel MI is wired",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
        name: ORACLE_IMPACT_EVIDENCE_FLOOR_KNOB,
        default: 3,
        min: 1,
        max: 1_000_000,
        unit: "distinct_outcomes",
        source: "ASTROLABE #49 corpus min-edge-support floor (3) reused as the predict grounded-speech floor",
        rationale: "predict_impact refuses (Insufficient, per-sensor deficit) unless the seeds carry at least this many distinct grounded outcomes between them, so candidate-pair fan-out cannot defeat the floor; matches the corpus's distinct-outcome edge-support floor; replace with a measured value once refusal precision is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
        name: ORACLE_IMPACT_COHORT_THIN_THRESHOLD_KNOB,
        default: 3,
        min: 1,
        max: 1_000_000,
        unit: "distinct_outcomes",
        source: "ASTROLABE blueprint 11_ORACLE §2 direct evidence: fold L2-similar peers when thin",
        rationale: "when a seed's own direct history has fewer distinct outcomes than this, the L2-similar cohort's outcomes are folded in and the consequence is clearly marked cohort evidence with trust downgraded to provisional; candidate-pair fan-out never changes thinness; replace with a measured threshold once cohort lift is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
        name: ORACLE_IMPACT_BACKTEST_TOP_K_KNOB,
        default: 5,
        min: 1,
        max: 1_000,
        unit: "tests",
        source: "ASTROLABE success criterion 01 §6.3 / blueprint §199: actually-failing test ranked top-5",
        rationale: "the backtest top-k metric: a held-out fix-commit is a hit when its actually-failing test is ranked within the top-k of the predicted test-selection set; 5 is the blueprint's top-5 success target; replace only if the success criterion itself changes",
    },
];

/// Returns the predict declaration for `name`, or `None`.
pub fn oracle_predict_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ORACLE_PREDICT_KNOBS.iter().find(|knob| knob.name == name)
}

fn predict_knob(name: &str) -> &'static U64KnobDeclaration {
    oracle_predict_knob(name).expect("oracle predict knob is declared")
}

// ---------------------------------------------------------------------------
// Prediction configuration
// ---------------------------------------------------------------------------

/// Validated change-impact prediction policy.
///
/// Fields hold the raw knob values (permille or counts); the resolved floating
/// factors are read through the accessor methods so every number stays a
/// registry-declared knob rather than a bare literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredictConfig {
    pub attenuation_permille: u64,
    pub prune_floor_permille: u64,
    pub max_depth: u64,
    pub sample_smoothing: u64,
    pub single_obs_self_consistency_permille: u64,
    pub provisional_confidence_permille: u64,
    pub max_confidence_permille: u64,
    pub evidence_floor: u64,
    pub cohort_thin_threshold: u64,
    pub backtest_top_k: u64,
    /// Whether the repo's backtest gate has been passed so grounded confidence
    /// may be advertised. When `false` every consequence is labeled provisional.
    pub advertise_grounded: bool,
}

impl Default for PredictConfig {
    fn default() -> Self {
        Self {
            attenuation_permille: predict_knob(ORACLE_IMPACT_ATTENUATION_PERMILLE_KNOB).default,
            prune_floor_permille: predict_knob(ORACLE_IMPACT_PRUNE_FLOOR_PERMILLE_KNOB).default,
            max_depth: predict_knob(ORACLE_IMPACT_MAX_DEPTH_KNOB).default,
            sample_smoothing: predict_knob(ORACLE_IMPACT_SAMPLE_SMOOTHING_KNOB).default,
            single_obs_self_consistency_permille: predict_knob(
                ORACLE_IMPACT_SINGLE_OBS_SELF_CONSISTENCY_PERMILLE_KNOB,
            )
            .default,
            provisional_confidence_permille: predict_knob(
                ORACLE_IMPACT_PROVISIONAL_CONFIDENCE_PERMILLE_KNOB,
            )
            .default,
            max_confidence_permille: predict_knob(ORACLE_IMPACT_MAX_CONFIDENCE_PERMILLE_KNOB)
                .default,
            evidence_floor: predict_knob(ORACLE_IMPACT_EVIDENCE_FLOOR_KNOB).default,
            cohort_thin_threshold: predict_knob(ORACLE_IMPACT_COHORT_THIN_THRESHOLD_KNOB).default,
            backtest_top_k: predict_knob(ORACLE_IMPACT_BACKTEST_TOP_K_KNOB).default,
            // Grounded serving is a persisted, repo-specific admission result;
            // the process default carries no authority to advertise it.
            advertise_grounded: false,
        }
    }
}

impl PredictConfig {
    /// Fails closed when any field is outside its declared knob bounds.
    pub fn validate(&self) -> Result<(), OracleError> {
        check_predict_knob(
            ORACLE_IMPACT_ATTENUATION_PERMILLE_KNOB,
            self.attenuation_permille,
        )?;
        check_predict_knob(
            ORACLE_IMPACT_PRUNE_FLOOR_PERMILLE_KNOB,
            self.prune_floor_permille,
        )?;
        check_predict_knob(ORACLE_IMPACT_MAX_DEPTH_KNOB, self.max_depth)?;
        check_predict_knob(ORACLE_IMPACT_SAMPLE_SMOOTHING_KNOB, self.sample_smoothing)?;
        check_predict_knob(
            ORACLE_IMPACT_SINGLE_OBS_SELF_CONSISTENCY_PERMILLE_KNOB,
            self.single_obs_self_consistency_permille,
        )?;
        check_predict_knob(
            ORACLE_IMPACT_PROVISIONAL_CONFIDENCE_PERMILLE_KNOB,
            self.provisional_confidence_permille,
        )?;
        check_predict_knob(
            ORACLE_IMPACT_MAX_CONFIDENCE_PERMILLE_KNOB,
            self.max_confidence_permille,
        )?;
        check_predict_knob(ORACLE_IMPACT_EVIDENCE_FLOOR_KNOB, self.evidence_floor)?;
        check_predict_knob(
            ORACLE_IMPACT_COHORT_THIN_THRESHOLD_KNOB,
            self.cohort_thin_threshold,
        )?;
        check_predict_knob(ORACLE_IMPACT_BACKTEST_TOP_K_KNOB, self.backtest_top_k)?;
        Ok(())
    }

    fn attenuation(&self) -> f64 {
        self.attenuation_permille as f64 / 1000.0
    }
    fn prune_floor(&self) -> f64 {
        self.prune_floor_permille as f64 / 1000.0
    }
    fn single_obs_self_consistency(&self) -> f64 {
        self.single_obs_self_consistency_permille as f64 / 1000.0
    }
    fn provisional_confidence(&self) -> f64 {
        self.provisional_confidence_permille as f64 / 1000.0
    }
    fn max_confidence(&self) -> f64 {
        self.max_confidence_permille as f64 / 1000.0
    }

    /// The hard confidence ceiling (DPI abundance cap) served consequences are
    /// bounded by, always strictly below `1.0`. This is the ceiling metadata that
    /// accompanies every served confidence through [`crate::gate::GatedConfidence`]
    /// (HONEST invariant 1: no unlabeled claim).
    pub fn served_ceiling(&self) -> f64 {
        self.max_confidence()
    }

    /// The structural-only provisional risk served for a symbol with no grounded
    /// change→outcome evidence — the registry-declared provisional-confidence knob
    /// (blueprint §3, default 0.35). Used as the labeled-provisional fallback in
    /// [`grounded_risk`] and the `detect_changes` grounded-risk surface.
    pub fn provisional_fallback_risk(&self) -> f64 {
        self.provisional_confidence()
    }
}

fn check_predict_knob(name: &str, value: u64) -> Result<(), OracleError> {
    let declared = predict_knob(name);
    if declared.accepts(value) {
        Ok(())
    } else {
        Err(OracleError {
            code: ASTRO_ORACLE_PREDICT_CONFIG_INVALID,
            message: format!(
                "predict knob {name} value {value} is outside declared bounds [{}, {}]",
                declared.min, declared.max
            ),
            remediation: PREDICT_REMEDIATION,
        })
    }
}

fn predict_error(code: &'static str, message: impl Into<String>) -> OracleError {
    OracleError {
        code,
        message: message.into(),
        remediation: PREDICT_REMEDIATION,
    }
}

// ---------------------------------------------------------------------------
// Composite consequence graph
// ---------------------------------------------------------------------------

/// The kind of a structural edge in the composite consequence graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConsequenceEdgeKind {
    /// A calls B: a change in B can break A's callers of it (propagation edge).
    Calls,
    /// Data flows from A to B (propagation edge).
    DataFlow,
    /// A drives B (lead/lag causal edge; propagation edge).
    Drives,
    /// A service/route edge between components (propagation edge).
    Service,
    /// A is covered by test B (test-selection edge; never a propagation edge).
    Tests,
}

impl ConsequenceEdgeKind {
    /// Whether the butterfly walk propagates impact along this edge kind.
    ///
    /// TESTS edges map a consequence node to the tests that cover it; they are
    /// used only to build the test-selection set, never to expand the tree.
    fn is_propagation(self) -> bool {
        !matches!(self, ConsequenceEdgeKind::Tests)
    }
}

/// One directed, typed edge of the composite graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsequenceEdge {
    pub from: CxId,
    pub to: CxId,
    pub kind: ConsequenceEdgeKind,
}

/// A validated composite structural graph: propagation adjacency plus the
/// separate TESTS-cover map, both in deterministic (sorted) order.
#[derive(Debug, Clone, Default)]
pub struct ConsequenceGraph {
    propagation: BTreeMap<CxId, BTreeSet<CxId>>,
    tests: BTreeMap<CxId, BTreeSet<CxId>>,
}

impl ConsequenceGraph {
    /// Builds a graph from directed edges, rejecting self-loops fail-closed.
    pub fn from_edges(edges: &[ConsequenceEdge]) -> Result<Self, OracleError> {
        let mut graph = ConsequenceGraph::default();
        for edge in edges {
            if edge.from == edge.to {
                return Err(predict_error(
                    ASTRO_ORACLE_GRAPH_INVALID,
                    format!("edge from {} to itself is a self-loop", edge.from),
                ));
            }
            if edge.kind.is_propagation() {
                graph
                    .propagation
                    .entry(edge.from)
                    .or_default()
                    .insert(edge.to);
            } else {
                graph.tests.entry(edge.from).or_default().insert(edge.to);
            }
        }
        Ok(graph)
    }

    fn propagation_children(&self, node: CxId) -> impl Iterator<Item = CxId> + '_ {
        self.propagation
            .get(&node)
            .into_iter()
            .flat_map(|set| set.iter().copied())
    }

    fn covering_tests(&self, node: CxId) -> impl Iterator<Item = CxId> + '_ {
        self.tests
            .get(&node)
            .into_iter()
            .flat_map(|set| set.iter().copied())
    }
}

// ---------------------------------------------------------------------------
// Grounded node evidence, indexed by subject
// ---------------------------------------------------------------------------

/// Aggregated grounded outcome evidence for one subject.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeEvidence {
    /// Number of distinct real outcomes on this subject. Candidate-pair rows do
    /// not increase this evidence floor.
    pub n: usize,
    /// Exact fixed-point mass of failing distinct outcomes.
    pub fail_mass: u128,
    /// Exact fixed-point mass of passing distinct outcomes.
    pub pass_mass: u128,
    /// Count of failing distinct outcomes (for pairwise self-consistency).
    pub n_fail: usize,
    /// Count of passing distinct outcomes.
    pub n_pass: usize,
    /// Rolled-up trust over the contributing outcomes' catalog trust.
    pub trust: TrustTag,
}

impl NodeEvidence {
    fn from_records<'a>(
        records: impl Iterator<Item = &'a OccurrenceRecord>,
    ) -> Result<Self, OracleError> {
        #[derive(Clone, Copy)]
        struct OutcomeSummary<'a> {
            source: &'a str,
            outcome_ts: u64,
            passed: bool,
            candidate_count: usize,
            observed_candidates: usize,
            credit_units: u128,
            trust: TrustTag,
        }

        let mut outcomes: BTreeMap<&OutcomeId, OutcomeSummary<'_>> = BTreeMap::new();
        for record in records {
            let entry = outcomes
                .entry(&record.outcome_id)
                .or_insert(OutcomeSummary {
                    source: &record.source,
                    outcome_ts: record.outcome_ts,
                    passed: record.passed,
                    candidate_count: record.candidate_count,
                    observed_candidates: 0,
                    credit_units: 0,
                    trust: record.trust,
                });
            if entry.source != record.source.as_str()
                || entry.outcome_ts != record.outcome_ts
                || entry.passed != record.passed
                || entry.candidate_count != record.candidate_count
                || entry.trust != record.trust
            {
                return Err(OracleError::new(
                    ASTRO_ORACLE_ROW_CORRUPT,
                    format!(
                        "outcome {} carries inconsistent occurrence metadata while building evidence",
                        record.outcome_id.as_str()
                    ),
                ));
            }
            entry.observed_candidates =
                entry.observed_candidates.checked_add(1).ok_or_else(|| {
                    OracleError::new(
                        ASTRO_ORACLE_ROW_CORRUPT,
                        format!(
                            "outcome {} candidate count overflowed usize",
                            record.outcome_id.as_str()
                        ),
                    )
                })?;
            entry.credit_units = entry
                .credit_units
                .checked_add(u128::from(record.credit.units()))
                .ok_or_else(|| {
                    OracleError::new(
                        ASTRO_ORACLE_ROW_CORRUPT,
                        format!(
                            "outcome {} credit mass overflowed u128",
                            record.outcome_id.as_str()
                        ),
                    )
                })?;
        }

        let mut n = 0usize;
        let mut fail_mass = 0u128;
        let mut pass_mass = 0u128;
        let mut n_fail = 0usize;
        let mut n_pass = 0usize;
        let mut trusts = Vec::new();
        for (outcome_id, outcome) in outcomes {
            if outcome.observed_candidates != outcome.candidate_count
                || outcome.credit_units != u128::from(ORACLE_ATTRIBUTION_SCALE)
            {
                return Err(OracleError::new(
                    ASTRO_ORACLE_ROW_CORRUPT,
                    format!(
                        "outcome {} has observed/declared candidates {}/{} and credit units {}/{}",
                        outcome_id.as_str(),
                        outcome.observed_candidates,
                        outcome.candidate_count,
                        outcome.credit_units,
                        ORACLE_ATTRIBUTION_SCALE
                    ),
                ));
            }
            n = n.checked_add(1).ok_or_else(|| {
                OracleError::new(
                    ASTRO_ORACLE_ROW_CORRUPT,
                    "distinct outcome count overflowed usize",
                )
            })?;
            if outcome.passed {
                pass_mass = pass_mass.checked_add(outcome.credit_units).ok_or_else(|| {
                    OracleError::new(
                        ASTRO_ORACLE_ROW_CORRUPT,
                        "passing credit mass overflowed u128",
                    )
                })?;
                n_pass = n_pass.checked_add(1).ok_or_else(|| {
                    OracleError::new(
                        ASTRO_ORACLE_ROW_CORRUPT,
                        "passing outcome count overflowed usize",
                    )
                })?;
            } else {
                fail_mass = fail_mass.checked_add(outcome.credit_units).ok_or_else(|| {
                    OracleError::new(
                        ASTRO_ORACLE_ROW_CORRUPT,
                        "failing credit mass overflowed u128",
                    )
                })?;
                n_fail = n_fail.checked_add(1).ok_or_else(|| {
                    OracleError::new(
                        ASTRO_ORACLE_ROW_CORRUPT,
                        "failing outcome count overflowed usize",
                    )
                })?;
            }
            trusts.push(outcome.trust);
        }
        Ok(NodeEvidence {
            n,
            fail_mass,
            pass_mass,
            n_fail,
            n_pass,
            trust: rollup_trust(trusts),
        })
    }

    fn credit_mass(&self) -> f64 {
        (self.fail_mass + self.pass_mass) as f64 / ORACLE_ATTRIBUTION_SCALE as f64
    }

    fn fail_rate(&self) -> f64 {
        let mass = self.fail_mass + self.pass_mass;
        if mass > 0 {
            self.fail_mass as f64 / mass as f64
        } else {
            0.0
        }
    }

    /// Raw failure-association confidence `support · separation · sample_support`.
    fn raw_confidence(&self, config: &PredictConfig) -> f64 {
        let fail_rate = self.fail_rate();
        let support = fail_rate;
        let separation = (2.0 * fail_rate - 1.0).abs();
        let sample_support = self.n as f64 / (self.n as f64 + config.sample_smoothing as f64);
        support * separation * sample_support
    }

    /// Pairwise outcome-agreement self-consistency ceiling (blueprint §5).
    fn self_consistency(&self, config: &PredictConfig) -> f64 {
        let pairs = choose2(self.n);
        if pairs == 0 {
            return config.single_obs_self_consistency();
        }
        let agree = choose2(self.n_fail) + choose2(self.n_pass);
        agree as f64 / pairs as f64
    }

    /// Abundance-honest DPI ceiling, always strictly below 1.0.
    fn dpi_ceiling(&self, config: &PredictConfig) -> f64 {
        let mass = self.credit_mass();
        let abundance = mass / (mass + 1.0);
        abundance.min(config.max_confidence())
    }

    /// The ceiling-capped node confidence `min(raw, self_consistency, dpi)`.
    fn ceiled_confidence(&self, config: &PredictConfig) -> f64 {
        self.raw_confidence(config)
            .min(self.self_consistency(config))
            .min(self.dpi_ceiling(config))
    }
}

fn choose2(k: usize) -> u128 {
    let k = k as u128;
    k * k.saturating_sub(1) / 2
}

/// A grounded-evidence index over occurrence rows, keyed by subject and counted
/// by exact independent outcome identity.
#[derive(Debug, Clone, Default)]
pub struct OracleEvidence {
    by_subject: BTreeMap<CxId, NodeEvidence>,
}

impl OracleEvidence {
    /// Builds the index from in-memory occurrence records, refusing incomplete
    /// or inconsistent candidate groups rather than inflating evidence.
    pub(crate) fn from_occurrences(records: &[OccurrenceRecord]) -> Result<Self, OracleError> {
        crate::gate::validated_outcome_groups(records)?;
        let mut grouped: BTreeMap<CxId, Vec<&OccurrenceRecord>> = BTreeMap::new();
        for record in records {
            grouped.entry(record.subject).or_default().push(record);
        }
        let by_subject = grouped
            .into_iter()
            .map(|(subject, recs)| {
                NodeEvidence::from_records(recs.into_iter()).map(|evidence| (subject, evidence))
            })
            .collect::<Result<_, _>>()?;
        Ok(OracleEvidence { by_subject })
    }

    fn insert_historical_group(
        &mut self,
        subject: CxId,
        group: NodeEvidence,
    ) -> Result<(), OracleError> {
        if group.n != 1 {
            return Err(predict_error(
                ASTRO_ORACLE_ROW_CORRUPT,
                format!(
                    "chronological replay expected one complete outcome group for {subject}, got {}",
                    group.n
                ),
            ));
        }
        match self.by_subject.entry(subject) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(group);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let current = entry.get_mut();
                current.n = current.n.checked_add(group.n).ok_or_else(|| {
                    predict_error(
                        ASTRO_ORACLE_ROW_CORRUPT,
                        "historical outcome count overflowed",
                    )
                })?;
                current.fail_mass =
                    current
                        .fail_mass
                        .checked_add(group.fail_mass)
                        .ok_or_else(|| {
                            predict_error(
                                ASTRO_ORACLE_ROW_CORRUPT,
                                "historical fail mass overflowed",
                            )
                        })?;
                current.pass_mass =
                    current
                        .pass_mass
                        .checked_add(group.pass_mass)
                        .ok_or_else(|| {
                            predict_error(
                                ASTRO_ORACLE_ROW_CORRUPT,
                                "historical pass mass overflowed",
                            )
                        })?;
                current.n_fail = current.n_fail.checked_add(group.n_fail).ok_or_else(|| {
                    predict_error(ASTRO_ORACLE_ROW_CORRUPT, "historical fail count overflowed")
                })?;
                current.n_pass = current.n_pass.checked_add(group.n_pass).ok_or_else(|| {
                    predict_error(ASTRO_ORACLE_ROW_CORRUPT, "historical pass count overflowed")
                })?;
                current.trust = rollup_trust([current.trust, group.trust]);
            }
        }
        Ok(())
    }

    /// Builds the index by reading persisted occurrence rows back from a vault.
    ///
    /// This is the FSV path: the evidence is reconstructed from the durable
    /// `Kv` CF rows, not from an in-memory planner echo.
    pub fn from_vault<C>(vault: &AsterVault<C>) -> calyx_core::Result<Self>
    where
        C: Clock,
    {
        let rows = read_occurrence_rows(vault)?;
        let records: Vec<OccurrenceRecord> = rows
            .into_iter()
            .map(|persisted| {
                let row = persisted.row;
                OccurrenceRecord {
                    subject: row.subject,
                    change_id: row.change_id,
                    outcome_id: row.outcome_id,
                    outcome_subject: row.outcome_subject,
                    outcome_kind: row.outcome_kind,
                    test_identity: row.test_identity,
                    source: row.source,
                    change_ts: row.change_ts,
                    outcome_ts: row.outcome_ts,
                    lag_s: row.lag_s,
                    decay_weight: row.decay_weight,
                    credit: row.credit,
                    passed: row.passed,
                    candidate_count: row.candidate_count,
                    trust: row.trust,
                }
            })
            .collect();
        Ok(OracleEvidence::from_occurrences(&records)?)
    }

    /// Builds the complete evidence index at one caller-retained snapshot.
    pub fn from_vault_at<C>(
        vault: &AsterVault<C>,
        snapshot: calyx_core::Seq,
    ) -> calyx_core::Result<Self>
    where
        C: Clock,
    {
        let rows = read_occurrence_rows_at(vault, snapshot)?;
        let records = rows
            .into_iter()
            .map(|persisted| {
                let row = persisted.row;
                OccurrenceRecord {
                    subject: row.subject,
                    change_id: row.change_id,
                    outcome_id: row.outcome_id,
                    outcome_subject: row.outcome_subject,
                    outcome_kind: row.outcome_kind,
                    test_identity: row.test_identity,
                    source: row.source,
                    change_ts: row.change_ts,
                    outcome_ts: row.outcome_ts,
                    lag_s: row.lag_s,
                    decay_weight: row.decay_weight,
                    credit: row.credit,
                    passed: row.passed,
                    candidate_count: row.candidate_count,
                    trust: row.trust,
                }
            })
            .collect::<Vec<_>>();
        Ok(Self::from_occurrences(&records)?)
    }

    /// Builds the evidence index from only the exact requested subjects at one
    /// retained snapshot. The persisted v5 occurrence key prefixes make this
    /// bounded by the requested subjects and their rows, never the whole `Kv`
    /// family or Oracle corpus.
    pub fn from_vault_subjects_at<C>(
        vault: &AsterVault<C>,
        snapshot: calyx_core::Seq,
        subjects: &BTreeSet<CxId>,
    ) -> calyx_core::Result<Self>
    where
        C: Clock,
    {
        let rows = read_occurrence_rows_for_subjects_at(vault, snapshot, subjects)?;
        let records: Vec<OccurrenceRecord> = rows
            .into_iter()
            .map(|persisted| {
                let row = persisted.row;
                OccurrenceRecord {
                    subject: row.subject,
                    change_id: row.change_id,
                    outcome_id: row.outcome_id,
                    outcome_subject: row.outcome_subject,
                    outcome_kind: row.outcome_kind,
                    test_identity: row.test_identity,
                    source: row.source,
                    change_ts: row.change_ts,
                    outcome_ts: row.outcome_ts,
                    lag_s: row.lag_s,
                    decay_weight: row.decay_weight,
                    credit: row.credit,
                    passed: row.passed,
                    candidate_count: row.candidate_count,
                    trust: row.trust,
                }
            })
            .collect();
        Ok(OracleEvidence::from_occurrences(&records)?)
    }

    fn node(&self, subject: CxId) -> Option<&NodeEvidence> {
        self.by_subject.get(&subject)
    }
}

// ---------------------------------------------------------------------------
// Request and result types
// ---------------------------------------------------------------------------

/// A `predict_impact` request: the seed symbols to change plus optional
/// L2-similar cohort peers used to backfill thin direct evidence.
#[derive(Debug, Clone, Default)]
pub struct PredictRequest {
    /// The symbol(s) being changed.
    pub seeds: Vec<CxId>,
    /// Per-seed L2-similar peers (clearly-marked cohort evidence when the seed's
    /// own direct history is thinner than the cohort threshold).
    pub cohort_peers: BTreeMap<CxId, Vec<CxId>>,
}

/// One ranked consequence of the predicted change.
#[derive(Debug, Clone, PartialEq)]
pub struct Consequence {
    /// The subject that is predicted to break.
    pub target: CxId,
    /// Attenuated, ceiling-capped consequence probability, strictly `< 1.0`.
    pub p: f64,
    /// The seed→target hop path.
    pub hop_path: Vec<CxId>,
    /// Number of distinct grounded outcomes backing this node (`0` = structural-only).
    pub evidence_n: usize,
    /// Trust of the consequence.
    pub trust: TrustTag,
    /// Whether this node was grounded in observed outcome evidence.
    pub grounded: bool,
    /// Whether L2-similar cohort evidence was folded in (clearly marked).
    pub cohort: bool,
}

/// One entry of the ranked test-selection set.
#[derive(Debug, Clone, PartialEq)]
pub struct TestSelection {
    /// The test subject to run.
    pub test: CxId,
    /// The probability inherited from the consequence it covers.
    pub p: f64,
    /// The consequence node whose TESTS edge selected this test.
    pub via: CxId,
}

/// A grounded change-impact prediction.
#[derive(Debug, Clone, PartialEq)]
pub struct ImpactPrediction {
    pub seeds: Vec<CxId>,
    /// Consequences ranked by probability, highest first.
    pub consequences: Vec<Consequence>,
    /// The test-selection set (consequences ∩ TESTS edges), ranked by `p`.
    pub test_selection: Vec<TestSelection>,
    /// Whether grounded confidence is advertised (the repo's backtest gate).
    pub grounded_mode: bool,
}

/// A per-sensor evidence deficit backing an `Insufficient` refusal.
#[derive(Debug, Clone, PartialEq)]
pub struct SensorDeficit {
    /// The evidence sensor that is short.
    pub sensor: &'static str,
    /// Distinct grounded outcomes available on this sensor.
    pub have: usize,
    /// Distinct grounded outcomes required before the tool will speak.
    pub need: usize,
    /// Information shortfall in bits: `log2(need+1) − log2(have+1)`.
    pub bits_short: f64,
}

/// An honest refusal: not enough grounded evidence to predict.
#[derive(Debug, Clone, PartialEq)]
pub struct InsufficientReport {
    pub seeds: Vec<CxId>,
    pub deficits: Vec<SensorDeficit>,
    pub remediation: &'static str,
}

/// The outcome of a `predict_impact` call: a grounded prediction or an honest
/// refusal-with-deficit (HONEST invariant 2 — never a confident guess).
#[derive(Debug, Clone, PartialEq)]
pub enum ImpactOutcome {
    Grounded(ImpactPrediction),
    Insufficient(InsufficientReport),
}

// ---------------------------------------------------------------------------
// detect_changes grounded risk (blueprint P6.3 scaffold, finalized #52)
// ---------------------------------------------------------------------------

/// A per-symbol change risk, grounded in oracle evidence where it exists and
/// falling back to the topological hop→risk (labeled provisional) where it does
/// not.
///
/// This finalizes the P6.3 `detect_changes` grounded-risk scaffold: an
/// oracle-backed failure-association probability *replaces* the hop→risk heuristic
/// whenever the subject carries grounded change→outcome evidence, and the legacy
/// hop→risk is served — clearly labeled `provisional` (HONEST invariant 3, a
/// labeled degradation) — only when no evidence exists. The risk is always capped
/// by the DPI ceiling so it is strictly below `1.0` and can be served through
/// [`crate::gate::GatedConfidence`].
#[derive(Debug, Clone, PartialEq)]
pub struct GroundedRisk {
    /// The subject the risk was computed for.
    pub subject: CxId,
    /// The change risk in `[0, ceiling]`, always strictly `< 1.0`.
    pub risk: f64,
    /// The DPI ceiling the risk is capped by (strictly `< 1.0`).
    pub ceiling: f64,
    /// Trust of the risk: the evidence trust when grounded above the floor, else
    /// `Provisional`.
    pub trust: TrustTag,
    /// Whether the risk came from oracle evidence (`true`) or the hop fallback.
    pub grounded: bool,
    /// Number of distinct grounded outcomes backing the risk (`0` = hop fallback).
    pub evidence_n: usize,
}

/// Computes the grounded change risk for one subject.
///
/// * **Grounded** (subject carries at least the evidence floor of distinct outcomes):
///   the risk is the subject's ceiling-capped failure-association confidence, with
///   the evidence's trust (or `Provisional` when grounded mode is off).
/// * **Thin** (subject carries some but fewer than the floor distinct outcomes): still a
///   probability from evidence, but labeled `Provisional`.
/// * **Ungrounded** (no outcomes): the `fallback_hop_risk` heuristic, clamped
///   below the ceiling and labeled `Provisional`.
///
/// `fallback_hop_risk` must be a finite, non-negative value (the legacy
/// `detect_changes` hop→risk); a malformed fallback fails closed.
pub fn grounded_risk(
    evidence: &OracleEvidence,
    subject: CxId,
    fallback_hop_risk: f64,
    config: &PredictConfig,
) -> Result<GroundedRisk, OracleError> {
    config.validate()?;
    let global_ceiling = config.max_confidence();
    match evidence.node(subject) {
        Some(node) => {
            let ceiling = node.dpi_ceiling(config);
            let risk = node.ceiled_confidence(config).min(ceiling);
            let grounded_enough =
                node.n >= config.evidence_floor as usize && config.advertise_grounded;
            let trust = if grounded_enough {
                node.trust
            } else {
                TrustTag::Provisional
            };
            Ok(GroundedRisk {
                subject,
                risk,
                ceiling,
                trust,
                grounded: true,
                evidence_n: node.n,
            })
        }
        None => {
            if !fallback_hop_risk.is_finite() || fallback_hop_risk < 0.0 {
                return Err(predict_error(
                    ASTRO_ORACLE_PREDICT_REQUEST_INVALID,
                    format!(
                        "fallback hop risk {fallback_hop_risk} is not a finite non-negative value"
                    ),
                ));
            }
            Ok(GroundedRisk {
                subject,
                risk: fallback_hop_risk.min(global_ceiling),
                ceiling: global_ceiling,
                trust: TrustTag::Provisional,
                grounded: false,
                evidence_n: 0,
            })
        }
    }
}

/// Computes risk only when the exact subject has persisted measured evidence.
///
/// Unlike [`grounded_risk`], this contract has no heuristic argument and no
/// ungrounded success state, so production callers that require measurement
/// cannot accidentally reintroduce a numeric fallback.
pub fn grounded_risk_required(
    evidence: &OracleEvidence,
    subject: CxId,
    config: &PredictConfig,
) -> Result<GroundedRisk, OracleError> {
    let result = grounded_risk(evidence, subject, 0.0, config)?;
    let required = config.evidence_floor as usize;
    if !result.grounded || result.evidence_n < required || !config.advertise_grounded {
        return Err(predict_error(
            ASTRO_ORACLE_GROUNDING_REQUIRED,
            format!(
                "subject {subject} is not admitted for grounded serving: distinct_outcomes={} required={} advertise_grounded={}; no numeric fallback is permitted",
                result.evidence_n, required, config.advertise_grounded
            ),
        ));
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// predict_impact
// ---------------------------------------------------------------------------

/// Predicts the grounded consequence tree of changing `request.seeds`.
///
/// Returns [`ImpactOutcome::Insufficient`] when the seeds carry fewer than the
/// declared evidence floor of distinct grounded outcomes between them (a labeled
/// refusal, not an error), and [`ImpactOutcome::Grounded`] otherwise. Structural
/// errors (bad config, empty request) fail closed with a coded [`OracleError`].
pub fn predict_impact(
    graph: &ConsequenceGraph,
    evidence: &OracleEvidence,
    request: &PredictRequest,
    config: &PredictConfig,
) -> Result<ImpactOutcome, OracleError> {
    config.validate()?;
    if request.seeds.is_empty() {
        return Err(predict_error(
            ASTRO_ORACLE_PREDICT_REQUEST_INVALID,
            "predict_impact requires at least one seed symbol",
        ));
    }

    // Deduplicate seeds while preserving a deterministic order.
    let mut seeds: Vec<CxId> = request.seeds.clone();
    seeds.sort();
    seeds.dedup();
    let seed_set = seeds.iter().copied().collect::<BTreeSet<_>>();

    // --- Honesty gate: total grounded direct evidence across the seeds. ---
    let mut direct_have = 0usize;
    for &seed in &seeds {
        if let Some(node) = evidence.node(seed) {
            direct_have += node.n;
        }
    }
    if direct_have < config.evidence_floor as usize {
        // Try the cohort sensor before refusing outright.
        let mut cohort_have = 0usize;
        let mut counted_cohort_subjects = BTreeSet::new();
        for &seed in &seeds {
            for peer in request.cohort_peers.get(&seed).into_iter().flatten() {
                if !seed_set.contains(peer)
                    && counted_cohort_subjects.insert(*peer)
                    && let Some(node) = evidence.node(*peer)
                {
                    cohort_have += node.n;
                }
            }
        }
        if direct_have + cohort_have < config.evidence_floor as usize {
            let need = config.evidence_floor as usize;
            let bits_short = (need as f64 + 1.0).log2() - (direct_have as f64 + 1.0).log2();
            return Ok(ImpactOutcome::Insufficient(InsufficientReport {
                seeds,
                deficits: vec![SensorDeficit {
                    sensor: ORACLE_SENSOR_DIRECT_CHANGE_HISTORY,
                    have: direct_have,
                    need,
                    bits_short,
                }],
                remediation: ORACLE_INSUFFICIENT_REMEDIATION,
            }));
        }
    }

    // --- Butterfly walk: one DFS per seed, merged by target (max p). ---
    let mut best: BTreeMap<CxId, Consequence> = BTreeMap::new();
    for &seed in &seeds {
        let mut path = Vec::new();
        walk(
            graph, evidence, request, config, seed, seed, 0, 1.0, &mut path, &mut best,
        );
    }

    let mut consequences: Vec<Consequence> = best.into_values().collect();
    consequences.sort_by(|a, b| b.p.total_cmp(&a.p).then_with(|| a.target.cmp(&b.target)));

    // --- Test selection: consequences ∩ TESTS edges, ranked by p. ---
    let mut test_best: BTreeMap<CxId, TestSelection> = BTreeMap::new();
    for consequence in &consequences {
        for test in graph.covering_tests(consequence.target) {
            let entry = test_best.entry(test).or_insert(TestSelection {
                test,
                p: consequence.p,
                via: consequence.target,
            });
            if consequence.p > entry.p {
                entry.p = consequence.p;
                entry.via = consequence.target;
            }
        }
    }
    let mut test_selection: Vec<TestSelection> = test_best.into_values().collect();
    test_selection.sort_by(|a, b| b.p.total_cmp(&a.p).then_with(|| a.test.cmp(&b.test)));

    Ok(ImpactOutcome::Grounded(ImpactPrediction {
        seeds,
        consequences,
        test_selection,
        grounded_mode: config.advertise_grounded,
    }))
}

/// Recursive butterfly expansion. A grounded node (child with corpus evidence)
/// is scored from that evidence and expanded further; a structural-only node is
/// emitted as a provisional leaf and never expanded. The `path` set is the cycle
/// guard; `attenuation` is the running `0.7^hop` factor.
#[allow(clippy::too_many_arguments)]
fn walk(
    graph: &ConsequenceGraph,
    evidence: &OracleEvidence,
    request: &PredictRequest,
    config: &PredictConfig,
    seed: CxId,
    node: CxId,
    hop: u64,
    attenuation: f64,
    path: &mut Vec<CxId>,
    best: &mut BTreeMap<CxId, Consequence>,
) {
    if path.contains(&node) {
        return; // cycle guard: never revisit a node on the current path
    }
    path.push(node);

    // Resolve the node's grounded evidence, folding in cohort peers only for the
    // seed itself when its direct history is thin (clearly marked).
    let (node_evidence, cohort_used) = resolve_evidence(evidence, request, config, seed, node);

    let (p, evidence_n, trust, grounded) = match &node_evidence {
        Some(ev) => {
            let ceiled = ev.ceiled_confidence(config);
            let trust = if cohort_used {
                TrustTag::Provisional
            } else {
                ev.trust
            };
            (attenuation * ceiled, ev.n, trust, true)
        }
        None => {
            // Structural-only leaf: provisional default, provisional trust.
            (
                attenuation * config.provisional_confidence(),
                0,
                TrustTag::Provisional,
                false,
            )
        }
    };

    let trust = if config.advertise_grounded {
        trust
    } else {
        TrustTag::Provisional
    };

    // Prune weak branches — dropped and never expanded.
    if p < config.prune_floor() {
        path.pop();
        return;
    }

    // Emit (or improve) this consequence, keeping the highest-probability path.
    let candidate = Consequence {
        target: node,
        p,
        hop_path: path.clone(),
        evidence_n,
        trust,
        grounded,
        cohort: cohort_used,
    };
    match best.get(&node) {
        Some(existing) if existing.p >= p => {}
        _ => {
            best.insert(node, candidate);
        }
    }

    // Only grounded nodes expand, and only within the depth bound.
    if grounded && hop < config.max_depth {
        let children: Vec<CxId> = graph.propagation_children(node).collect();
        for child in children {
            walk(
                graph,
                evidence,
                request,
                config,
                seed,
                child,
                hop + 1,
                attenuation * config.attenuation(),
                path,
                best,
            );
        }
    }

    path.pop();
}

/// Resolves a node's grounded evidence. For the seed with thin direct history,
/// the L2-similar cohort's distinct outcomes are folded in and the second element of
/// the return is `true` (clearly-marked cohort evidence).
fn resolve_evidence(
    evidence: &OracleEvidence,
    request: &PredictRequest,
    config: &PredictConfig,
    seed: CxId,
    node: CxId,
) -> (Option<NodeEvidence>, bool) {
    let direct = evidence.node(node).cloned();
    // Cohort backfill applies only to the seed node and only when it is thin.
    if node == seed {
        let thin =
            direct.as_ref().map(|e| e.n).unwrap_or(0) < config.cohort_thin_threshold as usize;
        if thin && let Some(peers) = request.cohort_peers.get(&seed) {
            let mut merged = direct.clone();
            let mut folded = false;
            for peer in peers.iter().copied().collect::<BTreeSet<_>>() {
                if peer != seed
                    && let Some(peer_ev) = evidence.node(peer)
                {
                    merged = Some(merge_evidence(merged, peer_ev));
                    folded = true;
                }
            }
            if folded {
                return (merged, true);
            }
        }
    }
    (direct, false)
}

fn merge_evidence(base: Option<NodeEvidence>, add: &NodeEvidence) -> NodeEvidence {
    match base {
        None => NodeEvidence {
            trust: TrustTag::Provisional,
            ..add.clone()
        },
        Some(b) => NodeEvidence {
            n: b.n + add.n,
            fail_mass: b.fail_mass + add.fail_mass,
            pass_mass: b.pass_mass + add.pass_mass,
            n_fail: b.n_fail + add.n_fail,
            n_pass: b.n_pass + add.n_pass,
            // Cohort backfill is never Trusted: it borrows a peer's history.
            trust: TrustTag::Provisional,
        },
    }
}

// ---------------------------------------------------------------------------
// Backtest gate (blueprint 11_ORACLE §2, capability 12.7)
// ---------------------------------------------------------------------------

/// One source-proven held-out historical case. It is derivable only from a
/// failed `TestPass` anchor with a nonempty `ci:` run identity, an exact graph-
/// proven test CxId, and one unambiguous credited Git change on the subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacktestCase {
    pub case_id: String,
    pub outcome_id: OutcomeId,
    pub change_id: String,
    pub change_ts: Ts,
    pub outcome_ts: Ts,
    pub run_identity: String,
    pub seed: CxId,
    pub actually_failing_test: CxId,
}

/// A backtest report over one corpus's held-out fix-commits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BacktestReport {
    /// Exact source-proven cases in chronological/case-id order.
    pub case_identities: Vec<BacktestCase>,
    /// Held-out cases scored.
    pub cases: usize,
    /// Failed outcome groups that lacked a graph-proven test identity.
    pub excluded_missing_test_identity: usize,
    /// Failed test groups whose source was not a nonempty `ci:` run identity.
    pub excluded_missing_run_identity: usize,
    /// Failed test groups with more than one candidate Git change; selecting a
    /// cause would manufacture a label, so they cannot become cases.
    pub excluded_ambiguous_change: usize,
    /// Cases where the grounded predictor ranked the failing test in the top-k.
    pub grounded_top_k_hits: usize,
    /// Cases where the hop-distance baseline ranked it in the top-k.
    pub baseline_top_k_hits: usize,
    /// Grounded top-k hit rate.
    pub grounded_top_k_rate: f64,
    /// Baseline top-k hit rate.
    pub baseline_top_k_rate: f64,
    /// Whether grounded strictly beat the hop-distance baseline.
    pub beats_baseline: bool,
    /// Whether the grounded top-k rate met the success target (≥ 0.60).
    pub meets_top_k_target: bool,
    /// Exact production admission verdict: at least one real case, grounded
    /// top-k ≥60%, and a strict hit-count win over the same-case baseline.
    pub admitted: bool,
    /// Coded reason when admission is unrepresentable or the measured criteria
    /// fail. Absence means `admitted=true`.
    pub refusal_code: Option<String>,
    /// The top-k used (declared knob).
    pub top_k: usize,
    /// Exact candidate/ranking contract used by the topology comparator.
    pub baseline_candidate_contract: String,
}

/// Success target for the top-k metric (success criterion 01 §6.3): the
/// actually-failing test is ranked top-k for at least 60% of backtested
/// fix-commits on a passing corpus.
pub const ORACLE_BACKTEST_TOP_K_SUCCESS_RATE: f64 = 0.60;
/// Integer form used by the authoritative admission predicate.
pub const ORACLE_BACKTEST_TOP_K_SUCCESS_PERMILLE: u64 = 600;
/// The baseline traverses propagation nodes but ranks only reachable TESTS
/// targets. Non-test intermediates never consume a top-k position.
pub const ORACLE_BACKTEST_BASELINE_CANDIDATE_CONTRACT: &str =
    "reachable_tests_only; min_directed_propagation_hops_plus_tests_edge; tie=cx_id";

struct ReplayGroup<'a> {
    subject: CxId,
    outcome_id: OutcomeId,
    outcome_ts: Ts,
    rows: Vec<&'a OccurrenceRecord>,
}

fn backtest_case_id(
    outcome_id: &OutcomeId,
    change_id: &str,
    change_ts: Ts,
    outcome_ts: Ts,
    run_identity: &str,
    seed: CxId,
    test: CxId,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"astrolabe.oracle-held-out-case.v1");
    for part in [
        outcome_id.as_str().as_bytes(),
        change_id.as_bytes(),
        &change_ts.to_be_bytes(),
        &outcome_ts.to_be_bytes(),
        run_identity.as_bytes(),
        seed.as_bytes(),
        test.as_bytes(),
    ] {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().to_hex().to_string()
}

fn replay_groups(records: &[OccurrenceRecord]) -> Result<Vec<ReplayGroup<'_>>, OracleError> {
    let validated = crate::gate::validated_outcome_groups(records)?;
    let mut by_identity: BTreeMap<(CxId, OutcomeId), Vec<&OccurrenceRecord>> = BTreeMap::new();
    for record in records {
        by_identity
            .entry((record.subject, record.outcome_id.clone()))
            .or_default()
            .push(record);
    }
    if by_identity.len() != validated.len() {
        return Err(predict_error(
            ASTRO_ORACLE_ROW_CORRUPT,
            "validated Oracle group count differs from chronological replay grouping",
        ));
    }
    let mut groups = by_identity
        .into_iter()
        .map(|((subject, outcome_id), mut rows)| {
            rows.sort_by(|left, right| {
                (left.lag_s, left.change_ts, left.change_id.as_str()).cmp(&(
                    right.lag_s,
                    right.change_ts,
                    right.change_id.as_str(),
                ))
            });
            ReplayGroup {
                subject,
                outcome_id,
                outcome_ts: rows[0].outcome_ts,
                rows,
            }
        })
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        (left.outcome_ts, left.subject, &left.outcome_id).cmp(&(
            right.outcome_ts,
            right.subject,
            &right.outcome_id,
        ))
    });
    Ok(groups)
}

fn derive_backtest_cases(
    records: &[OccurrenceRecord],
) -> Result<(Vec<BacktestCase>, usize, usize, usize), OracleError> {
    let groups = crate::gate::validated_outcome_groups(records)?;
    let mut cases = Vec::new();
    let mut missing_test = 0usize;
    let mut missing_run = 0usize;
    let mut ambiguous_change = 0usize;
    for group in groups {
        if group.passed {
            continue;
        }
        let Some(test) = group.test_identity.filter(|identity| {
            group.outcome_kind == AnchorKind::TestPass && *identity == group.outcome_subject
        }) else {
            missing_test = missing_test.checked_add(1).ok_or_else(|| {
                predict_error(
                    ASTRO_ORACLE_ROW_CORRUPT,
                    "missing-test exclusion count overflowed",
                )
            })?;
            continue;
        };
        if !group
            .source
            .strip_prefix("ci:")
            .is_some_and(|identity| !identity.trim().is_empty())
        {
            missing_run = missing_run.checked_add(1).ok_or_else(|| {
                predict_error(
                    ASTRO_ORACLE_ROW_CORRUPT,
                    "missing-run exclusion count overflowed",
                )
            })?;
            continue;
        }
        if group.candidate_count != 1 {
            ambiguous_change = ambiguous_change.checked_add(1).ok_or_else(|| {
                predict_error(
                    ASTRO_ORACLE_ROW_CORRUPT,
                    "ambiguous-change exclusion count overflowed",
                )
            })?;
            continue;
        }
        cases.push(BacktestCase {
            case_id: backtest_case_id(
                &group.outcome_id,
                &group.change_id,
                group.change_ts,
                group.outcome_ts,
                &group.source,
                group.subject,
                test,
            ),
            outcome_id: group.outcome_id,
            change_id: group.change_id,
            change_ts: group.change_ts,
            outcome_ts: group.outcome_ts,
            run_identity: group.source,
            seed: group.subject,
            actually_failing_test: test,
        });
    }
    cases.sort_by(|left, right| {
        (left.outcome_ts, left.case_id.as_str()).cmp(&(right.outcome_ts, right.case_id.as_str()))
    });
    Ok((cases, missing_test, missing_run, ambiguous_change))
}

/// Runs a chronological held-out backtest derived exclusively from source-
/// proven occurrence groups, comparing the grounded predictor's test-selection
/// ranking against a pure hop-distance baseline.
///
/// For a case observed at `t`, evidence contains only complete outcome groups
/// with `outcome_ts < t`; neither the target row nor any same-timestamp outcome
/// can leak into training. Groups are admitted once as time advances, so the
/// corpus is not rescanned per case (PC-04/PC-16/PC-38).
pub fn run_backtest(
    graph: &ConsequenceGraph,
    records: &[OccurrenceRecord],
    config: &PredictConfig,
) -> Result<BacktestReport, OracleError> {
    config.validate()?;
    let groups = replay_groups(records)?;
    let (
        cases,
        excluded_missing_test_identity,
        excluded_missing_run_identity,
        excluded_ambiguous_change,
    ) = derive_backtest_cases(records)?;
    let top_k = config.backtest_top_k as usize;
    let mut grounded_hits = 0usize;
    let mut baseline_hits = 0usize;
    let mut evidence = OracleEvidence::default();
    let mut next_group = 0usize;
    let mut baseline_by_seed: BTreeMap<CxId, Vec<CxId>> = BTreeMap::new();

    for case in &cases {
        while next_group < groups.len() && groups[next_group].outcome_ts < case.outcome_ts {
            let group = &groups[next_group];
            let node = NodeEvidence::from_records(group.rows.iter().copied())?;
            evidence.insert_historical_group(group.subject, node)?;
            next_group += 1;
        }
        let request = PredictRequest {
            seeds: vec![case.seed],
            cohort_peers: BTreeMap::new(),
        };
        if let ImpactOutcome::Grounded(prediction) =
            predict_impact(graph, &evidence, &request, config)?
        {
            let grounded_rank = prediction
                .test_selection
                .iter()
                .position(|t| t.test == case.actually_failing_test);
            if matches!(grounded_rank, Some(rank) if rank < top_k) {
                grounded_hits += 1;
            }
        }

        if !baseline_by_seed.contains_key(&case.seed) {
            baseline_by_seed.insert(case.seed, hop_distance_test_ranking(graph, case.seed)?);
        }
        let ranked = baseline_by_seed.get(&case.seed).ok_or_else(|| {
            predict_error(
                ASTRO_ORACLE_GRAPH_INVALID,
                "test-only baseline memo disappeared after deterministic insertion",
            )
        })?;
        let baseline_rank = ranked
            .iter()
            .position(|node| *node == case.actually_failing_test);
        if matches!(baseline_rank, Some(rank) if rank < top_k) {
            baseline_hits += 1;
        }
    }

    let denominator = cases.len();
    let grounded_rate = if denominator == 0 {
        0.0
    } else {
        grounded_hits as f64 / denominator as f64
    };
    let baseline_rate = if denominator == 0 {
        0.0
    } else {
        baseline_hits as f64 / denominator as f64
    };
    let beats_baseline = denominator > 0 && grounded_hits > baseline_hits;
    let meets_top_k_target = denominator > 0
        && (grounded_hits as u128) * 1_000
            >= (denominator as u128) * u128::from(ORACLE_BACKTEST_TOP_K_SUCCESS_PERMILLE);
    let admitted = beats_baseline && meets_top_k_target;
    let refusal_code = (!admitted).then(|| {
        if denominator == 0 {
            ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED.to_string()
        } else if !beats_baseline {
            crate::gate::ASTRO_ORACLE_BACKTEST_NOT_BEATEN.to_string()
        } else {
            ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED.to_string()
        }
    });
    Ok(BacktestReport {
        case_identities: cases.clone(),
        cases: denominator,
        excluded_missing_test_identity,
        excluded_missing_run_identity,
        excluded_ambiguous_change,
        grounded_top_k_hits: grounded_hits,
        baseline_top_k_hits: baseline_hits,
        grounded_top_k_rate: grounded_rate,
        baseline_top_k_rate: baseline_rate,
        beats_baseline,
        meets_top_k_target,
        admitted,
        refusal_code,
        top_k,
        baseline_candidate_contract: ORACLE_BACKTEST_BASELINE_CANDIDATE_CONTRACT.to_string(),
    })
}

/// The pre-oracle hop-distance baseline over the same semantic candidate class
/// as `test_selection`: reachable TESTS targets only. Propagation nodes carry
/// distance but never occupy a top-k position.
fn hop_distance_test_ranking(
    graph: &ConsequenceGraph,
    seed: CxId,
) -> Result<Vec<CxId>, OracleError> {
    let mut distance: BTreeMap<CxId, usize> = BTreeMap::new();
    let mut frontier = vec![seed];
    distance.insert(seed, 0);
    let mut depth = 0usize;
    while !frontier.is_empty() {
        depth = depth.checked_add(1).ok_or_else(|| {
            predict_error(
                ASTRO_ORACLE_GRAPH_INVALID,
                "test-only baseline propagation depth overflowed usize",
            )
        })?;
        let mut next = Vec::new();
        for node in frontier {
            if let Some(children) = graph.propagation.get(&node) {
                for &child in children {
                    if let std::collections::btree_map::Entry::Vacant(entry) = distance.entry(child)
                    {
                        entry.insert(depth);
                        next.push(child);
                    }
                }
            }
        }
        frontier = next;
    }
    let mut best_test_distance = BTreeMap::<CxId, usize>::new();
    for (covered, propagation_hops) in distance {
        for test in graph.covering_tests(covered) {
            let test_hops = propagation_hops.checked_add(1).ok_or_else(|| {
                predict_error(
                    ASTRO_ORACLE_GRAPH_INVALID,
                    "test-only baseline TESTS hop overflowed usize",
                )
            })?;
            best_test_distance
                .entry(test)
                .and_modify(|current| *current = (*current).min(test_hops))
                .or_insert(test_hops);
        }
    }
    let mut ranked = best_test_distance
        .into_iter()
        .map(|(test, distance)| (distance, test))
        .collect::<Vec<_>>();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    Ok(ranked.into_iter().map(|(_, node)| node).collect())
}

/// The P7 phase exit gate: grounded mode is enabled for the phase only when the
/// grounded predictor beats the hop-distance baseline on at least
/// `required` of the pinned corpora (blueprint: ≥ 2 of 3).
pub fn backtest_phase_gate(reports: &[BacktestReport], required: usize) -> bool {
    reports.iter().filter(|report| report.admitted).count() >= required
}
