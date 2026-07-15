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
use calyx_core::{Clock, CxId};

use crate::corpus::{OccurrenceRecord, OracleError, read_occurrence_rows};

// ---------------------------------------------------------------------------
// Stable failure codes
// ---------------------------------------------------------------------------

/// Stable failure code for an out-of-bounds prediction configuration.
pub const ASTRO_ORACLE_PREDICT_CONFIG_INVALID: &str = "ASTRO_ORACLE_PREDICT_CONFIG_INVALID";
/// Stable failure code for a structurally invalid consequence-graph edge.
pub const ASTRO_ORACLE_GRAPH_INVALID: &str = "ASTRO_ORACLE_GRAPH_INVALID";
/// Stable failure code for an empty or malformed predict request.
pub const ASTRO_ORACLE_PREDICT_REQUEST_INVALID: &str = "ASTRO_ORACLE_PREDICT_REQUEST_INVALID";

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
pub const ORACLE_PREDICT_KNOB_REGISTRY_VERSION: &str = "astrolabe-oracle-predict-knobs-v1";

/// Name of the per-hop attenuation knob (permille).
pub const ORACLE_IMPACT_ATTENUATION_PERMILLE_KNOB: &str = "oracle_impact_attenuation_permille";
/// Name of the prune-floor knob (permille).
pub const ORACLE_IMPACT_PRUNE_FLOOR_PERMILLE_KNOB: &str = "oracle_impact_prune_floor_permille";
/// Name of the max butterfly depth knob (hops).
pub const ORACLE_IMPACT_MAX_DEPTH_KNOB: &str = "oracle_impact_max_depth";
/// Name of the sample-support Laplace smoothing knob (occurrences).
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
/// Name of the grounded-evidence floor knob (occurrences).
pub const ORACLE_IMPACT_EVIDENCE_FLOOR_KNOB: &str = "oracle_impact_evidence_floor";
/// Name of the cohort-thinness threshold knob (occurrences).
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
        unit: "occurrences",
        source: "Laplace/additive smoothing (add-k) applied to the sample-support factor n/(n+k)",
        rationale: "discounts thin evidence: with k=1 a single observation yields sample_support 0.5 and the factor saturates toward 1 as evidence accumulates, so one lucky occurrence cannot mint a confident prediction; replace with a measured value once the count-to-reliability curve is benchmarked",
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
        unit: "occurrences",
        source: "ASTROLABE #49 corpus min-edge-support floor (3) reused as the predict grounded-speech floor",
        rationale: "predict_impact refuses (Insufficient, per-sensor deficit) unless the seeds carry at least this many grounded occurrences between them, so it never advertises a grounded consequence tree built on one or two coincidences; matches the corpus's own edge-support floor; replace with a measured value once refusal precision is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
        name: ORACLE_IMPACT_COHORT_THIN_THRESHOLD_KNOB,
        default: 3,
        min: 1,
        max: 1_000_000,
        unit: "occurrences",
        source: "ASTROLABE blueprint 11_ORACLE §2 direct evidence: fold L2-similar peers when thin",
        rationale: "when a seed's own direct history is thinner than this, the L2-similar cohort's occurrences are folded in and the consequence is clearly marked cohort evidence with trust downgraded to provisional; matches the evidence floor so cohort backfill and the refusal gate agree; replace with a measured thinness threshold once cohort lift is benchmarked",
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            advertise_grounded: true,
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
    hop_distance_edges: BTreeMap<CxId, BTreeSet<CxId>>,
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
                // The undirected reach used by the hop-distance baseline.
                graph
                    .hop_distance_edges
                    .entry(edge.from)
                    .or_default()
                    .insert(edge.to);
            } else {
                graph.tests.entry(edge.from).or_default().insert(edge.to);
                // A subject reaches its covering test in one hop, for the baseline.
                graph
                    .hop_distance_edges
                    .entry(edge.from)
                    .or_default()
                    .insert(edge.to);
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
    /// Number of attributed occurrences on this subject.
    pub n: usize,
    /// Credit-weighted mass of failing outcomes.
    pub fail_mass: f64,
    /// Credit-weighted mass of passing outcomes.
    pub pass_mass: f64,
    /// Count of failing occurrences (for the pairwise self-consistency).
    pub n_fail: usize,
    /// Count of passing occurrences.
    pub n_pass: usize,
    /// Rolled-up trust over the contributing occurrences' catalog trust.
    pub trust: TrustTag,
}

impl NodeEvidence {
    fn from_records<'a>(records: impl Iterator<Item = &'a OccurrenceRecord>) -> Self {
        let mut n = 0usize;
        let mut fail_mass = 0.0f64;
        let mut pass_mass = 0.0f64;
        let mut n_fail = 0usize;
        let mut n_pass = 0usize;
        let mut trusts = Vec::new();
        for record in records {
            n += 1;
            if record.passed {
                pass_mass += record.credit;
                n_pass += 1;
            } else {
                fail_mass += record.credit;
                n_fail += 1;
            }
            trusts.push(record.trust);
        }
        NodeEvidence {
            n,
            fail_mass,
            pass_mass,
            n_fail,
            n_pass,
            trust: rollup_trust(trusts),
        }
    }

    fn credit_mass(&self) -> f64 {
        self.fail_mass + self.pass_mass
    }

    fn fail_rate(&self) -> f64 {
        let mass = self.credit_mass();
        if mass > 0.0 {
            self.fail_mass / mass
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
        let pairs = self.n.checked_mul(self.n.saturating_sub(1)).unwrap_or(0) / 2;
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

fn choose2(k: usize) -> usize {
    k.saturating_mul(k.saturating_sub(1)) / 2
}

/// A grounded-evidence index over occurrence records, keyed by subject.
#[derive(Debug, Clone, Default)]
pub struct OracleEvidence {
    by_subject: BTreeMap<CxId, NodeEvidence>,
}

impl OracleEvidence {
    /// Builds the index from in-memory occurrence records.
    pub fn from_occurrences(records: &[OccurrenceRecord]) -> Self {
        let mut grouped: BTreeMap<CxId, Vec<&OccurrenceRecord>> = BTreeMap::new();
        for record in records {
            grouped.entry(record.subject).or_default().push(record);
        }
        let by_subject = grouped
            .into_iter()
            .map(|(subject, recs)| (subject, NodeEvidence::from_records(recs.into_iter())))
            .collect();
        OracleEvidence { by_subject }
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
        Ok(OracleEvidence::from_occurrences(&records))
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
    /// Number of grounded occurrences backing this node (`0` = structural-only).
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
    /// Grounded occurrences available on this sensor.
    pub have: usize,
    /// Grounded occurrences required before the tool will speak.
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
    /// Number of grounded occurrences backing the risk (`0` = hop fallback).
    pub evidence_n: usize,
}

/// Computes the grounded change risk for one subject.
///
/// * **Grounded** (subject carries at least the evidence floor of occurrences):
///   the risk is the subject's ceiling-capped failure-association confidence, with
///   the evidence's trust (or `Provisional` when grounded mode is off).
/// * **Thin** (subject carries some but fewer than the floor occurrences): still a
///   probability from evidence, but labeled `Provisional`.
/// * **Ungrounded** (no occurrences): the `fallback_hop_risk` heuristic, clamped
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
    let ceiling = config.max_confidence();
    match evidence.node(subject) {
        Some(node) => {
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
                risk: fallback_hop_risk.min(ceiling),
                ceiling,
                trust: TrustTag::Provisional,
                grounded: false,
                evidence_n: 0,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// predict_impact
// ---------------------------------------------------------------------------

/// Predicts the grounded consequence tree of changing `request.seeds`.
///
/// Returns [`ImpactOutcome::Insufficient`] when the seeds carry fewer than the
/// declared evidence floor of grounded occurrences between them (a labeled
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
        for &seed in &seeds {
            for peer in request.cohort_peers.get(&seed).into_iter().flatten() {
                if let Some(node) = evidence.node(*peer) {
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
/// the L2-similar cohort's occurrences are folded in and the second element of
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
            for peer in peers {
                if let Some(peer_ev) = evidence.node(*peer) {
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

/// One held-out historical fix-commit: changing `seed` actually broke
/// `actually_failing_test`. The backtest asks whether the predictor ranks that
/// test near the top of its selection set.
#[derive(Debug, Clone, PartialEq)]
pub struct BacktestCase {
    pub seed: CxId,
    pub actually_failing_test: CxId,
}

/// A backtest report over one corpus's held-out fix-commits.
#[derive(Debug, Clone, PartialEq)]
pub struct BacktestReport {
    /// Held-out cases scored.
    pub cases: usize,
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
    /// The top-k used (declared knob).
    pub top_k: usize,
}

/// Success target for the top-k metric (success criterion 01 §6.3): the
/// actually-failing test is ranked top-k for at least 60% of backtested
/// fix-commits on a passing corpus.
pub const ORACLE_BACKTEST_TOP_K_SUCCESS_RATE: f64 = 0.60;

/// Runs a held-out backtest over `cases`, comparing the grounded predictor's
/// test-selection ranking against a pure hop-distance baseline.
///
/// The grounded ranking is the `predict_impact` test-selection set (ranked by
/// probability). The baseline ranks the same reachable tests by ascending
/// hop-distance from the seed (topology only, the pre-oracle `detect_changes`
/// behavior). A case is a hit when the actually-failing test lands within the
/// top-k of the respective ranking.
pub fn run_backtest(
    graph: &ConsequenceGraph,
    evidence: &OracleEvidence,
    cases: &[BacktestCase],
    config: &PredictConfig,
) -> Result<BacktestReport, OracleError> {
    config.validate()?;
    let top_k = config.backtest_top_k as usize;
    let mut grounded_hits = 0usize;
    let mut baseline_hits = 0usize;

    for case in cases {
        // Grounded ranking.
        let request = PredictRequest {
            seeds: vec![case.seed],
            cohort_peers: BTreeMap::new(),
        };
        if let ImpactOutcome::Grounded(prediction) =
            predict_impact(graph, evidence, &request, config)?
        {
            let grounded_rank = prediction
                .test_selection
                .iter()
                .position(|t| t.test == case.actually_failing_test);
            if matches!(grounded_rank, Some(rank) if rank < top_k) {
                grounded_hits += 1;
            }
        }

        // Hop-distance baseline ranking (topology only).
        let ranked = hop_distance_ranking(graph, case.seed);
        let baseline_rank = ranked
            .iter()
            .position(|node| *node == case.actually_failing_test);
        if matches!(baseline_rank, Some(rank) if rank < top_k) {
            baseline_hits += 1;
        }
    }

    let n = cases.len().max(1) as f64;
    let grounded_rate = grounded_hits as f64 / n;
    let baseline_rate = baseline_hits as f64 / n;
    Ok(BacktestReport {
        cases: cases.len(),
        grounded_top_k_hits: grounded_hits,
        baseline_top_k_hits: baseline_hits,
        grounded_top_k_rate: grounded_rate,
        baseline_top_k_rate: baseline_rate,
        beats_baseline: grounded_rate > baseline_rate,
        meets_top_k_target: grounded_rate >= ORACLE_BACKTEST_TOP_K_SUCCESS_RATE,
        top_k,
    })
}

/// The pre-oracle hop-distance baseline: every node reachable from `seed`,
/// ordered by ascending BFS hop distance (nearest first), ties broken by CxId.
/// This is the "topology, not evidence" ranking `predict_impact` must beat.
fn hop_distance_ranking(graph: &ConsequenceGraph, seed: CxId) -> Vec<CxId> {
    let mut distance: BTreeMap<CxId, usize> = BTreeMap::new();
    let mut frontier = vec![seed];
    distance.insert(seed, 0);
    let mut depth = 0usize;
    while !frontier.is_empty() {
        depth += 1;
        let mut next = Vec::new();
        for node in frontier {
            if let Some(children) = graph.hop_distance_edges.get(&node) {
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
    // Exclude the seed itself; rank the rest by (distance, CxId).
    let mut ranked: Vec<(usize, CxId)> = distance
        .into_iter()
        .filter(|(node, _)| *node != seed)
        .map(|(node, dist)| (dist, node))
        .collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    ranked.into_iter().map(|(_, node)| node).collect()
}

/// The P7 phase exit gate: grounded mode is enabled for the phase only when the
/// grounded predictor beats the hop-distance baseline on at least
/// `required` of the pinned corpora (blueprint: ≥ 2 of 3).
pub fn backtest_phase_gate(reports: &[BacktestReport], required: usize) -> bool {
    reports.iter().filter(|r| r.beats_baseline).count() >= required
}
