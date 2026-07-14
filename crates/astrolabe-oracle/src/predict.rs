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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::{
        AttributionConfig, ChangeEvent, OutcomeEvent, mine_occurrences, persist_corpus,
    };

    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use calyx_aster::vault::{AsterVault, VaultOptions};
    use calyx_core::{SystemClock, Ts, VaultId};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
    const TEST_SALT: &[u8] = b"astrolabe-oracle-predict-fsv";

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    impl std::ops::Deref for TempDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }
    fn temp_dir(name: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "astrolabe-oracle-predict-{name}-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }
    fn open_vault(dir: &Path) -> AsterVault<SystemClock> {
        AsterVault::new_durable(
            dir,
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<VaultId>().unwrap(),
            TEST_SALT.to_vec(),
            VaultOptions::default(),
        )
        .expect("open durable predict test vault")
    }

    fn cx(byte: u8) -> CxId {
        CxId::from_bytes([byte; 16])
    }
    fn change(id: &str, subject: CxId, ts: Ts) -> ChangeEvent {
        ChangeEvent {
            change_id: id.to_string(),
            subject,
            change_ts: ts,
        }
    }
    fn outcome(source: &str, subject: CxId, ts: Ts, passed: bool) -> OutcomeEvent {
        OutcomeEvent {
            source: source.to_string(),
            subject,
            outcome_ts: ts,
            passed,
        }
    }
    fn edge(from: CxId, to: CxId, kind: ConsequenceEdgeKind) -> ConsequenceEdge {
        ConsequenceEdge { from, to, kind }
    }

    /// Builds occurrence records directly on a subject: `n_fail` fails then
    /// `n_pass` passes, each a single-candidate outcome (credit 1.0), all from a
    /// Trusted `ci:` source, spaced one hour apart inside the window.
    fn records_on(subject: CxId, base: Ts, n_fail: usize, n_pass: usize) -> Vec<OccurrenceRecord> {
        let config = AttributionConfig::default();
        let mut changes = Vec::new();
        let mut outcomes = Vec::new();
        let total = n_fail + n_pass;
        // Space each change→outcome pair 30 days apart — beyond the 14-day
        // attribution window — so every outcome attributes to exactly one change.
        const PAIR_SPACING_SECS: u64 = 30 * 24 * 60 * 60;
        for i in 0..total {
            let change_ts = base + (i as u64) * PAIR_SPACING_SECS;
            let outcome_ts = change_ts + 3_600; // 1h lag, single in-window candidate
            let passed = i >= n_fail;
            changes.push(change(&format!("chg-{subject}-{i}"), subject, change_ts));
            outcomes.push(outcome(
                &format!("ci:bt:{subject}-{i}"),
                subject,
                outcome_ts,
                passed,
            ));
        }
        let recs = mine_occurrences(&changes, &outcomes, &config).expect("mine records_on");
        assert_eq!(
            recs.len(),
            total,
            "one single-candidate occurrence per outcome"
        );
        for r in &recs {
            assert_eq!(r.credit, 1.0, "single-candidate credit is 1.0");
            assert_eq!(r.trust, TrustTag::Trusted);
        }
        recs
    }

    // ------------------------------------------------------------------
    // Knob registry sanity (standing invariant 4)
    // ------------------------------------------------------------------

    #[test]
    fn every_predict_knob_declares_bounds_that_contain_its_default() {
        assert!(!ORACLE_PREDICT_KNOBS.is_empty());
        for knob in ORACLE_PREDICT_KNOBS {
            assert_eq!(
                knob.registry_version, ORACLE_PREDICT_KNOB_REGISTRY_VERSION,
                "{knob:?}"
            );
            assert!(knob.min <= knob.max, "{knob:?}");
            assert!(knob.accepts(knob.default), "{knob:?}");
            assert!(!knob.unit.is_empty(), "{knob:?}");
            assert!(!knob.source.is_empty(), "{knob:?}");
            assert!(!knob.rationale.is_empty(), "{knob:?}");
        }
        // The blueprint's ×0.7 attenuation, <0.05 prune, and never-1.0 cap are
        // all pinned as declared knobs strictly inside (0, 1).
        let attenuation = predict_knob(ORACLE_IMPACT_ATTENUATION_PERMILLE_KNOB);
        assert_eq!(attenuation.default, 700);
        assert!(attenuation.max < 1000, "attenuation strictly contractive");
        assert_eq!(
            predict_knob(ORACLE_IMPACT_PRUNE_FLOOR_PERMILLE_KNOB).default,
            50
        );
        assert!(predict_knob(ORACLE_IMPACT_MAX_CONFIDENCE_PERMILLE_KNOB).max < 1000);
        PredictConfig::default()
            .validate()
            .expect("default validates");
    }

    // ------------------------------------------------------------------
    // DoD 1: tree mechanics golden — exact shape, attenuation, prune, cycle
    // ------------------------------------------------------------------

    #[test]
    fn tree_mechanics_golden_pins_shape_attenuation_prune_and_cycle() {
        let config = PredictConfig::default();
        let base = 1_000_000_000u64;

        // Hand-computable evidence:
        //  seed A (cx1): 4 fails, 0 pass  -> raw 0.8, sc 1.0, dpi 0.8 => ceiled 0.8
        //  child B (cx2): 2 fails, 1 pass -> raw 1/6, sc 1/3, dpi 0.75 => ceiled 1/6
        //  grandchild C (cx3): structural-only (no evidence) -> provisional leaf
        //  D (cx4): reachable only past the prune floor, to pin pruning
        let mut records = Vec::new();
        records.extend(records_on(cx(1), base, 4, 0));
        records.extend(records_on(cx(2), base, 2, 1));
        // cx3 has NO evidence (structural-only). cx4 has weak evidence that will
        // be pruned after two hops of attenuation.
        records.extend(records_on(cx(4), base, 1, 0)); // raw: support1*sep1*ss(1/2)=0.5, but 3 hops
        let evidence = OracleEvidence::from_occurrences(&records);

        // Graph:  A -calls-> B -calls-> C (structural-only leaf, no expand)
        //         A -calls-> B -dataflow-> A  (cycle: guarded)
        //         B -calls-> D  (deep, gets pruned by attenuation)
        //         B -tests-> Tb ; A -tests-> Ta   (test-selection edges)
        let graph = ConsequenceGraph::from_edges(&[
            edge(cx(1), cx(2), ConsequenceEdgeKind::Calls),
            edge(cx(2), cx(3), ConsequenceEdgeKind::Calls),
            edge(cx(2), cx(1), ConsequenceEdgeKind::DataFlow), // back-edge => cycle
            edge(cx(2), cx(4), ConsequenceEdgeKind::Calls),
            edge(cx(1), cx(20), ConsequenceEdgeKind::Tests), // Ta covers A
            edge(cx(2), cx(21), ConsequenceEdgeKind::Tests), // Tb covers B
        ])
        .expect("graph");

        let request = PredictRequest {
            seeds: vec![cx(1)],
            cohort_peers: BTreeMap::new(),
        };
        let ImpactOutcome::Grounded(prediction) =
            predict_impact(&graph, &evidence, &request, &config).expect("predict")
        else {
            panic!("seed A has ample evidence; must be Grounded");
        };

        // --- Seed A: hop 0, p = ceiled 0.8 exactly. ---
        let a = prediction
            .consequences
            .iter()
            .find(|c| c.target == cx(1))
            .expect("A present");
        assert!((a.p - 0.8).abs() < 1e-12, "A p = 0.8, got {}", a.p);
        assert_eq!(a.hop_path, vec![cx(1)]);
        assert_eq!(a.evidence_n, 4);
        assert!(a.grounded);
        assert_eq!(a.trust, TrustTag::Trusted);

        // --- Child B: hop 1, p = 0.7 * (1/6). ---
        let b = prediction
            .consequences
            .iter()
            .find(|c| c.target == cx(2))
            .expect("B present");
        let expected_b = 0.7 * (1.0 / 6.0);
        assert!((b.p - expected_b).abs() < 1e-12, "B p, got {}", b.p);
        assert_eq!(b.hop_path, vec![cx(1), cx(2)]);
        assert_eq!(b.evidence_n, 3);

        // --- Grandchild C: hop 2, structural-only provisional leaf. ---
        let c = prediction
            .consequences
            .iter()
            .find(|c| c.target == cx(3))
            .expect("C present");
        let expected_c = 0.7 * 0.7 * config.provisional_confidence(); // 0.49 * 0.35
        assert!((c.p - expected_c).abs() < 1e-12, "C p, got {}", c.p);
        assert!(!c.grounded, "C is structural-only");
        assert_eq!(c.evidence_n, 0);
        assert_eq!(c.trust, TrustTag::Provisional);

        // --- D at hop 2 from B: p = 0.49 * ceiled(cx4). cx4 raw=0.5,
        //     sc(single-obs)=0.5, dpi=min(1/2,0.99)=0.5 => ceiled 0.5 => 0.245. ---
        let d = prediction
            .consequences
            .iter()
            .find(|c| c.target == cx(4))
            .expect("D present");
        assert!((d.p - 0.49 * 0.5).abs() < 1e-12, "D p, got {}", d.p);

        // --- Cycle guard: A never appears twice; the B->A back-edge is dropped
        //     so A keeps its hop-0 path, never a hop-2 revisit. ---
        assert_eq!(
            a.hop_path,
            vec![cx(1)],
            "cycle guard preserved A's hop-0 path"
        );

        // --- Ranking: A (0.8) > D (0.245) > C (0.1715) > B (0.11667). ---
        let order: Vec<CxId> = prediction.consequences.iter().map(|c| c.target).collect();
        assert_eq!(order, vec![cx(1), cx(4), cx(3), cx(2)], "ranked by p desc");

        // --- Test selection: Ta via A (0.8) ranks above Tb via B. ---
        assert_eq!(prediction.test_selection.len(), 2);
        assert_eq!(prediction.test_selection[0].test, cx(20));
        assert!((prediction.test_selection[0].p - 0.8).abs() < 1e-12);
        assert_eq!(prediction.test_selection[0].via, cx(1));
        assert_eq!(prediction.test_selection[1].test, cx(21));
    }

    #[test]
    fn prune_boundary_is_pinned_at_the_declared_floor() {
        // A node whose attenuated confidence lands just below 0.05 is dropped;
        // nudging the evidence so it lands just above 0.05 makes it appear.
        let config = PredictConfig::default();
        let base = 2_000_000_000u64;

        // seed A: strong evidence so it expands. child B at hop 3:
        // attenuation 0.7^3 = 0.343. To straddle 0.05 the ceiled value must
        // straddle 0.05/0.343 = 0.1458.
        let mut records = Vec::new();
        records.extend(records_on(cx(1), base, 5, 0)); // seed, ceiled ~0.833
        records.extend(records_on(cx(2), base, 5, 0)); // hop1 grounded, expands
        records.extend(records_on(cx(3), base, 5, 0)); // hop2 grounded, expands
        // hop3 node cx4: give it a ceiled value below the straddle -> pruned.
        // 1 fail,3 pass: fail_rate .25 support .25 sep .5 ss 4/5=.8 raw=.1;
        // sc: pairs=6 agree=C(1,2)+C(3,2)=0+3=3 =>0.5; dpi min(4/5,.99)=.8;
        // ceiled=min(.1,.5,.8)=.1; p=0.343*.1=0.0343 < 0.05 => pruned.
        let mut pruned_records = records.clone();
        pruned_records.extend(records_on(cx(4), base, 1, 3));
        let pruned_ev = OracleEvidence::from_occurrences(&pruned_records);

        let graph = ConsequenceGraph::from_edges(&[
            edge(cx(1), cx(2), ConsequenceEdgeKind::Calls),
            edge(cx(2), cx(3), ConsequenceEdgeKind::Calls),
            edge(cx(3), cx(4), ConsequenceEdgeKind::Calls),
        ])
        .expect("graph");
        let request = PredictRequest {
            seeds: vec![cx(1)],
            cohort_peers: BTreeMap::new(),
        };

        let ImpactOutcome::Grounded(pred_pruned) =
            predict_impact(&graph, &pruned_ev, &request, &config).unwrap()
        else {
            panic!("grounded");
        };
        assert!(
            !pred_pruned.consequences.iter().any(|c| c.target == cx(4)),
            "hop-3 node below the 0.05 floor is pruned"
        );

        // Now strengthen cx4 above the floor: all-fail single => ceiled 0.5,
        // p = 0.343*0.5 = 0.1715 > 0.05 => appears.
        let mut kept_records = records;
        kept_records.extend(records_on(cx(4), base, 4, 0));
        let kept_ev = OracleEvidence::from_occurrences(&kept_records);
        let ImpactOutcome::Grounded(pred_kept) =
            predict_impact(&graph, &kept_ev, &request, &config).unwrap()
        else {
            panic!("grounded");
        };
        let d = pred_kept
            .consequences
            .iter()
            .find(|c| c.target == cx(4))
            .expect("cx4 above floor now appears");
        assert!(d.p > config.prune_floor());
    }

    #[test]
    fn depth_bound_terminates_the_walk() {
        // A long grounded chain: only the first max_depth hops are emitted.
        let config = PredictConfig::default();
        let base = 3_000_000_000u64;
        let mut records = Vec::new();
        let mut edges = Vec::new();
        // Chain cx1 -> cx2 -> ... -> cx8, all strongly grounded (all-fail).
        for k in 1..=8u8 {
            records.extend(records_on(cx(k), base, 5, 0));
            if k < 8 {
                edges.push(edge(cx(k), cx(k + 1), ConsequenceEdgeKind::Calls));
            }
        }
        let evidence = OracleEvidence::from_occurrences(&records);
        let graph = ConsequenceGraph::from_edges(&edges).expect("graph");
        let request = PredictRequest {
            seeds: vec![cx(1)],
            cohort_peers: BTreeMap::new(),
        };
        let ImpactOutcome::Grounded(pred) =
            predict_impact(&graph, &evidence, &request, &config).unwrap()
        else {
            panic!("grounded");
        };
        // Seed at hop0 plus max_depth hops => nodes cx1..=cx5 (5 nodes).
        let max_hop = pred
            .consequences
            .iter()
            .map(|c| c.hop_path.len() - 1)
            .max()
            .unwrap();
        assert_eq!(max_hop as u64, config.max_depth, "walk stops at max_depth");
        assert!(pred.consequences.iter().all(|c| c.target != cx(7)));
    }

    // ------------------------------------------------------------------
    // DoD 2: ceiling invariant — no confidence exceeds any of its 3 ceilings,
    // and confidence is always < 1.0 (deterministic sweep of many shapes).
    // ------------------------------------------------------------------

    #[test]
    fn no_confidence_exceeds_its_ceilings_and_never_reaches_one() {
        let config = PredictConfig::default();
        let base = 500_000_000u64;
        // Sweep many (n_fail, n_pass) evidence shapes as the seed and as a hop-1
        // child, asserting the emitted p respects every ceiling and stays < 1.
        for n_fail in 0..=12usize {
            for n_pass in 0..=12usize {
                if n_fail + n_pass == 0 {
                    continue;
                }
                let mut records = Vec::new();
                // Strong seed so the child always expands.
                records.extend(records_on(cx(1), base, 6, 0));
                records.extend(records_on(cx(2), base + 1_000_000, n_fail, n_pass));
                let evidence = OracleEvidence::from_occurrences(&records);
                let graph =
                    ConsequenceGraph::from_edges(&[edge(cx(1), cx(2), ConsequenceEdgeKind::Calls)])
                        .expect("graph");
                let request = PredictRequest {
                    seeds: vec![cx(1)],
                    cohort_peers: BTreeMap::new(),
                };
                let ImpactOutcome::Grounded(pred) =
                    predict_impact(&graph, &evidence, &request, &config).unwrap()
                else {
                    panic!("grounded");
                };
                for consequence in &pred.consequences {
                    assert!(
                        consequence.p < 1.0,
                        "confidence must never reach 1.0, got {} for {:?}",
                        consequence.p,
                        consequence.target
                    );
                    if consequence.grounded {
                        // Reconstruct the node's ceilings and assert p (divided by
                        // its hop attenuation) never exceeds any of the three.
                        let node = evidence.node(consequence.target).unwrap();
                        let hop = (consequence.hop_path.len() - 1) as i32;
                        let attenuation = config.attenuation().powi(hop);
                        let unattenuated = consequence.p / attenuation;
                        let raw = node.raw_confidence(&config);
                        let sc = node.self_consistency(&config);
                        let dpi = node.dpi_ceiling(&config);
                        let eps = 1e-9;
                        assert!(unattenuated <= raw + eps, "exceeds raw");
                        assert!(unattenuated <= sc + eps, "exceeds self_consistency");
                        assert!(unattenuated <= dpi + eps, "exceeds dpi_ceiling");
                        assert!(dpi < 1.0, "dpi ceiling is always < 1.0");
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // DoD 3: grounded-vs-provisional labeling.
    // ------------------------------------------------------------------

    #[test]
    fn grounded_and_structural_only_branches_are_labeled() {
        let config = PredictConfig::default();
        let base = 700_000_000u64;
        // cx1 seed grounded, cx2 grounded child, cx3 structural-only child.
        let mut records = Vec::new();
        records.extend(records_on(cx(1), base, 4, 0));
        records.extend(records_on(cx(2), base, 3, 0));
        let evidence = OracleEvidence::from_occurrences(&records);
        let graph = ConsequenceGraph::from_edges(&[
            edge(cx(1), cx(2), ConsequenceEdgeKind::Calls),
            edge(cx(1), cx(3), ConsequenceEdgeKind::Calls),
        ])
        .expect("graph");
        let request = PredictRequest {
            seeds: vec![cx(1)],
            cohort_peers: BTreeMap::new(),
        };
        let ImpactOutcome::Grounded(pred) =
            predict_impact(&graph, &evidence, &request, &config).unwrap()
        else {
            panic!("grounded");
        };
        let g = pred
            .consequences
            .iter()
            .find(|c| c.target == cx(2))
            .unwrap();
        assert!(g.grounded && g.trust == TrustTag::Trusted && g.evidence_n == 3);
        let s = pred
            .consequences
            .iter()
            .find(|c| c.target == cx(3))
            .unwrap();
        assert!(!s.grounded && s.trust == TrustTag::Provisional && s.evidence_n == 0);

        // advertise_grounded = false forces every branch provisional.
        let gated = PredictConfig {
            advertise_grounded: false,
            ..config
        };
        let ImpactOutcome::Grounded(pred2) =
            predict_impact(&graph, &evidence, &request, &gated).unwrap()
        else {
            panic!("grounded");
        };
        assert!(!pred2.grounded_mode);
        assert!(
            pred2
                .consequences
                .iter()
                .all(|c| c.trust == TrustTag::Provisional),
            "gate closed => all provisional"
        );
    }

    #[test]
    fn thin_seed_folds_clearly_marked_cohort_evidence() {
        let config = PredictConfig::default();
        let base = 800_000_000u64;
        // Seed cx1 has only 1 occurrence (below cohort_thin_threshold 3); its L2
        // peer cx9 has 4. The cohort backfill lets the seed clear the floor and
        // marks the consequence cohort=true, trust downgraded to provisional.
        let mut records = Vec::new();
        records.extend(records_on(cx(1), base, 1, 0));
        records.extend(records_on(cx(9), base, 4, 0));
        let evidence = OracleEvidence::from_occurrences(&records);
        let graph =
            ConsequenceGraph::from_edges(&[edge(cx(1), cx(20), ConsequenceEdgeKind::Tests)])
                .expect("graph");
        let mut cohort = BTreeMap::new();
        cohort.insert(cx(1), vec![cx(9)]);
        let request = PredictRequest {
            seeds: vec![cx(1)],
            cohort_peers: cohort,
        };
        let ImpactOutcome::Grounded(pred) =
            predict_impact(&graph, &evidence, &request, &config).unwrap()
        else {
            panic!("cohort backfill clears the floor => grounded");
        };
        let seed = pred
            .consequences
            .iter()
            .find(|c| c.target == cx(1))
            .unwrap();
        assert!(seed.cohort, "cohort evidence clearly marked");
        assert_eq!(seed.trust, TrustTag::Provisional, "cohort => provisional");
        assert_eq!(seed.evidence_n, 5, "1 direct + 4 cohort folded");
    }

    // ------------------------------------------------------------------
    // DoD 4: refusal — zero-history module => Insufficient w/ per-sensor deficit
    // ------------------------------------------------------------------

    #[test]
    fn zero_history_module_refuses_with_per_sensor_deficit() {
        let config = PredictConfig::default();
        // Evidence exists for other subjects, but the seed cx5 has none.
        let records = records_on(cx(1), 900_000_000, 4, 0);
        let evidence = OracleEvidence::from_occurrences(&records);
        let graph = ConsequenceGraph::from_edges(&[edge(cx(5), cx(6), ConsequenceEdgeKind::Calls)])
            .expect("graph");
        let request = PredictRequest {
            seeds: vec![cx(5)],
            cohort_peers: BTreeMap::new(),
        };
        let outcome = predict_impact(&graph, &evidence, &request, &config).unwrap();
        let ImpactOutcome::Insufficient(report) = outcome else {
            panic!("zero-history seed must refuse, not guess");
        };
        assert_eq!(report.seeds, vec![cx(5)]);
        assert_eq!(report.deficits.len(), 1);
        let deficit = &report.deficits[0];
        assert_eq!(deficit.sensor, ORACLE_SENSOR_DIRECT_CHANGE_HISTORY);
        assert_eq!(deficit.have, 0);
        assert_eq!(deficit.need, config.evidence_floor as usize);
        // bits_short = log2(need+1) - log2(0+1) = log2(4) = 2.0 for floor 3.
        assert!((deficit.bits_short - (config.evidence_floor as f64 + 1.0).log2()).abs() < 1e-12);
        assert_eq!(report.remediation, ORACLE_INSUFFICIENT_REMEDIATION);
        assert!(report.remediation.contains("anchor_outcome"));

        // Empty seed list is a hard, coded refusal (not Insufficient).
        let empty = PredictRequest {
            seeds: vec![],
            cohort_peers: BTreeMap::new(),
        };
        assert_eq!(
            predict_impact(&graph, &evidence, &empty, &config)
                .expect_err("empty seeds")
                .code,
            ASTRO_ORACLE_PREDICT_REQUEST_INVALID
        );

        // Bad config fails closed.
        let bad = PredictConfig {
            attenuation_permille: 0,
            ..config
        };
        assert_eq!(
            predict_impact(&graph, &evidence, &request, &bad)
                .expect_err("bad config")
                .code,
            ASTRO_ORACLE_PREDICT_CONFIG_INVALID
        );

        // Self-loop graph edge fails closed.
        assert_eq!(
            ConsequenceGraph::from_edges(&[edge(cx(1), cx(1), ConsequenceEdgeKind::Calls)])
                .expect_err("self loop")
                .code,
            ASTRO_ORACLE_GRAPH_INVALID
        );
    }

    // ------------------------------------------------------------------
    // DoD 5 + 6: backtest gate over 3 pinned corpora + top-5 metric, FSV.
    // ------------------------------------------------------------------

    /// Builds one backtest corpus where grounded evidence should beat the
    /// hop-distance baseline: the actually-failing test is FAR (many hops) from
    /// the seed but strongly grounded, while several no-evidence tests sit ONE
    /// hop away — so topology ranks the true test low and evidence ranks it high.
    ///
    /// Returns (records, edges, cases).
    fn beating_corpus(
        seed_byte: u8,
        far_test_byte: u8,
        base: Ts,
    ) -> (
        Vec<OccurrenceRecord>,
        Vec<ConsequenceEdge>,
        Vec<BacktestCase>,
    ) {
        let seed = cx(seed_byte);
        let mid = cx(seed_byte.wrapping_add(40));
        let far = cx(seed_byte.wrapping_add(80));
        let far_test = cx(far_test_byte);

        let mut records = Vec::new();
        // Grounded chain seed -> mid -> far, all all-fail (strong).
        records.extend(records_on(seed, base, 6, 0));
        records.extend(records_on(mid, base, 6, 0));
        records.extend(records_on(far, base, 6, 0));

        let mut edges = vec![
            edge(seed, mid, ConsequenceEdgeKind::Calls),
            edge(mid, far, ConsequenceEdgeKind::Calls),
            // The true failing test covers the FAR node (3 hops away).
            edge(far, far_test, ConsequenceEdgeKind::Tests),
        ];
        // Six decoy tests directly covering the seed (1 hop) with NO evidence on
        // their covered nodes, so the hop-distance baseline ranks them ahead of
        // the far test and pushes the true test out of the top-5.
        for d in 0..6u8 {
            let decoy_node = cx(seed_byte.wrapping_add(120).wrapping_add(d));
            let decoy_test = cx(seed_byte.wrapping_add(160).wrapping_add(d));
            edges.push(edge(seed, decoy_node, ConsequenceEdgeKind::Calls));
            edges.push(edge(decoy_node, decoy_test, ConsequenceEdgeKind::Tests));
        }

        let cases = vec![BacktestCase {
            seed,
            actually_failing_test: far_test,
        }];
        (records, edges, cases)
    }

    /// A corpus where grounded does NOT beat the baseline: the true failing test
    /// is one hop from the seed (baseline finds it too), and there are no decoys,
    /// so grounded and baseline tie — beats_baseline is false. This makes the
    /// 2-of-3 phase gate a real gate, not a tautology.
    fn tying_corpus(
        seed_byte: u8,
        test_byte: u8,
        base: Ts,
    ) -> (
        Vec<OccurrenceRecord>,
        Vec<ConsequenceEdge>,
        Vec<BacktestCase>,
    ) {
        let seed = cx(seed_byte);
        let test = cx(test_byte);
        let mut records = Vec::new();
        records.extend(records_on(seed, base, 6, 0));
        let edges = vec![edge(seed, test, ConsequenceEdgeKind::Tests)];
        let cases = vec![BacktestCase {
            seed,
            actually_failing_test: test,
        }];
        (records, edges, cases)
    }

    #[test]
    fn backtest_gate_beats_hop_distance_baseline_on_two_of_three_corpora() {
        let config = PredictConfig::default();
        let corpora = [
            beating_corpus(1, 200, 1_000_000_000),
            beating_corpus(2, 201, 1_100_000_000),
            tying_corpus(3, 202, 1_200_000_000),
        ];
        let mut reports = Vec::new();
        for (records, edges, cases) in &corpora {
            let evidence = OracleEvidence::from_occurrences(records);
            let graph = ConsequenceGraph::from_edges(edges).expect("graph");
            let report = run_backtest(&graph, &evidence, cases, &config).expect("backtest");
            reports.push(report);
        }

        // The two beating corpora: grounded strictly beats hop-distance, and the
        // top-5 metric is met (the true test is ranked top-5, rate 1.0 >= 0.6).
        assert!(
            reports[0].beats_baseline,
            "corpus 0 grounded beats baseline"
        );
        assert!(reports[0].meets_top_k_target);
        assert_eq!(reports[0].grounded_top_k_hits, 1);
        assert_eq!(
            reports[0].baseline_top_k_hits, 0,
            "topology misses the far test"
        );
        assert!(reports[1].beats_baseline);
        assert!(reports[1].meets_top_k_target);
        // The tying corpus: baseline also finds the 1-hop test, so no strict win.
        assert!(!reports[2].beats_baseline, "tie => baseline not beaten");

        // Phase gate: >= 2 of 3 corpora beat the baseline => grounded mode on.
        assert!(
            backtest_phase_gate(&reports, 2),
            "2 of 3 corpora beat baseline => phase gate passes"
        );
        // The gate is real: requiring all 3 would fail.
        assert!(!backtest_phase_gate(&reports, 3));
    }

    #[test]
    fn backtest_reads_evidence_from_a_reopened_vault_fsv() {
        // Full-state verification: mine + persist a beating corpus into a real
        // durable vault, drop it, reopen, rebuild evidence from the persisted
        // occurrence rows, and run the backtest off that read-back state.
        let config = PredictConfig::default();
        let (records, edges, cases) = beating_corpus(7, 210, 1_500_000_000);

        // Persist via the corpus API (occurrences -> Kv rows + ledger).
        let corpus = crate::corpus::OracleCorpus {
            occurrences: records.clone(),
            edges: Vec::new(),
        };
        let dir = temp_dir("bt-fsv");
        let vault = open_vault(&dir);
        let report = persist_corpus(&vault, &corpus, "predict-test").expect("persist");
        assert_eq!(report.occurrence_count, records.len());
        drop(vault);

        // Independent read-back: rebuild the evidence index from durable rows.
        let reopened = open_vault(&dir);
        let evidence = OracleEvidence::from_vault(&reopened).expect("evidence from vault");
        // Every seeded subject is present with the right occurrence count.
        for subject in [cx(7), cx(47), cx(87)] {
            assert!(
                evidence.node(subject).is_some(),
                "persisted subject {subject} read back"
            );
        }

        let graph = ConsequenceGraph::from_edges(&edges).expect("graph");
        let backtest = run_backtest(&graph, &evidence, &cases, &config).expect("backtest");
        assert!(
            backtest.beats_baseline,
            "grounded beats baseline off read-back state"
        );
        assert!(backtest.meets_top_k_target);

        // And a live prediction off the same read-back evidence is grounded and
        // ranks the far test's coverage first.
        let request = PredictRequest {
            seeds: vec![cx(7)],
            cohort_peers: BTreeMap::new(),
        };
        let ImpactOutcome::Grounded(pred) =
            predict_impact(&graph, &evidence, &request, &config).unwrap()
        else {
            panic!("grounded off read-back state");
        };
        assert_eq!(
            pred.test_selection[0].test,
            cx(210),
            "far test ranked first"
        );
        drop(reopened);
    }
}
