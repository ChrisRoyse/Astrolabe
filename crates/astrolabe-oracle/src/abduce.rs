//! Root-cause abduction (`abduce_cause`, blueprint 11_ORACLE §3, capability 7.2).
//!
//! "This failed — what most plausibly caused it?" answered by walking *backward*
//! from an observed failure anchor through the grounded change→outcome corpus
//! mined in [`crate::corpus`] and the composite structural graph shared with
//! [`crate::predict`]. This is the inverse of `predict_impact`: instead of
//! expanding a change forward into consequences, it reverse-walks the propagation
//! edges (depth ≤ [`AbductionConfig::max_depth`]) from the failure to the
//! candidate causes upstream of it, and scores each candidate against the
//! evidence it has actually preceded failures on.
//!
//! ## Reuse (not fork)
//!
//! Abduction is built on the same evidence substrate as prediction: it consumes
//! the corpus's own [`OccurrenceRecord`]s directly (never a re-derived copy) and
//! the same [`ConsequenceEdge`]/[`ConsequenceEdgeKind`] graph vocabulary. Only
//! the walk direction and the scoring differ; the grounding invariants are the
//! same.
//!
//! ## Confidence
//!
//! A candidate cause `C` reachable at reverse depth `d` from the failure `F`:
//!
//! * **grounded** when `C` carries failing occurrences preceding the observation
//!   (`outcome_ts ≤ observed_ts`). Its *fail support* is the recency- and
//!   credit-weighted mass of those failures,
//!   `s = Σ credit · 0.5^((observed − outcome_ts)/half_life)`; its base
//!   confidence is the abundance term `s/(s+1)`, always strictly `< 1.0`.
//! * **structural-only** when `C` is reachable by an edge but has no failing
//!   history: it is emitted as a provisional leaf at the
//!   [`AbductionConfig::provisional_confidence`] default (0.35) and its
//!   confidence never exceeds that cap.
//!
//! The base confidence is attenuated by `depth_attenuation^d` (a cause three hops
//! upstream is a weaker root-cause claim than a direct one). Two independent
//! cross-checks rank a *grounded* candidate up: membership in the caller's
//! recent-change set, and a DRIVES edge running from the candidate into the
//! failure region. Every confidence is finally capped by
//! [`AbductionConfig::max_confidence`] (< 1.0), so no hypothesis is ever certain
//! (HONEST invariant 2). Each hypothesis names its *disconfirming test* — a test
//! covering the candidate whose passing would refute the hypothesis.
//!
//! When the failure's reverse-reachable region carries fewer than
//! [`AbductionConfig::evidence_floor`] failing occurrences in total, the tool
//! refuses with a per-sensor deficit ([`AbductionOutcome::Insufficient`]) rather
//! than abducing from a coincidence.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::TrustTag;
use astrolabe_domain::knobs::U64KnobDeclaration;
use astrolabe_domain::rollup_trust;
use calyx_core::{CxId, Ts};

use crate::corpus::{OccurrenceRecord, OracleError};
use crate::predict::{
    ASTRO_ORACLE_GRAPH_INVALID, ConsequenceEdge, ConsequenceEdgeKind, InsufficientReport,
    SensorDeficit,
};

// ---------------------------------------------------------------------------
// Stable failure codes
// ---------------------------------------------------------------------------

/// Stable failure code for an out-of-bounds abduction configuration.
pub const ASTRO_ORACLE_ABDUCE_CONFIG_INVALID: &str = "ASTRO_ORACLE_ABDUCE_CONFIG_INVALID";
/// Stable failure code for a malformed abduction request.
pub const ASTRO_ORACLE_ABDUCE_REQUEST_INVALID: &str = "ASTRO_ORACLE_ABDUCE_REQUEST_INVALID";

/// Stable deficit-sensor name: grounded failing history in the failure region.
pub const ORACLE_SENSOR_FAILURE_HISTORY: &str = "failure_history";

const ABDUCE_REMEDIATION: &str = "supply a validated AbductionConfig, a well-formed consequence edge set, and a failure \
     anchor; bootstrap grounded history with ingest_outcome_anchors + mine_corpus when the \
     failure region has no change→outcome evidence";

/// Operator-facing bootstrap text emitted with an abduction refusal.
pub const ORACLE_ABDUCE_INSUFFICIENT_REMEDIATION: &str = "No grounded failing history in this failure's region. Record the failing outcome via \
     anchor_outcome (ingest_outcome_anchors) and re-mine the change→outcome corpus with \
     mine_corpus so abduce_cause has failures to reason back from.";

// ---------------------------------------------------------------------------
// Registry-declared abduction knobs (standing invariant 4)
// ---------------------------------------------------------------------------

/// Registry version tag for the root-cause abduction knobs (#51).
pub const ORACLE_ABDUCE_KNOB_REGISTRY_VERSION: &str = "astrolabe-oracle-abduce-knobs-v1";

/// Name of the reverse-walk max-depth knob (hops).
pub const ORACLE_ABDUCE_MAX_DEPTH_KNOB: &str = "oracle_abduce_max_depth";
/// Name of the per-hop depth-attenuation knob (permille).
pub const ORACLE_ABDUCE_DEPTH_ATTENUATION_PERMILLE_KNOB: &str =
    "oracle_abduce_depth_attenuation_permille";
/// Name of the structural-only provisional-confidence knob (permille).
pub const ORACLE_ABDUCE_PROVISIONAL_CONFIDENCE_PERMILLE_KNOB: &str =
    "oracle_abduce_provisional_confidence_permille";
/// Name of the recency half-life knob (seconds).
pub const ORACLE_ABDUCE_RECENCY_HALF_LIFE_SECS_KNOB: &str = "oracle_abduce_recency_half_life_secs";
/// Name of the recent-change cross-check boost knob (permille, 1000 = ×1.0).
pub const ORACLE_ABDUCE_RECENT_CHANGE_BOOST_PERMILLE_KNOB: &str =
    "oracle_abduce_recent_change_boost_permille";
/// Name of the DRIVES-into-failure-region cross-check boost knob (permille).
pub const ORACLE_ABDUCE_DRIVES_BOOST_PERMILLE_KNOB: &str = "oracle_abduce_drives_boost_permille";
/// Name of the hard max-confidence cap knob (permille).
pub const ORACLE_ABDUCE_MAX_CONFIDENCE_PERMILLE_KNOB: &str =
    "oracle_abduce_max_confidence_permille";
/// Name of the prune-floor knob (permille).
pub const ORACLE_ABDUCE_PRUNE_FLOOR_PERMILLE_KNOB: &str = "oracle_abduce_prune_floor_permille";
/// Name of the grounded-evidence floor knob (occurrences).
pub const ORACLE_ABDUCE_EVIDENCE_FLOOR_KNOB: &str = "oracle_abduce_evidence_floor";

/// The root-cause abduction knob registry (#51).
///
/// Depth ≤3 is the blueprint's reverse-walk bound; the ×0.7 depth attenuation and
/// <0.05 prune floor mirror the predict butterfly constants (a cause farther
/// upstream is a weaker claim); the 0.35 provisional default matches the
/// structural-only prior used across the oracle; the recency half-life mirrors
/// the corpus decay; the boosts are seed cross-check multipliers strictly ≥ ×1.0
/// so a cross-check can only rank a cause *up*; and the max-confidence cap keeps
/// every hypothesis strictly below certainty. Every default is a seed to be
/// replaced by a measured value once abduction precision is benchmarked per repo.
pub const ORACLE_ABDUCE_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: ORACLE_ABDUCE_KNOB_REGISTRY_VERSION,
        name: ORACLE_ABDUCE_MAX_DEPTH_KNOB,
        default: 3,
        min: 1,
        max: 8,
        unit: "hops",
        source: "ASTROLABE blueprint 11_ORACLE §3 reverse-walk depth ≤ 3",
        rationale: "the abduction reverse walk climbs at most 3 propagation hops upstream from the failure anchor; combined with depth attenuation and the prune floor this bounds the candidate set to load-bearing causes; a hard hop cap also guarantees termination; replace with a measured horizon once root-cause chain lengths are benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_ABDUCE_KNOB_REGISTRY_VERSION,
        name: ORACLE_ABDUCE_DEPTH_ATTENUATION_PERMILLE_KNOB,
        default: 700,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §2/§3 per-hop ×0.7 attenuation (reused for the reverse walk)",
        rationale: "each reverse hop multiplies a cause's confidence by 0.7: a candidate two calls upstream is a weaker root-cause claim than a direct predecessor; capped below 1000 so attenuation is strictly contractive; replace with a measured decay once reverse-hop causality strength is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_ABDUCE_KNOB_REGISTRY_VERSION,
        name: ORACLE_ABDUCE_PROVISIONAL_CONFIDENCE_PERMILLE_KNOB,
        default: 350,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §3 structural-only candidate default (0.35)",
        rationale: "a structural-only candidate (reachable by an edge but with no failing history) is scored at the 0.35 provisional prior before attenuation and never boosted, so its confidence never exceeds this cap; matches the predict structural-only default so grounded and structural causes score on one scale; replace with a measured structural prior once available",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_ABDUCE_KNOB_REGISTRY_VERSION,
        name: ORACLE_ABDUCE_RECENCY_HALF_LIFE_SECS_KNOB,
        default: 7 * 24 * 60 * 60,
        min: 1,
        max: 10 * 365 * 24 * 60 * 60,
        unit: "seconds",
        source: "half-life time-decay recency weighting, mirroring the #49 corpus decay half-life",
        rationale: "a candidate's failing occurrences are recency-weighted by 0.5^((observed − outcome_ts)/half_life): a failure it preceded last week counts more than one a year ago; 7 days halves the weight each week; zero is illegal because it collapses every weight to zero; replace with a measured recency decay once available",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_ABDUCE_KNOB_REGISTRY_VERSION,
        name: ORACLE_ABDUCE_RECENT_CHANGE_BOOST_PERMILLE_KNOB,
        default: 1500,
        min: 1000,
        max: 10000,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §3 cross-check: recent-change intersection ranks up",
        rationale: "a grounded candidate that also appears in the caller's recent-change set has its confidence multiplied by 1.5 (1500 permille), reflecting that a freshly-touched cause is a more plausible culprit; the floor of 1000 (×1.0) guarantees the cross-check can only rank a cause up, never down; the result is still capped below 1.0 by the max-confidence knob; replace with a measured lift once recent-change precision is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_ABDUCE_KNOB_REGISTRY_VERSION,
        name: ORACLE_ABDUCE_DRIVES_BOOST_PERMILLE_KNOB,
        default: 1300,
        min: 1000,
        max: 10000,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §3 cross-check: DRIVES edges into the failure region rank up",
        rationale: "a grounded candidate linked to the failure region by a DRIVES (lead/lag causal) edge has its confidence multiplied by 1.3 (1300 permille), reflecting the stronger causal semantics of a DRIVES edge over a plain call; the floor of 1000 (×1.0) guarantees the cross-check only ranks up; the result stays capped below 1.0; replace with a measured lift once DRIVES-edge precision is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_ABDUCE_KNOB_REGISTRY_VERSION,
        name: ORACLE_ABDUCE_MAX_CONFIDENCE_PERMILLE_KNOB,
        default: 990,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE ceilings: confidence never reaches 1.0",
        rationale: "hard upper bound on any abduced confidence so that even a heavily-supported, cross-check-boosted cause is never certified at 1.0; combined with the s/(s+1) abundance base this keeps every hypothesis strictly below certainty; capped below 1000 by construction; replace with a measured ceiling once available",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_ABDUCE_KNOB_REGISTRY_VERSION,
        name: ORACLE_ABDUCE_PRUNE_FLOOR_PERMILLE_KNOB,
        default: 50,
        min: 1,
        max: 999,
        unit: "permille",
        source: "ASTROLABE blueprint 11_ORACLE §2/§3 prune < 0.05 (reused for abduction)",
        rationale: "a candidate whose attenuated, capped confidence falls below 0.05 (50 permille) is dropped, so the hypothesis set stays a small ranked list of plausible causes rather than every reverse-reachable node; replace with a measured precision/recall floor once abduction lift is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_ABDUCE_KNOB_REGISTRY_VERSION,
        name: ORACLE_ABDUCE_EVIDENCE_FLOOR_KNOB,
        default: 3,
        min: 1,
        max: 1_000_000,
        unit: "occurrences",
        source: "ASTROLABE #49 corpus min-edge-support floor (3) reused as the abduction grounded-speech floor",
        rationale: "abduce_cause refuses (Insufficient, per-sensor deficit) unless the failure's reverse-reachable region carries at least this many grounded failing occurrences, so it never abduces a cause from one or two coincidences; matches the corpus edge-support floor; replace with a measured value once refusal precision is benchmarked",
    },
];

/// Returns the abduction knob declaration for `name`, or `None`.
pub fn oracle_abduce_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ORACLE_ABDUCE_KNOBS.iter().find(|knob| knob.name == name)
}

fn abduce_knob(name: &str) -> &'static U64KnobDeclaration {
    oracle_abduce_knob(name).expect("oracle abduce knob is declared")
}

// ---------------------------------------------------------------------------
// Abduction configuration
// ---------------------------------------------------------------------------

/// Validated root-cause abduction policy.
///
/// Fields hold the raw knob values (permille, counts, or seconds); the resolved
/// floating factors are read through the accessor methods so every number stays a
/// registry-declared knob rather than a bare literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbductionConfig {
    pub max_depth: u64,
    pub depth_attenuation_permille: u64,
    pub provisional_confidence_permille: u64,
    pub recency_half_life_secs: u64,
    pub recent_change_boost_permille: u64,
    pub drives_boost_permille: u64,
    pub max_confidence_permille: u64,
    pub prune_floor_permille: u64,
    pub evidence_floor: u64,
}

impl Default for AbductionConfig {
    fn default() -> Self {
        Self {
            max_depth: abduce_knob(ORACLE_ABDUCE_MAX_DEPTH_KNOB).default,
            depth_attenuation_permille: abduce_knob(ORACLE_ABDUCE_DEPTH_ATTENUATION_PERMILLE_KNOB)
                .default,
            provisional_confidence_permille: abduce_knob(
                ORACLE_ABDUCE_PROVISIONAL_CONFIDENCE_PERMILLE_KNOB,
            )
            .default,
            recency_half_life_secs: abduce_knob(ORACLE_ABDUCE_RECENCY_HALF_LIFE_SECS_KNOB).default,
            recent_change_boost_permille: abduce_knob(
                ORACLE_ABDUCE_RECENT_CHANGE_BOOST_PERMILLE_KNOB,
            )
            .default,
            drives_boost_permille: abduce_knob(ORACLE_ABDUCE_DRIVES_BOOST_PERMILLE_KNOB).default,
            max_confidence_permille: abduce_knob(ORACLE_ABDUCE_MAX_CONFIDENCE_PERMILLE_KNOB)
                .default,
            prune_floor_permille: abduce_knob(ORACLE_ABDUCE_PRUNE_FLOOR_PERMILLE_KNOB).default,
            evidence_floor: abduce_knob(ORACLE_ABDUCE_EVIDENCE_FLOOR_KNOB).default,
        }
    }
}

impl AbductionConfig {
    /// Fails closed when any field is outside its declared knob bounds.
    pub fn validate(&self) -> Result<(), OracleError> {
        check(ORACLE_ABDUCE_MAX_DEPTH_KNOB, self.max_depth)?;
        check(
            ORACLE_ABDUCE_DEPTH_ATTENUATION_PERMILLE_KNOB,
            self.depth_attenuation_permille,
        )?;
        check(
            ORACLE_ABDUCE_PROVISIONAL_CONFIDENCE_PERMILLE_KNOB,
            self.provisional_confidence_permille,
        )?;
        check(
            ORACLE_ABDUCE_RECENCY_HALF_LIFE_SECS_KNOB,
            self.recency_half_life_secs,
        )?;
        check(
            ORACLE_ABDUCE_RECENT_CHANGE_BOOST_PERMILLE_KNOB,
            self.recent_change_boost_permille,
        )?;
        check(
            ORACLE_ABDUCE_DRIVES_BOOST_PERMILLE_KNOB,
            self.drives_boost_permille,
        )?;
        check(
            ORACLE_ABDUCE_MAX_CONFIDENCE_PERMILLE_KNOB,
            self.max_confidence_permille,
        )?;
        check(
            ORACLE_ABDUCE_PRUNE_FLOOR_PERMILLE_KNOB,
            self.prune_floor_permille,
        )?;
        check(ORACLE_ABDUCE_EVIDENCE_FLOOR_KNOB, self.evidence_floor)?;
        Ok(())
    }

    fn depth_attenuation(&self) -> f64 {
        self.depth_attenuation_permille as f64 / 1000.0
    }
    fn provisional_confidence(&self) -> f64 {
        self.provisional_confidence_permille as f64 / 1000.0
    }
    fn recent_change_boost(&self) -> f64 {
        self.recent_change_boost_permille as f64 / 1000.0
    }
    fn drives_boost(&self) -> f64 {
        self.drives_boost_permille as f64 / 1000.0
    }
    fn max_confidence(&self) -> f64 {
        self.max_confidence_permille as f64 / 1000.0
    }
    fn prune_floor(&self) -> f64 {
        self.prune_floor_permille as f64 / 1000.0
    }
}

fn check(name: &str, value: u64) -> Result<(), OracleError> {
    let declared = abduce_knob(name);
    if declared.accepts(value) {
        Ok(())
    } else {
        Err(OracleError {
            code: ASTRO_ORACLE_ABDUCE_CONFIG_INVALID,
            message: format!(
                "abduce knob {name} value {value} is outside declared bounds [{}, {}]",
                declared.min, declared.max
            ),
            remediation: ABDUCE_REMEDIATION,
        })
    }
}

// ---------------------------------------------------------------------------
// Request and result types
// ---------------------------------------------------------------------------

/// An `abduce_cause` request: the observed failure anchor, the wall-clock instant
/// it was observed (the recency reference), and the caller's set of
/// recently-changed subjects (the recent-change cross-check).
#[derive(Debug, Clone)]
pub struct AbductionRequest {
    /// The failing subject to reason back from.
    pub failure: CxId,
    /// The instant the failure was observed; recency and causality reference.
    pub observed_ts: Ts,
    /// Subjects changed inside the caller's recent window (cross-check boost).
    pub recent_changes: BTreeSet<CxId>,
}

/// One ranked root-cause hypothesis.
#[derive(Debug, Clone, PartialEq)]
pub struct CauseHypothesis {
    /// The candidate cause subject.
    pub cause: CxId,
    /// Attenuated, cross-checked, capped confidence, strictly `< 1.0`.
    pub confidence: f64,
    /// Reverse depth from the failure (`0` = the failure's own history).
    pub depth: usize,
    /// Whether the candidate carries grounded failing history (`false` =
    /// structural-only provisional leaf).
    pub grounded: bool,
    /// Recency- and credit-weighted failing-occurrence mass (`0.0` = structural).
    pub fail_support: f64,
    /// Trust of the hypothesis.
    pub trust: TrustTag,
    /// Whether the recent-change cross-check ranked this candidate up.
    pub recent_change_boosted: bool,
    /// Whether a DRIVES edge into the failure region ranked this candidate up.
    pub drives_boosted: bool,
    /// The disconfirming test: a test covering the candidate whose passing would
    /// refute this hypothesis. `None` (labeled absence) when the candidate has no
    /// covering test.
    pub disconfirming_test: Option<CxId>,
    /// The failure→cause reverse-hop path.
    pub hop_path: Vec<CxId>,
}

/// A grounded abduction: the ranked root-cause hypotheses for a failure.
#[derive(Debug, Clone, PartialEq)]
pub struct AbductionReport {
    pub failure: CxId,
    pub observed_ts: Ts,
    /// Hypotheses ranked by confidence, highest first (CxId tiebreak).
    pub hypotheses: Vec<CauseHypothesis>,
}

/// The outcome of an `abduce_cause` call: ranked hypotheses or an honest
/// refusal-with-deficit (HONEST invariant 2 — never a confident guess).
#[derive(Debug, Clone, PartialEq)]
pub enum AbductionOutcome {
    Grounded(AbductionReport),
    Insufficient(InsufficientReport),
}

// ---------------------------------------------------------------------------
// abduce_cause
// ---------------------------------------------------------------------------

/// Abduces the ranked root causes of an observed failure.
///
/// Reverse-walks the propagation edges backward from `request.failure` (depth ≤
/// `config.max_depth`), scoring each reachable candidate — plus the failure's own
/// history at depth 0 — against the recency- and credit-weighted failing
/// occurrences it has preceded. Returns [`AbductionOutcome::Insufficient`] when
/// the reverse-reachable region carries fewer than the declared evidence floor of
/// failing occurrences (a labeled refusal, not an error); structural errors (bad
/// config, a self-loop edge, a zero observation instant) fail closed with a coded
/// [`OracleError`].
pub fn abduce_cause(
    edges: &[ConsequenceEdge],
    records: &[OccurrenceRecord],
    request: &AbductionRequest,
    config: &AbductionConfig,
) -> Result<AbductionOutcome, OracleError> {
    config.validate()?;
    if request.observed_ts == 0 {
        return Err(OracleError {
            code: ASTRO_ORACLE_ABDUCE_REQUEST_INVALID,
            message: "abduce_cause requires a non-zero observed_ts (the failure instant)"
                .to_string(),
            remediation: ABDUCE_REMEDIATION,
        });
    }

    // --- Build the reverse propagation adjacency, the DRIVES pairs, and the
    //     TESTS-cover map from the raw edge set (self-loops fail closed). ---
    let mut rev_prop: BTreeMap<CxId, BTreeSet<CxId>> = BTreeMap::new();
    let mut drives_pairs: BTreeSet<(CxId, CxId)> = BTreeSet::new();
    let mut tests_cover: BTreeMap<CxId, BTreeSet<CxId>> = BTreeMap::new();
    for edge in edges {
        if edge.from == edge.to {
            return Err(OracleError {
                code: ASTRO_ORACLE_GRAPH_INVALID,
                message: format!("edge from {} to itself is a self-loop", edge.from),
                remediation: ABDUCE_REMEDIATION,
            });
        }
        match edge.kind {
            ConsequenceEdgeKind::Tests => {
                tests_cover.entry(edge.from).or_default().insert(edge.to);
            }
            kind => {
                // A propagation edge from → to; reverse-reachability climbs to.
                rev_prop.entry(edge.to).or_default().insert(edge.from);
                if kind == ConsequenceEdgeKind::Drives {
                    drives_pairs.insert((edge.from, edge.to));
                }
            }
        }
    }

    // --- Reverse BFS from the failure: min depth per reachable ancestor. ---
    let max_depth = config.max_depth as usize;
    let mut depth: BTreeMap<CxId, usize> = BTreeMap::new();
    depth.insert(request.failure, 0);
    let mut frontier = vec![request.failure];
    let mut d = 0usize;
    while !frontier.is_empty() && d < max_depth {
        d += 1;
        let mut next = Vec::new();
        for node in frontier {
            if let Some(parents) = rev_prop.get(&node) {
                for &parent in parents {
                    if let std::collections::btree_map::Entry::Vacant(entry) = depth.entry(parent) {
                        entry.insert(d);
                        next.push(parent);
                    }
                }
            }
        }
        frontier = next;
    }

    // --- Index failing occurrences preceding the observation, by subject. ---
    let mut failing_by_subject: BTreeMap<CxId, Vec<&OccurrenceRecord>> = BTreeMap::new();
    for record in records {
        if !record.passed && record.outcome_ts <= request.observed_ts {
            failing_by_subject
                .entry(record.subject)
                .or_default()
                .push(record);
        }
    }

    // --- Honesty gate: total grounded failing occurrences in the region. ---
    let mut grounded_fail_count = 0usize;
    for &node in depth.keys() {
        if let Some(fails) = failing_by_subject.get(&node) {
            grounded_fail_count += fails.len();
        }
    }
    if grounded_fail_count < config.evidence_floor as usize {
        let need = config.evidence_floor as usize;
        let bits_short = (need as f64 + 1.0).log2() - (grounded_fail_count as f64 + 1.0).log2();
        return Ok(AbductionOutcome::Insufficient(InsufficientReport {
            seeds: vec![request.failure],
            deficits: vec![SensorDeficit {
                sensor: ORACLE_SENSOR_FAILURE_HISTORY,
                have: grounded_fail_count,
                need,
                bits_short,
            }],
            remediation: ORACLE_ABDUCE_INSUFFICIENT_REMEDIATION,
        }));
    }

    // --- Score every reachable candidate. ---
    let mut hypotheses = Vec::new();
    for (&node, &node_depth) in &depth {
        let atten = config.depth_attenuation().powi(node_depth as i32);

        // Recency- and credit-weighted failing support.
        let (fail_support, trusts): (f64, Vec<TrustTag>) = match failing_by_subject.get(&node) {
            Some(fails) => {
                let mut support = 0.0f64;
                let mut trusts = Vec::with_capacity(fails.len());
                for rec in fails {
                    support +=
                        rec.credit * recency_weight(request.observed_ts, rec.outcome_ts, config);
                    trusts.push(rec.trust);
                }
                (support, trusts)
            }
            None => (0.0, Vec::new()),
        };
        let grounded = fail_support > 0.0;

        // Grounded candidates score from their evidence and may be cross-check
        // boosted; structural-only candidates stay at the provisional prior and
        // are never boosted, so their confidence never exceeds the cap.
        let recent_change_boosted = grounded && request.recent_changes.contains(&node);
        let drives_boosted =
            grounded && drives_into_region(&drives_pairs, &depth, node, node_depth);

        let confidence = if grounded {
            let base = fail_support / (fail_support + 1.0);
            let mut c = base * atten;
            if recent_change_boosted {
                c *= config.recent_change_boost();
            }
            if drives_boosted {
                c *= config.drives_boost();
            }
            c.min(config.max_confidence())
        } else {
            config.provisional_confidence() * atten
        };

        if confidence < config.prune_floor() {
            continue;
        }

        let trust = if grounded {
            rollup_trust(trusts)
        } else {
            TrustTag::Provisional
        };
        let disconfirming_test = tests_cover
            .get(&node)
            .and_then(|tests| tests.iter().next().copied());
        let hop_path = reverse_path(&rev_prop, &depth, request.failure, node);

        hypotheses.push(CauseHypothesis {
            cause: node,
            confidence,
            depth: node_depth,
            grounded,
            fail_support,
            trust,
            recent_change_boosted,
            drives_boosted,
            disconfirming_test,
            hop_path,
        });
    }

    hypotheses.sort_by(|a, b| {
        b.confidence
            .total_cmp(&a.confidence)
            .then_with(|| a.cause.cmp(&b.cause))
    });

    Ok(AbductionOutcome::Grounded(AbductionReport {
        failure: request.failure,
        observed_ts: request.observed_ts,
        hypotheses,
    }))
}

/// Recency weight `0.5^((observed − outcome_ts)/half_life)` in `(0, 1]`.
///
/// A failing occurrence at the observation instant weighs `1.0`; older failures
/// decay by half each half-life. Callers filter `outcome_ts ≤ observed_ts` first,
/// so the exponent is non-negative and the weight never exceeds `1.0`.
fn recency_weight(observed_ts: Ts, outcome_ts: Ts, config: &AbductionConfig) -> f64 {
    let age = observed_ts.saturating_sub(outcome_ts);
    0.5_f64.powf(age as f64 / config.recency_half_life_secs as f64)
}

/// Whether `node` reaches the failure region by a DRIVES edge on a shortest
/// reverse path — i.e. a DRIVES edge `node → X` where `X` sits one hop closer to
/// the failure (`depth[X] == depth[node] − 1`).
fn drives_into_region(
    drives_pairs: &BTreeSet<(CxId, CxId)>,
    depth: &BTreeMap<CxId, usize>,
    node: CxId,
    node_depth: usize,
) -> bool {
    if node_depth == 0 {
        return false;
    }
    drives_pairs
        .iter()
        .any(|&(from, to)| from == node && depth.get(&to).is_some_and(|&td| td + 1 == node_depth))
}

/// Reconstructs the `failure → … → cause` reverse-hop path by climbing one
/// shortest step at a time (each step picks the smallest-CxId parent that sits at
/// the next depth up), then reversing into failure-first order.
fn reverse_path(
    rev_prop: &BTreeMap<CxId, BTreeSet<CxId>>,
    depth: &BTreeMap<CxId, usize>,
    failure: CxId,
    cause: CxId,
) -> Vec<CxId> {
    // Walk from the cause back down toward the failure by descending depth.
    let mut path = vec![cause];
    let mut current = cause;
    let mut current_depth = depth.get(&cause).copied().unwrap_or(0);
    while current != failure && current_depth > 0 {
        // The forward edge current → child runs toward the failure, so `child`
        // is a node with a reverse edge to `current` sitting one depth down.
        let mut step = None;
        for (&child, children_parents) in rev_prop.iter() {
            if depth.get(&child).copied() == Some(current_depth - 1)
                && children_parents.contains(&current)
            {
                step = Some(child);
                break; // rev_prop iterates in CxId order; first is the smallest
            }
        }
        match step {
            Some(child) => {
                path.push(child);
                current = child;
                current_depth -= 1;
            }
            None => break,
        }
    }
    path.reverse();
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::{
        AttributionConfig, ChangeEvent, OutcomeEvent, mine_corpus, persist_corpus,
        read_occurrence_rows,
    };

    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use calyx_aster::vault::{AsterVault, VaultOptions};
    use calyx_core::{SystemClock, VaultId};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
    const TEST_SALT: &[u8] = b"astrolabe-oracle-abduce-fsv";

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
            "astrolabe-oracle-abduce-{name}-{}-{}",
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
        .expect("open durable abduce test vault")
    }

    fn cx(byte: u8) -> CxId {
        CxId::from_bytes([byte; 16])
    }
    fn edge(from: CxId, to: CxId, kind: ConsequenceEdgeKind) -> ConsequenceEdge {
        ConsequenceEdge { from, to, kind }
    }

    /// A single-candidate failing (or passing) occurrence on `subject` observed at
    /// `outcome_ts`, credit 1.0, Trusted source — the hand-computable unit.
    fn occ(subject: CxId, tag: &str, outcome_ts: Ts, passed: bool) -> OccurrenceRecord {
        OccurrenceRecord {
            subject,
            change_id: format!("chg-{tag}"),
            source: format!("ci:abduce:{tag}"),
            change_ts: outcome_ts.saturating_sub(3_600),
            outcome_ts,
            lag_s: outcome_ts.min(3_600),
            decay_weight: 1.0,
            credit: 1.0,
            passed,
            candidate_count: 1,
            trust: TrustTag::Trusted,
        }
    }

    fn req(failure: CxId, observed_ts: Ts) -> AbductionRequest {
        AbductionRequest {
            failure,
            observed_ts,
            recent_changes: BTreeSet::new(),
        }
    }

    fn grounded(outcome: AbductionOutcome) -> AbductionReport {
        match outcome {
            AbductionOutcome::Grounded(report) => report,
            AbductionOutcome::Insufficient(report) => {
                panic!("expected Grounded, got Insufficient: {report:?}")
            }
        }
    }

    // ------------------------------------------------------------------
    // Knob registry sanity (standing invariant 4)
    // ------------------------------------------------------------------

    #[test]
    fn every_abduce_knob_declares_bounds_that_contain_its_default() {
        assert!(!ORACLE_ABDUCE_KNOBS.is_empty());
        for knob in ORACLE_ABDUCE_KNOBS {
            assert_eq!(
                knob.registry_version, ORACLE_ABDUCE_KNOB_REGISTRY_VERSION,
                "{knob:?}"
            );
            assert!(knob.min <= knob.max, "{knob:?}");
            assert!(knob.accepts(knob.default), "{knob:?}");
            assert!(!knob.unit.is_empty(), "{knob:?}");
            assert!(!knob.source.is_empty(), "{knob:?}");
            assert!(!knob.rationale.is_empty(), "{knob:?}");
        }
        // The boosts can only rank up (floor ×1.0); the max-confidence cap is <1.0.
        assert_eq!(
            abduce_knob(ORACLE_ABDUCE_RECENT_CHANGE_BOOST_PERMILLE_KNOB).min,
            1000
        );
        assert_eq!(
            abduce_knob(ORACLE_ABDUCE_DRIVES_BOOST_PERMILLE_KNOB).min,
            1000
        );
        assert!(abduce_knob(ORACLE_ABDUCE_MAX_CONFIDENCE_PERMILLE_KNOB).max < 1000);
        AbductionConfig::default()
            .validate()
            .expect("default validates");
    }

    // ------------------------------------------------------------------
    // DoD 1: abduction golden — planted cause ranked first at exact n/(n+1),
    // disconfirming test names the right test.
    // ------------------------------------------------------------------

    #[test]
    fn abduction_golden_ranks_planted_cause_first_at_exact_n_over_n_plus_one() {
        let config = AbductionConfig::default();
        let t = 1_000_000_000u64;
        // Failure F = cx1. Its own history: 3 failing occurrences recorded at the
        // observation instant (each recency weight 1.0, credit 1.0) => fail
        // support 3.0 => confidence 3/(3+1) = 0.75 exact, depth 0, no boosts.
        let records = vec![
            occ(cx(1), "f-a", t, false),
            occ(cx(1), "f-b", t, false),
            occ(cx(1), "f-c", t, false),
        ];
        // A structural-only competitor upstream (cx2 -> cx1), plus a TESTS edge
        // naming the disconfirming test cx20 that covers the failure.
        let edges = vec![
            edge(cx(2), cx(1), ConsequenceEdgeKind::Calls),
            edge(cx(1), cx(20), ConsequenceEdgeKind::Tests),
        ];
        let report = grounded(
            abduce_cause(&edges, &records, &req(cx(1), t), &config).expect("abduce golden"),
        );

        let top = &report.hypotheses[0];
        assert_eq!(top.cause, cx(1), "planted cause ranked first");
        assert!(
            (top.confidence - 0.75).abs() < 1e-12,
            "confidence n/(n+1) = 3/4 exact, got {}",
            top.confidence
        );
        assert_eq!(top.fail_support, 3.0);
        assert_eq!(top.depth, 0);
        assert!(top.grounded);
        assert_eq!(top.trust, TrustTag::Trusted);
        assert_eq!(
            top.disconfirming_test,
            Some(cx(20)),
            "disconfirming test names the covering test"
        );
        assert_eq!(top.hop_path, vec![cx(1)]);

        // The structural competitor is present, provisional, below the cause.
        let comp = report
            .hypotheses
            .iter()
            .find(|h| h.cause == cx(2))
            .expect("structural competitor present");
        assert!(!comp.grounded);
        assert!(comp.confidence < top.confidence);
    }

    // ------------------------------------------------------------------
    // DoD 2: cross-check ablations — recent-change and DRIVES each independently
    // flip the ranking (holding evidence fixed).
    // ------------------------------------------------------------------

    #[test]
    fn recent_change_cross_check_flips_the_ranking() {
        let config = AbductionConfig::default();
        let t = 2_000_000_000u64;
        // Two grounded predecessors, each 2 failing occurrences => equal base
        // 2/3, equal depth 1 => equal confidence; CxId tiebreak puts cx2 first.
        let records = vec![
            occ(cx(2), "a", t, false),
            occ(cx(2), "b", t, false),
            occ(cx(3), "c", t, false),
            occ(cx(3), "d", t, false),
        ];
        let edges = vec![
            edge(cx(2), cx(1), ConsequenceEdgeKind::Calls),
            edge(cx(3), cx(1), ConsequenceEdgeKind::Calls),
        ];
        // Baseline: no recent-change set => tie broken by CxId, cx2 first.
        let base =
            grounded(abduce_cause(&edges, &records, &req(cx(1), t), &config).expect("baseline"));
        let base_order: Vec<CxId> = base
            .hypotheses
            .iter()
            .filter(|h| h.grounded)
            .map(|h| h.cause)
            .collect();
        assert_eq!(base_order, vec![cx(2), cx(3)], "tie broken by CxId");

        // Ablation: mark cx3 recently-changed => cx3 ×1.5 ranks above cx2.
        let mut request = req(cx(1), t);
        request.recent_changes.insert(cx(3));
        let boosted = grounded(abduce_cause(&edges, &records, &request, &config).expect("boosted"));
        let boosted_order: Vec<CxId> = boosted
            .hypotheses
            .iter()
            .filter(|h| h.grounded)
            .map(|h| h.cause)
            .collect();
        assert_eq!(
            boosted_order,
            vec![cx(3), cx(2)],
            "recent-change boost ranks cx3 up"
        );
        let cx3 = boosted
            .hypotheses
            .iter()
            .find(|h| h.cause == cx(3))
            .unwrap();
        assert!(cx3.recent_change_boosted);
    }

    #[test]
    fn drives_cross_check_flips_the_ranking() {
        let config = AbductionConfig::default();
        let t = 3_000_000_000u64;
        let records = vec![
            occ(cx(2), "a", t, false),
            occ(cx(2), "b", t, false),
            occ(cx(3), "c", t, false),
            occ(cx(3), "d", t, false),
        ];
        // cx2 reaches the failure by a plain Calls edge; cx3 by a DRIVES edge.
        let edges = vec![
            edge(cx(2), cx(1), ConsequenceEdgeKind::Calls),
            edge(cx(3), cx(1), ConsequenceEdgeKind::Drives),
        ];
        let report =
            grounded(abduce_cause(&edges, &records, &req(cx(1), t), &config).expect("drives"));
        let order: Vec<CxId> = report
            .hypotheses
            .iter()
            .filter(|h| h.grounded)
            .map(|h| h.cause)
            .collect();
        assert_eq!(order, vec![cx(3), cx(2)], "DRIVES edge ranks cx3 up");
        let cx3 = report.hypotheses.iter().find(|h| h.cause == cx(3)).unwrap();
        let cx2 = report.hypotheses.iter().find(|h| h.cause == cx(2)).unwrap();
        assert!(cx3.drives_boosted, "cx3 reached by DRIVES");
        assert!(!cx2.drives_boosted, "cx2 reached by Calls");
    }

    // ------------------------------------------------------------------
    // DoD 3: provisional discipline — structural-only candidates never exceed
    // the provisional cap and are never boosted.
    // ------------------------------------------------------------------

    #[test]
    fn structural_only_candidates_stay_capped_and_are_never_boosted() {
        let config = AbductionConfig::default();
        let t = 4_000_000_000u64;
        // cx1 grounded (clears the floor); cx2 structural-only upstream at depth 1.
        let records = vec![
            occ(cx(1), "a", t, false),
            occ(cx(1), "b", t, false),
            occ(cx(1), "c", t, false),
        ];
        let edges = vec![edge(cx(2), cx(1), ConsequenceEdgeKind::Calls)];
        // Even marking the structural node recently-changed must NOT boost it.
        let mut request = req(cx(1), t);
        request.recent_changes.insert(cx(2));
        let report = grounded(abduce_cause(&edges, &records, &request, &config).expect("abduce"));

        let s = report.hypotheses.iter().find(|h| h.cause == cx(2)).unwrap();
        assert!(!s.grounded);
        assert_eq!(s.trust, TrustTag::Provisional);
        assert!(!s.recent_change_boosted, "structural node never boosted");
        // confidence <= provisional cap (0.35), never exceeded by a boost.
        assert!(
            s.confidence <= config.provisional_confidence() + 1e-12,
            "structural confidence {} exceeds cap 0.35",
            s.confidence
        );
        // Depth-1 structural leaf: exactly 0.35 * 0.7.
        assert!((s.confidence - 0.35 * 0.7).abs() < 1e-12);
    }

    // ------------------------------------------------------------------
    // No hypothesis ever reaches certainty, even fully boosted.
    // ------------------------------------------------------------------

    #[test]
    fn no_hypothesis_reaches_certainty_even_fully_boosted() {
        let config = AbductionConfig::default();
        let t = 5_000_000_000u64;
        // A depth-1 cause with heavy support (200 fails), recent-changed AND
        // reached by a DRIVES edge => base 200/201, *0.7, *1.5, *1.3 >> 1.0,
        // but the max-confidence cap holds it at exactly 0.99 (< 1.0).
        let records: Vec<OccurrenceRecord> = (0..200)
            .map(|i| occ(cx(2), &format!("f{i}"), t, false))
            .collect();
        let edges = vec![edge(cx(2), cx(1), ConsequenceEdgeKind::Drives)];
        let mut request = req(cx(1), t);
        request.recent_changes.insert(cx(2));
        let report = grounded(abduce_cause(&edges, &records, &request, &config).expect("abduce"));
        let c = report.hypotheses.iter().find(|h| h.cause == cx(2)).unwrap();
        assert!(c.recent_change_boosted && c.drives_boosted);
        assert!(c.confidence < 1.0, "never certain, got {}", c.confidence);
        assert!(
            (c.confidence - config.max_confidence()).abs() < 1e-12,
            "capped at 0.99"
        );
    }

    // ------------------------------------------------------------------
    // Edge triad: no history, single-occurrence, ambiguous dual-cause.
    // ------------------------------------------------------------------

    #[test]
    fn no_history_refuses_with_a_deficit() {
        let config = AbductionConfig::default();
        let t = 6_000_000_000u64;
        // Failure with no occurrences anywhere and no edges: before => nothing.
        let outcome = abduce_cause(&[], &[], &req(cx(1), t), &config).expect("no-history abduce");
        let AbductionOutcome::Insufficient(report) = outcome else {
            panic!("empty region must refuse");
        };
        assert_eq!(report.seeds, vec![cx(1)]);
        assert_eq!(report.deficits.len(), 1);
        assert_eq!(report.deficits[0].sensor, ORACLE_SENSOR_FAILURE_HISTORY);
        assert_eq!(report.deficits[0].have, 0);
        assert_eq!(report.deficits[0].need, config.evidence_floor as usize);
        assert!(report.deficits[0].bits_short > 0.0);

        // After recording enough failing history the same failure is grounded.
        let records = vec![
            occ(cx(1), "a", t, false),
            occ(cx(1), "b", t, false),
            occ(cx(1), "c", t, false),
        ];
        let after = abduce_cause(&[], &records, &req(cx(1), t), &config).expect("after");
        assert!(
            matches!(after, AbductionOutcome::Grounded(_)),
            "now grounded"
        );
    }

    #[test]
    fn single_occurrence_refuses_below_the_floor() {
        let config = AbductionConfig::default();
        let t = 7_000_000_000u64;
        let records = vec![occ(cx(1), "only", t, false)];
        let outcome = abduce_cause(&[], &records, &req(cx(1), t), &config).expect("single");
        let AbductionOutcome::Insufficient(report) = outcome else {
            panic!("one occurrence is below the floor => refuse");
        };
        assert_eq!(report.deficits[0].have, 1);
        assert_eq!(report.deficits[0].need, 3);
    }

    #[test]
    fn ambiguous_dual_cause_emits_both_deterministically() {
        let config = AbductionConfig::default();
        let t = 8_000_000_000u64;
        // Two equally-supported causes (2 fails each; total 4 clears the floor).
        let records = vec![
            occ(cx(2), "a", t, false),
            occ(cx(2), "b", t, false),
            occ(cx(3), "c", t, false),
            occ(cx(3), "d", t, false),
        ];
        let edges = vec![
            edge(cx(2), cx(1), ConsequenceEdgeKind::Calls),
            edge(cx(3), cx(1), ConsequenceEdgeKind::Calls),
        ];
        let report =
            grounded(abduce_cause(&edges, &records, &req(cx(1), t), &config).expect("dual"));
        let g: Vec<&CauseHypothesis> = report.hypotheses.iter().filter(|h| h.grounded).collect();
        assert_eq!(g.len(), 2, "both causes emitted");
        assert!(
            (g[0].confidence - g[1].confidence).abs() < 1e-12,
            "equal confidence"
        );
        assert_eq!(
            (g[0].cause, g[1].cause),
            (cx(2), cx(3)),
            "deterministic CxId tiebreak"
        );
    }

    // ------------------------------------------------------------------
    // FSV: abduction over occurrence rows read back from a REOPENED vault.
    // ------------------------------------------------------------------

    #[test]
    fn fsv_abduction_reads_back_persisted_corpus_and_ranks_the_cause() {
        let config = AbductionConfig::default();
        let attribution = AttributionConfig::default();
        // Plant three single-candidate failing occurrences on cx1, spaced 30 days
        // apart (beyond the 14-day window, so each attributes to exactly one
        // change), the last at the observation instant.
        const SPACING: u64 = 30 * 24 * 60 * 60;
        let base = 1_500_000_000u64;
        let mut changes = Vec::new();
        let mut outcomes = Vec::new();
        for i in 0..3u64 {
            let ots = base + i * SPACING;
            changes.push(ChangeEvent {
                change_id: format!("fixsha-{i}"),
                subject: cx(1),
                change_ts: ots - 3_600,
            });
            outcomes.push(OutcomeEvent {
                source: format!("ci:abduce:{i}"),
                subject: cx(1),
                outcome_ts: ots,
                passed: false,
            });
        }
        let observed_ts = base + 2 * SPACING;
        let corpus = mine_corpus(&changes, &outcomes, &attribution).expect("mine");
        assert_eq!(corpus.occurrences.len(), 3, "single-candidate per outcome");

        let dir = temp_dir("fsv");
        {
            let vault = open_vault(&dir);
            persist_corpus(&vault, &corpus, "abduce-fsv").expect("persist");
        }
        // Reopen and read the occurrence rows back from durable state.
        let reopened = open_vault(&dir);
        let rows = read_occurrence_rows(&reopened).expect("read rows");
        assert_eq!(rows.len(), 3, "three occurrence rows on disk");
        let records: Vec<OccurrenceRecord> = rows
            .into_iter()
            .map(|p| OccurrenceRecord {
                subject: p.row.subject,
                change_id: p.row.change_id,
                source: p.row.source,
                change_ts: p.row.change_ts,
                outcome_ts: p.row.outcome_ts,
                lag_s: p.row.lag_s,
                decay_weight: p.row.decay_weight,
                credit: p.row.credit,
                passed: p.row.passed,
                candidate_count: p.row.candidate_count,
                trust: p.row.trust,
            })
            .collect();
        // Mirror the mine_occurrences golden trust check on the read-back rows.
        assert!(records.iter().all(|r| !r.passed && r.credit == 1.0));

        let edges = vec![
            edge(cx(2), cx(1), ConsequenceEdgeKind::Calls),
            edge(cx(1), cx(20), ConsequenceEdgeKind::Tests),
        ];
        let report = grounded(
            abduce_cause(&edges, &records, &req(cx(1), observed_ts), &config)
                .expect("abduce over read-back rows"),
        );
        let top = &report.hypotheses[0];
        assert_eq!(
            top.cause,
            cx(1),
            "planted cause ranked first from disk state"
        );
        assert!(top.grounded);
        assert_eq!(top.disconfirming_test, Some(cx(20)));
        assert!(
            top.confidence > 0.0 && top.confidence < 1.0,
            "grounded, non-certain, got {}",
            top.confidence
        );
    }
}
