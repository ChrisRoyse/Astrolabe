//! Oracle evidence substrate: change-to-outcome corpus mining with attribution
//! windows (blueprint P7.5).
//!
//! A *change* (a commit or edit touching a subject constellation at a wall-clock
//! instant) is paired with a later *outcome* (a grounded anchor observation on
//! the same subject) whenever the outcome falls inside the change's attribution
//! window. Each surviving `(change → outcome)` pair becomes an
//! [`OccurrenceRecord`] carrying its exact lag, an exponential-decay weight, and
//! a normalized credit share; the per-subject aggregate becomes a lead/lag
//! [`PrecedesEdge`]. Both are persisted as `Kv` CF rows under oracle-owned key
//! prefixes, each mutation paired with a `Score` ledger entry and verified by an
//! independent full-state readback (FSV).
//!
//! Grounding invariants (HONEST): every occurrence row carries the outcome's
//! catalog [`TrustTag`]; the attribution window, decay half-life, candidate cap,
//! and edge-support threshold are registry-declared knobs, never bare constants;
//! and every persisted mutation is paired with its ledger entry. Nothing is
//! synthetic — changes come from validated Git archaeology and outcomes from
//! grounded anchor rows.

use std::collections::{BTreeMap, BTreeSet};

use astrolabe_anchors::PersistedAnchorRow;
use astrolabe_anchors::archaeology::GitArchaeologyReport;
use astrolabe_domain::TrustTag;
use astrolabe_domain::fsv::FsvAck;
use astrolabe_domain::knobs::U64KnobDeclaration;
use astrolabe_ingest::VaultMutationPlan;
use calyx_aster::cf::{ColumnFamily, ledger_key};
use calyx_aster::ledger_view::parse_aster_ledger_seq;
use calyx_aster::mvcc::{is_tombstone_value, tombstone_value};
use calyx_aster::vault::AsterVault;
use calyx_core::{AnchorValue, CalyxError, Clock, CxId, LedgerRef, Ts, VaultStore};
use calyx_ledger::decode as decode_ledger;
use calyx_ledger::{ActorId, EntryKind, RedactionPolicy, SubjectId};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Stable failure codes
// ---------------------------------------------------------------------------

/// Stable failure code for an out-of-bounds attribution configuration.
pub const ASTRO_ORACLE_CONFIG_INVALID: &str = "ASTRO_ORACLE_CONFIG_INVALID";
/// Stable failure code for a structurally invalid change or outcome event.
pub const ASTRO_ORACLE_EVENT_INVALID: &str = "ASTRO_ORACLE_EVENT_INVALID";
/// Stable failure code for corrupt or inconsistent persisted oracle rows.
pub const ASTRO_ORACLE_ROW_CORRUPT: &str = "ASTRO_ORACLE_ROW_CORRUPT";
/// Stable failure code when the paired ledger entry cannot be recovered.
pub const ASTRO_ORACLE_LEDGER_MISSING: &str = "ASTRO_ORACLE_LEDGER_MISSING";

const ORACLE_REMEDIATION: &str = "re-mine the corpus with astrolabe_oracle::mine_corpus from validated change and outcome events, then persist with persist_corpus";

// ---------------------------------------------------------------------------
// Schemas and CF key prefixes
// ---------------------------------------------------------------------------

/// Row schema tag for a persisted occurrence row.
pub const ORACLE_OCCURRENCE_ROW_SCHEMA: &str = "astrolabe-oracle-occurrence-row-v1";
/// Row schema tag for a persisted lead/lag PRECEDES edge row.
pub const ORACLE_PRECEDES_ROW_SCHEMA: &str = "astrolabe-oracle-precedes-edge-row-v1";
/// Ledger payload schema for one corpus-persistence group commit.
pub const ORACLE_CORPUS_LEDGER_SCHEMA: &str = "astrolabe.oracle_corpus.v1";
/// Stable direction label: a change always precedes the outcome it credits.
pub const PRECEDES_DIRECTION: &str = "change_precedes_outcome";

const ORACLE_OCCURRENCE_PREFIX: &[u8] = b"astrolabe:oracle-occurrence:v1:";
const ORACLE_PRECEDES_PREFIX: &[u8] = b"astrolabe:oracle-precedes:v1:";

// ---------------------------------------------------------------------------
// Registry-declared attribution knobs (standing invariant 4)
// ---------------------------------------------------------------------------

/// Registry version tag for the oracle attribution knobs (#49).
pub const ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION: &str = "astrolabe-oracle-attribution-knobs-v1";

/// Name of the attribution-window knob.
pub const ORACLE_ATTRIBUTION_WINDOW_SECS_KNOB: &str = "oracle_attribution_window_secs";
/// Name of the decay half-life knob.
pub const ORACLE_DECAY_HALF_LIFE_SECS_KNOB: &str = "oracle_decay_half_life_secs";
/// Name of the per-outcome candidate-cap knob.
pub const ORACLE_CANDIDATE_CAP_KNOB: &str = "oracle_candidate_cap";
/// Name of the minimum edge-support knob.
pub const ORACLE_MIN_EDGE_SUPPORT_KNOB: &str = "oracle_min_edge_support";

/// Default attribution window: 14 days in seconds.
pub const ORACLE_DEFAULT_ATTRIBUTION_WINDOW_SECS: u64 = 14 * 24 * 60 * 60;
/// Smallest legal window: a window must admit at least one second of lag.
pub const ORACLE_MIN_ATTRIBUTION_WINDOW_SECS: u64 = 1;
/// Largest legal window: ten years, an upper bound so a corpus pass stays bounded.
pub const ORACLE_MAX_ATTRIBUTION_WINDOW_SECS: u64 = 10 * 365 * 24 * 60 * 60;

/// Default decay half-life: 7 days in seconds (credit halves each week of lag).
pub const ORACLE_DEFAULT_DECAY_HALF_LIFE_SECS: u64 = 7 * 24 * 60 * 60;
/// Smallest legal half-life. Zero is illegal: a zero half-life makes every decay
/// weight collapse to zero, which erases the credit signal this knob exists for.
pub const ORACLE_MIN_DECAY_HALF_LIFE_SECS: u64 = 1;
/// Largest legal half-life: ten years, matching the window ceiling.
pub const ORACLE_MAX_DECAY_HALF_LIFE_SECS: u64 = 10 * 365 * 24 * 60 * 60;

/// Default per-outcome candidate cap: the 50 nearest preceding changes.
pub const ORACLE_DEFAULT_CANDIDATE_CAP: u64 = 50;
/// Smallest legal candidate cap: an attributed outcome must credit at least one
/// change. Zero is illegal: a zero cap silently drops every attribution.
pub const ORACLE_MIN_CANDIDATE_CAP: u64 = 1;
/// Largest legal candidate cap: an upper bound so a pathological history cannot
/// make one outcome credit an unbounded number of changes.
pub const ORACLE_MAX_CANDIDATE_CAP: u64 = 100_000;

/// Default minimum edge support: three attributed occurrences before a lead/lag
/// PRECEDES edge is emitted for a subject.
pub const ORACLE_DEFAULT_MIN_EDGE_SUPPORT: u64 = 3;
/// Smallest legal edge support. Zero is illegal: a zero threshold would mint an
/// edge from no evidence at all.
pub const ORACLE_MIN_MIN_EDGE_SUPPORT: u64 = 1;
/// Largest legal edge support: an upper bound so the threshold stays a small,
/// operator-tunable count rather than an effectively-unreachable gate.
pub const ORACLE_MAX_MIN_EDGE_SUPPORT: u64 = 1_000_000;

/// The oracle attribution knob registry (#49).
///
/// The window default follows common CI/incident attribution practice (a
/// two-week regression-attribution horizon); the exponential decay mirrors the
/// half-life credit-attribution model used in marketing/causal attribution
/// (credit halves every half-life of lag); the candidate cap bounds fan-out; and
/// the edge-support threshold keeps a single coincidence from minting an edge.
/// Every default is a seed to be replaced by a measured value once corpus
/// statistics are benchmarked.
pub const ORACLE_ATTRIBUTION_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION,
        name: ORACLE_ATTRIBUTION_WINDOW_SECS_KNOB,
        default: ORACLE_DEFAULT_ATTRIBUTION_WINDOW_SECS,
        min: ORACLE_MIN_ATTRIBUTION_WINDOW_SECS,
        max: ORACLE_MAX_ATTRIBUTION_WINDOW_SECS,
        unit: "seconds",
        source: "ASTROLABE blueprint P7.5 change-to-outcome attribution horizon; two-week regression-attribution window common in CI/incident post-mortems",
        rationale: "bounds how long after a change an outcome may still be attributed to it; 14 days is the seed horizon over which a regression is still plausibly caused by a change; replace with a measured value once outcome-lag distributions are benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION,
        name: ORACLE_DECAY_HALF_LIFE_SECS_KNOB,
        default: ORACLE_DEFAULT_DECAY_HALF_LIFE_SECS,
        min: ORACLE_MIN_DECAY_HALF_LIFE_SECS,
        max: ORACLE_MAX_DECAY_HALF_LIFE_SECS,
        unit: "seconds",
        source: "half-life time-decay credit-attribution model (credit halves every half-life of lag), as used in causal/marketing attribution",
        rationale: "sets how fast attribution credit decays with lag: weight = 0.5^(lag/half_life); 7 days halves a change's credit each week; zero is illegal because it collapses every weight to zero; replace with a measured decay once lag-to-causality strength is benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION,
        name: ORACLE_CANDIDATE_CAP_KNOB,
        default: ORACLE_DEFAULT_CANDIDATE_CAP,
        min: ORACLE_MIN_CANDIDATE_CAP,
        max: ORACLE_MAX_CANDIDATE_CAP,
        unit: "changes",
        source: "ASTROLABE #49 bounded attribution fan-out; mirrors astrolabe-domain DEFAULT_SIMILARITY_EXACT_PAIR_NODE_LIMIT-style per-record caps",
        rationale: "bounds how many preceding changes one outcome credits (the nearest-by-lag N), so an outcome in a dense history cannot fan out unboundedly; the cap is applied deterministically (smallest lag first, change-id tiebreak); replace with a measured value once fan-out distributions are benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION,
        name: ORACLE_MIN_EDGE_SUPPORT_KNOB,
        default: ORACLE_DEFAULT_MIN_EDGE_SUPPORT,
        min: ORACLE_MIN_MIN_EDGE_SUPPORT,
        max: ORACLE_MAX_MIN_EDGE_SUPPORT,
        unit: "occurrences",
        source: "ASTROLABE #49 lead/lag edge support gate; minimum-support convention from frequent-pattern / association-rule mining",
        rationale: "minimum attributed occurrences on a subject before a lead/lag PRECEDES edge is emitted, so a single coincidence cannot mint an edge; 3 is the seed support floor; replace with a measured value once edge precision/recall is benchmarked",
    },
];

/// Returns the oracle attribution declaration for `name`, or `None`.
pub fn oracle_attribution_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ORACLE_ATTRIBUTION_KNOBS
        .iter()
        .find(|knob| knob.name == name)
}

fn knob(name: &str) -> &'static U64KnobDeclaration {
    oracle_attribution_knob(name).expect("oracle attribution knob is declared")
}

// ---------------------------------------------------------------------------
// Attribution configuration
// ---------------------------------------------------------------------------

/// Validated attribution policy for one corpus-mining pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributionConfig {
    /// Inclusive upper bound on `outcome_ts - change_ts`, in seconds.
    pub window_secs: u64,
    /// Exponential decay half-life, in seconds.
    pub decay_half_life_secs: u64,
    /// Maximum preceding changes credited per outcome (nearest-by-lag).
    pub candidate_cap: usize,
    /// Minimum attributed occurrences before a subject earns a PRECEDES edge.
    pub min_edge_support: usize,
}

impl Default for AttributionConfig {
    /// The registry-declared defaults.
    fn default() -> Self {
        Self {
            window_secs: knob(ORACLE_ATTRIBUTION_WINDOW_SECS_KNOB).default,
            decay_half_life_secs: knob(ORACLE_DECAY_HALF_LIFE_SECS_KNOB).default,
            candidate_cap: knob(ORACLE_CANDIDATE_CAP_KNOB).default as usize,
            min_edge_support: knob(ORACLE_MIN_EDGE_SUPPORT_KNOB).default as usize,
        }
    }
}

impl AttributionConfig {
    /// Fails closed when any field falls outside its declared knob bounds.
    pub fn validate(&self) -> Result<(), OracleError> {
        check_knob(ORACLE_ATTRIBUTION_WINDOW_SECS_KNOB, self.window_secs)?;
        check_knob(ORACLE_DECAY_HALF_LIFE_SECS_KNOB, self.decay_half_life_secs)?;
        check_knob(ORACLE_CANDIDATE_CAP_KNOB, self.candidate_cap as u64)?;
        check_knob(ORACLE_MIN_EDGE_SUPPORT_KNOB, self.min_edge_support as u64)?;
        Ok(())
    }
}

fn check_knob(name: &str, value: u64) -> Result<(), OracleError> {
    let declared = knob(name);
    if declared.accepts(value) {
        Ok(())
    } else {
        Err(OracleError::new(
            ASTRO_ORACLE_CONFIG_INVALID,
            format!(
                "attribution knob {name} value {value} is outside declared bounds [{}, {}]",
                declared.min, declared.max
            ),
        ))
    }
}

// ---------------------------------------------------------------------------
// Coded error
// ---------------------------------------------------------------------------

/// Coded, remediable oracle error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleError {
    pub code: &'static str,
    pub message: String,
    pub remediation: &'static str,
}

impl OracleError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            remediation: ORACLE_REMEDIATION,
        }
    }
}

impl std::fmt::Display for OracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for OracleError {}

impl From<OracleError> for CalyxError {
    fn from(error: OracleError) -> Self {
        CalyxError {
            code: error.code,
            message: error.message,
            remediation: error.remediation,
        }
    }
}

// ---------------------------------------------------------------------------
// Input events
// ---------------------------------------------------------------------------

/// A change touching one subject constellation at a wall-clock instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEvent {
    /// Stable change identifier (for example a Git object id).
    pub change_id: String,
    /// Subject constellation the change touched.
    pub subject: CxId,
    /// Change wall-clock timestamp (seconds), never `0`.
    pub change_ts: Ts,
}

/// A grounded outcome observed on one subject constellation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeEvent {
    /// Catalog outcome source (for example `ci:github:42`).
    pub source: String,
    /// Subject constellation the outcome was observed on.
    pub subject: CxId,
    /// Outcome wall-clock timestamp (seconds), never `0`.
    pub outcome_ts: Ts,
    /// Whether the outcome was a pass.
    pub passed: bool,
}

fn validate_change(change: &ChangeEvent) -> Result<(), OracleError> {
    if change.change_id.trim().is_empty() {
        return Err(OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            "change_id is empty; a change must carry a stable identifier",
        ));
    }
    if change.change_ts == 0 {
        return Err(OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            format!(
                "change {:?} has change_ts 0; a real change carries a non-zero timestamp",
                change.change_id
            ),
        ));
    }
    Ok(())
}

fn validate_outcome(outcome: &OutcomeEvent) -> Result<(), OracleError> {
    if outcome.outcome_ts == 0 {
        return Err(OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            format!(
                "outcome {:?} has outcome_ts 0; a grounded outcome carries a non-zero timestamp",
                outcome.source
            ),
        ));
    }
    // The trust label is derived from the catalog source, so an unknown prefix
    // must refuse here rather than persist an unlabeled occurrence.
    trust_of(&outcome.source)?;
    Ok(())
}

fn trust_of(source: &str) -> Result<TrustTag, OracleError> {
    astrolabe_anchors::trust_for_source(source).map_err(|error| {
        OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            format!(
                "outcome source {source:?} is not a catalog source: {}",
                error.message()
            ),
        )
    })
}

// ---------------------------------------------------------------------------
// Mined records
// ---------------------------------------------------------------------------

/// One attributed `(change → outcome)` pair.
#[derive(Debug, Clone, PartialEq)]
pub struct OccurrenceRecord {
    /// Subject both the change and the outcome share.
    pub subject: CxId,
    /// The crediting change's identifier.
    pub change_id: String,
    /// The outcome's catalog source.
    pub source: String,
    /// Change timestamp (seconds).
    pub change_ts: Ts,
    /// Outcome timestamp (seconds).
    pub outcome_ts: Ts,
    /// Attribution lag `outcome_ts - change_ts` (seconds), always `<= window`.
    pub lag_s: u64,
    /// Exponential-decay weight `0.5^(lag/half_life)`, in `(0, 1]`.
    pub decay_weight: f64,
    /// Normalized credit share; the credits of all candidates for one outcome
    /// sum to `1.0`.
    pub credit: f64,
    /// Whether the outcome was a pass.
    pub passed: bool,
    /// Number of candidate changes the outcome's credit was split across.
    pub candidate_count: usize,
    /// Trust of the outcome's catalog source.
    pub trust: TrustTag,
}

/// One lead/lag PRECEDES edge aggregated over a subject's occurrences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecedesEdge {
    /// Subject the edge summarizes.
    pub subject: CxId,
    /// Number of attributed occurrences supporting the edge.
    pub support: usize,
    /// Lower-median attribution lag across the supporting occurrences (seconds).
    pub median_lag_s: u64,
}

/// A mined corpus: attributed occurrences plus the lead/lag edges over them.
#[derive(Debug, Clone, PartialEq)]
pub struct OracleCorpus {
    pub occurrences: Vec<OccurrenceRecord>,
    pub edges: Vec<PrecedesEdge>,
}

/// Exponential time-decay weight for one lag, in `(0, 1]`.
///
/// `weight = 0.5^(lag / half_life)`: `1.0` at lag `0`, halving each half-life.
fn decay_weight(lag_s: u64, half_life_secs: u64) -> f64 {
    0.5_f64.powf(lag_s as f64 / half_life_secs as f64)
}

/// Mines every attributed `(change → outcome)` occurrence.
///
/// For each outcome, the candidate changes are those on the same subject with
/// `change_ts <= outcome_ts` and `outcome_ts - change_ts <= window_secs`. The
/// candidates are ordered nearest-lag-first (change-id tiebreak) and capped at
/// `candidate_cap`; each candidate's decay weight is normalized so the credits
/// of one outcome's candidates sum to `1.0`.
///
/// Deterministic and seed-independent: the returned records are in a canonical
/// order that depends only on the event content, not on input ordering.
pub fn mine_occurrences(
    changes: &[ChangeEvent],
    outcomes: &[OutcomeEvent],
    config: &AttributionConfig,
) -> Result<Vec<OccurrenceRecord>, OracleError> {
    config.validate()?;
    for change in changes {
        validate_change(change)?;
    }
    for outcome in outcomes {
        validate_outcome(outcome)?;
    }

    // Index changes by subject, each list sorted by (ts, change_id) so the
    // candidate scan and its cap are input-order independent.
    let mut by_subject: BTreeMap<CxId, Vec<&ChangeEvent>> = BTreeMap::new();
    for change in changes {
        by_subject.entry(change.subject).or_default().push(change);
    }
    for list in by_subject.values_mut() {
        list.sort_by(|a, b| (a.change_ts, &a.change_id).cmp(&(b.change_ts, &b.change_id)));
        list.dedup_by(|a, b| a.change_id == b.change_id && a.change_ts == b.change_ts);
    }

    // Outcomes in a canonical order so the emitted records are deterministic.
    let mut outcomes_sorted: Vec<&OutcomeEvent> = outcomes.iter().collect();
    outcomes_sorted.sort_by(|a, b| {
        (a.subject, a.outcome_ts, &a.source, a.passed).cmp(&(
            b.subject,
            b.outcome_ts,
            &b.source,
            b.passed,
        ))
    });

    let mut records = Vec::new();
    for outcome in outcomes_sorted {
        let Some(subject_changes) = by_subject.get(&outcome.subject) else {
            continue;
        };
        let mut candidates: Vec<(u64, &ChangeEvent)> = subject_changes
            .iter()
            .filter(|change| {
                change.change_ts <= outcome.outcome_ts
                    && outcome.outcome_ts - change.change_ts <= config.window_secs
            })
            .map(|change| (outcome.outcome_ts - change.change_ts, *change))
            .collect();
        if candidates.is_empty() {
            continue;
        }
        // Nearest lag first, change-id tiebreak — the deterministic cap order.
        candidates.sort_by(|a, b| (a.0, &a.1.change_id).cmp(&(b.0, &b.1.change_id)));
        candidates.truncate(config.candidate_cap);

        let decays: Vec<f64> = candidates
            .iter()
            .map(|(lag, _)| decay_weight(*lag, config.decay_half_life_secs))
            .collect();
        // Every decay weight is strictly positive for a finite lag, so the sum
        // is strictly positive and the normalized credits sum to 1.0.
        let decay_sum: f64 = decays.iter().sum();
        let trust = trust_of(&outcome.source)?;
        let candidate_count = candidates.len();
        for (index, (lag, change)) in candidates.iter().enumerate() {
            records.push(OccurrenceRecord {
                subject: outcome.subject,
                change_id: change.change_id.clone(),
                source: outcome.source.clone(),
                change_ts: change.change_ts,
                outcome_ts: outcome.outcome_ts,
                lag_s: *lag,
                decay_weight: decays[index],
                credit: decays[index] / decay_sum,
                passed: outcome.passed,
                candidate_count,
                trust,
            });
        }
    }
    records.sort_by(occurrence_order);
    Ok(records)
}

/// Aggregates occurrences into lead/lag PRECEDES edges.
///
/// A subject earns an edge only when at least `min_edge_support` occurrences
/// credit it; the edge's `median_lag_s` is the lower-median attribution lag over
/// those occurrences. Because every occurrence has `change_ts <= outcome_ts`,
/// the median lag is non-negative — the change always precedes the outcome.
pub fn precedes_edges(
    records: &[OccurrenceRecord],
    config: &AttributionConfig,
) -> Vec<PrecedesEdge> {
    let mut lags_by_subject: BTreeMap<CxId, Vec<u64>> = BTreeMap::new();
    for record in records {
        lags_by_subject
            .entry(record.subject)
            .or_default()
            .push(record.lag_s);
    }
    let mut edges = Vec::new();
    for (subject, mut lags) in lags_by_subject {
        if lags.len() < config.min_edge_support {
            continue;
        }
        lags.sort_unstable();
        let median_lag_s = lags[(lags.len() - 1) / 2];
        edges.push(PrecedesEdge {
            subject,
            support: lags.len(),
            median_lag_s,
        });
    }
    edges.sort_by_key(|edge| edge.subject);
    edges
}

/// Mines the full corpus: occurrences plus their PRECEDES edges.
pub fn mine_corpus(
    changes: &[ChangeEvent],
    outcomes: &[OutcomeEvent],
    config: &AttributionConfig,
) -> Result<OracleCorpus, OracleError> {
    let occurrences = mine_occurrences(changes, outcomes, config)?;
    let edges = precedes_edges(&occurrences, config);
    Ok(OracleCorpus { occurrences, edges })
}

fn occurrence_order(a: &OccurrenceRecord, b: &OccurrenceRecord) -> std::cmp::Ordering {
    (
        a.subject,
        a.outcome_ts,
        &a.source,
        a.passed,
        a.lag_s,
        &a.change_id,
    )
        .cmp(&(
            b.subject,
            b.outcome_ts,
            &b.source,
            b.passed,
            b.lag_s,
            &b.change_id,
        ))
}

// ---------------------------------------------------------------------------
// Adapters from validated ground truth
// ---------------------------------------------------------------------------

/// Derives change events from a validated Git-archaeology report.
///
/// Each SZZ finding's fix commit is a change touching the subject constellation
/// that `subject_for_path` resolves the changed path to. Paths that resolve to
/// `None` (unmapped in the current panel) are skipped — counted absence, never a
/// silent guess. Duplicate `(fix_commit, subject)` pairs collapse to one change.
pub fn changes_from_git_archaeology(
    report: &GitArchaeologyReport,
    mut subject_for_path: impl FnMut(&str) -> Option<CxId>,
) -> Vec<ChangeEvent> {
    let mut seen: BTreeSet<(String, CxId)> = BTreeSet::new();
    let mut changes = Vec::new();
    for finding in &report.szz_findings {
        let Some(subject) = subject_for_path(&finding.path) else {
            continue;
        };
        if seen.insert((finding.fix_commit.clone(), subject)) {
            changes.push(ChangeEvent {
                change_id: finding.fix_commit.clone(),
                subject,
                change_ts: finding.observed_at,
            });
        }
    }
    changes
}

/// Derives outcome events from persisted boolean anchor rows.
///
/// Each boolean-valued anchor becomes one outcome on the row's subject, carrying
/// its catalog source, observed-at timestamp, and pass/fail. Non-boolean anchors
/// carry no pass/fail semantics and are skipped.
pub fn outcomes_from_anchor_rows(rows: &[PersistedAnchorRow]) -> Vec<OutcomeEvent> {
    let mut outcomes = Vec::new();
    for persisted in rows {
        for anchor in &persisted.row.anchors {
            if let AnchorValue::Bool(passed) = anchor.value {
                outcomes.push(OutcomeEvent {
                    source: anchor.source.clone(),
                    subject: persisted.row.cx_id,
                    outcome_ts: anchor.observed_at,
                    passed,
                });
            }
        }
    }
    outcomes
}

// ---------------------------------------------------------------------------
// Persisted rows
// ---------------------------------------------------------------------------

/// A persisted occurrence row (`Kv` CF, oracle-owned prefix).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OccurrenceRowV1 {
    /// Always [`ORACLE_OCCURRENCE_ROW_SCHEMA`].
    pub schema: String,
    pub subject: CxId,
    pub change_id: String,
    pub source: String,
    pub change_ts: Ts,
    pub outcome_ts: Ts,
    pub lag_s: u64,
    pub decay_weight: f64,
    pub credit: f64,
    pub passed: bool,
    pub candidate_count: usize,
    pub trust: TrustTag,
}

/// A persisted lead/lag PRECEDES edge row (`Kv` CF, oracle-owned prefix).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrecedesEdgeRowV1 {
    /// Always [`ORACLE_PRECEDES_ROW_SCHEMA`].
    pub schema: String,
    pub subject: CxId,
    pub support: usize,
    pub median_lag_s: u64,
    /// Always [`PRECEDES_DIRECTION`].
    pub direction: String,
}

impl OccurrenceRowV1 {
    fn from_record(record: &OccurrenceRecord) -> Self {
        Self {
            schema: ORACLE_OCCURRENCE_ROW_SCHEMA.to_string(),
            subject: record.subject,
            change_id: record.change_id.clone(),
            source: record.source.clone(),
            change_ts: record.change_ts,
            outcome_ts: record.outcome_ts,
            lag_s: record.lag_s,
            decay_weight: record.decay_weight,
            credit: record.credit,
            passed: record.passed,
            candidate_count: record.candidate_count,
            trust: record.trust,
        }
    }
}

impl PrecedesEdgeRowV1 {
    fn from_edge(edge: &PrecedesEdge) -> Self {
        Self {
            schema: ORACLE_PRECEDES_ROW_SCHEMA.to_string(),
            subject: edge.subject,
            support: edge.support,
            median_lag_s: edge.median_lag_s,
            direction: PRECEDES_DIRECTION.to_string(),
        }
    }
}

/// CF key for one occurrence: prefix ‖ blake3(subject ‖ change_id ‖ source ‖ ts).
///
/// The identity is `(subject, change_id, source, outcome_ts)` — a change credits
/// a given outcome (identified by its source and instant) exactly once.
fn occurrence_key(subject: CxId, change_id: &str, source: &str, outcome_ts: Ts) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(subject.as_bytes());
    hasher.update(&[0]);
    hasher.update(change_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(source.as_bytes());
    hasher.update(&[0]);
    hasher.update(&outcome_ts.to_be_bytes());
    let mut key = ORACLE_OCCURRENCE_PREFIX.to_vec();
    key.extend_from_slice(hasher.finalize().as_bytes());
    key
}

/// CF key for one subject's PRECEDES edge: prefix ‖ blake3(subject).
fn precedes_key(subject: CxId) -> Vec<u8> {
    let mut key = ORACLE_PRECEDES_PREFIX.to_vec();
    key.extend_from_slice(blake3::hash(subject.as_bytes()).as_bytes());
    key
}

fn is_oracle_key(key: &[u8]) -> bool {
    key.starts_with(ORACLE_OCCURRENCE_PREFIX) || key.starts_with(ORACLE_PRECEDES_PREFIX)
}

// ---------------------------------------------------------------------------
// Persistence report and read-back witnesses
// ---------------------------------------------------------------------------

/// Report for one corpus-persistence group commit.
#[derive(Debug, Clone, PartialEq)]
pub struct OracleCorpusPersistReport {
    /// Occurrence rows the corpus produced.
    pub occurrence_count: usize,
    /// PRECEDES edge rows the corpus produced.
    pub edge_count: usize,
    /// Rows written or rewritten in this commit.
    pub rows_written: usize,
    /// Rows already byte-identical and left untouched.
    pub rows_unchanged: usize,
    /// Owned rows tombstoned because the fresh corpus no longer produces them.
    pub rows_tombstoned: usize,
    /// Lowercase-hex blake3 of the canonical corpus dump, as ledgered.
    pub corpus_dump_hash: String,
    /// Ledger entry paired with this mutation batch.
    pub ledger_ref: LedgerRef,
    /// Full-readback witness when rows changed; labeled absence on a no-op.
    pub fsv: Option<FsvAck>,
}

/// One decoded, key-verified occurrence row read back from the `Kv` CF.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedOccurrenceRow {
    pub key: Vec<u8>,
    pub row: OccurrenceRowV1,
}

/// One decoded, key-verified PRECEDES edge row read back from the `Kv` CF.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedPrecedesEdgeRow {
    pub key: Vec<u8>,
    pub row: PrecedesEdgeRowV1,
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Persists a mined corpus into the `Kv` CF, reconciling against the full
/// oracle-owned keyspace.
///
/// Rows are written when new or changed, kept when byte-identical, and
/// tombstoned when the fresh corpus no longer produces them. Because the desired
/// state is recomputed in full from `corpus` on every call, persisting an
/// incrementally-grown corpus converges to byte-identical live CF state as a
/// single full-pass persist of the same final corpus. The batch and its
/// hash-only `Score` ledger entry land in one atomic group commit, and the
/// mutation is FSV-verified against an independent readback.
pub fn persist_corpus<C>(
    vault: &AsterVault<C>,
    corpus: &OracleCorpus,
    actor: impl Into<String>,
) -> calyx_core::Result<OracleCorpusPersistReport>
where
    C: Clock,
{
    let mut new_rows: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for record in &corpus.occurrences {
        let key = occurrence_key(
            record.subject,
            &record.change_id,
            &record.source,
            record.outcome_ts,
        );
        let value = serde_json::to_vec(&OccurrenceRowV1::from_record(record))
            .map_err(|error| oracle_corrupt(format!("encode occurrence row: {error}")))?;
        if new_rows.insert(key, value).is_some() {
            return Err(oracle_corrupt(format!(
                "corpus holds a duplicate occurrence identity for subject {} change {:?}",
                record.subject, record.change_id
            )));
        }
    }
    for edge in &corpus.edges {
        let key = precedes_key(edge.subject);
        let value = serde_json::to_vec(&PrecedesEdgeRowV1::from_edge(edge))
            .map_err(|error| oracle_corrupt(format!("encode precedes edge row: {error}")))?;
        if new_rows.insert(key, value).is_some() {
            return Err(oracle_corrupt(format!(
                "corpus holds a duplicate PRECEDES edge for subject {}",
                edge.subject
            )));
        }
    }

    // Owned keyspace: every live oracle row plus every fresh corpus key.
    let snapshot = vault.snapshot();
    let mut owned_keys: BTreeSet<Vec<u8>> = BTreeSet::new();
    for (key, value) in vault.scan_cf_at(snapshot, ColumnFamily::Kv)? {
        if is_oracle_key(&key) && !is_tombstone_value(&value) {
            owned_keys.insert(key);
        }
    }
    for key in new_rows.keys() {
        owned_keys.insert(key.clone());
    }

    let tombstone = tombstone_value();
    let mut batch = Vec::new();
    let mut rows_written = 0usize;
    let mut rows_unchanged = 0usize;
    let mut rows_tombstoned = 0usize;
    for key in &owned_keys {
        let existing = vault.read_cf_at(snapshot, ColumnFamily::Kv, key)?;
        match (new_rows.get(key), existing) {
            (Some(value), Some(existing_value)) if existing_value == *value => {
                rows_unchanged += 1;
            }
            (Some(value), _) => {
                batch.push((ColumnFamily::Kv, key.clone(), value.clone()));
                rows_written += 1;
            }
            (None, Some(_)) => {
                batch.push((ColumnFamily::Kv, key.clone(), tombstone.clone()));
                rows_tombstoned += 1;
            }
            (None, None) => {}
        }
    }

    let dump = corpus_dump_bytes(corpus);
    let corpus_dump_hash = hex_lower(blake3::hash(&dump).as_bytes());

    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": ORACLE_CORPUS_LEDGER_SCHEMA,
        "occurrence_count": corpus.occurrences.len(),
        "edge_count": corpus.edges.len(),
        "rows_written": rows_written,
        "rows_unchanged": rows_unchanged,
        "rows_tombstoned": rows_tombstoned,
        "corpus_dump_hash": corpus_dump_hash,
    }))
    .map_err(|error| oracle_corrupt(format!("encode oracle ledger payload: {error}")))?;
    RedactionPolicy::check_payload(&payload)?;

    let subject =
        SubjectId::Query(format!("astrolabe-oracle-corpus:{corpus_dump_hash}").into_bytes());
    let actor = ActorId::Service(actor.into());
    let mut fsv_plan =
        VaultMutationPlan::new("persist_oracle_corpus", EntryKind::Score, &actor, &subject);
    for (cf, key, value) in &batch {
        if *value == tombstone {
            fsv_plan.push_tombstoned(*cf, key.clone(), &tombstone);
        } else {
            fsv_plan.push_content(*cf, key.clone(), value);
        }
    }

    let (ledger_ref, commit_seq) = if batch.is_empty() {
        (
            vault.append_ledger_entry(EntryKind::Score, subject, payload, actor)?,
            None,
        )
    } else {
        let commit_seq = vault.write_cf_batch_with_ledger_entry(
            batch,
            EntryKind::Score,
            subject,
            payload,
            actor,
        )?;
        (ledger_ref_at_commit(vault, commit_seq)?, Some(commit_seq))
    };
    vault.flush()?;
    let fsv = commit_seq
        .map(|commit_seq| fsv_plan.verify_committed(vault, commit_seq))
        .transpose()?;

    Ok(OracleCorpusPersistReport {
        occurrence_count: corpus.occurrences.len(),
        edge_count: corpus.edges.len(),
        rows_written,
        rows_unchanged,
        rows_tombstoned,
        corpus_dump_hash,
        ledger_ref,
        fsv,
    })
}

/// Reads back and key-verifies every live persisted occurrence row.
pub fn read_occurrence_rows<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<Vec<PersistedOccurrenceRow>>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut rows = Vec::new();
    for (key, value) in vault.scan_cf_at(snapshot, ColumnFamily::Kv)? {
        if !key.starts_with(ORACLE_OCCURRENCE_PREFIX) || is_tombstone_value(&value) {
            continue;
        }
        let row: OccurrenceRowV1 = serde_json::from_slice(&value).map_err(|error| {
            oracle_corrupt(format!(
                "decode occurrence row {}: {error}",
                hex_lower(&key)
            ))
        })?;
        if row.schema != ORACLE_OCCURRENCE_ROW_SCHEMA {
            return Err(oracle_corrupt(format!(
                "occurrence row {} carries schema {:?}",
                hex_lower(&key),
                row.schema
            )));
        }
        let expected = occurrence_key(row.subject, &row.change_id, &row.source, row.outcome_ts);
        if key != expected {
            return Err(oracle_corrupt(format!(
                "occurrence row key {} does not match its decoded identity",
                hex_lower(&key)
            )));
        }
        if row.outcome_ts < row.change_ts {
            return Err(oracle_corrupt(format!(
                "occurrence row {} has outcome_ts < change_ts (anti-causal)",
                hex_lower(&key)
            )));
        }
        if row.lag_s != row.outcome_ts - row.change_ts {
            return Err(oracle_corrupt(format!(
                "occurrence row {} lag_s does not equal outcome_ts - change_ts",
                hex_lower(&key)
            )));
        }
        rows.push(PersistedOccurrenceRow { key, row });
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(rows)
}

/// Reads back and key-verifies every live persisted PRECEDES edge row.
pub fn read_precedes_edges<C>(
    vault: &AsterVault<C>,
) -> calyx_core::Result<Vec<PersistedPrecedesEdgeRow>>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut rows = Vec::new();
    for (key, value) in vault.scan_cf_at(snapshot, ColumnFamily::Kv)? {
        if !key.starts_with(ORACLE_PRECEDES_PREFIX) || is_tombstone_value(&value) {
            continue;
        }
        let row: PrecedesEdgeRowV1 = serde_json::from_slice(&value).map_err(|error| {
            oracle_corrupt(format!(
                "decode precedes edge row {}: {error}",
                hex_lower(&key)
            ))
        })?;
        if row.schema != ORACLE_PRECEDES_ROW_SCHEMA || row.direction != PRECEDES_DIRECTION {
            return Err(oracle_corrupt(format!(
                "precedes edge row {} carries schema {:?} / direction {:?}",
                hex_lower(&key),
                row.schema,
                row.direction
            )));
        }
        if key != precedes_key(row.subject) {
            return Err(oracle_corrupt(format!(
                "precedes edge row key {} does not match its decoded subject",
                hex_lower(&key)
            )));
        }
        rows.push(PersistedPrecedesEdgeRow { key, row });
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(rows)
}

/// Live oracle `Kv` rows in canonical order, tombstones excluded — the byte
/// substrate for the incremental-equals-full-pass comparison.
pub fn raw_oracle_rows<C>(vault: &AsterVault<C>) -> calyx_core::Result<Vec<(Vec<u8>, Vec<u8>)>>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    let mut rows: Vec<(Vec<u8>, Vec<u8>)> = vault
        .scan_cf_at(snapshot, ColumnFamily::Kv)?
        .into_iter()
        .filter(|(key, value)| is_oracle_key(key) && !is_tombstone_value(value))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(rows)
}

/// Canonical byte dump of a corpus for the ledger content hash and determinism
/// probes. One sorted line per occurrence and per edge; floats are dumped by
/// their exact IEEE-754 bit pattern so equal corpora hash identically.
pub fn corpus_dump_bytes(corpus: &OracleCorpus) -> Vec<u8> {
    let mut lines = Vec::new();
    for record in &corpus.occurrences {
        lines.push(format!(
            "OCC\t{}\t{}\t{}\t{}\t{}\t{}\t{:016x}\t{:016x}\t{}\t{}\t{}",
            record.subject,
            record.change_id,
            record.source,
            record.change_ts,
            record.outcome_ts,
            record.lag_s,
            record.decay_weight.to_bits(),
            record.credit.to_bits(),
            record.passed,
            record.candidate_count,
            record.trust.as_str(),
        ));
    }
    for edge in &corpus.edges {
        lines.push(format!(
            "EDGE\t{}\t{}\t{}",
            edge.subject, edge.support, edge.median_lag_s
        ));
    }
    lines.sort();
    let mut out = String::new();
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
    out.into_bytes()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn ledger_ref_at_commit<C>(vault: &AsterVault<C>, commit_seq: u64) -> calyx_core::Result<LedgerRef>
where
    C: Clock,
{
    let (key, value) = vault
        .scan_cf_at(commit_seq, ColumnFamily::Ledger)?
        .into_iter()
        .max_by(|left, right| left.0.cmp(&right.0))
        .ok_or_else(|| CalyxError {
            code: ASTRO_ORACLE_LEDGER_MISSING,
            message: "Ledger CF empty at oracle corpus commit snapshot".to_string(),
            remediation: ORACLE_REMEDIATION,
        })?;
    let key_seq = parse_aster_ledger_seq(&key)?;
    let entry = decode_ledger(&value)?;
    if entry.seq != key_seq {
        return Err(CalyxError {
            code: ASTRO_ORACLE_LEDGER_MISSING,
            message: format!(
                "Ledger CF key seq {key_seq} does not match encoded entry seq {}",
                entry.seq
            ),
            remediation: ORACLE_REMEDIATION,
        });
    }
    debug_assert_eq!(key, ledger_key(key_seq));
    Ok(LedgerRef {
        seq: entry.seq,
        hash: entry.entry_hash,
    })
}

fn oracle_corrupt(message: String) -> CalyxError {
    CalyxError {
        code: ASTRO_ORACLE_ROW_CORRUPT,
        message,
        remediation: ORACLE_REMEDIATION,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    use astrolabe_anchors::archaeology::{GitArchaeologyConfig, GitMineMode, mine_git_archaeology};
    use astrolabe_anchors::{
        OutcomeAnchorRequest, OutcomeKind, OutcomeSubject, ingest_outcome_anchors, read_anchor_rows,
    };
    use calyx_aster::vault::VaultOptions;
    use calyx_core::{AnchorKind, SystemClock, VaultId};
    use calyx_ledger::{EntryKind, decode as decode_ledger};
    use proptest::prelude::*;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
    const TEST_SALT: &[u8] = b"astrolabe-oracle-corpus-fsv";

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
            "astrolabe-oracle-{name}-{}-{}",
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
        .expect("open durable oracle test vault")
    }

    fn fresh_vault(name: &str) -> (TempDir, AsterVault<SystemClock>) {
        let dir = temp_dir(name);
        let vault = open_vault(&dir);
        (dir, vault)
    }

    fn cx(byte: u8) -> CxId {
        CxId::from_bytes([byte; 16])
    }

    /// Regression (#340): a persisted occurrence row's raw f64 `decay_weight` and
    /// `credit` must read back bit-for-bit identical after a serde_json round-trip
    /// through the `Kv` CF, or a served prediction recomputed from reloaded corpus
    /// rows silently drifts from the value committed at ingest.
    ///
    /// serde_json's default float parser is lossy for some f64 values — e.g.
    /// `0.9500000000000001` (bits `0x3fee666666666667`) parses back as `0.95`
    /// (bits `0x3fee666666666666`), a one-ULP shift. The `float_roundtrip`
    /// feature (declared on this crate's serde_json) makes the parse exact. This
    /// FSV writes real durable rows carrying known-lossy and edge-case f64 values,
    /// reopens the store, reads them back through the production
    /// [`read_occurrence_rows`] reader, and asserts exact IEEE-754 bit equality.
    #[test]
    fn occurrence_row_f64_round_trips_bit_exact_across_persist_reload() {
        // Known-lossy under the default parser, plus max-precision, subnormals,
        // negative zero, and exactly-representable no-op values.
        let probes: &[(f64, f64)] = &[
            // Headline Wilson-CI-shaped lossy value in both float fields.
            (0.9500000000000001, 0.9500000000000001),
            (f64::MAX, f64::MIN_POSITIVE),      // max magnitude / smallest normal
            // smallest subnormal / largest subnormal (denormal boundary, by bits).
            (5e-324, f64::from_bits(0x000f_ffff_ffff_ffff)),
            (1.0 / 3.0, std::f64::consts::PI),  // repeating / transcendental
            (-0.0, 0.5),                        // negative zero vs exact no-op
            (0.29999999999999993, 0.1 + 0.2),   // classic binary-fp residues
        ];

        let corpus = OracleCorpus {
            occurrences: probes
                .iter()
                .enumerate()
                .map(|(i, &(decay_weight, credit))| OccurrenceRecord {
                    subject: cx(1),
                    change_id: format!("fix-{i}"),
                    source: "ci:test".to_string(),
                    change_ts: 1_000,
                    outcome_ts: 4_600,
                    lag_s: 3_600,
                    decay_weight,
                    credit,
                    passed: true,
                    candidate_count: 1,
                    trust: TrustTag::Trusted,
                })
                .collect(),
            edges: Vec::new(),
        };

        let (vault_dir, vault) = fresh_vault("f64-roundtrip");
        let report = persist_corpus(&vault, &corpus, "oracle-f64-fsv").expect("persist corpus");
        assert_eq!(report.occurrence_count, probes.len());
        drop(vault);

        // Independent readback from a reopened durable store — real persisted bytes.
        let reopened = open_vault(&vault_dir);
        let rows = read_occurrence_rows(&reopened).expect("read occurrence rows");
        assert_eq!(rows.len(), probes.len(), "every row persisted and re-read");

        for (i, &(decay_weight, credit)) in probes.iter().enumerate() {
            let change_id = format!("fix-{i}");
            let row = rows
                .iter()
                .map(|persisted| &persisted.row)
                .find(|row| row.change_id == change_id)
                .unwrap_or_else(|| panic!("row {change_id} missing after reload"));
            assert_eq!(
                row.decay_weight.to_bits(),
                decay_weight.to_bits(),
                "decay_weight bit drift for {change_id}: wrote {decay_weight:?} \
                 (0x{:016x}) read 0x{:016x}",
                decay_weight.to_bits(),
                row.decay_weight.to_bits(),
            );
            assert_eq!(
                row.credit.to_bits(),
                credit.to_bits(),
                "credit bit drift for {change_id}: wrote {credit:?} \
                 (0x{:016x}) read 0x{:016x}",
                credit.to_bits(),
                row.credit.to_bits(),
            );
        }
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

    fn narrow_config(window: u64) -> AttributionConfig {
        AttributionConfig {
            window_secs: window,
            decay_half_life_secs: window / 2 + 1,
            candidate_cap: 50,
            min_edge_support: 3,
        }
    }

    // ------------------------------------------------------------------
    // Registry knob sanity (standing invariant 4)
    // ------------------------------------------------------------------

    #[test]
    fn every_attribution_knob_declares_bounds_that_contain_its_default() {
        assert!(!ORACLE_ATTRIBUTION_KNOBS.is_empty());
        for declared in ORACLE_ATTRIBUTION_KNOBS {
            assert_eq!(
                declared.registry_version, ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION,
                "{declared:?}"
            );
            assert!(declared.min <= declared.max, "{declared:?}");
            assert!(declared.accepts(declared.default), "{declared:?}");
            assert!(!declared.unit.is_empty(), "{declared:?}");
            assert!(!declared.source.is_empty(), "{declared:?}");
            assert!(!declared.rationale.is_empty(), "{declared:?}");
        }
        // Zero is illegal for half-life, candidate cap, and edge support.
        assert!(
            !oracle_attribution_knob(ORACLE_DECAY_HALF_LIFE_SECS_KNOB)
                .unwrap()
                .accepts(0)
        );
        assert!(
            !oracle_attribution_knob(ORACLE_CANDIDATE_CAP_KNOB)
                .unwrap()
                .accepts(0)
        );
        assert!(
            !oracle_attribution_knob(ORACLE_MIN_EDGE_SUPPORT_KNOB)
                .unwrap()
                .accepts(0)
        );
        // The default config is the declared defaults and validates.
        let config = AttributionConfig::default();
        assert_eq!(config.window_secs, ORACLE_DEFAULT_ATTRIBUTION_WINDOW_SECS);
        assert_eq!(config.candidate_cap, ORACLE_DEFAULT_CANDIDATE_CAP as usize);
        config.validate().expect("default config validates");
    }

    // ------------------------------------------------------------------
    // DoD 1: attribution golden — lag_s + decay, 14d boundary, out-of-window
    // ------------------------------------------------------------------

    #[test]
    fn attribution_golden_pins_lag_decay_and_the_14_day_boundary() {
        let config = AttributionConfig::default();
        let window = config.window_secs; // 14 days
        let base = 1_000_000_000u64;
        let changes = vec![change("aaaa", cx(1), base)];
        // One outcome exactly at the window edge (included), one one second past
        // it (excluded), one lag-0 outcome to pin the decay=1.0 endpoint.
        let outcomes = vec![
            outcome("ci:x:edge", cx(1), base + window, true),
            outcome("ci:x:past", cx(1), base + window + 1, true),
            outcome("ci:x:zero", cx(1), base, false),
        ];
        let records = mine_occurrences(&changes, &outcomes, &config).expect("mine golden");

        // The out-of-window outcome contributes no occurrence.
        assert!(
            records.iter().all(|r| r.source != "ci:x:past"),
            "an outcome one second past the window must be excluded"
        );

        let edge = records
            .iter()
            .find(|r| r.source == "ci:x:edge")
            .expect("window-edge outcome is attributed");
        assert_eq!(edge.lag_s, window);
        // half-life is 7 days, lag is 14 days => two half-lives => 0.25.
        let expected_decay = 0.5_f64.powf(2.0);
        assert!((edge.decay_weight - expected_decay).abs() < 1e-12);
        assert_eq!(edge.credit, 1.0, "single candidate takes all credit");
        assert_eq!(edge.candidate_count, 1);
        assert_eq!(edge.trust, TrustTag::Trusted);

        let zero = records
            .iter()
            .find(|r| r.source == "ci:x:zero")
            .expect("lag-0 outcome is attributed");
        assert_eq!(zero.lag_s, 0);
        assert_eq!(zero.decay_weight, 1.0, "lag 0 => decay 1.0");
        assert!(!zero.passed);

        // Empty-input edge of the triad: no changes or no outcomes => no records.
        assert!(
            mine_occurrences(&[], &outcomes, &config)
                .unwrap()
                .is_empty()
        );
        assert!(mine_occurrences(&changes, &[], &config).unwrap().is_empty());
    }

    // ------------------------------------------------------------------
    // DoD 2: credit splitting sums to 1.0 (proptest)
    // ------------------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn credit_across_candidates_of_one_outcome_sums_to_one(
            lags in prop::collection::vec(1u64..500_000, 1..80usize)
        ) {
            let config = AttributionConfig::default();
            let outcome_ts = 2_000_000_000u64;
            // Distinct changes preceding a single outcome by the sampled lags.
            let changes: Vec<ChangeEvent> = lags
                .iter()
                .enumerate()
                .map(|(i, lag)| change(&format!("c{i:04}"), cx(7), outcome_ts - lag))
                .collect();
            let outcomes = vec![outcome("ci:p:1", cx(7), outcome_ts, true)];
            let records = mine_occurrences(&changes, &outcomes, &config).expect("mine");
            // Every emitted occurrence belongs to the one outcome's split.
            let sum: f64 = records.iter().map(|r| r.credit).sum();
            prop_assert!((sum - 1.0).abs() < 1e-9, "credit sum {sum} != 1.0");
            // The split never exceeds the candidate cap.
            prop_assert!(records.len() <= config.candidate_cap);
            for record in &records {
                prop_assert!(record.credit > 0.0 && record.credit <= 1.0);
            }
        }
    }

    // ------------------------------------------------------------------
    // DoD 3: lead/lag PRECEDES edge — sign + median lag, noise => no edge
    // ------------------------------------------------------------------

    #[test]
    fn precedes_edge_has_correct_sign_and_median_and_noise_yields_no_edge() {
        let config = narrow_config(100);

        // Signal: on one subject, three changes each followed within the narrow
        // window by exactly one outcome (earlier changes fall out of window), so
        // lags are a clean 10 / 20 / 30 => support 3, lower-median 20.
        let changes = vec![
            change("a", cx(1), 1_000),
            change("b", cx(1), 2_000),
            change("c", cx(1), 3_000),
        ];
        let outcomes = vec![
            outcome("ci:s:1", cx(1), 1_010, true),
            outcome("ci:s:2", cx(1), 2_020, true),
            outcome("ci:s:3", cx(1), 3_030, true),
        ];
        let corpus = mine_corpus(&changes, &outcomes, &config).expect("signal corpus");
        assert_eq!(corpus.occurrences.len(), 3, "one candidate per outcome");
        for record in &corpus.occurrences {
            assert!(
                record.outcome_ts >= record.change_ts,
                "change precedes outcome (positive lag)"
            );
        }
        assert_eq!(corpus.edges.len(), 1);
        let edge = &corpus.edges[0];
        assert_eq!(edge.subject, cx(1));
        assert_eq!(edge.support, 3);
        assert_eq!(edge.median_lag_s, 20, "lower-median of {{10,20,30}}");

        // Noise: outcomes all precede every change (anti-causal). No change ever
        // precedes an outcome within the window => zero occurrences => no edge.
        let noise_changes = vec![
            change("a", cx(1), 2_000),
            change("b", cx(1), 3_000),
            change("c", cx(1), 4_000),
        ];
        let noise_outcomes = vec![
            outcome("ci:n:1", cx(1), 1_000, true),
            outcome("ci:n:2", cx(1), 1_500, true),
            outcome("ci:n:3", cx(1), 1_700, true),
        ];
        let noise = mine_corpus(&noise_changes, &noise_outcomes, &config).expect("noise corpus");
        assert!(
            noise.occurrences.is_empty(),
            "anti-causal => no occurrences"
        );
        assert!(noise.edges.is_empty(), "noise => no PRECEDES edge");

        // Support gate: two in-window occurrences (< min_edge_support 3) => no edge.
        let gate = mine_corpus(
            &[change("a", cx(1), 1_000), change("b", cx(1), 2_000)],
            &[
                outcome("ci:g:1", cx(1), 1_010, true),
                outcome("ci:g:2", cx(1), 2_020, true),
            ],
            &config,
        )
        .expect("gate corpus");
        assert_eq!(gate.occurrences.len(), 2);
        assert!(gate.edges.is_empty(), "support below threshold => no edge");
    }

    // ------------------------------------------------------------------
    // DoD 4: candidate <= 50 cap is deterministic (nearest by lag)
    // ------------------------------------------------------------------

    #[test]
    fn candidate_cap_keeps_the_fifty_nearest_deterministically() {
        let config = AttributionConfig::default();
        let outcome_ts = 3_000_000_000u64;
        // 60 changes preceding one outcome by distinct lags 1..=60.
        let mut changes: Vec<ChangeEvent> = (1..=60u64)
            .map(|k| change(&format!("c{k:03}"), cx(3), outcome_ts - k))
            .collect();
        let outcomes = vec![outcome("ci:c:1", cx(3), outcome_ts, true)];

        let first = mine_occurrences(&changes, &outcomes, &config).expect("mine");
        assert_eq!(first.len(), 50, "capped at candidate_cap");
        let kept: BTreeSet<u64> = first.iter().map(|r| r.lag_s).collect();
        assert_eq!(kept, (1..=50u64).collect(), "the 50 smallest lags survive");
        assert!(first.iter().all(|r| r.candidate_count == 50));

        // Determinism under input reordering: the reversed input yields the same
        // occurrence set (canonical order, nearest-lag cap, id tiebreak).
        changes.reverse();
        let second = mine_occurrences(&changes, &outcomes, &config).expect("mine reversed");
        assert_eq!(first, second, "cap is input-order independent");
    }

    // ------------------------------------------------------------------
    // DoD 5: incremental persist == full-pass persist (CF byte-compare)
    // ------------------------------------------------------------------

    #[test]
    fn incremental_persist_converges_to_full_pass_cf_bytes() {
        let config = narrow_config(1_000);
        // A subject with enough in-window pairs to also produce a PRECEDES edge.
        let all_changes = vec![
            change("c1", cx(1), 10_000),
            change("c2", cx(1), 10_500),
            change("c3", cx(1), 11_000),
            change("d1", cx(2), 20_000),
        ];
        let all_outcomes = vec![
            outcome("ci:i:1", cx(1), 10_200, true),
            outcome("ci:i:2", cx(1), 10_700, false),
            outcome("ci:i:3", cx(1), 11_100, true),
            outcome("ci:i:4", cx(2), 20_100, true),
        ];
        let full = mine_corpus(&all_changes, &all_outcomes, &config).expect("full corpus");
        assert!(
            full.edges.iter().any(|e| e.subject == cx(1)),
            "cx(1) earns an edge"
        );

        // Partial: first two changes and first two outcomes.
        let partial =
            mine_corpus(&all_changes[..2], &all_outcomes[..2], &config).expect("partial corpus");

        // Vault A: persist partial, then full (incremental convergence).
        let (dir_a, vault_a) = fresh_vault("incr-a");
        persist_corpus(&vault_a, &partial, "oracle-test").expect("persist partial");
        persist_corpus(&vault_a, &full, "oracle-test").expect("persist full over partial");

        // Vault B: one full-pass persist from a clean store.
        let (dir_b, vault_b) = fresh_vault("incr-b");
        persist_corpus(&vault_b, &full, "oracle-test").expect("persist full");

        drop(vault_a);
        drop(vault_b);
        let reopened_a = open_vault(&dir_a);
        let reopened_b = open_vault(&dir_b);
        let rows_a = raw_oracle_rows(&reopened_a).expect("raw rows a");
        let rows_b = raw_oracle_rows(&reopened_b).expect("raw rows b");
        assert!(!rows_a.is_empty(), "corpus actually persisted");
        assert_eq!(
            rows_a, rows_b,
            "incremental persist must be byte-identical to full-pass persist"
        );
    }

    // ------------------------------------------------------------------
    // DoD 6: FSV readback of occurrence rows vs git + anchor ground truth
    // ------------------------------------------------------------------

    struct GitFixture {
        root: PathBuf,
        ts: u64,
    }
    impl GitFixture {
        fn new(root: &Path) -> Self {
            fs::create_dir_all(root.join("src")).expect("mkdir src");
            let fixture = Self {
                root: root.to_path_buf(),
                ts: 1_700_000_000,
            };
            fixture.git(&["init", "-q", "--object-format=sha1"]);
            fixture.git(&["config", "user.email", "oracle@example.invalid"]);
            fixture.git(&["config", "user.name", "Oracle Test"]);
            fixture.git(&["config", "commit.gpgsign", "false"]);
            fixture.git(&["config", "core.autocrlf", "false"]);
            fixture
        }
        fn commit(&mut self, message: &str) -> (String, u64) {
            self.git(&["add", "."]);
            let ts = self.ts;
            let date = format!("@{ts} +0000");
            let out = Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(["commit", "-q", "--no-gpg-sign", "-m", message])
                .env("GIT_AUTHOR_DATE", &date)
                .env("GIT_COMMITTER_DATE", &date)
                .output()
                .expect("git commit");
            assert!(
                out.status.success(),
                "commit: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            self.ts += 60;
            (self.head(), ts)
        }
        fn head(&self) -> String {
            String::from_utf8(self.run(&["rev-parse", "HEAD"]))
                .unwrap()
                .trim()
                .to_string()
        }
        fn git(&self, args: &[&str]) {
            let out = Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(args)
                .output()
                .expect("git");
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        fn run(&self, args: &[&str]) -> Vec<u8> {
            let out = Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(args)
                .output()
                .expect("git");
            assert!(out.status.success(), "git {args:?}");
            out.stdout
        }
    }

    #[test]
    fn fsv_readback_matches_git_and_anchor_ground_truth() {
        // --- Real Git ground truth: an SZZ-recoverable planted fix. ---
        let git_root = temp_dir("gt-git");
        let mut git = GitFixture::new(&git_root);
        fs::write(
            git_root.join("src/calc.c"),
            b"int adjust(int x) {\n    return x + 1;\n}\n",
        )
        .unwrap();
        git.commit("initial safe calculator");
        fs::write(
            git_root.join("src/calc.c"),
            b"int adjust(int x) {\n    return x - 1;\n}\n",
        )
        .unwrap();
        git.commit("feature: tweak adjust");
        fs::write(
            git_root.join("src/calc.c"),
            b"int adjust(int x) {\n    return x + 1;\n}\n",
        )
        .unwrap();
        let (fix_sha, fix_ts) = git.commit("fix: restore adjust correctness");

        let report = mine_git_archaeology(
            &git_root,
            &GitArchaeologyConfig {
                since: "30 years ago".to_string(),
                ..GitArchaeologyConfig::default()
            },
            &GitMineMode::Full,
        )
        .expect("mine archaeology");
        assert!(
            report
                .szz_findings
                .iter()
                .any(|f| f.fix_commit == fix_sha && f.path == "src/calc.c"),
            "planted fix is recovered by SZZ"
        );

        // The change is derived from the real report; the fix touches src/calc.c
        // which we bind to subject cx(1).
        let changes =
            changes_from_git_archaeology(&report, |path| (path == "src/calc.c").then(|| cx(1)));
        assert!(
            changes
                .iter()
                .any(|c| c.change_id == fix_sha && c.change_ts == fix_ts),
            "change derived from the git fix commit"
        );

        // --- Real anchor ground truth: a grounded outcome on cx(1). ---
        let (vault_dir, vault) = fresh_vault("gt-vault");
        let outcome_ts = fix_ts + 3_600; // 1 hour after the fix, well inside 14d
        let anchor_source = "ci:github:9001";
        let anchor_request = OutcomeAnchorRequest::new(
            OutcomeKind::TestRun,
            anchor_source,
            outcome_ts,
            None,
            vec![OutcomeSubject {
                subject_id: "calc::adjust".to_string(),
                anchor_kind: AnchorKind::TestPass,
                value: AnchorValue::Bool(true),
            }],
        )
        .expect("anchor request");
        let cx_ids = BTreeMap::from([("calc::adjust".to_string(), cx(1))]);
        ingest_outcome_anchors(&vault, &anchor_request, &cx_ids, "oracle-test")
            .expect("ingest anchor outcome");
        let anchor_rows = read_anchor_rows(&vault).expect("read anchor rows");
        let outcomes = outcomes_from_anchor_rows(&anchor_rows);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].subject, cx(1));
        assert_eq!(outcomes[0].outcome_ts, outcome_ts);
        assert_eq!(outcomes[0].source, anchor_source);

        // --- Mine + persist into the SAME real vault (anchors + oracle coexist). ---
        let corpus =
            mine_corpus(&changes, &outcomes, &AttributionConfig::default()).expect("mine corpus");
        assert_eq!(corpus.occurrences.len(), 1, "one change->outcome pair");
        let report_persist = persist_corpus(&vault, &corpus, "oracle-test").expect("persist");
        assert_eq!(report_persist.occurrence_count, 1);
        let fsv = report_persist
            .fsv
            .as_ref()
            .expect("mutation earns FSV witness");
        assert_eq!(fsv.label(), astrolabe_domain::fsv::FSV_LABEL_VERIFIED);
        assert_eq!(fsv.ledger_seq(), report_persist.ledger_ref.seq);
        drop(vault);

        // --- Independent readback from a reopened store. ---
        let reopened = open_vault(&vault_dir);
        let persisted = read_occurrence_rows(&reopened).expect("read occurrence rows");
        assert_eq!(persisted.len(), 1);
        let row = &persisted[0].row;
        assert_eq!(row.subject, cx(1));
        assert_eq!(
            row.change_id, fix_sha,
            "occurrence credits the real git fix commit"
        );
        assert_eq!(row.change_ts, fix_ts, "change_ts is the git commit epoch");
        assert_eq!(
            row.source, anchor_source,
            "outcome source is the real anchor source"
        );
        assert_eq!(row.outcome_ts, outcome_ts);
        assert_eq!(row.lag_s, 3_600, "lag == outcome_ts - fix_ts");
        assert!(row.passed);
        assert_eq!(row.trust, TrustTag::Trusted, "ci: source is Trusted");

        // Paired ledger entry: same-commit Score entry, hash-only payload with no
        // raw git object id leaked.
        let ledger_bytes = reopened
            .read_cf_at(
                reopened.snapshot(),
                ColumnFamily::Ledger,
                &ledger_key(report_persist.ledger_ref.seq),
            )
            .expect("read ledger row")
            .expect("ledger row present");
        let entry = decode_ledger(&ledger_bytes).expect("decode ledger entry");
        assert_eq!(entry.kind, EntryKind::Score);
        let payload: serde_json::Value =
            serde_json::from_slice(&entry.payload).expect("payload json");
        assert_eq!(payload["schema"], ORACLE_CORPUS_LEDGER_SCHEMA);
        assert_eq!(payload["occurrence_count"], 1);
        assert_eq!(payload["corpus_dump_hash"], report_persist.corpus_dump_hash);
        let payload_text = String::from_utf8(entry.payload.clone()).expect("utf8");
        assert!(
            !payload_text.contains(&fix_sha),
            "raw git object id must not leak into the ledger payload"
        );
        drop(reopened);
    }

    // ------------------------------------------------------------------
    // Edge triad: invalid config / events fail closed; empty corpus is a
    // labeled no-op.
    // ------------------------------------------------------------------

    #[test]
    fn invalid_config_and_events_fail_closed() {
        let base = AttributionConfig::default();

        // Invalid config: zero window, zero half-life, zero cap each refuse.
        for bad in [
            AttributionConfig {
                window_secs: 0,
                ..base
            },
            AttributionConfig {
                decay_half_life_secs: 0,
                ..base
            },
            AttributionConfig {
                candidate_cap: 0,
                ..base
            },
            AttributionConfig {
                min_edge_support: 0,
                ..base
            },
        ] {
            assert_eq!(
                mine_occurrences(&[], &[], &bad)
                    .expect_err("bad config refuses")
                    .code,
                ASTRO_ORACLE_CONFIG_INVALID
            );
        }

        // Invalid events: zero change_ts, zero outcome_ts, unknown source.
        let good_out = vec![outcome("ci:e:1", cx(1), 100, true)];
        assert_eq!(
            mine_occurrences(&[change("z", cx(1), 0)], &good_out, &base)
                .expect_err("zero change_ts")
                .code,
            ASTRO_ORACLE_EVENT_INVALID
        );
        assert_eq!(
            mine_occurrences(
                &[change("z", cx(1), 50)],
                &[outcome("ci:e:1", cx(1), 0, true)],
                &base
            )
            .expect_err("zero outcome_ts")
            .code,
            ASTRO_ORACLE_EVENT_INVALID
        );
        assert_eq!(
            mine_occurrences(
                &[change("z", cx(1), 50)],
                &[outcome("not-a-catalog-source", cx(1), 100, true)],
                &base
            )
            .expect_err("unknown source")
            .code,
            ASTRO_ORACLE_EVENT_INVALID
        );

        // Empty corpus persists as a labeled no-op: ledger entry, no FSV witness.
        let (dir, vault) = fresh_vault("empty");
        let empty = OracleCorpus {
            occurrences: Vec::new(),
            edges: Vec::new(),
        };
        let report = persist_corpus(&vault, &empty, "oracle-test").expect("persist empty");
        assert_eq!(report.rows_written, 0);
        assert!(report.fsv.is_none(), "no-op replay labels FSV absence");
        assert!(read_occurrence_rows(&vault).unwrap().is_empty());
        assert!(read_precedes_edges(&vault).unwrap().is_empty());
        drop(vault);
        let _ = dir;
    }

    #[test]
    fn corpus_dump_hash_is_deterministic_for_equal_corpora() {
        let config = narrow_config(1_000);
        let changes = vec![change("c1", cx(1), 100), change("c2", cx(1), 500)];
        let outcomes = vec![
            outcome("ci:d:1", cx(1), 300, true),
            outcome("ci:d:2", cx(1), 700, false),
        ];
        let a = mine_corpus(&changes, &outcomes, &config).expect("a");
        // Reversed input yields an equal canonical corpus and an equal dump.
        let mut rev_changes = changes.clone();
        rev_changes.reverse();
        let mut rev_outcomes = outcomes.clone();
        rev_outcomes.reverse();
        let b = mine_corpus(&rev_changes, &rev_outcomes, &config).expect("b");
        assert_eq!(a, b, "mining is input-order independent");
        assert_eq!(corpus_dump_bytes(&a), corpus_dump_bytes(&b));
    }
}
