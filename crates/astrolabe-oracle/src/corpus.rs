//! Oracle evidence substrate: change-to-outcome corpus mining with attribution
//! windows (blueprint P7.5).
//!
//! A *change* (a commit or edit touching a subject constellation at a wall-clock
//! instant) is paired with a later *outcome* (a grounded anchor observation on
//! the same subject) whenever the outcome falls inside the change's attribution
//! window. Each surviving `(change → outcome)` pair becomes an
//! [`OccurrenceRecord`] carrying its exact lag, a deterministic fixed-point
//! half-life weight, and an exact fixed-point credit share; the per-subject
//! aggregate becomes a lead/lag
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

use astrolabe_anchors::archaeology::{GitArchaeologyReport, GitHistoryState};
use astrolabe_anchors::{PersistedAnchorRow, SCHEMA_ANCHOR_ROW};
use astrolabe_domain::TrustTag;
use astrolabe_domain::fsv::FsvAck;
use astrolabe_domain::knobs::U64KnobDeclaration;
use astrolabe_ingest::{
    CbmCompactGraphReceipt, GraphProjectionManifestIdentity, VaultMutationPlan,
};
use calyx_aster::cf::{ColumnFamily, anchor_key, full_content_hash, ledger_key, prefix_range};
use calyx_aster::mvcc::{is_tombstone_value, tombstone_value};
use calyx_aster::vault::AsterVault;
use calyx_core::{
    AnchorKind, AnchorValue, CalyxError, Clock, CxId, LedgerRef, Seq, Ts, VaultStore,
};
use calyx_ledger::decode as decode_ledger;
use calyx_ledger::{ActorId, EntryKind, SubjectId};
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
pub const ORACLE_OCCURRENCE_ROW_SCHEMA: &str = "astrolabe-oracle-occurrence-row-v3";
/// Row schema tag for a persisted lead/lag PRECEDES edge row.
pub const ORACLE_PRECEDES_ROW_SCHEMA: &str = "astrolabe-oracle-precedes-edge-row-v3";
/// Row schema tag for one durable Git-archaeology change input.
pub const ORACLE_CHANGE_ROW_SCHEMA: &str = "astrolabe-oracle-change-row-v1";
/// Ledger payload schema for one corpus-persistence group commit.
pub const ORACLE_CORPUS_LEDGER_SCHEMA: &str = "astrolabe.oracle_corpus.v5";
/// Fixed marker schema proving the source-bound v5 layout was installed
/// atomically with retirement of every prior occurrence/edge layout.
pub const ORACLE_CORPUS_LAYOUT_SCHEMA: &str = "astrolabe.oracle_corpus.layout.v5";
/// The only timestamp unit admitted by Oracle mining and chronological replay.
pub const ORACLE_TIMEBASE_CONTRACT: &str = "unix_epoch_seconds.v1";
/// Exact source-binding schema carried by the corpus layout.
pub const ORACLE_CORPUS_SOURCE_BINDING_SCHEMA: &str = "astrolabe.oracle_corpus.source_binding.v1";
/// Point-readable binding returned to gate and serving consumers.
pub const ORACLE_CORPUS_BINDING_SCHEMA: &str = "astrolabe.oracle_corpus.binding.v1";
/// Exact integer scale shared by decay weights and normalized attribution
/// credits. One full unit of outcome credit is exactly this many integer units.
pub const ORACLE_ATTRIBUTION_SCALE: u64 = 1_u64 << 60;
/// Number of exact dyadic half-life boundaries representable by the scale.
pub const ORACLE_ATTRIBUTION_FRACTION_BITS: u64 = 60;
/// Stable direction label: a change always precedes the outcome it credits.
pub const PRECEDES_DIRECTION: &str = "change_precedes_outcome";

const LEGACY_ORACLE_OCCURRENCE_PREFIX_V1: &[u8] = b"astrolabe:oracle-occurrence:v1:";
const LEGACY_ORACLE_OCCURRENCE_PREFIX_V2: &[u8] = b"astrolabe:oracle-occurrence:v2:";
const LEGACY_ORACLE_OCCURRENCE_PREFIX_V3: &[u8] = b"astrolabe:oracle-occurrence:v3:";
const LEGACY_ORACLE_OCCURRENCE_PREFIX_V4: &[u8] = b"astrolabe:oracle-occurrence:v4:";
const ORACLE_OCCURRENCE_PREFIX: &[u8] = b"astrolabe:oracle-occurrence:v5:";
const LEGACY_ORACLE_PRECEDES_PREFIX_V1: &[u8] = b"astrolabe:oracle-precedes:v1:";
const LEGACY_ORACLE_PRECEDES_PREFIX_V2: &[u8] = b"astrolabe:oracle-precedes:v2:";
const ORACLE_PRECEDES_PREFIX: &[u8] = b"astrolabe:oracle-precedes:v3:";
const ORACLE_CHANGE_PREFIX: &[u8] = b"astrolabe:oracle-change:v1:";
const LEGACY_ORACLE_CORPUS_LAYOUT_KEY_V3: &[u8] = b"astrolabe:oracle-corpus-layout:v3";
const LEGACY_ORACLE_CORPUS_LAYOUT_KEY_V4: &[u8] = b"astrolabe:oracle-corpus-layout:v4";
const ORACLE_CORPUS_LAYOUT_KEY: &[u8] = b"astrolabe:oracle-corpus-layout:v5";
const ORACLE_DECAY_MODEL: &str = "piecewise-linear-dyadic-half-life.v1";
const ORACLE_CREDIT_APPORTIONMENT: &str = "positive-largest-remainder.v1";

// ---------------------------------------------------------------------------
// Registry-declared attribution knobs (standing invariant 4)
// ---------------------------------------------------------------------------

/// Registry version tag for the oracle attribution knobs (#49).
pub const ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION: &str = "astrolabe-oracle-attribution-knobs-v2";

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
/// Smallest legal half-life. Zero is illegal because the declared reciprocal
/// half-life equation would have no positive time scale.
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

/// Default minimum edge support: three distinct attributed outcomes before a
/// lead/lag PRECEDES edge is emitted for a subject.
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
/// two-week regression-attribution horizon); deterministic dyadic decay halves
/// at every full half-life and linearly interpolates in exact integer space;
/// the candidate cap bounds fan-out; and
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
        source: "deterministic piecewise-linear dyadic half-life model at a 2^60 fixed-point scale",
        rationale: "sets how fast attribution credit decays with lag: weight halves exactly at every full half-life and interpolates linearly between adjacent dyadic boundaries; configurations whose window exceeds the scale's 60 positive half-lives refuse, so there is no platform floating math, clamp, or underflow fallback; replace only with a measured fixed-point model plus schema/registry bump",
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
        unit: "distinct_outcomes",
        source: "ASTROLABE #49 lead/lag edge support gate; minimum-support convention from frequent-pattern / association-rule mining",
        rationale: "minimum distinct real outcomes on a subject before a lead/lag PRECEDES edge is emitted; candidate-pair fan-out never increases support, so a single outcome cannot mint an edge; replace with a measured value once edge precision/recall is benchmarked",
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionConfig {
    /// Inclusive upper bound on `outcome_ts - change_ts`, in seconds.
    pub window_secs: u64,
    /// Dyadic decay half-life, in seconds.
    pub decay_half_life_secs: u64,
    /// Maximum preceding changes credited per outcome (nearest-by-lag).
    pub candidate_cap: usize,
    /// Minimum distinct attributed outcomes before a subject earns a PRECEDES edge.
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
        let candidate_cap = u64::try_from(self.candidate_cap).map_err(|_| {
            OracleError::new(
                ASTRO_ORACLE_CONFIG_INVALID,
                format!("candidate cap {} exceeds u64", self.candidate_cap),
            )
        })?;
        check_knob(ORACLE_CANDIDATE_CAP_KNOB, candidate_cap)?;
        let min_edge_support = u64::try_from(self.min_edge_support).map_err(|_| {
            OracleError::new(
                ASTRO_ORACLE_CONFIG_INVALID,
                format!("minimum edge support {} exceeds u64", self.min_edge_support),
            )
        })?;
        check_knob(ORACLE_MIN_EDGE_SUPPORT_KNOB, min_edge_support)?;
        let representable_window = self
            .decay_half_life_secs
            .checked_mul(ORACLE_ATTRIBUTION_FRACTION_BITS)
            .ok_or_else(|| {
                OracleError::new(
                    ASTRO_ORACLE_CONFIG_INVALID,
                    "fixed-point representable-window calculation overflowed u64",
                )
            })?;
        if self.window_secs > representable_window {
            return Err(OracleError::new(
                ASTRO_ORACLE_CONFIG_INVALID,
                format!(
                    "attribution window {} exceeds the exact 2^60 fixed-point horizon {} for half-life {}; choose a half-life of at least ceil(window/{})",
                    self.window_secs,
                    representable_window,
                    self.decay_half_life_secs,
                    ORACLE_ATTRIBUTION_FRACTION_BITS
                ),
            ));
        }
        Ok(())
    }
}

/// One unambiguous wall-clock contract shared by Git archaeology, persisted
/// anchors, attribution windows, and chronological held-out replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleTimebase {
    /// Always [`ORACLE_TIMEBASE_CONTRACT`].
    pub contract: String,
    /// Inclusive publication observation in Unix epoch seconds. Source events
    /// after this instant are impossible members of this generation.
    pub observed_through_seconds: Ts,
}

impl OracleTimebase {
    /// Constructs the sole supported timebase. The caller must pass the exact
    /// generation observation converted to seconds once at admission.
    pub fn unix_epoch_seconds(observed_through_seconds: Ts) -> Result<Self, OracleError> {
        let timebase = Self {
            contract: ORACLE_TIMEBASE_CONTRACT.to_string(),
            observed_through_seconds,
        };
        timebase.validate()?;
        Ok(timebase)
    }

    fn validate(&self) -> Result<(), OracleError> {
        if self.contract != ORACLE_TIMEBASE_CONTRACT || self.observed_through_seconds == 0 {
            return Err(OracleError::new(
                ASTRO_ORACLE_CONFIG_INVALID,
                format!(
                    "Oracle timebase must be {ORACLE_TIMEBASE_CONTRACT:?} with a nonzero publication observation, got {self:?}"
                ),
            ));
        }
        Ok(())
    }
}

/// Exact graph/anchor/history generation from which one corpus was mined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleCorpusSourceBinding {
    pub schema: String,
    pub project: String,
    pub timebase: OracleTimebase,
    /// Exact Git history observation, or `None` only for an explicitly non-Git
    /// corpus whose gate can never claim historical prediction lift.
    pub git_history: Option<GitHistoryState>,
    /// `full`, `incremental`, `history_absent`, or `unavailable`.
    pub git_mining_mode: String,
    pub graph_content_generation: Seq,
    pub anchors_content_generation: Seq,
    /// Exact bounded node/range/raw-edge projection already read by shadow
    /// import; Oracle reuses it instead of rescanning Graph.
    pub compact_graph: CbmCompactGraphReceipt,
    pub projection_manifest: GraphProjectionManifestIdentity,
}

impl OracleCorpusSourceBinding {
    /// Validates the complete source tuple before any mining or persistence.
    pub fn validate(&self) -> Result<(), OracleError> {
        self.timebase.validate()?;
        if self.schema != ORACLE_CORPUS_SOURCE_BINDING_SCHEMA
            || self.project.trim().is_empty()
            || !matches!(
                self.git_mining_mode.as_str(),
                "full" | "incremental" | "history_absent" | "unavailable"
            )
            || (self.git_history.is_some() && self.git_mining_mode == "unavailable")
            || (self.git_history.is_none() && self.git_mining_mode != "unavailable")
            || self.compact_graph.project != self.project
        {
            return Err(OracleError::new(
                ASTRO_ORACLE_CONFIG_INVALID,
                format!("Oracle corpus source binding is non-canonical: {self:?}"),
            ));
        }
        if let Some(history) = &self.git_history {
            history.validate().map_err(|error| {
                OracleError::new(
                    ASTRO_ORACLE_CONFIG_INVALID,
                    format!("Oracle Git history binding is invalid: {error}"),
                )
            })?;
        }
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
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
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

/// Exact identity of one real persisted outcome-anchor observation.
///
/// There is deliberately no public arbitrary constructor. The identity is
/// derived by [`outcomes_from_anchor_rows`] from the verified persisted anchor
/// row key plus the exact boolean anchor slot and payload. This prevents two
/// independent outcomes with equal source/timestamp fields from collapsing and
/// prevents callers from fabricating evidence identities.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OutcomeId(String);

impl OutcomeId {
    /// Canonical lowercase-hex identity used by persisted rows and receipts.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_persisted_boolean_anchor(
        persisted_key: &[u8],
        source: &str,
        observed_at: Ts,
        passed: bool,
        confidence_bits: u32,
    ) -> Self {
        let observed_at = observed_at.to_be_bytes();
        let confidence_bits = confidence_bits.to_be_bytes();
        let passed = [u8::from(passed)];
        Self(hex_lower(&full_content_hash([
            b"astrolabe.oracle-outcome-anchor-identity.v1".as_slice(),
            persisted_key,
            source.as_bytes(),
            observed_at.as_slice(),
            passed.as_slice(),
            confidence_bits.as_slice(),
        ])))
    }

    fn validate(&self) -> calyx_core::Result<()> {
        if self.0.len() != 64
            || !self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(oracle_corrupt(format!(
                "Oracle outcome identity {:?} is not canonical lowercase BLAKE3 hex",
                self.0
            )));
        }
        Ok(())
    }
}

/// Positive fixed-point attribution quantity at [`ORACLE_ATTRIBUTION_SCALE`].
///
/// Persisted weights and credits use this integer representation exclusively;
/// no platform `pow`, floating rounding tolerance, clamp, or underflow fallback
/// participates in corpus mining or validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AttributionUnits(u64);

impl AttributionUnits {
    /// Exact stored units.
    pub const fn units(self) -> u64 {
        self.0
    }

    /// A presentation/consumer projection. The persisted authority remains the
    /// exact integer returned by [`Self::units`].
    pub fn as_f64(self) -> f64 {
        self.0 as f64 / ORACLE_ATTRIBUTION_SCALE as f64
    }

    fn new(units: u64) -> Result<Self, OracleError> {
        if units == 0 || units > ORACLE_ATTRIBUTION_SCALE {
            return Err(OracleError::new(
                ASTRO_ORACLE_EVENT_INVALID,
                format!(
                    "attribution quantity {units} is outside exact fixed-point range [1, {ORACLE_ATTRIBUTION_SCALE}]"
                ),
            ));
        }
        Ok(Self(units))
    }

    fn validate(self, label: &str) -> calyx_core::Result<()> {
        if self.0 == 0 || self.0 > ORACLE_ATTRIBUTION_SCALE {
            return Err(oracle_corrupt(format!(
                "Oracle {label} {} is outside exact fixed-point range [1, {ORACLE_ATTRIBUTION_SCALE}]",
                self.0
            )));
        }
        Ok(())
    }
}

// Compatibility for the abduction scorer: its recency model is floating-point,
// while the authoritative corpus credit remains exact fixed-point units.
impl std::ops::Mul<f64> for AttributionUnits {
    type Output = f64;

    fn mul(self, rhs: f64) -> Self::Output {
        self.as_f64() * rhs
    }
}

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

/// Exact source SZZ finding retained independently from its current symbol
/// projection. This lets an incremental Git mine merge old+new findings and
/// re-project the complete source roster after CxIds change, without rescanning
/// history or preserving stale symbol identities.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitChangeInput {
    /// Fix commit whose deleted/modified parent line produced this SZZ finding.
    /// This is the observed change used by the Oracle; `blamed_commit` remains
    /// the exact archaeology evidence explaining why that line was selected.
    pub fix_commit: String,
    pub blamed_commit: String,
    pub path: String,
    pub line: u32,
    /// Source Git timestamp of `fix_commit`, in the declared corpus timebase.
    pub observed_at: Ts,
    pub confidence_bits: u32,
}

/// Deterministic accounting for projecting exact SZZ findings onto the current
/// persisted symbol ranges. One finding may overlap multiple nested symbols;
/// every resulting `(fix_commit, CxId)` is retained once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitChangeProjection {
    pub finding_count: usize,
    pub mapped_finding_count: usize,
    pub unmapped_finding_count: usize,
    pub multi_symbol_finding_count: usize,
    pub inputs: Vec<GitChangeInput>,
    pub events: Vec<ChangeEvent>,
}

/// A grounded outcome observed on one subject constellation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeEvent {
    /// Exact identity derived from the persisted source anchor evidence.
    outcome_id: OutcomeId,
    /// Catalog outcome source (for example `ci:github:42`).
    source: String,
    /// Exact constellation carrying the persisted source anchor.
    outcome_subject: CxId,
    /// Grounded anchor axis. Only `TestPass` plus a graph-proven test identity is
    /// eligible to become a prediction-lift case.
    outcome_kind: AnchorKind,
    /// Changed subjects to which this source outcome is attributed. A single
    /// source outcome may cover multiple symbols without manufacturing new
    /// source identities; candidate credit remains complete per subject.
    attribution_subjects: Vec<CxId>,
    /// Exact test constellation when the persisted graph proves that the anchor
    /// subject covers every attributed symbol through TESTS/TESTS_FILE edges.
    test_identity: Option<CxId>,
    /// Outcome wall-clock timestamp (seconds), never `0`.
    outcome_ts: Ts,
    /// Whether the outcome was a pass.
    passed: bool,
}

impl OutcomeEvent {
    /// Exact source-backed identity.
    pub fn outcome_id(&self) -> &OutcomeId {
        &self.outcome_id
    }

    /// Catalog source carried by the persisted anchor.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Subject constellation carrying the anchor.
    pub const fn outcome_subject(&self) -> CxId {
        self.outcome_subject
    }

    /// Persisted anchor axis.
    pub fn outcome_kind(&self) -> &AnchorKind {
        &self.outcome_kind
    }

    /// Canonical changed-subject attribution roster.
    pub fn attribution_subjects(&self) -> &[CxId] {
        &self.attribution_subjects
    }

    /// Exact graph-proven test identity, when available.
    pub const fn test_identity(&self) -> Option<CxId> {
        self.test_identity
    }

    /// Raw source observation timestamp.
    pub const fn outcome_ts(&self) -> Ts {
        self.outcome_ts
    }

    /// Whether the grounded outcome passed.
    pub const fn passed(&self) -> bool {
        self.passed
    }

    /// Binds a real persisted test outcome to the exact covered-symbol roster
    /// read from the same graph projection. The source identity and payload are
    /// immutable; only their graph-derived attribution is replaced.
    pub fn bind_test_attribution(
        &mut self,
        mut covered_subjects: Vec<CxId>,
    ) -> Result<(), OracleError> {
        if self.outcome_kind != AnchorKind::TestPass {
            return Err(OracleError::new(
                ASTRO_ORACLE_EVENT_INVALID,
                "only a TestPass anchor may carry a test identity",
            ));
        }
        covered_subjects.sort();
        covered_subjects.dedup();
        if covered_subjects.is_empty() {
            return Err(OracleError::new(
                ASTRO_ORACLE_EVENT_INVALID,
                "test attribution requires at least one graph-proven covered subject",
            ));
        }
        self.attribution_subjects = covered_subjects;
        self.test_identity = Some(self.outcome_subject);
        Ok(())
    }
}

fn validate_change(change: &ChangeEvent, timebase: &OracleTimebase) -> Result<(), OracleError> {
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
    if change.change_ts > timebase.observed_through_seconds {
        return Err(OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            format!(
                "change {:?} timestamp {} is after generation observation {} under {}",
                change.change_id,
                change.change_ts,
                timebase.observed_through_seconds,
                timebase.contract
            ),
        ));
    }
    Ok(())
}

fn validate_outcome(outcome: &OutcomeEvent, timebase: &OracleTimebase) -> Result<(), OracleError> {
    outcome.outcome_id.validate().map_err(|error| {
        OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            format!("outcome identity is invalid: {}", error.message),
        )
    })?;
    if outcome.outcome_ts == 0 {
        return Err(OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            format!(
                "outcome {:?} has outcome_ts 0; a grounded outcome carries a non-zero timestamp",
                outcome.source
            ),
        ));
    }
    if outcome.outcome_ts > timebase.observed_through_seconds {
        return Err(OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            format!(
                "outcome {:?} timestamp {} is after generation observation {} under {}; millisecond values are not silently converted",
                outcome.source,
                outcome.outcome_ts,
                timebase.observed_through_seconds,
                timebase.contract
            ),
        ));
    }
    if outcome.attribution_subjects.is_empty()
        || !outcome
            .attribution_subjects
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || outcome.test_identity.is_some_and(|test| {
            test != outcome.outcome_subject || outcome.outcome_kind != AnchorKind::TestPass
        })
    {
        return Err(OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            format!(
                "outcome {} has a non-canonical attribution/test binding",
                outcome.outcome_id.as_str()
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OccurrenceRecord {
    /// Subject both the change and the outcome share.
    pub subject: CxId,
    /// The crediting change's identifier.
    pub change_id: String,
    /// Exact identity of the persisted real outcome evidence.
    pub outcome_id: OutcomeId,
    /// Exact constellation carrying the source anchor (for a test case, the
    /// runner-native test identity resolved through the persisted node map).
    pub outcome_subject: CxId,
    /// Persisted anchor axis.
    pub outcome_kind: AnchorKind,
    /// Graph-proven test identity eligible for held-out prediction lift.
    pub test_identity: Option<CxId>,
    /// The outcome's catalog source.
    pub source: String,
    /// Change timestamp (seconds).
    pub change_ts: Ts,
    /// Outcome timestamp (seconds).
    pub outcome_ts: Ts,
    /// Attribution lag `outcome_ts - change_ts` (seconds), always `<= window`.
    pub lag_s: u64,
    /// Deterministic half-life decay weight in exact fixed-point units.
    pub decay_weight: AttributionUnits,
    /// Positive normalized credit share in exact fixed-point units; the credits
    /// of all candidates for one outcome sum exactly to
    /// [`ORACLE_ATTRIBUTION_SCALE`].
    pub credit: AttributionUnits,
    /// Whether the outcome was a pass.
    pub passed: bool,
    /// Number of candidate changes the outcome's credit was split across.
    pub candidate_count: usize,
    /// Trust of the outcome's catalog source.
    pub trust: TrustTag,
}

/// One lead/lag PRECEDES edge aggregated over a subject's distinct outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecedesEdge {
    /// Subject the edge summarizes.
    pub subject: CxId,
    /// Number of distinct attributed outcomes supporting the edge.
    pub support: usize,
    /// Lower median of the nearest candidate lag for each supporting outcome.
    pub median_lag_s: u64,
}

/// A mined corpus: attributed occurrences plus the lead/lag edges over them.
#[derive(Debug, Clone, PartialEq)]
pub struct OracleCorpus {
    /// Exact policy used to derive every occurrence and edge.
    attribution: AttributionConfig,
    /// Exact source generation and wall-clock contract.
    source_binding: OracleCorpusSourceBinding,
    /// Canonically ordered complete Git change catalog used by this generation,
    /// including changes that currently have no attributed outcome.
    changes: Vec<ChangeEvent>,
    /// Complete exact SZZ source roster, including currently unmapped findings.
    git_change_inputs: Vec<GitChangeInput>,
    /// Exact number of change events presented to this mining pass. Production
    /// corpus cardinality is unknown until measured, so it is receipt data.
    input_change_event_count: usize,
    /// Exact number of outcome events presented to this mining pass.
    input_outcome_event_count: usize,
    /// Number of `(source outcome, attributed subject)` groups presented to
    /// mining. This may exceed the source outcome count when one test covers
    /// several changed symbols.
    input_attribution_count: usize,
    occurrences: Vec<OccurrenceRecord>,
    edges: Vec<PrecedesEdge>,
}

impl OracleCorpus {
    /// Exact validated policy used for this mined receipt.
    pub const fn attribution(&self) -> AttributionConfig {
        self.attribution
    }

    /// Exact graph/anchor/history/timebase binding for this corpus.
    pub fn source_binding(&self) -> &OracleCorpusSourceBinding {
        &self.source_binding
    }

    /// Complete canonical source change catalog.
    pub fn changes(&self) -> &[ChangeEvent] {
        &self.changes
    }

    /// Complete canonical SZZ source roster for incremental merge/reprojection.
    pub fn git_change_inputs(&self) -> &[GitChangeInput] {
        &self.git_change_inputs
    }

    /// Exact number of source change events presented to mining.
    pub const fn input_change_event_count(&self) -> usize {
        self.input_change_event_count
    }

    /// Exact number of source outcome events presented to mining.
    pub const fn input_outcome_event_count(&self) -> usize {
        self.input_outcome_event_count
    }

    /// Exact number of source-outcome/changed-subject attribution groups.
    pub const fn input_attribution_count(&self) -> usize {
        self.input_attribution_count
    }

    /// Canonically ordered attributed candidate-pair rows.
    pub fn occurrences(&self) -> &[OccurrenceRecord] {
        &self.occurrences
    }

    /// Canonically ordered distinct-outcome PRECEDES edges.
    pub fn edges(&self) -> &[PrecedesEdge] {
        &self.edges
    }
}

/// Deterministic dyadic half-life weight at the declared fixed-point scale.
/// Every full half-life is an exact right shift; the remainder is linearly
/// interpolated between adjacent dyadic boundaries and rounded upward. The
/// validated 60-half-life horizon guarantees a positive result without a clamp
/// or underflow fallback.
fn decay_weight(lag_s: u64, half_life_secs: u64) -> Result<AttributionUnits, OracleError> {
    if half_life_secs == 0 {
        return Err(OracleError::new(
            ASTRO_ORACLE_CONFIG_INVALID,
            "decay half-life is zero",
        ));
    }
    let full_half_lives = lag_s / half_life_secs;
    let remainder = lag_s % half_life_secs;
    if full_half_lives > ORACLE_ATTRIBUTION_FRACTION_BITS
        || (full_half_lives == ORACLE_ATTRIBUTION_FRACTION_BITS && remainder != 0)
    {
        return Err(OracleError::new(
            ASTRO_ORACLE_CONFIG_INVALID,
            format!(
                "lag {lag_s} exceeds the exact fixed-point horizon of {ORACLE_ATTRIBUTION_FRACTION_BITS} half-lives"
            ),
        ));
    }
    let upper = ORACLE_ATTRIBUTION_SCALE >> full_half_lives;
    if remainder == 0 {
        return AttributionUnits::new(upper);
    }
    let lower = upper >> 1;
    let numerator = u128::from(upper)
        .checked_mul(u128::from(half_life_secs - remainder))
        .and_then(|value| {
            u128::from(lower)
                .checked_mul(u128::from(remainder))
                .and_then(|lower_part| value.checked_add(lower_part))
        })
        .ok_or_else(|| {
            OracleError::new(
                ASTRO_ORACLE_EVENT_INVALID,
                "decay interpolation numerator overflowed u128",
            )
        })?;
    let denominator = u128::from(half_life_secs);
    let rounded_up = numerator.checked_add(denominator - 1).ok_or_else(|| {
        OracleError::new(ASTRO_ORACLE_EVENT_INVALID, "decay rounding overflowed u128")
    })? / denominator;
    let units = u64::try_from(rounded_up).map_err(|_| {
        OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            format!("decay weight {rounded_up} exceeds u64"),
        )
    })?;
    AttributionUnits::new(units)
}

/// Positive largest-remainder apportionment at the exact declared scale.
///
/// One unit is reserved by definition for every candidate, then the remaining
/// units are distributed proportionally to the decay weights. Residual units
/// go to largest remainders with canonical candidate-order tiebreaks. This is a
/// single declared integer algorithm: every credit is positive and the total is
/// exactly the scale, with no clamp, epsilon, or floating fallback.
fn apportioned_credits(weights: &[AttributionUnits]) -> Result<Vec<AttributionUnits>, OracleError> {
    if weights.is_empty() {
        return Err(OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            "cannot apportion credit across zero candidates",
        ));
    }
    let candidate_count = u64::try_from(weights.len()).map_err(|_| {
        OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            format!("candidate count {} exceeds u64", weights.len()),
        )
    })?;
    if candidate_count > ORACLE_ATTRIBUTION_SCALE {
        return Err(OracleError::new(
            ASTRO_ORACLE_CONFIG_INVALID,
            format!(
                "candidate count {candidate_count} exceeds fixed-point attribution scale {ORACLE_ATTRIBUTION_SCALE}"
            ),
        ));
    }
    let weight_sum = weights.iter().try_fold(0u128, |sum, weight| {
        sum.checked_add(u128::from(weight.units())).ok_or_else(|| {
            OracleError::new(ASTRO_ORACLE_EVENT_INVALID, "weight sum overflowed u128")
        })
    })?;
    let distributable = ORACLE_ATTRIBUTION_SCALE - candidate_count;
    let mut assigned = 0u64;
    let mut credits = Vec::with_capacity(weights.len());
    let mut remainders = Vec::with_capacity(weights.len());
    for (index, weight) in weights.iter().enumerate() {
        let numerator = u128::from(distributable)
            .checked_mul(u128::from(weight.units()))
            .ok_or_else(|| {
                OracleError::new(
                    ASTRO_ORACLE_EVENT_INVALID,
                    "credit numerator overflowed u128",
                )
            })?;
        let quotient = u64::try_from(numerator / weight_sum).map_err(|_| {
            OracleError::new(ASTRO_ORACLE_EVENT_INVALID, "credit quotient exceeds u64")
        })?;
        assigned = assigned.checked_add(quotient).ok_or_else(|| {
            OracleError::new(ASTRO_ORACLE_EVENT_INVALID, "assigned credit overflowed u64")
        })?;
        credits.push(1u64 + quotient);
        remainders.push((numerator % weight_sum, index));
    }
    let residual = distributable.checked_sub(assigned).ok_or_else(|| {
        OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            "apportioned credit exceeded the declared scale",
        )
    })?;
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let residual = usize::try_from(residual).map_err(|_| {
        OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            "residual credit count exceeds usize",
        )
    })?;
    for (_, index) in remainders.into_iter().take(residual) {
        credits[index] += 1;
    }
    credits.into_iter().map(AttributionUnits::new).collect()
}

/// Mines every attributed `(change → outcome)` occurrence.
///
/// For each outcome, the candidate changes are those on the same subject with
/// `change_ts <= outcome_ts` and `outcome_ts - change_ts <= window_secs`. The
/// candidates are ordered nearest-lag-first (change-id tiebreak) and capped at
/// `candidate_cap`; each candidate's decay weight is normalized so the credits
/// of one outcome's candidates sum exactly to [`ORACLE_ATTRIBUTION_SCALE`].
///
/// Deterministic and seed-independent: the returned records are in a canonical
/// order that depends only on the event content, not on input ordering.
///
/// Cost contract (#1064 PC-04/PC-07/PC-16/PC-38/PC-41): indexing costs
/// `sum(C_s log C_s)`, canonical outcome ordering costs `O(O log O)`, and each
/// outcome performs two binary partition points and visits only its emitted
/// capped slice, for `sum(O_s log C_s + emitted_s)`. The invariant across the
/// per-outcome loop is each subject's reverse-timestamp/change-id order. The production graph is
/// N=192,873/E=328,899 (2026-08-20), but this path never opens or scans it;
/// production change/outcome counts remain unknown and are persisted as exact
/// mining-receipt fields by [`mine_corpus`].
pub fn mine_occurrences(
    changes: &[ChangeEvent],
    outcomes: &[OutcomeEvent],
    config: &AttributionConfig,
    timebase: &OracleTimebase,
) -> Result<Vec<OccurrenceRecord>, OracleError> {
    config.validate()?;
    timebase.validate()?;
    let mut change_identities: BTreeMap<(CxId, &str), Ts> = BTreeMap::new();
    for change in changes {
        validate_change(change, timebase)?;
        if let Some(existing_ts) = change_identities.insert(
            (change.subject, change.change_id.as_str()),
            change.change_ts,
        ) && existing_ts != change.change_ts
        {
            return Err(OracleError::new(
                ASTRO_ORACLE_EVENT_INVALID,
                format!(
                    "change identity {:?} on subject {} carries timestamps {existing_ts} and {}",
                    change.change_id, change.subject, change.change_ts
                ),
            ));
        }
    }
    let mut outcome_ids = BTreeSet::new();
    for outcome in outcomes {
        validate_outcome(outcome, timebase)?;
        if !outcome_ids.insert(&outcome.outcome_id) {
            return Err(OracleError::new(
                ASTRO_ORACLE_EVENT_INVALID,
                format!(
                    "outcome identity {} appears more than once in one mining pass",
                    outcome.outcome_id.as_str()
                ),
            ));
        }
    }

    // Index changes by subject. Reverse timestamp makes the exact desired
    // nearest-lag/change-id order contiguous, so two partition points bound the
    // window without scanning pre-window history.
    let mut by_subject: BTreeMap<CxId, Vec<&ChangeEvent>> = BTreeMap::new();
    for change in changes {
        by_subject.entry(change.subject).or_default().push(change);
    }
    for list in by_subject.values_mut() {
        list.sort_by(|a, b| {
            b.change_ts
                .cmp(&a.change_ts)
                .then_with(|| a.change_id.cmp(&b.change_id))
        });
        list.dedup_by(|a, b| a.change_id == b.change_id && a.change_ts == b.change_ts);
    }

    // Outcomes in a canonical order so the emitted records are deterministic.
    let mut outcomes_sorted: Vec<&OutcomeEvent> = outcomes.iter().collect();
    outcomes_sorted.sort_by(|a, b| {
        (
            a.outcome_ts,
            &a.outcome_id,
            &a.outcome_kind,
            a.outcome_subject,
            &a.source,
            a.passed,
        )
            .cmp(&(
                b.outcome_ts,
                &b.outcome_id,
                &b.outcome_kind,
                b.outcome_subject,
                &b.source,
                b.passed,
            ))
    });
    let mut records = Vec::new();
    for outcome in outcomes_sorted {
        for &subject in &outcome.attribution_subjects {
            let Some(subject_changes) = by_subject.get(&subject) else {
                continue;
            };
            let oldest_ts = outcome.outcome_ts.saturating_sub(config.window_secs);
            let start =
                subject_changes.partition_point(|change| change.change_ts > outcome.outcome_ts);
            let end = subject_changes.partition_point(|change| change.change_ts >= oldest_ts);
            if start >= end {
                continue;
            }
            let retained = (end - start).min(config.candidate_cap);
            let capped_end = start + retained;
            let candidates = &subject_changes[start..capped_end];
            let decays: Vec<AttributionUnits> = candidates
                .iter()
                .map(|change| {
                    decay_weight(
                        outcome.outcome_ts - change.change_ts,
                        config.decay_half_life_secs,
                    )
                })
                .collect::<Result<_, _>>()?;
            let credits = apportioned_credits(&decays)?;
            let trust = trust_of(&outcome.source)?;
            let candidate_count = candidates.len();
            for (index, change) in candidates.iter().enumerate() {
                let lag = outcome.outcome_ts - change.change_ts;
                records.push(OccurrenceRecord {
                    subject,
                    change_id: change.change_id.clone(),
                    outcome_id: outcome.outcome_id.clone(),
                    outcome_subject: outcome.outcome_subject,
                    outcome_kind: outcome.outcome_kind.clone(),
                    test_identity: outcome.test_identity,
                    source: outcome.source.clone(),
                    change_ts: change.change_ts,
                    outcome_ts: outcome.outcome_ts,
                    lag_s: lag,
                    decay_weight: decays[index],
                    credit: credits[index],
                    passed: outcome.passed,
                    candidate_count,
                    trust,
                });
            }
        }
    }
    records.sort_by(occurrence_order);
    Ok(records)
}

/// Aggregates occurrences into lead/lag PRECEDES edges.
///
/// A subject earns an edge only when at least `min_edge_support` distinct real
/// outcomes credit it. Each outcome contributes its nearest candidate lag once;
/// `median_lag_s` is the lower median of those per-outcome lags. Candidate-pair
/// fan-out therefore cannot inflate support or its lag sample.
pub fn precedes_edges(
    records: &[OccurrenceRecord],
    config: &AttributionConfig,
) -> Vec<PrecedesEdge> {
    let mut nearest_by_outcome: BTreeMap<(CxId, OutcomeId), u64> = BTreeMap::new();
    for record in records {
        nearest_by_outcome
            .entry((record.subject, record.outcome_id.clone()))
            .and_modify(|lag| *lag = (*lag).min(record.lag_s))
            .or_insert(record.lag_s);
    }
    let mut lags_by_subject: BTreeMap<CxId, Vec<u64>> = BTreeMap::new();
    for ((subject, _), lag) in nearest_by_outcome {
        lags_by_subject.entry(subject).or_default().push(lag);
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
    git_change_inputs: &[GitChangeInput],
    changes: &[ChangeEvent],
    outcomes: &[OutcomeEvent],
    config: &AttributionConfig,
    source_binding: OracleCorpusSourceBinding,
) -> Result<OracleCorpus, OracleError> {
    source_binding.validate()?;
    let mut git_change_inputs = git_change_inputs.to_vec();
    git_change_inputs.sort();
    git_change_inputs.dedup();
    for input in &git_change_inputs {
        validate_git_change_input(input, &source_binding.timebase)?;
    }
    let occurrences = mine_occurrences(changes, outcomes, config, &source_binding.timebase)?;
    let edges = precedes_edges(&occurrences, config);
    let mut changes = changes.to_vec();
    changes.sort_by(|left, right| {
        (left.subject, left.change_ts, &left.change_id).cmp(&(
            right.subject,
            right.change_ts,
            &right.change_id,
        ))
    });
    changes.dedup();
    let input_attribution_count = outcomes.iter().try_fold(0usize, |count, outcome| {
        count
            .checked_add(outcome.attribution_subjects.len())
            .ok_or_else(|| {
                OracleError::new(
                    ASTRO_ORACLE_EVENT_INVALID,
                    "Oracle attribution count overflowed usize",
                )
            })
    })?;
    Ok(OracleCorpus {
        attribution: *config,
        source_binding,
        git_change_inputs,
        input_change_event_count: changes.len(),
        input_outcome_event_count: outcomes.len(),
        input_attribution_count,
        changes,
        occurrences,
        edges,
    })
}

fn occurrence_order(a: &OccurrenceRecord, b: &OccurrenceRecord) -> std::cmp::Ordering {
    (
        a.subject,
        a.outcome_ts,
        &a.outcome_id,
        &a.outcome_kind,
        a.outcome_subject,
        a.test_identity,
        &a.source,
        a.passed,
        a.lag_s,
        &a.change_id,
    )
        .cmp(&(
            b.subject,
            b.outcome_ts,
            &b.outcome_id,
            &b.outcome_kind,
            b.outcome_subject,
            b.test_identity,
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
/// Each SZZ finding's fix commit is a change touching every exact persisted
/// symbol range that overlaps its `(path,line)`. Unmapped findings and findings
/// spanning nested symbols are counted explicitly. Duplicate
/// `(fix_commit, subject)` pairs collapse to one change only when their source
/// timestamps agree; a disagreement refuses.
pub fn changes_from_git_archaeology(
    report: &GitArchaeologyReport,
    timebase: &OracleTimebase,
    subjects_for_range: impl FnMut(&str, u32) -> Vec<CxId>,
) -> Result<GitChangeProjection, OracleError> {
    let inputs = git_change_inputs_from_archaeology(report, timebase)?;
    project_git_change_inputs(&inputs, timebase, subjects_for_range)
}

/// Extracts the complete exact SZZ source roster without projecting symbols.
pub fn git_change_inputs_from_archaeology(
    report: &GitArchaeologyReport,
    timebase: &OracleTimebase,
) -> Result<Vec<GitChangeInput>, OracleError> {
    timebase.validate()?;
    let mut inputs = report
        .szz_findings
        .iter()
        .map(|finding| GitChangeInput {
            fix_commit: finding.fix_commit.clone(),
            blamed_commit: finding.blamed_commit.clone(),
            path: finding.path.replace('\\', "/"),
            line: finding.line,
            observed_at: finding.observed_at,
            confidence_bits: finding.confidence.to_bits(),
        })
        .collect::<Vec<_>>();
    inputs.sort();
    inputs.dedup();
    for input in &inputs {
        validate_git_change_input(input, timebase)?;
    }
    Ok(inputs)
}

/// Projects a complete exact SZZ source roster onto current symbol ranges.
pub fn project_git_change_inputs(
    inputs: &[GitChangeInput],
    timebase: &OracleTimebase,
    mut subjects_for_range: impl FnMut(&str, u32) -> Vec<CxId>,
) -> Result<GitChangeProjection, OracleError> {
    timebase.validate()?;
    let mut changes: BTreeMap<(String, CxId), Ts> = BTreeMap::new();
    let mut mapped_finding_count = 0usize;
    let mut unmapped_finding_count = 0usize;
    let mut multi_symbol_finding_count = 0usize;
    let mut canonical_inputs = inputs.to_vec();
    canonical_inputs.sort();
    canonical_inputs.dedup();
    for finding in &canonical_inputs {
        validate_git_change_input(finding, timebase)?;
        let mut subjects = subjects_for_range(&finding.path, finding.line);
        subjects.sort();
        subjects.dedup();
        if subjects.is_empty() {
            unmapped_finding_count += 1;
            continue;
        }
        mapped_finding_count += 1;
        multi_symbol_finding_count += usize::from(subjects.len() > 1);
        for subject in subjects {
            let key = (finding.fix_commit.clone(), subject);
            if let Some(previous) = changes.insert(key.clone(), finding.observed_at)
                && previous != finding.observed_at
            {
                return Err(OracleError::new(
                    ASTRO_ORACLE_EVENT_INVALID,
                    format!(
                        "Git change {:?} on subject {} carries source timestamps {previous} and {}",
                        finding.fix_commit, subject, finding.observed_at
                    ),
                ));
            }
        }
    }
    let events = changes
        .into_iter()
        .map(|((change_id, subject), change_ts)| ChangeEvent {
            change_id,
            subject,
            change_ts,
        })
        .collect::<Vec<_>>();
    for event in &events {
        validate_change(event, timebase)?;
    }
    Ok(GitChangeProjection {
        finding_count: canonical_inputs.len(),
        mapped_finding_count,
        unmapped_finding_count,
        multi_symbol_finding_count,
        inputs: canonical_inputs,
        events,
    })
}

fn validate_git_change_input(
    input: &GitChangeInput,
    timebase: &OracleTimebase,
) -> Result<(), OracleError> {
    let confidence = f32::from_bits(input.confidence_bits);
    if input.fix_commit.trim().is_empty()
        || input.blamed_commit.trim().is_empty()
        || input.path.trim().is_empty()
        || input.path.contains('\\')
        || input.path.starts_with('/')
        || input.path.split('/').any(|component| component == "..")
        || input.line == 0
        || input.observed_at == 0
        || input.observed_at > timebase.observed_through_seconds
        || !confidence.is_finite()
        || !(0.0..=1.0).contains(&confidence)
    {
        return Err(OracleError::new(
            ASTRO_ORACLE_EVENT_INVALID,
            format!("Git change input is non-canonical: {input:?}"),
        ));
    }
    Ok(())
}

/// Derives outcome events from persisted boolean anchor rows.
///
/// Each boolean-valued anchor becomes one outcome on the row's subject, carrying
/// its catalog source, observed-at timestamp, and pass/fail. Non-boolean anchors
/// carry no pass/fail semantics and are skipped. The adapter re-verifies the
/// persisted row key/schema-bearing anchor structure and refuses duplicates;
/// it never accepts a caller-supplied opaque outcome identifier.
pub fn outcomes_from_anchor_rows(
    rows: &[PersistedAnchorRow],
    timebase: &OracleTimebase,
) -> Result<Vec<OutcomeEvent>, OracleError> {
    timebase.validate()?;
    let mut outcomes = Vec::new();
    let mut outcome_ids = BTreeSet::new();
    for persisted in rows {
        if persisted.row.schema.as_str() != SCHEMA_ANCHOR_ROW
            || persisted.key != anchor_key(persisted.row.cx_id, &persisted.row.kind)
        {
            return Err(OracleError::new(
                ASTRO_ORACLE_EVENT_INVALID,
                format!(
                    "persisted anchor row {} has schema {:?} or key inconsistent with its decoded subject/kind",
                    hex_lower(&persisted.key),
                    persisted.row.schema
                ),
            ));
        }
        for anchor in &persisted.row.anchors {
            anchor.validate_schema().map_err(|error| {
                OracleError::new(
                    ASTRO_ORACLE_EVENT_INVALID,
                    format!(
                        "persisted anchor row {} carries invalid anchor evidence: {}",
                        hex_lower(&persisted.key),
                        error.message
                    ),
                )
            })?;
            if anchor.kind != persisted.row.kind {
                return Err(OracleError::new(
                    ASTRO_ORACLE_EVENT_INVALID,
                    format!(
                        "persisted anchor row {} carries a foreign anchor kind",
                        hex_lower(&persisted.key)
                    ),
                ));
            }
            if let AnchorValue::Bool(passed) = &anchor.value {
                let passed = *passed;
                let outcome = OutcomeEvent {
                    outcome_id: OutcomeId::from_persisted_boolean_anchor(
                        &persisted.key,
                        &anchor.source,
                        anchor.observed_at,
                        passed,
                        anchor.confidence.to_bits(),
                    ),
                    source: anchor.source.clone(),
                    outcome_subject: persisted.row.cx_id,
                    outcome_kind: anchor.kind.clone(),
                    attribution_subjects: vec![persisted.row.cx_id],
                    test_identity: None,
                    outcome_ts: anchor.observed_at,
                    passed,
                };
                validate_outcome(&outcome, timebase)?;
                if !outcome_ids.insert(outcome.outcome_id.clone()) {
                    return Err(OracleError::new(
                        ASTRO_ORACLE_EVENT_INVALID,
                        format!(
                            "persisted anchor evidence repeats outcome identity {}",
                            outcome.outcome_id.as_str()
                        ),
                    ));
                }
                outcomes.push(outcome);
            }
        }
    }
    outcomes.sort_by(|left, right| left.outcome_id.cmp(&right.outcome_id));
    Ok(outcomes)
}

// ---------------------------------------------------------------------------
// Persisted rows
// ---------------------------------------------------------------------------

/// A persisted occurrence row (`Kv` CF, oracle-owned prefix).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceRowV3 {
    /// Always [`ORACLE_OCCURRENCE_ROW_SCHEMA`].
    pub schema: String,
    pub subject: CxId,
    pub change_id: String,
    pub outcome_id: OutcomeId,
    pub outcome_subject: CxId,
    pub outcome_kind: AnchorKind,
    pub test_identity: Option<CxId>,
    pub source: String,
    pub change_ts: Ts,
    pub outcome_ts: Ts,
    pub lag_s: u64,
    pub decay_weight: AttributionUnits,
    pub credit: AttributionUnits,
    pub passed: bool,
    pub candidate_count: usize,
    pub trust: TrustTag,
}

/// A persisted lead/lag PRECEDES edge row (`Kv` CF, oracle-owned prefix).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrecedesEdgeRowV3 {
    /// Always [`ORACLE_PRECEDES_ROW_SCHEMA`].
    pub schema: String,
    pub subject: CxId,
    pub support: usize,
    pub median_lag_s: u64,
    /// Always [`PRECEDES_DIRECTION`].
    pub direction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleChangeRowV1 {
    pub schema: String,
    pub fix_commit: String,
    pub blamed_commit: String,
    pub path: String,
    pub line: u32,
    pub observed_at: Ts,
    pub confidence_bits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OracleCorpusLayoutV5 {
    schema: String,
    occurrence_key_schema: String,
    occurrence_row_schema: String,
    precedes_row_schema: String,
    change_row_schema: String,
    attribution_knob_registry_version: String,
    attribution_scale: u64,
    attribution_fraction_bits: u64,
    decay_model: String,
    credit_apportionment: String,
    attribution: AttributionConfig,
    source_binding: OracleCorpusSourceBinding,
    input_change_event_count: usize,
    input_outcome_event_count: usize,
    input_attribution_count: usize,
    distinct_attribution_count: usize,
    mapped_change_event_count: usize,
    change_count: usize,
    occurrence_count: usize,
    edge_count: usize,
    corpus_dump_hash: String,
    content_rows_hash: String,
    retired_occurrence_layouts: Vec<String>,
    retired_precedes_layouts: Vec<String>,
    retired_layout_markers: Vec<String>,
}

impl OracleCorpusLayoutV5 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        attribution: AttributionConfig,
        source_binding: OracleCorpusSourceBinding,
        input_change_event_count: usize,
        input_outcome_event_count: usize,
        input_attribution_count: usize,
        distinct_attribution_count: usize,
        mapped_change_event_count: usize,
        change_count: usize,
        occurrence_count: usize,
        edge_count: usize,
        corpus_dump_hash: String,
        content_rows_hash: String,
    ) -> Self {
        Self {
            schema: ORACLE_CORPUS_LAYOUT_SCHEMA.to_string(),
            occurrence_key_schema: "calyx-length-delimited-subject-outcome-key.v5".to_string(),
            occurrence_row_schema: ORACLE_OCCURRENCE_ROW_SCHEMA.to_string(),
            precedes_row_schema: ORACLE_PRECEDES_ROW_SCHEMA.to_string(),
            change_row_schema: ORACLE_CHANGE_ROW_SCHEMA.to_string(),
            attribution_knob_registry_version: ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION.to_string(),
            attribution_scale: ORACLE_ATTRIBUTION_SCALE,
            attribution_fraction_bits: ORACLE_ATTRIBUTION_FRACTION_BITS,
            decay_model: ORACLE_DECAY_MODEL.to_string(),
            credit_apportionment: ORACLE_CREDIT_APPORTIONMENT.to_string(),
            attribution,
            source_binding,
            input_change_event_count,
            input_outcome_event_count,
            input_attribution_count,
            distinct_attribution_count,
            mapped_change_event_count,
            change_count,
            occurrence_count,
            edge_count,
            corpus_dump_hash,
            content_rows_hash,
            retired_occurrence_layouts: vec![
                "nul-delimited-hash.v1".to_string(),
                "nul-delimited-subject-key.v2".to_string(),
                "length-delimited-subject-key.v3".to_string(),
                "length-delimited-subject-outcome-key.v4".to_string(),
            ],
            retired_precedes_layouts: vec![
                "subject-hash.v1".to_string(),
                "subject-hash.v2".to_string(),
            ],
            retired_layout_markers: vec![
                "astrolabe.oracle_corpus.layout.v3".to_string(),
                "astrolabe.oracle_corpus.layout.v4".to_string(),
            ],
        }
    }

    fn validate(&self) -> calyx_core::Result<()> {
        let expected = Self::new(
            self.attribution,
            self.source_binding.clone(),
            self.input_change_event_count,
            self.input_outcome_event_count,
            self.input_attribution_count,
            self.distinct_attribution_count,
            self.mapped_change_event_count,
            self.change_count,
            self.occurrence_count,
            self.edge_count,
            self.corpus_dump_hash.clone(),
            self.content_rows_hash.clone(),
        );
        if self != &expected
            || self.attribution.validate().is_err()
            || self.source_binding.validate().is_err()
            || self.distinct_attribution_count > self.input_attribution_count
            || self.distinct_attribution_count > self.occurrence_count
            || self.mapped_change_event_count != self.input_change_event_count
            || self.corpus_dump_hash.len() != 64
            || !self
                .corpus_dump_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.content_rows_hash.len() != 64
            || !self
                .content_rows_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(oracle_corrupt(format!(
                "Oracle corpus layout marker is non-canonical: {self:?}"
            )));
        }
        Ok(())
    }
}

impl OccurrenceRowV3 {
    fn from_record(record: &OccurrenceRecord) -> Self {
        Self {
            schema: ORACLE_OCCURRENCE_ROW_SCHEMA.to_string(),
            subject: record.subject,
            change_id: record.change_id.clone(),
            outcome_id: record.outcome_id.clone(),
            outcome_subject: record.outcome_subject,
            outcome_kind: record.outcome_kind.clone(),
            test_identity: record.test_identity,
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

impl PrecedesEdgeRowV3 {
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

#[derive(Clone, Copy)]
struct OccurrenceView<'a> {
    subject: CxId,
    change_id: &'a str,
    outcome_id: &'a OutcomeId,
    outcome_subject: CxId,
    outcome_kind: &'a AnchorKind,
    test_identity: Option<CxId>,
    source: &'a str,
    change_ts: Ts,
    outcome_ts: Ts,
    lag_s: u64,
    decay_weight: AttributionUnits,
    credit: AttributionUnits,
    passed: bool,
    candidate_count: usize,
    trust: TrustTag,
}

fn validate_occurrence_view(
    occurrence: OccurrenceView<'_>,
    config: &AttributionConfig,
) -> calyx_core::Result<()> {
    let OccurrenceView {
        change_id,
        outcome_id,
        outcome_subject,
        outcome_kind,
        test_identity,
        source,
        change_ts,
        outcome_ts,
        lag_s,
        decay_weight,
        credit,
        candidate_count,
        trust,
        ..
    } = occurrence;
    if change_id.trim().is_empty() {
        return Err(oracle_corrupt(
            "Oracle occurrence change_id is empty".to_string(),
        ));
    }
    outcome_id.validate()?;
    if test_identity
        .is_some_and(|test| test != outcome_subject || outcome_kind != &AnchorKind::TestPass)
    {
        return Err(oracle_corrupt(format!(
            "Oracle outcome {} has an invalid test/anchor-subject binding",
            outcome_id.as_str()
        )));
    }
    if change_ts == 0 || outcome_ts == 0 || outcome_ts < change_ts {
        return Err(oracle_corrupt(format!(
            "Oracle occurrence {change_id:?}/{source:?} has invalid timestamps change={change_ts} outcome={outcome_ts}"
        )));
    }
    if lag_s != outcome_ts - change_ts {
        return Err(oracle_corrupt(format!(
            "Oracle occurrence {change_id:?}/{source:?} lag {lag_s} does not equal outcome-change {}",
            outcome_ts - change_ts
        )));
    }
    if lag_s > config.window_secs {
        return Err(oracle_corrupt(format!(
            "Oracle occurrence {change_id:?}/{source:?} lag {lag_s} exceeds configured window {}",
            config.window_secs
        )));
    }
    decay_weight.validate("decay_weight")?;
    credit.validate("credit")?;
    let expected_decay = decay_weight(lag_s, config.decay_half_life_secs).map_err(|error| {
        oracle_corrupt(format!(
            "derive exact decay weight for {change_id:?}/{source:?}: {error}"
        ))
    })?;
    if decay_weight != expected_decay {
        return Err(oracle_corrupt(format!(
            "Oracle occurrence {change_id:?}/{source:?} decay units {} differ from configured exact units {}",
            decay_weight.units(),
            expected_decay.units()
        )));
    }
    if candidate_count == 0 || candidate_count > config.candidate_cap {
        return Err(oracle_corrupt(format!(
            "Oracle occurrence {change_id:?}/{source:?} candidate_count {candidate_count} is outside [1, {}]",
            config.candidate_cap
        )));
    }
    let expected_trust = trust_of(source).map_err(|error| {
        oracle_corrupt(format!(
            "Oracle occurrence {change_id:?} has invalid outcome source {source:?}: {error}"
        ))
    })?;
    if trust != expected_trust {
        return Err(oracle_corrupt(format!(
            "Oracle occurrence {change_id:?}/{source:?} trust {trust:?} differs from catalog-derived {expected_trust:?}"
        )));
    }
    Ok(())
}

fn occurrence_record_view(record: &OccurrenceRecord) -> OccurrenceView<'_> {
    OccurrenceView {
        subject: record.subject,
        change_id: &record.change_id,
        outcome_id: &record.outcome_id,
        outcome_subject: record.outcome_subject,
        outcome_kind: &record.outcome_kind,
        test_identity: record.test_identity,
        source: &record.source,
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

fn occurrence_row_view(row: &OccurrenceRowV3) -> OccurrenceView<'_> {
    OccurrenceView {
        subject: row.subject,
        change_id: &row.change_id,
        outcome_id: &row.outcome_id,
        outcome_subject: row.outcome_subject,
        outcome_kind: &row.outcome_kind,
        test_identity: row.test_identity,
        source: &row.source,
        change_ts: row.change_ts,
        outcome_ts: row.outcome_ts,
        lag_s: row.lag_s,
        decay_weight: row.decay_weight,
        credit: row.credit,
        passed: row.passed,
        candidate_count: row.candidate_count,
        trust: row.trust,
    }
}

fn validate_occurrence_row(
    row: &OccurrenceRowV3,
    config: &AttributionConfig,
) -> calyx_core::Result<()> {
    if row.schema != ORACLE_OCCURRENCE_ROW_SCHEMA {
        return Err(oracle_corrupt(format!(
            "Oracle occurrence row carries schema {:?}",
            row.schema
        )));
    }
    validate_occurrence_view(occurrence_row_view(row), config)
}

fn validate_precedes_edge(edge: &PrecedesEdge) -> calyx_core::Result<()> {
    if edge.support == 0 {
        return Err(oracle_corrupt(format!(
            "Oracle PRECEDES edge for {} has zero support",
            edge.subject
        )));
    }
    Ok(())
}

fn validate_precedes_row(row: &PrecedesEdgeRowV3) -> calyx_core::Result<()> {
    if row.schema != ORACLE_PRECEDES_ROW_SCHEMA
        || row.direction != PRECEDES_DIRECTION
        || row.support == 0
    {
        return Err(oracle_corrupt(format!(
            "Oracle PRECEDES row for {} is non-canonical: schema={:?} direction={:?} support={}",
            row.subject, row.schema, row.direction, row.support
        )));
    }
    Ok(())
}

/// Validates each candidate row once, groups in `O(K log G)`, and canonically
/// sorts each group in `sum(k_g log k_g)`, bounded by `O(K log K)`. No outcome
/// group rescans the full `K`-row corpus (PC-04/PC-16).
fn validate_occurrence_groups<'a>(
    occurrences: impl IntoIterator<Item = OccurrenceView<'a>>,
    config: &AttributionConfig,
) -> calyx_core::Result<(usize, BTreeMap<CxId, Vec<u64>>)> {
    let mut groups: BTreeMap<(CxId, &'a OutcomeId), Vec<OccurrenceView<'a>>> = BTreeMap::new();
    for occurrence in occurrences {
        validate_occurrence_view(occurrence, config)?;
        groups
            .entry((occurrence.subject, occurrence.outcome_id))
            .or_default()
            .push(occurrence);
    }

    let distinct_outcomes = groups.len();
    let mut lags_by_subject: BTreeMap<CxId, Vec<u64>> = BTreeMap::new();
    for ((subject, outcome_id), group) in &mut groups {
        group.sort_by(|a, b| {
            (a.lag_s, a.change_id, a.change_ts).cmp(&(b.lag_s, b.change_id, b.change_ts))
        });
        let first = group[0];
        if group.iter().any(|row| {
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
            return Err(oracle_corrupt(format!(
                "Oracle outcome group {} carries inconsistent subject/source/time/pass/count/trust metadata",
                outcome_id.as_str()
            )));
        }
        if group.len() != first.candidate_count {
            return Err(oracle_corrupt(format!(
                "Oracle outcome group {} has {} candidate rows but declares {}",
                outcome_id.as_str(),
                group.len(),
                first.candidate_count
            )));
        }
        let mut change_ids = BTreeSet::new();
        let mut credit_sum = 0u64;
        let mut weights = Vec::with_capacity(group.len());
        for row in group.iter() {
            if !change_ids.insert(row.change_id) {
                return Err(oracle_corrupt(format!(
                    "Oracle outcome group {} repeats change identity {:?}",
                    outcome_id.as_str(),
                    row.change_id
                )));
            }
            credit_sum = credit_sum.checked_add(row.credit.units()).ok_or_else(|| {
                oracle_corrupt(format!(
                    "Oracle outcome group {} credit sum overflowed u64",
                    outcome_id.as_str()
                ))
            })?;
            weights.push(row.decay_weight);
        }
        if credit_sum != ORACLE_ATTRIBUTION_SCALE {
            return Err(oracle_corrupt(format!(
                "Oracle outcome group {} credit sum {credit_sum} differs from exact scale {ORACLE_ATTRIBUTION_SCALE}",
                outcome_id.as_str()
            )));
        }
        let expected_credits = apportioned_credits(&weights).map_err(|error| {
            oracle_corrupt(format!(
                "derive exact credits for Oracle outcome {}: {error}",
                outcome_id.as_str()
            ))
        })?;
        if group
            .iter()
            .zip(expected_credits)
            .any(|(row, expected)| row.credit != expected)
        {
            return Err(oracle_corrupt(format!(
                "Oracle outcome group {} credits do not match the declared fixed-point apportionment",
                outcome_id.as_str()
            )));
        }
        lags_by_subject
            .entry(*subject)
            .or_default()
            .push(group[0].lag_s);
    }
    Ok((distinct_outcomes, lags_by_subject))
}

fn validate_corpus_semantics(corpus: &OracleCorpus) -> calyx_core::Result<()> {
    corpus.attribution.validate()?;
    corpus.source_binding.validate()?;
    let (distinct_outcomes, _) = validate_occurrence_groups(
        corpus.occurrences.iter().map(occurrence_record_view),
        &corpus.attribution,
    )?;
    if distinct_outcomes > corpus.input_attribution_count {
        return Err(oracle_corrupt(format!(
            "Oracle corpus attributes {distinct_outcomes} distinct subject/outcome groups from only {} input attribution groups",
            corpus.input_attribution_count
        )));
    }
    if corpus.input_outcome_event_count > corpus.input_attribution_count {
        return Err(oracle_corrupt(format!(
            "Oracle corpus has {} source outcomes but only {} subject attributions",
            corpus.input_outcome_event_count, corpus.input_attribution_count
        )));
    }
    if !corpus
        .git_change_inputs
        .windows(2)
        .all(|pair| pair[0] < pair[1])
    {
        return Err(oracle_corrupt(
            "Oracle exact Git change-input roster is not strictly canonical".to_string(),
        ));
    }
    for input in &corpus.git_change_inputs {
        validate_git_change_input(input, &corpus.source_binding.timebase)
            .map_err(CalyxError::from)?;
    }
    let source_change_times = corpus
        .git_change_inputs
        .iter()
        .map(|input| (input.fix_commit.as_str(), input.observed_at))
        .collect::<BTreeSet<_>>();
    let change_roster = corpus
        .changes
        .iter()
        .map(|change| (change.subject, change.change_id.as_str(), change.change_ts))
        .collect::<BTreeSet<_>>();
    if change_roster.len() != corpus.changes.len()
        || corpus.changes.len() != corpus.input_change_event_count
    {
        return Err(oracle_corrupt(
            "Oracle complete change catalog is not canonical or its count differs from the mining receipt"
                .to_string(),
        ));
    }
    for change in &corpus.changes {
        validate_change(change, &corpus.source_binding.timebase).map_err(CalyxError::from)?;
        if !source_change_times.contains(&(change.change_id.as_str(), change.change_ts)) {
            return Err(oracle_corrupt(format!(
                "Oracle mapped change {:?}/{} has no exact SZZ source finding",
                change.change_id, change.change_ts
            )));
        }
    }
    let distinct_changes = corpus
        .occurrences
        .iter()
        .map(|row| (row.subject, &row.change_id, row.change_ts))
        .collect::<BTreeSet<_>>()
        .len();
    if distinct_changes > corpus.changes.len() {
        return Err(oracle_corrupt(format!(
            "Oracle corpus credits {distinct_changes} distinct changes from only {} input change events",
            corpus.input_change_event_count
        )));
    }
    for edge in &corpus.edges {
        validate_precedes_edge(edge)?;
    }
    let expected_edges = precedes_edges(&corpus.occurrences, &corpus.attribution);
    if corpus.edges != expected_edges {
        return Err(oracle_corrupt(format!(
            "Oracle PRECEDES edge roster does not exactly match distinct-outcome derivation: observed={:?} expected={expected_edges:?}",
            corpus.edges
        )));
    }
    Ok(())
}

fn validate_persisted_occurrence_groups(
    rows: &[PersistedOccurrenceRow],
    config: &AttributionConfig,
) -> calyx_core::Result<()> {
    validate_occurrence_groups(
        rows.iter()
            .map(|persisted| occurrence_row_view(&persisted.row)),
        config,
    )?;
    Ok(())
}

/// CF key for one occurrence:
/// `v5-prefix ‖ subject ‖ full_content_hash(subject, change_id, outcome_id)`.
///
/// The source-backed [`OutcomeId`] is part of the identity, so independent real
/// observations cannot collapse merely because source and wall-clock timestamp
/// happen to match. Calyx length-prefixes every hashed part.
fn occurrence_key(subject: CxId, change_id: &str, outcome_id: &OutcomeId) -> Vec<u8> {
    let digest = full_content_hash([
        b"astrolabe.oracle-occurrence-key.v5".as_slice(),
        subject.as_bytes().as_slice(),
        change_id.as_bytes(),
        outcome_id.as_str().as_bytes(),
    ]);
    let mut key = occurrence_subject_prefix(subject);
    key.extend_from_slice(&digest);
    key
}

fn change_key(change: &GitChangeInput) -> Vec<u8> {
    let line = change.line.to_be_bytes();
    let observed_at = change.observed_at.to_be_bytes();
    let confidence_bits = change.confidence_bits.to_be_bytes();
    let digest = full_content_hash([
        b"astrolabe.oracle-change-key.v1".as_slice(),
        change.fix_commit.as_bytes(),
        change.blamed_commit.as_bytes(),
        change.path.as_bytes(),
        line.as_slice(),
        observed_at.as_slice(),
        confidence_bits.as_slice(),
    ]);
    let mut key = ORACLE_CHANGE_PREFIX.to_vec();
    key.extend_from_slice(&digest);
    key
}

impl OracleChangeRowV1 {
    fn from_change(change: &GitChangeInput) -> Self {
        Self {
            schema: ORACLE_CHANGE_ROW_SCHEMA.to_string(),
            fix_commit: change.fix_commit.clone(),
            blamed_commit: change.blamed_commit.clone(),
            path: change.path.clone(),
            line: change.line,
            observed_at: change.observed_at,
            confidence_bits: change.confidence_bits,
        }
    }

    fn into_change(self) -> GitChangeInput {
        GitChangeInput {
            fix_commit: self.fix_commit,
            blamed_commit: self.blamed_commit,
            path: self.path,
            line: self.line,
            observed_at: self.observed_at,
            confidence_bits: self.confidence_bits,
        }
    }
}

fn occurrence_subject_prefix(subject: CxId) -> Vec<u8> {
    let mut prefix = ORACLE_OCCURRENCE_PREFIX.to_vec();
    prefix.extend_from_slice(subject.as_bytes());
    prefix
}

/// CF key for one subject's PRECEDES edge: prefix ‖ blake3(subject).
fn precedes_key(subject: CxId) -> Vec<u8> {
    let mut key = ORACLE_PRECEDES_PREFIX.to_vec();
    key.extend_from_slice(blake3::hash(subject.as_bytes()).as_bytes());
    key
}

// ---------------------------------------------------------------------------
// Persistence report and read-back witnesses
// ---------------------------------------------------------------------------

/// Report for one corpus-persistence group commit.
#[derive(Debug, Clone, PartialEq)]
pub struct OracleCorpusPersistReport {
    /// Exact number of input change events presented to the mining pass.
    pub input_change_event_count: usize,
    /// Exact number of input outcome events presented to the mining pass.
    pub input_outcome_event_count: usize,
    /// Exact number of source-outcome/changed-subject groups presented to mining.
    pub input_attribution_count: usize,
    /// Distinct `(changed subject, source outcome)` groups with candidates.
    pub distinct_attribution_count: usize,
    /// Complete durable Git change inputs retained for incremental merging.
    pub change_count: usize,
    /// Current-symbol change events projected from the complete source roster.
    pub mapped_change_event_count: usize,
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
    /// Hash of exact occurrence, PRECEDES, and change rows (layout excluded).
    pub content_rows_hash: String,
    /// Point-readable binding used by gate and serving admission.
    pub binding: OracleCorpusBinding,
    /// Ledger entry paired with this mutation batch.
    pub ledger_ref: LedgerRef,
    /// Independent full-state readback of the exact live owned rows and exact
    /// hash-bound Ledger entry. Present for mutations and Ledger-only no-ops.
    pub fsv: OracleCorpusFsv,
}

/// Full-state witness returned by every corpus persistence operation.
#[derive(Debug, Clone, PartialEq)]
pub struct OracleCorpusFsv {
    /// Durable sequence containing the corpus Ledger transition.
    pub commit_seq: Seq,
    /// Exact number of live v5 occurrence, v3 PRECEDES, v1 change, and layout rows.
    pub live_owned_row_count: usize,
    /// Lowercase BLAKE3 over canonical length-delimited key/value pairs.
    pub live_owned_rows_hash: String,
    /// Hash of the independently constructed desired row roster.
    pub desired_owned_rows_hash: String,
    /// Whether the exact Ledger row was point-read, hash-verified, and matched
    /// to the expected kind, actor, subject, and payload.
    pub ledger_verified: bool,
    /// Row-level mutation readback when the commit changed owned Kv rows. A
    /// Ledger-only no-op has no row mutation plan, while the live-roster and
    /// exact Ledger proofs above remain mandatory.
    pub mutation: Option<FsvAck>,
}

/// One decoded, key-verified occurrence row read back from the `Kv` CF.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedOccurrenceRow {
    pub key: Vec<u8>,
    pub row: OccurrenceRowV3,
}

/// One decoded, key-verified PRECEDES edge row read back from the `Kv` CF.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedPrecedesEdgeRow {
    pub key: Vec<u8>,
    pub row: PrecedesEdgeRowV3,
}

/// Point-readable, canonical identity of one complete persisted Oracle corpus.
/// Consumers bind this exact structure into a gate attestation; they do not
/// rescan the corpus merely to decide whether a retained generation is current.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleCorpusBinding {
    pub schema: String,
    pub layout_key_hex: String,
    pub layout_bytes: u64,
    pub layout_blake3: String,
    pub content_rows_hash: String,
    pub corpus_dump_hash: String,
    pub source_binding: OracleCorpusSourceBinding,
    pub attribution: AttributionConfig,
    pub input_change_event_count: usize,
    pub input_outcome_event_count: usize,
    pub input_attribution_count: usize,
    pub distinct_attribution_count: usize,
    pub change_count: usize,
    pub mapped_change_event_count: usize,
    pub occurrence_count: usize,
    pub edge_count: usize,
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
///
/// Cost contract (#1064 PC-04/PC-07/PC-16): full replacement deliberately opens
/// only the Oracle-owned `Kv` prefixes plus the two layout-marker point keys.
/// For `R` live/desired owned rows it performs `O(R log R)` canonical roster
/// work and one independent `O(R log R)` readback; it never scans unrelated `Kv`,
/// graph N=192,873, or graph E=328,899. Production `R` is not guessed: the
/// returned live/written/unchanged/tombstoned counts are the receipt.
pub fn persist_corpus<C>(
    vault: &AsterVault<C>,
    corpus: &OracleCorpus,
    actor: impl Into<String>,
) -> calyx_core::Result<OracleCorpusPersistReport>
where
    C: Clock,
{
    validate_corpus_semantics(corpus)?;
    let dump = corpus_dump_bytes(corpus)?;
    let corpus_dump_hash = hex_lower(blake3::hash(&dump).as_bytes());
    let distinct_attribution_count = corpus
        .occurrences
        .iter()
        .map(|record| (record.subject, &record.outcome_id))
        .collect::<BTreeSet<_>>()
        .len();
    let mut new_rows: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for change in &corpus.git_change_inputs {
        let key = change_key(change);
        let value = serde_json::to_vec(&OracleChangeRowV1::from_change(change))
            .map_err(|error| oracle_corrupt(format!("encode Oracle change row: {error}")))?;
        if new_rows.insert(key, value).is_some() {
            return Err(oracle_corrupt(format!(
                "corpus holds a duplicate Git change input for fix {:?} path {:?} line {}",
                change.fix_commit, change.path, change.line
            )));
        }
    }
    for record in &corpus.occurrences {
        let key = occurrence_key(record.subject, &record.change_id, &record.outcome_id);
        let value = serde_json::to_vec(&OccurrenceRowV3::from_record(record))
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
        let value = serde_json::to_vec(&PrecedesEdgeRowV3::from_edge(edge))
            .map_err(|error| oracle_corrupt(format!("encode precedes edge row: {error}")))?;
        if new_rows.insert(key, value).is_some() {
            return Err(oracle_corrupt(format!(
                "corpus holds a duplicate PRECEDES edge for subject {}",
                edge.subject
            )));
        }
    }
    let content_rows_hash = canonical_content_rows_hash(&new_rows);
    let layout = OracleCorpusLayoutV5::new(
        corpus.attribution,
        corpus.source_binding.clone(),
        corpus.input_change_event_count,
        corpus.input_outcome_event_count,
        corpus.input_attribution_count,
        distinct_attribution_count,
        corpus.changes.len(),
        corpus.git_change_inputs.len(),
        corpus.occurrences.len(),
        corpus.edges.len(),
        corpus_dump_hash.clone(),
        content_rows_hash.clone(),
    );
    let layout_value = serde_json::to_vec(&layout)
        .map_err(|error| oracle_corrupt(format!("encode Oracle corpus layout marker: {error}")))?;
    new_rows.insert(ORACLE_CORPUS_LAYOUT_KEY.to_vec(), layout_value);

    // Owned keyspace: every live oracle row plus every fresh corpus key.
    let snapshot = vault.snapshot();
    let mut existing_rows: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for prefix in [
        ORACLE_OCCURRENCE_PREFIX,
        LEGACY_ORACLE_OCCURRENCE_PREFIX_V4,
        LEGACY_ORACLE_OCCURRENCE_PREFIX_V3,
        LEGACY_ORACLE_OCCURRENCE_PREFIX_V2,
        LEGACY_ORACLE_OCCURRENCE_PREFIX_V1,
        ORACLE_PRECEDES_PREFIX,
        LEGACY_ORACLE_PRECEDES_PREFIX_V2,
        LEGACY_ORACLE_PRECEDES_PREFIX_V1,
        ORACLE_CHANGE_PREFIX,
    ] {
        for (key, value) in
            vault.scan_cf_range_at(snapshot, ColumnFamily::Kv, &prefix_range(prefix))?
        {
            if !is_tombstone_value(&value) {
                if existing_rows.insert(key.clone(), value).is_some() {
                    return Err(oracle_corrupt(format!(
                        "Oracle owned-key scan returned duplicate key {}",
                        hex_lower(&key)
                    )));
                }
            }
        }
    }
    if let Some(value) = vault.read_cf_at(snapshot, ColumnFamily::Kv, ORACLE_CORPUS_LAYOUT_KEY)? {
        if !is_tombstone_value(&value) {
            existing_rows.insert(ORACLE_CORPUS_LAYOUT_KEY.to_vec(), value);
        }
    }
    if let Some(value) = vault.read_cf_at(
        snapshot,
        ColumnFamily::Kv,
        LEGACY_ORACLE_CORPUS_LAYOUT_KEY_V4,
    )? {
        if !is_tombstone_value(&value) {
            existing_rows.insert(LEGACY_ORACLE_CORPUS_LAYOUT_KEY_V4.to_vec(), value);
        }
    }
    if let Some(value) = vault.read_cf_at(
        snapshot,
        ColumnFamily::Kv,
        LEGACY_ORACLE_CORPUS_LAYOUT_KEY_V3,
    )? {
        if !is_tombstone_value(&value) {
            existing_rows.insert(LEGACY_ORACLE_CORPUS_LAYOUT_KEY_V3.to_vec(), value);
        }
    }
    let mut owned_keys = existing_rows.keys().cloned().collect::<BTreeSet<_>>();
    for key in new_rows.keys() {
        owned_keys.insert(key.clone());
    }

    let tombstone = tombstone_value();
    let mut batch = Vec::new();
    let mut rows_written = 0usize;
    let mut rows_unchanged = 0usize;
    let mut rows_tombstoned = 0usize;
    for key in &owned_keys {
        match (new_rows.get(key), existing_rows.get(key)) {
            (Some(value), Some(existing_value)) if *existing_value == value => {
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

    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": ORACLE_CORPUS_LEDGER_SCHEMA,
        "attribution_knob_registry_version": ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION,
        "attribution_scale": ORACLE_ATTRIBUTION_SCALE,
        "attribution_fraction_bits": ORACLE_ATTRIBUTION_FRACTION_BITS,
        "decay_model": ORACLE_DECAY_MODEL,
        "credit_apportionment": ORACLE_CREDIT_APPORTIONMENT,
        "attribution": corpus.attribution,
        "source_binding": corpus.source_binding,
        "input_change_event_count": corpus.input_change_event_count,
        "input_outcome_event_count": corpus.input_outcome_event_count,
        "input_attribution_count": corpus.input_attribution_count,
        "distinct_attribution_count": distinct_attribution_count,
        "mapped_change_event_count": corpus.changes.len(),
        "change_count": corpus.git_change_inputs.len(),
        "occurrence_count": corpus.occurrences.len(),
        "edge_count": corpus.edges.len(),
        "rows_written": rows_written,
        "rows_unchanged": rows_unchanged,
        "rows_tombstoned": rows_tombstoned,
        "corpus_dump_hash": corpus_dump_hash,
        "content_rows_hash": content_rows_hash,
    }))
    .map_err(|error| oracle_corrupt(format!("encode oracle ledger payload: {error}")))?;
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

    let batch_changed_rows = !batch.is_empty();
    let (commit_seq, ledger_ref) = vault.write_cf_batch_with_ledger_entry_if_seq(
        snapshot,
        batch,
        EntryKind::Score,
        subject.clone(),
        payload.clone(),
        actor.clone(),
    )?;
    vault.flush()?;
    let mutation = batch_changed_rows
        .then(|| fsv_plan.verify_committed_with_ledger_ref(vault, commit_seq, &ledger_ref))
        .transpose()?;
    verify_oracle_ledger_ref(
        vault,
        commit_seq,
        &ledger_ref,
        EntryKind::Score,
        &subject,
        &payload,
        &actor,
    )?;
    let live_rows = read_live_oracle_owned_rows_at(vault, commit_seq)?;
    if live_rows != new_rows {
        return Err(oracle_corrupt(format!(
            "Oracle corpus full readback differs from desired state: live_rows={} desired_rows={} live_hash={} desired_hash={}",
            live_rows.len(),
            new_rows.len(),
            canonical_owned_rows_hash(&live_rows),
            canonical_owned_rows_hash(&new_rows)
        )));
    }
    let live_owned_rows_hash = canonical_owned_rows_hash(&live_rows);
    let desired_owned_rows_hash = canonical_owned_rows_hash(&new_rows);
    let fsv = OracleCorpusFsv {
        commit_seq,
        live_owned_row_count: live_rows.len(),
        live_owned_rows_hash,
        desired_owned_rows_hash,
        ledger_verified: true,
        mutation,
    };
    let binding = read_oracle_corpus_binding_at(vault, commit_seq)?;
    if binding.content_rows_hash != content_rows_hash
        || binding.corpus_dump_hash != corpus_dump_hash
        || binding.source_binding != corpus.source_binding
    {
        return Err(oracle_corrupt(
            "Oracle corpus point binding differs from the committed desired corpus".to_string(),
        ));
    }

    Ok(OracleCorpusPersistReport {
        input_change_event_count: corpus.input_change_event_count,
        input_outcome_event_count: corpus.input_outcome_event_count,
        input_attribution_count: corpus.input_attribution_count,
        distinct_attribution_count,
        change_count: corpus.git_change_inputs.len(),
        mapped_change_event_count: corpus.changes.len(),
        occurrence_count: corpus.occurrences.len(),
        edge_count: corpus.edges.len(),
        rows_written,
        rows_unchanged,
        rows_tombstoned,
        corpus_dump_hash,
        content_rows_hash,
        binding,
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
    read_occurrence_rows_at(vault, snapshot)
}

/// Reads every occurrence row at one caller-retained exact snapshot.
pub fn read_occurrence_rows_at<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
) -> calyx_core::Result<Vec<PersistedOccurrenceRow>>
where
    C: Clock,
{
    let marker = read_oracle_layout_at(vault, snapshot)?;
    let rows = read_occurrence_rows_in_range(
        vault,
        snapshot,
        &prefix_range(ORACLE_OCCURRENCE_PREFIX),
        &marker.attribution,
    )?;
    if rows.len() != marker.occurrence_count {
        return Err(oracle_corrupt(format!(
            "Oracle v5 layout marker declares {} occurrence rows but full readback found {}",
            marker.occurrence_count,
            rows.len()
        )));
    }
    let distinct_attributions = rows
        .iter()
        .map(|persisted| (persisted.row.subject, &persisted.row.outcome_id))
        .collect::<BTreeSet<_>>()
        .len();
    if distinct_attributions != marker.distinct_attribution_count {
        return Err(oracle_corrupt(format!(
            "Oracle v5 layout marker declares {} distinct attributions but full readback found {distinct_attributions}",
            marker.distinct_attribution_count
        )));
    }
    Ok(rows)
}

/// Reads only the occurrence rows for the exact requested subjects at one
/// retained snapshot. This opens exactly `M` subject-prefix ranges and decodes
/// `rows(M)` results, rather than scanning the whole Oracle/Kv corpus; physical
/// range-open/SST-seek cost is therefore `O(M * range_open + rows(M))`, not a
/// claimed constant (PC-07/PC-41). Production `M` remains an explicit request
/// receipt field at the server boundary, not a guessed corpus constant.
pub fn read_occurrence_rows_for_subjects_at<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    subjects: &BTreeSet<CxId>,
) -> calyx_core::Result<Vec<PersistedOccurrenceRow>>
where
    C: Clock,
{
    let marker = read_oracle_layout_at(vault, snapshot)?;
    let mut rows = Vec::new();
    for subject in subjects {
        rows.extend(read_occurrence_rows_in_range(
            vault,
            snapshot,
            &prefix_range(&occurrence_subject_prefix(*subject)),
            &marker.attribution,
        )?);
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    validate_persisted_occurrence_groups(&rows, &marker.attribution)?;
    Ok(rows)
}

fn read_occurrence_rows_in_range<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    range: &calyx_aster::cf::KeyRange,
    config: &AttributionConfig,
) -> calyx_core::Result<Vec<PersistedOccurrenceRow>>
where
    C: Clock,
{
    let mut rows = Vec::new();
    for (key, value) in vault.scan_cf_range_at(snapshot, ColumnFamily::Kv, range)? {
        if is_tombstone_value(&value) {
            continue;
        }
        let row: OccurrenceRowV3 = serde_json::from_slice(&value).map_err(|error| {
            oracle_corrupt(format!(
                "decode occurrence row {}: {error}",
                hex_lower(&key)
            ))
        })?;
        validate_occurrence_row(&row, config)?;
        let canonical = serde_json::to_vec(&row).map_err(|error| {
            oracle_corrupt(format!(
                "re-encode occurrence row {}: {error}",
                hex_lower(&key)
            ))
        })?;
        if value != canonical {
            return Err(oracle_corrupt(format!(
                "occurrence row {} is semantically decodable but not in canonical persisted byte form",
                hex_lower(&key)
            )));
        }
        let expected = occurrence_key(row.subject, &row.change_id, &row.outcome_id);
        if key != expected {
            return Err(oracle_corrupt(format!(
                "occurrence row key {} does not match its decoded identity",
                hex_lower(&key)
            )));
        }
        rows.push(PersistedOccurrenceRow { key, row });
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    validate_persisted_occurrence_groups(&rows, config)?;
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
    let marker = read_oracle_layout_at(vault, snapshot)?;
    let mut rows = Vec::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Kv,
        &prefix_range(ORACLE_PRECEDES_PREFIX),
    )? {
        if is_tombstone_value(&value) {
            continue;
        }
        let row: PrecedesEdgeRowV3 = serde_json::from_slice(&value).map_err(|error| {
            oracle_corrupt(format!(
                "decode precedes edge row {}: {error}",
                hex_lower(&key)
            ))
        })?;
        validate_precedes_row(&row)?;
        let canonical = serde_json::to_vec(&row).map_err(|error| {
            oracle_corrupt(format!(
                "re-encode PRECEDES row {}: {error}",
                hex_lower(&key)
            ))
        })?;
        if value != canonical {
            return Err(oracle_corrupt(format!(
                "PRECEDES row {} is semantically decodable but not in canonical persisted byte form",
                hex_lower(&key)
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
    if rows.len() != marker.edge_count {
        return Err(oracle_corrupt(format!(
            "Oracle v5 layout marker declares {} PRECEDES rows but full readback found {}",
            marker.edge_count,
            rows.len()
        )));
    }
    Ok(rows)
}

/// Reads the complete durable Git-change catalog at one retained snapshot.
/// The scan is restricted to the Oracle-owned change prefix and independently
/// verifies every key, canonical row byte sequence, and layout count.
pub fn read_git_change_inputs_at<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
) -> calyx_core::Result<Vec<GitChangeInput>>
where
    C: Clock,
{
    let marker = read_oracle_layout_at(vault, snapshot)?;
    let mut changes = Vec::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Kv,
        &prefix_range(ORACLE_CHANGE_PREFIX),
    )? {
        if is_tombstone_value(&value) {
            continue;
        }
        let row: OracleChangeRowV1 = serde_json::from_slice(&value).map_err(|error| {
            oracle_corrupt(format!(
                "decode Oracle change row {}: {error}",
                hex_lower(&key)
            ))
        })?;
        let canonical = serde_json::to_vec(&row).map_err(|error| {
            oracle_corrupt(format!(
                "re-encode Oracle change row {}: {error}",
                hex_lower(&key)
            ))
        })?;
        if row.schema != ORACLE_CHANGE_ROW_SCHEMA || canonical != value {
            return Err(oracle_corrupt(format!(
                "Oracle change row {} is not a canonical {ORACLE_CHANGE_ROW_SCHEMA} row",
                hex_lower(&key)
            )));
        }
        let change = row.into_change();
        validate_git_change_input(&change, &marker.source_binding.timebase)
            .map_err(CalyxError::from)?;
        if key != change_key(&change) {
            return Err(oracle_corrupt(format!(
                "Oracle change row key {} does not match its decoded identity",
                hex_lower(&key)
            )));
        }
        changes.push(change);
    }
    changes.sort();
    if changes.len() != marker.change_count {
        return Err(oracle_corrupt(format!(
            "Oracle v5 layout marker declares {} changes but readback found {}",
            marker.change_count,
            changes.len()
        )));
    }
    Ok(changes)
}

/// Point-reads the exact v5 layout identity at one retained generation.
pub fn read_oracle_corpus_binding_at<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
) -> calyx_core::Result<OracleCorpusBinding>
where
    C: Clock,
{
    try_read_oracle_corpus_binding_at(vault, snapshot)?
        .ok_or_else(|| oracle_corrupt("Oracle v5 corpus layout marker is absent".to_string()))
}

/// Point-reads the current layout when present. A missing/tombstoned marker is
/// an explicit legacy/absent state; any present malformed marker still refuses.
pub fn try_read_oracle_corpus_binding_at<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
) -> calyx_core::Result<Option<OracleCorpusBinding>>
where
    C: Clock,
{
    let Some(value) = vault.read_cf_at(snapshot, ColumnFamily::Kv, ORACLE_CORPUS_LAYOUT_KEY)?
    else {
        return Ok(None);
    };
    if is_tombstone_value(&value) {
        return Ok(None);
    }
    let marker = decode_oracle_layout(&value)?;
    let layout_bytes = u64::try_from(value.len()).map_err(|_| {
        oracle_corrupt(format!(
            "Oracle layout byte length {} exceeds u64",
            value.len()
        ))
    })?;
    Ok(Some(OracleCorpusBinding {
        schema: ORACLE_CORPUS_BINDING_SCHEMA.to_string(),
        layout_key_hex: hex_lower(ORACLE_CORPUS_LAYOUT_KEY),
        layout_bytes,
        layout_blake3: hex_lower(blake3::hash(&value).as_bytes()),
        content_rows_hash: marker.content_rows_hash,
        corpus_dump_hash: marker.corpus_dump_hash,
        source_binding: marker.source_binding,
        attribution: marker.attribution,
        input_change_event_count: marker.input_change_event_count,
        input_outcome_event_count: marker.input_outcome_event_count,
        input_attribution_count: marker.input_attribution_count,
        distinct_attribution_count: marker.distinct_attribution_count,
        change_count: marker.change_count,
        mapped_change_event_count: marker.mapped_change_event_count,
        occurrence_count: marker.occurrence_count,
        edge_count: marker.edge_count,
    }))
}

/// Live oracle `Kv` rows in canonical order, tombstones excluded — the byte
/// substrate for the incremental-equals-full-pass comparison.
pub fn raw_oracle_rows<C>(vault: &AsterVault<C>) -> calyx_core::Result<Vec<(Vec<u8>, Vec<u8>)>>
where
    C: Clock,
{
    let snapshot = vault.snapshot();
    Ok(read_live_oracle_owned_rows_at(vault, snapshot)?
        .into_iter()
        .collect())
}

/// Canonical length-delimited binary dump of a corpus for the Ledger content
/// hash and determinism probes. Every UTF-8 and numeric field is independently
/// framed, weights/credits use exact fixed-point integers, and complete records
/// are sorted bytewise. Delimiters inside valid strings therefore cannot alias
/// a different corpus.
pub fn corpus_dump_bytes(corpus: &OracleCorpus) -> calyx_core::Result<Vec<u8>> {
    fn frame(out: &mut Vec<u8>, bytes: &[u8]) -> calyx_core::Result<()> {
        let len = u64::try_from(bytes.len()).map_err(|_| {
            oracle_corrupt(format!(
                "Oracle corpus frame length {} exceeds u64",
                bytes.len()
            ))
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
        Ok(())
    }

    let mut records = Vec::new();
    for record in &corpus.occurrences {
        let mut encoded = Vec::new();
        frame(&mut encoded, b"occurrence")?;
        frame(&mut encoded, record.subject.as_bytes())?;
        frame(&mut encoded, record.change_id.as_bytes())?;
        frame(&mut encoded, record.outcome_id.as_str().as_bytes())?;
        frame(&mut encoded, record.outcome_subject.as_bytes())?;
        frame(
            &mut encoded,
            &serde_json::to_vec(&record.outcome_kind)
                .map_err(|error| oracle_corrupt(format!("encode Oracle outcome kind: {error}")))?,
        )?;
        match record.test_identity {
            Some(test) => {
                frame(&mut encoded, &[1])?;
                frame(&mut encoded, test.as_bytes())?;
            }
            None => frame(&mut encoded, &[0])?,
        }
        frame(&mut encoded, record.source.as_bytes())?;
        frame(&mut encoded, &record.change_ts.to_be_bytes())?;
        frame(&mut encoded, &record.outcome_ts.to_be_bytes())?;
        frame(&mut encoded, &record.lag_s.to_be_bytes())?;
        frame(&mut encoded, &record.decay_weight.units().to_be_bytes())?;
        frame(&mut encoded, &record.credit.units().to_be_bytes())?;
        frame(&mut encoded, &[u8::from(record.passed)])?;
        let candidate_count = u64::try_from(record.candidate_count).map_err(|_| {
            oracle_corrupt(format!(
                "Oracle candidate count {} exceeds u64",
                record.candidate_count
            ))
        })?;
        frame(&mut encoded, &candidate_count.to_be_bytes())?;
        frame(&mut encoded, record.trust.as_str().as_bytes())?;
        records.push(encoded);
    }
    for input in &corpus.git_change_inputs {
        let mut encoded = Vec::new();
        frame(&mut encoded, b"git_change_input")?;
        frame(&mut encoded, input.fix_commit.as_bytes())?;
        frame(&mut encoded, input.blamed_commit.as_bytes())?;
        frame(&mut encoded, input.path.as_bytes())?;
        frame(&mut encoded, &input.line.to_be_bytes())?;
        frame(&mut encoded, &input.observed_at.to_be_bytes())?;
        frame(&mut encoded, &input.confidence_bits.to_be_bytes())?;
        records.push(encoded);
    }
    for change in &corpus.changes {
        let mut encoded = Vec::new();
        frame(&mut encoded, b"change")?;
        frame(&mut encoded, change.subject.as_bytes())?;
        frame(&mut encoded, change.change_id.as_bytes())?;
        frame(&mut encoded, &change.change_ts.to_be_bytes())?;
        records.push(encoded);
    }
    for edge in &corpus.edges {
        let mut encoded = Vec::new();
        frame(&mut encoded, b"precedes")?;
        frame(&mut encoded, edge.subject.as_bytes())?;
        let support = u64::try_from(edge.support).map_err(|_| {
            oracle_corrupt(format!(
                "Oracle PRECEDES support {} exceeds u64",
                edge.support
            ))
        })?;
        frame(&mut encoded, &support.to_be_bytes())?;
        frame(&mut encoded, &edge.median_lag_s.to_be_bytes())?;
        records.push(encoded);
    }
    records.sort();
    let mut out = Vec::new();
    frame(&mut out, b"astrolabe.oracle-corpus-dump.v5")?;
    frame(
        &mut out,
        ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION.as_bytes(),
    )?;
    frame(&mut out, &ORACLE_ATTRIBUTION_SCALE.to_be_bytes())?;
    frame(&mut out, &ORACLE_ATTRIBUTION_FRACTION_BITS.to_be_bytes())?;
    frame(&mut out, ORACLE_DECAY_MODEL.as_bytes())?;
    frame(&mut out, ORACLE_CREDIT_APPORTIONMENT.as_bytes())?;
    frame(
        &mut out,
        &serde_json::to_vec(&corpus.source_binding)
            .map_err(|error| oracle_corrupt(format!("encode Oracle source binding: {error}")))?,
    )?;
    frame(&mut out, &corpus.attribution.window_secs.to_be_bytes())?;
    frame(
        &mut out,
        &corpus.attribution.decay_half_life_secs.to_be_bytes(),
    )?;
    let candidate_cap = u64::try_from(corpus.attribution.candidate_cap).map_err(|_| {
        oracle_corrupt(format!(
            "Oracle candidate cap {} exceeds u64",
            corpus.attribution.candidate_cap
        ))
    })?;
    frame(&mut out, &candidate_cap.to_be_bytes())?;
    let min_edge_support = u64::try_from(corpus.attribution.min_edge_support).map_err(|_| {
        oracle_corrupt(format!(
            "Oracle minimum edge support {} exceeds u64",
            corpus.attribution.min_edge_support
        ))
    })?;
    frame(&mut out, &min_edge_support.to_be_bytes())?;
    let input_change_event_count =
        u64::try_from(corpus.input_change_event_count).map_err(|_| {
            oracle_corrupt(format!(
                "Oracle input change-event count {} exceeds u64",
                corpus.input_change_event_count
            ))
        })?;
    frame(&mut out, &input_change_event_count.to_be_bytes())?;
    let git_change_input_count = u64::try_from(corpus.git_change_inputs.len()).map_err(|_| {
        oracle_corrupt(format!(
            "Oracle Git change-input count {} exceeds u64",
            corpus.git_change_inputs.len()
        ))
    })?;
    frame(&mut out, &git_change_input_count.to_be_bytes())?;
    let input_outcome_event_count =
        u64::try_from(corpus.input_outcome_event_count).map_err(|_| {
            oracle_corrupt(format!(
                "Oracle input outcome-event count {} exceeds u64",
                corpus.input_outcome_event_count
            ))
        })?;
    frame(&mut out, &input_outcome_event_count.to_be_bytes())?;
    let input_attribution_count = u64::try_from(corpus.input_attribution_count).map_err(|_| {
        oracle_corrupt(format!(
            "Oracle input attribution count {} exceeds u64",
            corpus.input_attribution_count
        ))
    })?;
    frame(&mut out, &input_attribution_count.to_be_bytes())?;
    let count = u64::try_from(records.len()).map_err(|_| {
        oracle_corrupt(format!(
            "Oracle corpus row count {} exceeds u64",
            records.len()
        ))
    })?;
    frame(&mut out, &count.to_be_bytes())?;
    for record in records {
        frame(&mut out, &record)?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn canonical_owned_rows_hash(rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> String {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(rows.len().saturating_mul(2).saturating_add(1));
    parts.push(b"astrolabe.oracle-corpus-owned-rows.v5");
    for (key, value) in rows {
        parts.push(key);
        parts.push(value);
    }
    hex_lower(&full_content_hash(parts))
}

fn canonical_content_rows_hash(rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> String {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(rows.len().saturating_mul(2).saturating_add(1));
    parts.push(b"astrolabe.oracle-corpus-content-rows.v5");
    for (key, value) in rows {
        parts.push(key);
        parts.push(value);
    }
    hex_lower(&full_content_hash(parts))
}

fn read_live_oracle_owned_rows_at<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
) -> calyx_core::Result<BTreeMap<Vec<u8>, Vec<u8>>>
where
    C: Clock,
{
    let mut rows = BTreeMap::new();
    for prefix in [
        ORACLE_OCCURRENCE_PREFIX,
        ORACLE_PRECEDES_PREFIX,
        ORACLE_CHANGE_PREFIX,
    ] {
        for (key, value) in
            vault.scan_cf_range_at(snapshot, ColumnFamily::Kv, &prefix_range(prefix))?
        {
            if is_tombstone_value(&value) {
                continue;
            }
            if rows.insert(key.clone(), value).is_some() {
                return Err(oracle_corrupt(format!(
                    "Oracle full readback returned duplicate key {}",
                    hex_lower(&key)
                )));
            }
        }
    }
    for prefix in [
        LEGACY_ORACLE_OCCURRENCE_PREFIX_V1,
        LEGACY_ORACLE_OCCURRENCE_PREFIX_V2,
        LEGACY_ORACLE_OCCURRENCE_PREFIX_V3,
        LEGACY_ORACLE_OCCURRENCE_PREFIX_V4,
        LEGACY_ORACLE_PRECEDES_PREFIX_V1,
        LEGACY_ORACLE_PRECEDES_PREFIX_V2,
    ] {
        let legacy = vault.scan_cf_range_at(snapshot, ColumnFamily::Kv, &prefix_range(prefix))?;
        if legacy.iter().any(|(_, value)| !is_tombstone_value(value)) {
            return Err(oracle_corrupt(format!(
                "Oracle full readback found a live retired Oracle row layout under {}",
                String::from_utf8_lossy(prefix)
            )));
        }
    }
    if let Some(value) = vault.read_cf_at(
        snapshot,
        ColumnFamily::Kv,
        LEGACY_ORACLE_CORPUS_LAYOUT_KEY_V4,
    )? {
        if !is_tombstone_value(&value) {
            return Err(oracle_corrupt(
                "Oracle full readback found a live retired v4 layout marker".to_string(),
            ));
        }
    }
    if let Some(value) = vault.read_cf_at(
        snapshot,
        ColumnFamily::Kv,
        LEGACY_ORACLE_CORPUS_LAYOUT_KEY_V3,
    )? {
        if !is_tombstone_value(&value) {
            return Err(oracle_corrupt(
                "Oracle full readback found a live retired v3 layout marker".to_string(),
            ));
        }
    }
    let layout_value = vault
        .read_cf_at(snapshot, ColumnFamily::Kv, ORACLE_CORPUS_LAYOUT_KEY)?
        .ok_or_else(|| oracle_corrupt("Oracle v5 corpus layout marker is absent".to_string()))?;
    let layout = decode_oracle_layout(&layout_value)?;
    let content_rows = rows.clone();
    let content_rows_hash = canonical_content_rows_hash(&content_rows);
    if content_rows_hash != layout.content_rows_hash {
        return Err(oracle_corrupt(format!(
            "Oracle content-row hash mismatch: layout={} readback={content_rows_hash}",
            layout.content_rows_hash
        )));
    }
    rows.insert(ORACLE_CORPUS_LAYOUT_KEY.to_vec(), layout_value);
    Ok(rows)
}

fn read_oracle_layout_at<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
) -> calyx_core::Result<OracleCorpusLayoutV5>
where
    C: Clock,
{
    let value = vault
        .read_cf_at(snapshot, ColumnFamily::Kv, ORACLE_CORPUS_LAYOUT_KEY)?
        .ok_or_else(|| {
            oracle_corrupt(
                "Oracle v5 corpus layout marker is absent; generate and persist the source-bound real corpus before grounded serving"
                    .to_string(),
            )
        })?;
    decode_oracle_layout(&value)
}

fn decode_oracle_layout(value: &[u8]) -> calyx_core::Result<OracleCorpusLayoutV5> {
    if is_tombstone_value(value) {
        return Err(oracle_corrupt(
            "Oracle v5 corpus layout marker is tombstoned".to_string(),
        ));
    }
    let marker: OracleCorpusLayoutV5 = serde_json::from_slice(value).map_err(|error| {
        oracle_corrupt(format!("decode Oracle v5 corpus layout marker: {error}"))
    })?;
    marker.validate()?;
    if serde_json::to_vec(&marker)
        .map_err(|error| oracle_corrupt(format!("re-encode Oracle layout marker: {error}")))?
        != value
    {
        return Err(oracle_corrupt(
            "Oracle v5 layout marker is not in canonical persisted byte form".to_string(),
        ));
    }
    Ok(marker)
}

#[allow(clippy::too_many_arguments)]
fn verify_oracle_ledger_ref<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    ledger_ref: &LedgerRef,
    expected_kind: EntryKind,
    expected_subject: &SubjectId,
    expected_payload: &[u8],
    expected_actor: &ActorId,
) -> calyx_core::Result<()>
where
    C: Clock,
{
    let key = ledger_key(ledger_ref.seq);
    let value = vault
        .read_cf_at(snapshot, ColumnFamily::Ledger, &key)?
        .ok_or_else(|| CalyxError {
            code: ASTRO_ORACLE_LEDGER_MISSING,
            message: format!(
                "Ledger CF has no row at oracle corpus ledger seq {}",
                ledger_ref.seq
            ),
            remediation: ORACLE_REMEDIATION,
        })?;
    let entry = decode_ledger(&value)?;
    if !entry.verify()
        || entry.seq != ledger_ref.seq
        || entry.entry_hash != ledger_ref.hash
        || entry.kind != expected_kind
        || &entry.subject != expected_subject
        || entry.payload.as_slice() != expected_payload
        || &entry.actor != expected_actor
    {
        return Err(CalyxError {
            code: ASTRO_ORACLE_LEDGER_MISSING,
            message: format!(
                "Oracle Ledger readback mismatch at seq {}: encoded_seq={} hash_match={} kind={:?} subject_match={} payload_match={} actor_match={} self_verified={}",
                ledger_ref.seq,
                entry.seq,
                entry.entry_hash == ledger_ref.hash,
                entry.kind,
                &entry.subject == expected_subject,
                entry.payload.as_slice() == expected_payload,
                &entry.actor == expected_actor,
                entry.verify(),
            ),
            remediation: ORACLE_REMEDIATION,
        });
    }
    Ok(())
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
