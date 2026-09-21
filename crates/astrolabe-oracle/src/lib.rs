#![forbid(unsafe_code)]

//! Oracle evidence substrate for ASTROLABE (blueprint P7.5).
//!
//! The oracle mines a change-to-outcome corpus with attribution windows: it
//! pairs each change (a commit or edit touching a subject constellation) with
//! later grounded outcomes on the same subject, splitting decayed credit across
//! the candidate changes and aggregating the per-subject lead/lag PRECEDES edge.
//! The corpus is persisted as ledger-paired, FSV-verified `Kv` CF rows so the
//! downstream oracle chain reads verified persisted state, never a planner echo.

pub mod abduce;
pub mod corpus;
pub mod forecast;
pub mod gate;
pub mod predict;

pub use predict::{
    ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED, ASTRO_ORACLE_GRAPH_INVALID,
    ASTRO_ORACLE_GROUNDING_REQUIRED, ASTRO_ORACLE_PREDICT_CONFIG_INVALID,
    ASTRO_ORACLE_PREDICT_REQUEST_INVALID, BacktestCase, BacktestReport, Consequence,
    ConsequenceEdge, ConsequenceEdgeKind, ConsequenceGraph, GroundedRisk, ImpactOutcome,
    ImpactPrediction, InsufficientReport, NodeEvidence,
    ORACLE_BACKTEST_BASELINE_CANDIDATE_CONTRACT, ORACLE_BACKTEST_TOP_K_SUCCESS_PERMILLE,
    ORACLE_BACKTEST_TOP_K_SUCCESS_RATE, ORACLE_INSUFFICIENT_REMEDIATION,
    ORACLE_PREDICT_KNOB_REGISTRY_VERSION, ORACLE_PREDICT_KNOBS,
    ORACLE_SENSOR_DIRECT_CHANGE_HISTORY, OracleEvidence, PredictConfig, PredictRequest,
    SensorDeficit, TestSelection, backtest_phase_gate, grounded_risk, grounded_risk_required,
    oracle_predict_knob, predict_impact, run_backtest,
};

pub use gate::{
    ASTRO_ORACLE_BACKTEST_NOT_BEATEN, ASTRO_ORACLE_FLAKY_EVIDENCE, ASTRO_ORACLE_INSUFFICIENT,
    ASTRO_ORACLE_NO_RECURRENCE, ASTRO_ORACLE_UNGATED_CONFIDENCE, DegradedMode, EvidenceSnapshot,
    FailureMode, GateConfig, GateRefusal, GateVerdict, GatedConfidence, LensDeficit,
    ORACLE_FAILURE_MODES, ORACLE_GATE_FLAKY_SELF_CONSISTENCY_PERMILLE_KNOB,
    ORACLE_GATE_KNOB_REGISTRY_VERSION, ORACLE_GATE_KNOBS,
    ORACLE_GATE_MIN_GROUNDED_OCCURRENCES_KNOB, ORACLE_GATE_RECURRENCE_FLOOR_KNOB,
    ORACLE_GATE_SENSOR_DIRECT_CHANGE_HISTORY, honesty_gate, oracle_failure_mode, oracle_gate_knob,
};

pub use abduce::{
    ASTRO_ORACLE_ABDUCE_CONFIG_INVALID, ASTRO_ORACLE_ABDUCE_REQUEST_INVALID, AbductionConfig,
    AbductionOutcome, AbductionReport, AbductionRequest, CauseHypothesis,
    ORACLE_ABDUCE_INSUFFICIENT_REMEDIATION, ORACLE_ABDUCE_KNOB_REGISTRY_VERSION,
    ORACLE_ABDUCE_KNOBS, ORACLE_SENSOR_FAILURE_HISTORY, abduce_cause, oracle_abduce_knob,
};

pub use forecast::{
    ASTRO_FLAKY_EVIDENCE, ASTRO_NO_RECURRENCE, ASTRO_ORACLE_FORECAST_CONFIG_INVALID, FlakyOutcome,
    FlakyRefusal, ForecastConfig, ForecastOutcome, ForecastReport,
    ORACLE_FLAKY_EVIDENCE_REMEDIATION, ORACLE_FORECAST_KNOB_REGISTRY_VERSION,
    ORACLE_FORECAST_KNOBS, ORACLE_NO_RECURRENCE_REMEDIATION, PeriodicityFit, RecurrenceRefusal,
    RegimeChange, RegimeDirection, failure_events_from_occurrences, forecast_flaky_window,
    forecast_recurrence, oracle_forecast_knob, outcome_series_from_occurrences,
};

pub use corpus::{
    ASTRO_ORACLE_CONFIG_INVALID, ASTRO_ORACLE_EVENT_INVALID, ASTRO_ORACLE_LEDGER_MISSING,
    ASTRO_ORACLE_ROW_CORRUPT, AttributionConfig, AttributionUnits, ChangeEvent, GitChangeInput,
    GitChangeProjection, ORACLE_ATTRIBUTION_FRACTION_BITS,
    ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION, ORACLE_ATTRIBUTION_KNOBS, ORACLE_ATTRIBUTION_SCALE,
    ORACLE_CHANGE_ROW_SCHEMA, ORACLE_CORPUS_BINDING_SCHEMA, ORACLE_CORPUS_LAYOUT_SCHEMA,
    ORACLE_CORPUS_LEDGER_SCHEMA, ORACLE_CORPUS_SOURCE_BINDING_SCHEMA, ORACLE_OCCURRENCE_ROW_SCHEMA,
    ORACLE_PRECEDES_ROW_SCHEMA, ORACLE_TIMEBASE_CONTRACT, OccurrenceRecord, OccurrenceRowV3,
    OracleChangeRowV1, OracleCorpus, OracleCorpusBinding, OracleCorpusPersistReport,
    OracleCorpusSourceBinding, OracleError, OracleTimebase, OutcomeEvent, OutcomeId,
    PRECEDES_DIRECTION, PersistedOccurrenceRow, PersistedPrecedesEdgeRow, PrecedesEdge,
    PrecedesEdgeRowV3, changes_from_git_archaeology, corpus_dump_bytes,
    git_change_inputs_from_archaeology, mine_corpus, mine_occurrences, oracle_attribution_knob,
    outcomes_from_anchor_rows, persist_corpus, precedes_edges, project_git_change_inputs,
    raw_oracle_rows, read_git_change_inputs_at, read_occurrence_rows, read_occurrence_rows_at,
    read_occurrence_rows_for_subjects_at, read_oracle_corpus_binding_at, read_precedes_edges,
    try_read_oracle_corpus_binding_at,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}
