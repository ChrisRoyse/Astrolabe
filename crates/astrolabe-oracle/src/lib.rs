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
pub mod predict;

pub use predict::{
    ASTRO_ORACLE_GRAPH_INVALID, ASTRO_ORACLE_PREDICT_CONFIG_INVALID,
    ASTRO_ORACLE_PREDICT_REQUEST_INVALID, BacktestCase, BacktestReport, Consequence,
    ConsequenceEdge, ConsequenceEdgeKind, ConsequenceGraph, ImpactOutcome, ImpactPrediction,
    InsufficientReport, NodeEvidence, ORACLE_BACKTEST_TOP_K_SUCCESS_RATE,
    ORACLE_INSUFFICIENT_REMEDIATION, ORACLE_PREDICT_KNOB_REGISTRY_VERSION, ORACLE_PREDICT_KNOBS,
    ORACLE_SENSOR_DIRECT_CHANGE_HISTORY, OracleEvidence, PredictConfig, PredictRequest,
    SensorDeficit, TestSelection, backtest_phase_gate, oracle_predict_knob, predict_impact,
    run_backtest,
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
    ASTRO_ORACLE_ROW_CORRUPT, AttributionConfig, ChangeEvent,
    ORACLE_ATTRIBUTION_KNOB_REGISTRY_VERSION, ORACLE_ATTRIBUTION_KNOBS,
    ORACLE_CORPUS_LEDGER_SCHEMA, ORACLE_OCCURRENCE_ROW_SCHEMA, ORACLE_PRECEDES_ROW_SCHEMA,
    OccurrenceRecord, OccurrenceRowV1, OracleCorpus, OracleCorpusPersistReport, OracleError,
    OutcomeEvent, PRECEDES_DIRECTION, PersistedOccurrenceRow, PersistedPrecedesEdgeRow,
    PrecedesEdge, PrecedesEdgeRowV1, changes_from_git_archaeology, corpus_dump_bytes, mine_corpus,
    mine_occurrences, oracle_attribution_knob, outcomes_from_anchor_rows, persist_corpus,
    precedes_edges, raw_oracle_rows, read_occurrence_rows, read_precedes_edges,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_calyx_parent() {
        assert_eq!(parent_system(), astrolabe_domain::ParentSystem::Calyx);
    }
}
