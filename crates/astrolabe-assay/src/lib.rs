//! Assay job scheduler for ASTROLABE (P5.1).
//!
//! This crate schedules the background measurement jobs that feed the P5
//! sufficiency chain. It provides:
//!
//! * **Deterministic, seeded stratified sampling** ([`strata`]) that is
//!   worker-count invariant — the sample is a pure function of the input set and
//!   the seed, never of iteration or partition order — with exact,
//!   hand-computable stratum proportions via largest-remainder apportionment.
//! * **Input fingerprints** ([`fingerprint`]) over the full input tuple (seed,
//!   sample size, panel version, shard set, population content) that key an
//!   exact cache and its invalidation: a panel bump, shard change, or content
//!   edit moves the key and sweeps the stale entry.
//! * **A real filesystem-backed store** ([`store`]) that persists results and
//!   strata rows and proves every write by reading the bytes back (FSV).
//! * **A background lane scheduler** ([`scheduler`]) with registry-declared
//!   cooperative-tick budgets and a serving-isolation p99 tripwire that defers
//!   background work — as a labeled degradation — rather than stealing serving
//!   latency.
//! * **The optimizer deficits producer** ([`deficits`]) that frames measured
//!   deficits into the `astrolabe.optimizer_deficits.v1` document the server's
//!   optimizer proposal path consumes (#115).
//!
//! Every budget and threshold is a registry-declared knob ([`knobs`]); every
//! failure is a fail-closed [`error::AssayError`] carrying a code, message, and
//! remediation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod bits;
pub mod calibration;
pub mod causality;
pub mod changepoint;
pub mod deficits;
pub mod diff;
pub mod diff_ledger;
pub mod drift;
pub mod error;
pub mod estimators;
pub mod fingerprint;
pub mod gate;
pub mod knobs;
pub mod ledger;
pub mod multivariate;
pub mod periodicity;
pub mod population;
pub mod projection;
pub mod redundancy;
pub mod redundancy_card;
pub mod rng;
pub mod scheduler;
pub mod score_calibration;
pub mod stats;
pub mod store;
pub mod strata;
pub mod synergy;
pub mod synergy_card;
pub mod transfer_entropy;

pub use bits::{
    AxisValues, BitsConfig, BitsInterval, DeficitSuggestedAction, SignalBits, SignalRankingCard,
    SlotDeficit, SlotObservations, SlotSummary, SlotValues, SufficiencyCard, build_signal_ranking,
    build_sufficiency_card, enforce_dpi_ceiling, measure_slot_bits,
};
pub use calibration::{
    CalibrationCard, CalibrationConfig, CalibrationLedger, CalibrationLedgerEntry,
    CalibrationSource, MeasuredPrecision, StrategyCalibration, StrategyObservation,
    build_calibration_card, calibration_input_fingerprint,
};
pub use causality::{
    CausalityCard, CausalityConfig, CausalityEdge, CausalityEdgeInput, CausalityLag,
    build_causality_card,
};
pub use changepoint::{ChangePointCard, measure_change_point};
pub use deficits::{DeficitMeasurement, OPTIMIZER_DEFICITS_SCHEMA, optimizer_deficits_document};
pub use diff::{DiffConfig, discretize_slot};
pub use diff_ledger::{DiffCardEntry, DiffLedger, DifferentiationCard};
pub use drift::{DriftCard, measure_drift};
pub use error::{AssayError, Result};
pub use estimators::{entropy_bits, mi_continuous_ksg, mi_discrete, mi_mixed_ross};
pub use fingerprint::InputFingerprint;
pub use gate::{
    GateAction, GateConfig, GateDecision, GateEvaluation, GateJournal, GateJournalEntry,
    GateVerdict, LensCapabilityCard, ServingAdmission, build_capability_card, gate_lens,
    is_sole_critical_carrier, max_admitted_correlation, pearson_correlation,
};
pub use ledger::{
    AssayCardAppendRequest, AssayCardBatchReceipt, AssayCardEntry, AssayCardLineReceipt,
    CardLedger, PreparedAssayCardBatch, input_fingerprint,
};
pub use multivariate::{
    conditional_mi_bits, interaction_information_bits, joint_entropy_bits, normalized_mi_bits,
    transfer_entropy_bits,
};
pub use periodicity::{PeriodicityCard, measure_periodicity};
pub use population::{AssaySubject, Population};
pub use redundancy::{PairwiseNmi, RedundancyGate, measure_redundancy};
pub use redundancy_card::{
    RedundancyCard, RedundancyConfig, RedundantPair, SlotColumn, build_redundancy_card,
};
pub use scheduler::{
    AssayScheduler, CooperativeScorer, IsolationDecision, SampleRequest, ScheduleOutcome,
    TickReport, TickStep, check_serving_isolation, serving_p99_micros,
};
// The score-distribution calibration substrate (#36) that turns a repo's own
// blind-spot gap scores into measured severity thresholds. Its `CalibrationConfig`
// is intentionally *not* re-exported at the crate root — that bare name belongs to
// the edge-strategy calibration card (#34); reach it as
// `score_calibration::CalibrationConfig`.
pub use score_calibration::{
    ASSAY_CALIBRATION_KNOB_REGISTRY_VERSION, ASSAY_CALIBRATION_KNOBS,
    ASSAY_CALIBRATION_MAX_SCORE_MILLIPOINTS, DistributionCalibration, assay_calibration_knob,
    calibrate_score_distribution, calibration_dump_bytes, read_calibration_bytes,
};
pub use stats::{inverse_standard_normal_cdf, wilson_interval};
pub use store::AssayStore;
pub use strata::{SampleResult, SelectedSubject, StratumAllocation, stratified_sample};
pub use synergy::{SynergyClass, measure_synergy, measure_synergy_triple};
pub use synergy_card::{
    SynergyCard, SynergyClassification, SynergyConfig, SynergyTriple, SynergyTripleInput,
    build_synergy_card,
};
pub use transfer_entropy::{DirectionEval, DrivesEdge, NamedSeries, measure_transfer_entropy};

/// The Cargo package name for this crate.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

/// Returns the upstream parent system this crate's behavior derives from.
pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}
