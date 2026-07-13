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

pub mod deficits;
pub mod error;
pub mod fingerprint;
pub mod knobs;
pub mod population;
pub mod scheduler;
pub mod store;
pub mod strata;

pub use deficits::{DeficitMeasurement, OPTIMIZER_DEFICITS_SCHEMA, optimizer_deficits_document};
pub use error::{AssayError, Result};
pub use fingerprint::InputFingerprint;
pub use population::{AssaySubject, Population};
pub use scheduler::{
    AssayScheduler, CooperativeScorer, IsolationDecision, SampleRequest, ScheduleOutcome,
    TickReport, TickStep, check_serving_isolation, serving_p99_micros,
};
pub use store::AssayStore;
pub use strata::{SampleResult, SelectedSubject, StratumAllocation, stratified_sample};

/// The Cargo package name for this crate.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

/// Returns the upstream parent system this crate's behavior derives from.
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
