//! Fleet layer: the durable catalog of external repositories Astrolabe farms
//! kernels from (issue #449, EPIC #461).
//!
//! # Why this is its own crate
//!
//! The fleet layer is its own domain, not ingest: the catalog and its
//! lifecycle state machine are shared infrastructure for GitHub discovery
//! (#450), the clone farm (#451), the batch orchestrator (#452), cross-repo
//! dedup (#455), kernel composition (#456), the growth scheduler (#457), and
//! fleet-scope serving (#459). None of those atoms import SQLite rows or run
//! panels; coupling them to the server would drag the C half into every fleet
//! tool. This crate depends on the Calyx vault engine, the ledger, and (since
//! #452, for the orchestrator's independent readbacks only) the pure-Rust
//! `astrolabe-ingest` kernel-artifact codec plus `rusqlite` — never `cbm-sys`.
//!
//! # Where the data lives
//!
//! Doctrine: structured data lives in Calyx — no side store. The catalog is
//! its own Calyx vault ([`catalog::FLEET_VAULT_ID`]) holding **one
//! constellation per repository** in the Base column family. Every lifecycle
//! mutation commits its ledger entry in the same atomic batch (invariant 5)
//! and is read back from the committed snapshot before the call returns
//! (fail-closed write-path FSV).

use std::thread;

pub mod catalog;
pub mod clone_farm;
pub mod compose;
pub mod dedup;
pub mod discover;
pub mod farm_lock;
pub mod grow;
pub mod orchestrator;
pub mod projection_upgrade;
pub mod record;
pub mod retirement;
pub mod shared_checkout;
pub mod state;

/// Name given to the explicitly sized host thread used by fleet CLI entrypoints.
pub const FLEET_HOST_THREAD_NAME: &str = "astrolabe-fleet-host";

/// Runs a fleet binary entrypoint on the same registry-sized host thread used by
/// the server before it can enter CBM/Astrolabe-heavy code paths.
///
/// Windows fixes the process main-thread stack reserve in the PE header. The
/// Astrolabe stack contract already records that in-process CBM/pipeline code
/// can overflow the default reserve with `STATUS_STACK_OVERFLOW` before it can
/// publish structured diagnostics. Fleet binaries link and dispatch through the
/// same crate graph, so their entrypoints use the declared host-thread reserve
/// by construction instead of depending on a caller-specific PE stack setting.
pub fn run_on_sized_host_thread<F>(entrypoint: F) -> i32
where
    F: FnOnce() -> i32 + Send + 'static,
{
    let host = thread::Builder::new()
        .name(FLEET_HOST_THREAD_NAME.to_string())
        .stack_size(astrolabe_domain::knobs::cbm_pipeline_host_stack_bytes())
        .spawn(entrypoint)
        .expect("spawn sized fleet host thread");
    match host.join() {
        Ok(code) => code,
        Err(_) => {
            eprintln!("astrolabe-fleet: host thread panicked");
            1
        }
    }
}

pub use catalog::{
    FLEET_ACTOR, FLEET_VAULT_ID, FLEET_VAULT_SALT, FleetCatalog, RegisterOutcome, RegisterReport,
    SourceRehydration, TransitionReport,
};
pub use clone_farm::{
    ASTRO_FLEET_CLONE_PASS_INCOMPLETE, ASTRO_FLEET_CLONE_TARGET_CONFLICT,
    ASTRO_FLEET_FARM_BUDGET_EXCEEDED, DEFAULT_FARM_BUDGET_BYTES, DEFAULT_FARM_ROOT,
    DEFAULT_GIT_TIMEOUT_SECS, DEFAULT_PARALLELISM, DEFAULT_SIZE_CAP_BYTES, FarmConfig, Selection,
    run_clone_pass, target_dir,
};
pub use compose::{
    ASTRO_FLEET_COMPOSE_NO_KERNELS, ASTRO_FLEET_KERNEL_MISSING, ComposeConfig,
    FLEET_COMPOSE_KNOB_REGISTRY_VERSION, FLEET_COMPOSE_KNOBS, FLEET_KERNEL_REPORT_KIND,
    compose_fleet_kernel, read_fleet_kernel, verify_member_provenance,
};
pub use discover::{
    ASTRO_FLEET_DISCOVERY_INCOMPLETE, ASTRO_FLEET_GH_API, DEFAULT_CATALOG_ROOT, DEFAULT_LANGUAGES,
    DEFAULT_STAR_FLOOR, run_discovery,
};
pub use orchestrator::{
    ASTRO_FLEET_HOST_BUSY, ASTRO_FLEET_PIPELINE_CONFIG, ASTRO_FLEET_PIPELINE_INCOMPLETE,
    ASTRO_FLEET_PIPELINE_SPAWN, DEFAULT_ARCHAEOLOGY_ROOT, DEFAULT_HOST_ADMISSION_TIMEOUT_SECS,
    DEFAULT_NOMIC_DIR, DEFAULT_PIPELINE_PARALLELISM, DEFAULT_PIPELINE_TIMEOUT_SECS,
    DEFAULT_STORE_ROOT, EXPENSIVE_INDEX_HOST_CARDINALITY, IndexAdmissionTelemetry, PipelineConfig,
    run_pipeline_pass,
};
pub use projection_upgrade::{
    ASTRO_FLEET_PROJECTION_UPGRADE_REFUSED, ProjectionUpgradeConfig, ProjectionUpgradePreparation,
    complete_projection_upgrade, prepare_projection_upgrade,
};
pub use record::{
    FLEET_PANEL_VERSION, FleetRepoRow, RepoRecord, SourceRetirement, SourceRetirementStage,
    TransitionContext, repo_cx_id, repo_identity_bytes,
};
pub use retirement::{
    ASTRO_FLEET_SOURCE_RETIREMENT_INCOMPLETE, ASTRO_FLEET_SOURCE_RETIREMENT_REFUSED,
    RetirementConfig, RetirementPassOutcome, run_source_retirement_pass,
};
pub use shared_checkout::{
    ASTRO_FLEET_SHARED_CHECKOUT_CONFIG, ASTRO_FLEET_SHARED_CHECKOUT_DRIFT,
    ASTRO_FLEET_SHARED_CHECKOUT_GIT, ASTRO_FLEET_SHARED_CHECKOUT_OUTPUT,
    ASTRO_FLEET_SHARED_CHECKOUT_VERIFY, REMEDIATE_OUTPUT, SharedCheckoutConfig,
    SharedCheckoutReport, create_shared_checkout,
};
pub use state::{
    ASTRO_FLEET_ILLEGAL_TRANSITION, ASTRO_FLEET_UNKNOWN_STATE, RepoState, check_transition,
};
