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

pub mod catalog;
pub mod clone_farm;
pub mod compose;
pub mod dedup;
pub mod discover;
pub mod farm_lock;
pub mod grow;
pub mod orchestrator;
pub mod record;
pub mod retirement;
pub mod state;

pub use catalog::{
    FLEET_ACTOR, FLEET_VAULT_ID, FLEET_VAULT_SALT, FleetCatalog, RegisterOutcome, RegisterReport,
    TransitionReport,
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
    ASTRO_FLEET_PIPELINE_INCOMPLETE, ASTRO_FLEET_PIPELINE_SPAWN, DEFAULT_ARCHAEOLOGY_ROOT,
    DEFAULT_NOMIC_DIR, DEFAULT_PIPELINE_PARALLELISM, DEFAULT_PIPELINE_TIMEOUT_SECS,
    DEFAULT_STORE_ROOT, PipelineConfig, run_pipeline_pass,
};
pub use record::{
    FLEET_PANEL_VERSION, FleetRepoRow, RepoRecord, SourceRetirement, SourceRetirementStage,
    TransitionContext, repo_cx_id, repo_identity_bytes,
};
pub use retirement::{
    ASTRO_FLEET_SOURCE_RETIREMENT_INCOMPLETE, ASTRO_FLEET_SOURCE_RETIREMENT_REFUSED,
    RetirementConfig, RetirementPassOutcome, run_source_retirement_pass,
};
pub use state::{
    ASTRO_FLEET_ILLEGAL_TRANSITION, ASTRO_FLEET_UNKNOWN_STATE, RepoState, check_transition,
};
