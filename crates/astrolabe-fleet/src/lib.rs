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
//! panels; coupling them to `astrolabe-ingest` would drag the whole import
//! machinery into every fleet tool. This crate depends only on the Calyx vault
//! engine and the ledger.
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
pub mod record;
pub mod state;

pub use catalog::{
    FLEET_ACTOR, FLEET_VAULT_ID, FLEET_VAULT_SALT, FleetCatalog, RegisterOutcome, RegisterReport,
    TransitionReport,
};
pub use record::{
    FLEET_PANEL_VERSION, FleetRepoRow, RepoRecord, TransitionContext, repo_cx_id,
    repo_identity_bytes,
};
pub use state::{
    ASTRO_FLEET_ILLEGAL_TRANSITION, ASTRO_FLEET_UNKNOWN_STATE, RepoState, check_transition,
};
