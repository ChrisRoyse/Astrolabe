use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use astrolabe_bridge::{CbmPipelineRows, CbmToolRunner};
use astrolabe_domain::SYMBOL_CANONICAL_TAG;
use astrolabe_guard::{
    PROMPT_INJECTION_FINDING_KIND, PROMPT_INJECTION_PATTERN_REGISTRY_VERSION,
    PromptInjectionFamily, PromptInjectionFinding, PromptScreenInput, PromptSourceKind,
    SECURITY_SCREEN_SCHEMA, SecurityFindingSeverity, SecurityGroundingNote,
    dependency_ood_screen_unavailable, screen_prompt_injection_inputs,
};
use astrolabe_ingest::{
    CBM_FILE_HASH_ROW_SCHEMA, CbmCompactGraphSnapshot, CbmFileHashRow, CbmGraphEdge, CbmGraphNode,
    CbmGraphSnapshot, CbmSqlitePipelineRows, RowSinkStreamParams, SqliteImportOptions,
    import_cbm_row_stream_to_vault, snapshot_into_row_stream, verify_chain,
};
use astrolabe_kernel::{
    BRIDGE_SCHEMA, BridgeKernelSymbol, BridgeReport, BridgeScopeKernel,
    CALYX_KERNEL_ANSWER_LEDGER_REQUIRED, DEFAULT_FUNNEL_ACTIVATION_RECORDS,
    KERNEL_ANSWER_KNOB_REGISTRY_VERSION, KERNEL_ANSWER_KNOBS, KERNEL_ANSWER_SCHEMA,
    KERNEL_GAP_REPORT_SCHEMA, KNOB_ANSWER_INDEX_CACHE_ENTRIES,
    LABEL_PROPAGATION_KNOB_REGISTRY_VERSION, LABEL_PROPAGATION_SCHEMA, LabelGraphEdge,
    LabelPropagationConfig, LabelPropagationReport, LabelSeed, LabelTombstone,
    SCOPE_SUMMARY_SCHEMA, SEARCH_SCALE_KNOB_REGISTRY_VERSION,
    SKILL_DISCOVERY_KNOB_REGISTRY_VERSION, SKILL_TREE_SCHEMA, ScopeRecallMeasurement, ScopeSummary,
    ScopeSummaryInput, ScopeSummaryMember, SearchIndexBackend, SearchScaleConfig, SearchScalePlan,
    SkillDiscoveryConfig, SkillSymbolInput, SkillTree, bridge_report_artifact_bytes,
    bridge_symbols, build_skill_tree, label_propagation_artifact_bytes, plan_search_scale,
    propagate_labels, scope_summary_artifact_bytes, skill_tree_artifact_bytes,
    summarize_scope_kernel,
};
use astrolabe_lower::{
    AS_OF_BUCKET_DEFAULT_WIDTH_MS, AS_OF_BUCKET_WIDTH_MS_KNOB, as_of_bucket_knob,
    lower_cbm_sqlite_at,
};
use astrolabe_lower::{
    ASTRO_TEAM_ARTIFACT_GRAPH_BYTES, ASTRO_TEAM_ARTIFACT_LEDGER_TAIL,
    ASTRO_TEAM_ARTIFACT_MERKLE_ROOT, ASTRO_TEAM_ARTIFACT_MISSING_GRAPH,
    ASTRO_TEAM_ARTIFACT_SIGNATURE, ASTRO_TEAM_ARTIFACT_SIGNATURE_SIGNER,
    ASTRO_TEAM_ARTIFACT_VAULT_BYTES, GRAPH_DB_ZST_NAME, LowerSqliteOptions, TEAM_ARTIFACT_SCHEMA,
    TeamArtifactExportOptions, TeamArtifactExportReport, TeamArtifactImportOptions,
    TeamArtifactImportReport, VAULT_EXPORT_ZST_NAME, export_team_artifact, import_team_artifact,
    lower_cbm_sqlite, verify_lowered_artifact,
};
use astrolabe_panel::{DEFAULT_PANEL_VERSION, PanelInput, PanelResult, PanelSlotSpec, SlotRuntime};
use astrolabe_provenance::{
    AnswerHop, AnswerTrace, ChainStatus, ChainVerification, Freshness, GET_PROVENANCE_SCHEMA,
    InterAgentTrustReport, LedgerPointer, LineageEvent, PROVENANCE_WARN_CHAIN_BROKEN,
    PROVENANCE_WARN_CHAIN_CORRUPT, PROVENANCE_WARN_CHAIN_EMPTY, PackManifest, ProvenancePayload,
    ProvenanceQuery, ProvenanceResponse, ProvenanceStore, ReproduceRecord, SymbolLineage,
    get_provenance, parse_pack_manifest_attestation, provenance_response_artifact_bytes,
    verify_pack_manifest_claim,
};
use astrolabe_weave::{
    AnomalyCalibration, AnomalyKind, AnomalyReport, AnomalySubstrateRow, BlindSpotAnomalyInputs,
    BlindSpotConfig, CrossTermValue, DEFAULT_BLIND_SPOT_PAIRS, DETECT_ANOMALIES_SCHEMA,
    EagerAgreementKind, LiveAnomalyInputs, SimilarityFamily, SimilarityNode,
    SimilarityPlannerConfig, SubscriptionId, acknowledge_reactive_subscription,
    anomaly_report_artifact_bytes, blind_spot_anomaly_inputs, blind_spot_slots, detect_anomalies,
    expand_persisted_similarity_region_from_vault, extend_similarity_candidate_region_for_family,
    live_anomaly_inputs_from_vault, persist_eager_cross_term_kind_run,
    persist_eager_cross_term_kind_run_delta, persist_similarity_family_run,
    persist_similarity_family_run_delta, plan_eager_cross_term_kind_run,
    plan_eager_cross_term_kind_run_delta, plan_similarity_family_run,
    reconcile_complete_associations, recover_reactive_state, run_index_time_drift,
};
use calyx_aster::cf::{ColumnFamily, ledger_key, prefix_range, slot_key};
use calyx_aster::ledger_view::{LedgerPointReadTrace, parse_aster_ledger_seq};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{Clock, LedgerRef, SlotId, SlotVector, VaultId, VaultStore};
use calyx_ledger::{ActorId, SubjectId, decode as decode_ledger};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::DynError;

mod helpers;
use helpers::*;

mod tool_fault;
use tool_fault::*;
pub(crate) use tool_fault::{
    TOOL_FAULT_SCHEMA, tool_fault_from_error, tool_fault_result_from_error,
};

mod config_store;
use config_store::*;

mod locks;
use locks::*;

mod project_transition;
pub(crate) use project_transition::*;

mod tool_defs;
use tool_defs::*;

mod team_artifact;
use team_artifact::*;

mod security_screen;
use security_screen::*;

mod search_scale;
use search_scale::*;

mod skill_tree;
use skill_tree::*;

mod bridges;
use bridges::*;

mod kernel_context;
use kernel_context::*;

mod kernel_gaps;
use kernel_gaps::*;

mod kernel_answer;
use kernel_answer::*;

mod fleet_serving;
use fleet_serving::*;

mod anomalies;
use anomalies::*;

mod agreement_graph;
use agreement_graph::*;

mod provenance;
use provenance::*;

mod shadow_watermark;
use shadow_watermark::*;

mod shadow_import;
use shadow_import::*;
pub(crate) use shadow_import::{
    SHADOW_PANEL_VERSION, ShadowSlotRuntime, open_shadow_vault_historical_read_only,
    shadow_available_slots,
};

mod preserved_stage;
use preserved_stage::*;

mod shadow_publication;
use shadow_publication::*;

mod git_archaeology;
use git_archaeology::*;
// #515/#530: the pooled historical-index extraction serve worker entry, dispatched from
// `run_cli` in lib.rs (`astrolabe cli --archaeology-extract-serve`). Explicitly
// re-exported because the glob `use` above is private to this module.
pub(crate) use git_archaeology::run_archaeology_extract_serve;

mod watcher_lane;
pub(crate) use watcher_lane::run_incremental_watcher_loop;

mod lowering_lane;
use lowering_lane::*;

mod invalidation_lane;
use invalidation_lane::*;

mod layout_lane;
use layout_lane::*;

mod status_surface;
use status_surface::*;
pub(crate) use status_surface::{janitor_startup_verify_projects, periodic_verify_chain_tick};

mod optimizer;
use optimizer::*;

mod impute;
use impute::*;

mod readiness;
use readiness::*;

mod measure_bits;
use measure_bits::*;

mod anchor_outcome;
use anchor_outcome::*;

mod anchor_erase;
use anchor_erase::*;

mod predict_impact;
use predict_impact::*;

mod oracle_surface;
use oracle_surface::*;

/// L5 latent (indirect) association discovery over the persisted composite
/// association projection (#1009).
mod latent_links;
use latent_links::*;

/// Complete grounded association discovery generation (#1012).
mod association_discovery;
use association_discovery::*;

mod coverage_ingest;
use coverage_ingest::*;

mod guard;
use guard::*;

mod guard_check;
use guard_check::*;

mod guard_drift;
use guard_drift::*;

mod guard_secondary;
use guard_secondary::*;

mod assay_gate;
use assay_gate::*;

mod guard_lock;
use guard_lock::*;

mod detect_changes_risk;
use detect_changes_risk::*;

mod search_fusion;
use search_fusion::*;

mod find_similar;
use find_similar::*;

mod trace_path;
use trace_path::*;

mod query_graph_as_of;
use query_graph_as_of::*;

mod architecture_aspects;
use architecture_aspects::*;

mod delete_project;
use delete_project::*;

mod dispatch;
// Non-test code reaches dispatch only through the two public entry points; the
// glob is needed by the colocated tests, which drive the gate internals directly.
pub use dispatch::{handle_jsonrpc_raw, handle_tool_raw};
// #428: the CLI `--help` path (lib.rs `run_cli_tool_help`) consults the native
// tool registry through this single entry point when the C schema registry does
// not know the tool, so help and execution share one membership predicate.
pub(crate) use dispatch::print_astrolabe_native_tool_help;

const VAULT_SUFFIX: &str = ".astrolabe-vault";
/// Write-side name for the per-project lowered-SQLite mirror the Rust host
/// places in the CBM store dir. This file ends in `.db` but is NOT a project
/// store; the C enumerator (`is_project_db_file` in `cbm/src/mcp/mcp.c`) skips
/// it via the reserved-suffix contract so it never surfaces in `list_projects`
/// or gets adopted by `resolve_store` (#414).
///
/// DRIFT CONTRACT: this string MUST byte-match the C-side reserved suffix
/// `CBM_ASTRO_LOWERED_DB_SUFFIX` (declared in `cbm/src/mcp/mcp.h`), which the C
/// enumerator uses to skip this file. The compile-time assertion in
/// [`assert_lowered_suffix_matches_c`] binds the two: editing either without the
/// other fails this crate's compile.
const LOWERED_SQLITE_SUFFIX: &str = ".astrolabe-lowered.db";

/// #414 drift guard — compile-time proof that the Rust write-side suffix and the
/// C read-side reserved suffix are one and the same string.
/// `astrolabe_bridge::CBM_ASTRO_LOWERED_DB_SUFFIX` re-exports the bindgen-
/// surfaced C macro (a NUL-terminated byte array); it is compared to
/// `LOWERED_SQLITE_SUFFIX` byte-for-byte. Drift in either definition breaks the
/// build here rather than silently resurrecting the phantom-project bug.
const _: () = {
    let rust = LOWERED_SQLITE_SUFFIX.as_bytes();
    let c = astrolabe_bridge::CBM_ASTRO_LOWERED_DB_SUFFIX;
    // The C array includes the trailing NUL; the Rust &str does not.
    assert!(
        c.len() == rust.len() + 1,
        "C CBM_ASTRO_LOWERED_DB_SUFFIX and Rust LOWERED_SQLITE_SUFFIX have drifted (length)"
    );
    let mut i = 0;
    while i < rust.len() {
        assert!(
            c[i] == rust[i],
            "C CBM_ASTRO_LOWERED_DB_SUFFIX and Rust LOWERED_SQLITE_SUFFIX have drifted (bytes)"
        );
        i += 1;
    }
    assert!(
        c[rust.len()] == 0,
        "C reserved suffix is not NUL-terminated"
    );
};

fn sqlite_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}.db"))
}

pub(crate) fn lowered_sqlite_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{LOWERED_SQLITE_SUFFIX}"))
}

pub(crate) fn vault_dir(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{VAULT_SUFFIX}"))
}

fn vault_salt(project: &str) -> String {
    format!("astrolabe-shadow-v1:{project}")
}
