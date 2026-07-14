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
use astrolabe_guard::{
    PROMPT_INJECTION_FINDING_KIND, PROMPT_INJECTION_PATTERN_REGISTRY_VERSION,
    PromptInjectionFamily, PromptInjectionFinding, PromptScreenInput, PromptSourceKind,
    SECURITY_SCREEN_SCHEMA, SecurityFindingSeverity, SecurityGroundingNote,
    dependency_ood_screen_unavailable, screen_prompt_injection_inputs,
};
use astrolabe_ingest::{
    CbmGraphEdge, CbmGraphNode, CbmGraphSnapshot, RowSinkStreamParams, SqliteImportOptions,
    import_cbm_row_stream_to_vault, import_sqlite_to_vault, snapshot_into_row_stream, verify_chain,
};
use astrolabe_kernel::{
    BRIDGE_SCHEMA, BridgeKernelSymbol, BridgeReport, BridgeScopeKernel,
    CALYX_KERNEL_ANSWER_LEDGER_REQUIRED, DEFAULT_FUNNEL_ACTIVATION_RECORDS,
    KERNEL_ANSWER_KNOB_REGISTRY_VERSION, KERNEL_ANSWER_SCHEMA, KERNEL_GAP_REPORT_SCHEMA,
    LABEL_PROPAGATION_KNOB_REGISTRY_VERSION, LABEL_PROPAGATION_SCHEMA, LabelGraphEdge,
    LabelPropagationConfig, LabelPropagationReport, LabelSeed, LabelTombstone,
    SCOPE_SUMMARY_SCHEMA, SEARCH_SCALE_KNOB_REGISTRY_VERSION, SEARCH_SCALE_SCHEMA,
    SKILL_DISCOVERY_KNOB_REGISTRY_VERSION, SKILL_TREE_SCHEMA, ScopeRecallMeasurement, ScopeSummary,
    ScopeSummaryInput, ScopeSummaryMember, SearchIndexBackend, SearchScaleConfig, SearchScalePlan,
    SkillDiscoveryConfig, SkillSymbolInput, SkillTree, bridge_report_artifact_bytes,
    bridge_symbols, build_skill_tree, label_propagation_artifact_bytes, plan_search_scale,
    propagate_labels, scope_summary_artifact_bytes, skill_tree_artifact_bytes,
    summarize_scope_kernel,
};
use astrolabe_lower::{
    ASTRO_TEAM_ARTIFACT_GRAPH_BYTES, ASTRO_TEAM_ARTIFACT_LEDGER_TAIL,
    ASTRO_TEAM_ARTIFACT_MERKLE_ROOT, ASTRO_TEAM_ARTIFACT_MISSING_GRAPH,
    ASTRO_TEAM_ARTIFACT_SIGNATURE, ASTRO_TEAM_ARTIFACT_SIGNATURE_SIGNER,
    ASTRO_TEAM_ARTIFACT_VAULT_BYTES, GRAPH_DB_ZST_NAME, LowerSqliteOptions, TEAM_ARTIFACT_SCHEMA,
    TeamArtifactExportOptions, TeamArtifactExportReport, TeamArtifactImportOptions,
    TeamArtifactImportReport, VAULT_EXPORT_ZST_NAME, export_team_artifact, import_team_artifact,
    lower_cbm_sqlite,
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
    BlindSpotConfig, DEFAULT_BLIND_SPOT_PAIRS, DETECT_ANOMALIES_SCHEMA, EagerAgreementKind,
    LiveAnomalyInputs, SimilarityNode, SimilarityPlannerConfig, SubscriptionId,
    acknowledge_reactive_subscription, anomaly_report_artifact_bytes, blind_spot_anomaly_inputs,
    blind_spot_slots, detect_anomalies, expand_similarity_dirty_region,
    live_anomaly_inputs_from_vault, persist_eager_cross_terms, persist_eager_cross_terms_delta,
    persist_similarity_edges, persist_similarity_edges_delta, plan_eager_cross_terms,
    plan_eager_cross_terms_for_symbols, plan_similarity_edges, read_similarity_edge_rows,
    recover_reactive_state, run_index_time_drift,
};
use calyx_aster::cf::{ColumnFamily, slot_key};
use calyx_aster::ledger_view::parse_aster_ledger_seq;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{Clock, LedgerRef, SlotId, SlotVector, VaultId, VaultStore};
use calyx_ledger::{ActorId, SubjectId, decode as decode_ledger};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::DynError;

mod helpers;
use helpers::*;

mod config_store;
use config_store::*;

mod locks;
use locks::*;

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

mod git_archaeology;
use git_archaeology::*;

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

mod dispatch;
// Non-test code reaches dispatch only through the two public entry points; the
// glob is needed by the colocated tests, which drive the gate internals directly.
#[cfg(test)]
use dispatch::*;
pub use dispatch::{handle_jsonrpc_raw, handle_tool_raw};

#[cfg(test)]
mod tests;

const VAULT_SUFFIX: &str = ".astrolabe-vault";
const LOWERED_SQLITE_SUFFIX: &str = ".astrolabe-lowered.db";

fn sqlite_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}.db"))
}

fn lowered_sqlite_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{LOWERED_SQLITE_SUFFIX}"))
}

fn vault_dir(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{VAULT_SUFFIX}"))
}

fn vault_salt(project: &str) -> String {
    format!("astrolabe-shadow-v1:{project}")
}
