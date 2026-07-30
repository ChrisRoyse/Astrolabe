#![forbid(unsafe_code)]

mod erasure_scrub;
pub mod fsv;
mod graph_projection;
mod janitor;
mod kernel_artifact;
mod label_propagation;
mod label_seeds;
mod ledger_scan;
mod ledger_verify;
mod registry;
mod row_sink_stream;
mod sqlite_import;

pub use erasure_scrub::{
    ASTRO_ERASURE_SCRUB_BATCH_INVALID, ASTRO_ERASURE_SCRUB_IO, ASTRO_ERASURE_SCRUB_NOT_DURABLE,
    ASTRO_ERASURE_SCRUB_TORN_WAL, ASTRO_ERASURE_SCRUB_WAL_UNCOVERED, WAL_SCRUB_LEDGER_SCHEMA,
    WalScrubParams, WalScrubReport, WalScrubStatus, scrub_erased_wal_history, wal_scrub_status,
};
pub use fsv::VaultMutationPlan;
pub use janitor::{
    ASTRO_FSV_JANITOR_CHAIN_DAMAGE, ASTRO_FSV_JANITOR_CHECKPOINT_CORRUPT,
    ASTRO_FSV_JANITOR_INTERVAL_INVALID, ASTRO_FSV_JANITOR_LANE_SPAWN_FAILED,
    ASTROLABE_FSV_JANITOR_ACTOR, FSV_JANITOR_SCRUB_LEDGER_SCHEMA, JANITOR_CHECKPOINT_KEY,
    JanitorLane, JanitorLaneConfig, JanitorLaneState, JanitorStepReport, janitor_startup_verify,
    read_janitor_checkpoint, run_janitor_scrub_step,
};

pub use row_sink_stream::{
    ASTRO_ROW_SINK_STREAM_BATCH_INVALID, ASTRO_ROW_SINK_STREAM_ROW_REFUSED, RowSinkStreamParams,
    RowSinkStreamReport, RowSinkStreamRow, import_cbm_row_stream_to_vault,
    snapshot_into_row_stream,
};

pub use label_propagation::{
    ASTRO_LABEL_PROP_ROW_CORRUPT, LABEL_EDGE_ROW_PREFIX, LABEL_GRAPH_LEDGER_SCHEMA,
    LABEL_PROPAGATION_LEDGER_SCHEMA, LABEL_SEED_ROW_PREFIX, LABEL_TOMBSTONE_ROW_PREFIX,
    LabelGraphPersistReport, LivePropagationReport, PROPAGATED_LABEL_ROW_PREFIX,
    PersistedPropagatedLabel, PropagatedLabelRow, SCHEMA_LABEL_EDGE_ROW, SCHEMA_LABEL_SEED_ROW,
    SCHEMA_LABEL_TOMBSTONE_ROW, SCHEMA_PROPAGATED_LABEL_ROW, persist_label_graph,
    propagate_labels_over_vault, read_propagated_label_rows,
};

pub use label_seeds::{
    IndexTimeLabelReport, KERNEL_CORE_LABEL, LABEL_SEED_ACTOR, NO_GROUNDED_LABEL_SOURCE,
    derive_and_propagate_index_time_labels, kernel_member_seeds, label_graph_edges_from_csr,
};

pub use graph_projection::{
    ASTRO_GRAPH_PROJECTION_CORRUPT, GRAPH_PROJECTION_CSR_PREFIX, GraphProjectionBuildOptions,
    GraphProjectionCsr, GraphProjectionCsrEdge, GraphProjectionKind,
    GraphProjectionMaterializeEntry, GraphProjectionMaterializeReport, GraphProjectionNode,
    ensure_graph_projection_csr, materialize_graph_projection, materialize_graph_projections,
    read_graph_projection_csr,
};
pub use kernel_artifact::{
    ASTRO_KERNEL_ARTIFACT_PERSIST_READBACK, ASTRO_KERNEL_GRAPH_ADAPTER_REFUSED,
    KERNEL_ARTIFACT_ACTOR, KERNEL_ARTIFACT_CF_PREFIX, KernelArtifactPersistReport,
    build_and_persist_kernel, kernel_graph_from_projection_csr, persist_kernel_artifact,
    read_persisted_kernel_artifact,
};
pub use ledger_scan::{
    ASTRO_LEDGER_SCAN_CHAIN_NOT_INTACT, ASTRO_LEDGER_SCAN_ROW_CORRUPT,
    ASTRO_LEDGER_SCAN_SUBJECT_EMPTY, LedgerScanRow, ledger_subject_key, scan_subject_ledger_rows,
    scan_subject_ledger_rows_vault_path,
};
pub use ledger_verify::{
    ASTRO_FSV_JANITOR_BUDGET_INVALID, JanitorCheckpoint, JanitorSliceReport, VerifyChainReport,
    verify_chain, verify_chain_slice, verify_chain_vault_path,
};
pub use registry::{
    ASTRO_SERIES_REGISTRY_PREFIX, ASTRO_VERIFY_DEEP_FAILED, DeepVerifyReport, GitRenameStatus,
    IngestError, IngestResult, QN_KEY_MAX_BYTES, QnIndexRow, RecurrenceRow, RenameHint,
    RenameRecord, ReverseIndexRow, SeriesIngestReport, SeriesSplitRecord, SeriesVersionInput,
    SeriesVersionRef, StoredSeriesRegistryRow, bounded_qn_key, ingest_series_batch,
    ingest_series_batch_parallel, parse_git_rename_status, qn_index_key, read_registry_snapshot,
    recurrence_key, reverse_index_key, series_row_key, split_record_key, verify_deep,
    verify_deep_vault_path,
};
pub use sqlite_import::{
    ASTRO_EDGE_DANGLING, ASTRO_EXACT_SOURCE_INVALID, ASTRO_INGEST_READBACK_MISMATCH,
    ASTRO_INGEST_SQLITE_INVALID, ASTRO_LEGACY_CBM_EDGE_ROWS, ASTRO_MISSING_CBM_PROJECT_ROW,
    ASTRO_QUANTIZATION_GATE_INVALID, CBM_FILE_HASH_ROW_SCHEMA, CBM_SQLITE_SCHEMA_VERSION,
    CbmFileHashRow, CbmGraphEdge, CbmGraphNode, CbmGraphSnapshot, CbmProjectRow,
    CbmProjectSummaryRow, CbmRawEdgeRow, CbmSqlitePipelineEdge, CbmSqlitePipelineFileHash,
    CbmSqlitePipelineNode, CbmSqlitePipelineRows, CbmTokenVectorRow, CxGraphErasureReport,
    EdgeSkipCounters, HISTORICAL_SYMBOL_INGEST_LEDGER_SCHEMA, HistoricalSymbolAdmissionReport,
    HistoricalSymbolLocation, InjectedNodeFault, QuantizationGateConfig,
    QuantizationGateMeasurement, QuantizationGatePolicyReport, QuantizationSlotDecision,
    SqliteImportDeepVerifyCounts, SqliteImportOptions, SqliteImportQuantizationReport,
    SqliteImportReadback, SqliteImportReport, admit_historical_symbol_snapshot,
    erase_imported_cx_graph_rows, fingerprint_sqlite_hex, import_cbm_graph_snapshot_to_vault,
    import_cbm_graph_snapshot_to_vault_direct, import_sqlite_to_vault, inject_node_property_fault,
    read_cbm_graph_snapshot, read_cbm_graph_snapshot_at, read_cbm_sqlite_pipeline_rows,
    read_node_map_cx_ids,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
/// Refusal code for vault state that still carries collision-prone v1 SeriesIds.
pub const ASTRO_SERIES_ID_V1_REBUILD_REQUIRED: &str = "ASTRO_SERIES_ID_V1_REBUILD_REQUIRED";

pub(crate) const SERIES_ID_V1_REBUILD_REMEDIATION: &str = "Rebuild the vault from source/CBM bytes so every series-bearing row is derived with the framed astro-series-v2 identity contract.";

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}
