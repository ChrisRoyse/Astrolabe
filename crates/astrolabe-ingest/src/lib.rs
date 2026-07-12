#![forbid(unsafe_code)]

mod erasure_scrub;
pub mod fsv;
mod graph_projection;
mod janitor;
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
    ASTROLABE_FSV_JANITOR_ACTOR, FSV_JANITOR_SCRUB_LEDGER_SCHEMA, JANITOR_CHECKPOINT_KEY,
    JanitorStepReport, janitor_startup_verify, read_janitor_checkpoint, run_janitor_scrub_step,
};

pub use row_sink_stream::{
    ASTRO_ROW_SINK_STREAM_BATCH_INVALID, ASTRO_ROW_SINK_STREAM_ROW_REFUSED, RowSinkStreamParams,
    RowSinkStreamReport, RowSinkStreamRow, import_cbm_row_stream_to_vault,
};

pub use graph_projection::{
    ASTRO_GRAPH_PROJECTION_CORRUPT, GRAPH_PROJECTION_CSR_PREFIX, GraphProjectionBuildOptions,
    GraphProjectionCsr, GraphProjectionCsrEdge, GraphProjectionKind,
    GraphProjectionMaterializeEntry, GraphProjectionMaterializeReport, GraphProjectionNode,
    ensure_graph_projection_csr, graph_projection_csr_rows, materialize_graph_projection,
    materialize_graph_projections, read_graph_projection_csr,
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
    ASTRO_EDGE_DANGLING, ASTRO_INGEST_READBACK_MISMATCH, ASTRO_INGEST_SQLITE_INVALID,
    ASTRO_LEGACY_CBM_EDGE_ROWS, ASTRO_MISSING_CBM_PROJECT_ROW, ASTRO_QUANTIZATION_GATE_INVALID,
    CbmFileHashRow, CbmGraphEdge, CbmGraphNode, CbmGraphSnapshot, CbmProjectRow,
    CbmProjectSummaryRow, CbmRawEdgeRow, CbmTokenVectorRow, CxGraphErasureReport, EdgeSkipCounters,
    InjectedNodeFault, QuantizationGateConfig, QuantizationGateMeasurement,
    QuantizationGatePolicyReport, QuantizationSlotDecision, SqliteImportDeepVerifyCounts,
    SqliteImportOptions, SqliteImportQuantizationReport, SqliteImportReadback, SqliteImportReport,
    erase_imported_cx_graph_rows, fingerprint_sqlite_hex, import_cbm_graph_snapshot_to_vault,
    import_cbm_graph_snapshot_to_vault_direct, import_sqlite_to_vault, inject_node_property_fault,
    read_cbm_graph_snapshot, read_node_map_cx_ids,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
/// Refusal code for vault state that still carries collision-prone v1 SeriesIds.
pub const ASTRO_SERIES_ID_V1_REBUILD_REQUIRED: &str = "ASTRO_SERIES_ID_V1_REBUILD_REQUIRED";

pub(crate) const SERIES_ID_V1_REBUILD_REMEDIATION: &str = "Rebuild the vault from source/CBM bytes so every series-bearing row is derived with the framed astro-series-v2 identity contract.";

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
