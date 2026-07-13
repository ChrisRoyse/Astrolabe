#![forbid(unsafe_code)]

pub mod fsv;
mod graph_projection;
mod ledger_scan;
mod ledger_verify;
mod registry;
mod sqlite_import;

pub use fsv::VaultMutationPlan;

pub use graph_projection::{
    ASTRO_GRAPH_PROJECTION_CORRUPT, GRAPH_PROJECTION_CSR_PREFIX, GraphProjectionBuildOptions,
    GraphProjectionCsr, GraphProjectionCsrEdge, GraphProjectionKind,
    GraphProjectionMaterializeEntry, GraphProjectionMaterializeReport, GraphProjectionNode,
    ensure_graph_projection_csr, graph_projection_csr_rows, materialize_graph_projection,
    materialize_graph_projections, read_graph_projection_csr,
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
    ASTRO_EDGE_DANGLING, ASTRO_INGEST_READBACK_MISMATCH, ASTRO_INGEST_SQLITE_INVALID,
    ASTRO_LEGACY_CBM_EDGE_ROWS, ASTRO_MISSING_CBM_PROJECT_ROW, ASTRO_QUANTIZATION_GATE_INVALID,
    CbmFileHashRow, CbmGraphEdge, CbmGraphNode, CbmGraphSnapshot, CbmProjectRow,
    CbmProjectSummaryRow, CbmRawEdgeRow, CbmTokenVectorRow, CxGraphErasureReport, EdgeSkipCounters,
    InjectedNodeFault, QuantizationGateConfig, QuantizationGateMeasurement,
    QuantizationGatePolicyReport, QuantizationSlotDecision, SqliteImportDeepVerifyCounts,
    SqliteImportOptions, SqliteImportQuantizationReport, SqliteImportReadback, SqliteImportReport,
    erase_imported_cx_graph_rows, fingerprint_sqlite_hex, import_cbm_graph_snapshot_to_vault,
    import_cbm_graph_snapshot_to_vault_direct, import_sqlite_to_vault, inject_node_property_fault,
    read_cbm_graph_snapshot,
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
