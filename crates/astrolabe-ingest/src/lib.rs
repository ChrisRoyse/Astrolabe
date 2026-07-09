#![forbid(unsafe_code)]

mod graph_projection;
mod ledger_verify;
mod registry;
mod sqlite_import;

pub use graph_projection::{
    ASTRO_GRAPH_PROJECTION_CORRUPT, GRAPH_PROJECTION_CSR_PREFIX, GraphProjectionBuildOptions,
    GraphProjectionCsr, GraphProjectionCsrEdge, GraphProjectionKind,
    GraphProjectionMaterializeEntry, GraphProjectionMaterializeReport, GraphProjectionNode,
    ensure_graph_projection_csr, graph_projection_csr_rows, materialize_graph_projection,
    materialize_graph_projections, read_graph_projection_csr,
};
pub use ledger_verify::{VerifyChainReport, verify_chain, verify_chain_vault_path};
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
    CbmFileHashRow, CbmGraphEdge, CbmGraphNode, CbmGraphSnapshot, CbmProjectRow,
    CbmProjectSummaryRow, CbmRawEdgeRow, CbmTokenVectorRow, CxGraphErasureReport, EdgeSkipCounters,
    SqliteImportDeepVerifyCounts, SqliteImportOptions, SqliteImportReadback, SqliteImportReport,
    erase_imported_cx_graph_rows, import_cbm_graph_snapshot_to_vault,
    import_cbm_graph_snapshot_to_vault_direct, import_sqlite_to_vault, read_cbm_graph_snapshot,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

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
