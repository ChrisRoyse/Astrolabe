#![forbid(unsafe_code)]

mod registry;
mod sqlite_import;

pub use registry::{
    ASTRO_SERIES_REGISTRY_PREFIX, DeepVerifyReport, GitRenameStatus, IngestError, IngestResult,
    QN_KEY_MAX_BYTES, QnIndexRow, RecurrenceRow, RenameHint, RenameRecord, ReverseIndexRow,
    SeriesIngestReport, SeriesSplitRecord, SeriesVersionInput, SeriesVersionRef,
    StoredSeriesRegistryRow, bounded_qn_key, ingest_series_batch, ingest_series_batch_parallel,
    parse_git_rename_status, qn_index_key, read_registry_snapshot, recurrence_key,
    reverse_index_key, series_row_key, split_record_key, verify_deep, verify_deep_vault_path,
};
pub use sqlite_import::{
    ASTRO_EDGE_DANGLING, ASTRO_INGEST_READBACK_MISMATCH, ASTRO_INGEST_SQLITE_INVALID,
    EdgeSkipCounters, SqliteImportDeepVerifyCounts, SqliteImportOptions, SqliteImportReadback,
    SqliteImportReport, import_sqlite_to_vault,
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
