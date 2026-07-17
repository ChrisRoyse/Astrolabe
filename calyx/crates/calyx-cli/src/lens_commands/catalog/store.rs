use std::collections::{BTreeMap, BTreeSet};
#[cfg(windows)]
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt as _;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle as _;

use bincode::config;
use calyx_aster::cf::{CfRouter, ColumnFamily};
use calyx_core::{CalyxError, LensCost, Placement, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_SHARE_READ, GetFileInformationByHandle,
    GetFinalPathNameByHandleW,
};

use super::{LensCatalog, LensCatalogEntry};

const V1_INDEX_KEY: &[u8] = b"calyx/lens/catalog/v1/index";
const V1_ENTRY_PREFIX: &[u8] = b"calyx/lens/catalog/v1/entry/";
const V1_INDEX_MAGIC: &[u8] = b"CLCATIX1\0";
const V1_ENTRY_MAGIC: &[u8] = b"CLCATEN1\0";
const V1_RETIREMENT_MAGIC: &[u8] = b"CLCATR22\0";
const V2_INDEX_KEY: &[u8] = b"calyx/lens/catalog/v2/index";
const V2_ENTRY_PREFIX: &[u8] = b"calyx/lens/catalog/v2/entry/";
const V2_IMPORT_RECEIPT_KEY: &[u8] = b"calyx/lens/catalog/v2/import-receipt";
const V2_INDEX_MAGIC: &[u8] = b"CLCATIX2\0";
const V2_ENTRY_MAGIC: &[u8] = b"CLCATEN2\0";
const V2_IMPORT_RECEIPT_MAGIC: &[u8] = b"CLCATIR2\0";
const CF_MEMTABLE_CAP: usize = 8 * 1024 * 1024;
const MAX_LEGACY_CATALOG_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(windows)]
const MAX_FINAL_PATH_CHARS: usize = 32_768;

static PROCESS_MUTATION_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, &'static Mutex<()>>>> =
    OnceLock::new();

pub(crate) const LEGACY_CATALOG_FILE: &str = "registry.json";

pub(crate) struct CatalogMutationGuard {
    db_key: PathBuf,
    _process_guard: MutexGuard<'static, ()>,
    _file: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LegacySourceIdentity {
    namespace: u64,
    file: u64,
}

/// One retained physical legacy-catalog source. The open handle and exact byte
/// snapshot survive runtime attestation so publication cannot silently switch
/// to a different junction, symlink, file identity, or file contents.
pub(crate) struct LegacyCatalogSource {
    requested_path: PathBuf,
    canonical_path: PathBuf,
    identity: LegacySourceIdentity,
    file: File,
    bytes: Vec<u8>,
    source_sha256: String,
}

impl LegacyCatalogSource {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let file = open_legacy_source_file(path)?;
        let canonical_path = legacy_source_final_path(&file, path)?;
        let identity = legacy_source_identity(&file)?;
        let bytes = read_legacy_source_bytes(&file, &canonical_path)?;
        let source = Self {
            requested_path: path.to_path_buf(),
            canonical_path,
            identity,
            file,
            source_sha256: hex_sha256(&bytes),
            bytes,
        };
        source.attest_unchanged()?;
        Ok(source)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    pub(crate) fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    fn attest_unchanged(&self) -> Result<()> {
        let retained_path = legacy_source_final_path(&self.file, &self.requested_path)?;
        let retained_identity = legacy_source_identity(&self.file)?;
        let retained_bytes = read_legacy_source_bytes(&self.file, &retained_path)?;
        if !same_source_path(&retained_path, &self.canonical_path)
            || retained_identity != self.identity
            || retained_bytes != self.bytes
        {
            return Err(error(
                "CALYX_LENS_CATALOG_IMPORT_SOURCE_CHANGED",
                format!(
                    "retained legacy source changed during attestation: before path={} identity={:?} bytes={} sha256={}; after path={} identity={retained_identity:?} bytes={} sha256={}",
                    self.canonical_path.display(),
                    self.identity,
                    self.bytes.len(),
                    self.source_sha256,
                    retained_path.display(),
                    retained_bytes.len(),
                    hex_sha256(&retained_bytes)
                ),
            ));
        }

        let reopened = open_legacy_source_file(&self.requested_path)?;
        let reopened_path = legacy_source_final_path(&reopened, &self.requested_path)?;
        let reopened_identity = legacy_source_identity(&reopened)?;
        if !same_source_path(&reopened_path, &self.canonical_path)
            || reopened_identity != self.identity
        {
            return Err(error(
                "CALYX_LENS_CATALOG_IMPORT_SOURCE_CHANGED",
                format!(
                    "legacy source alias {} changed physical identity during attestation: expected path={} identity={:?}; observed path={} identity={reopened_identity:?}",
                    self.requested_path.display(),
                    self.canonical_path.display(),
                    self.identity,
                    reopened_path.display()
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct CatalogMutationLockRecord<'a> {
    pid: u32,
    started_unix_ms: u128,
    operation: &'a str,
    catalog_db: &'a Path,
}

impl CatalogMutationGuard {
    pub(crate) fn acquire(db_root: &Path, operation: &str) -> Result<Self> {
        let db_key = catalog_key(db_root)?;
        let process_guard = process_mutex(&db_key)?.lock().map_err(|_| {
            error(
                "CALYX_LENS_CATALOG_LOCK_FAILED",
                "catalog process mutex poisoned",
            )
        })?;
        let lock_path = mutation_lock_path(&db_key)?;
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|reason| {
                error(
                    "CALYX_LENS_CATALOG_LOCK_FAILED",
                    format!(
                        "open catalog mutation lock {} failed: {reason}",
                        lock_path.display()
                    ),
                )
            })?;
        file.lock().map_err(|reason| {
            error(
                "CALYX_LENS_CATALOG_LOCK_FAILED",
                format!(
                    "acquire catalog mutation lock {} failed: {reason}",
                    lock_path.display()
                ),
            )
        })?;
        let record = CatalogMutationLockRecord {
            pid: std::process::id(),
            started_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|reason| {
                    error(
                        "CALYX_LENS_CATALOG_LOCK_FAILED",
                        format!("system clock precedes Unix epoch: {reason}"),
                    )
                })?
                .as_millis(),
            operation,
            catalog_db: &db_key,
        };
        let bytes = serde_json::to_vec(&record).map_err(|reason| {
            error(
                "CALYX_LENS_CATALOG_LOCK_FAILED",
                format!("serialize catalog mutation lock owner failed: {reason}"),
            )
        })?;
        file.set_len(0).map_err(|reason| {
            error(
                "CALYX_LENS_CATALOG_LOCK_FAILED",
                format!(
                    "truncate catalog mutation lock {} failed: {reason}",
                    lock_path.display()
                ),
            )
        })?;
        file.seek(SeekFrom::Start(0)).map_err(|reason| {
            error(
                "CALYX_LENS_CATALOG_LOCK_FAILED",
                format!(
                    "seek catalog mutation lock {} failed: {reason}",
                    lock_path.display()
                ),
            )
        })?;
        file.write_all(&bytes).map_err(|reason| {
            error(
                "CALYX_LENS_CATALOG_LOCK_FAILED",
                format!(
                    "write catalog mutation lock {} failed: {reason}",
                    lock_path.display()
                ),
            )
        })?;
        file.sync_all().map_err(|reason| {
            error(
                "CALYX_LENS_CATALOG_LOCK_FAILED",
                format!(
                    "sync catalog mutation lock {} failed: {reason}",
                    lock_path.display()
                ),
            )
        })?;
        Ok(Self {
            db_key,
            _process_guard: process_guard,
            _file: file,
        })
    }

    fn require_catalog(&self, db_root: &Path) -> Result<()> {
        let observed = catalog_key(db_root)?;
        if observed == self.db_key {
            return Ok(());
        }
        Err(error(
            "CALYX_LENS_CATALOG_LOCK_MISMATCH",
            format!(
                "catalog mutation lock owns {}, but write targets {}",
                self.db_key.display(),
                observed.display()
            ),
        ))
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct LensCatalogDbReadback {
    pub(crate) catalog_db: PathBuf,
    pub(crate) schema: &'static str,
    pub(crate) row_count: usize,
    pub(crate) lens_count: usize,
    pub(crate) manifest_digest_count: usize,
    pub(crate) import_receipt_count: usize,
    pub(crate) import_source_sha256: Option<String>,
    pub(crate) import_receipt_sha256: Option<String>,
    pub(crate) total_value_bytes: u64,
    pub(crate) index_value_sha256: String,
    pub(crate) catalog_sha256: String,
    pub(crate) readback_matches: bool,
}

pub(crate) enum V1MigrationRead {
    Live(V1MigrationSnapshot),
    Retired {
        catalog: LensCatalog,
        readback: LensCatalogDbReadback,
    },
}

pub(crate) struct V1MigrationSnapshot {
    pub(crate) catalog: LensCatalog,
    pub(crate) source_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LensCatalogIndexV1 {
    format: String,
    lens_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LensCatalogIndexV2 {
    format: String,
    lens_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct V1RetirementRecord {
    format: String,
    v1_lens_ids: Vec<String>,
    v1_source_sha256: String,
    v2_catalog_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct LegacyImportReceipt {
    format: String,
    canonical_source: PathBuf,
    source_sha256: String,
    imported_catalog_sha256: String,
}

/// Exact historical v1 bincode row. Do not add, remove, reorder, or change a
/// field: v1 is decoded only into this type and then explicitly migrated.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct LensCatalogEntryV1 {
    lens_id: String,
    name: String,
    modality: String,
    runtime: String,
    dim: u32,
    retrieval_only: bool,
    excluded_from_dedup: bool,
    weights_sha256: String,
    manifest: PathBuf,
    cost: LensCost,
    placement: Placement,
}

impl From<LensCatalogEntryV1> for LensCatalogEntry {
    fn from(entry: LensCatalogEntryV1) -> Self {
        Self {
            lens_id: entry.lens_id,
            name: entry.name,
            modality: entry.modality,
            runtime: entry.runtime,
            dim: entry.dim,
            retrieval_only: entry.retrieval_only,
            excluded_from_dedup: entry.excluded_from_dedup,
            weights_sha256: entry.weights_sha256,
            manifest: entry.manifest,
            manifest_sha256: String::new(),
            execution_attestation: None,
            cost: entry.cost,
            placement: entry.placement,
        }
    }
}

pub(crate) fn read(db_root: &Path) -> Result<LensCatalog> {
    Ok(read_with_readback(db_root)?.0)
}

pub(crate) fn read_with_readback(db_root: &Path) -> Result<(LensCatalog, LensCatalogDbReadback)> {
    let router = CfRouter::open(db_root, CF_MEMTABLE_CAP)?;
    let v1 = router.get(ColumnFamily::Graph, V1_INDEX_KEY)?;
    let v2 = router.get(ColumnFamily::Graph, V2_INDEX_KEY)?;
    if let Some(v2) = v2 {
        let (catalog, readback) = read_v2_only(db_root, &router)?;
        if let Some(v1) = v1 {
            if readback.import_receipt_count != 0 {
                return Err(schema_ambiguity(
                    "v2 catalog carries both retired-v1 and legacy-JSON import provenance",
                ));
            }
            let retirement = decode_retirement(&v1)?.ok_or_else(|| {
                schema_ambiguity(
                    "live v1 and v2 catalog indexes coexist; no reader can infer which catalog is authoritative",
                )
            })?;
            if retirement.v2_catalog_sha256 != readback.catalog_sha256 {
                return Err(schema_ambiguity(format!(
                    "v1 retirement record binds v2 catalog {}, but current v2 rows hash to {} (index_bytes={})",
                    retirement.v2_catalog_sha256,
                    readback.catalog_sha256,
                    v2.len()
                )));
            }
            let source_sha256 = reconstructed_v1_source_sha256(&router, &retirement.v1_lens_ids)?;
            if retirement.v1_source_sha256 != source_sha256 {
                return Err(schema_ambiguity(format!(
                    "v1 retirement record binds source {}, but current historical v1 rows hash to {}",
                    retirement.v1_source_sha256, source_sha256
                )));
            }
        }
        return Ok((catalog, readback));
    }
    if let Some(v1) = v1 {
        if decode_retirement(&v1)?.is_some() {
            return Err(error(
                "CALYX_LENS_CATALOG_DB_INVALID",
                "v1 catalog index is retired but no v2 index exists",
            ));
        }
        if v1.starts_with(V1_INDEX_MAGIC) {
            return Err(error(
                "CALYX_LENS_CATALOG_SCHEMA_MIGRATION_REQUIRED",
                format!(
                    "catalog {} contains schema v1 rows without immutable manifest digests",
                    db_root.display()
                ),
            ));
        }
        return Err(error(
            "CALYX_LENS_CATALOG_DB_INVALID",
            "catalog contains an unrecognized v1 index value",
        ));
    }
    if legacy_catalog_path(db_root).exists() {
        return Err(error(
            "CALYX_LENS_CATALOG_DB_MISSING",
            "legacy lens registry.json exists but the authoritative Calyx/Aster catalog row is missing",
        ));
    }
    let catalog = LensCatalog { lenses: Vec::new() };
    let readback = empty_readback(db_root, &catalog)?;
    Ok((catalog, readback))
}

pub(crate) fn has_v1_catalog_state(db_root: &Path) -> Result<bool> {
    if !db_root.is_dir() {
        return Ok(false);
    }
    let router = CfRouter::open(db_root, CF_MEMTABLE_CAP)?;
    Ok(router.get(ColumnFamily::Graph, V1_INDEX_KEY)?.is_some())
}

/// Decode v1 only through its exact historical row type. This function never
/// mutates either schema. Explicit migration may use it to recover a crash
/// that left a live v1 index beside an untrusted v2 candidate; the writer will
/// retire v1 only when that candidate exactly matches fresh re-attestation.
pub(crate) fn read_v1_for_migration(db_root: &Path) -> Result<V1MigrationRead> {
    let router = CfRouter::open(db_root, CF_MEMTABLE_CAP)?;
    let index_value = router
        .get(ColumnFamily::Graph, V1_INDEX_KEY)?
        .ok_or_else(|| {
            error(
                "CALYX_LENS_CATALOG_DB_MISSING",
                "explicit v1 migration source has no v1 catalog index",
            )
        })?;
    if let Some(retirement) = decode_retirement(&index_value)? {
        let (catalog, readback) = read_v2_only(db_root, &router)?;
        if readback.import_receipt_count != 0 {
            return Err(schema_ambiguity(
                "retired-v1 migration source also carries legacy-JSON import provenance",
            ));
        }
        if retirement.v2_catalog_sha256 != readback.catalog_sha256 {
            return Err(schema_ambiguity(format!(
                "retired v1 source binds v2 catalog {}, but current v2 rows hash to {}",
                retirement.v2_catalog_sha256, readback.catalog_sha256
            )));
        }
        let source_sha256 = reconstructed_v1_source_sha256(&router, &retirement.v1_lens_ids)?;
        if source_sha256 != retirement.v1_source_sha256 {
            return Err(schema_ambiguity(format!(
                "retired v1 source rows hash to {}, but retirement binds {}",
                source_sha256, retirement.v1_source_sha256
            )));
        }
        return Ok(V1MigrationRead::Retired { catalog, readback });
    }
    Ok(V1MigrationRead::Live(live_v1_snapshot(
        &router,
        &index_value,
    )?))
}

pub(crate) fn write(
    db_root: &Path,
    catalog: &LensCatalog,
    expected_catalog_sha256: &str,
    guard: &CatalogMutationGuard,
) -> Result<LensCatalogDbReadback> {
    guard.require_catalog(db_root)?;
    let catalog = canonical_catalog(catalog)?;
    let mut router = CfRouter::open(db_root, CF_MEMTABLE_CAP)?;
    let v1 = router.get(ColumnFamily::Graph, V1_INDEX_KEY)?;
    let retirement = match v1.as_deref() {
        Some(v1) => {
            let retirement = decode_retirement(v1)?;
            if retirement.is_none() {
                return Err(error(
                    "CALYX_LENS_CATALOG_SCHEMA_MIGRATION_REQUIRED",
                    "refusing to write v2 while a live v1 catalog index exists",
                ));
            }
            retirement
        }
        None => None,
    };
    let current = if router.get(ColumnFamily::Graph, V2_INDEX_KEY)?.is_some() {
        let (current, readback) = read_v2_only(db_root, &router)?;
        if retirement.is_some() && readback.import_receipt_count != 0 {
            return Err(schema_ambiguity(
                "catalog carries both retired-v1 and legacy-JSON import provenance before mutation",
            ));
        }
        current
    } else if retirement.is_some() {
        return Err(error(
            "CALYX_LENS_CATALOG_DB_INVALID",
            "v1 catalog index is retired but no v2 index exists",
        ));
    } else {
        LensCatalog { lenses: Vec::new() }
    };
    let current_sha256 = catalog_sha256(&current)?;
    if let Some(retirement) = retirement.as_ref() {
        if retirement.v2_catalog_sha256 != current_sha256 {
            return Err(schema_ambiguity(format!(
                "v1 retirement record binds v2 catalog {}, but current rows hash to {}",
                retirement.v2_catalog_sha256, current_sha256
            )));
        }
        let source_sha256 = reconstructed_v1_source_sha256(&router, &retirement.v1_lens_ids)?;
        if source_sha256 != retirement.v1_source_sha256 {
            return Err(schema_ambiguity(format!(
                "v1 retirement record binds source {}, but historical rows hash to {}",
                retirement.v1_source_sha256, source_sha256
            )));
        }
    }
    if current_sha256 != expected_catalog_sha256 {
        return Err(error(
            "CALYX_LENS_CATALOG_CONCURRENT_MUTATION",
            format!(
                "catalog {} changed before mutation (expected_sha256={} current_sha256={})",
                db_root.display(),
                expected_catalog_sha256,
                current_sha256
            ),
        ));
    }
    write_v2_rows(&mut router, &catalog, retirement, None)?;
    drop(router);
    verify_written_catalog(db_root, &catalog)
}

/// Explicit migration writer. An in-place v1 source remains authoritative
/// until every v2 row has been flushed and independently read back. Only then
/// is its index overwritten with a retirement marker; historical v1 entry
/// rows and the older physical index SST remain untouched.
pub(crate) fn write_migration(
    db_root: &Path,
    catalog: &LensCatalog,
    source: &Path,
    expected_v1_source_sha256: Option<&str>,
    expected_legacy_source: Option<&LegacyCatalogSource>,
    guard: &CatalogMutationGuard,
) -> Result<LensCatalogDbReadback> {
    guard.require_catalog(db_root)?;
    let catalog = canonical_catalog(catalog)?;
    let legacy_receipt = expected_legacy_source
        .map(|source| {
            source.attest_unchanged()?;
            legacy_import_receipt(source.canonical_path(), source.source_sha256(), &catalog)
        })
        .transpose()?;
    let mut router = CfRouter::open(db_root, CF_MEMTABLE_CAP)?;
    let v1 = router.get(ColumnFamily::Graph, V1_INDEX_KEY)?;
    let v2 = router.get(ColumnFamily::Graph, V2_INDEX_KEY)?;
    let live_v1 = match v1.as_deref() {
        Some(value) => decode_retirement(value)?.is_none(),
        None => false,
    };
    if !live_v1 {
        if expected_v1_source_sha256.is_some() {
            return Err(error(
                "CALYX_LENS_CATALOG_CONCURRENT_MUTATION",
                "v1 migration source was live during attestation but is no longer live at publication",
            ));
        }
        if let Some(source) = expected_legacy_source {
            source.attest_unchanged()?;
        }
        if let Some(v2) = v2 {
            let index_bytes = v2.len();
            let (candidate, _) = read_v2_only(db_root, &router)?;
            if catalog_sha256(&candidate)? != catalog_sha256(&catalog)? {
                return Err(schema_ambiguity(format!(
                    "migration destination already contains a different v2 catalog (index_bytes={})",
                    index_bytes
                )));
            }
            if legacy_receipt.is_some() && v1.is_some() {
                return Err(schema_ambiguity(
                    "legacy JSON import cannot claim a catalog that already carries retired-v1 provenance",
                ));
            }
            if let Some(expected_receipt) = legacy_receipt.as_ref() {
                match router.get(ColumnFamily::Graph, V2_IMPORT_RECEIPT_KEY)? {
                    Some(bytes) => {
                        let persisted = decode_import_receipt(&bytes)?;
                        if &persisted != expected_receipt {
                            return Err(error(
                                "CALYX_LENS_CATALOG_IMPORT_PROVENANCE_MISMATCH",
                                format!(
                                    "catalog {} was imported from source={} sha256={}, not source={} sha256={}",
                                    db_root.display(),
                                    persisted.canonical_source.display(),
                                    persisted.source_sha256,
                                    expected_receipt.canonical_source.display(),
                                    expected_receipt.source_sha256
                                ),
                            ));
                        }
                    }
                    None => {
                        if let Some(source) = expected_legacy_source {
                            source.attest_unchanged()?;
                        }
                        router.put(
                            ColumnFamily::Graph,
                            V2_IMPORT_RECEIPT_KEY,
                            &encode(expected_receipt, V2_IMPORT_RECEIPT_MAGIC)?,
                        )?;
                        router.flush_cf(ColumnFamily::Graph)?;
                    }
                }
            }
            drop(router);
            let (current, readback) = read_with_readback(db_root)?;
            if catalog_sha256(&current)? != catalog_sha256(&catalog)? {
                return Err(schema_ambiguity(format!(
                    "migration destination already contains a different v2 catalog (index_bytes={})",
                    index_bytes
                )));
            }
            return Ok(readback);
        }
        if v1.is_some() {
            return Err(error(
                "CALYX_LENS_CATALOG_DB_INVALID",
                "catalog has a retired or unrecognized v1 state without a readable v2 catalog",
            ));
        }
        if let Some(source) = expected_legacy_source {
            source.attest_unchanged()?;
        }
        write_v2_rows(&mut router, &catalog, None, legacy_receipt.as_ref())?;
        drop(router);
        return verify_written_catalog(db_root, &catalog);
    }
    if !same_existing_path(db_root, source)? {
        return Err(error(
            "CALYX_LENS_CATALOG_SCHEMA_MIGRATION_REQUIRED",
            format!(
                "destination {} has a live v1 catalog, but explicit migration source is {}",
                db_root.display(),
                source.display()
            ),
        ));
    }
    if expected_legacy_source.is_some() {
        return Err(error(
            "CALYX_LENS_CATALOG_SCHEMA_MIGRATION_REQUIRED",
            "in-place v1 migration received a legacy-file source proof",
        ));
    }
    if router
        .get(ColumnFamily::Graph, V2_IMPORT_RECEIPT_KEY)?
        .is_some()
    {
        return Err(schema_ambiguity(
            "live-v1 migration destination already carries legacy-JSON import provenance",
        ));
    }
    let expected_v1_source_sha256 = expected_v1_source_sha256.ok_or_else(|| {
        error(
            "CALYX_LENS_CATALOG_SCHEMA_MIGRATION_REQUIRED",
            "in-place v1 migration omitted the exact index-plus-row source digest",
        )
    })?;
    let original_v1_index = v1.ok_or_else(|| {
        error(
            "CALYX_LENS_CATALOG_DB_MISSING",
            "live v1 catalog disappeared before migration write",
        )
    })?;
    let current_v1 = live_v1_snapshot(&router, &original_v1_index)?;
    if current_v1.source_sha256 != expected_v1_source_sha256 {
        return Err(schema_ambiguity(format!(
            "v1 source changed after runtime attestation (expected_source_sha256={} current_source_sha256={})",
            expected_v1_source_sha256, current_v1.source_sha256
        )));
    }
    if legacy_projection(&current_v1.catalog) != legacy_projection(&catalog) {
        return Err(schema_ambiguity(
            "v1 catalog rows changed after runtime attestation and before v2 migration write",
        ));
    }

    if v2.is_none() {
        write_v2_rows(&mut router, &catalog, None, None)?;
    } else {
        let (candidate, _) = read_v2_only(db_root, &router)?;
        if catalog_sha256(&candidate)? != catalog_sha256(&catalog)? {
            return Err(schema_ambiguity(
                "existing v2 migration candidate differs from the freshly re-attested v1 source",
            ));
        }
    }

    // Controlled readback intentionally ignores the still-live v1 index. The
    // normal reader continues to fail closed on this transient coexistence.
    let (readback_catalog, _) = read_v2_only(db_root, &router)?;
    let expected_catalog_sha256 = catalog_sha256(&catalog)?;
    if catalog_sha256(&readback_catalog)? != expected_catalog_sha256 {
        return Err(error(
            "CALYX_LENS_CATALOG_DB_MISMATCH",
            "v2 migration/recovery candidate does not match the freshly re-attested v1 source catalog",
        ));
    }
    let final_v1_index = router
        .get(ColumnFamily::Graph, V1_INDEX_KEY)?
        .ok_or_else(|| schema_ambiguity("v1 index disappeared during v2 migration readback"))?;
    let final_v1 = live_v1_snapshot(&router, &final_v1_index)?;
    if final_v1.source_sha256 != expected_v1_source_sha256
        || legacy_projection(&final_v1.catalog) != legacy_projection(&catalog)
    {
        return Err(schema_ambiguity(format!(
            "v1 index or referenced rows changed during v2 migration readback (expected_source_sha256={} current_source_sha256={})",
            expected_v1_source_sha256, final_v1.source_sha256
        )));
    }

    let retirement = V1RetirementRecord {
        format: "calyx-lens-catalog-v1-retired-by-v2".to_string(),
        v1_lens_ids: current_v1
            .catalog
            .lenses
            .iter()
            .map(|entry| entry.lens_id.clone())
            .collect(),
        v1_source_sha256: expected_v1_source_sha256.to_string(),
        v2_catalog_sha256: expected_catalog_sha256,
    };
    router.put(
        ColumnFamily::Graph,
        V1_INDEX_KEY,
        &encode(&retirement, V1_RETIREMENT_MAGIC)?,
    )?;
    router.flush_cf(ColumnFamily::Graph)?;
    drop(router);
    verify_written_catalog(db_root, &catalog)
}

pub(crate) fn catalog_sha256(catalog: &LensCatalog) -> Result<String> {
    let catalog = canonical_catalog(catalog)?;
    let payload = bincode::serde::encode_to_vec(&catalog, config::standard()).map_err(|err| {
        error(
            "CALYX_LENS_CATALOG_DB_ENCODE",
            format!("encode lens catalog fingerprint failed: {err}"),
        )
    })?;
    Ok(hex_sha256(&payload))
}

pub(crate) fn legacy_catalog_path(db_root: &Path) -> PathBuf {
    db_root
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(LEGACY_CATALOG_FILE)
}

pub(crate) fn same_existing_catalog_path(left: &Path, right: &Path) -> Result<bool> {
    same_existing_path(left, right)
}

fn read_v2_only(db_root: &Path, router: &CfRouter) -> Result<(LensCatalog, LensCatalogDbReadback)> {
    let index_value = router
        .get(ColumnFamily::Graph, V2_INDEX_KEY)?
        .ok_or_else(|| {
            error(
                "CALYX_LENS_CATALOG_DB_MISSING",
                "v2 catalog index is missing",
            )
        })?;
    let index: LensCatalogIndexV2 = decode(&index_value, V2_INDEX_MAGIC)?;
    if index.format != "calyx-lens-catalog-v2" {
        return Err(error(
            "CALYX_LENS_CATALOG_DB_INVALID",
            "v2 lens catalog index decoded to an unsupported format",
        ));
    }
    validate_index_order("v2", &index.lens_ids)?;
    let mut seen = BTreeSet::new();
    let mut lenses = Vec::with_capacity(index.lens_ids.len());
    let mut total_value_bytes = index_value.len() as u64;
    for lens_id in &index.lens_ids {
        if !seen.insert(lens_id.clone()) {
            return Err(error(
                "CALYX_LENS_CATALOG_DB_INVALID",
                format!("v2 lens catalog index contains duplicate lens_id {lens_id}"),
            ));
        }
        let value = router
            .get(ColumnFamily::Graph, &entry_key(V2_ENTRY_PREFIX, lens_id)?)?
            .ok_or_else(|| {
                error(
                    "CALYX_LENS_CATALOG_DB_MISSING",
                    format!("v2 lens catalog entry row missing for lens_id {lens_id}"),
                )
            })?;
        let entry: LensCatalogEntry = decode(&value, V2_ENTRY_MAGIC)?;
        if entry.lens_id != *lens_id {
            return Err(error(
                "CALYX_LENS_CATALOG_DB_INVALID",
                format!(
                    "v2 lens catalog entry row key {lens_id} decoded as {}",
                    entry.lens_id
                ),
            ));
        }
        validate_manifest_digest(&entry)?;
        total_value_bytes = total_value_bytes.saturating_add(value.len() as u64);
        lenses.push(entry);
    }
    lenses.sort_by(|left, right| left.lens_id.cmp(&right.lens_id));
    let catalog = canonical_catalog(&LensCatalog { lenses })?;
    let import_receipt_value = router.get(ColumnFamily::Graph, V2_IMPORT_RECEIPT_KEY)?;
    let import_receipt = import_receipt_value
        .as_deref()
        .map(decode_import_receipt)
        .transpose()?;
    if let Some(value) = import_receipt_value.as_ref() {
        total_value_bytes = total_value_bytes.saturating_add(value.len() as u64);
    }
    let import_receipt_count = if import_receipt.is_some() { 1 } else { 0 };
    let readback = LensCatalogDbReadback {
        catalog_db: db_root.to_path_buf(),
        schema: "calyx-lens-catalog-v2",
        row_count: catalog
            .lenses
            .len()
            .saturating_add(1)
            .saturating_add(import_receipt_count),
        lens_count: catalog.lenses.len(),
        manifest_digest_count: catalog.lenses.len(),
        import_receipt_count,
        import_source_sha256: import_receipt
            .as_ref()
            .map(|receipt| receipt.source_sha256.clone()),
        import_receipt_sha256: import_receipt_value.as_deref().map(hex_sha256),
        total_value_bytes,
        index_value_sha256: hex_sha256(&index_value),
        catalog_sha256: catalog_sha256(&catalog)?,
        readback_matches: true,
    };
    Ok((catalog, readback))
}

fn write_v2_rows(
    router: &mut CfRouter,
    catalog: &LensCatalog,
    mut retirement: Option<V1RetirementRecord>,
    import_receipt: Option<&LegacyImportReceipt>,
) -> Result<()> {
    let index = LensCatalogIndexV2 {
        format: "calyx-lens-catalog-v2".to_string(),
        lens_ids: catalog
            .lenses
            .iter()
            .map(|entry| entry.lens_id.clone())
            .collect(),
    };
    for entry in &catalog.lenses {
        validate_manifest_digest(entry)?;
        router.put(
            ColumnFamily::Graph,
            &entry_key(V2_ENTRY_PREFIX, &entry.lens_id)?,
            &encode(entry, V2_ENTRY_MAGIC)?,
        )?;
    }
    router.put(
        ColumnFamily::Graph,
        V2_INDEX_KEY,
        &encode(&index, V2_INDEX_MAGIC)?,
    )?;
    if let Some(retirement) = retirement.as_mut() {
        retirement.v2_catalog_sha256 = catalog_sha256(catalog)?;
        router.put(
            ColumnFamily::Graph,
            V1_INDEX_KEY,
            &encode(retirement, V1_RETIREMENT_MAGIC)?,
        )?;
    }
    if let Some(receipt) = import_receipt {
        router.put(
            ColumnFamily::Graph,
            V2_IMPORT_RECEIPT_KEY,
            &encode(receipt, V2_IMPORT_RECEIPT_MAGIC)?,
        )?;
    }
    router.flush_cf(ColumnFamily::Graph)?;
    Ok(())
}

fn verify_written_catalog(db_root: &Path, expected: &LensCatalog) -> Result<LensCatalogDbReadback> {
    let (readback_catalog, readback) = read_with_readback(db_root)?;
    if catalog_sha256(&readback_catalog)? != catalog_sha256(expected)? {
        return Err(error(
            "CALYX_LENS_CATALOG_DB_MISMATCH",
            "lens catalog v2 Calyx/Aster Graph CF readback does not match the written catalog",
        ));
    }
    Ok(readback)
}

fn canonical_catalog(catalog: &LensCatalog) -> Result<LensCatalog> {
    let mut out = catalog.clone();
    let mut ids = BTreeSet::new();
    for entry in &out.lenses {
        if entry.lens_id.trim().is_empty() {
            return Err(error(
                "CALYX_LENS_CATALOG_DB_INVALID",
                "lens catalog entry has an empty lens_id",
            ));
        }
        validate_manifest_digest(entry)?;
        if !ids.insert(entry.lens_id.clone()) {
            return Err(error(
                "CALYX_LENS_CATALOG_DB_INVALID",
                format!("lens catalog contains duplicate lens_id {}", entry.lens_id),
            ));
        }
    }
    out.lenses
        .sort_by(|left, right| left.lens_id.cmp(&right.lens_id));
    Ok(out)
}

fn legacy_projection(catalog: &LensCatalog) -> LensCatalog {
    let mut projected = catalog.clone();
    for entry in &mut projected.lenses {
        entry.manifest_sha256.clear();
        entry.execution_attestation = None;
    }
    projected
        .lenses
        .sort_by(|left, right| left.lens_id.cmp(&right.lens_id));
    projected
}

fn validate_manifest_digest(entry: &LensCatalogEntry) -> Result<()> {
    if entry.manifest_sha256.len() != 64
        || !entry
            .manifest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error(
            "CALYX_LENS_CATALOG_MANIFEST_DIGEST_MISSING",
            format!(
                "lens catalog entry {} lacks a canonical lowercase SHA-256 digest for {}",
                entry.lens_id,
                entry.manifest.display()
            ),
        ));
    }
    validate_execution_attestation(entry)?;
    Ok(())
}

fn validate_execution_attestation(entry: &LensCatalogEntry) -> Result<()> {
    let expected_runtime = match entry.runtime.as_str() {
        "candle_local" => Some("candle-local"),
        "onnx" => Some("onnx-custom"),
        "onnx_colbert" => Some("onnx-colbert"),
        "fastembed_dense" | "fastembed_sparse" | "fastembed_bgem3" | "fastembed_reranker" => {
            Some("onnx-fastembed-5.16.0-owned")
        }
        "fastembed_qwen3" => Some("fastembed-qwen3"),
        _ => None,
    };
    let Some(attestation) = entry.execution_attestation.as_ref() else {
        if expected_runtime.is_some() {
            return Err(error(
                "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_MISSING",
                format!(
                    "mandatory local catalog entry {} runtime={} has no persisted first-real-inference execution attestation",
                    entry.lens_id, entry.runtime
                ),
            ));
        }
        return Ok(());
    };
    let Some(expected_runtime) = expected_runtime else {
        return Err(error(
            "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_UNEXPECTED",
            format!(
                "catalog entry {} runtime={} carries execution evidence even though that runtime has no catalog execution-attestation contract",
                entry.lens_id, entry.runtime
            ),
        ));
    };
    if attestation.executable_lens_id != entry.lens_id
        || attestation.runtime != expected_runtime
        || attestation.executable_corpus_hash.len() != 64
        || !attestation
            .executable_corpus_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || [
            attestation.runtime.as_str(),
            attestation.provider.as_str(),
            attestation.observed_execution_device.as_str(),
            attestation.evidence_kind.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(error(
            "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
            format!(
                "catalog entry {} contains incomplete or conflicting persisted execution evidence",
                entry.lens_id
            ),
        ));
    }
    let provider = attestation.provider.to_ascii_uppercase();
    match entry.placement {
        Placement::Gpu => {
            if provider.contains("CPU") || !provider.contains("CUDA") {
                return Err(error(
                    "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
                    format!(
                        "GPU catalog entry {} persisted non-CUDA provider {}",
                        entry.lens_id, attestation.provider
                    ),
                ));
            }
            attestation
                .observed_execution_device
                .parse::<calyx_forge::PinnedCudaDeviceIdentity>()
                .map_err(|reason| {
                    error(
                        "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
                        format!(
                            "GPU catalog entry {} persisted nonphysical device {:?}: {reason}",
                            entry.lens_id, attestation.observed_execution_device
                        ),
                    )
                })?;
        }
        Placement::Cpu => {
            if provider.contains("CUDA")
                || !provider.contains("CPU")
                || attestation.observed_execution_device != "cpu"
            {
                return Err(error(
                    "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
                    format!(
                        "CPU catalog entry {} persisted provider={} device={}",
                        entry.lens_id, attestation.provider, attestation.observed_execution_device
                    ),
                ));
            }
        }
    }
    if matches!(
        entry.runtime.as_str(),
        "onnx"
            | "onnx_colbert"
            | "fastembed_dense"
            | "fastembed_sparse"
            | "fastembed_bgem3"
            | "fastembed_reranker"
    ) {
        let total = attestation.total_compute_nodes.ok_or_else(|| {
            error(
                "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
                format!("ONNX catalog entry {} omitted total nodes", entry.lens_id),
            )
        })?;
        let cpu = attestation.cpu_compute_nodes.ok_or_else(|| {
            error(
                "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
                format!("ONNX catalog entry {} omitted CPU nodes", entry.lens_id),
            )
        })?;
        let expected_cpu = if entry.placement == Placement::Cpu {
            total
        } else {
            0
        };
        if total == 0 || cpu != expected_cpu {
            return Err(error(
                "CALYX_LENS_CATALOG_EXECUTION_ATTESTATION_INVALID",
                format!(
                    "ONNX catalog entry {} placement={:?} persisted cpu_nodes={cpu}/{total}",
                    entry.lens_id, entry.placement
                ),
            ));
        }
    }
    Ok(())
}

fn live_v1_snapshot(router: &CfRouter, index_value: &[u8]) -> Result<V1MigrationSnapshot> {
    let index: LensCatalogIndexV1 = decode(index_value, V1_INDEX_MAGIC)?;
    if index.format != "calyx-lens-catalog-v1" {
        return Err(error(
            "CALYX_LENS_CATALOG_DB_INVALID",
            "v1 lens catalog index decoded to an unsupported format",
        ));
    }
    validate_index_order("v1", &index.lens_ids)?;
    let mut seen = BTreeSet::new();
    let mut lenses = Vec::with_capacity(index.lens_ids.len());
    for lens_id in &index.lens_ids {
        if !seen.insert(lens_id.clone()) {
            return Err(error(
                "CALYX_LENS_CATALOG_DB_INVALID",
                format!("v1 lens catalog index contains duplicate lens_id {lens_id}"),
            ));
        }
        let value = router
            .get(ColumnFamily::Graph, &entry_key(V1_ENTRY_PREFIX, lens_id)?)?
            .ok_or_else(|| {
                error(
                    "CALYX_LENS_CATALOG_DB_MISSING",
                    format!("v1 lens catalog entry row missing for lens_id {lens_id}"),
                )
            })?;
        let entry: LensCatalogEntryV1 = decode(&value, V1_ENTRY_MAGIC)?;
        if entry.lens_id != *lens_id {
            return Err(error(
                "CALYX_LENS_CATALOG_DB_INVALID",
                format!(
                    "v1 lens catalog entry row key {lens_id} decoded as {}",
                    entry.lens_id
                ),
            ));
        }
        lenses.push(entry.into());
    }
    lenses.sort_by(|left, right| left.lens_id.cmp(&right.lens_id));
    Ok(V1MigrationSnapshot {
        catalog: LensCatalog { lenses },
        source_sha256: v1_source_sha256(router, index_value, &index.lens_ids)?,
    })
}

fn reconstructed_v1_source_sha256(router: &CfRouter, lens_ids: &[String]) -> Result<String> {
    let index = LensCatalogIndexV1 {
        format: "calyx-lens-catalog-v1".to_string(),
        lens_ids: lens_ids.to_vec(),
    };
    let index_value = encode(&index, V1_INDEX_MAGIC)?;
    v1_source_sha256(router, &index_value, &index.lens_ids)
}

fn v1_source_sha256(router: &CfRouter, index_value: &[u8], lens_ids: &[String]) -> Result<String> {
    let mut hasher = Sha256::new();
    hash_source_part(&mut hasher, b"calyx-lens-catalog-v1-source-v1");
    hash_source_part(&mut hasher, index_value);
    for lens_id in lens_ids {
        let key = entry_key(V1_ENTRY_PREFIX, lens_id)?;
        let value = router.get(ColumnFamily::Graph, &key)?.ok_or_else(|| {
            error(
                "CALYX_LENS_CATALOG_DB_MISSING",
                format!("v1 lens catalog entry row missing for lens_id {lens_id}"),
            )
        })?;
        hash_source_part(&mut hasher, &key);
        hash_source_part(&mut hasher, &value);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn hash_source_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn validate_index_order(schema: &str, lens_ids: &[String]) -> Result<()> {
    if lens_ids
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(error(
            "CALYX_LENS_CATALOG_DB_INVALID",
            format!("{schema} catalog index lens_ids are not strictly ascending"),
        ));
    }
    Ok(())
}

fn open_legacy_source_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    options.share_mode(FILE_SHARE_READ);
    options.open(path).map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_OPEN_FAILED",
            format!(
                "open legacy catalog source {} with immutable sharing failed: {reason}",
                path.display()
            ),
        )
    })
}

fn read_legacy_source_bytes(file: &File, path: &Path) -> Result<Vec<u8>> {
    let before = file.metadata().map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_READ_FAILED",
            format!(
                "read metadata for retained legacy catalog source {} failed: {reason}",
                path.display()
            ),
        )
    })?;
    if !before.file_type().is_file() {
        return Err(error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_INVALID",
            format!(
                "legacy catalog source {} is not a regular file",
                path.display()
            ),
        ));
    }
    if before.len() > MAX_LEGACY_CATALOG_BYTES {
        return Err(error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_TOO_LARGE",
            format!(
                "legacy catalog source {} has {} bytes, exceeding the {}-byte import limit",
                path.display(),
                before.len(),
                MAX_LEGACY_CATALOG_BYTES
            ),
        ));
    }
    let byte_len = usize::try_from(before.len()).map_err(|_| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_TOO_LARGE",
            format!(
                "legacy catalog source {} length {} exceeds the process address space",
                path.display(),
                before.len()
            ),
        )
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(byte_len).map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_ALLOCATION_FAILED",
            format!(
                "reserve {byte_len} bytes for legacy catalog source {} failed: {reason}",
                path.display()
            ),
        )
    })?;
    bytes.resize(byte_len, 0);
    let mut reader = file.try_clone().map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_READ_FAILED",
            format!(
                "duplicate retained legacy catalog handle {} failed: {reason}",
                path.display()
            ),
        )
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_READ_FAILED",
            format!(
                "seek retained legacy catalog source {} failed: {reason}",
                path.display()
            ),
        )
    })?;
    reader.read_exact(&mut bytes).map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_CHANGED",
            format!(
                "legacy catalog source {} changed while reading {} expected bytes: {reason}",
                path.display(),
                before.len()
            ),
        )
    })?;
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra).map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_READ_FAILED",
            format!(
                "read terminal byte from legacy catalog source {} failed: {reason}",
                path.display()
            ),
        )
    })? != 0
    {
        return Err(error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_CHANGED",
            format!(
                "legacy catalog source {} grew while its bytes were being read",
                path.display()
            ),
        ));
    }
    let after = file.metadata().map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_READ_FAILED",
            format!(
                "re-read metadata for legacy catalog source {} failed: {reason}",
                path.display()
            ),
        )
    })?;
    if after.len() != before.len() || !after.file_type().is_file() {
        return Err(error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_CHANGED",
            format!(
                "legacy catalog source {} changed during read (before_bytes={} after_bytes={})",
                path.display(),
                before.len(),
                after.len()
            ),
        ));
    }
    Ok(bytes)
}

#[cfg(windows)]
fn legacy_source_final_path(file: &File, _requested_path: &Path) -> Result<PathBuf> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut capacity = 512_usize;
    loop {
        let mut buffer = vec![0_u16; capacity];
        // SAFETY: `file` owns a live handle and `buffer` is writable for the
        // exact capacity passed to the Win32 API.
        let written = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0)
        } as usize;
        if written == 0 {
            let reason = std::io::Error::last_os_error();
            return Err(error(
                "CALYX_LENS_CATALOG_IMPORT_SOURCE_IDENTITY_FAILED",
                format!("resolve retained legacy catalog handle path failed: {reason}"),
            ));
        }
        if written < buffer.len() {
            buffer.truncate(written);
            if buffer.is_empty() || buffer.contains(&0) {
                return Err(error(
                    "CALYX_LENS_CATALOG_IMPORT_SOURCE_IDENTITY_FAILED",
                    "retained legacy catalog handle resolved to an invalid final path",
                ));
            }
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        capacity = written.checked_add(1).ok_or_else(|| {
            error(
                "CALYX_LENS_CATALOG_IMPORT_SOURCE_IDENTITY_FAILED",
                "legacy catalog final-path length overflowed usize",
            )
        })?;
        if capacity > MAX_FINAL_PATH_CHARS {
            return Err(error(
                "CALYX_LENS_CATALOG_IMPORT_SOURCE_IDENTITY_FAILED",
                format!("legacy catalog final path requires {capacity} UTF-16 units"),
            ));
        }
    }
}

#[cfg(not(windows))]
fn legacy_source_final_path(_file: &File, requested_path: &Path) -> Result<PathBuf> {
    fs::canonicalize(requested_path).map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_IDENTITY_FAILED",
            format!(
                "canonicalize legacy catalog source {} failed: {reason}",
                requested_path.display()
            ),
        )
    })
}

#[cfg(windows)]
fn legacy_source_identity(file: &File) -> Result<LegacySourceIdentity> {
    // SAFETY: BY_HANDLE_FILE_INFORMATION is a plain output structure and the
    // handle remains owned by `file` for the duration of the call.
    let mut information = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    // SAFETY: both pointers are valid and writable/readable as required by the
    // Win32 contract.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut information) } == 0
    {
        let reason = std::io::Error::last_os_error();
        return Err(error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_IDENTITY_FAILED",
            format!("read retained legacy catalog file identity failed: {reason}"),
        ));
    }
    Ok(LegacySourceIdentity {
        namespace: u64::from(information.dwVolumeSerialNumber),
        file: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    })
}

#[cfg(unix)]
fn legacy_source_identity(file: &File) -> Result<LegacySourceIdentity> {
    let metadata = file.metadata().map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_IDENTITY_FAILED",
            format!("read retained legacy catalog file identity failed: {reason}"),
        )
    })?;
    Ok(LegacySourceIdentity {
        namespace: metadata.dev(),
        file: metadata.ino(),
    })
}

#[cfg(not(any(unix, windows)))]
fn legacy_source_identity(file: &File) -> Result<LegacySourceIdentity> {
    let metadata = file.metadata().map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_IMPORT_SOURCE_IDENTITY_FAILED",
            format!("read retained legacy catalog file identity failed: {reason}"),
        )
    })?;
    Ok(LegacySourceIdentity {
        namespace: metadata.len(),
        file: 0,
    })
}

#[cfg(windows)]
fn same_source_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(not(windows))]
fn same_source_path(left: &Path, right: &Path) -> bool {
    left == right
}

fn legacy_import_receipt(
    source: &Path,
    source_sha256: &str,
    catalog: &LensCatalog,
) -> Result<LegacyImportReceipt> {
    if !source.is_absolute() {
        return Err(error(
            "CALYX_LENS_CATALOG_IMPORT_PROVENANCE_INVALID",
            format!(
                "handle-resolved legacy import source {} is not absolute",
                source.display()
            ),
        ));
    }
    let receipt = LegacyImportReceipt {
        format: "calyx-lens-catalog-v2-legacy-import-v1".to_string(),
        canonical_source: source.to_path_buf(),
        source_sha256: source_sha256.to_string(),
        imported_catalog_sha256: catalog_sha256(catalog)?,
    };
    validate_import_receipt(&receipt)?;
    Ok(receipt)
}

fn decode_import_receipt(bytes: &[u8]) -> Result<LegacyImportReceipt> {
    let receipt: LegacyImportReceipt = decode(bytes, V2_IMPORT_RECEIPT_MAGIC)?;
    validate_import_receipt(&receipt)?;
    Ok(receipt)
}

fn validate_import_receipt(receipt: &LegacyImportReceipt) -> Result<()> {
    let valid_digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if receipt.format != "calyx-lens-catalog-v2-legacy-import-v1"
        || !receipt.canonical_source.is_absolute()
        || !valid_digest(&receipt.source_sha256)
        || !valid_digest(&receipt.imported_catalog_sha256)
    {
        return Err(error(
            "CALYX_LENS_CATALOG_IMPORT_PROVENANCE_INVALID",
            "legacy catalog import receipt is malformed",
        ));
    }
    Ok(())
}

fn decode_retirement(bytes: &[u8]) -> Result<Option<V1RetirementRecord>> {
    if !bytes.starts_with(V1_RETIREMENT_MAGIC) {
        return Ok(None);
    }
    let record: V1RetirementRecord = decode(bytes, V1_RETIREMENT_MAGIC)?;
    if record.format != "calyx-lens-catalog-v1-retired-by-v2"
        || validate_index_order("retired-v1", &record.v1_lens_ids).is_err()
        || record.v1_source_sha256.len() != 64
        || record.v2_catalog_sha256.len() != 64
        || !record
            .v1_source_sha256
            .bytes()
            .chain(record.v2_catalog_sha256.bytes())
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(error(
            "CALYX_LENS_CATALOG_DB_INVALID",
            "v1 retirement record is malformed",
        ));
    }
    Ok(Some(record))
}

fn process_mutex(path: &Path) -> Result<&'static Mutex<()>> {
    let locks = PROCESS_MUTATION_LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut locks = locks.lock().map_err(|_| {
        error(
            "CALYX_LENS_CATALOG_LOCK_FAILED",
            "catalog mutation lock registry mutex poisoned",
        )
    })?;
    if let Some(lock) = locks.get(path) {
        return Ok(lock);
    }
    let lock = Box::leak(Box::new(Mutex::new(())));
    locks.insert(path.to_path_buf(), lock);
    Ok(lock)
}

fn catalog_key(db_root: &Path) -> Result<PathBuf> {
    if db_root.exists() {
        return db_root.canonicalize().map_err(|reason| {
            error(
                "CALYX_LENS_CATALOG_LOCK_FAILED",
                format!(
                    "canonicalize existing catalog path {} failed: {reason}",
                    db_root.display()
                ),
            )
        });
    }
    let parent = db_root.parent().ok_or_else(|| {
        error(
            "CALYX_LENS_CATALOG_LOCK_FAILED",
            format!("catalog path {} has no parent", db_root.display()),
        )
    })?;
    fs::create_dir_all(parent).map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_LOCK_FAILED",
            format!(
                "create catalog parent {} failed: {reason}",
                parent.display()
            ),
        )
    })?;
    let parent = parent.canonicalize().map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_LOCK_FAILED",
            format!(
                "canonicalize catalog parent {} failed: {reason}",
                parent.display()
            ),
        )
    })?;
    let name = db_root.file_name().ok_or_else(|| {
        error(
            "CALYX_LENS_CATALOG_LOCK_FAILED",
            format!("catalog path {} has no file name", db_root.display()),
        )
    })?;
    Ok(parent.join(name))
}

fn mutation_lock_path(db_key: &Path) -> Result<PathBuf> {
    let name = db_key.file_name().ok_or_else(|| {
        error(
            "CALYX_LENS_CATALOG_LOCK_FAILED",
            format!(
                "canonical catalog path {} has no file name",
                db_key.display()
            ),
        )
    })?;
    let mut lock_name = name.to_os_string();
    lock_name.push(".mutation.lock");
    Ok(db_key.with_file_name(lock_name))
}

fn entry_key(prefix: &[u8], lens_id: &str) -> Result<Vec<u8>> {
    if lens_id.trim().is_empty() || lens_id.as_bytes().contains(&0) {
        return Err(error(
            "CALYX_LENS_CATALOG_DB_INVALID_KEY",
            "lens catalog entry key requires a non-empty lens_id without NUL bytes",
        ));
    }
    let mut key = Vec::with_capacity(prefix.len() + lens_id.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(lens_id.as_bytes());
    Ok(key)
}

fn encode<T: Serialize>(record: &T, magic: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = magic.to_vec();
    let payload = bincode::serde::encode_to_vec(record, config::standard()).map_err(|err| {
        error(
            "CALYX_LENS_CATALOG_DB_ENCODE",
            format!("encode lens catalog row failed: {err}"),
        )
    })?;
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8], magic: &[u8]) -> Result<T> {
    let payload = bytes.strip_prefix(magic).ok_or_else(|| {
        error(
            "CALYX_LENS_CATALOG_DB_INVALID",
            "lens catalog row has invalid schema magic",
        )
    })?;
    let (record, consumed): (T, usize) =
        bincode::serde::decode_from_slice(payload, config::standard()).map_err(|err| {
            error(
                "CALYX_LENS_CATALOG_DB_DECODE",
                format!("decode lens catalog row failed: {err}"),
            )
        })?;
    if consumed != payload.len() {
        return Err(error(
            "CALYX_LENS_CATALOG_DB_INVALID",
            "lens catalog row has trailing bytes",
        ));
    }
    Ok(record)
}

fn same_existing_path(left: &Path, right: &Path) -> Result<bool> {
    let left = fs::canonicalize(left).map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_SCHEMA_MIGRATION_REQUIRED",
            format!(
                "canonicalize migration destination {}: {reason}",
                left.display()
            ),
        )
    })?;
    let right = fs::canonicalize(right).map_err(|reason| {
        error(
            "CALYX_LENS_CATALOG_SCHEMA_MIGRATION_REQUIRED",
            format!(
                "canonicalize migration source {}: {reason}",
                right.display()
            ),
        )
    })?;
    Ok(left == right)
}

fn empty_readback(db_root: &Path, catalog: &LensCatalog) -> Result<LensCatalogDbReadback> {
    Ok(LensCatalogDbReadback {
        catalog_db: db_root.to_path_buf(),
        schema: "calyx-lens-catalog-v2",
        row_count: 0,
        lens_count: 0,
        manifest_digest_count: 0,
        import_receipt_count: 0,
        import_source_sha256: None,
        import_receipt_sha256: None,
        total_value_bytes: 0,
        index_value_sha256: String::new(),
        catalog_sha256: catalog_sha256(catalog)?,
        readback_matches: true,
    })
}

fn schema_ambiguity(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_CATALOG_SCHEMA_AMBIGUOUS",
        message: message.into(),
        remediation: "preserve both schema indexes and all physical rows, inspect their hashes, and complete one explicit attested migration before any catalog mutation",
    }
}

fn error(code: &'static str, message: impl Into<String>) -> CalyxError {
    CalyxError {
        code,
        message: message.into(),
        remediation: "write and read schema-v2 lens rows through Calyx/Aster Graph CF; use calyx lens migrate-catalog for an explicit fully attested v1 or JSON import",
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
