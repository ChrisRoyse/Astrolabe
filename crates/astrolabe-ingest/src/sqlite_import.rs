use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use astrolabe_domain::{
    ASTRO_ANCHOR_CONFIDENCE_RANGE, ASTRO_PANEL_VERSION_ZERO, ASTRO_SOURCE_DRIFT,
    ASTRO_SYMBOL_IDENTITY_EMPTY, ASTRO_SYMBOL_NON_FINITE, AnchorEvidence, DomainError, EdgeKind,
    SeriesId, SymbolIdentity, SymbolLabel, SymbolRecord,
};
use astrolabe_panel::{PanelDriver, PanelInput, SlotRuntime, default_panel_slots};
use calyx_aster::cf::{ColumnFamily, base_key, ledger_key, ledger_range, prefix_range, slot_key};
use calyx_aster::vault::{AsterVault, encode};
use calyx_core::{
    AbsentReason, Clock, Constellation, CxFlags, CxId, InputRef, LedgerRef, Modality, Seq, SlotId,
    SlotVector,
};
use calyx_ledger::{ActorId, EntryKind, SubjectId, decode};
use rusqlite::{Connection, OpenFlags, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{IngestError, IngestResult};

/// Dangling edge refusal/skip code from blueprint `04_DATA_MODEL.md` section 7.
pub const ASTRO_EDGE_DANGLING: &str = "ASTRO_EDGE_DANGLING";
/// Refusal code for malformed or incompatible CBM SQLite input.
pub const ASTRO_INGEST_SQLITE_INVALID: &str = "ASTRO_INGEST_SQLITE_INVALID";
/// Refusal code for post-write readback mismatches.
pub const ASTRO_INGEST_READBACK_MISMATCH: &str = "ASTRO_INGEST_READBACK_MISMATCH";

const SQLITE_REMEDIATION: &str = "Open a valid Codebase Memory MCP SQLite dump with nodes, edges, and optional node_vectors tables.";
const READBACK_REMEDIATION: &str = "Stop ingest, inspect the Aster vault, and rerun astrolabe verify --deep before trusting the batch.";
const NODE_MAP_PREFIX: &[u8] = b"astrolabe:node-map:v1:";
const STRUCTURAL_NODE_PREFIX: &[u8] = b"astrolabe:structural-node:v1:";
const PROJECT_ROW_PREFIX: &[u8] = b"astrolabe:cbm-project:v1:";
const FILE_HASH_ROW_PREFIX: &[u8] = b"astrolabe:file-hash:v1:";
const PROJECT_SUMMARY_ROW_PREFIX: &[u8] = b"astrolabe:project-summary:v1:";
const TOKEN_VECTOR_ROW_PREFIX: &[u8] = b"astrolabe:token-vector:v1:";
const CBM_EDGE_ROW_PREFIX: &[u8] = b"astrolabe:cbm-edge:v1:";
pub(crate) const EDGE_ROW_PREFIX: &[u8] = b"astrolabe:edge:v1:";
const SCHEMA_NODE_MAP: &str = "astrolabe-node-map-v1";
const SCHEMA_STRUCTURAL_NODE: &str = "astrolabe-structural-node-v1";
const SCHEMA_PROJECT_ROW: &str = "astrolabe-cbm-project-v1";
const SCHEMA_FILE_HASH_ROW: &str = "astrolabe-file-hash-v1";
const SCHEMA_PROJECT_SUMMARY_ROW: &str = "astrolabe-project-summary-v1";
const SCHEMA_TOKEN_VECTOR_ROW: &str = "astrolabe-token-vector-v1";
const SCHEMA_CBM_EDGE_ROW: &str = "astrolabe-cbm-edge-v1";
pub(crate) const SCHEMA_EDGE_ROW: &str = "astrolabe-edge-v1";
const SCHEMA_LEDGER: &str = "astrolabe-sqlite-ingest-ledger-v1";
const ASTROLABE_INGEST_ACTOR: &str = "astrolabe-ingest";

/// Import configuration for a CBM SQLite dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteImportOptions {
    /// CBM project key to import from the dump.
    pub project: String,
    /// Commit or run identifier recorded in metadata and the ingest ledger.
    pub commit: String,
    /// Non-zero Astrolabe panel version used for symbol identity and measurement.
    pub panel_version: u32,
    /// Worker count used for deterministic pre-write preparation.
    pub workers: usize,
    /// Slots with source inputs available to the panel runtime.
    pub available_slots: BTreeSet<SlotId>,
}

impl SqliteImportOptions {
    /// Builds default options with all v1 slots available and one worker.
    pub fn new(project: impl Into<String>, commit: impl Into<String>, panel_version: u32) -> Self {
        Self {
            project: project.into(),
            commit: commit.into(),
            panel_version,
            workers: 1,
            available_slots: default_panel_slots()
                .iter()
                .map(|slot| slot.slot_id())
                .collect(),
        }
    }

    /// Sets the deterministic preparation worker count.
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.max(1);
        self
    }

    /// Restricts the panel runtime to a caller-supplied slot availability set.
    pub fn with_available_slots<I>(mut self, slots: I) -> Self
    where
        I: IntoIterator<Item = SlotId>,
    {
        self.available_slots = slots.into_iter().collect();
        self
    }
}

/// Exact skipped-edge accounting for an import batch.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EdgeSkipCounters {
    /// Edges whose source or target node id was absent from the SQLite node table.
    pub dangling: usize,
}

/// Readback verification summary for a SQLite import batch.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqliteImportReadback {
    /// Base CF rows decoded and compared against prepared constellation fields.
    pub base_rows_verified: usize,
    /// Slot CF rows decoded and compared against prepared panel vectors.
    pub slot_rows_verified: usize,
    /// Graph CF rows decoded or byte-compared after mapping/structural writes.
    pub graph_rows_verified: usize,
    /// Typed edge Graph CF rows decoded and field-compared.
    pub edge_rows_verified: usize,
    /// Expected Base CF rows for the imported non-structural symbols.
    pub expected_base_rows: usize,
    /// Expected slot sidecar rows for the imported non-structural symbols.
    pub expected_slot_rows: usize,
    /// Expected graph mapping plus structural metadata rows.
    pub expected_graph_rows: usize,
    /// Expected typed edge rows.
    pub expected_edge_rows: usize,
}

/// Summary of a CBM SQLite-to-Aster import batch.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqliteImportReport {
    /// SHA-256 fingerprint of the SQLite input bytes.
    pub sqlite_fingerprint_sha256: [u8; 32],
    /// Number of `nodes` rows read for the selected project.
    pub sqlite_nodes: usize,
    /// Number of `node_vectors` rows read for the selected project.
    pub sqlite_node_vectors: usize,
    /// Number of `edges` rows read for the selected project.
    pub sqlite_edges: usize,
    /// Non-structural symbols measured into constellations.
    pub constellation_inputs: usize,
    /// Structural-only nodes written as graph metadata rows, with no panel measurement.
    pub structural_only: usize,
    /// Imported `CxId`s that had no Base CF row before this run.
    pub new_cx_ids: usize,
    /// Imported `CxId`s already present in Base CF before this run.
    pub reused_cx_ids: usize,
    /// Graph CF rows whose bytes changed in this run.
    pub graph_rows_written: usize,
    /// Typed edge Graph CF rows whose bytes changed in this run.
    pub edge_rows_written: usize,
    /// Latest vault sequence after the run ledger append.
    pub seq: Seq,
    /// Ledger sequence of the real `EntryKind::Ingest` run record.
    pub ledger_seq: u64,
    /// Ledger rows visible before this import began.
    pub ledger_rows_before: usize,
    /// Ledger rows visible after the run record was appended.
    pub ledger_rows_after: usize,
    /// Exact skipped-edge counters.
    pub edge_skips: EdgeSkipCounters,
    /// Post-write CF readback verification counts.
    pub readback: SqliteImportReadback,
    /// Imported constellation ids in deterministic node-id order.
    pub cx_ids: Vec<CxId>,
}

/// Deep verification counts for SQLite-imported graph mapping rows.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqliteImportDeepVerifyCounts {
    /// Graph CF node-to-constellation map rows verified against Base CF metadata.
    pub node_map_rows: usize,
    /// Structural metadata-only Graph CF rows decoded.
    pub structural_rows: usize,
    /// Base CF constellation rows decoded through node-map references.
    pub constellation_rows: usize,
    /// Typed edge rows decoded and provenance-checked.
    pub edge_rows: usize,
}

#[derive(Debug, Clone)]
struct RawNodeRow {
    id: i64,
    project: String,
    label: String,
    name: String,
    qualified_name: String,
    file_path: String,
    start_line: i64,
    end_line: i64,
    properties: Value,
    properties_json: String,
    node_vector: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct RawEdgeRow {
    id: i64,
    project: String,
    source_id: i64,
    target_id: i64,
    edge_type: String,
    properties: Value,
    properties_json: String,
    local_name_gen: String,
}

#[derive(Debug, Clone)]
struct RawProjectRow {
    name: String,
    indexed_at: String,
    root_path: String,
}

#[derive(Debug, Clone)]
struct RawFileHashRow {
    project: String,
    rel_path: String,
    sha256: String,
    mtime_ns: i64,
    size: i64,
}

#[derive(Debug, Clone)]
struct RawProjectSummaryRow {
    project: String,
    summary: String,
    source_hash: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone)]
struct RawTokenVectorRow {
    id: i64,
    project: String,
    token: String,
    vector: Vec<u8>,
    idf: i64,
}

#[derive(Debug, Clone)]
struct RawMetadataRows {
    projects: Vec<RawProjectRow>,
    file_hashes: Vec<RawFileHashRow>,
    project_summaries: Vec<RawProjectSummaryRow>,
    token_vectors: Vec<RawTokenVectorRow>,
}

#[derive(Debug, Clone)]
struct RawCbmImportInput {
    metadata: RawMetadataRows,
    nodes: Vec<RawNodeRow>,
    edges: Vec<RawEdgeRow>,
    sqlite_fingerprint: [u8; 32],
    ledger_rows_before: usize,
}

#[derive(Debug, Clone)]
struct ExtractedNode {
    id: i64,
    label: SymbolLabel,
    name: String,
    symbol: SymbolRecord,
    node_vector_sha256: Option<[u8; 32]>,
    node_vector_bytes: Option<usize>,
    properties_json: String,
    node_vector: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct PreparedConstellation {
    node_id: i64,
    name: String,
    properties_json: String,
    node_vector: Option<Vec<u8>>,
    symbol: SymbolRecord,
    identity: SymbolIdentity,
    constellation: Constellation,
}

#[derive(Debug, Clone)]
struct PreparedBatch {
    constellations: Vec<PreparedConstellation>,
    graph_rows: Vec<(Vec<u8>, Vec<u8>)>,
    edge_rows: Vec<PreparedEdgeRow>,
    structural_only: usize,
    sqlite_edges: usize,
    edge_skips: EdgeSkipCounters,
}

#[derive(Debug, Clone)]
struct PreparedEdgeRow {
    key: Vec<u8>,
    row: EdgeGraphRow,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct NodeMapRow {
    schema: String,
    project: String,
    node_id: i64,
    qualified_name: String,
    label: String,
    cx_id: CxId,
    series_id: SeriesId,
    file_path: String,
    commit: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    start_line: Option<i64>,
    #[serde(default)]
    end_line: Option<i64>,
    #[serde(default)]
    properties_json: Option<String>,
    #[serde(default)]
    node_vector: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct StructuralNodeRow {
    schema: String,
    project: String,
    node_id: i64,
    qualified_name: String,
    label: String,
    name: String,
    file_path: String,
    commit: String,
    #[serde(default)]
    start_line: Option<i64>,
    #[serde(default)]
    end_line: Option<i64>,
    #[serde(default)]
    properties_json: Option<String>,
    #[serde(default)]
    node_vector: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct EdgeGraphRow {
    pub(crate) schema: String,
    pub(crate) project: String,
    pub(crate) sqlite_edge_id: i64,
    pub(crate) source_node_id: i64,
    pub(crate) target_node_id: i64,
    pub(crate) src: CxId,
    pub(crate) dst: CxId,
    pub(crate) edge_type: String,
    pub(crate) etype: u16,
    pub(crate) local_name_gen: String,
    pub(crate) weight: f32,
    pub(crate) props: Value,
    #[serde(default)]
    pub(crate) properties_json: Option<String>,
    pub(crate) provenance: LedgerRef,
    pub(crate) commit: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CbmProjectRow {
    pub schema: String,
    pub project: String,
    pub indexed_at: String,
    pub root_path: String,
    pub commit: String,
    pub sqlite_fingerprint_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CbmFileHashRow {
    pub schema: String,
    pub project: String,
    pub rel_path: String,
    pub sha256: String,
    pub mtime_ns: i64,
    pub size: i64,
    pub commit: String,
    pub sqlite_fingerprint_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CbmProjectSummaryRow {
    pub schema: String,
    pub project: String,
    pub summary: String,
    pub source_hash: String,
    pub created_at: String,
    pub updated_at: String,
    pub commit: String,
    pub sqlite_fingerprint_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CbmTokenVectorRow {
    pub schema: String,
    pub id: i64,
    pub project: String,
    pub token: String,
    pub vector: Vec<u8>,
    pub idf: i64,
    pub commit: String,
    pub sqlite_fingerprint_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CbmRawEdgeRow {
    pub schema: String,
    pub sqlite_edge_id: i64,
    pub project: String,
    pub source_node_id: i64,
    pub target_node_id: i64,
    pub edge_type: String,
    pub properties_json: String,
    pub local_name_gen: String,
    pub commit: String,
    pub sqlite_fingerprint_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmGraphNode {
    pub source_node_id: i64,
    pub project: String,
    pub label: String,
    pub name: String,
    pub qualified_name: String,
    pub file_path: String,
    pub start_line: i64,
    pub end_line: i64,
    pub properties_json: String,
    pub node_vector: Option<Vec<u8>>,
    pub cx_id: Option<CxId>,
    pub structural: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CbmGraphEdge {
    pub sqlite_edge_id: i64,
    pub project: String,
    pub source_node_id: i64,
    pub target_node_id: i64,
    pub src: Option<CxId>,
    pub dst: Option<CxId>,
    pub edge_type: String,
    pub local_name_gen: String,
    pub weight: f32,
    pub properties_json: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CbmGraphSnapshot {
    pub project: String,
    pub panel_version: Option<u32>,
    pub projects: Vec<CbmProjectRow>,
    pub nodes: Vec<CbmGraphNode>,
    pub edges: Vec<CbmGraphEdge>,
    pub file_hashes: Vec<CbmFileHashRow>,
    pub project_summaries: Vec<CbmProjectSummaryRow>,
    pub token_vectors: Vec<CbmTokenVectorRow>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct IngestLedgerPayload {
    schema: String,
    sqlite_fingerprint_sha256: String,
    project_hash_sha256: String,
    commit_hash_sha256: String,
    sqlite_nodes: u64,
    sqlite_node_vectors: u64,
    sqlite_edges: u64,
    constellation_inputs: u64,
    structural_only: u64,
    new_cx_ids: u64,
    reused_cx_ids: u64,
    graph_rows_written: u64,
    edge_inputs: u64,
    edge_rows_written: u64,
    edge_dangling_skipped: u64,
    expected_base_rows: u64,
    expected_slot_rows: u64,
    expected_graph_rows: u64,
    expected_edge_rows: u64,
    first_cx_id: Option<String>,
    last_cx_id: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct IngestLedgerStats {
    sqlite_node_vectors: usize,
    new_cx_ids: usize,
    reused_cx_ids: usize,
    graph_rows_written: usize,
    edge_rows_written: usize,
}

/// Imports a Codebase Memory MCP SQLite dump into an Aster vault.
pub fn import_sqlite_to_vault<C, R>(
    sqlite_path: impl AsRef<Path>,
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
) -> IngestResult<SqliteImportReport>
where
    C: Clock,
    R: SlotRuntime + Sync,
{
    validate_options(options)?;

    let sqlite_bytes = fs::read(sqlite_path.as_ref()).map_err(|error| {
        invalid_sqlite(format!(
            "read SQLite input {}: {error}",
            sqlite_path.as_ref().display()
        ))
    })?;
    let sqlite_fingerprint = sha256_digest(&sqlite_bytes);
    let ledger_rows_before = ledger_row_count(vault)?;

    let connection = Connection::open_with_flags(
        sqlite_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| invalid_sqlite(format!("open SQLite input: {error}")))?;
    let raw_metadata = read_metadata_rows(&connection, options, sqlite_fingerprint)?;
    let raw_nodes = read_nodes(&connection, &options.project)?;
    let raw_edges = read_edges(&connection, &options.project)?;
    import_raw_cbm_rows_to_vault(
        vault,
        runtime,
        options,
        RawCbmImportInput {
            metadata: raw_metadata,
            nodes: raw_nodes,
            edges: raw_edges,
            sqlite_fingerprint,
            ledger_rows_before,
        },
    )
}

fn import_raw_cbm_rows_to_vault<C, R>(
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    input: RawCbmImportInput,
) -> IngestResult<SqliteImportReport>
where
    C: Clock,
    R: SlotRuntime + Sync,
{
    let sqlite_node_vectors = input
        .nodes
        .iter()
        .filter(|node| node.node_vector.is_some())
        .count();
    let sqlite_nodes = input.nodes.len();
    let extracted = extract_nodes(input.nodes)?;
    let prepared = prepare_batch(
        vault,
        runtime,
        options,
        &extracted,
        input.edges,
        input.metadata,
        input.sqlite_fingerprint,
    )?;

    let before_snapshot = vault.latest_seq();
    let mut new_cx_ids = 0;
    let mut reused_cx_ids = 0;
    for prepared_cx in &prepared.constellations {
        if vault
            .read_cf_at(
                before_snapshot,
                ColumnFamily::Base,
                &base_key(prepared_cx.identity.cx_id),
            )?
            .is_some()
        {
            reused_cx_ids += 1;
        } else {
            new_cx_ids += 1;
        }
    }

    let cx_ids = prepared
        .constellations
        .iter()
        .map(|prepared| prepared.identity.cx_id)
        .collect::<Vec<_>>();
    verify_preexisting_constellations(vault, before_snapshot, &prepared)?;
    let (planned_graph_rows_written, planned_edge_rows_written) =
        count_changed_graph_rows(vault, before_snapshot, &prepared)?;
    let payload = ingest_ledger_payload(
        input.sqlite_fingerprint,
        options,
        &prepared,
        IngestLedgerStats {
            sqlite_node_vectors,
            new_cx_ids,
            reused_cx_ids,
            graph_rows_written: planned_graph_rows_written,
            edge_rows_written: planned_edge_rows_written,
        },
    )?;
    let (ledger_ref, graph_rows_written, edge_rows_written) =
        write_import_rows(vault, &prepared, input.sqlite_fingerprint, payload)?;
    let readback = verify_import_readback(vault, &prepared)?;
    let ledger_rows_after = ledger_row_count(vault)?;

    Ok(SqliteImportReport {
        sqlite_fingerprint_sha256: input.sqlite_fingerprint,
        sqlite_nodes,
        sqlite_node_vectors,
        sqlite_edges: prepared.sqlite_edges,
        constellation_inputs: prepared.constellations.len(),
        structural_only: prepared.structural_only,
        new_cx_ids,
        reused_cx_ids,
        graph_rows_written,
        edge_rows_written,
        seq: vault.latest_seq(),
        ledger_seq: ledger_ref.seq,
        ledger_rows_before: input.ledger_rows_before,
        ledger_rows_after,
        edge_skips: prepared.edge_skips,
        readback,
        cx_ids,
    })
}

/// Imports an in-memory CBM row stream through the canonical SQLite importer.
///
/// This is the Rust-side contract for `cbm_pipeline_set_sink` callbacks: a sink
/// must provide the same rows CBM would have persisted to SQLite. The direct
/// pipeline-to-vault writer can replace the temporary materialization step while
/// retaining this parity harness.
pub fn import_cbm_graph_snapshot_to_vault<C, R>(
    snapshot: &CbmGraphSnapshot,
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
) -> IngestResult<SqliteImportReport>
where
    C: Clock,
    R: SlotRuntime + Sync,
{
    if snapshot.project != options.project {
        return Err(invalid_sqlite(format!(
            "row-sink snapshot project {:?} does not match import project {:?}",
            snapshot.project, options.project
        )));
    }
    let path = temp_row_sink_sqlite_path(&snapshot.project);
    let result = (|| {
        write_cbm_graph_snapshot_sqlite(snapshot, &path)?;
        import_sqlite_to_vault(&path, vault, runtime, options)
    })();
    cleanup_sqlite_path(&path);
    result
}

/// Imports a CBM row-sink snapshot directly into an Aster vault.
///
/// `source_fingerprint_sha256` is the provenance fingerprint that should be
/// written into the existing SQLite-import metadata schema. Parity tests pass
/// the fingerprint of the canonical SQLite artifact so the direct sink path can
/// be byte-compared against the import path without synthesizing a temporary
/// database.
pub fn import_cbm_graph_snapshot_to_vault_direct<C, R>(
    snapshot: &CbmGraphSnapshot,
    source_fingerprint_sha256: [u8; 32],
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
) -> IngestResult<SqliteImportReport>
where
    C: Clock,
    R: SlotRuntime + Sync,
{
    validate_options(options)?;
    if snapshot.project != options.project {
        return Err(invalid_sqlite(format!(
            "row-sink snapshot project {:?} does not match import project {:?}",
            snapshot.project, options.project
        )));
    }
    let raw_metadata = snapshot_metadata_rows(snapshot, options, source_fingerprint_sha256)?;
    let raw_nodes = snapshot_node_rows(snapshot, &options.project)?;
    let raw_edges = snapshot_edge_rows(snapshot, &options.project)?;
    let ledger_rows_before = ledger_row_count(vault)?;
    import_raw_cbm_rows_to_vault(
        vault,
        runtime,
        options,
        RawCbmImportInput {
            metadata: raw_metadata,
            nodes: raw_nodes,
            edges: raw_edges,
            sqlite_fingerprint: source_fingerprint_sha256,
            ledger_rows_before,
        },
    )
}

fn write_cbm_graph_snapshot_sqlite(snapshot: &CbmGraphSnapshot, path: &Path) -> IngestResult<()> {
    cleanup_sqlite_path(path);
    let connection = Connection::open(path)
        .map_err(|error| invalid_sqlite(format!("create row-sink SQLite: {error}")))?;
    connection
        .execute_batch(
            "CREATE TABLE projects (
               name TEXT PRIMARY KEY,
               indexed_at TEXT NOT NULL,
               root_path TEXT NOT NULL
             );
             CREATE TABLE file_hashes (
               project TEXT NOT NULL,
               rel_path TEXT NOT NULL,
               sha256 TEXT NOT NULL,
               mtime_ns INTEGER NOT NULL DEFAULT 0,
               size INTEGER NOT NULL DEFAULT 0,
               PRIMARY KEY(project, rel_path)
             );
             CREATE TABLE nodes (
               id INTEGER PRIMARY KEY,
               project TEXT NOT NULL,
               label TEXT NOT NULL,
               name TEXT NOT NULL,
               qualified_name TEXT NOT NULL,
               file_path TEXT DEFAULT '',
               start_line INTEGER DEFAULT 0,
               end_line INTEGER DEFAULT 0,
               properties TEXT DEFAULT '{}',
               UNIQUE(project, qualified_name)
             );
             CREATE TABLE edges (
               id INTEGER PRIMARY KEY,
               project TEXT NOT NULL,
               source_id INTEGER NOT NULL,
               target_id INTEGER NOT NULL,
               type TEXT NOT NULL,
               properties TEXT DEFAULT '{}',
               url_path_gen TEXT GENERATED ALWAYS AS (json_extract(properties,'$.url_path')),
               local_name_gen TEXT GENERATED ALWAYS AS (CASE WHEN type='IMPORTS'
                 THEN coalesce(json_extract(properties,'$.local_name'),'') ELSE '' END),
               UNIQUE(source_id, target_id, type, local_name_gen)
             );
             CREATE TABLE project_summaries (
               project TEXT PRIMARY KEY,
               summary TEXT NOT NULL,
               source_hash TEXT NOT NULL,
               created_at TEXT NOT NULL,
               updated_at TEXT NOT NULL
             );
             CREATE TABLE node_vectors (
               node_id INTEGER PRIMARY KEY,
               project TEXT NOT NULL,
               vector BLOB NOT NULL
             );
             CREATE TABLE token_vectors (
               id INTEGER PRIMARY KEY,
               project TEXT NOT NULL,
               token TEXT NOT NULL,
               vector BLOB NOT NULL,
               idf INTEGER NOT NULL
             );",
        )
        .map_err(|error| invalid_sqlite(format!("create row-sink schema: {error}")))?;

    let projects = if snapshot.projects.is_empty() {
        vec![CbmProjectRow {
            schema: SCHEMA_PROJECT_ROW.to_string(),
            project: snapshot.project.clone(),
            indexed_at: String::new(),
            root_path: String::new(),
            commit: String::new(),
            sqlite_fingerprint_sha256: String::new(),
        }]
    } else {
        snapshot.projects.clone()
    };
    for project in projects {
        connection
            .execute(
                "INSERT INTO projects(name, indexed_at, root_path) VALUES (?1, ?2, ?3)",
                params![project.project, project.indexed_at, project.root_path],
            )
            .map_err(|error| invalid_sqlite(format!("insert row-sink project: {error}")))?;
    }
    for file_hash in &snapshot.file_hashes {
        connection
            .execute(
                "INSERT INTO file_hashes(project, rel_path, sha256, mtime_ns, size)
             VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    file_hash.project,
                    file_hash.rel_path,
                    file_hash.sha256,
                    file_hash.mtime_ns,
                    file_hash.size,
                ],
            )
            .map_err(|error| invalid_sqlite(format!("insert row-sink file hash: {error}")))?;
    }
    for node in &snapshot.nodes {
        ensure_json_object_text(&node.properties_json, "row-sink node properties")?;
        connection.execute(
            "INSERT INTO nodes(id, project, label, name, qualified_name, file_path, start_line, end_line, properties)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                node.source_node_id,
                node.project,
                node.label,
                node.name,
                node.qualified_name,
                node.file_path,
                node.start_line,
                node.end_line,
                node.properties_json,
            ],
        )
        .map_err(|error| invalid_sqlite(format!("insert row-sink node: {error}")))?;
        if let Some(vector) = &node.node_vector {
            connection
                .execute(
                    "INSERT INTO node_vectors(node_id, project, vector) VALUES (?1, ?2, ?3)",
                    params![node.source_node_id, node.project, vector],
                )
                .map_err(|error| invalid_sqlite(format!("insert row-sink node vector: {error}")))?;
        }
    }
    for edge in &snapshot.edges {
        ensure_json_object_text(&edge.properties_json, "row-sink edge properties")?;
        connection
            .execute(
                "INSERT INTO edges(id, project, source_id, target_id, type, properties)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    edge.sqlite_edge_id,
                    edge.project,
                    edge.source_node_id,
                    edge.target_node_id,
                    edge.edge_type,
                    edge.properties_json,
                ],
            )
            .map_err(|error| invalid_sqlite(format!("insert row-sink edge: {error}")))?;
    }
    for summary in &snapshot.project_summaries {
        connection.execute(
            "INSERT INTO project_summaries(project, summary, source_hash, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                summary.project,
                summary.summary,
                summary.source_hash,
                summary.created_at,
                summary.updated_at,
            ],
        )
        .map_err(|error| invalid_sqlite(format!("insert row-sink project summary: {error}")))?;
    }
    for token_vector in &snapshot.token_vectors {
        connection
            .execute(
                "INSERT INTO token_vectors(id, project, token, vector, idf)
             VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    token_vector.id,
                    token_vector.project,
                    token_vector.token,
                    token_vector.vector,
                    token_vector.idf,
                ],
            )
            .map_err(|error| invalid_sqlite(format!("insert row-sink token vector: {error}")))?;
    }
    drop(connection);
    Ok(())
}

fn temp_row_sink_sqlite_path(project: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let project_hash = hex_lower(&sha256_digest(project.as_bytes()));
    std::env::temp_dir().join(format!(
        "astrolabe-cbm-row-sink-{}-{}-{nanos}.db",
        std::process::id(),
        &project_hash[..16],
    ))
}

fn cleanup_sqlite_path(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(path.with_extension("db-wal"));
    let _ = fs::remove_file(path.with_extension("db-shm"));
    let _ = fs::remove_file(path.with_extension("db-journal"));
}

fn snapshot_metadata_rows(
    snapshot: &CbmGraphSnapshot,
    options: &SqliteImportOptions,
    source_fingerprint_sha256: [u8; 32],
) -> IngestResult<RawMetadataRows> {
    let mut projects = Vec::new();
    for project in &snapshot.projects {
        validate_snapshot_schema(
            &project.schema,
            SCHEMA_PROJECT_ROW,
            "row-sink project metadata",
        )?;
        if project.project == options.project {
            projects.push(RawProjectRow {
                name: project.project.clone(),
                indexed_at: project.indexed_at.clone(),
                root_path: project.root_path.clone(),
            });
        }
    }
    if projects.is_empty() {
        projects.push(RawProjectRow {
            name: options.project.clone(),
            indexed_at: hex_lower(&source_fingerprint_sha256),
            root_path: String::new(),
        });
    }

    let mut file_hashes = Vec::new();
    for file_hash in &snapshot.file_hashes {
        validate_snapshot_schema(
            &file_hash.schema,
            SCHEMA_FILE_HASH_ROW,
            "row-sink file hash metadata",
        )?;
        if file_hash.project == options.project {
            file_hashes.push(RawFileHashRow {
                project: file_hash.project.clone(),
                rel_path: file_hash.rel_path.clone(),
                sha256: file_hash.sha256.clone(),
                mtime_ns: file_hash.mtime_ns,
                size: file_hash.size,
            });
        }
    }
    file_hashes.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));

    let mut project_summaries = Vec::new();
    for summary in &snapshot.project_summaries {
        validate_snapshot_schema(
            &summary.schema,
            SCHEMA_PROJECT_SUMMARY_ROW,
            "row-sink project summary metadata",
        )?;
        if summary.project == options.project {
            project_summaries.push(RawProjectSummaryRow {
                project: summary.project.clone(),
                summary: summary.summary.clone(),
                source_hash: summary.source_hash.clone(),
                created_at: summary.created_at.clone(),
                updated_at: summary.updated_at.clone(),
            });
        }
    }
    project_summaries.sort_by(|left, right| left.project.cmp(&right.project));

    let mut token_vectors = Vec::new();
    for token_vector in &snapshot.token_vectors {
        validate_snapshot_schema(
            &token_vector.schema,
            SCHEMA_TOKEN_VECTOR_ROW,
            "row-sink token vector metadata",
        )?;
        if token_vector.project == options.project {
            token_vectors.push(RawTokenVectorRow {
                id: token_vector.id,
                project: token_vector.project.clone(),
                token: token_vector.token.clone(),
                vector: token_vector.vector.clone(),
                idf: token_vector.idf,
            });
        }
    }
    token_vectors.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.token.cmp(&right.token))
    });

    Ok(RawMetadataRows {
        projects,
        file_hashes,
        project_summaries,
        token_vectors,
    })
}

fn snapshot_node_rows(snapshot: &CbmGraphSnapshot, project: &str) -> IngestResult<Vec<RawNodeRow>> {
    let mut rows = Vec::new();
    for node in snapshot.nodes.iter().filter(|node| node.project == project) {
        let properties = serde_json::from_str::<Value>(&node.properties_json).map_err(|error| {
            invalid_sqlite(format!(
                "row-sink node {} properties JSON is invalid: {error}",
                node.source_node_id
            ))
        })?;
        if !properties.is_object() {
            return Err(invalid_sqlite(format!(
                "row-sink node {} properties JSON must be an object",
                node.source_node_id
            )));
        }
        rows.push(RawNodeRow {
            id: node.source_node_id,
            project: node.project.clone(),
            label: node.label.clone(),
            name: node.name.clone(),
            qualified_name: node.qualified_name.clone(),
            file_path: node.file_path.clone(),
            start_line: node.start_line,
            end_line: node.end_line,
            properties,
            properties_json: node.properties_json.clone(),
            node_vector: node.node_vector.clone(),
        });
    }
    rows.sort_by_key(|row| row.id);
    Ok(rows)
}

fn snapshot_edge_rows(snapshot: &CbmGraphSnapshot, project: &str) -> IngestResult<Vec<RawEdgeRow>> {
    let mut rows = Vec::new();
    for edge in snapshot.edges.iter().filter(|edge| edge.project == project) {
        let properties = serde_json::from_str::<Value>(&edge.properties_json).map_err(|error| {
            invalid_sqlite(format!(
                "row-sink edge {} properties JSON is invalid: {error}",
                edge.sqlite_edge_id
            ))
        })?;
        if !properties.is_object() {
            return Err(invalid_sqlite(format!(
                "row-sink edge {} properties JSON must be an object",
                edge.sqlite_edge_id
            )));
        }
        let expected_local_name = row_sink_local_name_gen(&edge.edge_type, &properties);
        if edge.local_name_gen != expected_local_name {
            return Err(invalid_sqlite(format!(
                "row-sink edge {} local_name_gen {:?} does not match properties-derived {:?}",
                edge.sqlite_edge_id, edge.local_name_gen, expected_local_name
            )));
        }
        rows.push(RawEdgeRow {
            id: edge.sqlite_edge_id,
            project: edge.project.clone(),
            source_id: edge.source_node_id,
            target_id: edge.target_node_id,
            edge_type: edge.edge_type.clone(),
            properties,
            properties_json: edge.properties_json.clone(),
            local_name_gen: edge.local_name_gen.clone(),
        });
    }
    rows.sort_by(|left, right| {
        left.source_id
            .cmp(&right.source_id)
            .then_with(|| left.target_id.cmp(&right.target_id))
            .then_with(|| left.edge_type.cmp(&right.edge_type))
            .then_with(|| left.local_name_gen.cmp(&right.local_name_gen))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(rows)
}

fn validate_snapshot_schema(actual: &str, expected: &str, label: &str) -> IngestResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_sqlite(format!(
            "{label} has schema {actual:?}, expected {expected:?}"
        )))
    }
}

fn row_sink_local_name_gen(edge_type: &str, properties: &Value) -> String {
    if edge_type == "IMPORTS" {
        properties
            .get("local_name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    } else {
        String::new()
    }
}

fn validate_options(options: &SqliteImportOptions) -> IngestResult<()> {
    if options.panel_version == 0 {
        return Err(DomainError::new(
            ASTRO_PANEL_VERSION_ZERO,
            "panel version 0 cannot be used for Astrolabe symbol identity",
            "Commission a non-zero panel version before deriving a CxId.",
        )
        .into());
    }
    if options.project.trim().is_empty() {
        return Err(DomainError::new(
            ASTRO_SYMBOL_IDENTITY_EMPTY,
            "SQLite import project must be non-empty",
            "Populate project, qualified_name, and label before deriving Astrolabe identity.",
        )
        .into());
    }
    Ok(())
}

fn read_nodes(connection: &Connection, project: &str) -> IngestResult<Vec<RawNodeRow>> {
    let vectors = read_node_vectors(connection, project)?;
    let mut statement = connection
        .prepare(
            "SELECT id, project, label, name, qualified_name, \
             COALESCE(file_path, ''), COALESCE(start_line, 0), \
             COALESCE(end_line, 0), COALESCE(properties, '{}') \
             FROM nodes WHERE project = ?1 ORDER BY id",
        )
        .map_err(|error| invalid_sqlite(format!("prepare nodes query: {error}")))?;
    let rows = statement
        .query_map(params![project], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(|error| invalid_sqlite(format!("query nodes: {error}")))?;

    let mut out = Vec::new();
    for row in rows {
        let (
            id,
            project,
            label,
            name,
            qualified_name,
            file_path,
            start_line,
            end_line,
            properties_json,
        ) = row.map_err(|error| invalid_sqlite(format!("read nodes row: {error}")))?;
        let properties = serde_json::from_str::<Value>(&properties_json).map_err(|error| {
            invalid_sqlite(format!("node {id} properties JSON is invalid: {error}"))
        })?;
        if !properties.is_object() {
            return Err(invalid_sqlite(format!(
                "node {id} properties JSON must be an object"
            )));
        }
        out.push(RawNodeRow {
            id,
            project,
            label,
            name,
            qualified_name,
            file_path,
            start_line,
            end_line,
            properties,
            properties_json,
            node_vector: vectors.get(&id).cloned(),
        });
    }
    Ok(out)
}

fn read_node_vectors(
    connection: &Connection,
    project: &str,
) -> IngestResult<HashMap<i64, Vec<u8>>> {
    if !table_exists(connection, "node_vectors")? {
        return Ok(HashMap::new());
    }
    let mut statement = connection
        .prepare("SELECT node_id, vector FROM node_vectors WHERE project = ?1 ORDER BY node_id")
        .map_err(|error| invalid_sqlite(format!("prepare node_vectors query: {error}")))?;
    let rows = statement
        .query_map(params![project], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|error| invalid_sqlite(format!("query node_vectors: {error}")))?;
    let mut out = HashMap::new();
    for row in rows {
        let (node_id, vector) =
            row.map_err(|error| invalid_sqlite(format!("read node_vectors row: {error}")))?;
        out.insert(node_id, vector);
    }
    Ok(out)
}

fn read_edges(connection: &Connection, project: &str) -> IngestResult<Vec<RawEdgeRow>> {
    if !table_exists(connection, "edges")? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT id, project, source_id, target_id, type, COALESCE(properties, '{}'), \
             CASE WHEN type = 'IMPORTS' AND json_valid(COALESCE(properties, '{}')) \
             THEN COALESCE(CAST(json_extract(properties, '$.local_name') AS TEXT), '') \
             ELSE '' END AS local_name_gen \
             FROM edges WHERE project = ?1 \
             ORDER BY source_id, target_id, type, local_name_gen, id",
        )
        .map_err(|error| invalid_sqlite(format!("prepare edges query: {error}")))?;
    let rows = statement
        .query_map(params![project], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|error| invalid_sqlite(format!("query edges: {error}")))?;

    let mut out = Vec::new();
    for row in rows {
        let (id, project, source_id, target_id, edge_type, properties_json, local_name_gen) =
            row.map_err(|error| invalid_sqlite(format!("read edges row: {error}")))?;
        let properties = serde_json::from_str::<Value>(&properties_json).map_err(|error| {
            invalid_sqlite(format!("edge {id} properties JSON is invalid: {error}"))
        })?;
        if !properties.is_object() {
            return Err(invalid_sqlite(format!(
                "edge {id} properties JSON must be an object"
            )));
        }
        out.push(RawEdgeRow {
            id,
            project,
            source_id,
            target_id,
            edge_type,
            properties,
            properties_json,
            local_name_gen,
        });
    }
    Ok(out)
}

fn table_exists(connection: &Connection, table: &str) -> IngestResult<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            params![table],
            |row| row.get::<_, i64>(0),
        )
        .map(|value| value != 0)
        .map_err(|error| invalid_sqlite(format!("probe table {table}: {error}")))
}

fn read_metadata_rows(
    connection: &Connection,
    options: &SqliteImportOptions,
    sqlite_fingerprint: [u8; 32],
) -> IngestResult<RawMetadataRows> {
    Ok(RawMetadataRows {
        projects: read_projects(connection, options, sqlite_fingerprint)?,
        file_hashes: read_file_hashes(connection, &options.project)?,
        project_summaries: read_project_summaries(connection, &options.project)?,
        token_vectors: read_token_vectors(connection, &options.project)?,
    })
}

fn read_projects(
    connection: &Connection,
    options: &SqliteImportOptions,
    sqlite_fingerprint: [u8; 32],
) -> IngestResult<Vec<RawProjectRow>> {
    if !table_exists(connection, "projects")? {
        return Ok(vec![RawProjectRow {
            name: options.project.clone(),
            indexed_at: hex_lower(&sqlite_fingerprint),
            root_path: String::new(),
        }]);
    }
    let mut statement = connection
        .prepare("SELECT name, indexed_at, root_path FROM projects WHERE name = ?1 ORDER BY name")
        .map_err(|error| invalid_sqlite(format!("prepare projects query: {error}")))?;
    let rows = statement
        .query_map(params![options.project], |row| {
            Ok(RawProjectRow {
                name: row.get(0)?,
                indexed_at: row.get(1)?,
                root_path: row.get(2)?,
            })
        })
        .map_err(|error| invalid_sqlite(format!("query projects: {error}")))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|error| invalid_sqlite(format!("read projects row: {error}")))?);
    }
    if out.is_empty() {
        out.push(RawProjectRow {
            name: options.project.clone(),
            indexed_at: hex_lower(&sqlite_fingerprint),
            root_path: String::new(),
        });
    }
    Ok(out)
}

fn read_file_hashes(connection: &Connection, project: &str) -> IngestResult<Vec<RawFileHashRow>> {
    if !table_exists(connection, "file_hashes")? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT project, rel_path, sha256, mtime_ns, size \
             FROM file_hashes WHERE project = ?1 ORDER BY rel_path",
        )
        .map_err(|error| invalid_sqlite(format!("prepare file_hashes query: {error}")))?;
    let rows = statement
        .query_map(params![project], |row| {
            Ok(RawFileHashRow {
                project: row.get(0)?,
                rel_path: row.get(1)?,
                sha256: row.get(2)?,
                mtime_ns: row.get(3)?,
                size: row.get(4)?,
            })
        })
        .map_err(|error| invalid_sqlite(format!("query file_hashes: {error}")))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|error| invalid_sqlite(format!("read file_hashes row: {error}")))?);
    }
    Ok(out)
}

fn read_project_summaries(
    connection: &Connection,
    project: &str,
) -> IngestResult<Vec<RawProjectSummaryRow>> {
    if !table_exists(connection, "project_summaries")? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT project, summary, source_hash, created_at, updated_at \
             FROM project_summaries WHERE project = ?1 ORDER BY project",
        )
        .map_err(|error| invalid_sqlite(format!("prepare project_summaries query: {error}")))?;
    let rows = statement
        .query_map(params![project], |row| {
            Ok(RawProjectSummaryRow {
                project: row.get(0)?,
                summary: row.get(1)?,
                source_hash: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })
        .map_err(|error| invalid_sqlite(format!("query project_summaries: {error}")))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(
            row.map_err(|error| invalid_sqlite(format!("read project_summaries row: {error}")))?,
        );
    }
    Ok(out)
}

fn read_token_vectors(
    connection: &Connection,
    project: &str,
) -> IngestResult<Vec<RawTokenVectorRow>> {
    if !table_exists(connection, "token_vectors")? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT id, project, token, vector, idf \
             FROM token_vectors WHERE project = ?1 ORDER BY id",
        )
        .map_err(|error| invalid_sqlite(format!("prepare token_vectors query: {error}")))?;
    let rows = statement
        .query_map(params![project], |row| {
            Ok(RawTokenVectorRow {
                id: row.get(0)?,
                project: row.get(1)?,
                token: row.get(2)?,
                vector: row.get(3)?,
                idf: row.get(4)?,
            })
        })
        .map_err(|error| invalid_sqlite(format!("query token_vectors: {error}")))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|error| invalid_sqlite(format!("read token_vectors row: {error}")))?);
    }
    Ok(out)
}

fn extract_nodes(raw_nodes: Vec<RawNodeRow>) -> IngestResult<Vec<ExtractedNode>> {
    let mut out = Vec::with_capacity(raw_nodes.len());
    for raw in raw_nodes {
        let label = parse_symbol_label(&raw.label)?;
        let start_line = line_u32(raw.start_line, raw.id, "start_line")?;
        let end_line = line_u32(raw.end_line, raw.id, "end_line")?;
        let language = string_property(&raw.properties, &["language", "lang"])
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| language_from_path(&raw.file_path).to_string());
        let signature = string_property(&raw.properties, &["signature", "definition"])
            .unwrap_or(raw.name.as_str())
            .to_string();
        let source_snippet = string_property(
            &raw.properties,
            &["source_snippet", "source", "body", "snippet"],
        )
        .unwrap_or(signature.as_str())
        .as_bytes()
        .to_vec();

        let mut symbol = SymbolRecord::new(
            raw.project,
            raw.qualified_name,
            label.as_str(),
            raw.file_path,
            language,
            source_snippet,
            signature,
            start_line,
            end_line,
        );
        symbol.expected_source_snippet_blake3 = source_hash(&raw.properties, raw.id)?;
        symbol.scalars = scalar_properties(&raw.properties)?;
        symbol
            .scalars
            .insert("start_line".to_string(), f64::from(start_line));
        symbol
            .scalars
            .insert("end_line".to_string(), f64::from(end_line));
        symbol.anchors = anchor_evidence(&raw.properties, raw.id)?;

        let node_vector_sha256 = raw.node_vector.as_ref().map(|bytes| sha256_digest(bytes));
        let node_vector_bytes = raw.node_vector.as_ref().map(Vec::len);
        out.push(ExtractedNode {
            id: raw.id,
            label,
            name: raw.name,
            symbol,
            node_vector_sha256,
            node_vector_bytes,
            properties_json: raw.properties_json,
            node_vector: raw.node_vector,
        });
    }
    Ok(out)
}

fn prepare_batch<C, R>(
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    nodes: &[ExtractedNode],
    edges: Vec<RawEdgeRow>,
    metadata: RawMetadataRows,
    sqlite_fingerprint: [u8; 32],
) -> IngestResult<PreparedBatch>
where
    C: Clock,
    R: SlotRuntime + Sync,
{
    let driver = PanelDriver::new(options.panel_version)?;
    let non_structural = nodes
        .iter()
        .filter(|node| !node.label.is_structural())
        .cloned()
        .collect::<Vec<_>>();
    let mut constellations =
        prepare_constellations_parallel(vault, runtime, options, &driver, non_structural)?;
    constellations.sort_by_key(|prepared| prepared.node_id);

    let mut graph_rows = metadata_graph_rows(options, metadata, sqlite_fingerprint)?;
    for prepared in &constellations {
        graph_rows.push(node_map_graph_row(options, prepared)?);
    }
    let structural_only = nodes
        .iter()
        .filter(|node| node.label.is_structural())
        .count();
    for node in nodes.iter().filter(|node| node.label.is_structural()) {
        graph_rows.push(structural_graph_row(options, node)?);
    }
    graph_rows.extend(raw_edge_graph_rows(options, &edges, sqlite_fingerprint)?);
    for (_, value) in &mut graph_rows {
        append_import_fingerprint(value, sqlite_fingerprint)?;
    }
    let sqlite_edges = edges.len();
    let (edge_rows, edge_skips) = prepare_edge_rows(options, &constellations, edges)?;

    Ok(PreparedBatch {
        constellations,
        graph_rows,
        edge_rows,
        structural_only,
        sqlite_edges,
        edge_skips,
    })
}

fn metadata_graph_rows(
    options: &SqliteImportOptions,
    metadata: RawMetadataRows,
    sqlite_fingerprint: [u8; 32],
) -> IngestResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let fingerprint = hex_lower(&sqlite_fingerprint);
    let mut rows = Vec::new();
    for project in metadata.projects {
        let row = CbmProjectRow {
            schema: SCHEMA_PROJECT_ROW.to_string(),
            project: project.name,
            indexed_at: project.indexed_at,
            root_path: project.root_path,
            commit: options.commit.clone(),
            sqlite_fingerprint_sha256: fingerprint.clone(),
        };
        rows.push((
            project_key(PROJECT_ROW_PREFIX, &row.project),
            serde_json::to_vec(&row)?,
        ));
    }
    for file_hash in metadata.file_hashes {
        let row = CbmFileHashRow {
            schema: SCHEMA_FILE_HASH_ROW.to_string(),
            project: file_hash.project,
            rel_path: file_hash.rel_path,
            sha256: file_hash.sha256,
            mtime_ns: file_hash.mtime_ns,
            size: file_hash.size,
            commit: options.commit.clone(),
            sqlite_fingerprint_sha256: fingerprint.clone(),
        };
        rows.push((
            keyed_graph_key(FILE_HASH_ROW_PREFIX, &row.project, row.rel_path.as_bytes()),
            serde_json::to_vec(&row)?,
        ));
    }
    for summary in metadata.project_summaries {
        let row = CbmProjectSummaryRow {
            schema: SCHEMA_PROJECT_SUMMARY_ROW.to_string(),
            project: summary.project,
            summary: summary.summary,
            source_hash: summary.source_hash,
            created_at: summary.created_at,
            updated_at: summary.updated_at,
            commit: options.commit.clone(),
            sqlite_fingerprint_sha256: fingerprint.clone(),
        };
        rows.push((
            project_key(PROJECT_SUMMARY_ROW_PREFIX, &row.project),
            serde_json::to_vec(&row)?,
        ));
    }
    for token_vector in metadata.token_vectors {
        let row = CbmTokenVectorRow {
            schema: SCHEMA_TOKEN_VECTOR_ROW.to_string(),
            id: token_vector.id,
            project: token_vector.project,
            token: token_vector.token,
            vector: token_vector.vector,
            idf: token_vector.idf,
            commit: options.commit.clone(),
            sqlite_fingerprint_sha256: fingerprint.clone(),
        };
        rows.push((
            graph_key(TOKEN_VECTOR_ROW_PREFIX, &row.project, row.id)?,
            serde_json::to_vec(&row)?,
        ));
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(rows)
}

fn raw_edge_graph_rows(
    options: &SqliteImportOptions,
    edges: &[RawEdgeRow],
    sqlite_fingerprint: [u8; 32],
) -> IngestResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let fingerprint = hex_lower(&sqlite_fingerprint);
    let mut rows = Vec::with_capacity(edges.len());
    for edge in edges {
        let row = CbmRawEdgeRow {
            schema: SCHEMA_CBM_EDGE_ROW.to_string(),
            sqlite_edge_id: edge.id,
            project: edge.project.clone(),
            source_node_id: edge.source_id,
            target_node_id: edge.target_id,
            edge_type: edge.edge_type.clone(),
            properties_json: edge.properties_json.clone(),
            local_name_gen: edge.local_name_gen.clone(),
            commit: options.commit.clone(),
            sqlite_fingerprint_sha256: fingerprint.clone(),
        };
        rows.push((raw_edge_key(&row)?, serde_json::to_vec(&row)?));
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(rows)
}

fn prepare_edge_rows(
    options: &SqliteImportOptions,
    constellations: &[PreparedConstellation],
    edges: Vec<RawEdgeRow>,
) -> IngestResult<(Vec<PreparedEdgeRow>, EdgeSkipCounters)> {
    let cx_by_node = constellations
        .iter()
        .map(|prepared| (prepared.node_id, prepared.identity.cx_id))
        .collect::<BTreeMap<_, _>>();
    let mut prepared = Vec::new();
    let mut skips = EdgeSkipCounters::default();

    for edge in edges {
        let Some(src) = cx_by_node.get(&edge.source_id).copied() else {
            skips.dangling += 1;
            continue;
        };
        let Some(dst) = cx_by_node.get(&edge.target_id).copied() else {
            skips.dangling += 1;
            continue;
        };
        let kind = EdgeKind::from_cbm_type(&edge.edge_type).ok_or_else(|| {
            invalid_sqlite(format!(
                "edge {} has unknown Codebase Memory MCP type {:?}",
                edge.id, edge.edge_type
            ))
        })?;
        let weight = edge_weight(kind, &edge.properties, edge.id)?;
        let row = EdgeGraphRow {
            schema: SCHEMA_EDGE_ROW.to_string(),
            project: edge.project,
            sqlite_edge_id: edge.id,
            source_node_id: edge.source_id,
            target_node_id: edge.target_id,
            src,
            dst,
            edge_type: edge.edge_type,
            etype: kind.code(),
            local_name_gen: edge.local_name_gen,
            weight,
            props: edge.properties,
            properties_json: Some(edge.properties_json),
            provenance: zero_ledger_ref(),
            commit: options.commit.clone(),
        };
        let key = edge_graph_key(row.src, row.dst, kind, &row.local_name_gen)?;
        prepared.push(PreparedEdgeRow { key, row });
    }
    prepared.sort_by(|left, right| left.key.cmp(&right.key));
    Ok((prepared, skips))
}

fn edge_weight(kind: EdgeKind, properties: &Value, edge_id: i64) -> IngestResult<f32> {
    let prior = kind.weight_prior();
    if let Some(property) = prior.dynamic_weight_property
        && let Some(weight) = numeric_property(properties, property, edge_id)?
    {
        return validate_edge_weight(weight, edge_id, property);
    }
    if matches!(kind, EdgeKind::Calls | EdgeKind::ResolvedCalls)
        && let Some(strategy) = string_property(properties, &["strategy"])
        && let Some(weight) = strategy_confidence(strategy)
    {
        return validate_edge_weight(weight, edge_id, "strategy");
    }
    validate_edge_weight(prior.fallback, edge_id, "prior")
}

fn numeric_property(properties: &Value, property: &str, edge_id: i64) -> IngestResult<Option<f32>> {
    let Some(value) = properties.get(property) else {
        return Ok(None);
    };
    match value {
        Value::Number(number) => Ok(number.as_f64().map(|value| value as f32)),
        Value::String(raw) => raw.parse::<f32>().map(Some).map_err(|error| {
            invalid_sqlite(format!(
                "edge {edge_id} property {property} could not parse {raw:?}: {error}"
            ))
        }),
        _ => Err(invalid_sqlite(format!(
            "edge {edge_id} property {property} must be numeric"
        ))),
    }
}

fn strategy_confidence(strategy: &str) -> Option<f32> {
    match strategy {
        "import_map" => Some(0.95),
        "same_module" => Some(0.90),
        "unique" | "unique_name" => Some(0.75),
        "suffix" | "suffix_match" => Some(0.55),
        "service_pattern" => Some(0.50),
        "lsp" | "lsp_resolve" | "lsp_resolved" => Some(0.60),
        _ => None,
    }
}

fn validate_edge_weight(weight: f32, edge_id: i64, source: &str) -> IngestResult<f32> {
    if weight.is_finite() && (0.0..=1.0).contains(&weight) {
        Ok(weight)
    } else {
        Err(invalid_sqlite(format!(
            "edge {edge_id} {source} weight {weight} is outside [0, 1]"
        )))
    }
}

fn prepare_constellations_parallel<C, R>(
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    driver: &PanelDriver,
    nodes: Vec<ExtractedNode>,
) -> IngestResult<Vec<PreparedConstellation>>
where
    C: Clock,
    R: SlotRuntime + Sync,
{
    if nodes.is_empty() {
        return Ok(Vec::new());
    }
    let worker_count = options.workers.min(nodes.len()).max(1);
    if worker_count == 1 {
        return nodes
            .into_iter()
            .map(|node| prepare_constellation(vault, runtime, options, driver, node))
            .collect();
    }

    let chunk_size = nodes.len().div_ceil(worker_count);
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in nodes.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            handles.push(scope.spawn(move || {
                chunk
                    .into_iter()
                    .map(|node| prepare_constellation(vault, runtime, options, driver, node))
                    .collect::<IngestResult<Vec<_>>>()
            }));
        }
        let mut out = Vec::new();
        for handle in handles {
            out.extend(
                handle
                    .join()
                    .map_err(|_| IngestError::InvalidInput("parallel import panicked".into()))??,
            );
        }
        Ok(out)
    })
}

fn prepare_constellation<C, R>(
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    driver: &PanelDriver,
    node: ExtractedNode,
) -> IngestResult<PreparedConstellation>
where
    C: Clock,
    R: SlotRuntime,
{
    let identity = node.symbol.identity(options.panel_version)?;
    let mut input = PanelInput::with_available_slots(node.label, options.available_slots.clone())
        .with_scalars(node.symbol.scalars.clone());
    input.source_bytes = node.symbol.source_snippet_bytes.clone();
    let readout = driver.measure(&input, runtime)?;
    let mut metadata = symbol_metadata(options, &node, &identity);
    metadata.insert(
        "input_hash_blake3".to_string(),
        hex_lower(blake3::hash(&identity.canonical_input_bytes).as_bytes()),
    );
    let degraded = readout.slots.values().any(slot_is_degraded);
    let constellation = Constellation {
        cx_id: identity.cx_id,
        vault_id: vault.vault_id(),
        panel_version: options.panel_version,
        created_at: 0,
        input_ref: InputRef {
            hash: *blake3::hash(&identity.canonical_input_bytes).as_bytes(),
            pointer: Some(format!("cbm-sqlite://nodes/{}", node.id)),
            redacted: false,
        },
        modality: modality_for_label(node.label),
        slots: readout.slots,
        scalars: readout.scalars,
        metadata,
        anchors: Vec::new(),
        provenance: LedgerRef {
            seq: 0,
            hash: [0; 32],
        },
        flags: CxFlags {
            ungrounded: true,
            degraded,
            novel_region: false,
            redacted_input: false,
        },
    };
    constellation.validate_schema()?;
    Ok(PreparedConstellation {
        node_id: node.id,
        name: node.name,
        properties_json: node.properties_json,
        node_vector: node.node_vector,
        symbol: node.symbol,
        identity,
        constellation,
    })
}

fn slot_is_degraded(vector: &SlotVector) -> bool {
    matches!(
        vector,
        SlotVector::Absent {
            reason: AbsentReason::LensUnavailable
                | AbsentReason::Redacted
                | AbsentReason::Deferred
                | AbsentReason::LensInactive
                | AbsentReason::Error(_)
        }
    )
}

fn symbol_metadata(
    options: &SqliteImportOptions,
    node: &ExtractedNode,
    identity: &SymbolIdentity,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "astrolabe_schema".to_string(),
        "astrolabe-sqlite-symbol-v1".to_string(),
    );
    metadata.insert("project".to_string(), node.symbol.project.clone());
    metadata.insert(
        "qualified_name".to_string(),
        node.symbol.qualified_name.clone(),
    );
    metadata.insert("label".to_string(), node.label.as_str().to_string());
    metadata.insert("name".to_string(), node.name.clone());
    metadata.insert("file_path".to_string(), node.symbol.rel_file_path.clone());
    metadata.insert("language".to_string(), node.symbol.language.clone());
    metadata.insert("source_node_id".to_string(), node.id.to_string());
    metadata.insert("series_id".to_string(), identity.series_id.to_string());
    metadata.insert("commit".to_string(), options.commit.clone());
    if let Some(hash) = node.node_vector_sha256 {
        metadata.insert("cbm_node_vector_sha256".to_string(), hex_lower(&hash));
    }
    if let Some(bytes) = node.node_vector_bytes {
        metadata.insert("cbm_node_vector_bytes".to_string(), bytes.to_string());
    }
    metadata
}

fn node_map_graph_row(
    options: &SqliteImportOptions,
    prepared: &PreparedConstellation,
) -> IngestResult<(Vec<u8>, Vec<u8>)> {
    let row = NodeMapRow {
        schema: SCHEMA_NODE_MAP.to_string(),
        project: prepared.symbol.project.clone(),
        node_id: prepared.node_id,
        qualified_name: prepared.symbol.qualified_name.clone(),
        label: prepared.symbol.label.clone(),
        cx_id: prepared.identity.cx_id,
        series_id: prepared.identity.series_id,
        file_path: prepared.symbol.rel_file_path.clone(),
        commit: options.commit.clone(),
        name: Some(prepared.name.clone()),
        start_line: Some(i64::from(prepared.symbol.start_line)),
        end_line: Some(i64::from(prepared.symbol.end_line)),
        properties_json: Some(prepared.properties_json.clone()),
        node_vector: prepared.node_vector.clone(),
    };
    Ok((
        graph_key(NODE_MAP_PREFIX, &prepared.symbol.project, prepared.node_id)?,
        serde_json::to_vec(&row)?,
    ))
}

fn structural_graph_row(
    options: &SqliteImportOptions,
    node: &ExtractedNode,
) -> IngestResult<(Vec<u8>, Vec<u8>)> {
    let row = StructuralNodeRow {
        schema: SCHEMA_STRUCTURAL_NODE.to_string(),
        project: node.symbol.project.clone(),
        node_id: node.id,
        qualified_name: node.symbol.qualified_name.clone(),
        label: node.symbol.label.clone(),
        name: node.name.clone(),
        file_path: node.symbol.rel_file_path.clone(),
        commit: options.commit.clone(),
        start_line: Some(i64::from(node.symbol.start_line)),
        end_line: Some(i64::from(node.symbol.end_line)),
        properties_json: Some(node.properties_json.clone()),
        node_vector: node.node_vector.clone(),
    };
    Ok((
        graph_key(STRUCTURAL_NODE_PREFIX, &node.symbol.project, node.id)?,
        serde_json::to_vec(&row)?,
    ))
}

fn append_import_fingerprint(
    value: &mut Vec<u8>,
    sqlite_fingerprint: [u8; 32],
) -> IngestResult<()> {
    let mut json = serde_json::from_slice::<serde_json::Map<String, Value>>(value)?;
    json.insert(
        "sqlite_fingerprint_sha256".to_string(),
        Value::String(hex_lower(&sqlite_fingerprint)),
    );
    *value = serde_json::to_vec(&json)?;
    Ok(())
}

fn verify_preexisting_constellations<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    prepared: &PreparedBatch,
) -> IngestResult<()>
where
    C: Clock,
{
    for prepared_cx in &prepared.constellations {
        if vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Base,
                &base_key(prepared_cx.identity.cx_id),
            )?
            .is_some()
        {
            verify_existing_constellation(vault, snapshot, prepared_cx)?;
        }
    }
    Ok(())
}

fn count_changed_graph_rows<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    prepared: &PreparedBatch,
) -> IngestResult<(usize, usize)>
where
    C: Clock,
{
    let mut changed = 0;
    for (key, value) in &prepared.graph_rows {
        if vault.read_cf_at(snapshot, ColumnFamily::Graph, key)? != Some(value.clone()) {
            changed += 1;
        }
    }
    let mut edge_changed = 0;
    for edge in &prepared.edge_rows {
        if !edge_row_matches_existing(vault, snapshot, edge)? {
            edge_changed += 1;
        }
    }
    Ok((changed + edge_changed, edge_changed))
}

fn edge_row_matches_existing<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    prepared: &PreparedEdgeRow,
) -> IngestResult<bool>
where
    C: Clock,
{
    let Some(bytes) = vault.read_cf_at(snapshot, ColumnFamily::Graph, &prepared.key)? else {
        return Ok(false);
    };
    let Ok(row) = serde_json::from_slice::<EdgeGraphRow>(&bytes) else {
        return Ok(false);
    };
    Ok(edge_row_matches_prepared(&row, prepared)
        && ledger_ref_matches(vault, snapshot, &row.provenance)?)
}

fn edge_row_matches_prepared(row: &EdgeGraphRow, prepared: &PreparedEdgeRow) -> bool {
    row.schema == SCHEMA_EDGE_ROW
        && row.project == prepared.row.project
        && row.sqlite_edge_id == prepared.row.sqlite_edge_id
        && row.source_node_id == prepared.row.source_node_id
        && row.target_node_id == prepared.row.target_node_id
        && row.src == prepared.row.src
        && row.dst == prepared.row.dst
        && row.edge_type == prepared.row.edge_type
        && row.etype == prepared.row.etype
        && row.local_name_gen == prepared.row.local_name_gen
        && (row.weight - prepared.row.weight).abs() <= f32::EPSILON
        && row.props == prepared.row.props
        && row.properties_json == prepared.row.properties_json
        && row.commit == prepared.row.commit
}

fn ledger_ref_matches<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    reference: &LedgerRef,
) -> IngestResult<bool>
where
    C: Clock,
{
    let Some(bytes) =
        vault.read_cf_at(snapshot, ColumnFamily::Ledger, &ledger_key(reference.seq))?
    else {
        return Ok(false);
    };
    let entry = decode(&bytes)?;
    Ok(entry.entry_hash == reference.hash)
}

fn verify_existing_constellation<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    prepared: &PreparedConstellation,
) -> IngestResult<()>
where
    C: Clock,
{
    let base_bytes = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Base,
            &base_key(prepared.identity.cx_id),
        )?
        .ok_or_else(|| readback_mismatch("preexisting Base CF row disappeared"))?;
    let decoded = encode::decode_constellation_base(&base_bytes)?;
    verify_base_fields(&decoded, prepared)?;
    for (slot, expected) in &prepared.constellation.slots {
        let slot_bytes = vault
            .read_cf_at(
                snapshot,
                ColumnFamily::slot(*slot),
                &slot_key(decoded.cx_id),
            )?
            .ok_or_else(|| readback_mismatch(format!("preexisting slot {slot} CF row missing")))?;
        let decoded_slot = encode::decode_slot_vector(&slot_bytes)?;
        if &decoded_slot != expected {
            return Err(readback_mismatch(format!(
                "preexisting slot {slot} differs for {}",
                decoded.cx_id
            )));
        }
    }
    Ok(())
}

fn write_import_rows<C>(
    vault: &AsterVault<C>,
    prepared: &PreparedBatch,
    sqlite_fingerprint: [u8; 32],
    payload: Vec<u8>,
) -> IngestResult<(LedgerRef, usize, usize)>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let mut rows = Vec::new();
    for prepared_cx in &prepared.constellations {
        if vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Base,
                &base_key(prepared_cx.identity.cx_id),
            )?
            .is_some()
        {
            continue;
        }
        let constellation = prepared_cx.constellation.clone();
        rows.push((
            ColumnFamily::Base,
            base_key(constellation.cx_id),
            encode::encode_constellation_base(&constellation)?,
        ));
        for (slot, vector) in &constellation.slots {
            rows.push((
                ColumnFamily::slot(*slot),
                slot_key(constellation.cx_id),
                encode::encode_slot_vector(vector)?,
            ));
        }
    }

    let mut graph_rows_written = 0;
    for (key, value) in &prepared.graph_rows {
        if vault.read_cf_at(snapshot, ColumnFamily::Graph, key)? != Some(value.clone()) {
            rows.push((ColumnFamily::Graph, key.clone(), value.clone()));
            graph_rows_written += 1;
        }
    }
    let mut edge_rows_written = 0;
    for prepared_edge in &prepared.edge_rows {
        if !edge_row_matches_existing(vault, snapshot, prepared_edge)? {
            rows.push((
                ColumnFamily::Graph,
                prepared_edge.key.clone(),
                serde_json::to_vec(&prepared_edge.row)?,
            ));
            graph_rows_written += 1;
            edge_rows_written += 1;
        }
    }

    if rows.is_empty() {
        let ledger_ref = vault.append_ledger_entry(
            EntryKind::Ingest,
            SubjectId::Query(sqlite_fingerprint.to_vec()),
            payload,
            ActorId::Service(ASTROLABE_INGEST_ACTOR.to_string()),
        )?;
        return Ok((ledger_ref, graph_rows_written, edge_rows_written));
    }

    let ledger_seq = ledger_row_count(vault)? as u64;
    vault.write_cf_batch_with_ledger_entry(
        rows,
        EntryKind::Ingest,
        SubjectId::Query(sqlite_fingerprint.to_vec()),
        payload,
        ActorId::Service(ASTROLABE_INGEST_ACTOR.to_string()),
    )?;
    let ledger_ref = read_ledger_ref(vault, ledger_seq)?;
    Ok((ledger_ref, graph_rows_written, edge_rows_written))
}

fn read_ledger_ref<C>(vault: &AsterVault<C>, seq: u64) -> IngestResult<LedgerRef>
where
    C: Clock,
{
    let bytes = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::Ledger, &ledger_key(seq))?
        .ok_or_else(|| readback_mismatch(format!("Ledger CF row {seq} missing after import")))?;
    let entry = decode(&bytes)?;
    Ok(LedgerRef {
        seq: entry.seq,
        hash: entry.entry_hash,
    })
}

fn verify_import_readback<C>(
    vault: &AsterVault<C>,
    prepared: &PreparedBatch,
) -> IngestResult<SqliteImportReadback>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let mut base_rows_verified = 0;
    let mut slot_rows_verified = 0;
    for prepared_cx in &prepared.constellations {
        let base_bytes = vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Base,
                &base_key(prepared_cx.identity.cx_id),
            )?
            .ok_or_else(|| readback_mismatch("Base CF row missing after import"))?;
        let decoded = encode::decode_constellation_base(&base_bytes)?;
        verify_base_fields(&decoded, prepared_cx)?;
        base_rows_verified += 1;

        for (slot, expected) in &prepared_cx.constellation.slots {
            let slot_bytes = vault
                .read_cf_at(
                    snapshot,
                    ColumnFamily::slot(*slot),
                    &slot_key(decoded.cx_id),
                )?
                .ok_or_else(|| readback_mismatch(format!("slot {slot} CF row missing")))?;
            let decoded_slot = encode::decode_slot_vector(&slot_bytes)?;
            if &decoded_slot != expected {
                return Err(readback_mismatch(format!(
                    "slot {slot} bytes decoded to a different vector for {}",
                    decoded.cx_id
                )));
            }
            slot_rows_verified += 1;
        }
    }

    let mut graph_rows_verified = 0;
    for (key, expected) in &prepared.graph_rows {
        let actual = vault
            .read_cf_at(snapshot, ColumnFamily::Graph, key)?
            .ok_or_else(|| readback_mismatch("Graph CF row missing after import"))?;
        if &actual != expected {
            return Err(readback_mismatch("Graph CF row bytes changed after import"));
        }
        graph_rows_verified += 1;
    }
    let mut edge_rows_verified = 0;
    for prepared_edge in &prepared.edge_rows {
        let actual = vault
            .read_cf_at(snapshot, ColumnFamily::Graph, &prepared_edge.key)?
            .ok_or_else(|| readback_mismatch("edge Graph CF row missing after import"))?;
        let decoded = serde_json::from_slice::<EdgeGraphRow>(&actual)
            .map_err(|error| readback_mismatch(format!("decode edge Graph CF row: {error}")))?;
        if !edge_row_matches_prepared(&decoded, prepared_edge) {
            return Err(readback_mismatch(
                "edge Graph CF row fields changed after import",
            ));
        }
        if !ledger_ref_matches(vault, snapshot, &decoded.provenance)? {
            return Err(readback_mismatch(
                "edge Graph CF row provenance does not match Ledger CF",
            ));
        }
        edge_rows_verified += 1;
    }
    graph_rows_verified += edge_rows_verified;

    let expected_base_rows = prepared.constellations.len();
    let expected_slot_rows = prepared
        .constellations
        .iter()
        .map(|prepared| prepared.constellation.slots.len())
        .sum();
    let expected_edge_rows = prepared.edge_rows.len();
    let expected_graph_rows = prepared.graph_rows.len() + expected_edge_rows;
    if base_rows_verified != expected_base_rows
        || slot_rows_verified != expected_slot_rows
        || graph_rows_verified != expected_graph_rows
        || edge_rows_verified != expected_edge_rows
    {
        return Err(readback_mismatch(
            "readback verified counts did not match committed counts",
        ));
    }

    Ok(SqliteImportReadback {
        base_rows_verified,
        slot_rows_verified,
        graph_rows_verified,
        edge_rows_verified,
        expected_base_rows,
        expected_slot_rows,
        expected_graph_rows,
        expected_edge_rows,
    })
}

fn verify_base_fields(
    decoded: &Constellation,
    prepared: &PreparedConstellation,
) -> IngestResult<()> {
    if decoded.cx_id != prepared.identity.cx_id
        || decoded.vault_id != prepared.constellation.vault_id
        || decoded.panel_version != prepared.constellation.panel_version
        || decoded.input_ref != prepared.constellation.input_ref
        || decoded.modality != prepared.constellation.modality
        || decoded.scalars != prepared.constellation.scalars
    {
        return Err(readback_mismatch(format!(
            "Base CF decoded fields differ for {}",
            prepared.identity.cx_id
        )));
    }
    for key in ["qualified_name", "label", "source_node_id", "series_id"] {
        if decoded.metadata.get(key) != prepared.constellation.metadata.get(key) {
            return Err(readback_mismatch(format!(
                "Base CF metadata {key} differs for {}",
                prepared.identity.cx_id
            )));
        }
    }
    Ok(())
}

pub(crate) fn verify_sqlite_import_deep<C>(
    vault: &AsterVault<C>,
    errors: &mut Vec<String>,
) -> IngestResult<SqliteImportDeepVerifyCounts>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let mut counts = SqliteImportDeepVerifyCounts::default();

    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(NODE_MAP_PREFIX),
    )? {
        match serde_json::from_slice::<NodeMapRow>(&value) {
            Ok(row) => {
                counts.node_map_rows += 1;
                if row.schema != SCHEMA_NODE_MAP {
                    errors.push(format!("node map {} has wrong schema", hex_lower(&key)));
                    continue;
                }
                match vault.read_cf_at(snapshot, ColumnFamily::Base, &base_key(row.cx_id))? {
                    Some(base) => match encode::decode_constellation_base(&base) {
                        Ok(decoded) => {
                            counts.constellation_rows += 1;
                            verify_node_map_matches_base(&row, &decoded, errors);
                        }
                        Err(err) => {
                            errors.push(format!("decode node map Base row {}: {err}", row.cx_id))
                        }
                    },
                    None => errors.push(format!(
                        "node map {} points to missing Base row {}",
                        hex_lower(&key),
                        row.cx_id
                    )),
                }
            }
            Err(err) => errors.push(format!("decode node map {}: {err}", hex_lower(&key))),
        }
    }

    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(STRUCTURAL_NODE_PREFIX),
    )? {
        match serde_json::from_slice::<StructuralNodeRow>(&value) {
            Ok(row) => {
                counts.structural_rows += 1;
                if row.schema != SCHEMA_STRUCTURAL_NODE {
                    errors.push(format!(
                        "structural node {} has wrong schema",
                        hex_lower(&key)
                    ));
                }
                if row.qualified_name.trim().is_empty() || row.label.trim().is_empty() {
                    errors.push(format!(
                        "structural node {} has empty identity metadata",
                        hex_lower(&key)
                    ));
                }
            }
            Err(err) => errors.push(format!("decode structural node {}: {err}", hex_lower(&key))),
        }
    }

    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(EDGE_ROW_PREFIX),
    )? {
        match serde_json::from_slice::<EdgeGraphRow>(&value) {
            Ok(row) => {
                counts.edge_rows += 1;
                verify_edge_row_deep(vault, snapshot, &key, &row, errors)?;
            }
            Err(err) => errors.push(format!("decode edge row {}: {err}", hex_lower(&key))),
        }
    }

    Ok(counts)
}

pub fn read_cbm_graph_snapshot<C>(
    vault: &AsterVault<C>,
    project: &str,
) -> IngestResult<CbmGraphSnapshot>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let mut panel_version = None;
    let mut nodes = Vec::new();

    for row in read_graph_rows::<C, NodeMapRow>(vault, snapshot, NODE_MAP_PREFIX)? {
        if row.project != project {
            continue;
        }
        if row.schema != SCHEMA_NODE_MAP {
            return Err(IngestError::InvalidInput(format!(
                "node map row {} has wrong schema {}",
                row.node_id, row.schema
            )));
        }
        let base = vault
            .read_cf_at(snapshot, ColumnFamily::Base, &base_key(row.cx_id))?
            .ok_or_else(|| {
                IngestError::InvalidInput(format!(
                    "node map row {} points to missing Base row {}",
                    row.node_id, row.cx_id
                ))
            })?;
        let decoded = encode::decode_constellation_base(&base)?;
        panel_version.get_or_insert(decoded.panel_version);
        let name = row
            .name
            .or_else(|| decoded.metadata_value("name").map(ToOwned::to_owned))
            .unwrap_or_else(|| local_name_from_qn(&row.qualified_name));
        let file_path = if row.file_path.is_empty() {
            decoded
                .metadata_value("file_path")
                .unwrap_or_default()
                .to_string()
        } else {
            row.file_path
        };
        let start_line = row
            .start_line
            .or_else(|| scalar_i64(&decoded, "start_line"))
            .unwrap_or(0);
        let end_line = row
            .end_line
            .or_else(|| scalar_i64(&decoded, "end_line"))
            .unwrap_or(0);
        let properties_json = row.properties_json.unwrap_or_else(|| "{}".to_string());
        ensure_json_object_text(&properties_json, "node properties")?;
        nodes.push(CbmGraphNode {
            source_node_id: row.node_id,
            project: row.project,
            label: row.label,
            name,
            qualified_name: row.qualified_name,
            file_path,
            start_line,
            end_line,
            properties_json,
            node_vector: row.node_vector,
            cx_id: Some(row.cx_id),
            structural: false,
        });
    }

    for row in read_graph_rows::<C, StructuralNodeRow>(vault, snapshot, STRUCTURAL_NODE_PREFIX)? {
        if row.project != project {
            continue;
        }
        if row.schema != SCHEMA_STRUCTURAL_NODE {
            return Err(IngestError::InvalidInput(format!(
                "structural node row {} has wrong schema {}",
                row.node_id, row.schema
            )));
        }
        let properties_json = row.properties_json.unwrap_or_else(|| "{}".to_string());
        ensure_json_object_text(&properties_json, "structural node properties")?;
        nodes.push(CbmGraphNode {
            source_node_id: row.node_id,
            project: row.project,
            label: row.label,
            name: row.name,
            qualified_name: row.qualified_name,
            file_path: row.file_path,
            start_line: row.start_line.unwrap_or(0),
            end_line: row.end_line.unwrap_or(0),
            properties_json,
            node_vector: row.node_vector,
            cx_id: None,
            structural: true,
        });
    }
    nodes.sort_by(|left, right| {
        left.qualified_name
            .cmp(&right.qualified_name)
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.source_node_id.cmp(&right.source_node_id))
    });

    let mut edges = Vec::new();
    for row in read_graph_rows::<C, CbmRawEdgeRow>(vault, snapshot, CBM_EDGE_ROW_PREFIX)? {
        if row.project != project {
            continue;
        }
        if row.schema != SCHEMA_CBM_EDGE_ROW {
            return Err(IngestError::InvalidInput(format!(
                "raw edge row {} has wrong schema {}",
                row.sqlite_edge_id, row.schema
            )));
        }
        ensure_json_object_text(&row.properties_json, "edge properties")?;
        edges.push(CbmGraphEdge {
            sqlite_edge_id: row.sqlite_edge_id,
            project: row.project,
            source_node_id: row.source_node_id,
            target_node_id: row.target_node_id,
            src: None,
            dst: None,
            edge_type: row.edge_type,
            local_name_gen: row.local_name_gen,
            weight: 1.0,
            properties_json: row.properties_json,
        });
    }
    if edges.is_empty() {
        for row in read_graph_rows::<C, EdgeGraphRow>(vault, snapshot, EDGE_ROW_PREFIX)? {
            if row.project != project {
                continue;
            }
            validate_edge_snapshot_row(&row)?;
            let properties_json = row.properties_json.unwrap_or_else(|| {
                serde_json::to_string(&row.props).unwrap_or_else(|_| "{}".into())
            });
            ensure_json_object_text(&properties_json, "edge properties")?;
            edges.push(CbmGraphEdge {
                sqlite_edge_id: row.sqlite_edge_id,
                project: row.project,
                source_node_id: row.source_node_id,
                target_node_id: row.target_node_id,
                src: Some(row.src),
                dst: Some(row.dst),
                edge_type: row.edge_type,
                local_name_gen: row.local_name_gen,
                weight: row.weight,
                properties_json,
            });
        }
    }
    edges.sort_by(|left, right| {
        left.sqlite_edge_id
            .cmp(&right.sqlite_edge_id)
            .then_with(|| left.source_node_id.cmp(&right.source_node_id))
            .then_with(|| left.target_node_id.cmp(&right.target_node_id))
            .then_with(|| left.edge_type.cmp(&right.edge_type))
            .then_with(|| left.local_name_gen.cmp(&right.local_name_gen))
    });

    let mut projects = filter_schema_project(
        read_graph_rows(vault, snapshot, PROJECT_ROW_PREFIX)?,
        project,
        |row: &CbmProjectRow| (&row.schema, SCHEMA_PROJECT_ROW, &row.project),
    )?;
    if projects.is_empty() {
        projects.push(CbmProjectRow {
            schema: SCHEMA_PROJECT_ROW.to_string(),
            project: project.to_string(),
            indexed_at: String::new(),
            root_path: String::new(),
            commit: String::new(),
            sqlite_fingerprint_sha256: String::new(),
        });
    }
    projects.sort_by(|left, right| left.project.cmp(&right.project));

    let mut file_hashes = filter_schema_project(
        read_graph_rows(vault, snapshot, FILE_HASH_ROW_PREFIX)?,
        project,
        |row: &CbmFileHashRow| (&row.schema, SCHEMA_FILE_HASH_ROW, &row.project),
    )?;
    file_hashes.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));

    let mut project_summaries = filter_schema_project(
        read_graph_rows(vault, snapshot, PROJECT_SUMMARY_ROW_PREFIX)?,
        project,
        |row: &CbmProjectSummaryRow| (&row.schema, SCHEMA_PROJECT_SUMMARY_ROW, &row.project),
    )?;
    project_summaries.sort_by(|left, right| left.project.cmp(&right.project));

    let mut token_vectors = filter_schema_project(
        read_graph_rows(vault, snapshot, TOKEN_VECTOR_ROW_PREFIX)?,
        project,
        |row: &CbmTokenVectorRow| (&row.schema, SCHEMA_TOKEN_VECTOR_ROW, &row.project),
    )?;
    token_vectors.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.token.cmp(&right.token))
    });

    Ok(CbmGraphSnapshot {
        project: project.to_string(),
        panel_version,
        projects,
        nodes,
        edges,
        file_hashes,
        project_summaries,
        token_vectors,
    })
}

fn read_graph_rows<C, T>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    prefix: &[u8],
) -> IngestResult<Vec<T>>
where
    C: Clock,
    T: DeserializeOwned,
{
    vault
        .scan_cf_range_at(snapshot, ColumnFamily::Graph, &prefix_range(prefix))?
        .into_iter()
        .map(|(key, value)| {
            serde_json::from_slice(&value).map_err(|error| {
                IngestError::InvalidInput(format!(
                    "decode Graph CF row {}: {error}",
                    hex_lower(&key)
                ))
            })
        })
        .collect()
}

fn filter_schema_project<T>(
    rows: Vec<T>,
    project: &str,
    metadata: impl Fn(&T) -> (&str, &'static str, &str),
) -> IngestResult<Vec<T>> {
    let mut out = Vec::new();
    for row in rows {
        let (actual_schema, expected_schema, row_project) = metadata(&row);
        if row_project != project {
            continue;
        }
        if actual_schema != expected_schema {
            return Err(IngestError::InvalidInput(format!(
                "Graph CF row for project {project} has wrong schema {actual_schema}"
            )));
        }
        out.push(row);
    }
    Ok(out)
}

fn local_name_from_qn(qualified_name: &str) -> String {
    qualified_name
        .rsplit_once('.')
        .map_or(qualified_name, |(_, name)| name)
        .to_string()
}

fn scalar_i64(decoded: &Constellation, key: &str) -> Option<i64> {
    decoded.scalars.get(key).and_then(|value| {
        if value.is_finite() && value.fract() == 0.0 {
            Some(*value as i64)
        } else {
            None
        }
    })
}

fn ensure_json_object_text(value: &str, label: &str) -> IngestResult<()> {
    let parsed = serde_json::from_str::<Value>(value)
        .map_err(|error| IngestError::InvalidInput(format!("{label} JSON is invalid: {error}")))?;
    if !parsed.is_object() {
        return Err(IngestError::InvalidInput(format!(
            "{label} JSON must be an object"
        )));
    }
    Ok(())
}

fn validate_edge_snapshot_row(row: &EdgeGraphRow) -> IngestResult<()> {
    if row.schema != SCHEMA_EDGE_ROW {
        return Err(IngestError::InvalidInput(format!(
            "edge row {} has wrong schema {}",
            row.sqlite_edge_id, row.schema
        )));
    }
    match EdgeKind::from_cbm_type(&row.edge_type) {
        Some(kind) if kind.code() == row.etype => {}
        Some(kind) => {
            return Err(IngestError::InvalidInput(format!(
                "edge row {} etype {} does not match {}",
                row.sqlite_edge_id,
                row.etype,
                kind.as_str()
            )));
        }
        None => {
            return Err(IngestError::InvalidInput(format!(
                "edge row {} has unknown type {}",
                row.sqlite_edge_id, row.edge_type
            )));
        }
    }
    if !(row.weight.is_finite() && (0.0..=1.0).contains(&row.weight)) {
        return Err(IngestError::InvalidInput(format!(
            "edge row {} weight {} is outside [0, 1]",
            row.sqlite_edge_id, row.weight
        )));
    }
    if !row.props.is_object() {
        return Err(IngestError::InvalidInput(format!(
            "edge row {} props are not an object",
            row.sqlite_edge_id
        )));
    }
    Ok(())
}

fn verify_edge_row_deep<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    key: &[u8],
    row: &EdgeGraphRow,
    errors: &mut Vec<String>,
) -> IngestResult<()>
where
    C: Clock,
{
    if row.schema != SCHEMA_EDGE_ROW {
        errors.push(format!("edge row {} has wrong schema", hex_lower(key)));
    }
    match EdgeKind::from_cbm_type(&row.edge_type) {
        Some(kind) if kind.code() == row.etype => {}
        Some(kind) => errors.push(format!(
            "edge row {} etype {} does not match {}",
            hex_lower(key),
            row.etype,
            kind.as_str()
        )),
        None => errors.push(format!(
            "edge row {} has unknown type {}",
            hex_lower(key),
            row.edge_type
        )),
    }
    if !(row.weight.is_finite() && (0.0..=1.0).contains(&row.weight)) {
        errors.push(format!(
            "edge row {} weight {} is outside [0, 1]",
            hex_lower(key),
            row.weight
        ));
    }
    if !row.props.is_object() {
        errors.push(format!(
            "edge row {} props are not an object",
            hex_lower(key)
        ));
    }
    if !ledger_ref_matches(vault, snapshot, &row.provenance)? {
        errors.push(format!(
            "edge row {} points to missing or mismatched ledger seq {}",
            hex_lower(key),
            row.provenance.seq
        ));
    }
    Ok(())
}

fn verify_node_map_matches_base(
    row: &NodeMapRow,
    decoded: &Constellation,
    errors: &mut Vec<String>,
) {
    let expected = [
        ("qualified_name", row.qualified_name.as_str()),
        ("label", row.label.as_str()),
        ("file_path", row.file_path.as_str()),
    ];
    for (key, value) in expected {
        if decoded.metadata_value(key) != Some(value) {
            errors.push(format!(
                "node map {} metadata {key} does not match Base row",
                row.cx_id
            ));
        }
    }
    let series_id = row.series_id.to_string();
    if decoded.metadata_value("series_id") != Some(series_id.as_str()) {
        errors.push(format!(
            "node map {} series_id does not match Base row",
            row.cx_id
        ));
    }
}

fn ingest_ledger_payload(
    sqlite_fingerprint: [u8; 32],
    options: &SqliteImportOptions,
    prepared: &PreparedBatch,
    stats: IngestLedgerStats,
) -> IngestResult<Vec<u8>> {
    let first = prepared
        .constellations
        .first()
        .map(|prepared| prepared.identity.cx_id.to_string());
    let last = prepared
        .constellations
        .last()
        .map(|prepared| prepared.identity.cx_id.to_string());
    let payload = IngestLedgerPayload {
        schema: SCHEMA_LEDGER.to_string(),
        sqlite_fingerprint_sha256: hex_lower(&sqlite_fingerprint),
        project_hash_sha256: hex_lower(&sha256_digest(options.project.as_bytes())),
        commit_hash_sha256: hex_lower(&sha256_digest(options.commit.as_bytes())),
        sqlite_nodes: (prepared.constellations.len() + prepared.structural_only) as u64,
        sqlite_node_vectors: stats.sqlite_node_vectors as u64,
        sqlite_edges: prepared.sqlite_edges as u64,
        constellation_inputs: prepared.constellations.len() as u64,
        structural_only: prepared.structural_only as u64,
        new_cx_ids: stats.new_cx_ids as u64,
        reused_cx_ids: stats.reused_cx_ids as u64,
        graph_rows_written: stats.graph_rows_written as u64,
        edge_inputs: prepared.edge_rows.len() as u64,
        edge_rows_written: stats.edge_rows_written as u64,
        edge_dangling_skipped: prepared.edge_skips.dangling as u64,
        expected_base_rows: prepared.constellations.len() as u64,
        expected_slot_rows: prepared
            .constellations
            .iter()
            .map(|prepared| prepared.constellation.slots.len() as u64)
            .sum(),
        expected_graph_rows: (prepared.graph_rows.len() + prepared.edge_rows.len()) as u64,
        expected_edge_rows: prepared.edge_rows.len() as u64,
        first_cx_id: first,
        last_cx_id: last,
    };
    Ok(serde_json::to_vec(&payload)?)
}

fn ledger_row_count<C>(vault: &AsterVault<C>) -> IngestResult<usize>
where
    C: Clock,
{
    Ok(vault
        .scan_cf_range_at(
            vault.latest_seq(),
            ColumnFamily::Ledger,
            &ledger_range(0, u64::MAX),
        )?
        .len())
}

fn graph_key(prefix: &[u8], project: &str, node_id: i64) -> IngestResult<Vec<u8>> {
    let node_id = u64::try_from(node_id)
        .map_err(|_| invalid_sqlite(format!("node id {node_id} cannot be encoded")))?;
    let mut key = Vec::with_capacity(prefix.len() + 32 + 8);
    key.extend_from_slice(prefix);
    key.extend_from_slice(&sha256_digest(project.as_bytes()));
    key.extend_from_slice(&node_id.to_be_bytes());
    Ok(key)
}

fn project_key(prefix: &[u8], project: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 32);
    key.extend_from_slice(prefix);
    key.extend_from_slice(&sha256_digest(project.as_bytes()));
    key
}

fn keyed_graph_key(prefix: &[u8], project: &str, discriminator: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 64);
    key.extend_from_slice(prefix);
    key.extend_from_slice(&sha256_digest(project.as_bytes()));
    key.extend_from_slice(&sha256_digest(discriminator));
    key
}

fn raw_edge_key(row: &CbmRawEdgeRow) -> IngestResult<Vec<u8>> {
    let id = u64::try_from(row.sqlite_edge_id)
        .map_err(|_| invalid_sqlite(format!("edge id {} cannot be encoded", row.sqlite_edge_id)))?;
    let mut key = Vec::with_capacity(CBM_EDGE_ROW_PREFIX.len() + 32 + 8);
    key.extend_from_slice(CBM_EDGE_ROW_PREFIX);
    key.extend_from_slice(&sha256_digest(row.project.as_bytes()));
    key.extend_from_slice(&id.to_be_bytes());
    Ok(key)
}

pub(crate) fn edge_graph_key(
    src: CxId,
    dst: CxId,
    kind: EdgeKind,
    local_name_gen: &str,
) -> IngestResult<Vec<u8>> {
    let local_len = u32::try_from(local_name_gen.len()).map_err(|_| {
        invalid_sqlite("edge local_name_gen is too long to encode into Graph CF key")
    })?;
    let mut key =
        Vec::with_capacity(EDGE_ROW_PREFIX.len() + 16 + 16 + 2 + 4 + local_name_gen.len());
    key.extend_from_slice(EDGE_ROW_PREFIX);
    key.extend_from_slice(src.as_bytes());
    key.extend_from_slice(dst.as_bytes());
    key.extend_from_slice(&kind.code().to_be_bytes());
    key.extend_from_slice(&local_len.to_be_bytes());
    key.extend_from_slice(local_name_gen.as_bytes());
    Ok(key)
}

fn zero_ledger_ref() -> LedgerRef {
    LedgerRef {
        seq: 0,
        hash: [0; 32],
    }
}

fn scalar_properties(properties: &Value) -> IngestResult<BTreeMap<String, f64>> {
    let mut scalars = BTreeMap::new();
    let object = properties
        .as_object()
        .expect("caller already validated properties object");
    for (key, value) in object {
        if let Some(number) = value.as_f64() {
            scalars.insert(format!("prop.{key}"), number);
            continue;
        }
        if let Some(name) = scalar_string_key(key) {
            let Some(raw) = value.as_str() else {
                continue;
            };
            let parsed = raw.parse::<f64>().map_err(|error| {
                invalid_sqlite(format!(
                    "scalar property {key} could not parse {raw:?}: {error}"
                ))
            })?;
            scalars.insert(name.to_string(), parsed);
        }
    }
    Ok(scalars)
}

fn scalar_string_key(key: &str) -> Option<&str> {
    key.strip_prefix("scalar_")
        .or_else(|| key.strip_prefix("scalar."))
        .or_else(|| key.strip_prefix("scalar:"))
        .filter(|name| !name.is_empty())
}

fn source_hash(properties: &Value, node_id: i64) -> IngestResult<Option<[u8; 32]>> {
    let Some(raw) = string_property(
        properties,
        &[
            "source_snippet_blake3",
            "source_hash_blake3",
            "snippet_blake3",
        ],
    ) else {
        return Ok(None);
    };
    parse_hex_32(raw)
        .map(Some)
        .map_err(|message| invalid_sqlite(format!("node {node_id} source hash invalid: {message}")))
}

fn anchor_evidence(properties: &Value, node_id: i64) -> IngestResult<Vec<AnchorEvidence>> {
    let Some(values) = properties.get("anchors").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut anchors = Vec::with_capacity(values.len());
    for value in values {
        let Some(object) = value.as_object() else {
            return Err(invalid_sqlite(format!(
                "node {node_id} anchor entry must be an object"
            )));
        };
        let source = object
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_sqlite(format!("node {node_id} anchor source missing")))?;
        let confidence = match object.get("confidence") {
            Some(value) if value.is_number() => value.as_f64().unwrap_or(f64::NAN) as f32,
            Some(value) => value
                .as_str()
                .ok_or_else(|| {
                    invalid_sqlite(format!("node {node_id} anchor confidence must be numeric"))
                })?
                .parse::<f32>()
                .map_err(|error| {
                    invalid_sqlite(format!("node {node_id} anchor confidence invalid: {error}"))
                })?,
            None => {
                return Err(invalid_sqlite(format!(
                    "node {node_id} anchor confidence missing"
                )));
            }
        };
        anchors.push(AnchorEvidence::new(source, confidence));
    }
    Ok(anchors)
}

fn string_property<'a>(properties: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| properties.get(*key).and_then(Value::as_str))
}

fn line_u32(value: i64, node_id: i64, column: &str) -> IngestResult<u32> {
    u32::try_from(value).map_err(|_| {
        invalid_sqlite(format!(
            "node {node_id} {column} must fit unsigned 32-bit lines"
        ))
    })
}

fn language_from_path(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("c") | Some("h") => "c",
        Some("cc") | Some("cpp") | Some("cxx") | Some("hpp") => "cpp",
        Some("cs") => "csharp",
        Some("go") => "go",
        Some("java") => "java",
        Some("js") | Some("jsx") => "javascript",
        Some("kt") | Some("kts") => "kotlin",
        Some("py") => "python",
        Some("rs") => "rust",
        Some("ts") | Some("tsx") => "typescript",
        _ => "unknown",
    }
}

fn parse_symbol_label(value: &str) -> IngestResult<SymbolLabel> {
    let normalized = value
        .chars()
        .filter(|ch| *ch != '_' && *ch != '-' && !ch.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    let label = match normalized.as_str() {
        "function" => SymbolLabel::Function,
        "method" => SymbolLabel::Method,
        "class" => SymbolLabel::Class,
        "struct" => SymbolLabel::Struct,
        "interface" => SymbolLabel::Interface,
        "enum" => SymbolLabel::Enum,
        "enummember" => SymbolLabel::EnumMember,
        "trait" => SymbolLabel::Trait,
        "type" => SymbolLabel::Type,
        "typealias" => SymbolLabel::TypeAlias,
        "field" => SymbolLabel::Field,
        "variable" => SymbolLabel::Variable,
        "constant" => SymbolLabel::Constant,
        "module" => SymbolLabel::Module,
        "file" => SymbolLabel::File,
        "route" => SymbolLabel::Route,
        "channel" => SymbolLabel::Channel,
        "resource" => SymbolLabel::Resource,
        "chart" => SymbolLabel::Chart,
        "package" => SymbolLabel::Package,
        "macro" => SymbolLabel::Macro,
        "section" => SymbolLabel::Section,
        "namespace" => SymbolLabel::Namespace,
        "property" => SymbolLabel::Property,
        "union" => SymbolLabel::Union,
        "protocol" => SymbolLabel::Protocol,
        "mixin" => SymbolLabel::Mixin,
        "object" => SymbolLabel::Object,
        "impl" => SymbolLabel::Impl,
        "annotation" => SymbolLabel::Annotation,
        "envvar" => SymbolLabel::EnvVar,
        "project" => SymbolLabel::Project,
        "branch" => SymbolLabel::Branch,
        "folder" => SymbolLabel::Folder,
        _ => {
            return Err(invalid_sqlite(format!(
                "unknown Codebase Memory MCP node label {value:?}"
            )));
        }
    };
    Ok(label)
}

fn modality_for_label(label: SymbolLabel) -> Modality {
    match label {
        SymbolLabel::Section => Modality::Text,
        SymbolLabel::Resource
        | SymbolLabel::Chart
        | SymbolLabel::Package
        | SymbolLabel::Route
        | SymbolLabel::Channel
        | SymbolLabel::EnvVar => Modality::Structured,
        SymbolLabel::Project | SymbolLabel::Branch | SymbolLabel::Folder => Modality::Structured,
        _ => Modality::Code,
    }
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("expected 64 hex characters, got {}", value.len()));
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_value(chunk[0]).ok_or_else(|| format!("invalid hex at {}", index * 2))?;
        let lo = hex_value(chunk[1]).ok_or_else(|| format!("invalid hex at {}", index * 2 + 1))?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn invalid_sqlite(message: impl Into<String>) -> IngestError {
    IngestError::refused(ASTRO_INGEST_SQLITE_INVALID, message, SQLITE_REMEDIATION)
}

fn readback_mismatch(message: impl Into<String>) -> IngestError {
    IngestError::refused(
        ASTRO_INGEST_READBACK_MISMATCH,
        message,
        READBACK_REMEDIATION,
    )
}

#[allow(dead_code)]
fn _validation_code_refs() -> [&'static str; 5] {
    [
        ASTRO_SYMBOL_NON_FINITE,
        ASTRO_SYMBOL_IDENTITY_EMPTY,
        ASTRO_SOURCE_DRIFT,
        ASTRO_ANCHOR_CONFIDENCE_RANGE,
        ASTRO_PANEL_VERSION_ZERO,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    use astrolabe_domain::{
        ASTRO_ANCHOR_CONFIDENCE_RANGE, ASTRO_PANEL_VERSION_ZERO, ASTRO_SOURCE_DRIFT,
        ASTRO_SYMBOL_IDENTITY_EMPTY, ASTRO_SYMBOL_NON_FINITE,
    };
    use astrolabe_panel::FixtureSlotRuntime;
    use calyx_aster::cf::{ledger_key, prefix_range};
    use calyx_core::{CxId, FixedClock, VaultId};
    use calyx_ledger::decode;

    const TEST_VAULT_ID: &str = "00000000000000000000000000";
    type NormalizedLedgerRow = (u64, [u8; 32], EntryKind, SubjectId, Vec<u8>, ActorId);

    fn vault() -> AsterVault<FixedClock> {
        AsterVault::with_clock(
            TEST_VAULT_ID.parse::<VaultId>().expect("valid vault id"),
            b"astrolabe-ingest-test".to_vec(),
            FixedClock::new(1_785_400_000),
        )
    }

    fn temp_db(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "astrolabe-ingest-{name}-{}-{nanos}.db",
            std::process::id()
        ))
    }

    fn create_db(path: &Path) -> Connection {
        let connection = Connection::open(path).expect("open test sqlite");
        connection
            .execute_batch(
                "CREATE TABLE nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project TEXT NOT NULL,
                    label TEXT NOT NULL,
                    name TEXT NOT NULL,
                    qualified_name TEXT NOT NULL,
                    file_path TEXT DEFAULT '',
                    start_line INTEGER DEFAULT 0,
                    end_line INTEGER DEFAULT 0,
                    properties TEXT DEFAULT '{}',
                    UNIQUE(project, qualified_name)
                );
                CREATE TABLE edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project TEXT NOT NULL,
                    source_id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    properties TEXT DEFAULT '{}',
                    url_path_gen TEXT GENERATED ALWAYS AS (json_extract(properties,'$.url_path')),
                    local_name_gen TEXT GENERATED ALWAYS AS (CASE WHEN type='IMPORTS'
                        THEN coalesce(json_extract(properties,'$.local_name'),'') ELSE '' END),
                    UNIQUE(source_id, target_id, type, local_name_gen)
                );
                CREATE TABLE node_vectors (
                    node_id INTEGER PRIMARY KEY,
                    project TEXT NOT NULL,
                    vector BLOB NOT NULL
                );",
            )
            .expect("create schema");
        connection
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_node(
        connection: &Connection,
        label: &str,
        name: &str,
        qn: &str,
        file: &str,
        start: i64,
        end: i64,
        properties: &str,
    ) -> i64 {
        connection
            .execute(
                "INSERT INTO nodes(project, label, name, qualified_name, file_path, start_line, end_line, properties)
                 VALUES ('demo', ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![label, name, qn, file, start, end, properties],
            )
            .expect("insert node");
        connection.last_insert_rowid()
    }

    fn insert_edge(
        connection: &Connection,
        source_id: i64,
        target_id: i64,
        edge_type: &str,
        properties: &str,
    ) -> i64 {
        connection
            .execute(
                "INSERT INTO edges(project, source_id, target_id, type, properties)
                 VALUES ('demo', ?1, ?2, ?3, ?4)",
                params![source_id, target_id, edge_type, properties],
            )
            .expect("insert edge");
        connection.last_insert_rowid()
    }

    fn options(workers: usize) -> SqliteImportOptions {
        SqliteImportOptions::new("demo", "commit-1", 7).with_workers(workers)
    }

    fn basic_fixture(path: &Path) {
        let connection = create_db(path);
        let function = insert_node(
            &connection,
            "Function",
            "add",
            "demo.math.add",
            "src/math.rs",
            10,
            12,
            r#"{"language":"rust","source_snippet":"fn add() -> i32 { 1 }","signature":"fn add() -> i32","complexity":2.0}"#,
        );
        insert_node(
            &connection,
            "Project",
            "demo",
            "demo",
            "",
            0,
            0,
            r#"{"source_snippet":"demo project"}"#,
        );
        connection
            .execute(
                "INSERT INTO node_vectors(node_id, project, vector) VALUES (?1, 'demo', ?2)",
                params![function, vec![1_u8, 2, 3, 4]],
            )
            .expect("insert vector");
        insert_edge(&connection, function, 9999, "CALLS", "{}");
    }

    fn edge_fixture(path: &Path) {
        let connection = create_db(path);
        let caller = insert_node(
            &connection,
            "Function",
            "handler",
            "demo.http.handler",
            "src/http.rs",
            5,
            20,
            r#"{"language":"rust","source_snippet":"fn handler() { helper(); }","signature":"fn handler()"}"#,
        );
        let callee = insert_node(
            &connection,
            "Function",
            "helper",
            "demo.http.helper",
            "src/http.rs",
            30,
            35,
            r#"{"language":"rust","source_snippet":"fn helper() {}","signature":"fn helper()"}"#,
        );
        let module = insert_node(
            &connection,
            "Module",
            "net",
            "demo.net",
            "src/net.rs",
            1,
            1,
            r#"{"language":"rust","source_snippet":"mod net;","signature":"mod net"}"#,
        );
        insert_edge(
            &connection,
            caller,
            callee,
            "CALLS",
            r#"{"confidence":0.85,"strategy":"import_map","line":11,"candidates":1}"#,
        );
        insert_edge(
            &connection,
            caller,
            module,
            "IMPORTS",
            r#"{"local_name":"alpha","line":2}"#,
        );
        insert_edge(
            &connection,
            caller,
            module,
            "IMPORTS",
            r#"{"local_name":"beta","line":3}"#,
        );
        insert_edge(&connection, caller, 9999, "CALLS", "{}");
    }

    fn edge_snapshot() -> CbmGraphSnapshot {
        CbmGraphSnapshot {
            project: "demo".to_string(),
            panel_version: Some(7),
            projects: Vec::new(),
            nodes: vec![
                CbmGraphNode {
                    source_node_id: 1,
                    project: "demo".to_string(),
                    label: "Function".to_string(),
                    name: "handler".to_string(),
                    qualified_name: "demo.http.handler".to_string(),
                    file_path: "src/http.rs".to_string(),
                    start_line: 5,
                    end_line: 20,
                    properties_json: r#"{"language":"rust","source_snippet":"fn handler() { helper(); }","signature":"fn handler()"}"#.to_string(),
                    node_vector: None,
                    cx_id: None,
                    structural: false,
                },
                CbmGraphNode {
                    source_node_id: 2,
                    project: "demo".to_string(),
                    label: "Function".to_string(),
                    name: "helper".to_string(),
                    qualified_name: "demo.http.helper".to_string(),
                    file_path: "src/http.rs".to_string(),
                    start_line: 30,
                    end_line: 35,
                    properties_json: r#"{"language":"rust","source_snippet":"fn helper() {}","signature":"fn helper()"}"#.to_string(),
                    node_vector: None,
                    cx_id: None,
                    structural: false,
                },
                CbmGraphNode {
                    source_node_id: 3,
                    project: "demo".to_string(),
                    label: "Module".to_string(),
                    name: "net".to_string(),
                    qualified_name: "demo.net".to_string(),
                    file_path: "src/net.rs".to_string(),
                    start_line: 1,
                    end_line: 1,
                    properties_json:
                        r#"{"language":"rust","source_snippet":"mod net;","signature":"mod net"}"#
                            .to_string(),
                    node_vector: None,
                    cx_id: None,
                    structural: false,
                },
            ],
            edges: vec![
                CbmGraphEdge {
                    sqlite_edge_id: 1,
                    project: "demo".to_string(),
                    source_node_id: 1,
                    target_node_id: 2,
                    src: None,
                    dst: None,
                    edge_type: "CALLS".to_string(),
                    local_name_gen: String::new(),
                    weight: 1.0,
                    properties_json:
                        r#"{"confidence":0.85,"strategy":"import_map","line":11,"candidates":1}"#
                            .to_string(),
                },
                CbmGraphEdge {
                    sqlite_edge_id: 2,
                    project: "demo".to_string(),
                    source_node_id: 1,
                    target_node_id: 3,
                    src: None,
                    dst: None,
                    edge_type: "IMPORTS".to_string(),
                    local_name_gen: "alpha".to_string(),
                    weight: 1.0,
                    properties_json: r#"{"local_name":"alpha","line":2}"#.to_string(),
                },
                CbmGraphEdge {
                    sqlite_edge_id: 3,
                    project: "demo".to_string(),
                    source_node_id: 1,
                    target_node_id: 3,
                    src: None,
                    dst: None,
                    edge_type: "IMPORTS".to_string(),
                    local_name_gen: "beta".to_string(),
                    weight: 1.0,
                    properties_json: r#"{"local_name":"beta","line":3}"#.to_string(),
                },
                CbmGraphEdge {
                    sqlite_edge_id: 4,
                    project: "demo".to_string(),
                    source_node_id: 1,
                    target_node_id: 9999,
                    src: None,
                    dst: None,
                    edge_type: "CALLS".to_string(),
                    local_name_gen: String::new(),
                    weight: 1.0,
                    properties_json: "{}".to_string(),
                },
            ],
            file_hashes: Vec::new(),
            project_summaries: Vec::new(),
            token_vectors: Vec::new(),
        }
    }

    fn edge_multiset<C>(vault: &AsterVault<C>) -> Vec<(CxId, CxId, u16, String, Value)>
    where
        C: Clock,
    {
        let mut edges = vault
            .scan_cf_range_at(
                vault.latest_seq(),
                ColumnFamily::Graph,
                &prefix_range(EDGE_ROW_PREFIX),
            )
            .expect("scan edge rows")
            .into_iter()
            .map(|(_, value)| {
                let edge = serde_json::from_slice::<EdgeGraphRow>(&value).expect("edge row");
                (
                    edge.src,
                    edge.dst,
                    edge.etype,
                    edge.local_name_gen,
                    edge.props,
                )
            })
            .collect::<Vec<_>>();
        edges.sort_by(|left, right| {
            (left.0, left.1, left.2, left.3.as_str()).cmp(&(
                right.0,
                right.1,
                right.2,
                right.3.as_str(),
            ))
        });
        edges
    }

    fn sqlite_fingerprint(path: &Path) -> [u8; 32] {
        sha256_digest(&fs::read(path).expect("read sqlite fixture"))
    }

    fn cf_rows<C>(vault: &AsterVault<C>, family: ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)>
    where
        C: Clock,
    {
        vault
            .scan_cf_at(vault.latest_seq(), family)
            .expect("scan CF rows")
    }

    fn normalize_graph_row(mut value: Vec<u8>) -> Vec<u8> {
        let Ok(mut json) = serde_json::from_slice::<Value>(&value) else {
            return value;
        };
        let Some(object) = json.as_object_mut() else {
            return value;
        };
        if !object.contains_key("provenance") {
            return value;
        }
        object.insert(
            "provenance".to_string(),
            serde_json::to_value(zero_ledger_ref()).expect("ledger ref JSON"),
        );
        value = serde_json::to_vec(&json).expect("normalized graph row JSON");
        value
    }

    fn normalized_base_rows<C>(vault: &AsterVault<C>) -> Vec<(Vec<u8>, Vec<u8>)>
    where
        C: Clock,
    {
        cf_rows(vault, ColumnFamily::Base)
            .into_iter()
            .map(|(key, value)| {
                let mut row = encode::decode_constellation_base(&value).expect("decode Base row");
                row.provenance = zero_ledger_ref();
                (
                    key,
                    encode::encode_constellation_base(&row).expect("encode Base row"),
                )
            })
            .collect()
    }

    fn normalized_graph_rows<C>(vault: &AsterVault<C>) -> Vec<(Vec<u8>, Vec<u8>)>
    where
        C: Clock,
    {
        cf_rows(vault, ColumnFamily::Graph)
            .into_iter()
            .map(|(key, value)| (key, normalize_graph_row(value)))
            .collect()
    }

    fn normalized_ledger_rows<C>(vault: &AsterVault<C>) -> Vec<NormalizedLedgerRow>
    where
        C: Clock,
    {
        cf_rows(vault, ColumnFamily::Ledger)
            .into_iter()
            .map(|(_, value)| {
                let entry = decode(&value).expect("decode Ledger row");
                (
                    entry.seq,
                    entry.prev_hash,
                    entry.kind,
                    entry.subject,
                    entry.payload,
                    entry.actor,
                )
            })
            .collect()
    }

    fn assert_import_cfs_match_with_ledger_ref_normalized<C>(
        left: &AsterVault<C>,
        right: &AsterVault<C>,
    ) where
        C: Clock,
    {
        assert_eq!(
            normalized_base_rows(left),
            normalized_base_rows(right),
            "Base CF rows differ after ledger-ref normalization"
        );
        assert_eq!(
            normalized_graph_rows(left),
            normalized_graph_rows(right),
            "Graph CF rows differ after ledger-ref normalization"
        );
        assert_eq!(
            normalized_ledger_rows(left),
            normalized_ledger_rows(right),
            "Ledger CF semantic rows differ after timestamp/hash normalization"
        );
        for slot in default_panel_slots() {
            assert_eq!(
                cf_rows(left, ColumnFamily::slot(slot.slot_id())),
                cf_rows(right, ColumnFamily::slot(slot.slot_id())),
                "slot {} CF rows differ",
                slot.slot_id()
            );
        }
    }

    fn full_vocabulary_fixture(path: &Path) {
        let connection = create_db(path);
        let source = insert_node(
            &connection,
            "Function",
            "source",
            "demo.vocab.source",
            "src/vocab.rs",
            1,
            5,
            r#"{"language":"rust","source_snippet":"fn source() {}","signature":"fn source()"}"#,
        );
        let target = insert_node(
            &connection,
            "Function",
            "target",
            "demo.vocab.target",
            "src/vocab.rs",
            10,
            15,
            r#"{"language":"rust","source_snippet":"fn target() {}","signature":"fn target()"}"#,
        );
        for kind in EdgeKind::ALL {
            let properties = if kind == EdgeKind::Imports {
                r#"{"local_name":"vocab"}"#
            } else {
                "{}"
            };
            insert_edge(&connection, source, target, kind.as_str(), properties);
        }
    }

    #[test]
    fn fsv_import_decodes_base_slot_graph_and_ledger_rows() {
        let path = temp_db("fsv");
        basic_fixture(&path);
        let vault = vault();

        let report = import_sqlite_to_vault(&path, &vault, &FixtureSlotRuntime, &options(1))
            .expect("import sqlite");

        assert_eq!(report.sqlite_nodes, 2);
        assert_eq!(report.sqlite_node_vectors, 1);
        assert_eq!(report.sqlite_edges, 1);
        assert_eq!(report.constellation_inputs, 1);
        assert_eq!(report.structural_only, 1);
        assert_eq!(report.new_cx_ids, 1);
        assert_eq!(report.edge_rows_written, 0);
        assert_eq!(report.edge_skips.dangling, 1);
        assert_eq!(report.seq, 1);
        assert_eq!(report.ledger_seq, 0);
        assert_eq!(report.readback.base_rows_verified, 1);
        assert_eq!(
            report.readback.slot_rows_verified,
            default_panel_slots().len()
        );
        assert_eq!(report.readback.graph_rows_verified, 4);
        assert_eq!(report.readback.edge_rows_verified, 0);
        assert_eq!(report.readback.expected_edge_rows, 0);
        let deep = crate::verify_deep(&vault).expect("deep verify");
        assert_eq!(deep.sqlite_node_map_rows, 1);
        assert_eq!(deep.sqlite_structural_rows, 1);
        assert_eq!(deep.sqlite_constellation_rows, 1);
        assert_eq!(deep.sqlite_edge_rows, 0);
        assert_eq!(deep.ledger_chain_status, "intact");
        assert_eq!(deep.ledger_rows, 1);
        assert_eq!(deep.ledger_payload_rows, 1);
        assert_eq!(deep.base_ledger_pairs, 1);

        let cx_id = report.cx_ids[0];
        let base = vault
            .read_cf_at(vault.latest_seq(), ColumnFamily::Base, &base_key(cx_id))
            .expect("read base")
            .expect("base exists");
        let decoded = encode::decode_constellation_base(&base).expect("decode base");
        assert_eq!(
            decoded.metadata_value("qualified_name"),
            Some("demo.math.add")
        );
        assert_eq!(decoded.metadata_value("label"), Some("Function"));

        let slot_zero = vault
            .read_cf_at(
                vault.latest_seq(),
                ColumnFamily::slot(SlotId::new(0)),
                &slot_key(cx_id),
            )
            .expect("read slot")
            .expect("slot exists");
        assert!(matches!(
            encode::decode_slot_vector(&slot_zero).expect("decode slot"),
            SlotVector::Dense { dim: 25, .. }
        ));

        let ledger = vault
            .read_cf_at(
                vault.latest_seq(),
                ColumnFamily::Ledger,
                &ledger_key(report.ledger_seq),
            )
            .expect("read ledger")
            .expect("ledger row");
        let entry = decode(&ledger).expect("decode ledger");
        assert_eq!(entry.kind, EntryKind::Ingest);
        assert_eq!(decoded.provenance.seq, report.ledger_seq);
        assert_eq!(decoded.provenance.hash, entry.entry_hash);
        let payload: Value = serde_json::from_slice(&entry.payload).expect("payload json");
        assert_eq!(
            payload.get("edge_dangling_skipped").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(payload.get("sqlite_edges").and_then(Value::as_u64), Some(1));
        assert_eq!(payload.get("edge_inputs").and_then(Value::as_u64), Some(0));
        assert_eq!(
            payload.get("edge_rows_written").and_then(Value::as_u64),
            Some(0)
        );
    }

    #[test]
    fn fsv_imports_typed_edges_with_multiedge_parity_and_idempotency() {
        let path = temp_db("edges");
        edge_fixture(&path);
        let vault = vault();

        let report = import_sqlite_to_vault(&path, &vault, &FixtureSlotRuntime, &options(1))
            .expect("import sqlite edges");

        assert_eq!(report.sqlite_nodes, 3);
        assert_eq!(report.sqlite_edges, 4);
        assert_eq!(report.edge_skips.dangling, 1);
        assert_eq!(report.edge_rows_written, 3);
        assert_eq!(report.graph_rows_written, 11);
        assert_eq!(report.readback.edge_rows_verified, 3);
        assert_eq!(report.readback.expected_edge_rows, 3);

        let ledger = vault
            .read_cf_at(
                vault.latest_seq(),
                ColumnFamily::Ledger,
                &ledger_key(report.ledger_seq),
            )
            .expect("read ledger")
            .expect("ledger row");
        let entry = decode(&ledger).expect("decode ledger");

        let mut edges = vault
            .scan_cf_range_at(
                vault.latest_seq(),
                ColumnFamily::Graph,
                &prefix_range(EDGE_ROW_PREFIX),
            )
            .expect("scan edge rows")
            .into_iter()
            .map(|(_, value)| serde_json::from_slice::<EdgeGraphRow>(&value).expect("edge row"))
            .collect::<Vec<_>>();
        edges.sort_by(|left, right| {
            (left.src, left.dst, left.etype, left.local_name_gen.as_str()).cmp(&(
                right.src,
                right.dst,
                right.etype,
                right.local_name_gen.as_str(),
            ))
        });

        assert_eq!(edges.len(), 3);
        let typed_multiset = edges
            .iter()
            .map(|edge| (edge.src, edge.dst, edge.etype, edge.local_name_gen.clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            typed_multiset,
            vec![
                (
                    report.cx_ids[0],
                    report.cx_ids[1],
                    EdgeKind::Calls.code(),
                    String::new()
                ),
                (
                    report.cx_ids[0],
                    report.cx_ids[2],
                    EdgeKind::Imports.code(),
                    "alpha".to_string()
                ),
                (
                    report.cx_ids[0],
                    report.cx_ids[2],
                    EdgeKind::Imports.code(),
                    "beta".to_string()
                ),
            ]
        );

        let call = edges
            .iter()
            .find(|edge| edge.edge_type == "CALLS")
            .expect("CALLS edge");
        assert_eq!(call.schema, SCHEMA_EDGE_ROW);
        assert_eq!(call.source_node_id, 1);
        assert_eq!(call.target_node_id, 2);
        assert_eq!(call.etype, EdgeKind::Calls.code());
        assert!((call.weight - 0.85).abs() <= f32::EPSILON);
        assert_eq!(
            call.props.get("strategy").and_then(Value::as_str),
            Some("import_map")
        );
        assert_eq!(call.props.get("line").and_then(Value::as_i64), Some(11));
        assert_eq!(call.provenance.seq, entry.seq);
        assert_eq!(call.provenance.hash, entry.entry_hash);

        for import in edges.iter().filter(|edge| edge.edge_type == "IMPORTS") {
            assert_eq!(import.weight, 1.0);
            assert_eq!(import.provenance.seq, entry.seq);
            assert_eq!(import.provenance.hash, entry.entry_hash);
        }

        let deep = crate::verify_deep(&vault).expect("deep verify edges");
        assert_eq!(deep.sqlite_edge_rows, 3);

        let before_graph = vault
            .scan_cf_range_at(
                vault.latest_seq(),
                ColumnFamily::Graph,
                &prefix_range(b"astrolabe:"),
            )
            .expect("scan graph before reimport");
        let before_ledger = ledger_row_count(&vault).expect("ledger count before reimport");
        let replay = import_sqlite_to_vault(&path, &vault, &FixtureSlotRuntime, &options(1))
            .expect("reimport sqlite edges");
        assert_eq!(replay.edge_rows_written, 0);
        assert_eq!(replay.graph_rows_written, 0);
        assert_eq!(replay.edge_skips.dangling, 1);
        assert_eq!(
            vault
                .scan_cf_range_at(
                    vault.latest_seq(),
                    ColumnFamily::Graph,
                    &prefix_range(b"astrolabe:"),
                )
                .expect("scan graph after reimport"),
            before_graph
        );
        assert_eq!(
            ledger_row_count(&vault).expect("ledger count after reimport"),
            before_ledger + 1
        );
    }

    #[test]
    fn row_sink_snapshot_import_matches_sqlite_import_for_typed_edges() {
        let path = temp_db("row-sink-edges");
        edge_fixture(&path);
        let sqlite_vault = vault();
        let row_sink_vault = vault();

        let sqlite = import_sqlite_to_vault(&path, &sqlite_vault, &FixtureSlotRuntime, &options(1))
            .expect("sqlite import");
        let row_sink = import_cbm_graph_snapshot_to_vault(
            &edge_snapshot(),
            &row_sink_vault,
            &FixtureSlotRuntime,
            &options(1),
        )
        .expect("row-sink import");

        assert_eq!(row_sink.cx_ids, sqlite.cx_ids);
        assert_eq!(row_sink.edge_skips, sqlite.edge_skips);
        assert_eq!(row_sink.sqlite_nodes, sqlite.sqlite_nodes);
        assert_eq!(row_sink.sqlite_edges, sqlite.sqlite_edges);
        assert_eq!(row_sink.readback.expected_edge_rows, 3);
        assert_eq!(row_sink.readback, sqlite.readback);
        assert_eq!(edge_multiset(&row_sink_vault), edge_multiset(&sqlite_vault));

        let deep = crate::verify_deep(&row_sink_vault).expect("deep verify row-sink");
        assert_eq!(deep.ledger_chain_status, "intact");
        assert_eq!(deep.sqlite_edge_rows, 3);

        fs::remove_file(path).ok();
    }

    #[test]
    fn direct_row_sink_snapshot_import_matches_sqlite_import_after_ledger_ref_normalization() {
        let path = temp_db("row-sink-direct-edges");
        edge_fixture(&path);
        let sqlite_vault = vault();
        let direct_vault = vault();
        let fingerprint = sqlite_fingerprint(&path);

        let sqlite = import_sqlite_to_vault(&path, &sqlite_vault, &FixtureSlotRuntime, &options(1))
            .expect("sqlite import");
        let direct = import_cbm_graph_snapshot_to_vault_direct(
            &edge_snapshot(),
            fingerprint,
            &direct_vault,
            &FixtureSlotRuntime,
            &options(1),
        )
        .expect("direct row-sink import");

        assert_eq!(direct, sqlite);
        assert_import_cfs_match_with_ledger_ref_normalized(&direct_vault, &sqlite_vault);

        fs::remove_file(path).ok();
    }

    #[test]
    fn direct_row_sink_snapshot_refuses_local_name_drift() {
        let mut snapshot = edge_snapshot();
        snapshot.edges[1].local_name_gen = "wrong".to_string();
        let err = import_cbm_graph_snapshot_to_vault_direct(
            &snapshot,
            [0; 32],
            &vault(),
            &FixtureSlotRuntime,
            &options(1),
        )
        .expect_err("local_name_gen mismatch should fail");

        assert_eq!(err.code(), Some(ASTRO_INGEST_SQLITE_INVALID));
        assert!(
            err.to_string().contains("local_name_gen"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn full_edge_vocabulary_imports_with_golden_priors() {
        let path = temp_db("edge-vocabulary");
        full_vocabulary_fixture(&path);
        let vault = vault();

        let report = import_sqlite_to_vault(&path, &vault, &FixtureSlotRuntime, &options(1))
            .expect("import full edge vocabulary");

        assert_eq!(report.sqlite_edges, EdgeKind::ALL.len());
        assert_eq!(report.edge_skips.dangling, 0);
        assert_eq!(report.edge_rows_written, EdgeKind::ALL.len());
        assert_eq!(report.readback.edge_rows_verified, EdgeKind::ALL.len());

        let edges = vault
            .scan_cf_range_at(
                vault.latest_seq(),
                ColumnFamily::Graph,
                &prefix_range(EDGE_ROW_PREFIX),
            )
            .expect("scan edge rows")
            .into_iter()
            .map(|(_, value)| serde_json::from_slice::<EdgeGraphRow>(&value).expect("edge row"))
            .collect::<Vec<_>>();
        assert_eq!(edges.len(), EdgeKind::ALL.len());

        for kind in EdgeKind::ALL {
            let row = edges
                .iter()
                .find(|edge| edge.etype == kind.code())
                .unwrap_or_else(|| panic!("missing edge kind {kind}"));
            assert_eq!(row.edge_type, kind.as_str());
            assert_eq!(row.src, report.cx_ids[0]);
            assert_eq!(row.dst, report.cx_ids[1]);
            assert!(
                (row.weight - kind.weight_prior().fallback).abs() <= f32::EPSILON,
                "weight prior mismatch for {kind}"
            );
        }

        let deep = crate::verify_deep(&vault).expect("deep verify full vocabulary");
        assert_eq!(deep.sqlite_edge_rows, EdgeKind::ALL.len());
    }

    #[test]
    fn idempotent_reimport_mutates_only_the_run_ledger() {
        let path = temp_db("idempotent");
        basic_fixture(&path);
        let vault = vault();
        import_sqlite_to_vault(&path, &vault, &FixtureSlotRuntime, &options(1))
            .expect("first import");

        let before_base = vault
            .scan_cf_at(vault.latest_seq(), ColumnFamily::Base)
            .expect("scan base");
        let before_graph = vault
            .scan_cf_range_at(
                vault.latest_seq(),
                ColumnFamily::Graph,
                &prefix_range(b"astrolabe:"),
            )
            .expect("scan graph");
        let before_ledger = ledger_row_count(&vault).expect("ledger count");

        let report = import_sqlite_to_vault(&path, &vault, &FixtureSlotRuntime, &options(1))
            .expect("second import");

        assert_eq!(report.new_cx_ids, 0);
        assert_eq!(report.reused_cx_ids, 1);
        assert_eq!(report.graph_rows_written, 0);
        assert_eq!(
            vault
                .scan_cf_at(vault.latest_seq(), ColumnFamily::Base)
                .expect("scan base after"),
            before_base
        );
        assert_eq!(
            vault
                .scan_cf_range_at(
                    vault.latest_seq(),
                    ColumnFamily::Graph,
                    &prefix_range(b"astrolabe:"),
                )
                .expect("scan graph after"),
            before_graph
        );
        assert_eq!(
            ledger_row_count(&vault).expect("ledger count after"),
            before_ledger + 1
        );
    }

    #[test]
    fn worker_count_does_not_change_imported_cx_ids() {
        let path = temp_db("workers");
        basic_fixture(&path);

        let mut expected = None;
        for run in 0..3 {
            let sequential = vault();
            let parallel = vault();

            let left = import_sqlite_to_vault(&path, &sequential, &FixtureSlotRuntime, &options(1))
                .expect("sequential import");
            let right = import_sqlite_to_vault(&path, &parallel, &FixtureSlotRuntime, &options(8))
                .expect("parallel import");

            assert_eq!(left.cx_ids, right.cx_ids, "worker mismatch on run {run}");
            assert_eq!(
                left.readback, right.readback,
                "readback mismatch on run {run}"
            );
            if let Some(expected) = &expected {
                assert_eq!(&left.cx_ids, expected, "run {run} changed CxId set");
            } else {
                expected = Some(left.cx_ids);
            }
        }
    }

    #[test]
    fn validation_refusals_are_fail_closed_with_exact_codes() {
        let cases = [
            (
                "empty-qn",
                "Function",
                "",
                r#"{"source_snippet":"x"}"#,
                7,
                ASTRO_SYMBOL_IDENTITY_EMPTY,
                "Populate project, qualified_name, and label before deriving Astrolabe identity.",
            ),
            (
                "panel-zero",
                "Function",
                "demo.bad.zero",
                r#"{"source_snippet":"x"}"#,
                0,
                ASTRO_PANEL_VERSION_ZERO,
                "Commission a non-zero panel version before deriving a CxId.",
            ),
            (
                "non-finite",
                "Function",
                "demo.bad.nan",
                r#"{"source_snippet":"x","scalar_complexity":"NaN"}"#,
                7,
                ASTRO_SYMBOL_NON_FINITE,
                "Drop or repair non-finite scalar values before admitting the symbol.",
            ),
            (
                "source-drift",
                "Function",
                "demo.bad.drift",
                &format!(
                    r#"{{"source_snippet":"x","source_snippet_blake3":"{}"}}"#,
                    "07".repeat(32)
                ),
                7,
                ASTRO_SOURCE_DRIFT,
                "Re-read the source snippet from persisted bytes and recompute the supplied hash before ingest.",
            ),
            (
                "bad-anchor",
                "Function",
                "demo.bad.anchor",
                r#"{"source_snippet":"x","anchors":[{"source":"ci:github","confidence":0.0}]}"#,
                7,
                ASTRO_ANCHOR_CONFIDENCE_RANGE,
                "Clamp or reject anchor confidence so only values in (0, 1] are admitted.",
            ),
        ];

        for (name, label, qn, properties, panel_version, code, remediation) in cases {
            let path = temp_db(name);
            let connection = create_db(&path);
            insert_node(
                &connection,
                label,
                "bad",
                qn,
                "src/bad.rs",
                1,
                1,
                properties,
            );
            let vault = vault();
            let err = import_sqlite_to_vault(
                &path,
                &vault,
                &FixtureSlotRuntime,
                &SqliteImportOptions::new("demo", "commit-1", panel_version),
            )
            .expect_err("validation must refuse");

            assert_eq!(err.code(), Some(code), "{name}");
            assert_eq!(err.remediation(), Some(remediation), "{name}");
            assert!(
                vault
                    .scan_cf_at(vault.latest_seq(), ColumnFamily::Base)
                    .expect("scan base")
                    .is_empty(),
                "{name}"
            );
            assert!(
                vault
                    .scan_cf_at(vault.latest_seq(), ColumnFamily::Graph)
                    .expect("scan graph")
                    .is_empty(),
                "{name}"
            );
            assert_eq!(ledger_row_count(&vault).expect("ledger count"), 0, "{name}");
        }
    }
}
