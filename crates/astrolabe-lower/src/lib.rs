#![forbid(unsafe_code)]

mod team_artifact;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use astrolabe_ingest::{CbmGraphEdge, CbmGraphNode, CbmGraphSnapshot, read_cbm_graph_snapshot};
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::AsterVault;
use calyx_core::{CalyxError, Clock, Seq};
use calyx_ledger::{ActorId, EntryKind, SubjectId, decode};
use rusqlite::{Connection, OpenFlags, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

pub use team_artifact::{
    ASTRO_TEAM_ARTIFACT_GRAPH_ATTESTATION, ASTRO_TEAM_ARTIFACT_GRAPH_BYTES,
    ASTRO_TEAM_ARTIFACT_LEDGER_TAIL, ASTRO_TEAM_ARTIFACT_MERKLE_ROOT,
    ASTRO_TEAM_ARTIFACT_MISSING_GRAPH, ASTRO_TEAM_ARTIFACT_SIGNATURE,
    ASTRO_TEAM_ARTIFACT_SIGNATURE_SIGNER, ASTRO_TEAM_ARTIFACT_VAULT_BYTES, GRAPH_DB_ZST_NAME,
    TEAM_ARTIFACT_SCHEMA, TeamArtifactExportOptions, TeamArtifactExportReport,
    TeamArtifactImportOptions, TeamArtifactImportReport, TeamArtifactManifest,
    TeamArtifactSignature, TeamLedgerHead, VAULT_EXPORT_ZST_NAME, export_team_artifact,
    import_team_artifact,
};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
pub const ASTRO_LOWER_ACTOR: &str = "astrolabe-lower";
pub const ASTRO_LOWERED_SQLITE_MANIFEST_PREFIX: &[u8] = b"astrolabe:lowered-sqlite:v1:";
pub const ASTRO_LOWERED_SQLITE_SCHEMA: &str = "astrolabe-lowered-sqlite-v1";
pub const ASTRO_META_SCHEMA: &str = "astrolabe-astro-meta-v1";
pub const DEFAULT_LOWERED_AT: &str = "1970-01-01T00:00:00Z";

pub type LowerResult<T> = Result<T, LowerError>;

#[derive(Debug)]
pub enum LowerError {
    Ingest(astrolabe_ingest::IngestError),
    Calyx(CalyxError),
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    Io(std::io::Error),
    /// Input refused fail-closed with a stable `ASTRO_*` code and operator remediation.
    ///
    /// The code is stored structurally (never embedded in a formatted message),
    /// so machine consumers can dispatch on [`LowerError::code`] without parsing
    /// display text, and a refusal can never carry a code that drifts from its
    /// message.
    Refused {
        /// Stable machine-readable refusal code (an `ASTRO_*` constant).
        code: &'static str,
        /// Human-readable description of what was refused.
        message: String,
        /// Operator-facing remediation for clearing the refusal.
        remediation: &'static str,
    },
    /// Caller supplied an invalid input that has no stable refusal code.
    InvalidInput(String),
}

impl fmt::Display for LowerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ingest(err) => write!(f, "{err}"),
            Self::Calyx(err) => write!(f, "{err}"),
            Self::Sqlite(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Refused {
                code,
                message,
                remediation,
            } => write!(f, "{code}: {message} Remediation: {remediation}"),
            Self::InvalidInput(message) => f.write_str(message),
        }
    }
}

impl Error for LowerError {}

impl LowerError {
    /// Builds a fail-closed refusal carrying a stable machine-readable code and
    /// its operator remediation.
    pub fn refused(
        code: &'static str,
        message: impl Into<String>,
        remediation: &'static str,
    ) -> Self {
        Self::Refused {
            code,
            message: message.into(),
            remediation,
        }
    }

    /// Returns the stable refusal code when this error carries one.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Refused { code, .. } => Some(code),
            Self::Ingest(err) => err.code(),
            Self::Calyx(_)
            | Self::Sqlite(_)
            | Self::Json(_)
            | Self::Io(_)
            | Self::InvalidInput(_) => None,
        }
    }

    /// Returns the operator-facing remediation when this error carries one.
    pub fn remediation(&self) -> Option<&str> {
        match self {
            Self::Refused { remediation, .. } => Some(remediation),
            Self::Ingest(err) => err.remediation(),
            Self::Calyx(_)
            | Self::Sqlite(_)
            | Self::Json(_)
            | Self::Io(_)
            | Self::InvalidInput(_) => None,
        }
    }
}

impl From<astrolabe_ingest::IngestError> for LowerError {
    fn from(value: astrolabe_ingest::IngestError) -> Self {
        Self::Ingest(value)
    }
}

impl From<CalyxError> for LowerError {
    fn from(value: CalyxError) -> Self {
        Self::Calyx(value)
    }
}

impl From<rusqlite::Error> for LowerError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<serde_json::Error> for LowerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<std::io::Error> for LowerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LowerSqliteOptions {
    pub project: String,
    pub lowered_at: String,
}

impl LowerSqliteOptions {
    pub fn new(project: impl Into<String>) -> Self {
        Self {
            project: project.into(),
            lowered_at: DEFAULT_LOWERED_AT.to_string(),
        }
    }

    pub fn with_lowered_at(mut self, lowered_at: impl Into<String>) -> Self {
        self.lowered_at = lowered_at.into();
        self
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LoweredSqliteReport {
    pub project: String,
    pub output_path: PathBuf,
    pub node_count: usize,
    pub edge_count: usize,
    pub skipped_edges: usize,
    pub file_hash_count: usize,
    pub project_summary_count: usize,
    pub node_vector_count: usize,
    pub token_vector_count: usize,
    pub panel_version: Option<u32>,
    pub source_ledger_head_hash: String,
    pub vault_fingerprint_sha256: String,
    pub artifact_sha256: String,
    pub manifest_seq: Seq,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct LoweredSqliteManifest {
    schema: String,
    project: String,
    output_filename: String,
    node_count: usize,
    edge_count: usize,
    skipped_edges: usize,
    file_hash_count: usize,
    project_summary_count: usize,
    node_vector_count: usize,
    token_vector_count: usize,
    panel_version: Option<u32>,
    source_ledger_head_hash: String,
    vault_fingerprint_sha256: String,
    artifact_sha256: String,
    lowered_at: String,
}

pub fn lower_cbm_sqlite<C>(
    vault: &AsterVault<C>,
    output_path: impl AsRef<Path>,
    options: &LowerSqliteOptions,
) -> LowerResult<LoweredSqliteReport>
where
    C: Clock,
{
    validate_options(options)?;
    let output_path = output_path.as_ref().to_path_buf();
    let snapshot = read_cbm_graph_snapshot(vault, &options.project)?;
    let source_ledger_head_hash = source_ledger_head_hash(vault)?;
    let vault_fingerprint_sha256 = snapshot_fingerprint(&snapshot, &source_ledger_head_hash);
    let lowered = LoweredRows::from_snapshot(snapshot)?;

    write_sqlite_artifact(
        &output_path,
        &lowered,
        &source_ledger_head_hash,
        &vault_fingerprint_sha256,
        &options.lowered_at,
    )?;
    let artifact_sha256 = hex_lower(&sha256_digest(&fs::read(&output_path)?));
    let manifest_seq = write_lower_manifest(
        vault,
        &output_path,
        &lowered,
        &source_ledger_head_hash,
        &vault_fingerprint_sha256,
        &artifact_sha256,
        &options.lowered_at,
    )?;

    Ok(LoweredSqliteReport {
        project: lowered.project,
        output_path,
        node_count: lowered.nodes.len(),
        edge_count: lowered.edges.len(),
        skipped_edges: lowered.skipped_edges,
        file_hash_count: lowered.file_hashes.len(),
        project_summary_count: lowered.project_summaries.len(),
        node_vector_count: lowered
            .nodes
            .iter()
            .filter(|node| node.node_vector.is_some())
            .count(),
        token_vector_count: lowered.token_vectors.len(),
        panel_version: lowered.panel_version,
        source_ledger_head_hash,
        vault_fingerprint_sha256,
        artifact_sha256,
        manifest_seq,
    })
}

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::CodebaseMemoryMcp
}

fn validate_options(options: &LowerSqliteOptions) -> LowerResult<()> {
    if options.project.trim().is_empty() {
        return Err(LowerError::InvalidInput(
            "lowered SQLite project must be non-empty".to_string(),
        ));
    }
    if options.lowered_at.trim().is_empty() {
        return Err(LowerError::InvalidInput(
            "lowered_at must be non-empty".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct LoweredRows {
    project: String,
    panel_version: Option<u32>,
    projects: Vec<astrolabe_ingest::CbmProjectRow>,
    nodes: Vec<LoweredNode>,
    edges: Vec<LoweredEdge>,
    skipped_edges: usize,
    file_hashes: Vec<astrolabe_ingest::CbmFileHashRow>,
    project_summaries: Vec<astrolabe_ingest::CbmProjectSummaryRow>,
    token_vectors: Vec<astrolabe_ingest::CbmTokenVectorRow>,
}

#[derive(Debug, Clone)]
struct LoweredNode {
    id: i64,
    project: String,
    label: String,
    name: String,
    qualified_name: String,
    file_path: String,
    start_line: i64,
    end_line: i64,
    properties_json: String,
    node_vector: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct LoweredEdge {
    id: i64,
    project: String,
    source_id: i64,
    target_id: i64,
    edge_type: String,
    properties_json: String,
}

impl LoweredRows {
    fn from_snapshot(snapshot: CbmGraphSnapshot) -> LowerResult<Self> {
        let mut seen_qn = BTreeSet::new();
        let mut id_by_source = BTreeMap::new();
        let mut nodes = Vec::with_capacity(snapshot.nodes.len());
        for (index, node) in snapshot.nodes.into_iter().enumerate() {
            if !seen_qn.insert((node.project.clone(), node.qualified_name.clone())) {
                return Err(LowerError::InvalidInput(format!(
                    "duplicate node qualified_name {} in project {}",
                    node.qualified_name, node.project
                )));
            }
            let id = i64::try_from(index + 1).map_err(|_| {
                LowerError::InvalidInput("too many nodes to assign dense SQLite ids".to_string())
            })?;
            if id_by_source.insert(node.source_node_id, id).is_some() {
                return Err(LowerError::InvalidInput(format!(
                    "duplicate source node id {}",
                    node.source_node_id
                )));
            }
            nodes.push(lower_node(id, node));
        }

        let mut edges = Vec::new();
        let mut skipped_edges = 0;
        for edge in snapshot.edges {
            let Some(source_id) = id_by_source.get(&edge.source_node_id).copied() else {
                skipped_edges += 1;
                continue;
            };
            let Some(target_id) = id_by_source.get(&edge.target_node_id).copied() else {
                skipped_edges += 1;
                continue;
            };
            let id = i64::try_from(edges.len() + 1).map_err(|_| {
                LowerError::InvalidInput("too many edges to assign SQLite ids".to_string())
            })?;
            edges.push(lower_edge(id, edge, source_id, target_id));
        }

        Ok(Self {
            project: snapshot.project,
            panel_version: snapshot.panel_version,
            projects: snapshot.projects,
            nodes,
            edges,
            skipped_edges,
            file_hashes: snapshot.file_hashes,
            project_summaries: snapshot.project_summaries,
            token_vectors: snapshot.token_vectors,
        })
    }
}

fn lower_node(id: i64, node: CbmGraphNode) -> LoweredNode {
    LoweredNode {
        id,
        project: node.project,
        label: node.label,
        name: node.name,
        qualified_name: node.qualified_name,
        file_path: node.file_path,
        start_line: node.start_line,
        end_line: node.end_line,
        properties_json: node.properties_json,
        node_vector: node.node_vector,
    }
}

fn lower_edge(id: i64, edge: CbmGraphEdge, source_id: i64, target_id: i64) -> LoweredEdge {
    LoweredEdge {
        id,
        project: edge.project,
        source_id,
        target_id,
        edge_type: edge.edge_type,
        properties_json: edge.properties_json,
    }
}

fn write_sqlite_artifact(
    output_path: &Path,
    rows: &LoweredRows,
    source_ledger_head_hash: &str,
    vault_fingerprint_sha256: &str,
    lowered_at: &str,
) -> LowerResult<()> {
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    remove_existing_sqlite(output_path)?;

    let mut connection = Connection::open_with_flags(
        output_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.execute_batch(
        "PRAGMA page_size=4096;\
         PRAGMA journal_mode=OFF;\
         PRAGMA synchronous=OFF;\
         PRAGMA foreign_keys=ON;\
         PRAGMA encoding='UTF-8';",
    )?;
    create_cbm_schema(&connection)?;
    let transaction = connection.transaction()?;
    insert_rows(
        &transaction,
        rows,
        source_ledger_head_hash,
        vault_fingerprint_sha256,
        lowered_at,
    )?;
    transaction.commit()?;
    connection.execute_batch("PRAGMA optimize;")?;
    drop(connection);
    Ok(())
}

fn remove_existing_sqlite(path: &Path) -> LowerResult<()> {
    remove_file_if_exists(path)?;
    remove_file_if_exists(&sidecar_path(path, "-wal"))?;
    remove_file_if_exists(&sidecar_path(path, "-shm"))?;
    remove_file_if_exists(&sidecar_path(path, "-journal"))?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> LowerResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut text = path.as_os_str().to_os_string();
    text.push(suffix);
    PathBuf::from(text)
}

fn create_cbm_schema(connection: &Connection) -> LowerResult<()> {
    connection.execute_batch(
        "CREATE TABLE projects (\n\t\tname TEXT PRIMARY KEY,\n\t\tindexed_at TEXT NOT NULL,\n\t\troot_path TEXT NOT NULL\n\t);\
         CREATE TABLE file_hashes (\n\t\tproject TEXT NOT NULL REFERENCES projects(name) ON DELETE CASCADE,\n\t\trel_path TEXT NOT NULL,\n\t\tsha256 TEXT NOT NULL,\n\t\tmtime_ns INTEGER NOT NULL DEFAULT 0,\n\t\tsize INTEGER NOT NULL DEFAULT 0,\n\t\tPRIMARY KEY (project, rel_path)\n\t);\
         CREATE TABLE nodes (\n\t\tid INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tproject TEXT NOT NULL REFERENCES projects(name) ON DELETE CASCADE,\n\t\tlabel TEXT NOT NULL,\n\t\tname TEXT NOT NULL,\n\t\tqualified_name TEXT NOT NULL,\n\t\tfile_path TEXT DEFAULT '',\n\t\tstart_line INTEGER DEFAULT 0,\n\t\tend_line INTEGER DEFAULT 0,\n\t\tproperties TEXT DEFAULT '{}',\n\t\tUNIQUE(project, qualified_name)\n\t);\
         CREATE TABLE edges (\n\t\tid INTEGER PRIMARY KEY AUTOINCREMENT,\n\t\tproject TEXT NOT NULL REFERENCES projects(name) ON DELETE CASCADE,\n\t\tsource_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,\n\t\ttarget_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,\n\t\ttype TEXT NOT NULL,\n\t\tproperties TEXT DEFAULT '{}',\n\t\turl_path_gen TEXT GENERATED ALWAYS AS (json_extract(properties,'$.url_path')),\n\t\tlocal_name_gen TEXT GENERATED ALWAYS AS (CASE WHEN type='IMPORTS' THEN coalesce(json_extract(properties,'$.local_name'),'') ELSE '' END),\n\t\tUNIQUE(source_id, target_id, type, local_name_gen)\n\t);\
         CREATE TABLE project_summaries (\n\t\t\tproject TEXT PRIMARY KEY,\n\t\t\tsummary TEXT NOT NULL,\n\t\t\tsource_hash TEXT NOT NULL,\n\t\t\tcreated_at TEXT NOT NULL,\n\t\t\tupdated_at TEXT NOT NULL\n\t\t);\
         CREATE TABLE node_vectors (\n\t\tnode_id INTEGER PRIMARY KEY,\n\t\tproject TEXT NOT NULL,\n\t\tvector BLOB NOT NULL\n\t);\
         CREATE TABLE token_vectors (\n\t\tid INTEGER PRIMARY KEY,\n\t\tproject TEXT NOT NULL,\n\t\ttoken TEXT NOT NULL,\n\t\tvector BLOB NOT NULL,\n\t\tidf INTEGER NOT NULL\n\t);\
         CREATE VIRTUAL TABLE nodes_fts USING fts5(  name, qualified_name, label, file_path,  content='',  tokenize='unicode61 remove_diacritics 2');\
         CREATE TABLE astro_meta (\
           schema TEXT NOT NULL,\
           vault_fingerprint TEXT NOT NULL,\
           ledger_head_hash TEXT NOT NULL,\
           panel_version INTEGER,\
           lowered_at TEXT NOT NULL\
         );\
         CREATE INDEX idx_nodes_label ON nodes(project, label);\
         CREATE INDEX idx_nodes_name ON nodes(project, name);\
         CREATE INDEX idx_nodes_file ON nodes(project, file_path);\
         CREATE INDEX idx_edges_source ON edges(source_id, type);\
         CREATE INDEX idx_edges_target ON edges(target_id, type);\
         CREATE INDEX idx_edges_type ON edges(project, type);\
         CREATE INDEX idx_edges_target_type ON edges(project, target_id, type);\
         CREATE INDEX idx_edges_source_type ON edges(project, source_id, type);\
         CREATE INDEX idx_edges_url_path ON edges(project, url_path_gen);",
    )?;
    Ok(())
}

fn insert_rows(
    tx: &Transaction<'_>,
    rows: &LoweredRows,
    source_ledger_head_hash: &str,
    vault_fingerprint_sha256: &str,
    lowered_at: &str,
) -> LowerResult<()> {
    insert_projects(tx, rows)?;
    insert_file_hashes(tx, rows)?;
    insert_nodes(tx, rows)?;
    insert_edges(tx, rows)?;
    insert_project_summaries(tx, rows)?;
    insert_token_vectors(tx, rows)?;
    tx.execute(
        "INSERT INTO astro_meta(schema, vault_fingerprint, ledger_head_hash, panel_version, lowered_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            ASTRO_META_SCHEMA,
            vault_fingerprint_sha256,
            source_ledger_head_hash,
            rows.panel_version.map(i64::from),
            lowered_at,
        ],
    )?;
    Ok(())
}

fn insert_projects(tx: &Transaction<'_>, rows: &LoweredRows) -> LowerResult<()> {
    let mut statement =
        tx.prepare("INSERT INTO projects(name, indexed_at, root_path) VALUES (?1, ?2, ?3)")?;
    for project in &rows.projects {
        statement.execute(params![
            project.project,
            project.indexed_at,
            project.root_path
        ])?;
    }
    Ok(())
}

fn insert_file_hashes(tx: &Transaction<'_>, rows: &LoweredRows) -> LowerResult<()> {
    let mut statement = tx.prepare(
        "INSERT INTO file_hashes(project, rel_path, sha256, mtime_ns, size)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for file_hash in &rows.file_hashes {
        statement.execute(params![
            file_hash.project,
            file_hash.rel_path,
            file_hash.sha256,
            file_hash.mtime_ns,
            file_hash.size,
        ])?;
    }
    Ok(())
}

fn insert_nodes(tx: &Transaction<'_>, rows: &LoweredRows) -> LowerResult<()> {
    let mut node_statement = tx.prepare(
        "INSERT INTO nodes(id, project, label, name, qualified_name, file_path, start_line, end_line, properties)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?;
    let mut vector_statement =
        tx.prepare("INSERT INTO node_vectors(node_id, project, vector) VALUES (?1, ?2, ?3)")?;
    let mut fts_statement = tx.prepare(
        "INSERT INTO nodes_fts(rowid, name, qualified_name, label, file_path)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for node in &rows.nodes {
        node_statement.execute(params![
            node.id,
            node.project,
            node.label,
            node.name,
            node.qualified_name,
            node.file_path,
            node.start_line,
            node.end_line,
            node.properties_json,
        ])?;
        if let Some(vector) = &node.node_vector {
            vector_statement.execute(params![node.id, node.project, vector])?;
        }
        let split_name = cbm_camel_split(&node.name);
        fts_statement.execute(params![
            node.id,
            split_name,
            node.qualified_name,
            node.label,
            node.file_path,
        ])?;
    }
    Ok(())
}

fn insert_edges(tx: &Transaction<'_>, rows: &LoweredRows) -> LowerResult<()> {
    let mut statement = tx.prepare(
        "INSERT INTO edges(id, project, source_id, target_id, type, properties)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for edge in &rows.edges {
        statement.execute(params![
            edge.id,
            edge.project,
            edge.source_id,
            edge.target_id,
            edge.edge_type,
            edge.properties_json,
        ])?;
    }
    Ok(())
}

fn insert_project_summaries(tx: &Transaction<'_>, rows: &LoweredRows) -> LowerResult<()> {
    let mut statement = tx.prepare(
        "INSERT INTO project_summaries(project, summary, source_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for summary in &rows.project_summaries {
        statement.execute(params![
            summary.project,
            summary.summary,
            summary.source_hash,
            summary.created_at,
            summary.updated_at,
        ])?;
    }
    Ok(())
}

fn insert_token_vectors(tx: &Transaction<'_>, rows: &LoweredRows) -> LowerResult<()> {
    let mut statement = tx.prepare(
        "INSERT INTO token_vectors(id, project, token, vector, idf)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for token_vector in &rows.token_vectors {
        statement.execute(params![
            token_vector.id,
            token_vector.project,
            token_vector.token,
            token_vector.vector,
            token_vector.idf,
        ])?;
    }
    Ok(())
}

fn source_ledger_head_hash<C>(vault: &AsterVault<C>) -> LowerResult<String>
where
    C: Clock,
{
    let mut selected = None;
    for (_key, bytes) in vault.scan_cf_at(vault.latest_seq(), ColumnFamily::Ledger)? {
        let entry = decode(&bytes)?;
        if matches!(&entry.actor, ActorId::Service(actor) if actor == ASTRO_LOWER_ACTOR) {
            continue;
        }
        if selected.is_none_or(|(seq, _)| entry.seq > seq) {
            selected = Some((entry.seq, entry.entry_hash));
        }
    }
    Ok(hex_lower(
        &selected.map_or([0_u8; 32], |(_, entry_hash)| entry_hash),
    ))
}

fn write_lower_manifest<C>(
    vault: &AsterVault<C>,
    output_path: &Path,
    rows: &LoweredRows,
    source_ledger_head_hash: &str,
    vault_fingerprint_sha256: &str,
    artifact_sha256: &str,
    lowered_at: &str,
) -> LowerResult<Seq>
where
    C: Clock,
{
    let manifest = LoweredSqliteManifest {
        schema: ASTRO_LOWERED_SQLITE_SCHEMA.to_string(),
        project: rows.project.clone(),
        output_filename: output_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string(),
        node_count: rows.nodes.len(),
        edge_count: rows.edges.len(),
        skipped_edges: rows.skipped_edges,
        file_hash_count: rows.file_hashes.len(),
        project_summary_count: rows.project_summaries.len(),
        node_vector_count: rows
            .nodes
            .iter()
            .filter(|node| node.node_vector.is_some())
            .count(),
        token_vector_count: rows.token_vectors.len(),
        panel_version: rows.panel_version,
        source_ledger_head_hash: source_ledger_head_hash.to_string(),
        vault_fingerprint_sha256: vault_fingerprint_sha256.to_string(),
        artifact_sha256: artifact_sha256.to_string(),
        lowered_at: lowered_at.to_string(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let key = lowered_manifest_key(&rows.project, vault_fingerprint_sha256);
    let payload = lower_ledger_payload(rows, vault_fingerprint_sha256, artifact_sha256)?;
    let existing = vault.read_cf_at(vault.latest_seq(), ColumnFamily::Kernel, &key)?;
    if existing.as_ref() == Some(&manifest_bytes) {
        vault.append_ledger_entry(
            EntryKind::Admin,
            SubjectId::Kernel(key),
            payload,
            ActorId::Service(ASTRO_LOWER_ACTOR.to_string()),
        )?;
        return Ok(vault.latest_seq());
    }
    vault.write_cf_batch_with_ledger_entry(
        [(ColumnFamily::Kernel, key.clone(), manifest_bytes)],
        EntryKind::Admin,
        SubjectId::Kernel(key),
        payload,
        ActorId::Service(ASTRO_LOWER_ACTOR.to_string()),
    )?;
    Ok(vault.latest_seq())
}

fn lower_ledger_payload(
    rows: &LoweredRows,
    vault_fingerprint_sha256: &str,
    artifact_sha256: &str,
) -> LowerResult<Vec<u8>> {
    // `artifact_sha256` carries the FULL 64-hex SHA-256 of the lowered artifact,
    // not a truncated prefix. This `asl_v1` Admin entry lives inside the
    // chain-verified, Merkle-rooted, signed ledger, so recording the whole
    // digest makes it a full-strength (256-bit) commitment to the lowered graph
    // bytes. Team-artifact import cross-checks the adopted graph against this
    // field (`team_artifact::ensure_graph_bound_to_ledger`) to bind the graph to
    // the signed envelope; a truncated prefix would leave a ~2^64 second-preimage
    // gap in that tamper-evidence guarantee (see #84).
    //
    // The field name MUST stay on Calyx's benign-long-token allowlist, or the
    // ledger group-commit hook rejects the whole write with
    // `CALYX_LEDGER_SECRET_IN_PAYLOAD` ("long non-whitespace token"): a bare
    // 64-hex digest reads as a secret. `calyx-ledger::redaction` allows a
    // <=64-char hex token only under a field named `hash`/`root`/`input_hash`,
    // ending in `_hash`/`_id`/`_sha256`/`_digest`, etc. Hence `_sha256` (like the
    // sibling `project_sha256`); renaming this back to a bare `artifact` would
    // silently break every lowering. `vault_fp` stays a 16-hex prefix, safely
    // under the 40-char `SECRET_TOKEN_MIN` run threshold.
    Ok(serde_json::to_vec(&json!({
        "schema": "asl_v1",
        "project_sha256": hex_lower(&sha256_digest(rows.project.as_bytes())),
        "vault_fp": &vault_fingerprint_sha256[..16],
        "artifact_sha256": artifact_sha256,
        "nodes": rows.nodes.len(),
        "edges": rows.edges.len(),
        "skipped": rows.skipped_edges,
    }))?)
}

fn lowered_manifest_key(project: &str, vault_fingerprint_sha256: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(ASTRO_LOWERED_SQLITE_MANIFEST_PREFIX.len() + 64);
    key.extend_from_slice(ASTRO_LOWERED_SQLITE_MANIFEST_PREFIX);
    key.extend_from_slice(&sha256_digest(project.as_bytes()));
    key.extend_from_slice(&sha256_digest(vault_fingerprint_sha256.as_bytes()));
    key
}

fn snapshot_fingerprint(snapshot: &CbmGraphSnapshot, source_ledger_head_hash: &str) -> String {
    let mut hasher = Sha256::new();
    update_str(&mut hasher, "astrolabe-cbm-snapshot-v1");
    update_str(&mut hasher, &snapshot.project);
    update_str(&mut hasher, source_ledger_head_hash);
    update_opt_u32(&mut hasher, snapshot.panel_version);
    for project in &snapshot.projects {
        update_str(&mut hasher, &project.project);
        update_str(&mut hasher, &project.indexed_at);
        update_str(&mut hasher, &project.root_path);
    }
    for node in &snapshot.nodes {
        update_i64(&mut hasher, node.source_node_id);
        update_str(&mut hasher, &node.project);
        update_str(&mut hasher, &node.label);
        update_str(&mut hasher, &node.name);
        update_str(&mut hasher, &node.qualified_name);
        update_str(&mut hasher, &node.file_path);
        update_i64(&mut hasher, node.start_line);
        update_i64(&mut hasher, node.end_line);
        update_str(&mut hasher, &node.properties_json);
        update_bytes_opt(&mut hasher, node.node_vector.as_deref());
    }
    for edge in &snapshot.edges {
        update_i64(&mut hasher, edge.sqlite_edge_id);
        update_i64(&mut hasher, edge.source_node_id);
        update_i64(&mut hasher, edge.target_node_id);
        update_str(&mut hasher, &edge.edge_type);
        update_str(&mut hasher, &edge.local_name_gen);
        update_str(&mut hasher, &edge.properties_json);
    }
    for file_hash in &snapshot.file_hashes {
        update_str(&mut hasher, &file_hash.rel_path);
        update_str(&mut hasher, &file_hash.sha256);
        update_i64(&mut hasher, file_hash.mtime_ns);
        update_i64(&mut hasher, file_hash.size);
    }
    for summary in &snapshot.project_summaries {
        update_str(&mut hasher, &summary.summary);
        update_str(&mut hasher, &summary.source_hash);
        update_str(&mut hasher, &summary.created_at);
        update_str(&mut hasher, &summary.updated_at);
    }
    for token_vector in &snapshot.token_vectors {
        update_i64(&mut hasher, token_vector.id);
        update_str(&mut hasher, &token_vector.token);
        update_bytes(&mut hasher, &token_vector.vector);
        update_i64(&mut hasher, token_vector.idf);
    }
    hex_lower(&hasher.finalize())
}

fn update_str(hasher: &mut Sha256, value: &str) {
    update_bytes(hasher, value.as_bytes());
}

fn update_bytes_opt(hasher: &mut Sha256, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            hasher.update([1]);
            update_bytes(hasher, bytes);
        }
        None => hasher.update([0]),
    }
}

fn update_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn update_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_be_bytes());
}

fn update_opt_u32(hasher: &mut Sha256, value: Option<u32>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        None => hasher.update([0]),
    }
}

pub fn cbm_camel_split(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    const CAMEL_SPLIT_BUF: usize = 2048;
    const CAMEL_BUF_GUARD: usize = 2;
    if input.len() + 1 >= CAMEL_SPLIT_BUF {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity((input.len() * 2 + 1).min(CAMEL_SPLIT_BUF));
    out.extend_from_slice(bytes);
    out.push(b' ');
    for index in 0..bytes.len() {
        if out.len() >= CAMEL_SPLIT_BUF - CAMEL_BUF_GUARD {
            break;
        }
        if camel_should_split(bytes, index) {
            out.push(b' ');
        }
        out.push(bytes[index]);
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

fn camel_should_split(input: &[u8], index: usize) -> bool {
    if index == 0 {
        return false;
    }
    let curr = input[index];
    let prev = input[index - 1];
    let next = input.get(index + 1).copied().unwrap_or(0);
    curr.is_ascii_uppercase() && prev.is_ascii_lowercase()
        || curr.is_ascii_uppercase() && prev.is_ascii_uppercase() && next.is_ascii_lowercase()
}

fn sha256_digest(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_ref());
    hasher.finalize().into()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("hex write to String");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrolabe_ingest::{
        SqliteImportOptions, erase_imported_cx_graph_rows, import_sqlite_to_vault, verify_chain,
    };
    use astrolabe_panel::FixtureSlotRuntime;
    use calyx_aster::erase::{EraseRegistry, EraseScope};
    use calyx_aster::vault::{AsterVault, QuotaConfig, VaultContext, VaultOptions};
    use calyx_core::{SystemClock, VaultId};
    use rusqlite::Connection;
    use serde_json::Value;
    use std::io::Cursor;

    #[test]
    fn identifies_cbm_parent() {
        assert_eq!(
            parent_system(),
            astrolabe_domain::ParentSystem::CodebaseMemoryMcp
        );
    }

    #[test]
    fn camel_split_matches_cbm_cases() {
        assert_eq!(
            cbm_camel_split("updateCloudClient"),
            "updateCloudClient update Cloud Client"
        );
        assert_eq!(cbm_camel_split("XMLParser"), "XMLParser XML Parser");
        assert_eq!(cbm_camel_split(""), "");
    }

    #[test]
    fn lower_roundtrips_nodes_edges_fts_vectors_and_is_deterministic() {
        let source = temp_path("source.db");
        let lowered_a = temp_path("lowered-a.db");
        let lowered_b = temp_path("lowered-b.db");
        fixture_sqlite(&source);

        let source_vault = vault();
        let import_report = import_sqlite_to_vault(
            &source,
            &source_vault,
            &FixtureSlotRuntime,
            &SqliteImportOptions::new("demo", "commit-a", 1),
        )
        .expect("import source sqlite");

        let options = LowerSqliteOptions::new("demo");
        let report_a = lower_cbm_sqlite(&source_vault, &lowered_a, &options).expect("lower a");
        let report_b = lower_cbm_sqlite(&source_vault, &lowered_b, &options).expect("lower b");
        assert_eq!(report_a.node_count, 3);
        assert_eq!(report_a.edge_count, 3);
        assert_eq!(report_a.skipped_edges, 0);
        assert_eq!(report_a.file_hash_count, 1);
        assert_eq!(report_a.project_summary_count, 1);
        assert_eq!(report_a.node_vector_count, 1);
        assert_eq!(report_a.token_vector_count, 1);
        assert_eq!(report_a.artifact_sha256, report_b.artifact_sha256);
        assert_eq!(
            fs::read(&lowered_a).expect("read lowered a"),
            fs::read(&lowered_b).expect("read lowered b")
        );

        verify_lowered_sqlite(&lowered_a, &report_a);

        let roundtrip_vault = vault();
        let roundtrip = import_sqlite_to_vault(
            &lowered_a,
            &roundtrip_vault,
            &FixtureSlotRuntime,
            &SqliteImportOptions::new("demo", "commit-b", 1),
        )
        .expect("roundtrip import");
        let mut original_ids = import_report.cx_ids;
        let mut roundtrip_ids = roundtrip.cx_ids;
        original_ids.sort();
        roundtrip_ids.sort();
        assert_eq!(original_ids, roundtrip_ids);

        cleanup(&source);
        cleanup(&lowered_a);
        cleanup(&lowered_b);
    }

    #[test]
    fn lower_refuses_legacy_vault_missing_raw_cbm_edge_rows() {
        use calyx_aster::cf::prefix_range;
        use calyx_aster::mvcc::tombstone_value;

        // On-disk raw CBM edge row prefix owned by astrolabe-ingest. A modern
        // import persists one raw row per source edge; a legacy vault imported
        // before that schema landed carries only typed astrolabe:edge:v1 rows.
        // Lowering such a vault must fail closed rather than silently drop the
        // dangling and structural-endpoint edges the typed rows never contained.
        const CBM_EDGE_ROW_PREFIX: &[u8] = b"astrolabe:cbm-edge:v1:";

        let source = temp_path("legacy-source.db");
        let lowered = temp_path("legacy-lowered.db");
        fixture_sqlite(&source);
        let source_vault = vault();
        import_sqlite_to_vault(
            &source,
            &source_vault,
            &FixtureSlotRuntime,
            &SqliteImportOptions::new("demo", "commit-legacy", 1),
        )
        .expect("import source sqlite");

        // Baseline: the modern vault lowers cleanly.
        lower_cbm_sqlite(&source_vault, &lowered, &LowerSqliteOptions::new("demo"))
            .expect("lower modern vault");

        // Downgrade to a legacy vault by tombstoning every raw CBM edge row.
        let tombstone = tombstone_value();
        let raw_rows = source_vault
            .scan_cf_range_at(
                source_vault.latest_seq(),
                ColumnFamily::Graph,
                &prefix_range(CBM_EDGE_ROW_PREFIX),
            )
            .expect("scan raw cbm edge rows");
        assert!(
            !raw_rows.is_empty(),
            "fixture must persist raw cbm edge rows to downgrade"
        );
        let downgrade = raw_rows
            .into_iter()
            .map(|(key, _)| (ColumnFamily::Graph, key, tombstone.clone()))
            .collect::<Vec<_>>();
        source_vault
            .write_cf_batch_with_ledger_entry(
                downgrade,
                EntryKind::Admin,
                SubjectId::Query(b"astro-lower-legacy-edge-downgrade".to_vec()),
                serde_json::to_vec(&json!({"schema": "astrolabe-legacy-edge-downgrade-test"}))
                    .expect("encode downgrade payload"),
                ActorId::Service(ASTRO_LOWER_ACTOR.to_string()),
            )
            .expect("tombstone raw cbm edge rows");
        source_vault
            .purge_tombstoned_cfs(&[ColumnFamily::Graph])
            .expect("purge tombstoned raw cbm edge rows");

        let err = lower_cbm_sqlite(&source_vault, &lowered, &LowerSqliteOptions::new("demo"))
            .expect_err("lowering a legacy vault must refuse");
        assert_eq!(
            err.code(),
            Some(astrolabe_ingest::ASTRO_LEGACY_CBM_EDGE_ROWS)
        );
        assert!(
            err.remediation().is_some(),
            "legacy-edge refusal must carry operator remediation"
        );

        cleanup(&source);
        cleanup(&lowered);
    }

    #[test]
    fn erasure_regenerates_lowered_sqlite_without_erased_bytes() {
        let source = temp_path("erasure-source.db");
        let before_lowered = temp_path("erasure-before.db");
        let after_lowered = temp_path("erasure-after.db");
        let (vault_dir, source_vault) = durable_vault("erasure-regeneration");
        const SENTINEL: &str = "erasemeph61token";
        fixture_sqlite_with_erased_sentinel(&source, SENTINEL);

        let import_report = import_sqlite_to_vault(
            &source,
            &source_vault,
            &FixtureSlotRuntime,
            &SqliteImportOptions::new("demo", "commit-erasure", 1),
        )
        .expect("import source sqlite");
        source_vault.flush().expect("flush imported durable vault");
        assert_eq!(import_report.cx_ids.len(), 3);
        assert!(
            !path_tree_byte_hits(&vault_dir, SENTINEL.as_bytes()).is_empty(),
            "sentinel must be present in durable vault before erasure"
        );

        let options = LowerSqliteOptions::new("demo");
        let before_report =
            lower_cbm_sqlite(&source_vault, &before_lowered, &options).expect("lower before erase");
        assert_eq!(before_report.node_count, 3);
        assert_eq!(before_report.edge_count, 3);
        assert!(
            bytes_contain(
                &fs::read(&before_lowered).expect("read before lowered"),
                SENTINEL.as_bytes()
            ),
            "sentinel must be materialized in the pre-erasure lowered artifact"
        );
        assert_eq!(sqlite_sentinel_hits(&before_lowered, SENTINEL), (1, 1));

        let erased_cx = import_report.cx_ids[1];
        let mut context = VaultContext::new(
            source_vault.vault_id(),
            b"astrolabe-lower-erasure-fsv",
            QuotaConfig::default(),
            "astrolabe-lower-test",
        )
        .expect("create erasure context");
        let erase = source_vault
            .erase(
                EraseScope::Cx(erased_cx),
                &mut context,
                &EraseRegistry::new(),
            )
            .expect("erase imported cx");
        assert_eq!(erase.records_deleted, 1);
        assert!(context.is_key_shredded_for_erasure());

        let graph_erase =
            erase_imported_cx_graph_rows(&source_vault, "demo", erased_cx).expect("erase graph");
        assert_eq!(graph_erase.node_map_rows_tombstoned, 1);
        assert_eq!(graph_erase.edge_rows_tombstoned, 2);
        assert_eq!(graph_erase.raw_edge_rows_tombstoned, 2);

        let after_report =
            lower_cbm_sqlite(&source_vault, &after_lowered, &options).expect("lower after erase");
        assert_eq!(after_report.node_count, 2);
        assert_eq!(after_report.edge_count, 1);
        assert_eq!(after_report.skipped_edges, 0);
        assert_ne!(after_report.artifact_sha256, before_report.artifact_sha256);

        let after_bytes = fs::read(&after_lowered).expect("read after lowered");
        assert!(
            !bytes_contain(&after_bytes, SENTINEL.as_bytes()),
            "regenerated lowered artifact retained erased sentinel bytes"
        );
        assert_eq!(sqlite_sentinel_hits(&after_lowered, SENTINEL), (0, 0));

        source_vault
            .flush()
            .expect("flush post-erasure durable vault");
        let durable_hits = path_tree_byte_hits(&vault_dir, SENTINEL.as_bytes());
        assert!(
            durable_hits
                .iter()
                .all(|path| path_is_under_child(&vault_dir, path, "wal")),
            "non-WAL durable vault files retained erased sentinel bytes: {durable_hits:?}"
        );
        let chain = verify_chain(&source_vault).expect("verify chain after graph erasure");
        assert_eq!(chain.status, "intact");

        cleanup(&source);
        cleanup(&before_lowered);
        cleanup(&after_lowered);
        cleanup_dir(&vault_dir);
    }

    #[test]
    fn signed_team_artifact_import_verifies_and_adopts_identical_graph() {
        let fixture = team_fixture(
            "team-signed",
            &TeamArtifactExportOptions::with_signing_key([7; 32]),
        );
        let adopted = temp_path("team-signed-adopted.db");
        cleanup(&adopted);

        let signer = hex_to_32(
            &fixture
                .export
                .manifest
                .signature
                .as_ref()
                .expect("signed manifest")
                .signer_pubkey_hex,
        );
        let report = import_team_artifact(
            &fixture.artifact_dir,
            &adopted,
            &TeamArtifactImportOptions::with_expected_signer(signer),
        )
        .expect("import signed team artifact");

        assert_eq!(report.mode, "chain_verified_vault_export");
        assert_eq!(report.signature_status, "verified");
        assert_eq!(
            report.merkle_root,
            fixture.export.manifest.merkle_root.clone()
        );
        assert_eq!(
            fs::read(&adopted).expect("read adopted graph"),
            fs::read(&fixture.lowered).expect("read source lowered graph")
        );
        verify_lowered_sqlite(&adopted, &fixture.lower_report);

        // #84 full-state verification of the graph-binding attestation, read
        // from the actual persisted ledger bytes in the bundled vault export.
        // The digest MUST be the full 64-hex SHA-256 under the Calyx-allowlisted
        // `artifact_sha256` field name: a bare `artifact` field is rejected by
        // the ledger secret hook (CALYX_LEDGER_SECRET_IN_PAYLOAD), and a
        // truncated prefix would reopen the ~2^64 second-preimage gap.
        let attestation = team_artifact::asl_v1_attestation_payload(&fixture.artifact_dir);
        let bound_digest = attestation
            .get("artifact_sha256")
            .and_then(serde_json::Value::as_str)
            .expect("asl_v1 attestation must carry the artifact_sha256 field");
        assert_eq!(
            bound_digest.len(),
            64,
            "artifact_sha256 must be the full 64-hex SHA-256, not a truncated prefix"
        );
        assert!(
            bound_digest.chars().all(|ch| ch.is_ascii_hexdigit()),
            "artifact_sha256 must be lowercase hex"
        );
        assert_eq!(
            bound_digest, fixture.export.manifest.graph_db_sha256,
            "ledger attestation must commit to the exact lowered graph bytes"
        );
        assert!(
            attestation.get("artifact").is_none(),
            "must not use the bare `artifact` field — Calyx secret hook rejects a bare 64-hex token"
        );

        let wrong = import_team_artifact(
            &fixture.artifact_dir,
            temp_path("team-signed-wrong-key.db"),
            &TeamArtifactImportOptions::with_expected_signer([9; 32]),
        )
        .expect_err("wrong signer is refused");
        assert_err_code(&wrong, ASTRO_TEAM_ARTIFACT_SIGNATURE_SIGNER);

        cleanup_team_fixture(&fixture);
        cleanup(&adopted);
    }

    #[test]
    fn unsigned_team_artifact_import_is_labeled() {
        let fixture = team_fixture("team-unsigned", &TeamArtifactExportOptions::unsigned());
        let adopted = temp_path("team-unsigned-adopted.db");
        cleanup(&adopted);

        let report = import_team_artifact(
            &fixture.artifact_dir,
            &adopted,
            &TeamArtifactImportOptions::new(),
        )
        .expect("import unsigned team artifact");

        assert!(fixture.export.manifest.unsigned_artifact);
        assert!(fixture.export.manifest.signature.is_none());
        assert_eq!(report.signature_status, "unsigned");
        assert_eq!(
            fs::read(&adopted).expect("read adopted graph"),
            fs::read(&fixture.lowered).expect("read lowered graph")
        );

        cleanup_team_fixture(&fixture);
        cleanup(&adopted);
    }

    #[test]
    fn team_artifact_tamper_matrix_names_refused_component() {
        let vault_bytes = team_fixture("team-tamper-vault", &TeamArtifactExportOptions::unsigned());
        flip_first_byte(&vault_bytes.artifact_dir.join(VAULT_EXPORT_ZST_NAME));
        let err = import_team_artifact(
            &vault_bytes.artifact_dir,
            temp_path("team-tamper-vault-adopt.db"),
            &TeamArtifactImportOptions::new(),
        )
        .expect_err("vault bytes tamper refused");
        assert_err_code(&err, ASTRO_TEAM_ARTIFACT_VAULT_BYTES);
        cleanup_team_fixture(&vault_bytes);

        let ledger_tail =
            team_fixture("team-tamper-ledger", &TeamArtifactExportOptions::unsigned());
        rewrite_vault_export_json(&ledger_tail.artifact_dir, |value| {
            value["ledger_rows"]
                .as_array_mut()
                .expect("ledger rows")
                .pop();
        });
        let err = import_team_artifact(
            &ledger_tail.artifact_dir,
            temp_path("team-tamper-ledger-adopt.db"),
            &TeamArtifactImportOptions::new(),
        )
        .expect_err("ledger tail tamper refused");
        assert_err_code(&err, ASTRO_TEAM_ARTIFACT_LEDGER_TAIL);
        cleanup_team_fixture(&ledger_tail);

        let merkle = team_fixture("team-tamper-merkle", &TeamArtifactExportOptions::unsigned());
        rewrite_manifest_json(&merkle.artifact_dir, |value| {
            value["merkle_root"] = Value::String("00".repeat(32));
        });
        let err = import_team_artifact(
            &merkle.artifact_dir,
            temp_path("team-tamper-merkle-adopt.db"),
            &TeamArtifactImportOptions::new(),
        )
        .expect_err("merkle root tamper refused");
        assert_err_code(&err, ASTRO_TEAM_ARTIFACT_MERKLE_ROOT);
        cleanup_team_fixture(&merkle);

        let signature = team_fixture(
            "team-tamper-signature",
            &TeamArtifactExportOptions::with_signing_key([11; 32]),
        );
        rewrite_manifest_json(&signature.artifact_dir, |value| {
            let signature_hex = value["signature"]["signature_hex"]
                .as_str()
                .expect("signature hex");
            let (first, rest) = signature_hex.split_at(1);
            let replacement = if first == "0" {
                format!("1{rest}")
            } else {
                format!("0{rest}")
            };
            value["signature"]["signature_hex"] = Value::String(replacement);
        });
        let err = import_team_artifact(
            &signature.artifact_dir,
            temp_path("team-tamper-signature-adopt.db"),
            &TeamArtifactImportOptions::new(),
        )
        .expect_err("signature tamper refused");
        assert_err_code(&err, ASTRO_TEAM_ARTIFACT_SIGNATURE);
        cleanup_team_fixture(&signature);
    }

    #[test]
    fn coordinated_graph_tamper_on_signed_artifact_is_refused() {
        // #84 regression / synthetic full-state verification.
        //
        // The Ed25519 signature covers only the ledger Merkle root, so an
        // attacker who swaps graph.db.zst AND rewrites the matching hash fields
        // in the *unsigned* artifact.json previously imported with
        // signature_status="verified". The graph is now bound to the signed
        // ledger via the asl_v1 lowering attestation, so the swap must be
        // refused before any graph is adopted.
        let fixture = team_fixture(
            "team-coordinated-signed",
            &TeamArtifactExportOptions::with_signing_key([23; 32]),
        );

        // Baseline: the untampered signed artifact still imports as verified
        // (proves the new binding check does not regress the honest path).
        let baseline_adopted = temp_path("team-coordinated-signed-baseline.db");
        cleanup(&baseline_adopted);
        let baseline = import_team_artifact(
            &fixture.artifact_dir,
            &baseline_adopted,
            &TeamArtifactImportOptions::new(),
        )
        .expect("baseline untampered signed import");
        assert_eq!(baseline.signature_status, "verified");
        assert_eq!(
            baseline.graph_db_sha256, fixture.export.manifest.graph_db_sha256,
            "baseline adopts the legitimate graph"
        );

        // Attacker payload: a valid but *different* SQLite file the importer
        // would happily adopt if the swap were undetected.
        let malicious = temp_path("team-coordinated-signed-malicious.db");
        fixture_sqlite(&malicious);
        let malicious_bytes = fs::read(&malicious).expect("read malicious graph");
        let malicious_hash = hex_lower(&sha256_digest(&malicious_bytes));
        assert_ne!(
            malicious_hash, fixture.export.manifest.graph_db_sha256,
            "attacker graph must differ from the legitimate graph"
        );

        coordinated_graph_swap(&fixture.artifact_dir, &malicious_bytes);

        // Prove the artifact is now internally self-consistent (the graph bytes
        // match the rewritten unsigned manifest) — i.e. the OLD graph-bytes check
        // would pass. Only the signed-ledger binding catches the tamper.
        let post_manifest: Value = serde_json::from_slice(
            &fs::read(fixture.artifact_dir.join("artifact.json")).expect("read tampered manifest"),
        )
        .expect("decode tampered manifest");
        assert_eq!(
            post_manifest["graph_db_sha256"].as_str(),
            Some(malicious_hash.as_str()),
            "coordinated tamper rewrote the manifest graph hash to the malicious graph"
        );

        let adopted = temp_path("team-coordinated-signed-adopt.db");
        cleanup(&adopted);
        let err = import_team_artifact(
            &fixture.artifact_dir,
            &adopted,
            &TeamArtifactImportOptions::new(),
        )
        .expect_err("coordinated graph tamper on signed artifact must be refused");
        assert_err_code(&err, ASTRO_TEAM_ARTIFACT_GRAPH_ATTESTATION);

        // Full-state verification against the source of truth (the filesystem):
        // the refused import must NOT have written the malicious graph anywhere.
        assert!(
            !adopted.exists(),
            "refused import must not adopt the malicious graph to disk"
        );

        cleanup(&malicious);
        cleanup(&baseline_adopted);
        cleanup(&adopted);
        cleanup_team_fixture(&fixture);
    }

    #[test]
    fn coordinated_graph_tamper_on_unsigned_artifact_is_refused() {
        // Same coordinated swap on an unsigned artifact: the graph must still be
        // bound to the (chain-verified) ledger's asl_v1 attestation and refused.
        let fixture = team_fixture(
            "team-coordinated-unsigned",
            &TeamArtifactExportOptions::unsigned(),
        );

        let malicious = temp_path("team-coordinated-unsigned-malicious.db");
        fixture_sqlite(&malicious);
        let malicious_bytes = fs::read(&malicious).expect("read malicious graph");
        assert_ne!(
            hex_lower(&sha256_digest(&malicious_bytes)),
            fixture.export.manifest.graph_db_sha256,
            "attacker graph must differ from the legitimate graph"
        );

        coordinated_graph_swap(&fixture.artifact_dir, &malicious_bytes);

        let adopted = temp_path("team-coordinated-unsigned-adopt.db");
        cleanup(&adopted);
        let err = import_team_artifact(
            &fixture.artifact_dir,
            &adopted,
            &TeamArtifactImportOptions::new(),
        )
        .expect_err("coordinated graph tamper on unsigned artifact must be refused");
        assert_err_code(&err, ASTRO_TEAM_ARTIFACT_GRAPH_ATTESTATION);
        assert!(
            !adopted.exists(),
            "refused import must not adopt the malicious graph to disk"
        );

        cleanup(&malicious);
        cleanup(&adopted);
        cleanup_team_fixture(&fixture);
    }

    #[test]
    fn malformed_signature_hex_is_signature_coded_not_vault_bytes() {
        let fixture = team_fixture(
            "team-malformed-sig-hex",
            &TeamArtifactExportOptions::with_signing_key([13; 32]),
        );
        // Inject a non-hex byte into the signature hex while keeping even length,
        // so decoding fails on the signature field specifically (not the vault
        // export container). This is the exact taxonomy bug from #132: the hex
        // decoder used to hardcode the vault-bytes component code.
        rewrite_manifest_json(&fixture.artifact_dir, |value| {
            let signature_hex = value["signature"]["signature_hex"]
                .as_str()
                .expect("signature hex");
            assert!(
                signature_hex.len().is_multiple_of(2),
                "fixture signature hex must have even length"
            );
            let mutated = format!("z{}", &signature_hex[1..]);
            assert_eq!(
                mutated.len(),
                signature_hex.len(),
                "mutation must preserve even hex length"
            );
            value["signature"]["signature_hex"] = Value::String(mutated);
        });

        let err = import_team_artifact(
            &fixture.artifact_dir,
            temp_path("team-malformed-sig-hex-adopt.db"),
            &TeamArtifactImportOptions::new(),
        )
        .expect_err("malformed signature hex is refused");

        assert_ne!(
            err.code(),
            Some(ASTRO_TEAM_ARTIFACT_VAULT_BYTES),
            "malformed signature hex must NOT carry the vault-bytes component code"
        );
        assert_refusal(
            &err,
            ASTRO_TEAM_ARTIFACT_SIGNATURE,
            "signature contains non-hex bytes",
            "Re-export the team artifact with a valid signature over the ledger Merkle root, \
             or import without an expected signer if the artifact is intentionally unsigned.",
        );

        cleanup_team_fixture(&fixture);
    }

    #[test]
    fn corrupt_vault_bytes_refusal_carries_exact_contract() {
        let fixture = team_fixture(
            "team-corrupt-vault-bytes",
            &TeamArtifactExportOptions::unsigned(),
        );
        // Corrupt the real compressed vault export bytes without updating the
        // manifest hash, so the vault-bytes integrity check refuses the import.
        flip_first_byte(&fixture.artifact_dir.join(VAULT_EXPORT_ZST_NAME));

        let err = import_team_artifact(
            &fixture.artifact_dir,
            temp_path("team-corrupt-vault-bytes-adopt.db"),
            &TeamArtifactImportOptions::new(),
        )
        .expect_err("corrupt vault bytes is refused");

        assert_refusal(
            &err,
            ASTRO_TEAM_ARTIFACT_VAULT_BYTES,
            "vault.export.zst compressed bytes do not match artifact.json",
            "Re-export the team artifact; vault.export.zst is missing, corrupt, \
             or does not match artifact.json.",
        );
        assert_eq!(
            err.remediation(),
            Some(
                "Re-export the team artifact; vault.export.zst is missing, corrupt, \
                 or does not match artifact.json."
            ),
            "structured remediation accessor must expose the vault-bytes remediation"
        );

        cleanup_team_fixture(&fixture);
    }

    #[test]
    fn legacy_plain_graph_db_zst_imports_without_vault_export() {
        let source = temp_path("team-legacy-source.db");
        let lowered = temp_path("team-legacy-lowered.db");
        let artifact_dir = temp_dir_path("team-legacy-artifact");
        let adopted = temp_path("team-legacy-adopted.db");
        fixture_sqlite(&source);
        let source_vault = vault();
        import_sqlite_to_vault(
            &source,
            &source_vault,
            &FixtureSlotRuntime,
            &SqliteImportOptions::new("demo", "commit-a", 1),
        )
        .expect("import source sqlite");
        let lower_report =
            lower_cbm_sqlite(&source_vault, &lowered, &LowerSqliteOptions::new("demo"))
                .expect("lower sqlite");

        fs::create_dir_all(&artifact_dir).expect("create legacy artifact dir");
        let graph_bytes = fs::read(&lowered).expect("read lowered graph");
        let graph_zst =
            zstd::stream::encode_all(Cursor::new(&graph_bytes), 3).expect("encode legacy graph");
        fs::write(artifact_dir.join(GRAPH_DB_ZST_NAME), graph_zst).expect("write graph.db.zst");

        let report =
            import_team_artifact(&artifact_dir, &adopted, &TeamArtifactImportOptions::new())
                .expect("legacy import");

        assert_eq!(report.mode, "legacy_plain_graph_db_zst");
        assert_eq!(report.signature_status, "legacy_unverified");
        assert_eq!(
            report.fallback,
            Some("local_reindex_if_graph_rejected".to_string())
        );
        assert_eq!(
            fs::read(&adopted).expect("read adopted"),
            fs::read(&lowered).expect("read lowered")
        );
        verify_lowered_sqlite(&adopted, &lower_report);

        cleanup(&source);
        cleanup(&lowered);
        cleanup(&adopted);
        cleanup_dir(&artifact_dir);
    }

    fn verify_lowered_sqlite(path: &Path, report: &LoweredSqliteReport) {
        let connection = Connection::open(path).expect("open lowered db");
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("integrity check");
        assert_eq!(integrity, "ok");

        let nodes: Vec<(i64, String)> = query_pairs(
            &connection,
            "SELECT id, qualified_name FROM nodes ORDER BY id",
        );
        assert_eq!(
            nodes,
            vec![
                (1, "demo.src.main.__file__".to_string()),
                (2, "demo.src.main.alpha".to_string()),
                (3, "demo.src.main.beta".to_string()),
            ]
        );

        let calls: String = connection
            .query_row(
                "SELECT s.name || '->' || t.name FROM edges e \
                 JOIN nodes s ON s.id=e.source_id JOIN nodes t ON t.id=e.target_id \
                 WHERE e.type='CALLS'",
                [],
                |row| row.get(0),
            )
            .expect("calls edge");
        assert_eq!(calls, "alpha->beta");

        let imports_local: String = connection
            .query_row(
                "SELECT local_name_gen FROM edges WHERE type='IMPORTS'",
                [],
                |row| row.get(0),
            )
            .expect("imports local name");
        assert_eq!(imports_local, "Thing");

        let fts_hits: i64 = connection
            .query_row(
                "SELECT count(*) FROM nodes_fts WHERE nodes_fts MATCH 'alpha'",
                [],
                |row| row.get(0),
            )
            .expect("fts query");
        assert!(fts_hits >= 1);

        let vector: Vec<u8> = connection
            .query_row(
                "SELECT v.vector FROM node_vectors v JOIN nodes n ON n.id=v.node_id WHERE n.name='alpha'",
                [],
                |row| row.get(0),
            )
            .expect("node vector");
        assert_eq!(vector, vec![1, 2, 3, 4]);

        let token_count: i64 = connection
            .query_row("SELECT count(*) FROM token_vectors", [], |row| row.get(0))
            .expect("token vector count");
        assert_eq!(token_count, 1);

        let file_hash_count: i64 = connection
            .query_row("SELECT count(*) FROM file_hashes", [], |row| row.get(0))
            .expect("file hash count");
        assert_eq!(file_hash_count, 1);

        let summary_count: i64 = connection
            .query_row("SELECT count(*) FROM project_summaries", [], |row| {
                row.get(0)
            })
            .expect("summary count");
        assert_eq!(summary_count, 1);

        let meta: (String, String, String, i64, String) = connection
            .query_row(
                "SELECT schema, vault_fingerprint, ledger_head_hash, panel_version, lowered_at FROM astro_meta",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .expect("astro_meta");
        assert_eq!(meta.0, ASTRO_META_SCHEMA);
        assert_eq!(meta.1, report.vault_fingerprint_sha256);
        assert_eq!(meta.2, report.source_ledger_head_hash);
        assert_eq!(meta.3, 1);
        assert_eq!(meta.4, DEFAULT_LOWERED_AT);
    }

    struct TeamFixture {
        source: PathBuf,
        lowered: PathBuf,
        artifact_dir: PathBuf,
        lower_report: LoweredSqliteReport,
        export: TeamArtifactExportReport,
    }

    fn team_fixture(name: &str, options: &TeamArtifactExportOptions) -> TeamFixture {
        let source = temp_path(&format!("{name}-source.db"));
        let lowered = temp_path(&format!("{name}-lowered.db"));
        let artifact_dir = temp_dir_path(&format!("{name}-artifact"));
        fixture_sqlite(&source);

        let source_vault = vault();
        import_sqlite_to_vault(
            &source,
            &source_vault,
            &FixtureSlotRuntime,
            &SqliteImportOptions::new("demo", "commit-a", 1),
        )
        .expect("import source sqlite");
        let lower_report =
            lower_cbm_sqlite(&source_vault, &lowered, &LowerSqliteOptions::new("demo"))
                .expect("lower sqlite");
        let export = export_team_artifact(&source_vault, &lowered, &artifact_dir, options)
            .expect("export team artifact");
        TeamFixture {
            source,
            lowered,
            artifact_dir,
            lower_report,
            export,
        }
    }

    fn cleanup_team_fixture(fixture: &TeamFixture) {
        cleanup(&fixture.source);
        cleanup(&fixture.lowered);
        cleanup_dir(&fixture.artifact_dir);
    }

    fn flip_first_byte(path: &Path) {
        let mut bytes = fs::read(path).expect("read file to tamper");
        bytes[0] ^= 0x01;
        fs::write(path, bytes).expect("write tampered file");
    }

    fn rewrite_vault_export_json<F>(artifact_dir: &Path, mutate: F)
    where
        F: FnOnce(&mut Value),
    {
        let path = artifact_dir.join(VAULT_EXPORT_ZST_NAME);
        let bytes = fs::read(&path).expect("read vault export");
        let decoded = zstd::stream::decode_all(Cursor::new(&bytes)).expect("decode vault export");
        let mut value: Value = serde_json::from_slice(&decoded).expect("decode export JSON");
        mutate(&mut value);
        let next_json = serde_json::to_vec(&value).expect("encode mutated export JSON");
        let next_zst =
            zstd::stream::encode_all(Cursor::new(&next_json), 3).expect("encode vault export");
        fs::write(&path, &next_zst).expect("write vault export");
        rewrite_manifest_json(artifact_dir, |manifest| {
            manifest["vault_export_zst_sha256"] =
                Value::String(hex_lower(&sha256_digest(&next_zst)));
        });
    }

    /// Simulates the #84 coordinated tamper: replace the compressed graph with
    /// attacker-chosen bytes and rewrite the *unsigned* artifact.json so its
    /// self-consistency checks (`graph_db_zst_sha256` / `graph_db_sha256`) still
    /// pass. The ledger, Merkle root, and any signature are left untouched.
    fn coordinated_graph_swap(artifact_dir: &Path, malicious_graph: &[u8]) {
        let graph_zst = zstd::stream::encode_all(Cursor::new(malicious_graph), 3)
            .expect("encode malicious graph");
        fs::write(artifact_dir.join(GRAPH_DB_ZST_NAME), &graph_zst)
            .expect("write malicious graph.db.zst");
        let zst_hash = hex_lower(&sha256_digest(&graph_zst));
        let raw_hash = hex_lower(&sha256_digest(malicious_graph));
        rewrite_manifest_json(artifact_dir, move |value| {
            value["graph_db_zst_sha256"] = Value::String(zst_hash);
            value["graph_db_sha256"] = Value::String(raw_hash);
        });
    }

    fn rewrite_manifest_json<F>(artifact_dir: &Path, mutate: F)
    where
        F: FnOnce(&mut Value),
    {
        let path = artifact_dir.join("artifact.json");
        let bytes = fs::read(&path).expect("read manifest");
        let mut value: Value = serde_json::from_slice(&bytes).expect("decode manifest");
        mutate(&mut value);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&value).expect("encode manifest"),
        )
        .expect("write manifest");
    }

    fn assert_err_code(error: &LowerError, code: &str) {
        assert_eq!(
            error.code(),
            Some(code),
            "expected structured refusal code {code}, got error {error:?}"
        );
    }

    fn assert_refusal(error: &LowerError, code: &str, message: &str, remediation: &str) {
        match error {
            LowerError::Refused {
                code: got_code,
                message: got_message,
                remediation: got_remediation,
            } => {
                assert_eq!(*got_code, code, "refusal code");
                assert_eq!(got_message, message, "refusal message");
                assert_eq!(*got_remediation, remediation, "refusal remediation");
            }
            other => panic!("expected structured LowerError::Refused, got {other:?}"),
        }
    }

    fn hex_to_32(input: &str) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (index, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
            out[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
        }
        out
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("non-hex byte"),
        }
    }

    fn query_pairs(connection: &Connection, sql: &str) -> Vec<(i64, String)> {
        let mut statement = connection.prepare(sql).expect("prepare query");
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query map")
            .map(|row| row.expect("query row"))
            .collect()
    }

    fn fixture_sqlite(path: &Path) {
        cleanup(path);
        let connection = Connection::open(path).expect("open fixture db");
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
            .expect("create fixture schema");
        connection
            .execute(
                "INSERT INTO projects(name, indexed_at, root_path) VALUES ('demo', '2026-03-14T00:00:00Z', '/repo')",
                [],
            )
            .expect("project");
        connection
            .execute(
                "INSERT INTO file_hashes(project, rel_path, sha256, mtime_ns, size) VALUES ('demo', 'src/main.rs', ?1, 10, 20)",
                ["00".repeat(32)],
            )
            .expect("file hash");
        insert_node(
            &connection,
            &FixtureNode {
                label: "File",
                name: "__file__",
                qualified_name: "demo.src.main.__file__",
                file_path: "src/main.rs",
                start_line: 1,
                end_line: 30,
                properties: r#"{"language":"rust","source_snippet":"mod main","signature":"mod main"}"#,
            },
        );
        insert_node(
            &connection,
            &FixtureNode {
                label: "Function",
                name: "alpha",
                qualified_name: "demo.src.main.alpha",
                file_path: "src/main.rs",
                start_line: 3,
                end_line: 8,
                properties: r#"{"language":"rust","source_snippet":"fn alpha(){ beta(); }","signature":"fn alpha()","complexity":2}"#,
            },
        );
        insert_node(
            &connection,
            &FixtureNode {
                label: "Function",
                name: "beta",
                qualified_name: "demo.src.main.beta",
                file_path: "src/main.rs",
                start_line: 10,
                end_line: 12,
                properties: r#"{"language":"rust","source_snippet":"fn beta() {}","signature":"fn beta()"}"#,
            },
        );
        connection
            .execute(
                "INSERT INTO node_vectors(node_id, project, vector) VALUES (2, 'demo', ?1)",
                [vec![1_u8, 2, 3, 4]],
            )
            .expect("node vector");
        connection
            .execute(
                "INSERT INTO token_vectors(id, project, token, vector, idf) VALUES (1, 'demo', 'alpha', ?1, 123)",
                [vec![9_u8, 8, 7]],
            )
            .expect("token vector");
        connection
            .execute(
                "INSERT INTO edges(project, source_id, target_id, type, properties) VALUES ('demo', 1, 2, 'DEFINES', '{}')",
                [],
            )
            .expect("defines");
        connection
            .execute(
                "INSERT INTO edges(project, source_id, target_id, type, properties) VALUES ('demo', 2, 3, 'CALLS', '{\"callee\":\"beta\"}')",
                [],
            )
            .expect("calls");
        connection
            .execute(
                "INSERT INTO edges(project, source_id, target_id, type, properties) VALUES ('demo', 1, 3, 'IMPORTS', '{\"local_name\":\"Thing\"}')",
                [],
            )
            .expect("imports");
        connection
            .execute(
                "INSERT INTO project_summaries(project, summary, source_hash, created_at, updated_at)
                 VALUES ('demo', 'summary', 'hash', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z')",
                [],
            )
            .expect("summary");
    }

    fn fixture_sqlite_with_erased_sentinel(path: &Path, sentinel: &str) {
        cleanup(path);
        let connection = Connection::open(path).expect("open erasure fixture db");
        connection
            .execute_batch(
                "CREATE TABLE projects (
                   name TEXT PRIMARY KEY,
                   indexed_at TEXT NOT NULL,
                   root_path TEXT NOT NULL
                 );
                 CREATE TABLE nodes (
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
                 );",
            )
            .expect("create erasure fixture schema");
        connection
            .execute(
                "INSERT INTO projects(name, indexed_at, root_path)
                 VALUES ('demo', '2026-03-14T00:00:00Z', '/repo')",
                [],
            )
            .expect("project");
        insert_node(
            &connection,
            &FixtureNode {
                label: "File",
                name: "__file__",
                qualified_name: "demo.src.main.__file__",
                file_path: "src/main.rs",
                start_line: 1,
                end_line: 40,
                properties: r#"{"language":"rust","source_snippet":"mod main"}"#,
            },
        );
        insert_node(
            &connection,
            &FixtureNode {
                label: "Function",
                name: sentinel,
                qualified_name: "demo.src.main.erasemeph61token",
                file_path: "src/main.rs",
                start_line: 4,
                end_line: 12,
                properties: r#"{"language":"rust","source_snippet":"fn erasemeph61token(){ kept_beta(); }","signature":"fn erasemeph61token()"}"#,
            },
        );
        insert_node(
            &connection,
            &FixtureNode {
                label: "Function",
                name: "kept_beta",
                qualified_name: "demo.src.main.kept_beta",
                file_path: "src/main.rs",
                start_line: 20,
                end_line: 24,
                properties: r#"{"language":"rust","source_snippet":"fn kept_beta() {}","signature":"fn kept_beta()"}"#,
            },
        );
        connection
            .execute(
                "INSERT INTO edges(project, source_id, target_id, type, properties)
                 VALUES ('demo', 1, 2, 'DEFINES', '{}')",
                [],
            )
            .expect("defines erased");
        connection
            .execute(
                "INSERT INTO edges(project, source_id, target_id, type, properties)
                 VALUES ('demo', 2, 3, 'CALLS', '{\"callee\":\"kept_beta\"}')",
                [],
            )
            .expect("calls erased");
        connection
            .execute(
                "INSERT INTO edges(project, source_id, target_id, type, properties)
                 VALUES ('demo', 1, 3, 'DEFINES', '{}')",
                [],
            )
            .expect("defines kept");
    }

    struct FixtureNode<'a> {
        label: &'a str,
        name: &'a str,
        qualified_name: &'a str,
        file_path: &'a str,
        start_line: i64,
        end_line: i64,
        properties: &'a str,
    }

    fn insert_node(connection: &Connection, node: &FixtureNode<'_>) {
        connection
            .execute(
                "INSERT INTO nodes(project, label, name, qualified_name, file_path, start_line, end_line, properties)
                 VALUES ('demo', ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    node.label,
                    node.name,
                    node.qualified_name,
                    node.file_path,
                    node.start_line,
                    node.end_line,
                    node.properties,
                ],
            )
            .expect("insert node");
    }

    fn vault() -> AsterVault<SystemClock> {
        AsterVault::with_clock(
            "00000000000000000000000000"
                .parse::<VaultId>()
                .expect("vault id"),
            b"astrolabe-lower-test".to_vec(),
            SystemClock,
        )
    }

    fn durable_vault(name: &str) -> (PathBuf, AsterVault<SystemClock>) {
        let dir = temp_dir_path(&format!("{name}.vault"));
        let vault = AsterVault::new_durable(
            &dir,
            "00000000000000000000000000"
                .parse::<VaultId>()
                .expect("vault id"),
            b"astrolabe-lower-test".to_vec(),
            VaultOptions::default(),
        )
        .expect("open durable lower test vault");
        (dir, vault)
    }

    fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    fn path_tree_byte_hits(root: &Path, needle: &[u8]) -> Vec<PathBuf> {
        if needle.is_empty() || !root.exists() {
            return Vec::new();
        }
        let mut hits = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            let metadata = fs::metadata(&path).expect("metadata during byte sweep");
            if metadata.is_dir() {
                for entry in fs::read_dir(&path).expect("read directory during byte sweep") {
                    stack.push(entry.expect("directory entry").path());
                }
            } else if metadata.is_file() {
                let bytes = fs::read(&path).expect("read file during byte sweep");
                if bytes_contain(&bytes, needle) {
                    hits.push(path);
                }
            }
        }
        hits.sort();
        hits
    }

    fn path_is_under_child(root: &Path, path: &Path, child: &str) -> bool {
        path.strip_prefix(root)
            .ok()
            .and_then(|relative| relative.components().next())
            .is_some_and(|component| component.as_os_str() == child)
    }

    fn sqlite_sentinel_hits(path: &Path, sentinel: &str) -> (i64, i64) {
        let connection = Connection::open(path).expect("open lowered sentinel db");
        let like = format!("%{sentinel}%");
        let table_hits = connection
            .query_row(
                "SELECT count(*) FROM nodes
                 WHERE name LIKE ?1 OR qualified_name LIKE ?1 OR properties LIKE ?1",
                [like],
                |row| row.get(0),
            )
            .expect("sentinel table query");
        let fts_hits = connection
            .query_row(
                "SELECT count(*) FROM nodes_fts WHERE nodes_fts MATCH ?1",
                [sentinel],
                |row| row.get(0),
            )
            .expect("sentinel fts query");
        (table_hits, fts_hits)
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let thread_name = std::thread::current()
            .name()
            .unwrap_or("test")
            .replace(|ch: char| !ch.is_ascii_alphanumeric(), "-");
        path.push(format!(
            "astrolabe-lower-{}-{}-{name}",
            std::process::id(),
            thread_name
        ));
        path
    }

    fn temp_dir_path(name: &str) -> PathBuf {
        let path = temp_path(name);
        cleanup_dir(&path);
        path
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(sidecar_path(path, "-wal"));
        let _ = fs::remove_file(sidecar_path(path, "-shm"));
        let _ = fs::remove_file(sidecar_path(path, "-journal"));
    }

    fn cleanup_dir(path: &Path) {
        let _ = fs::remove_dir_all(path);
        let _ = fs::remove_file(path);
    }
}
