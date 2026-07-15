#![forbid(unsafe_code)]

pub mod debounce;
mod team_artifact;

pub use debounce::{ASTRO_LOWER_DEBOUNCE_WINDOW_OUT_OF_RANGE, LowerDebouncer, RunOutcome};

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use astrolabe_domain::knobs::U64KnobDeclaration;
use astrolabe_ingest::{
    CbmGraphEdge, CbmGraphNode, CbmGraphSnapshot, read_cbm_graph_snapshot,
    read_cbm_graph_snapshot_at,
};
use astrolabe_weave::{
    PersistedSimilarityEdgeRow, SCHEMA_SIM_EDGE_ROW, SIM_EDGE_ROW_PREFIX, SimEdgeGraphRow,
    read_similarity_edge_rows,
};
use calyx_aster::cf::{ColumnFamily, prefix_range};
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

/// SQLITE_BUSY retry window for the throwaway lowered-artifact db (#76). Since the
/// content-freshness watermark work (#221), `index_status` re-lowers on a source
/// mismatch while another `index_status` process may still hold a shared read lock
/// on the same lowered sidecar; with no busy timeout the writer returns
/// "database is locked" immediately instead of waiting for the reader to drain,
/// which reddens the cross-process gate (check-cross-process-vault.py). Mirrors the
/// config store's CONFIG_DB_BUSY_TIMEOUT_MS operational-resilience window
/// (crates/astrolabe-server/src/migration.rs). journal_mode stays OFF because the
/// artifact is fully rebuilt each lowering; this only changes lock-wait behaviour.
const LOWERED_DB_BUSY_TIMEOUT_MS: u64 = 5_000;

/// Stable refusal code: the lowered artifact file is absent on disk.
pub const ASTRO_LOWER_ARTIFACT_MISSING: &str = "ASTRO_LOWER_ARTIFACT_MISSING";
/// Stable refusal code: the artifact's `astro_meta` row is missing, duplicated,
/// undecodable, or disagrees with the ledgered lowering manifest.
pub const ASTRO_LOWER_ARTIFACT_META_INVALID: &str = "ASTRO_LOWER_ARTIFACT_META_INVALID";
/// Stable refusal code: no ledgered lowering manifest in this vault binds the
/// artifact's claimed vault fingerprint for the requested project.
pub const ASTRO_LOWER_ARTIFACT_UNBOUND: &str = "ASTRO_LOWER_ARTIFACT_UNBOUND";
/// Stable refusal code: the artifact bytes on disk do not hash to the digest
/// the ledgered lowering manifest committed to.
pub const ASTRO_LOWER_ARTIFACT_FINGERPRINT_MISMATCH: &str =
    "ASTRO_LOWER_ARTIFACT_FINGERPRINT_MISMATCH";
/// Stable refusal code: the artifact was lowered from an older vault state than
/// the vault's current content fingerprint.
pub const ASTRO_LOWER_ARTIFACT_STALE: &str = "ASTRO_LOWER_ARTIFACT_STALE";

const ARTIFACT_VERIFY_REMEDIATION: &str = "Regenerate the lowered artifact from the current vault with lower_cbm_sqlite; never serve a lowered artifact that fails load-time verification.";

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
    // The canonical lowering reads the vault's latest committed state and uses
    // weave's own key-verified similarity reader, so its output byte-stream is
    // unchanged by the `as_of` time-travel work below.
    let snapshot = vault.latest_seq();
    let similarity_edges = read_similarity_edge_rows(vault)?;
    let build = lower_at_inner(vault, &output_path, options, snapshot, similarity_edges)?;
    let manifest_seq = write_lower_manifest(
        vault,
        &output_path,
        &build.lowered,
        &build.source_ledger_head_hash,
        &build.vault_fingerprint_sha256,
        &build.artifact_sha256,
        &options.lowered_at,
    )?;
    let lowered = build.lowered;

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
        source_ledger_head_hash: build.source_ledger_head_hash,
        vault_fingerprint_sha256: build.vault_fingerprint_sha256,
        artifact_sha256: build.artifact_sha256,
        manifest_seq,
    })
}

/// The built lowered artifact, before any manifest is (or is not) committed.
struct LoweredArtifactBuild {
    lowered: LoweredRows,
    source_ledger_head_hash: String,
    vault_fingerprint_sha256: String,
    artifact_sha256: String,
}

/// Reads the graph at `snapshot`, writes the lowered SQLite artifact to
/// `output_path`, and returns its content digest. Pure derivation: it never
/// mutates the vault, so both the canonical lowering (which then commits a
/// manifest) and the `as_of` lowering (which does not) share it.
fn lower_at_inner<C>(
    vault: &AsterVault<C>,
    output_path: &Path,
    options: &LowerSqliteOptions,
    snapshot: Seq,
    similarity_edges: Vec<PersistedSimilarityEdgeRow>,
) -> LowerResult<LoweredArtifactBuild>
where
    C: Clock,
{
    let graph = read_cbm_graph_snapshot_at(vault, &options.project, snapshot)?;
    let source_ledger_head_hash = source_ledger_head_hash_at(vault, snapshot)?;
    let vault_fingerprint_sha256 = snapshot_fingerprint(&graph, &source_ledger_head_hash);
    let lowered = LoweredRows::from_snapshot(graph, similarity_edges)?;

    write_sqlite_artifact(
        output_path,
        &lowered,
        &source_ledger_head_hash,
        &vault_fingerprint_sha256,
        &options.lowered_at,
    )?;
    let artifact_sha256 = hex_lower(&sha256_digest(&fs::read(output_path)?));
    Ok(LoweredArtifactBuild {
        lowered,
        source_ledger_head_hash,
        vault_fingerprint_sha256,
        artifact_sha256,
    })
}

/// A lowered SQLite artifact built as of an explicit MVCC snapshot sequence
/// (#43 `query_graph` `as_of`). Unlike [`LoweredSqliteReport`] this carries no
/// `manifest_seq`: the `as_of` lowering is a read-only historical projection
/// and never commits a lowering manifest into the (present-time) vault.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AsOfLoweredArtifact {
    /// Project the artifact serves.
    pub project: String,
    /// Path the artifact was written to.
    pub output_path: PathBuf,
    /// MVCC snapshot sequence the graph was read at.
    pub snapshot_seq: Seq,
    /// Node rows written.
    pub node_count: usize,
    /// Edge rows written.
    pub edge_count: usize,
    /// Source edges dropped because an endpoint was outside the snapshot.
    pub skipped_edges: usize,
    /// SHA-256 of the artifact bytes on disk.
    pub artifact_sha256: String,
    /// Vault content fingerprint at the snapshot.
    pub vault_fingerprint_sha256: String,
    /// Non-lowering ledger head hash visible at the snapshot.
    pub source_ledger_head_hash: String,
}

/// Lowers the CBM graph to a throwaway SQLite artifact **as of** an explicit
/// MVCC snapshot sequence (#43 `query_graph` `as_of` time-travel).
///
/// The read is pinned to `snapshot`: nodes, edges, projects, file hashes,
/// summaries, token vectors, similarity edges, and the source ledger head are
/// all read at that seqno, so the artifact is a pure function of
/// `(vault, project, snapshot, options.lowered_at)`. Re-lowering the same
/// `snapshot` after later commits yields a byte-identical file. Callers resolve
/// a wall-clock `as_of` to a seqno with [`AsterVault::as_of`] (the `time_index`
/// CF); the resolution fails closed (`CALYX_TIMETRAVEL_*`) when the vault has no
/// write at or before the timestamp, or the timestamp is below the retention
/// horizon. No manifest is committed — this is a read-only view, never a
/// canonical lowering of present state.
pub fn lower_cbm_sqlite_at<C>(
    vault: &AsterVault<C>,
    output_path: impl AsRef<Path>,
    options: &LowerSqliteOptions,
    snapshot: Seq,
) -> LowerResult<AsOfLoweredArtifact>
where
    C: Clock,
{
    validate_options(options)?;
    let output_path = output_path.as_ref().to_path_buf();
    let similarity_edges = read_similarity_edge_rows_at(vault, snapshot)?;
    let build = lower_at_inner(vault, &output_path, options, snapshot, similarity_edges)?;
    Ok(AsOfLoweredArtifact {
        project: build.lowered.project,
        output_path,
        snapshot_seq: snapshot,
        node_count: build.lowered.nodes.len(),
        edge_count: build.lowered.edges.len(),
        skipped_edges: build.lowered.skipped_edges,
        artifact_sha256: build.artifact_sha256,
        vault_fingerprint_sha256: build.vault_fingerprint_sha256,
        source_ledger_head_hash: build.source_ledger_head_hash,
    })
}

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::CodebaseMemoryMcp
}

/// Load-time verification report for a lowered SQLite artifact (#178, scope item 3).
///
/// Returned only when every check passed: the on-disk bytes hash to the
/// digest the ledgered lowering manifest committed to, the artifact's
/// `astro_meta` row matches that manifest, and the artifact's vault
/// fingerprint equals the fingerprint recomputed from the vault's current
/// content — so a caller holding this value is provably not serving stale or
/// tampered derived state.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LoweredArtifactVerification {
    /// Project the artifact serves.
    pub project: String,
    /// Verified artifact path.
    pub artifact_path: PathBuf,
    /// SHA-256 of the artifact bytes read back from disk during verification.
    pub artifact_sha256: String,
    /// Vault content fingerprint recorded in `astro_meta` and the manifest.
    pub vault_fingerprint_sha256: String,
    /// Non-lowering ledger head hash the artifact was lowered from.
    pub source_ledger_head_hash: String,
    /// Panel version recorded at lowering time.
    pub panel_version: Option<u32>,
    /// Lowering timestamp recorded at lowering time.
    pub lowered_at: String,
}

/// Verifies a lowered SQLite artifact against its vault before it is served.
///
/// Fail-closed (#178): a missing file, an unreadable or duplicated
/// `astro_meta` row, a fingerprint with no ledgered manifest, disk bytes that
/// do not hash to the manifest digest, or staleness against the vault's
/// current content each return a [`LowerError::Refused`] with a stable
/// `ASTRO_LOWER_ARTIFACT_*` code and operator remediation. Callers must treat
/// every error as "do not serve this artifact".
pub fn verify_lowered_artifact<C>(
    vault: &AsterVault<C>,
    artifact_path: impl AsRef<Path>,
    project: &str,
) -> LowerResult<LoweredArtifactVerification>
where
    C: Clock,
{
    let artifact_path = artifact_path.as_ref().to_path_buf();
    let bytes = match fs::read(&artifact_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(LowerError::refused(
                ASTRO_LOWER_ARTIFACT_MISSING,
                format!(
                    "lowered artifact is missing at {}.",
                    artifact_path.display()
                ),
                ARTIFACT_VERIFY_REMEDIATION,
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let artifact_sha256 = hex_lower(&sha256_digest(&bytes));
    let meta = read_astro_meta(&artifact_path)?;

    let manifest_key = lowered_manifest_key(project, &meta.vault_fingerprint);
    let manifest_bytes = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::Kernel, &manifest_key)?
        .ok_or_else(|| {
            LowerError::refused(
                ASTRO_LOWER_ARTIFACT_UNBOUND,
                format!(
                    "no lowering manifest in this vault binds project {project} at the artifact's claimed vault fingerprint {}.",
                    fingerprint_prefix(&meta.vault_fingerprint),
                ),
                ARTIFACT_VERIFY_REMEDIATION,
            )
        })?;
    let manifest = serde_json::from_slice::<LoweredSqliteManifest>(&manifest_bytes)
        .map_err(|error| meta_invalid(format!("decode ledgered lowering manifest: {error}.")))?;
    if manifest.schema != ASTRO_LOWERED_SQLITE_SCHEMA || manifest.project != project {
        return Err(meta_invalid(format!(
            "ledgered lowering manifest carries schema {} for project {}; expected {ASTRO_LOWERED_SQLITE_SCHEMA} for project {project}.",
            manifest.schema, manifest.project
        )));
    }
    if manifest.artifact_sha256 != artifact_sha256 {
        return Err(LowerError::refused(
            ASTRO_LOWER_ARTIFACT_FINGERPRINT_MISMATCH,
            format!(
                "artifact bytes at {} hash to {artifact_sha256} but the ledgered manifest committed to {}.",
                artifact_path.display(),
                manifest.artifact_sha256
            ),
            ARTIFACT_VERIFY_REMEDIATION,
        ));
    }
    if manifest.vault_fingerprint_sha256 != meta.vault_fingerprint
        || manifest.source_ledger_head_hash != meta.ledger_head_hash
        || manifest.panel_version != meta.panel_version
    {
        return Err(meta_invalid(
            "astro_meta row does not match the ledgered lowering manifest.".to_string(),
        ));
    }

    let current_head = source_ledger_head_hash_at(vault, vault.latest_seq())?;
    let current_snapshot = read_cbm_graph_snapshot(vault, project)?;
    let current_fingerprint = snapshot_fingerprint(&current_snapshot, &current_head);
    if current_fingerprint != meta.vault_fingerprint {
        return Err(LowerError::refused(
            ASTRO_LOWER_ARTIFACT_STALE,
            format!(
                "artifact was lowered at vault fingerprint {} but the vault now fingerprints {}; refusing to serve stale derived state.",
                fingerprint_prefix(&meta.vault_fingerprint),
                fingerprint_prefix(&current_fingerprint),
            ),
            ARTIFACT_VERIFY_REMEDIATION,
        ));
    }

    Ok(LoweredArtifactVerification {
        project: project.to_string(),
        artifact_path,
        artifact_sha256,
        vault_fingerprint_sha256: meta.vault_fingerprint,
        source_ledger_head_hash: meta.ledger_head_hash,
        panel_version: meta.panel_version,
        lowered_at: meta.lowered_at,
    })
}

struct AstroMetaRow {
    vault_fingerprint: String,
    ledger_head_hash: String,
    panel_version: Option<u32>,
    lowered_at: String,
}

fn meta_invalid(message: String) -> LowerError {
    LowerError::refused(
        ASTRO_LOWER_ARTIFACT_META_INVALID,
        message,
        ARTIFACT_VERIFY_REMEDIATION,
    )
}

/// First 16 characters of a fingerprint for refusal messages, tolerant of
/// tampered non-ASCII content (falls back to the full string rather than
/// slicing through a UTF-8 boundary).
fn fingerprint_prefix(fingerprint: &str) -> &str {
    fingerprint.get(..16).unwrap_or(fingerprint)
}

fn read_astro_meta(path: &Path) -> LowerResult<AstroMetaRow> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| {
        meta_invalid(format!(
            "open lowered artifact {}: {error}.",
            path.display()
        ))
    })?;
    connection.busy_timeout(std::time::Duration::from_millis(LOWERED_DB_BUSY_TIMEOUT_MS))?;
    let mut statement = connection
        .prepare(
            "SELECT schema, vault_fingerprint, ledger_head_hash, panel_version, lowered_at \
             FROM astro_meta",
        )
        .map_err(|error| {
            meta_invalid(format!("read astro_meta from {}: {error}.", path.display()))
        })?;
    let mut rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .and_then(|mapped| mapped.collect::<Result<Vec<_>, _>>())
        .map_err(|error| {
            meta_invalid(format!(
                "read astro_meta rows from {}: {error}.",
                path.display()
            ))
        })?;
    if rows.len() != 1 {
        return Err(meta_invalid(format!(
            "astro_meta must contain exactly one row; found {}.",
            rows.len()
        )));
    }
    let Some((schema, vault_fingerprint, ledger_head_hash, panel_version, lowered_at)) = rows.pop()
    else {
        return Err(meta_invalid(
            "astro_meta row disappeared mid-read.".to_string(),
        ));
    };
    if schema != ASTRO_META_SCHEMA {
        return Err(meta_invalid(format!(
            "astro_meta schema is {schema}; expected {ASTRO_META_SCHEMA}."
        )));
    }
    let panel_version = match panel_version {
        None => None,
        Some(value) => Some(u32::try_from(value).map_err(|_| {
            meta_invalid(format!(
                "astro_meta panel_version {value} does not fit u32."
            ))
        })?),
    };
    Ok(AstroMetaRow {
        vault_fingerprint,
        ledger_head_hash,
        panel_version,
        lowered_at,
    })
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
    fn from_snapshot(
        snapshot: CbmGraphSnapshot,
        similarity_edges: Vec<PersistedSimilarityEdgeRow>,
    ) -> LowerResult<Self> {
        let mut seen_qn = BTreeSet::new();
        let mut id_by_source = BTreeMap::new();
        let mut id_by_qn = BTreeMap::new();
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
            id_by_qn.insert(node.qualified_name.clone(), id);
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
        for persisted in similarity_edges {
            let row = persisted.row;
            let source_id = id_by_qn.get(&row.source_qn).copied().ok_or_else(|| {
                LowerError::InvalidInput(format!(
                    "persisted {} similarity edge points to missing source {:?}",
                    row.family, row.source_qn
                ))
            })?;
            let target_id = id_by_qn.get(&row.target_qn).copied().ok_or_else(|| {
                LowerError::InvalidInput(format!(
                    "persisted {} similarity edge points to missing target {:?}",
                    row.family, row.target_qn
                ))
            })?;
            let id = i64::try_from(edges.len() + 1).map_err(|_| {
                LowerError::InvalidInput("too many edges to assign SQLite ids".to_string())
            })?;
            edges.push(LoweredEdge {
                id,
                project: snapshot.project.clone(),
                source_id,
                target_id,
                edge_type: row.family,
                properties_json: serde_json::to_string(&row.props)?,
            });
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

/// Open the throwaway lowered-artifact SQLite db with the fixed pragmas and the
/// #76 SQLITE_BUSY retry window. Kept as a named helper so the busy-timeout
/// contract is directly asserted by `lowered_connection_sets_busy_timeout`.
fn open_lowered_connection(output_path: &Path) -> LowerResult<Connection> {
    let connection = Connection::open_with_flags(
        output_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // #76: wait for a transient shared-lock holder (a concurrent index_status
    // reader of the same lowered sidecar) instead of failing SQLITE_BUSY at once.
    connection.busy_timeout(std::time::Duration::from_millis(LOWERED_DB_BUSY_TIMEOUT_MS))?;
    connection.execute_batch(
        "PRAGMA page_size=4096;\
         PRAGMA journal_mode=OFF;\
         PRAGMA synchronous=OFF;\
         PRAGMA foreign_keys=ON;\
         PRAGMA encoding='UTF-8';",
    )?;
    Ok(connection)
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

    let mut connection = open_lowered_connection(output_path)?;
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

/// Non-lowering ledger head hash visible at an explicit MVCC `snapshot`.
///
/// Pins the Ledger CF scan to `snapshot` so the fingerprint reflects exactly the
/// ledger state as of that sequence (#43 `as_of`); passing `vault.latest_seq()`
/// reproduces the present-time head used by the canonical lowering.
fn source_ledger_head_hash_at<C>(vault: &AsterVault<C>, snapshot: Seq) -> LowerResult<String>
where
    C: Clock,
{
    let mut selected = None;
    for (_key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Ledger)? {
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

/// Reads the persisted similarity (`SIM_*`) edge rows at an explicit MVCC
/// `snapshot` sequence, mirroring [`astrolabe_weave::read_similarity_edge_rows`]
/// but pinned to a historical seqno instead of the vault's latest snapshot.
///
/// Rows are scanned in Graph-CF key order (identical to weave's reader), each
/// decoded to a [`SimEdgeGraphRow`], schema-checked, and required to name a
/// known similarity family. At `vault.latest_seq()` this yields the same rows
/// weave's reader returns for the same vault, so the `as_of` lowering of the
/// present state matches the canonical lowering.
fn read_similarity_edge_rows_at<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
) -> LowerResult<Vec<PersistedSimilarityEdgeRow>>
where
    C: Clock,
{
    let mut rows = Vec::new();
    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(SIM_EDGE_ROW_PREFIX),
    )? {
        let row: SimEdgeGraphRow = serde_json::from_slice(&value)?;
        if row.schema != SCHEMA_SIM_EDGE_ROW {
            return Err(LowerError::InvalidInput(format!(
                "persisted SIM_* row {} carries schema {:?}, expected {SCHEMA_SIM_EDGE_ROW}",
                hex_lower(&key),
                row.schema
            )));
        }
        if row.similarity_family().is_none() {
            return Err(LowerError::InvalidInput(format!(
                "persisted SIM_* row {} names unknown similarity family {:?}",
                hex_lower(&key),
                row.family
            )));
        }
        rows.push(PersistedSimilarityEdgeRow { key, row });
    }
    Ok(rows)
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

// ---------------------------------------------------------------------------
// #43 `query_graph` `as_of`: per-t-bucket lowered-SQLite cache.
// ---------------------------------------------------------------------------

/// Registry version tag for the `as_of` time-bucket lowering knobs (#43).
pub const AS_OF_BUCKET_KNOB_REGISTRY_VERSION: &str = "astrolabe-as-of-bucket-knobs-v1";

/// Name of the `as_of` lowered-SQLite time-bucket width knob.
pub const AS_OF_BUCKET_WIDTH_MS_KNOB: &str = "as_of_bucket_width_ms";

/// Default width, in milliseconds, of one `as_of` cache bucket.
///
/// A `query_graph` `as_of=t` request is quantized to the bucket
/// `floor(t / width)`; every `t` in a bucket serves the one lowered artifact
/// built for that bucket's floor timestamp, so repeated historical queries in
/// the same window reuse the cached SQLite view byte-for-byte and a re-lowering
/// happens only when a query crosses into a new bucket. 1000ms mirrors the
/// wall-clock second an operator naturally reasons in ("the graph a minute
/// ago") and keeps the cache from re-lowering on every millisecond of clock
/// jitter, while staying fine enough that adjacent edits usually fall in
/// distinct buckets.
pub const AS_OF_BUCKET_DEFAULT_WIDTH_MS: u64 = 1_000;
/// Smallest legal bucket width. Zero is illegal: a zero-width bucket cannot be
/// divided into and would re-lower on every distinct millisecond, defeating the
/// cache this knob exists to bound (the same "zero disables the protection"
/// failure the FSV sampling and debounce knobs forbid).
pub const AS_OF_BUCKET_MIN_WIDTH_MS: u64 = 1;
/// Largest legal bucket width: one day. An upper bound keeps a bucket from
/// growing so coarse that "an hour ago" and "now" collapse into one served view.
pub const AS_OF_BUCKET_MAX_WIDTH_MS: u64 = 86_400_000;

/// The `as_of` time-bucket lowering knob registry (#43).
pub const AS_OF_BUCKET_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: AS_OF_BUCKET_KNOB_REGISTRY_VERSION,
    name: AS_OF_BUCKET_WIDTH_MS_KNOB,
    default: AS_OF_BUCKET_DEFAULT_WIDTH_MS,
    min: AS_OF_BUCKET_MIN_WIDTH_MS,
    max: AS_OF_BUCKET_MAX_WIDTH_MS,
    unit: "milliseconds",
    source: "ASTROLABE #43 query_graph as_of time-travel; wall-clock-second granularity that an operator reasons in",
    rationale: "quantizes an as_of wall-clock timestamp to a floor(t/width) cache bucket so historical queries in the same window reuse one lowered SQLite artifact byte-identically and re-lower only on a bucket boundary crossing; 1000ms is the natural operator second; zero is illegal (undivisible, re-lowers per millisecond); replace with a measured value once historical-query cadence is benchmarked",
}];

/// Returns the `as_of` bucket declaration for `name`, or `None` when undeclared.
pub fn as_of_bucket_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    AS_OF_BUCKET_KNOBS.iter().find(|knob| knob.name == name)
}

/// Stable refusal code: the requested `as_of` bucket width is outside the
/// registry-declared bounds.
pub const ASTRO_AS_OF_BUCKET_WIDTH_OUT_OF_RANGE: &str = "ASTRO_AS_OF_BUCKET_WIDTH_OUT_OF_RANGE";

const AS_OF_BUCKET_WIDTH_REMEDIATION: &str = "Pass an as_of bucket width inside the declared as_of_bucket_width_ms knob bounds (1..=86_400_000 ms).";

/// One cached lowered artifact for a single `as_of` time bucket.
#[derive(Debug, Clone, Eq, PartialEq)]
struct AsOfBucketEntry {
    canonical_millis: u64,
    snapshot_seq: Seq,
    artifact_path: PathBuf,
    artifact_sha256: String,
    node_count: usize,
    edge_count: usize,
    skipped_edges: usize,
}

/// The outcome of serving one `as_of` request through the cache.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AsOfServeReport {
    /// Bucket the requested timestamp quantized to (`floor(as_of / width)`).
    pub bucket: u64,
    /// Bucket floor timestamp the snapshot seqno was resolved from.
    pub canonical_millis: u64,
    /// MVCC snapshot sequence the served artifact was lowered at.
    pub snapshot_seq: Seq,
    /// Path of the served lowered SQLite artifact.
    pub artifact_path: PathBuf,
    /// SHA-256 of the served artifact bytes.
    pub artifact_sha256: String,
    /// `true` when this bucket was already cached (no re-lowering happened).
    pub cache_hit: bool,
    /// Node rows in the served artifact.
    pub node_count: usize,
    /// Edge rows in the served artifact.
    pub edge_count: usize,
    /// Source edges dropped because an endpoint was outside the snapshot.
    pub skipped_edges: usize,
    /// Total re-lowerings this cache has performed (bumped only on a miss).
    pub relower_count: u64,
    /// Total cache hits this cache has served (bumped only on a hit).
    pub hit_count: u64,
}

/// A per-t-bucket cache of `as_of` lowered SQLite artifacts (#43).
///
/// A `query_graph` `as_of=t` request is quantized to the bucket
/// `floor(t / width)` (`width` is the registry-declared
/// [`AS_OF_BUCKET_WIDTH_MS_KNOB`]). The first request in a bucket resolves the
/// bucket floor timestamp to an MVCC seqno via [`AsterVault::as_of`] and lowers
/// that snapshot to a SQLite file, bumping the instrumented re-lower counter.
/// Every later request in the same bucket is served from that cached file
/// byte-for-byte, bumping only the hit counter — so the served view is stable
/// within a bucket and re-lowers exactly on a boundary crossing. Resolution
/// fails closed (`CALYX_TIMETRAVEL_*`) when the vault has no write at or before
/// the bucket floor, or the floor is below the retention horizon.
#[derive(Debug)]
pub struct AsOfLoweredCache {
    project: String,
    output_dir: PathBuf,
    bucket_width_ms: u64,
    entries: BTreeMap<u64, AsOfBucketEntry>,
    relower_count: u64,
    hit_count: u64,
}

impl AsOfLoweredCache {
    /// Builds a cache with an explicit bucket width, refusing a width outside
    /// the declared knob bounds.
    pub fn new(
        project: impl Into<String>,
        output_dir: impl Into<PathBuf>,
        bucket_width_ms: u64,
    ) -> LowerResult<Self> {
        let knob = as_of_bucket_knob(AS_OF_BUCKET_WIDTH_MS_KNOB)
            .expect("as_of bucket width knob is declared in the as_of bucket knob registry");
        if !knob.accepts(bucket_width_ms) {
            return Err(LowerError::refused(
                ASTRO_AS_OF_BUCKET_WIDTH_OUT_OF_RANGE,
                format!(
                    "as_of bucket width {bucket_width_ms} ms is outside the declared knob bounds [{}, {}] for {}",
                    knob.min, knob.max, knob.name
                ),
                AS_OF_BUCKET_WIDTH_REMEDIATION,
            ));
        }
        Ok(Self {
            project: project.into(),
            output_dir: output_dir.into(),
            bucket_width_ms,
            entries: BTreeMap::new(),
            relower_count: 0,
            hit_count: 0,
        })
    }

    /// Builds a cache at the registry-default bucket width.
    pub fn with_default_width(project: impl Into<String>, output_dir: impl Into<PathBuf>) -> Self {
        Self::new(project, output_dir, AS_OF_BUCKET_DEFAULT_WIDTH_MS)
            .expect("registry-default as_of bucket width is inside its own declared bounds")
    }

    /// The bucket a wall-clock `as_of` timestamp quantizes to.
    pub fn bucket_for(&self, as_of_millis: u64) -> u64 {
        as_of_millis / self.bucket_width_ms
    }

    /// The bucket floor timestamp a snapshot is resolved at for `bucket`.
    pub fn canonical_millis(&self, bucket: u64) -> u64 {
        bucket.saturating_mul(self.bucket_width_ms)
    }

    /// Re-lowerings performed so far (bumped only when a bucket boundary is
    /// crossed into an uncached bucket).
    pub fn relower_count(&self) -> u64 {
        self.relower_count
    }

    /// Cache hits served so far.
    pub fn hit_count(&self) -> u64 {
        self.hit_count
    }

    /// Serves the lowered artifact for a wall-clock `as_of` timestamp, lowering
    /// (and caching) the bucket's snapshot on a miss and reusing the cached
    /// artifact byte-for-byte on a hit.
    pub fn serve<C>(
        &mut self,
        vault: &AsterVault<C>,
        as_of_millis: u64,
    ) -> LowerResult<AsOfServeReport>
    where
        C: Clock,
    {
        let bucket = self.bucket_for(as_of_millis);
        if let Some(entry) = self.entries.get(&bucket) {
            self.hit_count += 1;
            return Ok(AsOfServeReport {
                bucket,
                canonical_millis: entry.canonical_millis,
                snapshot_seq: entry.snapshot_seq,
                artifact_path: entry.artifact_path.clone(),
                artifact_sha256: entry.artifact_sha256.clone(),
                cache_hit: true,
                node_count: entry.node_count,
                edge_count: entry.edge_count,
                skipped_edges: entry.skipped_edges,
                relower_count: self.relower_count,
                hit_count: self.hit_count,
            });
        }

        let canonical_millis = self.canonical_millis(bucket);
        // Hold the time-travel pin across the whole lowering so version GC
        // cannot reclaim the historical versions the read walks.
        let snapshot = vault.as_of(canonical_millis)?;
        let snapshot_seq = snapshot.seqno();
        let artifact_path = self
            .output_dir
            .join(as_of_artifact_filename(&self.project, bucket));
        // Deterministic `lowered_at` derived from the bucket floor keeps the
        // artifact a pure function of the bucket, so re-lowering it is
        // byte-identical.
        let options = LowerSqliteOptions::new(self.project.clone())
            .with_lowered_at(format!("as_of:{canonical_millis}"));
        let artifact = lower_cbm_sqlite_at(vault, &artifact_path, &options, snapshot_seq)?;
        drop(snapshot);

        self.relower_count += 1;
        let entry = AsOfBucketEntry {
            canonical_millis,
            snapshot_seq,
            artifact_path: artifact.output_path.clone(),
            artifact_sha256: artifact.artifact_sha256.clone(),
            node_count: artifact.node_count,
            edge_count: artifact.edge_count,
            skipped_edges: artifact.skipped_edges,
        };
        self.entries.insert(bucket, entry);
        Ok(AsOfServeReport {
            bucket,
            canonical_millis,
            snapshot_seq,
            artifact_path: artifact.output_path,
            artifact_sha256: artifact.artifact_sha256,
            cache_hit: false,
            node_count: artifact.node_count,
            edge_count: artifact.edge_count,
            skipped_edges: artifact.skipped_edges,
            relower_count: self.relower_count,
            hit_count: self.hit_count,
        })
    }
}

/// Filesystem-safe artifact filename for one project/bucket pair. The project
/// segment is reduced to `[A-Za-z0-9._-]` (other bytes become `_`) so an
/// arbitrary project name can never escape `output_dir` or collide with a
/// sidecar suffix.
fn as_of_artifact_filename(project: &str, bucket: u64) -> String {
    let mut safe = String::with_capacity(project.len());
    for ch in project.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            safe.push(ch);
        } else {
            safe.push('_');
        }
    }
    if safe.is_empty() {
        safe.push('_');
    }
    format!("asof-{safe}-bucket-{bucket}.sqlite")
}
