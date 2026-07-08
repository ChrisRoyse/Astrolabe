use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::thread;

use astrolabe_domain::{SeriesId, SymbolRecord};
use calyx_aster::cf::{ColumnFamily, KeyRange};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{CalyxError, Clock, CxId, Seq, VaultId};
use serde::{Deserialize, Serialize};

use crate::sqlite_import::verify_sqlite_import_deep;

/// Namespace prefix for every Astrolabe series registry key stored in Aster.
pub const ASTRO_SERIES_REGISTRY_PREFIX: &[u8] = b"astrolabe:series-registry:v1:";
/// Maximum QN key bytes before the CBM-style FNV tail fallback is applied.
pub const QN_KEY_MAX_BYTES: usize = 255;

const QN_HASH_SUFFIX_BYTES: usize = 9;
const SERIES_ROW_TAG: &[u8] = b"series:";
const REVERSE_ROW_TAG: &[u8] = b"reverse:";
const QN_ROW_TAG: &[u8] = b"qn:";
const SPLIT_ROW_TAG: &[u8] = b"split:";
const RECURRENCE_ROW_TAG: &[u8] = b"recurrence:";
const SCHEMA_SERIES: &str = "astrolabe-series-row-v1";
const SCHEMA_REVERSE: &str = "astrolabe-series-reverse-v1";
const SCHEMA_QN: &str = "astrolabe-series-qn-index-v1";
const SCHEMA_RECURRENCE: &str = "astrolabe-series-recurrence-v1";
const SCHEMA_SPLIT: &str = "astrolabe-series-split-v1";

/// Result type for Astrolabe ingest and registry operations.
pub type IngestResult<T> = std::result::Result<T, IngestError>;

/// Error returned by Astrolabe ingest and registry operations.
#[derive(Debug)]
pub enum IngestError {
    /// A domain identity operation failed.
    Domain(astrolabe_domain::DomainError),
    /// A panel measurement operation failed.
    Panel(astrolabe_panel::PanelError),
    /// A Calyx/Aster operation failed.
    Calyx(CalyxError),
    /// A registry row failed deterministic JSON serialization or decoding.
    Json(serde_json::Error),
    /// Input was refused fail-closed with a stable `ASTRO_*` code.
    Refused {
        /// Stable refusal code.
        code: &'static str,
        /// Human-readable refusal message.
        message: String,
        /// Operator-facing remediation.
        remediation: &'static str,
    },
    /// Caller supplied an invalid registry input.
    InvalidInput(String),
    /// Deep verification found persisted CF bytes that violate registry invariants.
    VerifyFailed(Vec<String>),
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(err) => write!(f, "{err}"),
            Self::Panel(err) => write!(f, "{err}"),
            Self::Calyx(err) => write!(f, "{err}"),
            Self::Json(err) => write!(f, "{err}"),
            Self::Refused {
                code,
                message,
                remediation,
            } => write!(f, "{code}: {message} Remediation: {remediation}"),
            Self::InvalidInput(message) => f.write_str(message),
            Self::VerifyFailed(errors) => {
                write!(
                    f,
                    "series registry verify --deep failed: {}",
                    errors.join("; ")
                )
            }
        }
    }
}

impl Error for IngestError {}

impl IngestError {
    /// Builds an ingest refusal with a stable machine-readable code.
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

    /// Returns the stable refusal code when this error has one.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Domain(err) => Some(err.code()),
            Self::Panel(err) => Some(err.code()),
            Self::Refused { code, .. } => Some(code),
            Self::Calyx(_) | Self::Json(_) | Self::InvalidInput(_) | Self::VerifyFailed(_) => None,
        }
    }

    /// Returns the operator-facing remediation when this error has one.
    pub fn remediation(&self) -> Option<&str> {
        match self {
            Self::Domain(err) => Some(err.remediation()),
            Self::Panel(err) => Some(err.remediation()),
            Self::Refused { remediation, .. } => Some(remediation),
            Self::Calyx(_) | Self::Json(_) | Self::InvalidInput(_) | Self::VerifyFailed(_) => None,
        }
    }
}

impl From<astrolabe_domain::DomainError> for IngestError {
    fn from(value: astrolabe_domain::DomainError) -> Self {
        Self::Domain(value)
    }
}

impl From<astrolabe_panel::PanelError> for IngestError {
    fn from(value: astrolabe_panel::PanelError) -> Self {
        Self::Panel(value)
    }
}

impl From<CalyxError> for IngestError {
    fn from(value: CalyxError) -> Self {
        Self::Calyx(value)
    }
}

impl From<serde_json::Error> for IngestError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

/// One immutable version linked into a symbol series.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SeriesVersionRef {
    /// One-based version ordinal inside the series.
    pub ordinal: u64,
    /// Commit or ingest-run identifier that introduced this version.
    pub commit: String,
    /// Immutable Calyx version id.
    pub cx_id: CxId,
}

/// Rename metadata kept on the continuing series row.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RenameRecord {
    /// Commit or ingest-run identifier where the rename was observed.
    pub commit: String,
    /// Previous qualified name that resolved to this series.
    pub old_qualified_name: String,
    /// Previous relative file path from the git rename signal.
    pub old_rel_file_path: String,
}

/// Persisted `series_id -> current state` row.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredSeriesRegistryRow {
    /// Row schema tag.
    pub schema: String,
    /// Project key.
    pub project: String,
    /// Stable series id.
    pub series_id: SeriesId,
    /// Current qualified name.
    pub qualified_name: String,
    /// Current symbol label.
    pub label: String,
    /// Current immutable version id.
    pub current_cx_id: CxId,
    /// Number of unique versions linked into this series.
    pub version_count: u64,
    /// Commit or ingest-run identifier for the first version.
    pub first_seen: String,
    /// Commit or ingest-run identifier for the current version.
    pub last_seen: String,
    /// Ordered version history.
    pub versions: Vec<SeriesVersionRef>,
    /// Rename continuity metadata.
    pub renamed_from: Vec<RenameRecord>,
}

/// Persisted `cx_id -> series_id` reverse index row.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReverseIndexRow {
    /// Row schema tag.
    pub schema: String,
    /// Immutable version id.
    pub cx_id: CxId,
    /// Stable series id.
    pub series_id: SeriesId,
}

/// Persisted QN secondary-index row.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct QnIndexRow {
    /// Row schema tag.
    pub schema: String,
    /// Project key.
    pub project: String,
    /// Symbol label.
    pub label: String,
    /// Full, unbounded qualified name.
    pub qualified_name: String,
    /// Hex form of the bounded key bytes used in the CF key.
    pub bounded_qn_key_hex: String,
    /// Stable series id.
    pub series_id: SeriesId,
}

/// Persisted recurrence occurrence for version succession.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecurrenceRow {
    /// Row schema tag.
    pub schema: String,
    /// Stable series id.
    pub series_id: SeriesId,
    /// One-based occurrence id inside the series.
    pub occurrence_id: u64,
    /// Occurrence kind.
    pub kind: String,
    /// Commit or ingest-run identifier that introduced the occurrence.
    pub commit: String,
    /// Previous version id, absent for the first version.
    pub prev_cx: Option<CxId>,
    /// New version id.
    pub new_cx: CxId,
}

/// Explicit split record written when rename continuity is ambiguous.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SeriesSplitRecord {
    /// Row schema tag.
    pub schema: String,
    /// Deterministic split id.
    pub split_id: String,
    /// Project key.
    pub project: String,
    /// Symbol label.
    pub label: String,
    /// Previous qualified name from the rename signal.
    pub old_qualified_name: String,
    /// New qualified name from the current symbol.
    pub new_qualified_name: String,
    /// Commit or ingest-run identifier where the ambiguity was observed.
    pub commit: String,
    /// Candidate series ids that made the rename ambiguous.
    pub candidate_series_ids: Vec<SeriesId>,
    /// Machine-readable reason.
    pub reason: String,
}

/// Git rename status parsed from CBM-compatible status lines.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GitRenameStatus {
    /// Git status code, such as `R` or `R100`.
    pub status: String,
    /// Old relative path.
    pub old_path: String,
    /// New relative path.
    pub new_path: String,
}

/// Rename continuity hint supplied with a symbol version.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RenameHint {
    /// Previous qualified name.
    pub old_qualified_name: String,
    /// Previous relative file path.
    pub old_rel_file_path: String,
    /// Optional externally resolved candidate series ids.
    pub candidate_series_ids: Vec<SeriesId>,
}

impl RenameHint {
    /// Builds a rename hint that will resolve candidates from the QN index.
    pub fn from_paths(
        old_qualified_name: impl Into<String>,
        old_rel_file_path: impl Into<String>,
    ) -> Self {
        Self {
            old_qualified_name: old_qualified_name.into(),
            old_rel_file_path: old_rel_file_path.into(),
            candidate_series_ids: Vec::new(),
        }
    }

    /// Builds a rename hint with explicit candidate series ids.
    pub fn with_candidates(
        old_qualified_name: impl Into<String>,
        old_rel_file_path: impl Into<String>,
        candidate_series_ids: Vec<SeriesId>,
    ) -> Self {
        Self {
            old_qualified_name: old_qualified_name.into(),
            old_rel_file_path: old_rel_file_path.into(),
            candidate_series_ids,
        }
    }
}

/// One symbol version to admit into the series registry.
#[derive(Debug, Clone, PartialEq)]
pub struct SeriesVersionInput {
    /// Symbol observation.
    pub symbol: SymbolRecord,
    /// Non-zero Calyx panel version used for `CxId` derivation.
    pub panel_version: u32,
    /// Commit or ingest-run identifier for this version.
    pub commit: String,
    /// Optional rename continuity hint.
    pub rename: Option<RenameHint>,
}

impl SeriesVersionInput {
    /// Builds a version input without rename metadata.
    pub fn new(symbol: SymbolRecord, panel_version: u32, commit: impl Into<String>) -> Self {
        Self {
            symbol,
            panel_version,
            commit: commit.into(),
            rename: None,
        }
    }

    /// Attaches rename metadata to this version input.
    pub fn with_rename(mut self, rename: RenameHint) -> Self {
        self.rename = Some(rename);
        self
    }
}

/// Summary of a registry ingest batch.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SeriesIngestReport {
    /// Number of input versions considered.
    pub inputs: usize,
    /// Number of raw CF rows mutated.
    pub mutated_rows: usize,
    /// Latest Aster sequence after the batch.
    pub seq: Seq,
}

/// Raw CF readback snapshot for registry verification.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RegistrySnapshot {
    /// Raw KV rows under the registry namespace.
    pub kv_rows: Vec<(Vec<u8>, Vec<u8>)>,
    /// Raw recurrence rows under the registry namespace.
    pub recurrence_rows: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Successful `verify --deep` report.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeepVerifyReport {
    /// Number of series rows verified.
    pub series_rows: usize,
    /// Number of reverse-index rows verified.
    pub reverse_rows: usize,
    /// Number of QN secondary-index rows verified.
    pub qn_index_rows: usize,
    /// Number of recurrence rows verified.
    pub recurrence_rows: usize,
    /// Number of split records verified.
    pub split_rows: usize,
    /// Number of SQLite-import node mapping rows verified against Base CF rows.
    pub sqlite_node_map_rows: usize,
    /// Number of SQLite-import structural metadata-only rows decoded.
    pub sqlite_structural_rows: usize,
    /// Number of SQLite-import Base CF constellation rows decoded via node maps.
    pub sqlite_constellation_rows: usize,
}

#[derive(Debug, Clone)]
struct PreparedVersionInput {
    input: SeriesVersionInput,
    series_id: SeriesId,
    cx_id: CxId,
}

/// Parses a CBM-compatible git rename status line.
pub fn parse_git_rename_status(line: &str) -> Option<GitRenameStatus> {
    let trimmed = line.trim();
    if !trimmed.starts_with('R') {
        return None;
    }

    if let Some((status, rest)) = trimmed.split_once('\t') {
        let (old_path, new_path) = rest.split_once('\t')?;
        return Some(GitRenameStatus {
            status: status.to_string(),
            old_path: old_path.to_string(),
            new_path: new_path.to_string(),
        });
    }

    let (status, rest) = trimmed.split_once(' ')?;
    let rest = rest.trim();
    let (old_path, new_path) = rest.split_once(" -> ")?;
    Some(GitRenameStatus {
        status: status.to_string(),
        old_path: old_path.to_string(),
        new_path: new_path.to_string(),
    })
}

/// Returns QN key bytes, preserving short QNs and FNV-suffixing long ones.
pub fn bounded_qn_key(qualified_name: &str) -> Vec<u8> {
    let bytes = qualified_name.as_bytes();
    if bytes.len() <= QN_KEY_MAX_BYTES {
        return bytes.to_vec();
    }

    let keep = QN_KEY_MAX_BYTES - QN_HASH_SUFFIX_BYTES;
    let hash = fnv1a32(bytes);
    let mut out = Vec::with_capacity(QN_KEY_MAX_BYTES);
    out.extend_from_slice(&bytes[..keep]);
    out.extend_from_slice(format!("-{hash:08x}").as_bytes());
    out
}

/// Returns the raw KV key for a series registry row.
pub fn series_row_key(series_id: SeriesId) -> Vec<u8> {
    prefixed_key(SERIES_ROW_TAG, series_id.as_bytes())
}

/// Returns the raw KV key for a version-to-series reverse row.
pub fn reverse_index_key(cx_id: CxId) -> Vec<u8> {
    prefixed_key(REVERSE_ROW_TAG, cx_id.as_bytes())
}

/// Returns the raw KV key for a QN secondary-index row.
pub fn qn_index_key(project: &str, label: &str, qualified_name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    append_frame(&mut body, project.as_bytes());
    append_frame(&mut body, label.as_bytes());
    append_frame(&mut body, &bounded_qn_key(qualified_name));
    prefixed_key(QN_ROW_TAG, &body)
}

/// Returns the raw KV key for a split record.
pub fn split_record_key(split_id: &str) -> Vec<u8> {
    prefixed_key(SPLIT_ROW_TAG, split_id.as_bytes())
}

/// Returns the raw Recurrence CF key for a version succession occurrence.
pub fn recurrence_key(series_id: SeriesId, occurrence_id: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(series_id.as_bytes().len() + 8);
    body.extend_from_slice(series_id.as_bytes());
    body.extend_from_slice(&occurrence_id.to_be_bytes());
    prefixed_key(RECURRENCE_ROW_TAG, &body)
}

/// Ingests a deterministic registry batch.
pub fn ingest_series_batch<C>(
    vault: &AsterVault<C>,
    inputs: &[SeriesVersionInput],
) -> IngestResult<SeriesIngestReport>
where
    C: Clock,
{
    let mut prepared = Vec::with_capacity(inputs.len());
    for input in inputs {
        prepared.push(prepare_input(input.clone())?);
    }
    apply_prepared_batch(vault, prepared)
}

/// Prepares symbol identities in parallel, then applies the same deterministic batch writer.
pub fn ingest_series_batch_parallel<C>(
    vault: &AsterVault<C>,
    inputs: &[SeriesVersionInput],
) -> IngestResult<SeriesIngestReport>
where
    C: Clock,
{
    let prepared = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(inputs.len());
        for input in inputs.iter().cloned() {
            handles.push(scope.spawn(move || prepare_input(input)));
        }
        let mut prepared = Vec::with_capacity(handles.len());
        for handle in handles {
            prepared.push(handle.join().map_err(|_| {
                IngestError::InvalidInput("parallel preparation panicked".into())
            })??);
        }
        IngestResult::Ok(prepared)
    })?;
    apply_prepared_batch(vault, prepared)
}

/// Reads raw registry CF bytes from Aster without going through writer APIs.
pub fn read_registry_snapshot<C>(vault: &AsterVault<C>) -> IngestResult<RegistrySnapshot>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let range = registry_range();
    Ok(RegistrySnapshot {
        kv_rows: vault.scan_cf_range_at(snapshot, ColumnFamily::Kv, &range)?,
        recurrence_rows: vault.scan_cf_range_at(snapshot, ColumnFamily::Recurrence, &range)?,
    })
}

/// Runs deep CF readback verification against an already opened Aster vault.
pub fn verify_deep<C>(vault: &AsterVault<C>) -> IngestResult<DeepVerifyReport>
where
    C: Clock,
{
    let snapshot = read_registry_snapshot(vault)?;
    let mut errors = Vec::new();
    let mut series = BTreeMap::new();
    let mut reverse = BTreeMap::new();
    let mut qn_index = Vec::new();
    let mut qn_rows = 0;
    let mut splits = 0;
    let mut recurrence = BTreeMap::new();

    for (key, value) in &snapshot.kv_rows {
        let Some(kind) = registry_kind(key) else {
            errors.push(format!("unknown registry KV key {}", hex_lower(key)));
            continue;
        };
        match kind {
            SERIES_ROW_TAG => match serde_json::from_slice::<StoredSeriesRegistryRow>(value) {
                Ok(row) => {
                    if row.schema != SCHEMA_SERIES {
                        errors.push(format!("series {} has wrong schema", row.series_id));
                    }
                    if row.version_count != row.versions.len() as u64 {
                        errors.push(format!("series {} version_count mismatch", row.series_id));
                    }
                    if row.versions.last().map(|version| version.cx_id) != Some(row.current_cx_id) {
                        errors.push(format!("series {} current_cx_id mismatch", row.series_id));
                    }
                    series.insert(row.series_id, row);
                }
                Err(err) => errors.push(format!("decode series row {}: {err}", hex_lower(key))),
            },
            REVERSE_ROW_TAG => match serde_json::from_slice::<ReverseIndexRow>(value) {
                Ok(row) => {
                    if row.schema != SCHEMA_REVERSE {
                        errors.push(format!("reverse {} has wrong schema", row.cx_id));
                    }
                    reverse.insert(row.cx_id, row.series_id);
                }
                Err(err) => errors.push(format!("decode reverse row {}: {err}", hex_lower(key))),
            },
            QN_ROW_TAG => match serde_json::from_slice::<QnIndexRow>(value) {
                Ok(row) => {
                    if row.schema != SCHEMA_QN {
                        errors.push(format!("qn index {} has wrong schema", row.qualified_name));
                    }
                    qn_index.push((key.clone(), row));
                    qn_rows += 1;
                }
                Err(err) => errors.push(format!("decode qn row {}: {err}", hex_lower(key))),
            },
            SPLIT_ROW_TAG => match serde_json::from_slice::<SeriesSplitRecord>(value) {
                Ok(row) => {
                    if row.schema != SCHEMA_SPLIT {
                        errors.push(format!("split {} has wrong schema", row.split_id));
                    }
                    splits += 1;
                }
                Err(err) => errors.push(format!("decode split row {}: {err}", hex_lower(key))),
            },
            _ => errors.push(format!("unexpected KV kind {}", hex_lower(kind))),
        }
    }

    for (key, value) in &snapshot.recurrence_rows {
        match serde_json::from_slice::<RecurrenceRow>(value) {
            Ok(row) => {
                if row.schema != SCHEMA_RECURRENCE {
                    errors.push(format!(
                        "recurrence {}:{} has wrong schema",
                        row.series_id, row.occurrence_id
                    ));
                }
                recurrence.insert((row.series_id, row.occurrence_id), row);
            }
            Err(err) => errors.push(format!("decode recurrence row {}: {err}", hex_lower(key))),
        }
    }

    for (key, row) in &qn_index {
        if !series.contains_key(&row.series_id) {
            errors.push(format!(
                "qn index {} points to missing series {}",
                row.qualified_name, row.series_id
            ));
        }
        let bounded_hex = hex_lower(&bounded_qn_key(&row.qualified_name));
        if row.bounded_qn_key_hex != bounded_hex {
            errors.push(format!(
                "qn index {} bounded key mismatch",
                row.qualified_name
            ));
        }
        let expected_key = qn_index_key(&row.project, &row.label, &row.qualified_name);
        if key != &expected_key {
            errors.push(format!("qn index {} key mismatch", row.qualified_name));
        }
    }

    for (series_id, row) in &series {
        for version in &row.versions {
            if reverse.get(&version.cx_id) != Some(series_id) {
                errors.push(format!(
                    "reverse row missing or wrong for {} -> {}",
                    version.cx_id, series_id
                ));
            }
            match recurrence.get(&(*series_id, version.ordinal)) {
                Some(occurrence) if occurrence.new_cx == version.cx_id => {}
                Some(_) => errors.push(format!(
                    "recurrence row mismatch for {} occurrence {}",
                    series_id, version.ordinal
                )),
                None => errors.push(format!(
                    "recurrence row missing for {} occurrence {}",
                    series_id, version.ordinal
                )),
            }
        }
    }

    let sqlite = verify_sqlite_import_deep(vault, &mut errors)?;

    if !errors.is_empty() {
        return Err(IngestError::VerifyFailed(errors));
    }

    Ok(DeepVerifyReport {
        series_rows: series.len(),
        reverse_rows: reverse.len(),
        qn_index_rows: qn_rows,
        recurrence_rows: recurrence.len(),
        split_rows: splits,
        sqlite_node_map_rows: sqlite.node_map_rows,
        sqlite_structural_rows: sqlite.structural_rows,
        sqlite_constellation_rows: sqlite.constellation_rows,
    })
}

/// Opens a durable Aster vault and runs deep registry verification.
pub fn verify_deep_vault_path(
    vault_dir: impl AsRef<Path>,
    vault_id: &str,
    vault_salt: &str,
) -> IngestResult<DeepVerifyReport> {
    let vault_id = VaultId::from_str(vault_id)
        .map_err(|err| IngestError::InvalidInput(format!("invalid vault id: {err}")))?;
    let options = VaultOptions {
        read_only: true,
        restore_ledger_hook: false,
        selected_cfs: Some(vec![ColumnFamily::Kv, ColumnFamily::Recurrence]),
        ..VaultOptions::default()
    };
    let vault = AsterVault::open(vault_dir, vault_id, vault_salt.as_bytes().to_vec(), options)?;
    verify_deep(&vault)
}

fn prepare_input(input: SeriesVersionInput) -> IngestResult<PreparedVersionInput> {
    let identity = input.symbol.identity(input.panel_version)?;
    Ok(PreparedVersionInput {
        input,
        series_id: identity.series_id,
        cx_id: identity.cx_id,
    })
}

fn apply_prepared_batch<C>(
    vault: &AsterVault<C>,
    mut prepared: Vec<PreparedVersionInput>,
) -> IngestResult<SeriesIngestReport>
where
    C: Clock,
{
    prepared.sort_by(|left, right| {
        (
            &left.input.commit,
            &left.input.symbol.project,
            &left.input.symbol.label,
            &left.input.symbol.qualified_name,
            left.cx_id.to_string(),
        )
            .cmp(&(
                &right.input.commit,
                &right.input.symbol.project,
                &right.input.symbol.label,
                &right.input.symbol.qualified_name,
                right.cx_id.to_string(),
            ))
    });

    let mut mutated_rows = 0;
    let inputs = prepared.len();
    for input in prepared {
        mutated_rows += apply_one(vault, input)?;
    }
    Ok(SeriesIngestReport {
        inputs,
        mutated_rows,
        seq: vault.latest_seq(),
    })
}

fn apply_one<C>(vault: &AsterVault<C>, prepared: PreparedVersionInput) -> IngestResult<usize>
where
    C: Clock,
{
    let mut series_id = prepared.series_id;
    let mut split_record = None;
    let mut rename_record = None;

    if let Some(rename) = &prepared.input.rename {
        let candidates = rename_candidates(vault, &prepared, rename)?;
        if candidates.len() == 1 {
            series_id = candidates[0];
            rename_record = Some(RenameRecord {
                commit: prepared.input.commit.clone(),
                old_qualified_name: rename.old_qualified_name.clone(),
                old_rel_file_path: rename.old_rel_file_path.clone(),
            });
        } else if candidates.len() > 1 {
            split_record = Some(build_split_record(&prepared, rename, candidates));
        }
    }

    let existing = read_series_row(vault, series_id)?;
    if existing.as_ref().is_some_and(|row| {
        row.versions
            .iter()
            .any(|version| version.cx_id == prepared.cx_id)
    }) {
        return Ok(0);
    }

    let (row, prev_cx) = match existing {
        Some(mut row) => {
            let prev = Some(row.current_cx_id);
            let ordinal = row.version_count + 1;
            row.qualified_name = prepared.input.symbol.qualified_name.clone();
            row.label = prepared.input.symbol.label.clone();
            row.current_cx_id = prepared.cx_id;
            row.version_count = ordinal;
            row.last_seen = prepared.input.commit.clone();
            row.versions.push(SeriesVersionRef {
                ordinal,
                commit: prepared.input.commit.clone(),
                cx_id: prepared.cx_id,
            });
            if let Some(rename) = rename_record
                && !row.renamed_from.contains(&rename)
            {
                row.renamed_from.push(rename);
            }
            (row, prev)
        }
        None => (
            StoredSeriesRegistryRow {
                schema: SCHEMA_SERIES.to_string(),
                project: prepared.input.symbol.project.clone(),
                series_id,
                qualified_name: prepared.input.symbol.qualified_name.clone(),
                label: prepared.input.symbol.label.clone(),
                current_cx_id: prepared.cx_id,
                version_count: 1,
                first_seen: prepared.input.commit.clone(),
                last_seen: prepared.input.commit.clone(),
                versions: vec![SeriesVersionRef {
                    ordinal: 1,
                    commit: prepared.input.commit.clone(),
                    cx_id: prepared.cx_id,
                }],
                renamed_from: rename_record.into_iter().collect(),
            },
            None,
        ),
    };

    let recurrence = RecurrenceRow {
        schema: SCHEMA_RECURRENCE.to_string(),
        series_id,
        occurrence_id: row.version_count,
        kind: "Recurrence".to_string(),
        commit: prepared.input.commit.clone(),
        prev_cx,
        new_cx: prepared.cx_id,
    };
    let reverse = ReverseIndexRow {
        schema: SCHEMA_REVERSE.to_string(),
        cx_id: prepared.cx_id,
        series_id,
    };
    let qn = QnIndexRow {
        schema: SCHEMA_QN.to_string(),
        project: prepared.input.symbol.project.clone(),
        label: prepared.input.symbol.label.clone(),
        qualified_name: prepared.input.symbol.qualified_name.clone(),
        bounded_qn_key_hex: hex_lower(&bounded_qn_key(&prepared.input.symbol.qualified_name)),
        series_id,
    };

    let mut rows = vec![
        (
            ColumnFamily::Kv,
            series_row_key(series_id),
            serde_json::to_vec(&row)?,
        ),
        (
            ColumnFamily::Kv,
            reverse_index_key(prepared.cx_id),
            serde_json::to_vec(&reverse)?,
        ),
        (
            ColumnFamily::Kv,
            qn_index_key(
                &prepared.input.symbol.project,
                &prepared.input.symbol.label,
                &prepared.input.symbol.qualified_name,
            ),
            serde_json::to_vec(&qn)?,
        ),
        (
            ColumnFamily::Recurrence,
            recurrence_key(series_id, row.version_count),
            serde_json::to_vec(&recurrence)?,
        ),
    ];
    if let Some(split) = split_record {
        rows.push((
            ColumnFamily::Kv,
            split_record_key(&split.split_id),
            serde_json::to_vec(&split)?,
        ));
    }

    let snapshot = vault.latest_seq();
    let mut changed = Vec::new();
    for (cf, key, value) in rows {
        if vault.read_cf_at(snapshot, cf, &key)?.as_ref() != Some(&value) {
            changed.push((cf, key, value));
        }
    }
    let changed_len = changed.len();
    if !changed.is_empty() {
        vault.write_cf_batch(changed)?;
    }
    Ok(changed_len)
}

fn rename_candidates<C>(
    vault: &AsterVault<C>,
    prepared: &PreparedVersionInput,
    rename: &RenameHint,
) -> IngestResult<Vec<SeriesId>>
where
    C: Clock,
{
    if !rename.candidate_series_ids.is_empty() {
        return Ok(rename.candidate_series_ids.clone());
    }

    let key = qn_index_key(
        &prepared.input.symbol.project,
        &prepared.input.symbol.label,
        &rename.old_qualified_name,
    );
    let Some(value) = vault.read_cf_at(vault.latest_seq(), ColumnFamily::Kv, &key)? else {
        return Ok(Vec::new());
    };
    let row: QnIndexRow = serde_json::from_slice(&value)?;
    Ok(vec![row.series_id])
}

fn read_series_row<C>(
    vault: &AsterVault<C>,
    series_id: SeriesId,
) -> IngestResult<Option<StoredSeriesRegistryRow>>
where
    C: Clock,
{
    let Some(value) = vault.read_cf_at(
        vault.latest_seq(),
        ColumnFamily::Kv,
        &series_row_key(series_id),
    )?
    else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_slice(&value)?))
}

fn build_split_record(
    prepared: &PreparedVersionInput,
    rename: &RenameHint,
    mut candidates: Vec<SeriesId>,
) -> SeriesSplitRecord {
    candidates.sort();
    let split_id = split_id(
        &prepared.input.symbol.project,
        &prepared.input.symbol.label,
        &rename.old_qualified_name,
        &prepared.input.symbol.qualified_name,
        &prepared.input.commit,
        &candidates,
    );
    SeriesSplitRecord {
        schema: SCHEMA_SPLIT.to_string(),
        split_id,
        project: prepared.input.symbol.project.clone(),
        label: prepared.input.symbol.label.clone(),
        old_qualified_name: rename.old_qualified_name.clone(),
        new_qualified_name: prepared.input.symbol.qualified_name.clone(),
        commit: prepared.input.commit.clone(),
        candidate_series_ids: candidates,
        reason: "rename_ambiguous".to_string(),
    }
}

fn split_id(
    project: &str,
    label: &str,
    old_qn: &str,
    new_qn: &str,
    commit: &str,
    candidates: &[SeriesId],
) -> String {
    let mut parts = Vec::new();
    parts.extend_from_slice(project.as_bytes());
    parts.push(0);
    parts.extend_from_slice(label.as_bytes());
    parts.push(0);
    parts.extend_from_slice(old_qn.as_bytes());
    parts.push(0);
    parts.extend_from_slice(new_qn.as_bytes());
    parts.push(0);
    parts.extend_from_slice(commit.as_bytes());
    for candidate in candidates {
        parts.extend_from_slice(candidate.as_bytes());
    }
    hex_lower(&calyx_core::content_address([parts.as_slice()]))
}

fn prefixed_key(tag: &[u8], body: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(ASTRO_SERIES_REGISTRY_PREFIX.len() + tag.len() + body.len());
    key.extend_from_slice(ASTRO_SERIES_REGISTRY_PREFIX);
    key.extend_from_slice(tag);
    key.extend_from_slice(body);
    key
}

fn registry_range() -> KeyRange {
    calyx_aster::cf::prefix_range(ASTRO_SERIES_REGISTRY_PREFIX)
}

fn registry_kind(key: &[u8]) -> Option<&'static [u8]> {
    let rest = key.strip_prefix(ASTRO_SERIES_REGISTRY_PREFIX)?;
    [SERIES_ROW_TAG, REVERSE_ROW_TAG, QN_ROW_TAG, SPLIT_ROW_TAG]
        .into_iter()
        .find(|kind| rest.starts_with(kind))
}

fn append_frame(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 2_166_136_261_u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use astrolabe_domain::SymbolLabel;
    use calyx_core::FixedClock;

    const TEST_VAULT_ID: &str = "00000000000000000000000000";
    const TEST_SALT: &str = "astrolabe-test";

    fn vault() -> AsterVault<FixedClock> {
        AsterVault::with_clock(
            TEST_VAULT_ID.parse::<VaultId>().expect("valid vault id"),
            TEST_SALT.as_bytes().to_vec(),
            FixedClock::new(1_785_400_000),
        )
    }

    fn durable_vault_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("astrolabe-{name}-{}-{nanos}", std::process::id()))
    }

    fn symbol(qn: &str, file: &str, body: &str, start: u32) -> SymbolRecord {
        SymbolRecord::new(
            "demo",
            qn,
            SymbolLabel::Function.as_str(),
            file,
            "rust",
            body.as_bytes().to_vec(),
            "fn add(a: i32, b: i32) -> i32",
            start,
            start + 2,
        )
    }

    fn input(qn: &str, file: &str, body: &str, start: u32, commit: &str) -> SeriesVersionInput {
        SeriesVersionInput::new(symbol(qn, file, body, start), 7, commit)
    }

    fn series_row_bytes(vault: &AsterVault<FixedClock>, id: SeriesId) -> Vec<u8> {
        vault
            .read_cf_at(vault.latest_seq(), ColumnFamily::Kv, &series_row_key(id))
            .expect("read series cf")
            .expect("series row exists")
    }

    fn series_row(vault: &AsterVault<FixedClock>, id: SeriesId) -> StoredSeriesRegistryRow {
        serde_json::from_slice(&series_row_bytes(vault, id)).expect("decode series row")
    }

    #[test]
    fn fsv_reads_actual_registry_rows_from_cf() {
        let vault = vault();
        let first = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
        let series_id = first.symbol.series_id().expect("series id");
        let cx_id = first.symbol.cx_id(7).expect("cx id");

        let report = ingest_series_batch(&vault, &[first]).expect("ingest");
        assert_eq!(report.mutated_rows, 4);

        let row = StoredSeriesRegistryRow {
            schema: SCHEMA_SERIES.to_string(),
            project: "demo".to_string(),
            series_id,
            qualified_name: "demo.math.add".to_string(),
            label: "Function".to_string(),
            current_cx_id: cx_id,
            version_count: 1,
            first_seen: "c1".to_string(),
            last_seen: "c1".to_string(),
            versions: vec![SeriesVersionRef {
                ordinal: 1,
                commit: "c1".to_string(),
                cx_id,
            }],
            renamed_from: Vec::new(),
        };
        assert_eq!(
            series_row_bytes(&vault, series_id),
            serde_json::to_vec(&row).expect("expected bytes")
        );

        let reverse_bytes = vault
            .read_cf_at(
                vault.latest_seq(),
                ColumnFamily::Kv,
                &reverse_index_key(cx_id),
            )
            .expect("read reverse")
            .expect("reverse row");
        let reverse: ReverseIndexRow = serde_json::from_slice(&reverse_bytes).expect("reverse");
        assert_eq!(reverse.series_id, series_id);

        assert_eq!(
            verify_deep(&vault).expect("verify"),
            DeepVerifyReport {
                series_rows: 1,
                reverse_rows: 1,
                qn_index_rows: 1,
                recurrence_rows: 1,
                split_rows: 0,
                sqlite_node_map_rows: 0,
                sqlite_structural_rows: 0,
                sqlite_constellation_rows: 0,
            }
        );
    }

    #[test]
    fn verify_deep_vault_path_reopens_durable_registry_rows() {
        let dir = durable_vault_dir("verify-deep");
        fs::create_dir_all(&dir).expect("create durable vault dir");
        {
            let vault = AsterVault::new_durable(
                &dir,
                TEST_VAULT_ID.parse::<VaultId>().expect("valid vault id"),
                TEST_SALT.as_bytes().to_vec(),
                VaultOptions::default(),
            )
            .expect("open durable vault");
            let version = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
            ingest_series_batch(&vault, &[version]).expect("ingest durable registry");
            vault.flush().expect("flush durable registry");
        }

        assert_eq!(
            verify_deep_vault_path(&dir, TEST_VAULT_ID, TEST_SALT).expect("verify durable path"),
            DeepVerifyReport {
                series_rows: 1,
                reverse_rows: 1,
                qn_index_rows: 1,
                recurrence_rows: 1,
                split_rows: 0,
                sqlite_node_map_rows: 0,
                sqlite_structural_rows: 0,
                sqlite_constellation_rows: 0,
            }
        );
        fs::remove_dir_all(&dir).expect("remove durable vault dir");
    }

    #[test]
    fn succession_tracks_three_versions_in_order() {
        let vault = vault();
        let versions = [
            input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1"),
            input("demo.math.add", "src/math.rs", "fn add() { 2 }", 10, "c2"),
            input("demo.math.add", "src/math.rs", "fn add() { 3 }", 10, "c3"),
        ];
        let series_id = versions[0].symbol.series_id().expect("series id");
        let cx_ids = versions
            .iter()
            .map(|version| version.symbol.cx_id(7).expect("cx id"))
            .collect::<Vec<_>>();

        for version in versions {
            ingest_series_batch(&vault, &[version]).expect("ingest version");
        }

        let row = series_row(&vault, series_id);
        assert_eq!(row.version_count, 3);
        assert_eq!(row.current_cx_id, cx_ids[2]);
        assert_eq!(
            row.versions
                .iter()
                .map(|version| version.cx_id)
                .collect::<Vec<_>>(),
            cx_ids
        );

        for ordinal in 1..=3 {
            let bytes = vault
                .read_cf_at(
                    vault.latest_seq(),
                    ColumnFamily::Recurrence,
                    &recurrence_key(series_id, ordinal),
                )
                .expect("read recurrence")
                .expect("recurrence row");
            let row: RecurrenceRow = serde_json::from_slice(&bytes).expect("recurrence");
            assert_eq!(row.occurrence_id, ordinal);
            assert_eq!(row.new_cx, cx_ids[(ordinal - 1) as usize]);
            if ordinal == 1 {
                assert_eq!(row.prev_cx, None);
            } else {
                assert_eq!(row.prev_cx, Some(cx_ids[(ordinal - 2) as usize]));
            }
        }
    }

    #[test]
    fn rename_continues_existing_series_and_records_renamed_from() {
        let vault = vault();
        let original = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
        let series_id = original.symbol.series_id().expect("series id");
        ingest_series_batch(&vault, &[original]).expect("original ingest");

        let status =
            parse_git_rename_status("R100\tsrc/math.rs\tsrc/arithmetic.rs").expect("parse rename");
        let renamed = SeriesVersionInput::new(
            symbol(
                "demo.arithmetic.add",
                "src/arithmetic.rs",
                "fn add() { 2 }",
                10,
            ),
            7,
            "c2",
        )
        .with_rename(RenameHint::from_paths(
            "demo.math.add",
            status.old_path.clone(),
        ));
        let renamed_cx = renamed.symbol.cx_id(7).expect("renamed cx");
        ingest_series_batch(&vault, &[renamed]).expect("rename ingest");

        let row = series_row(&vault, series_id);
        assert_eq!(row.qualified_name, "demo.arithmetic.add");
        assert_eq!(row.version_count, 2);
        assert_eq!(row.current_cx_id, renamed_cx);
        assert_eq!(
            row.renamed_from,
            vec![RenameRecord {
                commit: "c2".to_string(),
                old_qualified_name: "demo.math.add".to_string(),
                old_rel_file_path: "src/math.rs".to_string(),
            }]
        );

        let reverse: ReverseIndexRow = serde_json::from_slice(
            &vault
                .read_cf_at(
                    vault.latest_seq(),
                    ColumnFamily::Kv,
                    &reverse_index_key(renamed_cx),
                )
                .expect("read reverse")
                .expect("reverse"),
        )
        .expect("decode reverse");
        assert_eq!(reverse.series_id, series_id);
    }

    #[test]
    fn ambiguous_rename_writes_queryable_split_record() {
        let vault = vault();
        let first = input("demo.math.add", "src/a.rs", "fn add() { 1 }", 10, "c1");
        let second = input("demo.math.add_alt", "src/b.rs", "fn add() { 1 }", 20, "c1");
        let candidate_a = first.symbol.series_id().expect("candidate a");
        let candidate_b = second.symbol.series_id().expect("candidate b");
        ingest_series_batch(&vault, &[first, second]).expect("seed candidates");

        let renamed = SeriesVersionInput::new(
            symbol("demo.math.renamed", "src/c.rs", "fn add() { 2 }", 10),
            7,
            "c2",
        )
        .with_rename(RenameHint::with_candidates(
            "demo.math.add",
            "src/a.rs",
            vec![candidate_b, candidate_a],
        ));
        ingest_series_batch(&vault, &[renamed]).expect("ambiguous rename");

        let snapshot = read_registry_snapshot(&vault).expect("snapshot");
        let split_rows = snapshot
            .kv_rows
            .iter()
            .filter(|(key, _)| registry_kind(key) == Some(SPLIT_ROW_TAG))
            .collect::<Vec<_>>();
        assert_eq!(split_rows.len(), 1);
        let split: SeriesSplitRecord =
            serde_json::from_slice(&split_rows[0].1).expect("decode split");
        assert_eq!(split.reason, "rename_ambiguous");
        let mut expected = vec![candidate_a, candidate_b];
        expected.sort();
        assert_eq!(split.candidate_series_ids, expected);
    }

    #[test]
    fn rename_without_prior_candidate_does_not_write_ambiguous_split() {
        let vault = vault();
        let renamed = SeriesVersionInput::new(
            symbol("demo.math.renamed", "src/renamed.rs", "fn add() { 2 }", 10),
            7,
            "c2",
        )
        .with_rename(RenameHint::from_paths("demo.math.add", "src/math.rs"));
        let series_id = renamed.symbol.series_id().expect("new series");

        ingest_series_batch(&vault, &[renamed]).expect("rename ingest");

        assert_eq!(series_row(&vault, series_id).version_count, 1);
        let snapshot = read_registry_snapshot(&vault).expect("snapshot");
        assert_eq!(
            snapshot
                .kv_rows
                .iter()
                .filter(|(key, _)| registry_kind(key) == Some(SPLIT_ROW_TAG))
                .count(),
            0
        );
    }

    #[test]
    fn reingest_unchanged_mutates_zero_rows_and_preserves_bytes() {
        let vault = vault();
        let version = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
        ingest_series_batch(&vault, std::slice::from_ref(&version)).expect("first ingest");
        let before = read_registry_snapshot(&vault).expect("before");

        let report = ingest_series_batch(&vault, &[version]).expect("second ingest");
        let after = read_registry_snapshot(&vault).expect("after");

        assert_eq!(report.mutated_rows, 0);
        assert_eq!(before, after);
    }

    #[test]
    fn parallel_preparation_matches_sequential_final_state() {
        let sequential = vault();
        let parallel = vault();
        let inputs = vec![
            input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1"),
            input("demo.math.sub", "src/math.rs", "fn sub() { 1 }", 20, "c1"),
            input("demo.math.mul", "src/math.rs", "fn mul() { 1 }", 30, "c1"),
        ];

        ingest_series_batch(&sequential, &inputs).expect("sequential");
        let mut reversed = inputs.clone();
        reversed.reverse();
        ingest_series_batch_parallel(&parallel, &reversed).expect("parallel");

        assert_eq!(
            read_registry_snapshot(&sequential).expect("sequential snapshot"),
            read_registry_snapshot(&parallel).expect("parallel snapshot")
        );
    }

    #[test]
    fn qn_fallback_respects_fnv_tail_cap_for_long_names() {
        let qn = format!("{}A", "x".repeat(300));
        let same_prefix = format!("{}B", "x".repeat(300));

        let bounded = bounded_qn_key(&qn);
        let other = bounded_qn_key(&same_prefix);

        assert_eq!(bounded.len(), QN_KEY_MAX_BYTES);
        assert_eq!(
            &bounded[..QN_KEY_MAX_BYTES - QN_HASH_SUFFIX_BYTES],
            "x".repeat(246).as_bytes()
        );
        assert_eq!(bounded[QN_KEY_MAX_BYTES - QN_HASH_SUFFIX_BYTES], b'-');
        assert_ne!(bounded, other);
        assert_eq!(bounded_qn_key("short.qn"), b"short.qn");
    }

    #[test]
    fn verify_deep_fails_on_corrupt_reverse_row() {
        let vault = vault();
        let version = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
        let cx_id = version.symbol.cx_id(7).expect("cx");
        ingest_series_batch(&vault, &[version]).expect("ingest");
        vault
            .write_cf(ColumnFamily::Kv, reverse_index_key(cx_id), b"{}".to_vec())
            .expect("corrupt reverse");

        assert!(matches!(
            verify_deep(&vault),
            Err(IngestError::VerifyFailed(_))
        ));
    }

    #[test]
    fn verify_deep_fails_on_qn_index_pointing_to_missing_series() {
        let vault = vault();
        let version = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
        ingest_series_batch(&vault, &[version]).expect("ingest");

        let key = qn_index_key("demo", SymbolLabel::Function.as_str(), "demo.math.add");
        let bytes = vault
            .read_cf_at(vault.latest_seq(), ColumnFamily::Kv, &key)
            .expect("read qn")
            .expect("qn row");
        let mut qn: QnIndexRow = serde_json::from_slice(&bytes).expect("decode qn");
        qn.series_id = SeriesId::from_bytes([9; 16]);
        vault
            .write_cf(
                ColumnFamily::Kv,
                key,
                serde_json::to_vec(&qn).expect("encode qn"),
            )
            .expect("corrupt qn");

        let err = verify_deep(&vault).expect_err("qn corruption should fail verify");
        let IngestError::VerifyFailed(errors) = err else {
            panic!("unexpected verify error: {err}");
        };
        assert!(
            errors
                .iter()
                .any(|error| error.contains("points to missing series"))
        );
    }

    #[test]
    fn registry_snapshot_scans_only_astrolabe_namespace() {
        let vault = vault();
        vault
            .write_cf(ColumnFamily::Kv, b"foreign".to_vec(), b"value".to_vec())
            .expect("foreign write");

        let snapshot = read_registry_snapshot(&vault).expect("snapshot");
        assert!(snapshot.kv_rows.is_empty());
        assert!(snapshot.recurrence_rows.is_empty());
    }

    #[test]
    fn split_id_is_candidate_order_independent() {
        let a = SeriesId::from_bytes([1; 16]);
        let b = SeriesId::from_bytes([2; 16]);
        let left = split_id("p", "Function", "old", "new", "c1", &[a, b]);
        let right = split_id("p", "Function", "old", "new", "c1", &[b, a]);

        assert_ne!(
            left, right,
            "caller must sort candidate order before split_id"
        );
        let mut candidates = vec![b, a];
        candidates.sort();
        let sorted = split_id("p", "Function", "old", "new", "c1", &candidates);
        assert_eq!(left, sorted);
    }

    #[test]
    fn parse_git_rename_status_accepts_porcelain_and_name_status() {
        assert_eq!(
            parse_git_rename_status("R  old.rs -> new.rs"),
            Some(GitRenameStatus {
                status: "R".to_string(),
                old_path: "old.rs".to_string(),
                new_path: "new.rs".to_string(),
            })
        );
        assert_eq!(
            parse_git_rename_status("R100\told.rs\tnew.rs"),
            Some(GitRenameStatus {
                status: "R100".to_string(),
                old_path: "old.rs".to_string(),
                new_path: "new.rs".to_string(),
            })
        );
    }
}
