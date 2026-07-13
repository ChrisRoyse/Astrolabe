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
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use serde::{Deserialize, Serialize};

use crate::fsv::VaultMutationPlan;
use crate::ledger_verify::{verify_chain, verify_ledger_pairing};
use crate::sqlite_import::verify_sqlite_import_deep;
use crate::{ASTRO_SERIES_ID_V1_REBUILD_REQUIRED, SERIES_ID_V1_REBUILD_REMEDIATION};

pub use astrolabe_domain::fsv::FsvAck;

/// Namespace prefix for every Astrolabe series registry key stored in Aster.
pub const ASTRO_SERIES_REGISTRY_PREFIX: &[u8] = b"astrolabe:series-registry:v2:";
/// Stable failure code for `astrolabe verify --deep` invariant violations.
pub const ASTRO_VERIFY_DEEP_FAILED: &str = "ASTRO_VERIFY_DEEP_FAILED";
/// Maximum QN key bytes before the CBM-style FNV tail fallback is applied.
pub const QN_KEY_MAX_BYTES: usize = 255;

const QN_HASH_SUFFIX_BYTES: usize = 9;
const LEGACY_SERIES_REGISTRY_PREFIX_V1: &[u8] = b"astrolabe:series-registry:v1:";
const SERIES_ROW_TAG: &[u8] = b"series:";
const REVERSE_ROW_TAG: &[u8] = b"reverse:";
const QN_ROW_TAG: &[u8] = b"qn:";
const SPLIT_ROW_TAG: &[u8] = b"split:";
const RECURRENCE_ROW_TAG: &[u8] = b"recurrence:";
const SCHEMA_SERIES: &str = "astrolabe-series-row-v2";
const SCHEMA_REVERSE: &str = "astrolabe-series-reverse-v2";
const SCHEMA_QN: &str = "astrolabe-series-qn-index-v2";
const SCHEMA_RECURRENCE: &str = "astrolabe-series-recurrence-v2";
const SCHEMA_SPLIT: &str = "astrolabe-series-split-v2";
const SCHEMA_REGISTRY_BATCH_LEDGER: &str = "astrolabe-registry-batch-ledger-v1";
const ASTROLABE_REGISTRY_ACTOR: &str = "astrolabe-registry";

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
                    "{ASTRO_VERIFY_DEEP_FAILED}: series registry verify --deep failed: {}",
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
            Self::Calyx(err) => Some(err.code),
            Self::Refused { code, .. } => Some(code),
            Self::VerifyFailed(_) => Some(ASTRO_VERIFY_DEEP_FAILED),
            Self::Json(_) | Self::InvalidInput(_) => None,
        }
    }

    /// Returns the operator-facing remediation when this error has one.
    pub fn remediation(&self) -> Option<&str> {
        match self {
            Self::Domain(err) => Some(err.remediation()),
            Self::Panel(err) => Some(err.remediation()),
            Self::Calyx(err) => Some(err.remediation),
            Self::Refused { remediation, .. } => Some(remediation),
            Self::VerifyFailed(_) => Some(
                "Quarantine the vault, inspect the named invariant violations, and rebuild from source bytes before serving reads.",
            ),
            Self::Json(_) | Self::InvalidInput(_) => None,
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct SeriesRegistryBatchLedgerPayload {
    schema: String,
    /// Inputs presented to the batch (before idempotent de-duplication).
    input_count: u64,
    /// Inputs that appended a new series version (non-idempotent applications).
    versions_added: u64,
    /// Ambiguous-rename split records written by the batch.
    splits_written: u64,
    /// Distinct CF rows physically written by the batch's single group commit.
    changed_rows: u64,
    /// blake3 over the applied `(series_id, cx_id, version_count, commit)` tuples in the
    /// batch's canonical (sorted) order, so the single ledger entry still fixes the exact
    /// set of versions the commit admitted.
    batch_digest: String,
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
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct SeriesIngestReport {
    /// Number of input versions considered.
    pub inputs: usize,
    /// Number of raw CF rows mutated.
    pub mutated_rows: usize,
    /// Latest Aster sequence after the batch.
    pub seq: Seq,
    /// Engine-native FSV write-ack (#178): present exactly when the batch
    /// persisted rows and every persisted row plus the paired ledger entry read
    /// back and matched. `None` is a *labeled* absence — an idempotent batch that
    /// changed nothing has no ledger entry to pair, so no `fsv:verified` claim is
    /// made. A caller must never treat a `None` here as a verified mutation.
    pub fsv: Option<FsvAck>,
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
    /// Number of SQLite-import typed edge rows decoded and provenance-checked.
    pub sqlite_edge_rows: usize,
    /// Ledger hash-chain status (`intact`, `broken`, or `corrupt`).
    pub ledger_chain_status: String,
    /// Number of Ledger CF rows visible during deep verification.
    pub ledger_rows: u64,
    /// Number of Ledger payload rows decoded and redaction-checked.
    pub ledger_payload_rows: usize,
    /// Number of Base CF rows paired to a real Ledger entry hash.
    pub base_ledger_pairs: usize,
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
    ensure_no_legacy_series_state(vault)?;
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
    ensure_no_legacy_series_state(vault)?;
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
    ensure_no_legacy_series_state(vault)?;
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

    // Reverse walk: an orphan reverse-index row whose owning (forward) series row is
    // missing decodes cleanly and must still fail closed, naming the exact reverse key.
    for (cx_id, series_id) in &reverse {
        if !series.contains_key(series_id) {
            errors.push(format!(
                "reverse row {} points to missing series {}",
                cx_id, series_id
            ));
        }
    }

    // Recurrence walk: an orphan recurrence row whose owning series row is missing, or
    // whose occurrence_id falls outside the owning series version count, decodes cleanly
    // and must still fail closed, naming the exact recurrence key (series:occurrence).
    for (series_id, occurrence_id) in recurrence.keys() {
        match series.get(series_id) {
            None => errors.push(format!(
                "recurrence row {}:{} points to missing series {}",
                series_id, occurrence_id, series_id
            )),
            Some(series_row) => {
                if *occurrence_id == 0 || *occurrence_id > series_row.version_count {
                    errors.push(format!(
                        "recurrence row {}:{} occurrence_id out of range for series {} (version_count={})",
                        series_id, occurrence_id, series_id, series_row.version_count
                    ));
                }
            }
        }
    }

    let ledger_chain = verify_chain(vault)?;
    if !ledger_chain.is_intact() {
        errors.push(format!(
            "ledger chain {} at seq {:?}; quarantine_seq={:?}",
            ledger_chain.status, ledger_chain.at_seq, ledger_chain.quarantine_seq
        ));
    }
    let ledger_pairing = verify_ledger_pairing(vault, &mut errors)?;
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
        sqlite_edge_rows: sqlite.edge_rows,
        ledger_chain_status: ledger_chain.status,
        ledger_rows: ledger_chain.ledger_rows,
        ledger_payload_rows: ledger_pairing.ledger_payload_rows,
        base_ledger_pairs: ledger_pairing.base_ledger_pairs,
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
        selected_cfs: Some(vec![
            ColumnFamily::Kv,
            ColumnFamily::Recurrence,
            ColumnFamily::Graph,
            ColumnFamily::Base,
            ColumnFamily::Ledger,
        ]),
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

    let inputs = prepared.len();

    // Stage every input against an in-memory working set seeded from the batch-start
    // snapshot, accumulating the CF mutations for the whole batch. This replaces the former
    // per-symbol `write_cf_batch_with_ledger_entry` loop (N fsync'd commits + N ledger rows
    // for N symbols) with a single group commit and a single batch-level ledger entry.
    let mut batch = RegistryBatch::new(vault.latest_seq());
    for input in prepared {
        stage_one(vault, &mut batch, input)?;
    }

    // Determine which staged rows differ from the batch-start snapshot. Iterating the
    // deduped write map (a BTreeMap) yields a deterministic, key-sorted change set.
    let mut changed = Vec::with_capacity(batch.writes.len());
    for ((cf, key), value) in &batch.writes {
        if vault.read_cf_at(batch.snapshot, *cf, key)?.as_ref() != Some(value) {
            changed.push((*cf, key.clone(), value.clone()));
        }
    }
    let mutated_rows = changed.len();

    let fsv = if changed.is_empty() {
        // Idempotent batch: nothing persisted, so there is no ledger entry to
        // pair and no `fsv:verified` claim to make. Reported as a labeled
        // absence (`None`), never as a silent success.
        None
    } else {
        let subject = SubjectId::Query(batch.digest.finalize().as_bytes().to_vec());
        let actor = ActorId::Service(ASTROLABE_REGISTRY_ACTOR.to_string());
        // Build the FSV plan from the exact rows the commit will persist, before
        // committing, so verification re-reads persisted bytes rather than the
        // write set. Every registry row is a live content write (no tombstones).
        let mut plan =
            VaultMutationPlan::new("ingest_series_batch", EntryKind::Ingest, &actor, &subject);
        for (cf, key, value) in &changed {
            plan.push_content(*cf, key.clone(), value);
        }
        let payload =
            series_registry_batch_ledger_payload(&batch, inputs as u64, mutated_rows as u64)?;
        vault.write_cf_batch_with_ledger_entry(
            changed,
            EntryKind::Ingest,
            subject,
            payload,
            actor,
        )?;
        // Write-ack-after-readback: re-read every persisted row and the paired
        // ledger entry at the commit snapshot. On any divergence this fails
        // closed and the batch never reports success.
        Some(plan.verify_committed(vault, vault.latest_seq())?)
    };

    Ok(SeriesIngestReport {
        inputs,
        mutated_rows,
        seq: vault.latest_seq(),
        fsv,
    })
}

/// In-memory accumulator for a single registry ingest batch.
///
/// Series rows evolve in `series` (seeded once from the batch-start snapshot), and every
/// resulting CF mutation is deduped by `(cf, key)` in `writes` so a series touched by
/// multiple versions in one batch collapses to its final row while distinct version rows
/// (reverse/recurrence keyed per version) are all retained.
struct RegistryBatch {
    snapshot: Seq,
    series: BTreeMap<SeriesId, Option<StoredSeriesRegistryRow>>,
    writes: BTreeMap<(ColumnFamily, Vec<u8>), Vec<u8>>,
    versions_added: u64,
    splits_written: u64,
    digest: blake3::Hasher,
}

impl RegistryBatch {
    fn new(snapshot: Seq) -> Self {
        Self {
            snapshot,
            series: BTreeMap::new(),
            writes: BTreeMap::new(),
            versions_added: 0,
            splits_written: 0,
            digest: blake3::Hasher::new(),
        }
    }

    /// Returns the current in-batch series row, seeding it from the snapshot on first touch.
    fn current_series<C>(
        &mut self,
        vault: &AsterVault<C>,
        series_id: SeriesId,
    ) -> IngestResult<Option<StoredSeriesRegistryRow>>
    where
        C: Clock,
    {
        if !self.series.contains_key(&series_id) {
            let seeded = read_series_row_at(vault, self.snapshot, series_id)?;
            self.series.insert(series_id, seeded);
        }
        Ok(self.series.get(&series_id).cloned().flatten())
    }

    /// Records the evolved series row: updates the working set and stages the CF write.
    fn set_series(
        &mut self,
        series_id: SeriesId,
        row: StoredSeriesRegistryRow,
    ) -> IngestResult<()> {
        self.push(
            ColumnFamily::Kv,
            series_row_key(series_id),
            serde_json::to_vec(&row)?,
        );
        self.series.insert(series_id, Some(row));
        Ok(())
    }

    fn push(&mut self, cf: ColumnFamily, key: Vec<u8>, value: Vec<u8>) {
        self.writes.insert((cf, key), value);
    }
}

fn stage_one<C>(
    vault: &AsterVault<C>,
    batch: &mut RegistryBatch,
    prepared: PreparedVersionInput,
) -> IngestResult<()>
where
    C: Clock,
{
    let mut series_id = prepared.series_id;
    let mut split_record = None;
    let mut rename_record = None;

    if let Some(rename) = &prepared.input.rename {
        let candidates = batch_rename_candidates(vault, batch, &prepared, rename)?;
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

    let existing = batch.current_series(vault, series_id)?;
    if existing.as_ref().is_some_and(|row| {
        row.versions
            .iter()
            .any(|version| version.cx_id == prepared.cx_id)
    }) {
        // Idempotent: this exact version is already present, so the input stages nothing.
        return Ok(());
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

    let ordinal = row.version_count;
    batch.set_series(series_id, row)?;
    batch.push(
        ColumnFamily::Kv,
        reverse_index_key(prepared.cx_id),
        serde_json::to_vec(&reverse)?,
    );
    batch.push(
        ColumnFamily::Kv,
        qn_index_key(
            &prepared.input.symbol.project,
            &prepared.input.symbol.label,
            &prepared.input.symbol.qualified_name,
        ),
        serde_json::to_vec(&qn)?,
    );
    batch.push(
        ColumnFamily::Recurrence,
        recurrence_key(series_id, ordinal),
        serde_json::to_vec(&recurrence)?,
    );
    if let Some(split) = split_record {
        batch.push(
            ColumnFamily::Kv,
            split_record_key(&split.split_id),
            serde_json::to_vec(&split)?,
        );
        batch.splits_written += 1;
    }

    // Fold this application into the batch provenance digest in canonical order.
    batch.digest.update(series_id.to_string().as_bytes());
    batch.digest.update(prepared.cx_id.to_string().as_bytes());
    batch.digest.update(&ordinal.to_le_bytes());
    batch.digest.update(prepared.input.commit.as_bytes());
    batch.versions_added += 1;

    Ok(())
}

fn series_registry_batch_ledger_payload(
    batch: &RegistryBatch,
    input_count: u64,
    changed_rows: u64,
) -> IngestResult<Vec<u8>> {
    let payload = SeriesRegistryBatchLedgerPayload {
        schema: SCHEMA_REGISTRY_BATCH_LEDGER.to_string(),
        input_count,
        versions_added: batch.versions_added,
        splits_written: batch.splits_written,
        changed_rows,
        batch_digest: hex_lower(batch.digest.finalize().as_bytes()),
    };
    Ok(serde_json::to_vec(&payload)?)
}

fn batch_rename_candidates<C>(
    vault: &AsterVault<C>,
    batch: &RegistryBatch,
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
    // A qn-index row staged earlier in this same batch wins over the committed snapshot, so
    // a rename can continue a series first observed within the batch.
    let value = if let Some(staged) = batch.writes.get(&(ColumnFamily::Kv, key.clone())) {
        Some(staged.clone())
    } else {
        vault.read_cf_at(batch.snapshot, ColumnFamily::Kv, &key)?
    };
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let row: QnIndexRow = serde_json::from_slice(&value)?;
    Ok(vec![row.series_id])
}

fn read_series_row_at<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    series_id: SeriesId,
) -> IngestResult<Option<StoredSeriesRegistryRow>>
where
    C: Clock,
{
    let Some(value) = vault.read_cf_at(snapshot, ColumnFamily::Kv, &series_row_key(series_id))?
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

fn ensure_no_legacy_series_state<C>(vault: &AsterVault<C>) -> IngestResult<()>
where
    C: Clock,
{
    ensure_no_legacy_series_registry(vault)?;
    crate::sqlite_import::ensure_no_legacy_node_maps(vault)
}

pub(crate) fn ensure_no_legacy_series_registry<C>(vault: &AsterVault<C>) -> IngestResult<()>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let range = calyx_aster::cf::prefix_range(LEGACY_SERIES_REGISTRY_PREFIX_V1);
    let legacy_kv = vault
        .scan_cf_range_at(snapshot, ColumnFamily::Kv, &range)?
        .len();
    let legacy_recurrence = vault
        .scan_cf_range_at(snapshot, ColumnFamily::Recurrence, &range)?
        .len();
    if legacy_kv != 0 || legacy_recurrence != 0 {
        return Err(IngestError::refused(
            ASTRO_SERIES_ID_V1_REBUILD_REQUIRED,
            format!(
                "vault contains collision-prone v1 series state: kv_rows={legacy_kv}, recurrence_rows={legacy_recurrence}"
            ),
            SERIES_ID_V1_REBUILD_REMEDIATION,
        ));
    }
    Ok(())
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
    fn legacy_v1_registry_is_refused_before_v2_mutation() {
        let vault = vault();
        let mut legacy_key = LEGACY_SERIES_REGISTRY_PREFIX_V1.to_vec();
        legacy_key.extend_from_slice(SERIES_ROW_TAG);
        legacy_key.extend_from_slice(&[7; 16]);
        vault
            .write_cf(ColumnFamily::Kv, legacy_key, b"legacy-v1".to_vec())
            .expect("write legacy registry marker");
        let before = vault.latest_seq();
        let version = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");

        let err = ingest_series_batch(&vault, &[version]).expect_err("legacy registry refused");
        assert_eq!(err.code(), Some(ASTRO_SERIES_ID_V1_REBUILD_REQUIRED));
        assert_eq!(err.remediation(), Some(SERIES_ID_V1_REBUILD_REMEDIATION));
        assert_eq!(vault.latest_seq(), before);
        assert!(
            vault
                .scan_cf_range_at(
                    vault.latest_seq(),
                    ColumnFamily::Kv,
                    &calyx_aster::cf::prefix_range(ASTRO_SERIES_REGISTRY_PREFIX),
                )
                .expect("scan v2 registry")
                .is_empty()
        );

        let err = verify_deep(&vault).expect_err("deep verify refuses legacy registry");
        assert_eq!(err.code(), Some(ASTRO_SERIES_ID_V1_REBUILD_REQUIRED));
        let err = crate::read_cbm_graph_snapshot(&vault, "demo")
            .expect_err("graph read refuses legacy registry");
        assert_eq!(err.code(), Some(ASTRO_SERIES_ID_V1_REBUILD_REQUIRED));
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
                sqlite_edge_rows: 0,
                ledger_chain_status: "intact".to_string(),
                ledger_rows: 1,
                ledger_payload_rows: 1,
                base_ledger_pairs: 0,
            }
        );
    }

    #[test]
    fn fsv_series_batch_ack_binds_persisted_rows_and_paired_ledger() {
        // The engine-native write-ack (#178) must be present, labeled full, and
        // its ledger_seq must be the ledger entry actually persisted on disk.
        let vault = vault();
        let first = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
        let report = ingest_series_batch(&vault, &[first]).expect("ingest");
        assert_eq!(report.mutated_rows, 4);

        let ack = report
            .fsv
            .as_ref()
            .expect("verified mutation carries an ack");
        assert_eq!(ack.label(), astrolabe_domain::fsv::FSV_LABEL_VERIFIED);
        assert!(ack.is_full_readback());
        assert_eq!(ack.rows_planned(), 4);
        assert_eq!(ack.rows_read_back(), 4);

        // Independent readback: the ledger entry named by the ack really is the
        // newest persisted Ledger CF row, and it is the batch Ingest entry.
        let (_key, ledger_bytes) = vault
            .scan_cf_at(vault.latest_seq(), ColumnFamily::Ledger)
            .expect("scan ledger")
            .into_iter()
            .max_by(|left, right| left.0.cmp(&right.0))
            .expect("ledger row exists");
        let entry = calyx_ledger::decode(&ledger_bytes).expect("decode ledger");
        assert_eq!(ack.ledger_seq(), entry.seq);
        assert_eq!(entry.kind, EntryKind::Ingest);
    }

    #[test]
    fn fsv_idempotent_replay_makes_no_verified_claim() {
        // A batch that changes nothing persists no ledger entry, so it must NOT
        // fabricate an `fsv:verified` ack. The absence is labeled (None), not a
        // silent success — proving the negative of standing invariant 1/3.
        let vault = vault();
        let first = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
        let ack = ingest_series_batch(&vault, std::slice::from_ref(&first))
            .expect("first ingest")
            .fsv;
        assert!(ack.is_some(), "the first batch really mutated rows");

        let replay = ingest_series_batch(&vault, &[first]).expect("idempotent replay");
        assert_eq!(replay.mutated_rows, 0);
        assert!(
            replay.fsv.is_none(),
            "an idempotent no-op batch must not claim fsv:verified"
        );
    }

    #[test]
    fn fsv_verify_committed_refuses_mutation_without_paired_ledger() {
        // A data write with no ledger entry cannot ack: mutation⇔ledger pairing
        // is enforced at the API, not by convention.
        let vault = vault();
        let key = b"astrolabe:series-registry:v2:series:unpaired".to_vec();
        let value = b"payload".to_vec();
        let mut plan = VaultMutationPlan::new(
            "unpaired-test",
            EntryKind::Ingest,
            &ActorId::Service(ASTROLABE_REGISTRY_ACTOR.to_string()),
            &SubjectId::Query(b"unpaired".to_vec()),
        );
        plan.push_content(ColumnFamily::Kv, key.clone(), &value);
        // Commit the row WITHOUT a ledger entry.
        vault
            .write_cf_batch([(ColumnFamily::Kv, key.clone(), value.clone())])
            .expect("write data row without ledger");

        let err = plan
            .verify_committed(&vault, vault.latest_seq())
            .expect_err("mutation without ledger must refuse");
        assert_eq!(err.code, astrolabe_domain::fsv::ASTRO_FSV_LEDGER_UNPAIRED);
    }

    #[test]
    fn fsv_verify_committed_detects_one_byte_tamper_in_persisted_kv_row_on_disk() {
        // Gold-standard FSV: write one real Kv row to a durable vault, flush it
        // to an on-disk SST, flip exactly one byte in that SST, reopen, and prove
        // verify_committed reads the tampered bytes back and refuses fail-closed,
        // naming the exact column family and key.
        let dir = durable_vault_dir("fsv-kv-tamper");
        fs::create_dir_all(&dir).expect("create durable vault dir");
        let key = b"astrolabe:series-registry:v2:series:tamper".to_vec();
        let value = b"the-canonical-persisted-registry-row-bytes".to_vec();
        let subject = SubjectId::Query(b"tamper".to_vec());
        let actor = ActorId::Service(ASTROLABE_REGISTRY_ACTOR.to_string());

        {
            let vault = AsterVault::new_durable(
                &dir,
                TEST_VAULT_ID.parse::<VaultId>().expect("valid vault id"),
                TEST_SALT.as_bytes().to_vec(),
                VaultOptions::default(),
            )
            .expect("open durable vault");
            let mut plan =
                VaultMutationPlan::new("tamper-test", EntryKind::Ingest, &actor, &subject);
            plan.push_content(ColumnFamily::Kv, key.clone(), &value);
            vault
                .write_cf_batch_with_ledger_entry(
                    [(ColumnFamily::Kv, key.clone(), value.clone())],
                    EntryKind::Ingest,
                    subject.clone(),
                    br#"{"schema":"astrolabe-fsv-tamper-test-v1"}"#.to_vec(),
                    actor.clone(),
                )
                .expect("commit registry row + ledger");
            // Clean commit reads back clean and produces a verified ack.
            let ack = plan
                .verify_committed(&vault, vault.latest_seq())
                .expect("clean readback");
            assert_eq!(ack.label(), astrolabe_domain::fsv::FSV_LABEL_VERIFIED);
            vault.flush().expect("flush durable vault");
        }

        // Independent read of the persisted bytes BEFORE tamper.
        let before = read_kv_sst_first_value(&dir);
        // Flip one byte on disk and repair the SST CRCs so the corruption is not
        // caught by the SST framing but only by the content-hash readback.
        tamper_cf_sst_first_value(&dir, ColumnFamily::Kv);
        let after = read_kv_sst_first_value(&dir);
        assert_ne!(before, after, "the on-disk value byte really changed");

        let vault = AsterVault::new_durable(
            &dir,
            TEST_VAULT_ID.parse::<VaultId>().expect("valid vault id"),
            TEST_SALT.as_bytes().to_vec(),
            VaultOptions::default(),
        )
        .expect("reopen durable vault (ledger intact, data CF tampered)");
        let mut plan = VaultMutationPlan::new("tamper-test", EntryKind::Ingest, &actor, &subject);
        plan.push_content(ColumnFamily::Kv, key.clone(), &value);
        let err = plan
            .verify_committed(&vault, vault.latest_seq())
            .expect_err("tampered persisted bytes must fail closed");
        assert_eq!(err.code, astrolabe_domain::fsv::ASTRO_FSV_READBACK_MISMATCH);
        assert!(err.to_string().contains("kv"), "names the CF: {err}");
        fs::remove_dir_all(&dir).ok();
    }

    /// Returns the value bytes of the first record in the Kv CF's SST.
    fn read_kv_sst_first_value(vault_dir: &Path) -> Vec<u8> {
        let (path, bytes) = read_cf_sst(vault_dir, ColumnFamily::Kv);
        let _ = path;
        let (_key_start, value_start, value_len) =
            first_sst_record_offsets(&bytes).expect("first record");
        bytes[value_start..value_start + value_len].to_vec()
    }

    fn read_cf_sst(vault_dir: &Path, cf: ColumnFamily) -> (std::path::PathBuf, Vec<u8>) {
        let cf_dir = vault_dir.join("cf").join(cf.name());
        for entry in fs::read_dir(&cf_dir).expect("read cf dir") {
            let path = entry.expect("cf dir entry").path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("sst") {
                let bytes = fs::read(&path).expect("read cf sst");
                if first_sst_record_offsets(&bytes).is_some() {
                    return (path, bytes);
                }
            }
        }
        panic!("no SST with a record in {}", cf_dir.display());
    }

    fn tamper_cf_sst_first_value(vault_dir: &Path, cf: ColumnFamily) {
        let (path, mut bytes) = read_cf_sst(vault_dir, cf);
        let (key_start, value_start, value_len) =
            first_sst_record_offsets(&bytes).expect("first record");
        assert!(value_len > 0, "value must be non-empty");
        bytes[value_start] ^= 0xff;
        rewrite_sst_crcs(&mut bytes, key_start, value_start, value_len);
        fs::write(&path, bytes).expect("write tampered cf sst");
    }

    fn first_sst_record_offsets(bytes: &[u8]) -> Option<(usize, usize, usize)> {
        const HEADER_LEN: usize = 32;
        const RECORD_HEADER_LEN: usize = 12;
        if bytes.len() < HEADER_LEN + RECORD_HEADER_LEN {
            return None;
        }
        let record = &bytes[HEADER_LEN..HEADER_LEN + RECORD_HEADER_LEN];
        let key_len = u32::from_le_bytes(record[0..4].try_into().expect("key len")) as usize;
        let value_len = u32::from_le_bytes(record[4..8].try_into().expect("value len")) as usize;
        let key_start = HEADER_LEN + RECORD_HEADER_LEN;
        let value_start = key_start + key_len;
        let value_end = value_start + value_len;
        (value_end <= bytes.len() && value_len > 0).then_some((key_start, value_start, value_len))
    }

    fn rewrite_sst_crcs(bytes: &mut [u8], key_start: usize, value_start: usize, value_len: usize) {
        const HEADER_LEN: usize = 32;
        let value_end = value_start + value_len;
        let mut record_hasher = crc32fast::Hasher::new();
        record_hasher.update(&bytes[key_start..value_start]);
        record_hasher.update(&bytes[value_start..value_end]);
        bytes[HEADER_LEN + 8..HEADER_LEN + 12]
            .copy_from_slice(&record_hasher.finalize().to_le_bytes());

        let mut body_hasher = crc32fast::Hasher::new();
        body_hasher.update(&bytes[HEADER_LEN..]);
        bytes[28..32].copy_from_slice(&body_hasher.finalize().to_le_bytes());
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
                sqlite_edge_rows: 0,
                ledger_chain_status: "intact".to_string(),
                ledger_rows: 1,
                ledger_payload_rows: 1,
                base_ledger_pairs: 0,
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
    fn batch_ingest_coalesces_distinct_symbols_into_one_ledger_entry() {
        let vault = vault();
        let inputs = vec![
            input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1"),
            input("demo.math.sub", "src/math.rs", "fn sub() { 1 }", 20, "c1"),
            input("demo.math.mul", "src/math.rs", "fn mul() { 1 }", 30, "c1"),
        ];

        let report = ingest_series_batch(&vault, &inputs).expect("ingest batch");

        // Three new series, four registry rows each (series/reverse/qn/recurrence), written
        // by a single group commit.
        assert_eq!(report.mutated_rows, 12);

        // FSV: exactly one Ledger CF row for the whole batch, where the per-symbol loop
        // previously wrote one fsync'd commit and one ledger row per symbol.
        let ledger_rows = vault
            .scan_cf_at(vault.latest_seq(), ColumnFamily::Ledger)
            .expect("scan ledger");
        assert_eq!(ledger_rows.len(), 1);

        let entry = calyx_ledger::decode(&ledger_rows[0].1).expect("decode ledger entry");
        assert_eq!(entry.kind, EntryKind::Ingest);
        let payload: SeriesRegistryBatchLedgerPayload =
            serde_json::from_slice(&entry.payload).expect("decode batch payload");
        assert_eq!(payload.schema, SCHEMA_REGISTRY_BATCH_LEDGER);
        assert_eq!(payload.input_count, 3);
        assert_eq!(payload.versions_added, 3);
        assert_eq!(payload.splits_written, 0);
        assert_eq!(payload.changed_rows, 12);

        verify_deep(&vault).expect("verify deep");
    }

    #[test]
    fn batch_accumulates_two_versions_of_one_series_in_a_single_commit() {
        // Two versions of the same series in one batch must accumulate through the in-memory
        // working set (the second version reads the first's staged row, not the vault) and
        // still land in a single commit.
        let vault = vault();
        let v1 = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
        let v2 = input("demo.math.add", "src/math.rs", "fn add() { 2 }", 10, "c2");
        let series_id = v1.symbol.series_id().expect("series id");
        let cx1 = v1.symbol.cx_id(7).expect("cx1");
        let cx2 = v2.symbol.cx_id(7).expect("cx2");

        ingest_series_batch(&vault, &[v1, v2]).expect("ingest two versions in one batch");

        // Single commit for both versions.
        assert_eq!(
            vault
                .scan_cf_at(vault.latest_seq(), ColumnFamily::Ledger)
                .expect("scan ledger")
                .len(),
            1
        );

        // The final series row reflects both versions in commit order.
        let row = series_row(&vault, series_id);
        assert_eq!(row.version_count, 2);
        assert_eq!(row.current_cx_id, cx2);
        assert_eq!(
            row.versions
                .iter()
                .map(|version| version.cx_id)
                .collect::<Vec<_>>(),
            vec![cx1, cx2]
        );

        // Both per-version recurrence rows persist (byte readback).
        for (ordinal, cx) in [(1u64, cx1), (2, cx2)] {
            let bytes = vault
                .read_cf_at(
                    vault.latest_seq(),
                    ColumnFamily::Recurrence,
                    &recurrence_key(series_id, ordinal),
                )
                .expect("read recurrence")
                .expect("recurrence row");
            let recurrence: RecurrenceRow =
                serde_json::from_slice(&bytes).expect("decode recurrence");
            assert_eq!(recurrence.occurrence_id, ordinal);
            assert_eq!(recurrence.new_cx, cx);
        }

        verify_deep(&vault).expect("verify deep");
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

        let err = verify_deep(&vault).expect_err("reverse corruption should fail verify");
        assert_eq!(err.code(), Some(ASTRO_VERIFY_DEEP_FAILED));
        assert!(err.to_string().contains(ASTRO_VERIFY_DEEP_FAILED), "{err}");
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
        assert_eq!(err.code(), Some(ASTRO_VERIFY_DEEP_FAILED));
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
    fn verify_deep_fails_on_orphan_reverse_row_missing_series() {
        let vault = vault();
        let version = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
        ingest_series_batch(&vault, &[version]).expect("ingest");
        verify_deep(&vault).expect("clean vault verifies clean before planting");

        // Plant a reverse-index row whose owning series row does not exist. It decodes
        // cleanly and is never referenced by any series version, so only the reverse walk
        // can catch it.
        let orphan_cx = CxId::from_bytes([0xAB; 16]);
        let missing_series = SeriesId::from_bytes([0xCD; 16]);
        let orphan = ReverseIndexRow {
            schema: SCHEMA_REVERSE.to_string(),
            cx_id: orphan_cx,
            series_id: missing_series,
        };
        vault
            .write_cf(
                ColumnFamily::Kv,
                reverse_index_key(orphan_cx),
                serde_json::to_vec(&orphan).expect("encode reverse"),
            )
            .expect("plant orphan reverse row");

        // Read the planted bytes back from the CF to prove the orphan is truly persisted.
        let planted = vault
            .read_cf_at(
                vault.latest_seq(),
                ColumnFamily::Kv,
                &reverse_index_key(orphan_cx),
            )
            .expect("read planted reverse")
            .expect("planted reverse row exists");
        assert_eq!(
            planted,
            serde_json::to_vec(&orphan).expect("encode reverse")
        );

        let err = verify_deep(&vault).expect_err("orphan reverse should fail verify");
        assert_eq!(err.code(), Some(ASTRO_VERIFY_DEEP_FAILED));
        let IngestError::VerifyFailed(errors) = err else {
            panic!("unexpected verify error kind");
        };
        assert!(
            errors.iter().any(|error| {
                error.contains(&orphan_cx.to_string())
                    && error.contains(&missing_series.to_string())
                    && error.contains("points to missing series")
            }),
            "expected orphan reverse finding naming planted keys, got: {errors:?}"
        );
    }

    #[test]
    fn verify_deep_fails_on_orphan_recurrence_row_missing_series() {
        let vault = vault();
        let version = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
        ingest_series_batch(&vault, &[version]).expect("ingest");
        verify_deep(&vault).expect("clean vault verifies clean before planting");

        // Plant a recurrence row whose owning series row does not exist.
        let missing_series = SeriesId::from_bytes([0x5A; 16]);
        let orphan = RecurrenceRow {
            schema: SCHEMA_RECURRENCE.to_string(),
            series_id: missing_series,
            occurrence_id: 1,
            kind: "Recurrence".to_string(),
            commit: "c9".to_string(),
            prev_cx: None,
            new_cx: CxId::from_bytes([0x33; 16]),
        };
        vault
            .write_cf(
                ColumnFamily::Recurrence,
                recurrence_key(missing_series, 1),
                serde_json::to_vec(&orphan).expect("encode recurrence"),
            )
            .expect("plant orphan recurrence row");

        let planted = vault
            .read_cf_at(
                vault.latest_seq(),
                ColumnFamily::Recurrence,
                &recurrence_key(missing_series, 1),
            )
            .expect("read planted recurrence")
            .expect("planted recurrence row exists");
        assert_eq!(
            planted,
            serde_json::to_vec(&orphan).expect("encode recurrence")
        );

        let err = verify_deep(&vault).expect_err("orphan recurrence should fail verify");
        assert_eq!(err.code(), Some(ASTRO_VERIFY_DEEP_FAILED));
        let IngestError::VerifyFailed(errors) = err else {
            panic!("unexpected verify error kind");
        };
        let planted_key = format!("{missing_series}:1");
        assert!(
            errors.iter().any(|error| {
                error.contains(&planted_key)
                    && error.contains(&missing_series.to_string())
                    && error.contains("points to missing series")
            }),
            "expected orphan recurrence finding naming planted key {planted_key}, got: {errors:?}"
        );
    }

    #[test]
    fn verify_deep_fails_on_recurrence_occurrence_beyond_version_count() {
        let vault = vault();
        let version = input("demo.math.add", "src/math.rs", "fn add() { 1 }", 10, "c1");
        let series_id = version.symbol.series_id().expect("series id");
        let cx_id = version.symbol.cx_id(7).expect("cx id");
        ingest_series_batch(&vault, &[version]).expect("ingest");
        verify_deep(&vault).expect("clean vault verifies clean before planting");

        // Plant a recurrence row for the real series but with an occurrence_id far beyond
        // the series version_count (1). The forward series->recurrence walk only visits
        // ordinal 1, so only the recurrence walk can catch this orphan occurrence.
        let beyond = 99_u64;
        let orphan = RecurrenceRow {
            schema: SCHEMA_RECURRENCE.to_string(),
            series_id,
            occurrence_id: beyond,
            kind: "Recurrence".to_string(),
            commit: "c1".to_string(),
            prev_cx: Some(cx_id),
            new_cx: cx_id,
        };
        vault
            .write_cf(
                ColumnFamily::Recurrence,
                recurrence_key(series_id, beyond),
                serde_json::to_vec(&orphan).expect("encode recurrence"),
            )
            .expect("plant out-of-range recurrence row");

        let planted = vault
            .read_cf_at(
                vault.latest_seq(),
                ColumnFamily::Recurrence,
                &recurrence_key(series_id, beyond),
            )
            .expect("read planted recurrence")
            .expect("planted recurrence row exists");
        assert_eq!(
            planted,
            serde_json::to_vec(&orphan).expect("encode recurrence")
        );

        let err = verify_deep(&vault).expect_err("out-of-range recurrence should fail verify");
        assert_eq!(err.code(), Some(ASTRO_VERIFY_DEEP_FAILED));
        let IngestError::VerifyFailed(errors) = err else {
            panic!("unexpected verify error kind");
        };
        let planted_key = format!("{series_id}:{beyond}");
        assert!(
            errors.iter().any(|error| {
                error.contains(&planted_key) && error.contains("occurrence_id out of range")
            }),
            "expected out-of-range recurrence finding naming planted key {planted_key}, got: {errors:?}"
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
