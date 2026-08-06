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
        remediation: String,
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
        remediation: impl Into<String>,
    ) -> Self {
        Self::Refused {
            code,
            message: message.into(),
            remediation: remediation.into(),
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

    /// Returns the human-readable failure message without repeating the stable
    /// code or remediation fields. Operational JSON surfaces use this accessor
    /// so callers never have to parse [`Display`](fmt::Display) text to recover
    /// a structured refusal.
    pub fn message(&self) -> String {
        match self {
            Self::Domain(err) => err.message().to_string(),
            Self::Panel(err) => err.message().to_string(),
            Self::Calyx(err) => err.message.to_string(),
            Self::Json(err) => err.to_string(),
            Self::Refused { message, .. } | Self::InvalidInput(message) => message.clone(),
            Self::VerifyFailed(errors) => format!(
                "series registry verify --deep failed: {}",
                errors.join("; ")
            ),
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
    /// Non-node semantic Graph rows bound to their Base constellation.
    pub sqlite_semantic_constellation_rows: usize,
    /// Current zero-gap semantic coverage witnesses reconstructed and ledger-bound.
    pub sqlite_semantic_coverage_witness_rows: usize,
    /// Concrete semantic Slot CF rows joined to immutable Base hashes.
    pub sqlite_semantic_slot_rows: usize,
    /// Persisted semantic atoms classified by deterministic encoders or embedders.
    pub sqlite_semantic_coverage_present: u64,
    /// Persisted semantic atoms classified by deterministic encoders.
    pub sqlite_semantic_coverage_encoded: u64,
    /// Persisted semantic atoms classified by learned embedders.
    pub sqlite_semantic_coverage_embedded: u64,
    /// Persisted semantic atoms classified by frozen imported-vector lenses.
    pub sqlite_semantic_coverage_imported_vectors: u64,
    /// Persisted semantic atoms without a frozen lens classification (zero on success).
    pub sqlite_semantic_coverage_uncovered: u64,
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
        sqlite_semantic_constellation_rows: sqlite.semantic_constellation_rows,
        sqlite_semantic_coverage_witness_rows: sqlite.semantic_coverage_witness_rows,
        sqlite_semantic_slot_rows: sqlite.semantic_slot_rows,
        sqlite_semantic_coverage_present: sqlite.semantic_coverage_present,
        sqlite_semantic_coverage_encoded: sqlite.semantic_coverage_encoded,
        sqlite_semantic_coverage_embedded: sqlite.semantic_coverage_embedded,
        sqlite_semantic_coverage_imported_vectors: sqlite.semantic_coverage_imported_vectors,
        sqlite_semantic_coverage_uncovered: sqlite.semantic_coverage_uncovered,
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
        // Deep verification must open every physically existing dynamic Slot CF;
        // a selected core-only view cannot prove the semantic vectors on disk.
        selected_cfs: None,
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
