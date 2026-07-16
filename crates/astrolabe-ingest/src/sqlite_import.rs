use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use astrolabe_domain::fsv::FsvAck;
use astrolabe_domain::{
    ASTRO_ANCHOR_CONFIDENCE_RANGE, ASTRO_PANEL_VERSION_ZERO, ASTRO_SOURCE_DRIFT,
    ASTRO_SYMBOL_IDENTITY_EMPTY, ASTRO_SYMBOL_NON_FINITE, AnchorEvidence, DomainError, EdgeKind,
    SERIES_ID_TAG, SeriesId, SymbolIdentity, SymbolLabel, SymbolRecord,
};
use astrolabe_panel::{PanelDriver, PanelInput, SlotRuntime, default_panel_slots};
use calyx_aster::cf::{ColumnFamily, base_key, ledger_key, ledger_range, prefix_range, slot_key};
use calyx_aster::ledger_view::parse_aster_ledger_seq;
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::input_store::InputRetention;
use calyx_aster::vault::{AsterVault, encode, input_store};
use calyx_core::{
    AbsentReason, Clock, Constellation, CxFlags, CxId, InputRef, LedgerRef, Modality, Seq, SlotId,
    SlotVector,
};
use calyx_ledger::{ActorId, EntryKind, SubjectId, decode};
use rusqlite::{Connection, OpenFlags, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    ASTRO_SERIES_ID_V1_REBUILD_REQUIRED, IngestError, IngestResult,
    SERIES_ID_V1_REBUILD_REMEDIATION, SeriesVersionInput, VaultMutationPlan, ingest_series_batch,
};

/// Dangling edge refusal/skip code from blueprint `04_DATA_MODEL.md` section 7.
pub const ASTRO_EDGE_DANGLING: &str = "ASTRO_EDGE_DANGLING";
/// Refusal code for malformed or incompatible CBM SQLite input.
pub const ASTRO_INGEST_SQLITE_INVALID: &str = "ASTRO_INGEST_SQLITE_INVALID";
/// Refusal code for post-write readback mismatches.
pub const ASTRO_INGEST_READBACK_MISMATCH: &str = "ASTRO_INGEST_READBACK_MISMATCH";
/// Refusal code for malformed quantization gate inputs.
pub const ASTRO_QUANTIZATION_GATE_INVALID: &str = "ASTRO_QUANTIZATION_GATE_INVALID";
/// Refusal code for a legacy vault whose raw `astrolabe:cbm-edge:v1` rows predate
/// the raw-edge schema, leaving only typed constellation-to-constellation edge
/// rows that silently omit dangling and structural-endpoint edges.
pub const ASTRO_LEGACY_CBM_EDGE_ROWS: &str = "ASTRO_LEGACY_CBM_EDGE_ROWS";
/// Refusal code for a vault whose read-back finds no `astrolabe:cbm-project:v1`
/// row for the requested project. Every import persists at least one project row
/// (`metadata_graph_rows` over a guaranteed-non-empty project set), so an empty
/// read means a corrupt/erased vault, a legacy vault predating project rows, or a
/// project name that was never imported. Fabricating a placeholder project row
/// here would silently mask that state.
pub const ASTRO_MISSING_CBM_PROJECT_ROW: &str = "ASTRO_MISSING_CBM_PROJECT_ROW";

const SQLITE_REMEDIATION: &str = "Open a valid Codebase Memory MCP SQLite dump with nodes, edges, and optional node_vectors tables.";
const READBACK_REMEDIATION: &str = "Stop ingest, inspect the Aster vault, and rerun astrolabe verify --deep before trusting the batch.";
const QUANTIZATION_GATE_REMEDIATION: &str = "Provide measured recall, panel-bits, guard-FAR, and provenance for every requested quantization candidate.";
const LEGACY_CBM_EDGE_ROWS_REMEDIATION: &str = "Re-import the project from its Codebase Memory MCP SQLite dump so the vault persists complete astrolabe:cbm-edge:v1 raw edge rows before reading or lowering its graph snapshot.";
const MISSING_CBM_PROJECT_ROW_REMEDIATION: &str = "Re-import the project from its Codebase Memory MCP SQLite dump so the vault persists an astrolabe:cbm-project:v1 row, and confirm the requested project name matches an imported project before reading or lowering its graph snapshot.";
const NODE_MAP_PREFIX: &[u8] = b"astrolabe:node-map:v2:";
const LEGACY_NODE_MAP_PREFIX_V1: &[u8] = b"astrolabe:node-map:v1:";
const STRUCTURAL_NODE_PREFIX: &[u8] = b"astrolabe:structural-node:v1:";
const PROJECT_ROW_PREFIX: &[u8] = b"astrolabe:cbm-project:v1:";
const FILE_HASH_ROW_PREFIX: &[u8] = b"astrolabe:file-hash:v1:";
const PROJECT_SUMMARY_ROW_PREFIX: &[u8] = b"astrolabe:project-summary:v1:";
const TOKEN_VECTOR_ROW_PREFIX: &[u8] = b"astrolabe:token-vector:v1:";
const CBM_EDGE_ROW_PREFIX: &[u8] = b"astrolabe:cbm-edge:v1:";
pub(crate) const EDGE_ROW_PREFIX: &[u8] = b"astrolabe:edge:v1:";
/// Persisted per-file content-digest manifest prefix (#345). One row per source file,
/// keyed by (project, file_path), recording the file's content digest and the identity
/// (node_id → cx_id/series_id) of every symbol it produced. A later import compares the
/// incoming per-file digest against this row to short-circuit unchanged files before the
/// O(corpus) per-symbol conversion, so a one-symbol delta reconciles only its file.
const FILE_DIGEST_ROW_PREFIX: &[u8] = b"astrolabe:file-digest:v1:";
const SCHEMA_NODE_MAP: &str = "astrolabe-node-map-v2";
const SCHEMA_SYMBOL_METADATA: &str = "astrolabe-sqlite-symbol-v2";
const SCHEMA_STRUCTURAL_NODE: &str = "astrolabe-structural-node-v1";
const SCHEMA_PROJECT_ROW: &str = "astrolabe-cbm-project-v1";
const SCHEMA_FILE_HASH_ROW: &str = "astrolabe-file-hash-v1";
const SCHEMA_PROJECT_SUMMARY_ROW: &str = "astrolabe-project-summary-v1";
const SCHEMA_TOKEN_VECTOR_ROW: &str = "astrolabe-token-vector-v1";
const SCHEMA_CBM_EDGE_ROW: &str = "astrolabe-cbm-edge-v1";
pub(crate) const SCHEMA_EDGE_ROW: &str = "astrolabe-edge-v1";
const SCHEMA_FILE_DIGEST_ROW: &str = "astrolabe-file-digest-v1";
/// Domain separator for the per-file content digest (#345). Bumped only when the set of
/// raw fields folded into the digest changes, so an old-domain digest can never be
/// compared against a new-domain one (a mismatch then fails open into full reconcile).
// v2 (#372): the digest additionally folds every raw edge whose SOURCE node lives in the
// file, so a matching digest proves the file's outgoing edges are byte-identical too —
// the soundness condition for carrying persisted edge rows forward without re-encoding.
// (An edge's properties, e.g. resolution strategy/candidates, can change when a THIRD file
// changes; folding edges into the source file's digest makes such a change invalidate the
// digest instead of being wrongly preserved.) v1 manifests mismatch and fail open into one
// labeled full reconcile.
const FILE_DIGEST_DOMAIN: &str = "astrolabe-file-digest-v2";
const SCHEMA_LEDGER: &str = "astrolabe-sqlite-ingest-ledger-v1";
/// Ledger payload schema for admitting historical symbol versions without
/// mutating the live graph projection.
pub const HISTORICAL_SYMBOL_INGEST_LEDGER_SCHEMA: &str = "astrolabe.historical_symbol_ingest.v1";
const SCHEMA_QUANTIZATION_GATE: &str = "astrolabe.quantization_gate.v1";
const ASTROLABE_INGEST_ACTOR: &str = "astrolabe-ingest";

/// SQLITE_BUSY retry window for the read-only CBM source connection — an
/// operational-resilience knob, not a measured value (#76). Concurrent agent
/// MCP/CLI processes on one repo can hold a brief write lock on the CBM store
/// (journal transitions, registration rows) while another process's shadow
/// import reads the same file; with no busy timeout the reader returns
/// "database is locked" immediately and reddens the cross-process gate
/// (check-cross-process-vault.py). Mirrors LOWERED_DB_BUSY_TIMEOUT_MS
/// (astrolabe-lower) and CONFIG_DB_BUSY_TIMEOUT_MS (astrolabe-server).
const CBM_SOURCE_DB_BUSY_TIMEOUT_MS: u64 = 5_000;

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
    /// Optional measured quantization gate for candidate compressed slots.
    pub quantization_gate: Option<QuantizationGateConfig>,
    /// Whether this live import also advances the durable symbol-series registry.
    pub update_series_registry: bool,
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
            quantization_gate: None,
            update_series_registry: false,
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

    /// Attaches a measured quantization gate to this import.
    pub fn with_quantization_gate(mut self, gate: QuantizationGateConfig) -> Self {
        self.quantization_gate = Some(gate);
        self
    }

    /// Advances series and recurrence rows for every imported non-structural symbol.
    pub fn with_series_registry(mut self, enabled: bool) -> Self {
        self.update_series_registry = enabled;
        self
    }
}

/// Measured non-regression policy for candidate quantization.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuantizationGateConfig {
    /// Candidate slot measurements to evaluate.
    pub measurements: Vec<QuantizationGateMeasurement>,
    /// Guard-designated slots that must retain raw sidecar bytes.
    pub guard_slots: BTreeSet<u16>,
    /// Minimum acceptable candidate recall@k, in millipoints.
    pub min_recall_millipoints: u16,
    /// Maximum acceptable recall drop from raw to candidate, in millipoints.
    pub max_recall_drop_millipoints: u16,
    /// Maximum acceptable guard FAR increase from raw to candidate, in millipoints.
    pub max_guard_far_regression_millipoints: u16,
    /// Whether candidate panel bits must be at least raw panel bits.
    pub require_panel_bits_non_regression: bool,
}

impl QuantizationGateConfig {
    /// Builds a strict measured gate with Astrolabe's conservative defaults.
    pub fn strict(measurements: Vec<QuantizationGateMeasurement>) -> Self {
        Self {
            measurements,
            guard_slots: BTreeSet::new(),
            min_recall_millipoints: 950,
            max_recall_drop_millipoints: 0,
            max_guard_far_regression_millipoints: 0,
            require_panel_bits_non_regression: true,
        }
    }

    /// Marks slots that must retain raw CF sidecars.
    pub fn with_guard_slots<I>(mut self, slots: I) -> Self
    where
        I: IntoIterator<Item = u16>,
    {
        self.guard_slots = slots.into_iter().collect();
        self
    }
}

/// Measured evidence for one candidate quantization policy.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuantizationGateMeasurement {
    /// Panel slot id.
    pub slot: u16,
    /// Human-readable candidate policy, e.g. `turboquant_3p5`.
    pub candidate_policy: String,
    /// Baseline raw recall@k, in millipoints.
    pub recall_at_k_raw_millipoints: u16,
    /// Candidate quantized recall@k, in millipoints.
    pub recall_at_k_candidate_millipoints: u16,
    /// Baseline raw panel bits, in millibits.
    pub panel_bits_raw_millibits: u64,
    /// Candidate quantized panel bits, in millibits.
    pub panel_bits_candidate_millibits: u64,
    /// Baseline raw guard false-accept rate, in millipoints.
    pub guard_far_raw_millipoints: u16,
    /// Candidate quantized guard false-accept rate, in millipoints.
    pub guard_far_candidate_millipoints: u16,
    /// Measurement provenance; must be non-empty.
    pub provenance_refs: Vec<String>,
}

/// Per-slot quantization gate decision.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuantizationSlotDecision {
    /// Panel slot id.
    pub slot: u16,
    /// Candidate policy evaluated for this slot.
    pub candidate_policy: String,
    /// Decision for this slot: `accepted`, `refused_raw`, or `raw_guard`.
    pub decision: String,
    /// Whether this candidate passed the gate.
    pub pass: bool,
    /// Baseline raw recall@k, in millipoints.
    pub recall_at_k_raw_millipoints: u16,
    /// Candidate quantized recall@k, in millipoints.
    pub recall_at_k_candidate_millipoints: u16,
    /// Baseline raw panel bits, in millibits.
    pub panel_bits_raw_millibits: u64,
    /// Candidate quantized panel bits, in millibits.
    pub panel_bits_candidate_millibits: u64,
    /// Baseline raw guard FAR, in millipoints.
    pub guard_far_raw_millipoints: u16,
    /// Candidate quantized guard FAR, in millipoints.
    pub guard_far_candidate_millipoints: u16,
    /// Measurement provenance copied from the gate input.
    pub provenance_refs: Vec<String>,
    /// Fail-closed reason when `pass=false`.
    pub reason: Option<String>,
    /// Operator-facing remediation when refused.
    pub remediation: Option<String>,
}

/// Policy ceilings carried with a quantization report.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuantizationGatePolicyReport {
    /// Minimum acceptable candidate recall@k, in millipoints.
    pub min_recall_millipoints: u16,
    /// Maximum acceptable recall drop from raw to candidate, in millipoints.
    pub max_recall_drop_millipoints: u16,
    /// Maximum acceptable guard FAR increase, in millipoints.
    pub max_guard_far_regression_millipoints: u16,
    /// Whether candidate panel bits must be at least raw panel bits.
    pub require_panel_bits_non_regression: bool,
}

/// Quantization gate summary attached to an import report and ledger payload.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqliteImportQuantizationReport {
    /// Stable report schema.
    pub schema: String,
    /// Overall status: `unconfigured`, `applied`, `refused_raw`, or `raw_guard`.
    pub status: String,
    /// True only when at least one candidate slot passed and no candidate failed.
    pub applied: bool,
    /// Current persisted storage mode for Astrolabe-owned imports.
    pub storage_mode: String,
    /// Explicit policy labels and ceilings.
    pub policy: QuantizationGatePolicyReport,
    /// Per-slot measured decisions.
    pub slots: Vec<QuantizationSlotDecision>,
    /// Number of accepted candidate slots.
    pub accepted_slot_count: usize,
    /// Number of refused candidate slots.
    pub refused_slot_count: usize,
    /// Number of guard-designated raw sidecar slots.
    pub guard_slot_count: usize,
    /// Raw guard-slot sidecar rows verified from CF readback.
    pub raw_guard_slot_rows_verified: usize,
    /// Raw guard-slot sidecar rows expected from the prepared import.
    pub expected_raw_guard_slot_rows: usize,
    /// Trust label for this report.
    pub trust: String,
    /// Freshness label for this report.
    pub freshness: String,
}

/// Exact skipped-edge accounting for an import batch.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EdgeSkipCounters {
    /// Edges skipped because a source or target node id was genuinely absent from the
    /// SQLite node table (dangling reference / corrupt or truncated dump).
    pub dangling: usize,
    /// Edges skipped because a source or target endpoint is a structural node
    /// (Project/Branch/Folder) that is persisted as a structural row rather than a
    /// constellation, and therefore has no typed edge target. This is a by-design skip,
    /// not corruption, so it is counted separately from `dangling`.
    pub structural_endpoint: usize,
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
    /// Guard raw sidecar slot CF rows byte-compared after quantization gating.
    pub raw_guard_slot_rows_verified: usize,
    /// Expected Base CF rows for the imported non-structural symbols.
    pub expected_base_rows: usize,
    /// Expected slot sidecar rows for the imported non-structural symbols.
    pub expected_slot_rows: usize,
    /// Expected graph mapping plus structural metadata rows.
    pub expected_graph_rows: usize,
    /// Expected typed edge rows.
    pub expected_edge_rows: usize,
    /// Expected guard raw sidecar slot CF rows.
    pub expected_raw_guard_slot_rows: usize,
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
    /// Symbol versions presented to the durable series registry.
    pub series_inputs: usize,
    /// Registry/reverse/QN/recurrence rows changed by this run.
    pub series_mutated_rows: usize,
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
    /// Measured quantization gate decision and raw guard-slot readback counts.
    pub quantization: SqliteImportQuantizationReport,
    /// Post-write CF readback verification counts.
    pub readback: SqliteImportReadback,
    /// Unforgeable full-readback witness when this import changed vault rows.
    /// An idempotent ledger-only replay carries labeled absence (`None`).
    #[serde(default, skip_deserializing)]
    pub fsv: Option<FsvAck>,
    /// Imported constellation ids in deterministic node-id order.
    pub cx_ids: Vec<CxId>,
    /// Newly measured constellation ids in deterministic node-id order.
    /// Incremental consumers use this dirty set instead of rescanning/reweaving
    /// every reused constellation in the full CBM snapshot.
    #[serde(default)]
    pub new_cx_id_values: Vec<CxId>,
    /// Per-file digest short-circuit accounting for this import (#345): how many files
    /// were observed, how many matched a persisted digest and skipped conversion, how many
    /// were fully reconciled (the labeled fail-open path), and how many symbols reused an
    /// identity straight from a matching file digest.
    #[serde(default)]
    pub file_digest: FileDigestReport,
    /// Row/edge encode short-circuit accounting for the delta fast path (#372): how many
    /// node-map, typed/raw edge, manifest, and file-hash rows were re-serialized this run
    /// versus carried forward byte-for-byte from unchanged files. On an unchanged-corpus
    /// reimport every `*_encoded` count collapses to zero, proving the encode/derive work
    /// is O(changed files), not O(corpus).
    #[serde(default)]
    pub encode_skip: EncodeSkipReport,
    /// Per-phase wall-clock milliseconds of this import run (#23 latency
    /// telemetry): stable labels, measured values — not knobs. Empty when the
    /// report was deserialized from persisted state.
    #[serde(default, skip)]
    pub timing_ms: PhaseTimings,
}

/// Wall-clock phase telemetry (#23).
///
/// Deliberately equality-neutral: two otherwise-identical reports must compare
/// equal regardless of how long their phases took, so report-level byte-parity
/// FSV assertions (e.g. direct row-sink vs SQLite import) stay claims about
/// persisted state, never about wall-clock.
#[derive(Debug, Clone, Default)]
pub struct PhaseTimings(pub Vec<(&'static str, u64)>);

impl PartialEq for PhaseTimings {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for PhaseTimings {}

/// Deterministic location and identity of one admitted historical symbol.
///
/// The record is derived from the same CBM row parsing and Astrolabe canonical
/// identity path as a live shadow import. It deliberately contains no source
/// bytes; callers use it to bind Git archaeology outcomes to the exact
/// historical `CxId`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoricalSymbolLocation {
    /// Git commit supplied through [`SqliteImportOptions::commit`].
    pub commit: String,
    /// Repository-relative source path at that commit.
    pub file_path: String,
    /// One-based inclusive symbol start line.
    pub start_line: u32,
    /// One-based inclusive symbol end line.
    pub end_line: u32,
    /// Historical qualified name emitted by CBM.
    pub qualified_name: String,
    /// Historical CBM symbol label.
    pub label: String,
    /// Exact immutable constellation id for this historical version.
    pub cx_id: CxId,
}

/// Result of admitting implicated historical symbol versions.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HistoricalSymbolAdmissionReport {
    /// Deterministically sorted admitted locations.
    pub locations: Vec<HistoricalSymbolLocation>,
    /// Non-structural symbol versions presented to the panel driver.
    pub constellation_inputs: usize,
    /// Constellations whose Base row did not previously exist.
    pub constellations_written: usize,
    /// Exact Base plus slot rows written by this call.
    pub rows_written: usize,
    /// Constellations already present and independently verified.
    pub constellations_reused: usize,
    /// Commit snapshot after this call; unchanged on an idempotent replay.
    pub seq: Seq,
    /// Paired Ingest ledger entry, present exactly when rows were written.
    pub ledger_ref: Option<LedgerRef>,
    /// Full persisted-row and paired-ledger readback witness for a mutation.
    #[serde(default, skip_deserializing)]
    pub fsv: Option<FsvAck>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct HistoricalSymbolIngestLedgerPayload {
    schema: String,
    project_hash_sha256: String,
    commit_hash_sha256: String,
    location_digest: String,
    constellation_inputs: u64,
    constellations_written: u64,
    rows_written: u64,
    constellations_reused: u64,
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CxGraphErasureReport {
    pub project: String,
    pub cx_id: CxId,
    pub node_map_rows_tombstoned: usize,
    pub edge_rows_tombstoned: usize,
    pub raw_edge_rows_tombstoned: usize,
    pub seq: Seq,
    /// Unforgeable tombstone-readback witness, absent for a no-op erasure.
    #[serde(default, skip_deserializing)]
    pub fsv: Option<FsvAck>,
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

/// One symbol's persisted identity inside a per-file digest manifest row (#345).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct FileDigestSymbol {
    node_id: i64,
    cx_id: CxId,
    series_id: SeriesId,
}

/// Persisted per-file content-digest manifest row (#345).
///
/// Written once per source file in the same ledger-paired batch as the graph rows it
/// summarizes, so the manifest and the rows it describes are always mutually consistent
/// (a crash rolls back the whole group). A later import recomputes each incoming file's
/// digest from its raw CBM rows and compares it here: an exact match (same digest domain
/// and panel version) proves every one of that file's symbols is byte-for-byte unchanged,
/// so their content-addressed identities are reused straight from `symbols` without
/// recomputing canonical bytes / CxIds or re-reading Base — turning the delta import from
/// O(corpus) into O(changed files). Any mismatch, missing row, or domain/version drift
/// fails open into the full per-symbol reconcile.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct FileDigestRow {
    schema: String,
    project: String,
    file_path: String,
    panel_version: u32,
    /// Digest domain tag, so an old-domain digest is never compared against a new one.
    domain: String,
    digest: String,
    symbols: Vec<FileDigestSymbol>,
}

/// Skip-accounting for the per-file digest short-circuit (#345), surfaced in the import
/// report so an unchanged-corpus reimport can prove it converted no unchanged file
/// (standing invariant 3: every skip is counted, never silent).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDigestReport {
    /// Distinct source files observed in this import.
    pub files_total: usize,
    /// Files whose persisted digest matched, so their symbols were reused without
    /// re-measuring.
    pub files_unchanged: usize,
    /// Files with no comparable persisted digest (first import, domain/version drift,
    /// or a digest mismatch) that were fully reconciled — the labeled fail-open count.
    pub files_reconciled: usize,
    /// Non-structural symbols whose identity was reused from a matching file digest
    /// instead of being recomputed and re-read from Base.
    pub symbols_reused_via_digest: usize,
    /// True when a persisted manifest existed for at least one file (so this was a real
    /// incremental import, not a cold first import with nothing to compare against).
    pub had_prior_manifest: bool,
}

/// Row/edge encode short-circuit accounting for the delta-import fast path (#372).
///
/// The per-file digest layer (#345) already skips recomputing identities for unchanged
/// files' symbols; #372 extends the skip to the graph-row and edge ENCODE and to the
/// change derivation. An unchanged file's persisted graph rows (node-map, typed/raw edge,
/// manifest, and file-hash rows) are carried forward byte-for-byte without re-serializing
/// them, comparing them, or re-deriving their provenance — the same doctrine as #345's
/// Base-row skip, backstopped by the whole-vault `verify_chain`. These counters make the
/// short-circuit auditable: on an unchanged-corpus reimport every `*_encoded` count is
/// driven purely by the changed files, so a test reads them back and asserts the encode
/// work is O(changed files), never O(corpus) (standing invariant 3: every skip counted).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodeSkipReport {
    /// Node-map rows serialized this run (changed/new symbols only).
    pub node_map_rows_encoded: usize,
    /// Node-map rows preserved from persisted bytes without re-encoding (digest-reused symbols).
    pub node_map_rows_preserved: usize,
    /// Typed edge rows serialized this run.
    pub edge_rows_encoded: usize,
    /// Typed edge rows preserved from persisted bytes without re-encoding (both endpoints reused).
    pub edge_rows_preserved: usize,
    /// Raw CBM edge rows serialized this run.
    pub raw_edge_rows_encoded: usize,
    /// Raw CBM edge rows preserved from persisted bytes without re-encoding.
    pub raw_edge_rows_preserved: usize,
    /// Per-file digest manifest rows serialized this run (changed/reconciled files only).
    pub manifest_rows_encoded: usize,
    /// Per-file digest manifest rows preserved from persisted bytes without re-encoding.
    pub manifest_rows_preserved: usize,
    /// File-hash metadata rows serialized this run.
    pub file_hash_rows_encoded: usize,
    /// File-hash metadata rows preserved from persisted bytes without re-encoding.
    pub file_hash_rows_preserved: usize,
}

impl EncodeSkipReport {
    /// Total persisted graph rows this import carried forward byte-for-byte instead of
    /// re-encoding and re-deriving. The delta fast path's O(changed-files) evidence.
    pub fn rows_preserved(&self) -> usize {
        self.node_map_rows_preserved
            + self.edge_rows_preserved
            + self.raw_edge_rows_preserved
            + self.manifest_rows_preserved
            + self.file_hash_rows_preserved
    }
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
struct PreparedLiveSymbol {
    node_id: i64,
    name: String,
    properties_json: String,
    node_vector: Option<Vec<u8>>,
    symbol: SymbolRecord,
    identity: SymbolIdentity,
    /// Present only when this content-addressed identity was not already in Base.
    /// Reused live symbols retain their graph identity without re-running 22 lenses.
    measured: Option<Constellation>,
}

#[derive(Debug, Clone)]
struct PreparedBatch {
    constellations: Vec<PreparedLiveSymbol>,
    graph_rows: Vec<(Vec<u8>, Vec<u8>)>,
    edge_rows: Vec<PreparedEdgeRow>,
    structural_only: usize,
    sqlite_edges: usize,
    edge_skips: EdgeSkipCounters,
    /// Persisted Graph CF keys this batch reuses byte-for-byte from unchanged files (#372):
    /// node-map rows for digest-reused symbols, typed/raw edge rows whose endpoints are both
    /// reused, manifest rows for unchanged files, and their file-hash rows. These keys were
    /// deliberately NOT re-encoded into `graph_rows`/`edge_rows`, so change derivation folds
    /// them into the "current" key set (preventing a spurious stale tombstone) without paying
    /// the per-row encode/compare/provenance cost.
    preserved_keys: BTreeSet<Vec<u8>>,
    /// Encode/derive short-circuit accounting for this run (#372 O(changed-files) evidence).
    encode_skip: EncodeSkipReport,
    /// Per-phase wall-clock millis of batch preparation (#23 latency telemetry).
    timing_ms: Vec<(&'static str, u64)>,
}

#[derive(Debug, Clone)]
struct PreparedEdgeRow {
    key: Vec<u8>,
    row: EdgeGraphRow,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct NodeMapRow {
    schema: String,
    series_id_schema: String,
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
    edge_structural_endpoint_skipped: u64,
    expected_base_rows: u64,
    expected_slot_rows: u64,
    expected_graph_rows: u64,
    expected_edge_rows: u64,
    quantization: SqliteImportQuantizationReport,
    /// Delta-import encode/derive short-circuit accounting (#372): durable, independently
    /// readable proof that this run's row/edge encode was O(changed files), not O(corpus).
    #[serde(default)]
    encode_skip: EncodeSkipReport,
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

    let sqlite_fingerprint = fingerprint_sqlite_file(sqlite_path.as_ref())?;
    let ledger_rows_before = ledger_row_count(vault)?;

    let connection = open_cbm_source_connection(sqlite_path.as_ref())?;
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

/// Open the CBM source SQLite read-only with the #76 SQLITE_BUSY retry window.
/// Kept as a named helper so the busy-timeout contract is directly asserted by
/// `cbm_source_connection_sets_busy_timeout`.
fn open_cbm_source_connection(sqlite_path: &Path) -> IngestResult<Connection> {
    // #412: extended-length (`\\?\`) normalization so the CBM `<project>.db` under
    // a deep store (total path > MAX_PATH) is read back instead of failing closed.
    let open_path = astrolabe_domain::winpath::sqlite_open_path(sqlite_path)
        .map_err(|error| invalid_sqlite(format!("normalize SQLite input path: {error}")))?;
    let connection = Connection::open_with_flags(
        &open_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| invalid_sqlite(format!("open SQLite input: {error}")))?;
    connection
        .busy_timeout(std::time::Duration::from_millis(
            CBM_SOURCE_DB_BUSY_TIMEOUT_MS,
        ))
        .map_err(|error| invalid_sqlite(format!("set SQLite busy timeout: {error}")))?;
    Ok(connection)
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
    ensure_no_legacy_series_state(vault)?;
    if input.nodes.is_empty() {
        // A dump that yields zero node rows for the requested project imports zero
        // constellations. Refuse rather than appending an Ingest ledger record for an
        // empty vault that would otherwise be reported as a successful import.
        return Err(invalid_sqlite(
            "SQLite import produced zero nodes for the requested project; \
             refusing to record an empty import as successful",
        ));
    }
    let sqlite_node_vectors = input
        .nodes
        .iter()
        .filter(|node| node.node_vector.is_some())
        .count();
    let sqlite_nodes = input.nodes.len();
    // #23 latency telemetry: stable-labeled per-phase millis, surfaced through
    // `SqliteImportReport::timing_ms` so M-scale FSV evidence can attribute the
    // import cost without external profilers.
    let mut timing_ms: Vec<(&'static str, u64)> = Vec::new();
    let mut phase_start = std::time::Instant::now();
    // Per-file content digests (#345) must be computed from the raw node rows before
    // `extract_nodes` consumes them; the manifest comparison happens after the shared
    // Graph scan below.
    let new_file_digests = compute_file_digests(&input.nodes, &input.edges, options.panel_version);
    let extracted = extract_nodes(input.nodes)?;
    timing_ms.push(("extract_nodes", phase_start.elapsed().as_millis() as u64));
    phase_start = std::time::Instant::now();
    // The one shared pre-commit Graph CF scan (#23). Every pre-commit
    // reconciliation pass (reuse, change derivation, stale detection) reads
    // this map instead of issuing per-row MVCC point reads or re-scanning the
    // CF once per pass.
    let existing_graph: BTreeMap<Vec<u8>, Vec<u8>> = vault
        .scan_cf_at(vault.latest_seq(), ColumnFamily::Graph)?
        .into_iter()
        .collect();
    timing_ms.push((
        "scan_existing_graph",
        phase_start.elapsed().as_millis() as u64,
    ));
    phase_start = std::time::Instant::now();
    // Per-file digest short-circuit (#345): compare each incoming file's content digest
    // (computed above from the raw rows) against the persisted manifest read out of the
    // shared Graph scan. A file whose digest matches contributes its symbols' identities
    // to the reuse map, so `prepare_live_symbol` skips recomputing their canonical bytes /
    // CxIds and `verify_preexisting_constellations` skips re-reading their Base rows —
    // turning the delta from O(corpus) into O(changed files). Any absent/mismatched digest
    // fails open into the full per-symbol reconcile.
    let prior_manifest = read_file_digest_manifest(&existing_graph, &options.project);
    let digest_plan = plan_digest_reuse(&new_file_digests, &prior_manifest, options.panel_version);
    let file_digest_report = digest_plan.report.clone();
    timing_ms.push((
        "plan_file_digest_reuse",
        phase_start.elapsed().as_millis() as u64,
    ));
    phase_start = std::time::Instant::now();
    // Hand ownership of the extracted node graph to `prepare_batch` (moved, not borrowed) so the
    // full `Vec<ExtractedNode>` does not stay alive in this frame alongside the prepared
    // constellations and serialized graph rows. Holding raw -> extracted -> prepared -> serialized
    // stages concurrently was the ~4x whole-graph memory hazard tracked by #101.
    let prepared = prepare_batch(
        vault,
        runtime,
        options,
        extracted,
        input.edges,
        input.metadata,
        input.sqlite_fingerprint,
        &existing_graph,
        &digest_plan.reuse,
        &digest_plan.unchanged_files,
        &new_file_digests,
    )?;
    timing_ms.push(("prepare_batch", phase_start.elapsed().as_millis() as u64));
    timing_ms.extend(prepared.timing_ms.iter().copied());
    phase_start = std::time::Instant::now();

    let before_snapshot = vault.latest_seq();
    let mut new_cx_ids = 0;
    let mut reused_cx_ids = 0;
    for prepared_cx in &prepared.constellations {
        if prepared_cx.measured.is_some() {
            new_cx_ids += 1;
        } else {
            reused_cx_ids += 1;
        }
    }

    let cx_ids = prepared
        .constellations
        .iter()
        .map(|prepared| prepared.identity.cx_id)
        .collect::<Vec<_>>();
    let new_cx_id_values = prepared
        .constellations
        .iter()
        .filter(|prepared| prepared.measured.is_some())
        .map(|prepared| prepared.identity.cx_id)
        .collect::<Vec<_>>();
    let mut quantization = quantization_gate_report(options, &prepared);
    verify_preexisting_constellations(
        vault,
        before_snapshot,
        &prepared,
        options.workers,
        &digest_plan.reuse,
    )?;
    timing_ms.push((
        "verify_preexisting",
        phase_start.elapsed().as_millis() as u64,
    ));
    phase_start = std::time::Instant::now();
    let changes = derive_graph_row_changes(
        vault,
        before_snapshot,
        &prepared,
        &options.project,
        &existing_graph,
        options.workers,
    )?;
    timing_ms.push((
        "derive_graph_changes",
        phase_start.elapsed().as_millis() as u64,
    ));
    phase_start = std::time::Instant::now();
    let payload = ingest_ledger_payload(
        input.sqlite_fingerprint,
        options,
        &prepared,
        &quantization,
        IngestLedgerStats {
            sqlite_node_vectors,
            new_cx_ids,
            reused_cx_ids,
            graph_rows_written: changes.graph_rows_written,
            edge_rows_written: changes.edge_rows_written,
        },
    )?;
    let (ledger_ref, fsv, graph_rows_written, edge_rows_written, write_timing_ms) =
        write_import_rows(
            vault,
            &prepared,
            input.sqlite_fingerprint,
            payload,
            options.quantization_gate.as_ref(),
            &changes,
        )?;
    timing_ms.push((
        "write_import_rows",
        phase_start.elapsed().as_millis() as u64,
    ));
    // #433 permanent labeled attribution INSIDE the vault write: row staging vs
    // the single atomic group commit vs the FSV readback, so the phase's cost is
    // attributable to a real sub-stage instead of guessed.
    timing_ms.extend(write_timing_ms);
    phase_start = std::time::Instant::now();
    let readback = verify_import_readback(
        vault,
        &prepared,
        options.quantization_gate.as_ref(),
        &changes,
        &existing_graph,
    )?;
    timing_ms.push((
        "verify_import_readback",
        phase_start.elapsed().as_millis() as u64,
    ));
    phase_start = std::time::Instant::now();
    let (series_inputs, series_mutated_rows) = if options.update_series_registry {
        let inputs = prepared
            .constellations
            .iter()
            .filter(|prepared| prepared.measured.is_some())
            .map(|prepared| {
                SeriesVersionInput::new(
                    prepared.symbol.clone(),
                    options.panel_version,
                    options.commit.clone(),
                )
            })
            .collect::<Vec<_>>();
        let report = ingest_series_batch(vault, &inputs)?;
        (report.inputs, report.mutated_rows)
    } else {
        (0, 0)
    };
    timing_ms.push(("series_registry", phase_start.elapsed().as_millis() as u64));
    quantization.raw_guard_slot_rows_verified = readback.raw_guard_slot_rows_verified;
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
        series_inputs,
        series_mutated_rows,
        seq: vault.latest_seq(),
        ledger_seq: ledger_ref.seq,
        ledger_rows_before: input.ledger_rows_before,
        ledger_rows_after,
        edge_skips: prepared.edge_skips,
        quantization,
        readback,
        fsv,
        cx_ids,
        new_cx_id_values,
        file_digest: file_digest_report,
        encode_skip: prepared.encode_skip.clone(),
        timing_ms: PhaseTimings(timing_ms),
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
    let convert_start = std::time::Instant::now();
    let raw_metadata = snapshot_metadata_rows(snapshot, options, source_fingerprint_sha256)?;
    let raw_nodes = snapshot_node_rows(snapshot, &options.project, options.workers)?;
    let raw_edges = snapshot_edge_rows(snapshot, &options.project, options.workers)?;
    let convert_ms = convert_start.elapsed().as_millis() as u64;
    let ledger_rows_before = ledger_row_count(vault)?;
    let mut report = import_raw_cbm_rows_to_vault(
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
    )?;
    report
        .timing_ms
        .0
        .insert(0, ("snapshot_row_convert", convert_ms));
    Ok(report)
}

/// Admits implicated historical CBM symbols as exact constellations without
/// changing the live node map, Graph CF, or edge projection.
///
/// `snapshot` is expected to contain the filtered nodes implicated by Git
/// archaeology at the real commit named by [`SqliteImportOptions::commit`].
/// Nodes pass through the canonical snapshot parser, [`SymbolRecord`] builder,
/// panel driver, and identity derivation used by live SQLite imports. Structural
/// nodes are ignored because they do not have constellations. New Base and slot
/// rows are written in one atomic `Ingest` group commit and verified with a
/// [`VaultMutationPlan`]. Replaying an unchanged snapshot verifies existing rows
/// and performs no mutation or ledger append.
pub fn admit_historical_symbol_snapshot<C, R>(
    snapshot: &CbmGraphSnapshot,
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
) -> IngestResult<HistoricalSymbolAdmissionReport>
where
    C: Clock,
    R: SlotRuntime + Sync,
{
    validate_options(options)?;
    ensure_no_legacy_series_state(vault)?;
    if options.commit.trim().is_empty() {
        return Err(invalid_sqlite(
            "historical symbol admission requires a non-empty real Git commit",
        ));
    }
    if snapshot.project != options.project {
        return Err(invalid_sqlite(format!(
            "historical snapshot project {:?} does not match import project {:?}",
            snapshot.project, options.project
        )));
    }

    let extracted = extract_nodes(snapshot_node_rows(
        snapshot,
        &options.project,
        options.workers,
    )?)?;
    let non_structural = extracted
        .into_iter()
        .filter(|node| !node.label.is_structural())
        .collect::<Vec<_>>();
    if non_structural.is_empty() {
        return Err(invalid_sqlite(
            "historical symbol snapshot contains no non-structural symbols to admit",
        ));
    }

    let driver = PanelDriver::new(options.panel_version)?;
    // #446: historical symbols retain their canonical input bytes under the
    // same vault-manifest knob as the live import path.
    let retention = vault.input_retention()?;
    let mut prepared = prepare_constellations_parallel(
        vault,
        runtime,
        options,
        &driver,
        non_structural,
        retention,
    )?;
    prepared.sort_by(|left, right| {
        left.symbol
            .rel_file_path
            .cmp(&right.symbol.rel_file_path)
            .then_with(|| left.symbol.start_line.cmp(&right.symbol.start_line))
            .then_with(|| left.symbol.end_line.cmp(&right.symbol.end_line))
            .then_with(|| left.symbol.qualified_name.cmp(&right.symbol.qualified_name))
            .then_with(|| left.symbol.label.cmp(&right.symbol.label))
            .then_with(|| left.identity.cx_id.cmp(&right.identity.cx_id))
    });
    for symbol in &mut prepared {
        symbol.constellation.metadata.insert(
            "start_line".to_string(),
            symbol.symbol.start_line.to_string(),
        );
        symbol
            .constellation
            .metadata
            .insert("end_line".to_string(), symbol.symbol.end_line.to_string());
        symbol
            .constellation
            .metadata
            .insert("historical_commit".to_string(), options.commit.clone());
    }
    let locations = prepared
        .iter()
        .map(|symbol| HistoricalSymbolLocation {
            commit: options.commit.clone(),
            file_path: symbol.symbol.rel_file_path.clone(),
            start_line: symbol.symbol.start_line,
            end_line: symbol.symbol.end_line,
            qualified_name: symbol.symbol.qualified_name.clone(),
            label: symbol.symbol.label.clone(),
            cx_id: symbol.identity.cx_id,
        })
        .collect::<Vec<_>>();
    let snapshot_seq = vault.latest_seq();
    let mut rows = Vec::new();
    let mut constellations_written = 0usize;
    let mut constellations_reused = 0usize;
    // #446: mirrors the live import path — input rows commit atomically with
    // their historical Base records under the vault's declared retention knob.
    let mut staged_input_hashes = BTreeSet::new();
    // #497: content-addressed intra-batch dedup. Two implicated nodes in one
    // historical commit can canonicalize to a single CxId (in shadow/fast mode the
    // canonical inputs carry no body content, so the same symbol observed as two
    // libcbm nodes at one span shares an identity). A CxId is a content address:
    // equal CxId => equal `canonical_input_bytes` (BLAKE3) => equal measured
    // constellation; the two observations differ only in per-observation provenance
    // metadata (`source_node_id`, node-vector digest) that is NOT part of the
    // identity. Staging both Base rows under `base_key(cx_id)` is a last-write-wins
    // collision that clobbers the earlier row and breaks its group-commit FSV
    // readback (ASTRO_FSV_READBACK_MISMATCH). Admit the content once and count the
    // rest as reused. Fail closed only on a genuine hash collision — a shared CxId
    // whose canonical bytes actually differ — which must never be silently merged.
    let mut staged_canonical: BTreeMap<CxId, [u8; 32]> = BTreeMap::new();
    for symbol in &prepared {
        let cx_id = symbol.identity.cx_id;
        let key = base_key(cx_id);
        let canonical_hash = *blake3::hash(&symbol.identity.canonical_input_bytes).as_bytes();
        // Cross-batch reuse: an earlier commit already persisted this content.
        if vault
            .read_cf_at(snapshot_seq, ColumnFamily::Base, &key)?
            .is_some()
        {
            verify_existing_historical_constellation(vault, snapshot_seq, symbol)?;
            constellations_reused += 1;
            continue;
        }
        // Intra-batch dedup (#497): this content is already staged in this commit.
        if let Some(prior_hash) = staged_canonical.get(&cx_id) {
            if *prior_hash != canonical_hash {
                return Err(invalid_sqlite(format!(
                    "historical CxId {cx_id} maps two distinct canonical inputs in one snapshot \
                     (BLAKE3 {} vs {}); refusing to clobber the first write",
                    hex_lower(prior_hash),
                    hex_lower(&canonical_hash),
                )));
            }
            constellations_reused += 1;
            continue;
        }
        rows.push((
            ColumnFamily::Base,
            key,
            encode::encode_constellation_base(&symbol.constellation)?,
        ));
        for (slot, vector) in &symbol.constellation.slots {
            rows.push((
                ColumnFamily::slot(*slot),
                slot_key(symbol.identity.cx_id),
                encode::encode_slot_vector(vector)?,
            ));
        }
        if retention == InputRetention::Persist
            && staged_input_hashes.insert(symbol.constellation.input_ref.hash)
        {
            for row in input_store::encode_input_rows(
                &symbol.constellation.input_ref.hash,
                &symbol.identity.canonical_input_bytes,
            )? {
                rows.push((row.cf, row.key, row.value));
            }
        }
        staged_canonical.insert(cx_id, canonical_hash);
        constellations_written += 1;
    }
    let rows_written = rows.len();
    if rows.is_empty() {
        return Ok(HistoricalSymbolAdmissionReport {
            locations,
            constellation_inputs: prepared.len(),
            constellations_written,
            rows_written,
            constellations_reused,
            seq: snapshot_seq,
            ledger_ref: None,
            fsv: None,
        });
    }

    let location_digest = historical_location_digest(&locations);
    let payload = serde_json::to_vec(&HistoricalSymbolIngestLedgerPayload {
        schema: HISTORICAL_SYMBOL_INGEST_LEDGER_SCHEMA.to_string(),
        project_hash_sha256: hex_lower(&sha256_digest(options.project.as_bytes())),
        commit_hash_sha256: hex_lower(&sha256_digest(options.commit.as_bytes())),
        location_digest: hex_lower(blake3::hash(&location_digest).as_bytes()),
        constellation_inputs: prepared.len() as u64,
        constellations_written: constellations_written as u64,
        rows_written: rows_written as u64,
        constellations_reused: constellations_reused as u64,
    })?;
    let subject = SubjectId::Query(blake3::hash(&location_digest).as_bytes().to_vec());
    let actor = ActorId::Service(ASTROLABE_INGEST_ACTOR.to_string());
    let planned_rows = rows.clone();
    let commit_seq = vault.write_cf_batch_with_ledger_entry(
        rows,
        EntryKind::Ingest,
        subject.clone(),
        payload,
        actor.clone(),
    )?;
    let ledger_ref = ledger_ref_at_commit(vault, commit_seq)?;
    let mut fsv_plan = VaultMutationPlan::new(
        "admit_historical_symbol_snapshot",
        EntryKind::Ingest,
        &actor,
        &subject,
    );
    for (cf, key, value) in planned_rows {
        let expected = expected_group_commit_bytes(cf, value, &ledger_ref)?;
        fsv_plan.push_content(cf, key, &expected);
    }
    vault.flush()?;
    let fsv = fsv_plan.verify_committed(vault, commit_seq)?;

    Ok(HistoricalSymbolAdmissionReport {
        locations,
        constellation_inputs: prepared.len(),
        constellations_written,
        rows_written,
        constellations_reused,
        seq: commit_seq,
        ledger_ref: Some(ledger_ref),
        fsv: Some(fsv),
    })
}

fn historical_location_digest(locations: &[HistoricalSymbolLocation]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for location in locations {
        for field in [
            location.commit.as_bytes(),
            location.file_path.as_bytes(),
            location.qualified_name.as_bytes(),
            location.label.as_bytes(),
            location.cx_id.as_bytes(),
        ] {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&location.start_line.to_be_bytes());
        bytes.extend_from_slice(&location.end_line.to_be_bytes());
    }
    bytes
}

fn verify_existing_historical_constellation<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    prepared: &PreparedConstellation,
) -> IngestResult<()>
where
    C: Clock,
{
    let bytes = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Base,
            &base_key(prepared.identity.cx_id),
        )?
        .ok_or_else(|| readback_mismatch("historical Base CF row disappeared"))?;
    let decoded = encode::decode_constellation_base(&bytes)?;
    if decoded.cx_id != prepared.identity.cx_id
        || decoded.vault_id != prepared.constellation.vault_id
        || decoded.panel_version != prepared.constellation.panel_version
        || decoded.input_ref.hash != prepared.constellation.input_ref.hash
        || decoded.input_ref.redacted != prepared.constellation.input_ref.redacted
        || decoded.modality != prepared.constellation.modality
        || decoded.scalars != prepared.constellation.scalars
    {
        return Err(readback_mismatch(format!(
            "preexisting historical Base CF fields differ for {}",
            prepared.identity.cx_id
        )));
    }
    for key in [
        "astrolabe_schema",
        "qualified_name",
        "label",
        "series_id_schema",
        "series_id",
        "input_hash_blake3",
    ] {
        if decoded.metadata.get(key) != prepared.constellation.metadata.get(key) {
            return Err(readback_mismatch(format!(
                "preexisting historical Base CF metadata {key} differs for {}",
                prepared.identity.cx_id
            )));
        }
    }
    for (slot, expected) in &prepared.constellation.slots {
        let bytes = vault
            .read_cf_at(
                snapshot,
                ColumnFamily::slot(*slot),
                &slot_key(prepared.identity.cx_id),
            )?
            .ok_or_else(|| {
                readback_mismatch(format!(
                    "preexisting historical slot {slot} missing for {}",
                    prepared.identity.cx_id
                ))
            })?;
        if encode::decode_slot_vector(&bytes)? != *expected {
            return Err(readback_mismatch(format!(
                "preexisting historical slot {slot} differs for {}",
                prepared.identity.cx_id
            )));
        }
    }
    Ok(())
}

fn write_cbm_graph_snapshot_sqlite(snapshot: &CbmGraphSnapshot, path: &Path) -> IngestResult<()> {
    cleanup_sqlite_path(path);
    // #412: extended-length (`\\?\`) normalization so a row-sink snapshot under a
    // deep store (total path > MAX_PATH) is created instead of failing closed.
    let open_path = astrolabe_domain::winpath::sqlite_open_path(path)
        .map_err(|error| invalid_sqlite(format!("normalize row-sink SQLite path: {error}")))?;
    let connection = Connection::open(&open_path)
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

    // Legitimate (not a silent fallback): the CBM row-sink pipeline emits nodes
    // and edges but no project-metadata rows, so production snapshots
    // (`pipeline_rows_to_graph_snapshot`) always carry `projects: Vec::new()`.
    // The project identity is authoritative -- `snapshot.project` is validated to
    // equal `options.project` before this path runs -- so synthesizing a single
    // provenance-carrying project row for the temp SQLite mirrors the documented
    // table-absent branch in `read_projects`. A genuinely empty/misidentified
    // import is still caught downstream by the >=1-node refusal, not masked here.
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
        // Legitimate (not a silent fallback): this is the production direct row-sink
        // path. `pipeline_rows_to_graph_snapshot` builds every snapshot with an empty
        // `projects` vec because the CBM pipeline emits no project-metadata rows, and
        // `snapshot.project` was validated to equal `options.project` before this
        // runs. Synthesize one provenance-carrying project row from the authoritative
        // project name and the source fingerprint so the metadata graph row is
        // labeled; a genuinely empty/misidentified import is still caught downstream
        // by the >=1-node refusal rather than masked here.
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

fn snapshot_node_rows(
    snapshot: &CbmGraphSnapshot,
    project: &str,
    workers: usize,
) -> IngestResult<Vec<RawNodeRow>> {
    let nodes = snapshot
        .nodes
        .iter()
        .filter(|node| node.project == project)
        .collect::<Vec<_>>();
    let mut rows = parallel_map(nodes, workers, |node| {
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
        Ok(RawNodeRow {
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
        })
    })?;
    rows.sort_by_key(|row| row.id);
    Ok(rows)
}

fn snapshot_edge_rows(
    snapshot: &CbmGraphSnapshot,
    project: &str,
    workers: usize,
) -> IngestResult<Vec<RawEdgeRow>> {
    let edges = snapshot
        .edges
        .iter()
        .filter(|edge| edge.project == project)
        .collect::<Vec<_>>();
    let mut rows = parallel_map(edges, workers, |edge| {
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
        Ok(RawEdgeRow {
            id: edge.sqlite_edge_id,
            project: edge.project.clone(),
            source_id: edge.source_node_id,
            target_id: edge.target_node_id,
            edge_type: edge.edge_type.clone(),
            properties,
            properties_json: edge.properties_json.clone(),
            local_name_gen: edge.local_name_gen.clone(),
        })
    })?;
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
    if let Some(gate) = &options.quantization_gate {
        validate_quantization_gate_config(gate)?;
    }
    Ok(())
}

fn validate_quantization_gate_config(gate: &QuantizationGateConfig) -> IngestResult<()> {
    if gate.min_recall_millipoints > 1000
        || gate.max_recall_drop_millipoints > 1000
        || gate.max_guard_far_regression_millipoints > 1000
    {
        return Err(quantization_gate_invalid(
            "quantization gate millipoint policy values must be <= 1000",
        ));
    }
    let known_slots = default_panel_slots()
        .iter()
        .map(|slot| slot.slot)
        .collect::<BTreeSet<_>>();
    for slot in &gate.guard_slots {
        if !known_slots.contains(slot) {
            return Err(quantization_gate_invalid(format!(
                "guard slot S{slot} is not in the frozen panel roster"
            )));
        }
    }
    let mut seen = BTreeSet::new();
    for measurement in &gate.measurements {
        if !known_slots.contains(&measurement.slot) {
            return Err(quantization_gate_invalid(format!(
                "quantization measurement slot S{} is not in the frozen panel roster",
                measurement.slot
            )));
        }
        if !seen.insert(measurement.slot) {
            return Err(quantization_gate_invalid(format!(
                "quantization measurement for slot S{} is duplicated",
                measurement.slot
            )));
        }
        if measurement.candidate_policy.trim().is_empty() {
            return Err(quantization_gate_invalid(format!(
                "quantization measurement for slot S{} has empty candidate_policy",
                measurement.slot
            )));
        }
        if measurement.recall_at_k_raw_millipoints > 1000
            || measurement.recall_at_k_candidate_millipoints > 1000
            || measurement.guard_far_raw_millipoints > 1000
            || measurement.guard_far_candidate_millipoints > 1000
        {
            return Err(quantization_gate_invalid(format!(
                "quantization measurement for slot S{} has millipoint values > 1000",
                measurement.slot
            )));
        }
        if measurement
            .provenance_refs
            .iter()
            .all(|provenance| provenance.trim().is_empty())
        {
            return Err(quantization_gate_invalid(format!(
                "quantization measurement for slot S{} requires non-empty provenance",
                measurement.slot
            )));
        }
    }
    Ok(())
}

fn quantization_gate_report(
    options: &SqliteImportOptions,
    prepared: &PreparedBatch,
) -> SqliteImportQuantizationReport {
    let Some(gate) = &options.quantization_gate else {
        return SqliteImportQuantizationReport {
            schema: SCHEMA_QUANTIZATION_GATE.to_string(),
            status: "unconfigured".to_string(),
            applied: false,
            storage_mode: "raw_cf".to_string(),
            policy: QuantizationGatePolicyReport {
                min_recall_millipoints: 0,
                max_recall_drop_millipoints: 0,
                max_guard_far_regression_millipoints: 0,
                require_panel_bits_non_regression: true,
            },
            slots: Vec::new(),
            accepted_slot_count: 0,
            refused_slot_count: 0,
            guard_slot_count: 0,
            raw_guard_slot_rows_verified: 0,
            expected_raw_guard_slot_rows: 0,
            trust: "provisional".to_string(),
            freshness: "not_evaluated".to_string(),
        };
    };
    let slots = gate
        .measurements
        .iter()
        .map(|measurement| quantization_slot_decision(gate, measurement))
        .collect::<Vec<_>>();
    let accepted_slot_count = slots
        .iter()
        .filter(|slot| slot.decision == "accepted")
        .count();
    let refused_slot_count = slots
        .iter()
        .filter(|slot| slot.decision == "refused_raw")
        .count();
    let status = if refused_slot_count > 0 {
        "refused_raw"
    } else if accepted_slot_count > 0 {
        "applied"
    } else {
        "raw_guard"
    };
    SqliteImportQuantizationReport {
        schema: SCHEMA_QUANTIZATION_GATE.to_string(),
        status: status.to_string(),
        applied: status == "applied",
        storage_mode: "raw_cf_with_measured_gate".to_string(),
        policy: QuantizationGatePolicyReport {
            min_recall_millipoints: gate.min_recall_millipoints,
            max_recall_drop_millipoints: gate.max_recall_drop_millipoints,
            max_guard_far_regression_millipoints: gate.max_guard_far_regression_millipoints,
            require_panel_bits_non_regression: gate.require_panel_bits_non_regression,
        },
        slots,
        accepted_slot_count,
        refused_slot_count,
        guard_slot_count: gate.guard_slots.len(),
        raw_guard_slot_rows_verified: 0,
        expected_raw_guard_slot_rows: expected_raw_guard_slot_rows(prepared, gate),
        trust: "verified".to_string(),
        freshness: "fresh".to_string(),
    }
}

fn quantization_slot_decision(
    gate: &QuantizationGateConfig,
    measurement: &QuantizationGateMeasurement,
) -> QuantizationSlotDecision {
    if gate.guard_slots.contains(&measurement.slot) {
        return QuantizationSlotDecision {
            slot: measurement.slot,
            candidate_policy: measurement.candidate_policy.clone(),
            decision: "raw_guard".to_string(),
            pass: true,
            recall_at_k_raw_millipoints: measurement.recall_at_k_raw_millipoints,
            recall_at_k_candidate_millipoints: measurement.recall_at_k_candidate_millipoints,
            panel_bits_raw_millibits: measurement.panel_bits_raw_millibits,
            panel_bits_candidate_millibits: measurement.panel_bits_candidate_millibits,
            guard_far_raw_millipoints: measurement.guard_far_raw_millipoints,
            guard_far_candidate_millipoints: measurement.guard_far_candidate_millipoints,
            provenance_refs: measurement.provenance_refs.clone(),
            reason: Some("guard-designated slots are stored raw".to_string()),
            remediation: None,
        };
    }
    let reasons = quantization_refusal_reasons(gate, measurement);
    let pass = reasons.is_empty();
    QuantizationSlotDecision {
        slot: measurement.slot,
        candidate_policy: measurement.candidate_policy.clone(),
        decision: if pass { "accepted" } else { "refused_raw" }.to_string(),
        pass,
        recall_at_k_raw_millipoints: measurement.recall_at_k_raw_millipoints,
        recall_at_k_candidate_millipoints: measurement.recall_at_k_candidate_millipoints,
        panel_bits_raw_millibits: measurement.panel_bits_raw_millibits,
        panel_bits_candidate_millibits: measurement.panel_bits_candidate_millibits,
        guard_far_raw_millipoints: measurement.guard_far_raw_millipoints,
        guard_far_candidate_millipoints: measurement.guard_far_candidate_millipoints,
        provenance_refs: measurement.provenance_refs.clone(),
        reason: (!pass).then(|| reasons.join("; ")),
        remediation: (!pass).then(|| {
            "keep raw slot storage and rerun the quantization replay with a non-regressing candidate"
                .to_string()
        }),
    }
}

fn quantization_refusal_reasons(
    gate: &QuantizationGateConfig,
    measurement: &QuantizationGateMeasurement,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if measurement.recall_at_k_candidate_millipoints < gate.min_recall_millipoints {
        reasons.push(format!(
            "candidate recall_at_k {} < required {}",
            measurement.recall_at_k_candidate_millipoints, gate.min_recall_millipoints
        ));
    }
    let recall_drop = measurement
        .recall_at_k_raw_millipoints
        .saturating_sub(measurement.recall_at_k_candidate_millipoints);
    if recall_drop > gate.max_recall_drop_millipoints {
        reasons.push(format!(
            "candidate recall drop {recall_drop} > allowed {}",
            gate.max_recall_drop_millipoints
        ));
    }
    if gate.require_panel_bits_non_regression
        && measurement.panel_bits_candidate_millibits < measurement.panel_bits_raw_millibits
    {
        reasons.push(format!(
            "candidate panel bits {} < raw {}",
            measurement.panel_bits_candidate_millibits, measurement.panel_bits_raw_millibits
        ));
    }
    let far_regression = measurement
        .guard_far_candidate_millipoints
        .saturating_sub(measurement.guard_far_raw_millipoints);
    if far_regression > gate.max_guard_far_regression_millipoints {
        reasons.push(format!(
            "candidate guard FAR regression {far_regression} > allowed {}",
            gate.max_guard_far_regression_millipoints
        ));
    }
    reasons
}

fn expected_raw_guard_slot_rows(prepared: &PreparedBatch, gate: &QuantizationGateConfig) -> usize {
    prepared
        .constellations
        .iter()
        .filter_map(|prepared| prepared.measured.as_ref())
        .map(|constellation| {
            constellation
                .slots
                .keys()
                .filter(|slot| gate.guard_slots.contains(&slot.get()))
                .count()
        })
        .sum()
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
        ) = row.map_err(|error| {
            invalid_sqlite(format!(
                "read nodes row: {error}; a non-UTF-8 text column violates the \
                 cbm_json_escape UTF-8 write contract (#493) — the DB was written \
                 by a pre-contract indexer; delete the store and re-index with a \
                 current binary"
            ))
        })?;
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
        return Err(invalid_sqlite(
            "SQLite dump has no edges table; a Codebase Memory MCP dump always \
             carries an edges table, so a missing one signals a truncated or \
             misidentified input",
        ));
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
            row.map_err(|error| {
                invalid_sqlite(format!(
                    "read edges row: {error}; a non-UTF-8 text column violates the \
                     cbm_json_escape UTF-8 write contract (#493) — the DB was written \
                     by a pre-contract indexer; delete the store and re-index with a \
                     current binary"
                ))
            })?;
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

/// A CBM pipeline node row read back from a persisted CBM SQLite `nodes` table.
///
/// These fields mirror exactly the ones the in-process graph-buffer row sink
/// emitted (`cbm_gbuf_row_node_t`): the SQLite `nodes` table and the row-sink
/// stream are two serializations of the identical in-memory dump-node array
/// (`cbm_gbuf_dump_to_sqlite` writes the same `dump_nodes` array the sink drains,
/// with the same final ids), so a readback reproduces the row-sink node stream
/// byte-for-byte. #405 reads this back after running the CBM pipeline
/// out-of-process, instead of forcing the pipeline in-process to carry an FFI
/// row-sink callback that cannot cross the supervisor's process boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbmSqlitePipelineNode {
    pub id: i64,
    pub project: String,
    pub label: String,
    pub name: String,
    pub qualified_name: String,
    pub file_path: String,
    pub start_line: i64,
    pub end_line: i64,
    pub properties_json: String,
}

/// A CBM pipeline edge row read back from a persisted CBM SQLite `edges` table.
///
/// Mirrors `cbm_gbuf_row_edge_t`. `local_name_gen` is derived exactly as both the
/// SQLite `local_name_gen` generated column and the graph-buffer sink derive it
/// (the `local_name` property of an `IMPORTS` edge, empty otherwise);
/// `url_path_gen` mirrors the `url_path_gen` generated column (`$.url_path`). Each
/// edge's `source_id`/`target_id` are the persisted node ids, matching the ids the
/// sink emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbmSqlitePipelineEdge {
    pub id: i64,
    pub project: String,
    pub source_id: i64,
    pub target_id: i64,
    pub edge_type: String,
    pub properties_json: String,
    pub url_path_gen: String,
    pub local_name_gen: String,
}

/// The full CBM pipeline row stream for one project, read back from its persisted
/// CBM SQLite (`<project>.db`) — the out-of-process equivalent of the in-process
/// FFI row sink (#405).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbmSqlitePipelineRows {
    pub project: String,
    pub nodes: Vec<CbmSqlitePipelineNode>,
    pub edges: Vec<CbmSqlitePipelineEdge>,
}

/// Reads the CBM pipeline row stream for `project` back from a persisted CBM SQLite
/// dump (`<project>.db`), reproducing the graph-buffer row sink's output from real
/// persisted bytes (#405).
///
/// This is the out-of-process equivalent of the in-process FFI row sink: the CBM
/// pipeline is run in a supervised child (which writes `<project>.db` from the same
/// in-memory `dump_nodes`/`dump_edges` arrays the sink would have drained), and the
/// parent rebuilds the identical row stream from the persisted `nodes`/`edges`
/// tables here. Node `id` equals the SQLite node rowid and each edge's
/// `source_id`/`target_id` equal those node ids — exactly as the sink emitted them —
/// so the row-sink-derived shadow surfaces built from these rows are byte-identical
/// to the old in-process row-sink path. Node vectors are intentionally not read: the
/// row sink never carried them either (`CbmPipelineNodeRow` has no vector field), so
/// omitting them preserves parity. Fails closed with a labeled
/// `ASTRO_INGEST_SQLITE_INVALID` error on any malformed input (missing tables,
/// non-object properties JSON).
pub fn read_cbm_sqlite_pipeline_rows(
    sqlite_path: &Path,
    project: &str,
) -> IngestResult<CbmSqlitePipelineRows> {
    let connection = open_cbm_source_connection(sqlite_path)?;
    let raw_nodes = read_nodes(&connection, project)?;
    let raw_edges = read_edges(&connection, project)?;
    let nodes = raw_nodes
        .into_iter()
        .map(|node| CbmSqlitePipelineNode {
            id: node.id,
            project: node.project,
            label: node.label,
            name: node.name,
            qualified_name: node.qualified_name,
            file_path: node.file_path,
            start_line: node.start_line,
            end_line: node.end_line,
            properties_json: node.properties_json,
        })
        .collect();
    let edges = raw_edges
        .into_iter()
        .map(|edge| {
            // url_path_gen mirrors the SQLite `url_path_gen` generated column
            // (json_extract properties '$.url_path'). It is captured for row-shape
            // fidelity with the sink even though the shadow import does not consume
            // it (the downstream `CbmGraphEdge` carries only `local_name_gen`).
            let url_path_gen = edge
                .properties
                .get("url_path")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            CbmSqlitePipelineEdge {
                id: edge.id,
                project: edge.project,
                source_id: edge.source_id,
                target_id: edge.target_id,
                edge_type: edge.edge_type,
                properties_json: edge.properties_json,
                url_path_gen,
                local_name_gen: edge.local_name_gen,
            }
        })
        .collect();
    Ok(CbmSqlitePipelineRows {
        project: project.to_string(),
        nodes,
        edges,
    })
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
        // Schema-light inputs (row-sink parity fixtures, minimal dumps) may omit the
        // projects table entirely. Synthesize a provenance-carrying project row from the
        // source fingerprint so the metadata graph row is still labeled, and rely on the
        // downstream ≥1-node refusal to reject a genuinely empty/misidentified import
        // rather than silently succeeding.
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
        // The projects table exists but does not contain the requested project. This is a
        // typo'd `--project` or a truncated dump; fail closed instead of fabricating a
        // project row and reporting a successful-but-empty import.
        return Err(invalid_sqlite(format!(
            "project {:?} is absent from the SQLite projects table; no such project to import",
            options.project
        )));
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

/// Deterministic content bytes for a symbol whose substrate (libcbm) emits no raw
/// source snippet (#413). Frames the signature and the exact extracted-property bytes so
/// the canonical identity bytes (and thus CxId) vary with every body-derived attribute
/// the panel measures -- `properties_json` is libcbm's per-definition attribute set
/// (`st`, `bt`, `fp`, `sp`, `callees`, complexity, docstring, type surface, ...), which
/// is deterministic for a given body and produced identically on the live and historical
/// extract paths by the one linked libcbm archive. The length-prefixed frame keeps the
/// signature and property bytes from bleeding into each other so no two distinct
/// (signature, properties) pairs can alias.
fn symbol_content_fingerprint(properties_json: &str, signature: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(signature.len() + properties_json.len() + 8);
    out.extend_from_slice(&(signature.len() as u64).to_be_bytes());
    out.extend_from_slice(signature.as_bytes());
    out.extend_from_slice(properties_json.as_bytes());
    out
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
        // #413: content-address identity on the exact symbol content. libcbm emits no
        // raw `source`/`body`/`snippet` property, so when one is absent we must NOT fall
        // back to the body-independent `signature` alone: two historically distinct
        // bodies of the same symbol (identical file/line-span/signature) would then
        // collide on one CxId while their panel slots -- encoded from the body-derived
        // libcbm properties (`st`, `bt`, `fp`, `sp`, `callees`, complexity, ...) --
        // diverge, tripping the immutable-Base readback mismatch
        // (ASTRO_INGEST_READBACK_MISMATCH: preexisting historical slot N differs) during
        // historical admission. Folding the full extracted property set into the
        // canonical content bytes makes CxId a complete content address over exactly the
        // inputs that determine the constellation: equal CxId => equal properties =>
        // equal slot inputs => equal slots, so an unchanged body legitimately reuses one
        // immutable row and any body change mints a distinct version. Applied uniformly
        // to the live and historical extract paths (both route through this function),
        // so the same body always derives the same CxId across HEAD and every commit.
        let source_snippet = match string_property(
            &raw.properties,
            &["source_snippet", "source", "body", "snippet"],
        ) {
            Some(source) => source.as_bytes().to_vec(),
            None => symbol_content_fingerprint(&raw.properties_json, &signature),
        };

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

// The eighth argument is the shared pre-commit Graph scan (#23); bundling it
// into a struct with the five owned batch inputs would only relocate the
// argument list.
#[allow(clippy::too_many_arguments)]
fn prepare_batch<C, R>(
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    nodes: Vec<ExtractedNode>,
    edges: Vec<RawEdgeRow>,
    metadata: RawMetadataRows,
    sqlite_fingerprint: [u8; 32],
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    digest_reuse: &HashMap<i64, (CxId, SeriesId)>,
    unchanged_files: &BTreeSet<String>,
    new_file_digests: &BTreeMap<String, String>,
) -> IngestResult<PreparedBatch>
where
    C: Clock,
    R: SlotRuntime + Sync,
{
    let driver = PanelDriver::new(options.panel_version)?;
    // Keys this batch reuses byte-for-byte from unchanged files (#372); folded into change
    // derivation's "current" set so stale detection preserves them without a re-encode.
    let mut preserved_keys: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut encode_skip = EncodeSkipReport::default();
    // Hash each distinct project string once for the whole batch's key derivation (#380)
    // rather than once per candidate row in the preserved-detection loops below.
    let mut project_digests = ProjectDigestCache::default();
    // Split the owned node graph into structural and non-structural buckets by MOVE. `partition`
    // is order-preserving and hands each `ExtractedNode` to exactly one bucket, so no whole-graph
    // clone is created (the previous `.iter().filter().cloned()` held a second full copy of every
    // non-structural node alongside the borrowed `extracted` slice). The small structural bucket is
    // retained for the structural rows and endpoint set; the non-structural bucket is consumed by
    // the parallel constellation builder.
    let (structural, non_structural): (Vec<ExtractedNode>, Vec<ExtractedNode>) = nodes
        .into_iter()
        .partition(|node| node.label.is_structural());
    let mut timing_ms: Vec<(&'static str, u64)> = Vec::new();
    let mut phase_start = std::time::Instant::now();
    // #446: resolved once per import from the vault manifest (declared knob,
    // persist default) and applied to every symbol prepared below.
    let retention = vault.input_retention()?;
    let mut constellations = prepare_live_symbols_parallel(
        vault,
        runtime,
        options,
        &driver,
        non_structural,
        digest_reuse,
        retention,
    )?;
    constellations.sort_by_key(|prepared| prepared.node_id);
    timing_ms.push((
        "prepare_live_symbols",
        phase_start.elapsed().as_millis() as u64,
    ));
    phase_start = std::time::Instant::now();

    // Metadata rows. File-hash rows for unchanged files are carried forward from persisted
    // bytes rather than re-encoded (#372); their keys join `preserved_keys`.
    let mut graph_rows = metadata_graph_rows(
        options,
        metadata,
        sqlite_fingerprint,
        unchanged_files,
        existing_graph,
        &mut preserved_keys,
        &mut encode_skip,
        &mut project_digests,
    )?;
    // Node-map rows. A digest-reused symbol's persisted node-map row is provably unchanged
    // (its file's content matched, so every derived row matches; volatile fields are reverted
    // anyway), so skip re-encoding it and preserve its key. Fail open: if the persisted row is
    // somehow absent, fall back to encoding it (the reconcile path then writes it).
    let to_encode = constellations
        .iter()
        .filter(|prepared| {
            if digest_reuse.contains_key(&prepared.node_id)
                && let Ok(key) = node_map_reuse_key(prepared, &mut project_digests)
                && existing_graph.contains_key(&key)
            {
                encode_skip.node_map_rows_preserved += 1;
                preserved_keys.insert(key);
                return false;
            }
            true
        })
        .collect::<Vec<_>>();
    encode_skip.node_map_rows_encoded = to_encode.len();
    let node_map_rows = parallel_map(to_encode, options.workers, |prepared| {
        node_map_graph_row(options, prepared)
    })?;
    graph_rows.extend(node_map_rows);
    let structural_only = structural.len();
    for node in &structural {
        graph_rows.push(structural_graph_row(options, node)?);
    }
    graph_rows.extend(raw_edge_graph_rows(
        options,
        &edges,
        sqlite_fingerprint,
        digest_reuse,
        existing_graph,
        &mut preserved_keys,
        &mut encode_skip,
        &mut project_digests,
        options.workers,
    )?);
    // Per-file digest manifest rows (#345). Appended to the same graph-row stream as the
    // metadata/node-map/edge rows so they are reconciled, ledgered, and read back through
    // the identical path: an unchanged file's manifest row is byte-identical to its persisted
    // bytes, so (#372) skip re-encoding it and preserve its key; a changed file's row is
    // rewritten in this batch.
    graph_rows.extend(file_digest_manifest_rows(
        options,
        &constellations,
        new_file_digests,
        unchanged_files,
        existing_graph,
        &mut preserved_keys,
        &mut encode_skip,
        &mut project_digests,
    )?);
    parallel_for_each_mut(&mut graph_rows, options.workers, |(_, value)| {
        append_import_fingerprint(value, sqlite_fingerprint)
    })?;
    timing_ms.push((
        "encode_graph_rows",
        phase_start.elapsed().as_millis() as u64,
    ));
    phase_start = std::time::Instant::now();
    reuse_semantically_unchanged_graph_rows(existing_graph, &mut graph_rows, options.workers)?;
    timing_ms.push((
        "reuse_unchanged_graph_rows",
        phase_start.elapsed().as_millis() as u64,
    ));
    phase_start = std::time::Instant::now();
    let sqlite_edges = edges.len();
    let structural_node_ids = structural
        .iter()
        .map(|node| node.id)
        .collect::<BTreeSet<_>>();
    let (edge_rows, edge_skips) = prepare_edge_rows(
        options,
        &constellations,
        &structural_node_ids,
        edges,
        digest_reuse,
        existing_graph,
        &mut preserved_keys,
        &mut encode_skip,
    )?;
    timing_ms.push((
        "prepare_edge_rows",
        phase_start.elapsed().as_millis() as u64,
    ));

    Ok(PreparedBatch {
        constellations,
        graph_rows,
        edge_rows,
        structural_only,
        sqlite_edges,
        edge_skips,
        preserved_keys,
        encode_skip,
        timing_ms,
    })
}

/// Applies `f` to every item of `items` in place, chunked over at most
/// `workers` scoped threads. Chunk boundaries never change results: `f` is
/// applied to each item independently and items stay in their slots, so the
/// outcome is worker-count-invariant (#23).
fn parallel_for_each_mut<T, F>(items: &mut [T], workers: usize, f: F) -> IngestResult<()>
where
    T: Send,
    F: Fn(&mut T) -> IngestResult<()> + Sync + Send,
{
    let worker_count = workers.min(items.len()).max(1);
    if worker_count == 1 {
        for item in items.iter_mut() {
            f(item)?;
        }
        return Ok(());
    }
    // #349 root cause (see `parallel_map`): route the per-row work through rayon's
    // pre-attached global pool instead of ad-hoc `thread::scope` spawns, which
    // thread-attach-fault in the debug + mingw + static-libcbm server binary.
    // `try_for_each` mutates each element in place and short-circuits on the first
    // error; the per-element mutation is independent, so the result is invariant to
    // the worker count.
    use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
    items.par_iter_mut().try_for_each(f)
}

/// Maps `items` through `f`, chunked over at most `workers` scoped threads,
/// preserving input order in the output regardless of worker count (#23).
fn parallel_map<T, U, F>(items: Vec<T>, workers: usize, f: F) -> IngestResult<Vec<U>>
where
    T: Send,
    U: Send,
    F: Fn(T) -> IngestResult<U> + Sync + Send,
{
    let worker_count = workers.min(items.len()).max(1);
    if worker_count == 1 {
        return items.into_iter().map(f).collect();
    }
    // #349 root cause: the previous ad-hoc `thread::scope` spawned fresh OS
    // threads, and in the debug + mingw + static-libcbm astrolabe-server binary
    // every new thread's C-runtime thread-attach STATUS_ACCESS_VIOLATIONs before
    // the closure even runs (green in release and in the non-libcbm ingest/weave
    // test binaries, which is why worker>1 was pinned to 1 as containment). rayon's
    // global pool threads are attached once at pool init and reused, so routing the
    // per-row decode through them avoids the repeated thread-attach fault entirely.
    // `into_par_iter().map(..).collect::<Result<Vec<_>>>()` preserves input order and
    // short-circuits on the first error, so the output stays byte-identical across
    // worker counts (the seeded worker-count-invariance FSVs still hold).
    use rayon::iter::{IntoParallelIterator, ParallelIterator};
    items.into_par_iter().map(f).collect()
}

/// Reverts planned Graph rows to their persisted bytes when only volatile
/// fields differ, so the import stays byte-idempotent for unchanged symbols.
///
/// `existing` is the one shared pre-commit Graph CF scan (#23): the previous
/// per-row `read_cf_at` did one MVCC point read per planned row (~550k at M
/// scale) with identical semantics.
fn reuse_semantically_unchanged_graph_rows(
    existing: &BTreeMap<Vec<u8>, Vec<u8>>,
    rows: &mut [(Vec<u8>, Vec<u8>)],
    workers: usize,
) -> IngestResult<()> {
    parallel_for_each_mut(rows, workers, |(key, planned)| {
        let Some(existing_bytes) = existing.get(key.as_slice()) else {
            return Ok(());
        };
        if graph_semantic_json(existing_bytes)? == graph_semantic_json(planned)? {
            *planned = existing_bytes.clone();
        }
        Ok(())
    })
}

fn graph_semantic_json(bytes: &[u8]) -> IngestResult<Value> {
    let mut value: Value = serde_json::from_slice(bytes)?;
    if let Some(object) = value.as_object_mut() {
        for volatile in [
            "commit",
            "sqlite_fingerprint_sha256",
            "indexed_at",
            "mtime_ns",
            "created_at",
            "updated_at",
        ] {
            object.remove(volatile);
        }
    }
    Ok(value)
}

/// Content digest over one source file's raw CBM node rows and outgoing edge rows
/// (#345, edge fold #372).
///
/// Folds every raw field that determines a symbol's content-addressed identity or its
/// persisted graph/base/slot rows — id, project, label, name, qualified name, file path,
/// line span, properties JSON, and node vector — plus, for every edge whose SOURCE node
/// lives in this file, the edge's raw fields (id, endpoints, type, properties JSON,
/// local_name_gen). Everything is length-prefixed so no field boundary is ambiguous,
/// together with the digest domain and panel version. Node and edge order is normalized by
/// id so the digest is independent of CBM's emission order. Deliberately conservative: it
/// never excludes a field that could change the persisted rows, because an under-broad
/// digest would let a changed symbol or edge be wrongly reused, whereas an over-broad one
/// only costs a fail-open full reconcile. The edge fold is what makes the #372 edge-row
/// carry-forward sound: edge properties (resolution strategy/candidates) can change when a
/// third file changes, and that change lands in the source file's digest.
fn file_content_digest(
    nodes: &mut Vec<&RawNodeRow>,
    edges: &mut Vec<&RawEdgeRow>,
    panel_version: u32,
) -> String {
    // Length-prefixed field so no boundary between adjacent fields is ambiguous.
    fn section(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    nodes.sort_by_key(|node| node.id);
    edges.sort_by_key(|edge| edge.id);
    let mut hasher = Sha256::new();
    section(&mut hasher, FILE_DIGEST_DOMAIN.as_bytes());
    section(&mut hasher, &panel_version.to_be_bytes());
    for node in nodes.iter() {
        section(&mut hasher, &node.id.to_be_bytes());
        section(&mut hasher, node.project.as_bytes());
        section(&mut hasher, node.label.as_bytes());
        section(&mut hasher, node.name.as_bytes());
        section(&mut hasher, node.qualified_name.as_bytes());
        section(&mut hasher, node.file_path.as_bytes());
        section(&mut hasher, &node.start_line.to_be_bytes());
        section(&mut hasher, &node.end_line.to_be_bytes());
        section(&mut hasher, node.properties_json.as_bytes());
        match &node.node_vector {
            Some(bytes) => {
                section(&mut hasher, &[1u8]);
                section(&mut hasher, bytes);
            }
            None => section(&mut hasher, &[0u8]),
        }
    }
    for edge in edges.iter() {
        section(&mut hasher, &edge.id.to_be_bytes());
        section(&mut hasher, edge.project.as_bytes());
        section(&mut hasher, &edge.source_id.to_be_bytes());
        section(&mut hasher, &edge.target_id.to_be_bytes());
        section(&mut hasher, edge.edge_type.as_bytes());
        section(&mut hasher, edge.properties_json.as_bytes());
        section(&mut hasher, edge.local_name_gen.as_bytes());
    }
    hex_lower(hasher.finalize().as_slice())
}

/// Groups this import's raw nodes by source file — and raw edges by their SOURCE node's
/// file (#372) — and computes each file's content digest (#345). One entry per distinct
/// `file_path`. An edge whose source node id is not among this import's nodes belongs to
/// no file and is folded into no digest; such an edge can only be preserved through the
/// fail-open reconcile path, never wrongly skipped.
fn compute_file_digests(
    nodes: &[RawNodeRow],
    edges: &[RawEdgeRow],
    panel_version: u32,
) -> BTreeMap<String, String> {
    let file_by_node = nodes
        .iter()
        .map(|node| (node.id, node.file_path.as_str()))
        .collect::<HashMap<i64, &str>>();
    let mut by_file: BTreeMap<String, Vec<&RawNodeRow>> = BTreeMap::new();
    for node in nodes {
        by_file
            .entry(node.file_path.clone())
            .or_default()
            .push(node);
    }
    let mut edges_by_file: BTreeMap<&str, Vec<&RawEdgeRow>> = BTreeMap::new();
    for edge in edges {
        if let Some(file_path) = file_by_node.get(&edge.source_id) {
            edges_by_file.entry(file_path).or_default().push(edge);
        }
    }
    by_file
        .into_iter()
        .map(|(file_path, mut file_nodes)| {
            let mut file_edges = edges_by_file.remove(file_path.as_str()).unwrap_or_default();
            let digest = file_content_digest(&mut file_nodes, &mut file_edges, panel_version);
            (file_path, digest)
        })
        .collect()
}

/// Reads the persisted per-file digest manifest for `project` out of the one shared
/// pre-commit Graph CF scan (#345). A row that fails to decode, or belongs to another
/// project, is skipped (fail-open: the file it describes is then treated as new).
fn read_file_digest_manifest(
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    project: &str,
) -> BTreeMap<String, FileDigestRow> {
    let mut manifest = BTreeMap::new();
    for (key, value) in existing_graph {
        if !key.starts_with(FILE_DIGEST_ROW_PREFIX) {
            continue;
        }
        if let Ok(row) = serde_json::from_slice::<FileDigestRow>(value)
            && row.project == project
        {
            manifest.insert(row.file_path.clone(), row);
        }
    }
    manifest
}

/// The digest-derived reuse plan for one import (#345): which non-structural node ids may
/// take their content-addressed identity straight from a matching persisted file digest,
/// plus the skip accounting surfaced in the report.
struct DigestReusePlan {
    /// node_id → reused (cx_id, series_id) for symbols in files whose digest matched.
    reuse: HashMap<i64, (CxId, SeriesId)>,
    /// Source file paths whose persisted digest matched, so every graph/edge row derived
    /// from them is provably unchanged and eligible for the encode short-circuit (#372).
    unchanged_files: BTreeSet<String>,
    report: FileDigestReport,
}

/// Builds the reuse plan by comparing this import's per-file digests against the persisted
/// manifest (#345). A file is reused only when a persisted row exists with the same digest
/// domain, panel version, and digest value; every other file is counted as reconciled
/// (the labeled fail-open path) and none of its symbols enter the reuse map.
fn plan_digest_reuse(
    new_digests: &BTreeMap<String, String>,
    manifest: &BTreeMap<String, FileDigestRow>,
    panel_version: u32,
) -> DigestReusePlan {
    let mut reuse = HashMap::new();
    let mut unchanged_files = BTreeSet::new();
    let mut report = FileDigestReport {
        files_total: new_digests.len(),
        had_prior_manifest: !manifest.is_empty(),
        ..FileDigestReport::default()
    };
    for (file_path, digest) in new_digests {
        let matched = manifest.get(file_path).filter(|row| {
            row.domain == FILE_DIGEST_DOMAIN
                && row.panel_version == panel_version
                && &row.digest == digest
        });
        match matched {
            Some(row) => {
                report.files_unchanged += 1;
                unchanged_files.insert(file_path.clone());
                for symbol in &row.symbols {
                    reuse.insert(symbol.node_id, (symbol.cx_id, symbol.series_id));
                    report.symbols_reused_via_digest += 1;
                }
            }
            None => report.files_reconciled += 1,
        }
    }
    DigestReusePlan {
        reuse,
        unchanged_files,
        report,
    }
}

/// Builds the fresh per-file digest manifest rows for this import (#345), one per source
/// file, recording the file's new digest and the identity of every non-structural symbol
/// it produced. These flow through the same graph-row reconcile/write/readback path as the
/// metadata rows, so an unchanged file's manifest row reverts to its persisted bytes (no
/// write) while a changed file's row is rewritten in the same ledger-paired batch.
#[allow(clippy::too_many_arguments)]
fn file_digest_manifest_rows(
    options: &SqliteImportOptions,
    constellations: &[PreparedLiveSymbol],
    new_digests: &BTreeMap<String, String>,
    unchanged_files: &BTreeSet<String>,
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    preserved_keys: &mut BTreeSet<Vec<u8>>,
    encode_skip: &mut EncodeSkipReport,
    project_digests: &mut ProjectDigestCache,
) -> IngestResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let project_digest = project_digests.digest(&options.project);
    let mut symbols_by_file: BTreeMap<&str, Vec<FileDigestSymbol>> = BTreeMap::new();
    for prepared in constellations {
        symbols_by_file
            .entry(prepared.symbol.rel_file_path.as_str())
            .or_default()
            .push(FileDigestSymbol {
                node_id: prepared.node_id,
                cx_id: prepared.identity.cx_id,
                series_id: prepared.identity.series_id,
            });
    }
    let mut rows = Vec::with_capacity(new_digests.len());
    for (file_path, digest) in new_digests {
        let key = keyed_graph_key_with_digest(
            FILE_DIGEST_ROW_PREFIX,
            &project_digest,
            file_path.as_bytes(),
        );
        // An unchanged file's new manifest row is byte-identical to the persisted one: the
        // digest matched and the reused symbol identities were themselves read out of that
        // same persisted row (#345). Carry it forward without re-encoding (#372); fail open
        // to the encode path if the persisted row is missing.
        if unchanged_files.contains(file_path) && existing_graph.contains_key(&key) {
            symbols_by_file.remove(file_path.as_str());
            encode_skip.manifest_rows_preserved += 1;
            preserved_keys.insert(key);
            continue;
        }
        let mut symbols = symbols_by_file
            .remove(file_path.as_str())
            .unwrap_or_default();
        symbols.sort_by_key(|symbol| symbol.node_id);
        let row = FileDigestRow {
            schema: SCHEMA_FILE_DIGEST_ROW.to_string(),
            project: options.project.clone(),
            file_path: file_path.clone(),
            panel_version: options.panel_version,
            domain: FILE_DIGEST_DOMAIN.to_string(),
            digest: digest.clone(),
            symbols,
        };
        encode_skip.manifest_rows_encoded += 1;
        rows.push((key, serde_json::to_vec(&row)?));
    }
    Ok(rows)
}

#[allow(clippy::too_many_arguments)]
fn metadata_graph_rows(
    options: &SqliteImportOptions,
    metadata: RawMetadataRows,
    sqlite_fingerprint: [u8; 32],
    unchanged_files: &BTreeSet<String>,
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    preserved_keys: &mut BTreeSet<Vec<u8>>,
    encode_skip: &mut EncodeSkipReport,
    project_digests: &mut ProjectDigestCache,
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
            project_key_with_digest(PROJECT_ROW_PREFIX, &project_digests.digest(&row.project)),
            serde_json::to_vec(&row)?,
        ));
    }
    for file_hash in metadata.file_hashes {
        let key = keyed_graph_key_with_digest(
            FILE_HASH_ROW_PREFIX,
            &project_digests.digest(&file_hash.project),
            file_hash.rel_path.as_bytes(),
        );
        // A file whose per-file digest matched (#345) is byte-for-byte unchanged, so its
        // persisted file-hash row is unchanged too (sha256/size are content-derived; the
        // volatile commit/fingerprint/mtime fields revert on reconcile anyway). Carry the
        // persisted row forward without re-encoding it (#372); fail open if it is absent.
        if unchanged_files.contains(&file_hash.rel_path) && existing_graph.contains_key(&key) {
            encode_skip.file_hash_rows_preserved += 1;
            preserved_keys.insert(key);
            continue;
        }
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
        encode_skip.file_hash_rows_encoded += 1;
        rows.push((key, serde_json::to_vec(&row)?));
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
            project_key_with_digest(
                PROJECT_SUMMARY_ROW_PREFIX,
                &project_digests.digest(&row.project),
            ),
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
            graph_key_with_digest(
                TOKEN_VECTOR_ROW_PREFIX,
                &project_digests.digest(&row.project),
                row.id,
            )?,
            serde_json::to_vec(&row)?,
        ));
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(rows)
}

#[allow(clippy::too_many_arguments)]
fn raw_edge_graph_rows(
    options: &SqliteImportOptions,
    edges: &[RawEdgeRow],
    sqlite_fingerprint: [u8; 32],
    digest_reuse: &HashMap<i64, (CxId, SeriesId)>,
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    preserved_keys: &mut BTreeSet<Vec<u8>>,
    encode_skip: &mut EncodeSkipReport,
    project_digests: &mut ProjectDigestCache,
    workers: usize,
) -> IngestResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let fingerprint = hex_lower(&sqlite_fingerprint);
    // Partition edges before encoding (#372): a raw edge whose BOTH endpoints are digest-
    // reused is derived entirely from two unchanged files, so its persisted raw row is
    // unchanged. Carry it forward from persisted bytes (fail open if its key is absent);
    // encode only the remainder.
    let mut to_encode: Vec<&RawEdgeRow> = Vec::with_capacity(edges.len());
    for edge in edges {
        if digest_reuse.contains_key(&edge.source_id)
            && digest_reuse.contains_key(&edge.target_id)
            && let Ok(key) =
                raw_edge_key_parts_with_digest(&project_digests.digest(&edge.project), edge.id)
            && existing_graph.contains_key(&key)
        {
            encode_skip.raw_edge_rows_preserved += 1;
            preserved_keys.insert(key);
            continue;
        }
        to_encode.push(edge);
    }
    encode_skip.raw_edge_rows_encoded = to_encode.len();
    let mut rows = parallel_map(to_encode, workers, |edge| {
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
        Ok::<(Vec<u8>, Vec<u8>), IngestError>((raw_edge_key(&row)?, serde_json::to_vec(&row)?))
    })?;
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(rows)
}

#[allow(clippy::too_many_arguments)]
fn prepare_edge_rows(
    options: &SqliteImportOptions,
    constellations: &[PreparedLiveSymbol],
    structural_node_ids: &BTreeSet<i64>,
    edges: Vec<RawEdgeRow>,
    digest_reuse: &HashMap<i64, (CxId, SeriesId)>,
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    preserved_keys: &mut BTreeSet<Vec<u8>>,
    encode_skip: &mut EncodeSkipReport,
) -> IngestResult<(Vec<PreparedEdgeRow>, EdgeSkipCounters)> {
    let cx_by_node = constellations
        .iter()
        .map(|prepared| (prepared.node_id, prepared.identity.cx_id))
        .collect::<BTreeMap<_, _>>();
    let mut prepared = Vec::new();
    let mut skips = EdgeSkipCounters::default();

    for edge in edges {
        let src = cx_by_node.get(&edge.source_id).copied();
        let dst = cx_by_node.get(&edge.target_id).copied();
        let (Some(src), Some(dst)) = (src, dst) else {
            // The edge cannot become a typed constellation-to-constellation row. Attribute
            // the skip: a genuinely missing endpoint (not a constellation, not a structural
            // node) is a dangling reference; otherwise the only non-constellation endpoints
            // are structural nodes (Project/Branch/Folder), which are a by-design skip.
            let missing_endpoint = |cx: Option<CxId>, node_id: i64| {
                cx.is_none() && !structural_node_ids.contains(&node_id)
            };
            if missing_endpoint(src, edge.source_id) || missing_endpoint(dst, edge.target_id) {
                skips.dangling += 1;
            } else {
                skips.structural_endpoint += 1;
            }
            continue;
        };
        let kind = EdgeKind::from_cbm_type(&edge.edge_type).ok_or_else(|| {
            invalid_sqlite(format!(
                "edge {} has unknown Codebase Memory MCP type {:?}",
                edge.id, edge.edge_type
            ))
        })?;
        // A typed edge whose BOTH endpoints are digest-reused connects two unchanged files,
        // so its persisted typed row (same src/dst CxIds, same kind/local_name_gen key, same
        // content-derived fields) is unchanged (#372). Carry it forward from persisted bytes
        // and fold its key into the "current" set; fail open to the encode path if its key is
        // absent. The whole-vault `verify_chain` covers provenance, mirroring #345's Base skip.
        if digest_reuse.contains_key(&edge.source_id)
            && digest_reuse.contains_key(&edge.target_id)
            && let Ok(key) = edge_graph_key(src, dst, kind, &edge.local_name_gen)
            && existing_graph.contains_key(&key)
        {
            encode_skip.edge_rows_preserved += 1;
            preserved_keys.insert(key);
            continue;
        }
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
    encode_skip.edge_rows_encoded = prepared.len();
    prepared.sort_by(|left, right| left.key.cmp(&right.key));
    Ok((prepared, skips))
}

fn prepare_live_symbols_parallel<C, R>(
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    driver: &PanelDriver,
    nodes: Vec<ExtractedNode>,
    digest_reuse: &HashMap<i64, (CxId, SeriesId)>,
    retention: InputRetention,
) -> IngestResult<Vec<PreparedLiveSymbol>>
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
            .map(|node| {
                prepare_live_symbol(
                    vault,
                    runtime,
                    options,
                    driver,
                    node,
                    digest_reuse,
                    retention,
                )
            })
            .collect();
    }
    let chunk_size = nodes.len().div_ceil(worker_count);
    let mut owned_chunks = Vec::with_capacity(worker_count);
    let mut drain = nodes.into_iter();
    loop {
        let chunk = drain.by_ref().take(chunk_size).collect::<Vec<_>>();
        if chunk.is_empty() {
            break;
        }
        owned_chunks.push(chunk);
    }
    thread::scope(|scope| {
        let handles = owned_chunks
            .into_iter()
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .into_iter()
                        .map(|node| {
                            prepare_live_symbol(
                                vault,
                                runtime,
                                options,
                                driver,
                                node,
                                digest_reuse,
                                retention,
                            )
                        })
                        .collect::<IngestResult<Vec<_>>>()
                })
            })
            .collect::<Vec<_>>();
        let mut out = Vec::new();
        for handle in handles {
            out.extend(handle.join().map_err(|_| {
                IngestError::InvalidInput("parallel live-symbol preparation panicked".into())
            })??);
        }
        Ok(out)
    })
}

fn prepare_live_symbol<C, R>(
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    driver: &PanelDriver,
    node: ExtractedNode,
    digest_reuse: &HashMap<i64, (CxId, SeriesId)>,
    retention: InputRetention,
) -> IngestResult<PreparedLiveSymbol>
where
    C: Clock,
    R: SlotRuntime,
{
    // Per-file digest fast path (#345): this node's file matched a persisted digest, so
    // its content — and therefore its content-addressed identity — is provably unchanged
    // since the import that wrote the manifest. Reuse the recorded (cx_id, series_id)
    // without recomputing canonical bytes / CxId or reading Base. The digest was written
    // in the same ledger-paired batch as the Base/graph rows it summarizes, so a matching
    // digest guarantees those rows exist; `verify_preexisting_constellations` skips the
    // redundant per-symbol Base readback for exactly these node ids. `canonical_input_bytes`
    // and `vault_salt` are left empty because a reused symbol writes no Base row and no
    // downstream reader consumes them for a `measured: None` constellation.
    if let Some((cx_id, series_id)) = digest_reuse.get(&node.id).copied() {
        return Ok(PreparedLiveSymbol {
            node_id: node.id,
            name: node.name,
            properties_json: node.properties_json,
            node_vector: node.node_vector,
            symbol: node.symbol,
            identity: SymbolIdentity {
                series_id,
                cx_id,
                canonical_input_bytes: Vec::new(),
                vault_salt: String::new(),
            },
            measured: None,
        });
    }
    let identity = node.symbol.identity(options.panel_version)?;
    let reused = vault
        .read_cf_at(
            vault.latest_seq(),
            ColumnFamily::Base,
            &base_key(identity.cx_id),
        )?
        .is_some();
    if reused {
        return Ok(PreparedLiveSymbol {
            node_id: node.id,
            name: node.name,
            properties_json: node.properties_json,
            node_vector: node.node_vector,
            symbol: node.symbol,
            identity,
            measured: None,
        });
    }
    let prepared = prepare_constellation(vault, runtime, options, driver, node, retention)?;
    Ok(PreparedLiveSymbol {
        node_id: prepared.node_id,
        name: prepared.name,
        properties_json: prepared.properties_json,
        node_vector: prepared.node_vector,
        symbol: prepared.symbol,
        identity: prepared.identity,
        measured: Some(prepared.constellation),
    })
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
    retention: InputRetention,
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
            .map(|node| prepare_constellation(vault, runtime, options, driver, node, retention))
            .collect();
    }

    let chunk_size = nodes.len().div_ceil(worker_count);
    // Carve the owned node graph into per-worker owned chunks by MOVE. `chunks(_).to_vec()` cloned
    // every node into a second whole-graph copy that coexisted with the original `nodes` Vec for
    // the duration of the scope; draining `into_iter()` in bounded takes moves each node exactly
    // once into its worker chunk and releases the source Vec, so peak memory holds one copy of the
    // node graph, not two (#101). Chunk sizes/boundaries are identical to the prior `chunks()`
    // partition, and the caller re-sorts constellations by node_id, so output is byte-identical and
    // worker-count invariant.
    let mut owned_chunks: Vec<Vec<ExtractedNode>> = Vec::with_capacity(worker_count);
    let mut drain = nodes.into_iter();
    loop {
        let chunk: Vec<ExtractedNode> = drain.by_ref().take(chunk_size).collect();
        if chunk.is_empty() {
            break;
        }
        owned_chunks.push(chunk);
    }
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in owned_chunks {
            handles.push(scope.spawn(move || {
                chunk
                    .into_iter()
                    .map(|node| {
                        prepare_constellation(vault, runtime, options, driver, node, retention)
                    })
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
    retention: InputRetention,
) -> IngestResult<PreparedConstellation>
where
    C: Clock,
    R: SlotRuntime,
{
    let identity = node.symbol.identity(options.panel_version)?;
    let mut input = PanelInput::with_available_slots(node.label, options.available_slots.clone())
        .with_scalars(node.symbol.scalars.clone());
    input.source_bytes = node.symbol.source_snippet_bytes.clone();
    input.symbol_name = node.name.clone();
    input.qualified_name = node.symbol.qualified_name.clone();
    input.rel_file_path = node.symbol.rel_file_path.clone();
    input.language = node.symbol.language.clone();
    input.signature = node.symbol.signature.clone();
    input.properties = serde_json::from_str(&node.properties_json)?;
    let readout = driver.measure(&input, runtime)?;
    // #386: `st` (S1 struct-trigram source) and `callees` (S4 api-callee source) are
    // emitted by libcbm into properties_json solely to feed the S1/S4 slot encoders
    // that `driver.measure` just ran. Once the slot vectors exist in `readout.slots`
    // (persisted to the S1/S4 slot CFs below, the source of truth), the raw strings
    // are redundant persisted bytes — at M scale (15k+ defs) meaningful vault growth
    // for data stored twice. Strip them from the properties_json before it reaches the
    // Graph-CF node-map row; the encoded slot vectors are untouched (byte-identical
    // pre/post strip). A node without either key keeps its exact original bytes.
    let properties_json = strip_slot_source_properties(&node.properties_json);
    let mut metadata = symbol_metadata(options, &node, &identity);
    metadata.insert(
        "input_hash_blake3".to_string(),
        hex_lower(blake3::hash(&identity.canonical_input_bytes).as_bytes()),
    );
    let degraded = readout.slots.values().any(slot_is_degraded);
    let input_hash = *blake3::hash(&identity.canonical_input_bytes).as_bytes();
    // #446: a persisted symbol either carries its retained canonical input bytes
    // (typed `cxinput:v1:` pointer, rows committed in the same atomic batch by
    // `write_import_rows`) or an explicit redaction label — never a silent drop.
    let input_ref = match retention {
        InputRetention::Persist => InputRef {
            hash: input_hash,
            pointer: Some(input_store::input_pointer(&input_hash)),
            redacted: false,
        },
        InputRetention::Redact => InputRef {
            hash: input_hash,
            pointer: Some(format!("cbm-sqlite://nodes/{}", node.id)),
            redacted: true,
        },
    };
    let constellation = Constellation {
        cx_id: identity.cx_id,
        vault_id: vault.vault_id(),
        panel_version: options.panel_version,
        created_at: 0,
        input_ref,
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
            redacted_input: retention == InputRetention::Redact,
        },
    };
    constellation.validate_schema()?;
    Ok(PreparedConstellation {
        node_id: node.id,
        name: node.name,
        properties_json,
        node_vector: node.node_vector,
        symbol: node.symbol,
        identity,
        constellation,
    })
}

/// #386: remove the `st` and `callees` node properties (the S1 struct-trigram and S4
/// api-callee slot-encoder sources) from a `properties_json` string after the slots
/// have been encoded. Returns the input unchanged when neither key is present, so a
/// node that never carried them keeps byte-identical persisted properties; otherwise
/// returns the re-serialized object with both keys removed. On any parse or
/// re-serialization failure the original string is returned untouched — fail-closed:
/// saving redundant bytes must never corrupt persisted properties.
fn strip_slot_source_properties(properties_json: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(properties_json) else {
        return properties_json.to_string();
    };
    let Some(object) = value.as_object_mut() else {
        return properties_json.to_string();
    };
    let removed_st = object.remove("st").is_some();
    let removed_callees = object.remove("callees").is_some();
    if !removed_st && !removed_callees {
        return properties_json.to_string();
    }
    serde_json::to_string(&value).unwrap_or_else(|_| properties_json.to_string())
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
        SCHEMA_SYMBOL_METADATA.to_string(),
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
    metadata.insert("series_id_schema".to_string(), SERIES_ID_TAG.to_string());
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

/// The Graph CF key of a symbol's node-map row, without encoding the row value (#372).
/// Used to decide whether a digest-reused symbol's persisted node-map row can be carried
/// forward untouched, and to fold its key into the "current" set for stale detection.
fn node_map_reuse_key(
    prepared: &PreparedLiveSymbol,
    project_digests: &mut ProjectDigestCache,
) -> IngestResult<Vec<u8>> {
    graph_key_with_digest(
        NODE_MAP_PREFIX,
        &project_digests.digest(&prepared.symbol.project),
        prepared.node_id,
    )
}

fn node_map_graph_row(
    options: &SqliteImportOptions,
    prepared: &PreparedLiveSymbol,
) -> IngestResult<(Vec<u8>, Vec<u8>)> {
    let row = NodeMapRow {
        schema: SCHEMA_NODE_MAP.to_string(),
        series_id_schema: SERIES_ID_TAG.to_string(),
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
    workers: usize,
    digest_reuse: &HashMap<i64, (CxId, SeriesId)>,
) -> IngestResult<()>
where
    C: Clock,
{
    // Per-row verification is independent, so chunking it over `workers`
    // threads cannot change the outcome (#23); each reused row is still read
    // back from the persisted Base CF and identity-checked exactly as before.
    //
    // Symbols reused via a matching file digest (#345) are excluded: their Base row was
    // written in the same ledger-paired batch as the digest that just matched, and the
    // whole-vault `verify_chain` still runs after the import, so re-reading each of their
    // Base rows here would reintroduce the O(corpus) point reads the digest layer exists
    // to remove. Symbols reused by the Base-existence path (digest absent/mismatched) are
    // still verified individually.
    let reused = prepared
        .constellations
        .iter()
        .filter(|prepared_cx| {
            prepared_cx.measured.is_none() && !digest_reuse.contains_key(&prepared_cx.node_id)
        })
        .collect::<Vec<_>>();
    parallel_map(reused, workers, |prepared_cx| {
        let bytes = vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Base,
                &base_key(prepared_cx.identity.cx_id),
            )?
            .ok_or_else(|| readback_mismatch("reused Base CF row disappeared"))?;
        let decoded = encode::decode_constellation_base(&bytes)?;
        if decoded.cx_id != prepared_cx.identity.cx_id {
            return Err(readback_mismatch(format!(
                "reused Base identity differs for {}",
                prepared_cx.identity.cx_id
            )));
        }
        Ok(())
    })?;
    Ok(())
}

/// Pre-commit reconciliation of the prepared batch against the persisted
/// Graph CF, derived exactly once (#23).
///
/// The previous shape recomputed this three times per import — a counting pass
/// (`count_changed_graph_rows`), a write-derivation pass (`write_import_rows`),
/// and a full-CF stale scan inside each — with one MVCC point read per planned
/// row, one JSON decode plus one Ledger CF point read per typed edge, per pass.
/// This derivation reads the one shared `existing_graph` scan, decodes each
/// persisted edge row once, and validates each *distinct* ledger provenance
/// once. The decision semantics are unchanged: byte inequality for plain Graph
/// rows, field + ledger-provenance inequality for typed edge rows, and
/// project-scoped stale tombstoning for persisted rows the batch no longer
/// plans.
struct GraphRowChanges {
    /// Plain Graph rows whose planned bytes differ from the persisted bytes.
    graph_writes: Vec<(Vec<u8>, Vec<u8>)>,
    /// Typed edge rows to (re)write, already encoded.
    edge_writes: Vec<(Vec<u8>, Vec<u8>)>,
    /// Persisted project rows the batch no longer plans; tombstoned on write.
    stale_keys: Vec<Vec<u8>>,
    /// Edge keys proven unchanged pre-commit (fields and ledger provenance).
    unchanged_edge_keys: BTreeSet<Vec<u8>>,
    /// Graph rows this import will change, including edges and stale tombstones.
    graph_rows_written: usize,
    /// Edge rows this import will change, including stale edge tombstones.
    edge_rows_written: usize,
}

fn derive_graph_row_changes<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    prepared: &PreparedBatch,
    project: &str,
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    workers: usize,
) -> IngestResult<GraphRowChanges>
where
    C: Clock,
{
    let mut graph_writes = Vec::new();
    for (key, value) in &prepared.graph_rows {
        if existing_graph.get(key) != Some(value) {
            graph_writes.push((key.clone(), value.clone()));
        }
    }

    enum EdgeMatch {
        Absent,
        FieldsMatch(LedgerRef),
        Different,
    }
    let matched = parallel_map(
        prepared.edge_rows.iter().collect::<Vec<_>>(),
        workers,
        |edge| {
            Ok::<EdgeMatch, IngestError>(match existing_graph.get(&edge.key) {
                None => EdgeMatch::Absent,
                Some(bytes) => match serde_json::from_slice::<EdgeGraphRow>(bytes) {
                    Ok(row) if edge_row_matches_prepared(&row, edge) => {
                        EdgeMatch::FieldsMatch(row.provenance)
                    }
                    _ => EdgeMatch::Different,
                },
            })
        },
    )?;
    let mut provenance_ok = BTreeMap::<(u64, [u8; 32]), bool>::new();
    let mut edge_writes = Vec::new();
    let mut unchanged_edge_keys = BTreeSet::new();
    for (edge, matched) in prepared.edge_rows.iter().zip(matched) {
        let unchanged = match matched {
            EdgeMatch::Absent | EdgeMatch::Different => false,
            EdgeMatch::FieldsMatch(reference) => {
                match provenance_ok.get(&(reference.seq, reference.hash)) {
                    Some(known) => *known,
                    None => {
                        let intact = ledger_ref_matches(vault, snapshot, &reference)?;
                        provenance_ok.insert((reference.seq, reference.hash), intact);
                        intact
                    }
                }
            }
        };
        if unchanged {
            unchanged_edge_keys.insert(edge.key.clone());
        } else {
            edge_writes.push((edge.key.clone(), serde_json::to_vec(&edge.row)?));
        }
    }

    // The "current" key set drives stale tombstoning: any persisted project row NOT here is
    // deleted. It must include the rows this batch carried forward from unchanged files
    // WITHOUT re-encoding (#372) — otherwise those live rows would be spuriously tombstoned.
    // `preserved_keys` are persisted, unchanged, and still current; they simply were not
    // re-serialized into `graph_rows`/`edge_rows`.
    let current = prepared
        .graph_rows
        .iter()
        .map(|(key, _)| key.as_slice())
        .chain(prepared.edge_rows.iter().map(|edge| edge.key.as_slice()))
        .chain(prepared.preserved_keys.iter().map(|key| key.as_slice()))
        .collect::<BTreeSet<_>>();
    let mut stale_keys = Vec::new();
    for (key, value) in existing_graph {
        if current.contains(key.as_slice()) {
            continue;
        }
        let belongs_to_project = serde_json::from_slice::<Value>(value)
            .ok()
            .and_then(|row| {
                row.get("project")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .is_some_and(|row_project| row_project == project);
        if belongs_to_project {
            stale_keys.push(key.clone());
        }
    }
    stale_keys.sort();
    let stale_edges = stale_keys
        .iter()
        .filter(|key| key.starts_with(EDGE_ROW_PREFIX))
        .count();

    Ok(GraphRowChanges {
        graph_rows_written: graph_writes.len() + edge_writes.len() + stale_keys.len(),
        edge_rows_written: edge_writes.len() + stale_edges,
        graph_writes,
        edge_writes,
        stale_keys,
        unchanged_edge_keys,
    })
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

/// Outcome of [`write_import_rows`]: the paired ledger ref, the committed-state
/// FSV ack (absent when no rows were staged), graph rows written, edge rows
/// written, and labeled sub-phase timings.
type ImportWriteOutcome = (
    LedgerRef,
    Option<FsvAck>,
    usize,
    usize,
    Vec<(&'static str, u64)>,
);

fn write_import_rows<C>(
    vault: &AsterVault<C>,
    prepared: &PreparedBatch,
    sqlite_fingerprint: [u8; 32],
    payload: Vec<u8>,
    quantization_gate: Option<&QuantizationGateConfig>,
    changes: &GraphRowChanges,
) -> IngestResult<ImportWriteOutcome>
where
    C: Clock,
{
    // #433 sub-phase attribution (permanent labeled timing): stage_rows (encode +
    // stage every CF row), group_commit (the single atomic ledger-paired batch),
    // fsv_verify (the full row-by-row committed-state readback). Measurement
    // first: the batching decision for this phase must name which of these grows.
    let mut write_timing_ms: Vec<(&'static str, u64)> = Vec::new();
    let mut sub_phase = std::time::Instant::now();
    let snapshot = vault.latest_seq();
    // #446: input-store rows for newly measured symbols ride the same atomic
    // group commit as their Base records; a symbol is never durable without its
    // retained canonical input bytes (or an explicit redaction label).
    let retention = vault.input_retention()?;
    let mut staged_input_hashes = BTreeSet::new();
    let mut rows = Vec::new();
    for prepared_cx in &prepared.constellations {
        if let Some(constellation) = &prepared_cx.measured {
            rows.push((
                ColumnFamily::Base,
                base_key(constellation.cx_id),
                encode::encode_constellation_base(constellation)?,
            ));
            for (slot, vector) in &constellation.slots {
                rows.push((
                    ColumnFamily::slot(*slot),
                    slot_key(constellation.cx_id),
                    encode::encode_slot_vector(vector)?,
                ));
            }
            if retention == InputRetention::Persist
                && staged_input_hashes.insert(constellation.input_ref.hash)
            {
                for row in input_store::encode_input_rows(
                    &constellation.input_ref.hash,
                    &prepared_cx.identity.canonical_input_bytes,
                )? {
                    rows.push((row.cf, row.key, row.value));
                }
            }
        }
        if let (Some(gate), Some(constellation)) = (quantization_gate, &prepared_cx.measured) {
            for (slot, vector) in &constellation.slots {
                if !gate.guard_slots.contains(&slot.get()) {
                    continue;
                }
                let key = slot_key(constellation.cx_id);
                let raw_bytes = encode::encode_slot_vector(vector)?;
                if vault.read_cf_at(snapshot, ColumnFamily::slot_raw(*slot), &key)?
                    != Some(raw_bytes.clone())
                {
                    rows.push((ColumnFamily::slot_raw(*slot), key, raw_bytes));
                }
            }
        }
    }

    // The Graph CF delta was derived exactly once against the shared pre-commit
    // scan (#23); this function only stages it.
    let graph_rows_written = changes.graph_rows_written;
    let edge_rows_written = changes.edge_rows_written;
    for (key, value) in &changes.graph_writes {
        rows.push((ColumnFamily::Graph, key.clone(), value.clone()));
    }
    for (key, value) in &changes.edge_writes {
        rows.push((ColumnFamily::Graph, key.clone(), value.clone()));
    }
    for key in &changes.stale_keys {
        rows.push((ColumnFamily::Graph, key.clone(), tombstone_value().to_vec()));
    }

    write_timing_ms.push((
        "write_import_rows.stage_rows",
        sub_phase.elapsed().as_millis() as u64,
    ));
    sub_phase = std::time::Instant::now();

    if rows.is_empty() {
        let ledger_ref = vault.append_ledger_entry(
            EntryKind::Ingest,
            SubjectId::Query(sqlite_fingerprint.to_vec()),
            payload,
            ActorId::Service(ASTROLABE_INGEST_ACTOR.to_string()),
        )?;
        return Ok((
            ledger_ref,
            None,
            graph_rows_written,
            edge_rows_written,
            write_timing_ms,
        ));
    }

    let subject = SubjectId::Query(sqlite_fingerprint.to_vec());
    let actor = ActorId::Service(ASTROLABE_INGEST_ACTOR.to_string());
    // Calyx's group-commit path deterministically binds the staged ledger ref
    // into Base and provenance-bearing Graph rows before persistence. Preserve
    // the caller's write set so we can derive those exact post-bind bytes after
    // recovering this commit's ledger ref; hashing the pre-bind input would be a
    // false mismatch, while hashing store readback would be circular.
    let planned_rows = rows.clone();

    // Deriving the ledger seq from a pre-commit `ledger_row_count` is a TOCTOU under the
    // supported cross-process concurrency: an interleaved append from another process
    // would make a fixed index point at someone else's entry. Instead, capture the commit
    // snapshot seq returned by the atomic group commit and read the newest ledger row as
    // of exactly that snapshot — later concurrent commits live at higher seqs and are
    // invisible here, so the entry recovered is unambiguously this run's record.
    let commit_seq = vault.write_cf_batch_with_ledger_entry(
        rows,
        EntryKind::Ingest,
        subject.clone(),
        payload,
        actor.clone(),
    )?;
    let ledger_ref = ledger_ref_at_commit(vault, commit_seq)?;
    write_timing_ms.push((
        "write_import_rows.group_commit",
        sub_phase.elapsed().as_millis() as u64,
    ));
    sub_phase = std::time::Instant::now();
    let mut fsv_plan = VaultMutationPlan::new("sqlite_import", EntryKind::Ingest, &actor, &subject);
    for (cf, key, value) in planned_rows {
        if value == tombstone_value() {
            fsv_plan.push_tombstoned(cf, key, &tombstone_value());
        } else {
            let expected = expected_group_commit_bytes(cf, value, &ledger_ref)?;
            fsv_plan.push_content(cf, key, &expected);
        }
    }
    let fsv = fsv_plan.verify_committed(vault, commit_seq)?;
    write_timing_ms.push((
        "write_import_rows.fsv_verify",
        sub_phase.elapsed().as_millis() as u64,
    ));
    Ok((
        ledger_ref,
        Some(fsv),
        graph_rows_written,
        edge_rows_written,
        write_timing_ms,
    ))
}

/// Mirrors Calyx Aster's deterministic ledger-ref attachment for FSV
/// expectations. Expected bytes come only from the intended write plus the
/// independently recovered paired ledger ref, never from the data-row readback
/// that the resulting plan verifies.
fn expected_group_commit_bytes(
    cf: ColumnFamily,
    value: Vec<u8>,
    ledger_ref: &LedgerRef,
) -> IngestResult<Vec<u8>> {
    if cf == ColumnFamily::Base {
        let mut constellation = encode::decode_constellation_base(&value)?;
        constellation.provenance = ledger_ref.clone();
        return Ok(encode::encode_constellation_base(&constellation)?);
    }
    if cf == ColumnFamily::Graph {
        let Ok(mut json) = serde_json::from_slice::<Value>(&value) else {
            return Ok(value);
        };
        let Some(object) = json.as_object_mut() else {
            return Ok(value);
        };
        if object.contains_key("provenance") {
            object.insert("provenance".to_string(), serde_json::to_value(ledger_ref)?);
            return Ok(serde_json::to_vec(&json)?);
        }
    }
    Ok(value)
}

/// Recovers the ledger reference for the group commit that produced `commit_seq`.
///
/// The read is pinned to `commit_seq`, so the newest *pairable* Ledger CF row at that
/// snapshot is the entry this commit staged, regardless of concurrent cross-process appends
/// that land at later snapshots. Periodic system checkpoint entries interleaving inside the
/// same commit at checkpoint-interval boundaries are skipped exactly (#495). Fails closed if
/// the ledger key and encoded entry seq disagree.
fn ledger_ref_at_commit<C>(vault: &AsterVault<C>, commit_seq: Seq) -> IngestResult<LedgerRef>
where
    C: Clock,
{
    let (key, value) = calyx_aster::ledger_view::newest_pairable_ledger(
        vault.scan_cf_at(commit_seq, ColumnFamily::Ledger)?,
    )?
    .ok_or_else(|| readback_mismatch("Ledger CF empty at import commit snapshot"))?;
    let key_seq = parse_aster_ledger_seq(&key)?;
    let entry = decode(&value)?;
    if entry.seq != key_seq {
        return Err(readback_mismatch(format!(
            "Ledger CF key seq {key_seq} does not match encoded entry seq {}",
            entry.seq
        )));
    }
    Ok(LedgerRef {
        seq: entry.seq,
        hash: entry.entry_hash,
    })
}

fn verify_import_readback<C>(
    vault: &AsterVault<C>,
    prepared: &PreparedBatch,
    quantization_gate: Option<&QuantizationGateConfig>,
    changes: &GraphRowChanges,
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> IngestResult<SqliteImportReadback>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    // Post-commit readback strategy (#23): rows this import WROTE are point-read
    // back at the post-commit snapshot below. Rows the atomic group commit did
    // not touch are verified against the shared pre-commit Graph scan — those
    // are persisted bytes read from the store this run, the commit's write set
    // is exactly `changes` (readback-verified row-by-row by the FSV ack in
    // `write_import_rows`), so pre-commit bytes ARE the post-commit persisted
    // state for every untouched key.
    let written_keys = changes
        .graph_writes
        .iter()
        .map(|(key, _)| key.as_slice())
        .chain(changes.edge_writes.iter().map(|(key, _)| key.as_slice()))
        .collect::<BTreeSet<_>>();
    let mut base_rows_verified = 0;
    let mut slot_rows_verified = 0;
    let mut raw_guard_slot_rows_verified = 0;
    for prepared_cx in &prepared.constellations {
        let Some(constellation) = &prepared_cx.measured else {
            base_rows_verified += 1;
            continue;
        };
        let base_bytes = vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Base,
                &base_key(prepared_cx.identity.cx_id),
            )?
            .ok_or_else(|| readback_mismatch("Base CF row missing after import"))?;
        let decoded = encode::decode_constellation_base(&base_bytes)?;
        verify_live_base_fields(&decoded, prepared_cx, constellation)?;
        base_rows_verified += 1;

        for (slot, expected) in &constellation.slots {
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
        if let Some(gate) = quantization_gate {
            for (slot, expected) in &constellation.slots {
                if !gate.guard_slots.contains(&slot.get()) {
                    continue;
                }
                let expected_bytes = encode::encode_slot_vector(expected)?;
                let raw_bytes = vault
                    .read_cf_at(
                        snapshot,
                        ColumnFamily::slot_raw(*slot),
                        &slot_key(decoded.cx_id),
                    )?
                    .ok_or_else(|| {
                        readback_mismatch(format!("guard raw slot {slot} CF row missing"))
                    })?;
                if raw_bytes != expected_bytes {
                    return Err(readback_mismatch(format!(
                        "guard raw slot {slot} CF bytes changed for {}",
                        decoded.cx_id
                    )));
                }
                raw_guard_slot_rows_verified += 1;
            }
        }
    }

    let mut graph_rows_verified = 0;
    for (key, expected) in &prepared.graph_rows {
        if written_keys.contains(key.as_slice()) {
            let actual = vault
                .read_cf_at(snapshot, ColumnFamily::Graph, key)?
                .ok_or_else(|| readback_mismatch("Graph CF row missing after import"))?;
            if &actual != expected {
                return Err(readback_mismatch("Graph CF row bytes changed after import"));
            }
        } else {
            let actual = existing_graph
                .get(key.as_slice())
                .ok_or_else(|| readback_mismatch("Graph CF row missing after import"))?;
            if actual != expected {
                return Err(readback_mismatch("Graph CF row bytes changed after import"));
            }
        }
        graph_rows_verified += 1;
    }
    let mut edge_rows_verified = 0;
    let mut provenance_ok = BTreeMap::<(u64, [u8; 32]), bool>::new();
    for prepared_edge in &prepared.edge_rows {
        // Edges the pre-commit derivation proved unchanged (fields matched and
        // their ledger provenance verified against persisted state) were not in
        // the write batch, so their pre-commit persisted bytes are the post-
        // commit state; the derivation already performed the decode + ledger
        // verification this loop used to repeat per edge (#23).
        if changes.unchanged_edge_keys.contains(&prepared_edge.key) {
            if !existing_graph.contains_key(&prepared_edge.key) {
                return Err(readback_mismatch(
                    "unwritten edge Graph CF row disappeared before readback",
                ));
            }
            edge_rows_verified += 1;
            continue;
        }
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
        let provenance_key = (decoded.provenance.seq, decoded.provenance.hash);
        let intact = match provenance_ok.get(&provenance_key) {
            Some(known) => *known,
            None => {
                let intact = ledger_ref_matches(vault, snapshot, &decoded.provenance)?;
                provenance_ok.insert(provenance_key, intact);
                intact
            }
        };
        if !intact {
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
        .filter_map(|prepared| prepared.measured.as_ref())
        .map(|constellation| constellation.slots.len())
        .sum();
    let expected_edge_rows = prepared.edge_rows.len();
    let expected_graph_rows = prepared.graph_rows.len() + expected_edge_rows;
    let expected_raw_guard_slot_rows = quantization_gate
        .map(|gate| expected_raw_guard_slot_rows(prepared, gate))
        .unwrap_or(0);
    if base_rows_verified != expected_base_rows
        || slot_rows_verified != expected_slot_rows
        || graph_rows_verified != expected_graph_rows
        || edge_rows_verified != expected_edge_rows
        || raw_guard_slot_rows_verified != expected_raw_guard_slot_rows
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
        raw_guard_slot_rows_verified,
        expected_base_rows,
        expected_slot_rows,
        expected_graph_rows,
        expected_edge_rows,
        expected_raw_guard_slot_rows,
    })
}

fn verify_live_base_fields(
    decoded: &Constellation,
    prepared: &PreparedLiveSymbol,
    constellation: &Constellation,
) -> IngestResult<()> {
    if decoded.cx_id != prepared.identity.cx_id
        || decoded.vault_id != constellation.vault_id
        || decoded.panel_version != constellation.panel_version
        || decoded.input_ref != constellation.input_ref
        || decoded.modality != constellation.modality
        || decoded.scalars != constellation.scalars
    {
        return Err(readback_mismatch(format!(
            "Base CF decoded fields differ for {}",
            prepared.identity.cx_id
        )));
    }
    for key in [
        "astrolabe_schema",
        "qualified_name",
        "label",
        "source_node_id",
        "series_id_schema",
        "series_id",
    ] {
        if decoded.metadata.get(key) != constellation.metadata.get(key) {
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
    ensure_no_legacy_series_state(vault)?;
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
                if row.series_id_schema != SERIES_ID_TAG {
                    errors.push(format!(
                        "node map {} has wrong SeriesId schema",
                        hex_lower(&key)
                    ));
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
    read_cbm_graph_snapshot_at(vault, project, vault.latest_seq())
}

/// Reads the CBM graph snapshot as it existed at an explicit MVCC `snapshot`
/// sequence (#43 `query_graph` `as_of` time-travel).
///
/// Identical to [`read_cbm_graph_snapshot`] except that every CF read is pinned
/// to the caller-supplied `snapshot` seqno rather than `vault.latest_seq()`, so
/// the returned graph is the temporally-consistent state as of that sequence.
/// Callers resolve a wall-clock `as_of` timestamp to a seqno with
/// [`calyx_aster::vault::AsterVault::as_of`] (the `time_index` CF) and pass its
/// `seqno()` here. The read is a pure function of `(vault, project, snapshot)`:
/// re-reading the same seqno after later commits yields byte-identical rows.
pub fn read_cbm_graph_snapshot_at<C>(
    vault: &AsterVault<C>,
    project: &str,
    snapshot: Seq,
) -> IngestResult<CbmGraphSnapshot>
where
    C: Clock,
{
    ensure_no_legacy_series_state(vault)?;
    let mut panel_version = None;
    let mut nodes = Vec::new();

    // Every node-map -> Base binding is proven against ONE keys-only range scan
    // of the Base CF (#370) rather than a per-row Base point read: the point read
    // only ever existed to assert the Base row's *existence*, since the FULL
    // constellation decode is skipped for modern node-map rows (#23) — the decoded
    // Base row is needed only for panel_version (first node) and for legacy rows
    // that predate the inline name/line/properties fields. #349 EXONERATED
    // `scan_cf_range_keys_at` (the deterministic FSV `issue349_selected_cf_keys_scan_fsv`
    // reads back byte-exact keys over multiple SST generations; the keys path is
    // bounds-checked safe Rust with no `unsafe`, and the historical AV was the
    // debug + mingw + static-libcbm thread-attach fault, not this scan). A membership
    // test against the scanned key set is therefore existence-equivalent to the point
    // read, and the byte output is unchanged; only rows that genuinely need a decode
    // still issue a point read to fetch the value.
    let base_keys: HashSet<Vec<u8>> = vault
        .scan_cf_range_keys_at(snapshot, ColumnFamily::Base, &prefix_range(&[]))?
        .into_iter()
        .collect();
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
        if row.series_id_schema != SERIES_ID_TAG {
            return Err(IngestError::InvalidInput(format!(
                "node map row {} has wrong SeriesId schema {}",
                row.node_id, row.series_id_schema
            )));
        }
        let bkey = base_key(row.cx_id);
        if !base_keys.contains(&bkey) {
            return Err(IngestError::InvalidInput(format!(
                "node map row {} points to missing Base row {}",
                row.node_id, row.cx_id
            )));
        }
        let needs_base_decode = panel_version.is_none()
            || row.name.is_none()
            || row.file_path.is_empty()
            || row.start_line.is_none()
            || row.end_line.is_none();
        let decoded = if needs_base_decode {
            // The value is only materialized for the rows that actually decode it;
            // the scanned key set already proved existence for the rest (#370).
            let base = vault
                .read_cf_at(snapshot, ColumnFamily::Base, &bkey)?
                .ok_or_else(|| {
                    IngestError::InvalidInput(format!(
                        "node map row {} points to missing Base row {}",
                        row.node_id, row.cx_id
                    ))
                })?;
            Some(encode::decode_constellation_base(&base)?)
        } else {
            None
        };
        if let Some(decoded) = &decoded {
            panel_version.get_or_insert(decoded.panel_version);
        }
        let name = row
            .name
            .or_else(|| {
                decoded
                    .as_ref()
                    .and_then(|decoded| decoded.metadata_value("name").map(ToOwned::to_owned))
            })
            .unwrap_or_else(|| local_name_from_qn(&row.qualified_name));
        let file_path = if row.file_path.is_empty() {
            decoded
                .as_ref()
                .and_then(|decoded| decoded.metadata_value("file_path"))
                .unwrap_or_default()
                .to_string()
        } else {
            row.file_path
        };
        let start_line = row
            .start_line
            .or_else(|| {
                decoded
                    .as_ref()
                    .and_then(|decoded| scalar_i64(decoded, "start_line"))
            })
            .unwrap_or(0);
        let end_line = row
            .end_line
            .or_else(|| {
                decoded
                    .as_ref()
                    .and_then(|decoded| scalar_i64(decoded, "end_line"))
            })
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

    let raw_edge_rows = read_graph_rows::<C, CbmRawEdgeRow>(vault, snapshot, CBM_EDGE_ROW_PREFIX)?
        .into_iter()
        .filter(|row| row.project == project)
        .collect::<Vec<_>>();
    // Validation + conversion is per-row independent; the JSON object check on
    // every edge properties string dominated this read at M scale (#23). The
    // decode now runs worker>1 again: `parallel_map` routes any worker_count>1
    // through rayon's pre-attached global pool (see its body), which is the #349
    // root-cause cure for the debug + mingw + static-libcbm STATUS_ACCESS_VIOLATION
    // — the fault was the ad-hoc `thread::scope` thread-attach, not this decode or
    // `scan_cf_range_keys_at` (both exonerated). rayon's global pool threads attach
    // once at pool init, so they never hit the fault. Output order is preserved by
    // rayon's ordered collect, so the read-back stays byte-identical.
    let mut edges = parallel_map(raw_edge_rows, rayon::current_num_threads().max(2), |row| {
        if row.schema != SCHEMA_CBM_EDGE_ROW {
            return Err(IngestError::InvalidInput(format!(
                "raw edge row {} has wrong schema {}",
                row.sqlite_edge_id, row.schema
            )));
        }
        ensure_json_object_text(&row.properties_json, "edge properties")?;
        Ok(CbmGraphEdge {
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
        })
    })?;
    if edges.is_empty() {
        // Every modern import persists a raw `astrolabe:cbm-edge:v1` row for each
        // source edge (see `raw_edge_graph_rows`), covering dangling and
        // structural-endpoint edges that never become typed
        // constellation-to-constellation rows. Their absence while typed
        // `astrolabe:edge:v1` rows still exist means the vault was imported before
        // the raw-edge schema landed. Silently substituting the typed rows would
        // drop the dangling and structural-endpoint edges and report
        // skipped_edges=0, so the lowered artifact would diverge from the source
        // CBM graph with clean counters. Refuse fail-closed instead.
        let legacy_typed_edges =
            read_graph_rows::<C, EdgeGraphRow>(vault, snapshot, EDGE_ROW_PREFIX)?
                .into_iter()
                .filter(|row| row.project == project)
                .count();
        if legacy_typed_edges != 0 {
            return Err(IngestError::refused(
                ASTRO_LEGACY_CBM_EDGE_ROWS,
                format!(
                    "project {project:?} has {legacy_typed_edges} typed astrolabe:edge:v1 row(s) but no raw astrolabe:cbm-edge:v1 rows; this vault predates the raw-edge schema and its lowered graph would silently omit dangling and structural-endpoint edges"
                ),
                LEGACY_CBM_EDGE_ROWS_REMEDIATION,
            ));
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
        // Every import persists an `astrolabe:cbm-project:v1` row for the project
        // (`metadata_graph_rows` iterates a project set that `read_projects` /
        // `snapshot_metadata_rows` guarantee is non-empty). Their absence at
        // read-back therefore means a corrupt/erased vault, a legacy vault
        // predating project rows, or a project name that was never imported.
        // Fabricating a placeholder `{project, indexed_at:"", ...}` row would
        // return a clean-looking snapshot for a project the vault does not carry,
        // masking the missing provenance. Refuse fail-closed instead.
        return Err(IngestError::refused(
            ASTRO_MISSING_CBM_PROJECT_ROW,
            format!(
                "vault has no astrolabe:cbm-project:v1 row for project {project:?}; the project row is missing, erased, or the requested project was never imported"
            ),
            MISSING_CBM_PROJECT_ROW_REMEDIATION,
        ));
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

pub fn erase_imported_cx_graph_rows<C>(
    vault: &AsterVault<C>,
    project: &str,
    cx_id: CxId,
) -> IngestResult<CxGraphErasureReport>
where
    C: Clock,
{
    ensure_no_legacy_series_state(vault)?;
    let snapshot = vault.latest_seq();
    let mut rows = Vec::new();
    let tombstone = tombstone_value();
    let mut seen_keys = BTreeSet::new();
    let mut source_node_ids = BTreeSet::new();
    let mut node_map_rows_tombstoned = 0;
    let mut edge_rows_tombstoned = 0;
    let mut raw_edge_rows_tombstoned = 0;

    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(NODE_MAP_PREFIX),
    )? {
        let row = decode_graph_row::<NodeMapRow>(&key, &value)?;
        if row.project == project && row.cx_id == cx_id && seen_keys.insert(key.clone()) {
            source_node_ids.insert(row.node_id);
            rows.push((ColumnFamily::Graph, key, tombstone.clone()));
            node_map_rows_tombstoned += 1;
        }
    }

    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(EDGE_ROW_PREFIX),
    )? {
        let row = decode_graph_row::<EdgeGraphRow>(&key, &value)?;
        let touches_cx = row.project == project
            && (row.src == cx_id
                || row.dst == cx_id
                || source_node_ids.contains(&row.source_node_id)
                || source_node_ids.contains(&row.target_node_id));
        if touches_cx && seen_keys.insert(key.clone()) {
            rows.push((ColumnFamily::Graph, key, tombstone.clone()));
            edge_rows_tombstoned += 1;
        }
    }

    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(CBM_EDGE_ROW_PREFIX),
    )? {
        let row = decode_graph_row::<CbmRawEdgeRow>(&key, &value)?;
        let touches_cx = row.project == project
            && (source_node_ids.contains(&row.source_node_id)
                || source_node_ids.contains(&row.target_node_id));
        if touches_cx && seen_keys.insert(key.clone()) {
            rows.push((ColumnFamily::Graph, key, tombstone.clone()));
            raw_edge_rows_tombstoned += 1;
        }
    }

    if rows.is_empty() {
        return Ok(CxGraphErasureReport {
            project: project.to_string(),
            cx_id,
            node_map_rows_tombstoned,
            edge_rows_tombstoned,
            raw_edge_rows_tombstoned,
            seq: vault.latest_seq(),
            fsv: None,
        });
    }

    let payload = serde_json::to_vec(&json!({
        "schema": "astrolabe-cx-graph-erasure-v1",
        "project_sha256": hex_lower(&sha256_digest(project.as_bytes())),
        "cx_id": cx_id.to_string(),
        "node_map_rows_tombstoned": node_map_rows_tombstoned,
        "edge_rows_tombstoned": edge_rows_tombstoned,
        "raw_edge_rows_tombstoned": raw_edge_rows_tombstoned,
    }))?;
    let subject = SubjectId::Cx(cx_id);
    let actor = ActorId::Service(ASTROLABE_INGEST_ACTOR.to_string());
    let mut fsv_plan = VaultMutationPlan::new(
        "erase_imported_cx_graph_rows",
        EntryKind::Admin,
        &actor,
        &subject,
    );
    for (cf, key, value) in &rows {
        fsv_plan.push_tombstoned(*cf, key.clone(), value);
    }
    let commit_seq =
        vault.write_cf_batch_with_ledger_entry(rows, EntryKind::Admin, subject, payload, actor)?;
    let fsv = fsv_plan.verify_committed(vault, commit_seq)?;
    vault.purge_tombstoned_cfs(&[ColumnFamily::Graph])?;

    Ok(CxGraphErasureReport {
        project: project.to_string(),
        cx_id,
        node_map_rows_tombstoned,
        edge_rows_tombstoned,
        raw_edge_rows_tombstoned,
        seq: vault.latest_seq(),
        fsv: Some(fsv),
    })
}

fn decode_graph_row<T>(key: &[u8], value: &[u8]) -> IngestResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(value).map_err(|error| {
        IngestError::InvalidInput(format!("decode Graph CF row {}: {error}", hex_lower(key)))
    })
}

/// Report of a deliberately injected node-property fault (#19 L2 parity harness).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct InjectedNodeFault {
    /// Qualified name of the perturbed node.
    pub qualified_name: String,
    /// Node field that was perturbed (always `properties`).
    pub field: String,
    /// The sentinel properties JSON now persisted in the vault.
    pub properties_json: String,
}

/// Resolves outcome subjects to current constellation ids from the node map.
///
/// Reads every `astrolabe:node-map:v2` row of `project` from the vault Graph CF
/// and returns a `qualified_name -> cx_id` map, so the `anchor_outcome` tool can
/// bind an outcome subject id (a symbol / test-case qualified name) to the
/// constellation id to anchor. A qualified name carried by more than one node
/// with differing `cx_id`s is ambiguous and is left out of the map, so the
/// caller accounts it as an unresolved subject (counted, never a silent guess)
/// rather than anchoring to a guessed constellation.
pub fn read_node_map_cx_ids<C>(
    vault: &AsterVault<C>,
    project: &str,
) -> IngestResult<BTreeMap<String, CxId>>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let mut resolved: BTreeMap<String, CxId> = BTreeMap::new();
    let mut ambiguous: BTreeSet<String> = BTreeSet::new();
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
        match resolved.get(&row.qualified_name) {
            Some(existing) if *existing == row.cx_id => {}
            Some(_) => {
                ambiguous.insert(row.qualified_name.clone());
            }
            None => {
                resolved.insert(row.qualified_name.clone(), row.cx_id);
            }
        }
    }
    for name in &ambiguous {
        resolved.remove(name);
    }
    Ok(resolved)
}

/// Deliberately perturbs one persisted node-map row's properties in the vault.
///
/// Exists solely for the L2 shadow-parity harness (#19): it proves the parity
/// gate bites on real vault-state divergence — not just on SQLite-side
/// perturbation — by rewriting the lowest-qualified-name node-map row for
/// `project` with a sentinel properties object, committed through the normal
/// ledger-paired batch path so the chain stays intact while the graph content
/// diverges. Returns the exact QN/field so the harness can assert its failure
/// names them. Never call this outside a fault-injection gate.
pub fn inject_node_property_fault<C>(
    vault: &AsterVault<C>,
    project: &str,
) -> IngestResult<InjectedNodeFault>
where
    C: Clock,
{
    const FAULT_PROPERTIES: &str = "{\"astrolabe_vault_fault\":true}";
    const FAULT_ACTOR: &str = "astrolabe-parity-fault";
    let snapshot = vault.latest_seq();
    let rows = vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(NODE_MAP_PREFIX),
    )?;
    let mut selected: Option<(Vec<u8>, NodeMapRow)> = None;
    for (key, value) in rows {
        let row: NodeMapRow = decode_graph_row(&key, &value)?;
        if row.project != project || row.schema != SCHEMA_NODE_MAP {
            continue;
        }
        if selected
            .as_ref()
            .is_none_or(|(_, current)| row.qualified_name < current.qualified_name)
        {
            selected = Some((key, row));
        }
    }
    let Some((key, mut row)) = selected else {
        return Err(IngestError::InvalidInput(format!(
            "no node-map rows found for project {project}; import before injecting a fault"
        )));
    };
    row.properties_json = Some(FAULT_PROPERTIES.to_string());
    let value = serde_json::to_vec(&row)?;
    let payload = serde_json::to_vec(&json!({
        "schema": "astrolabe-parity-fault-v1",
        "project": project,
        "qualified_name": row.qualified_name,
        "field": "properties",
    }))?;
    vault.write_cf_batch_with_ledger_entry(
        [(ColumnFamily::Graph, key, value)],
        EntryKind::Admin,
        SubjectId::Query(FAULT_ACTOR.as_bytes().to_vec()),
        payload,
        ActorId::Service(FAULT_ACTOR.to_string()),
    )?;
    Ok(InjectedNodeFault {
        qualified_name: row.qualified_name,
        field: "properties".to_string(),
        properties_json: FAULT_PROPERTIES.to_string(),
    })
}

fn read_graph_rows<C, T>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    prefix: &[u8],
) -> IngestResult<Vec<T>>
where
    C: Clock,
    T: DeserializeOwned + Send,
{
    vault
        .scan_cf_range_at(snapshot, ColumnFamily::Graph, &prefix_range(prefix))?
        .into_iter()
        .map(|(key, value)| decode_graph_row(&key, &value))
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
        ("astrolabe_schema", SCHEMA_SYMBOL_METADATA),
        ("qualified_name", row.qualified_name.as_str()),
        ("label", row.label.as_str()),
        ("file_path", row.file_path.as_str()),
        ("series_id_schema", row.series_id_schema.as_str()),
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
    quantization: &SqliteImportQuantizationReport,
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
        edge_structural_endpoint_skipped: prepared.edge_skips.structural_endpoint as u64,
        expected_base_rows: prepared.constellations.len() as u64,
        expected_slot_rows: prepared
            .constellations
            .iter()
            .filter_map(|prepared| prepared.measured.as_ref())
            .map(|constellation| constellation.slots.len() as u64)
            .sum(),
        expected_graph_rows: (prepared.graph_rows.len() + prepared.edge_rows.len()) as u64,
        expected_edge_rows: prepared.edge_rows.len() as u64,
        quantization: quantization.clone(),
        encode_skip: prepared.encode_skip.clone(),
        first_cx_id: first,
        last_cx_id: last,
    };
    Ok(serde_json::to_vec(&payload)?)
}

fn ledger_row_count<C>(vault: &AsterVault<C>) -> IngestResult<usize>
where
    C: Clock,
{
    // Count by scanning keys only. Materializing every Ledger CF value (three times per
    // import) just to take a length needlessly copied the entire ledger payload set into
    // memory; the key-only scan keeps the count O(rows) in keys, not values.
    Ok(vault
        .scan_cf_range_keys_at(
            vault.latest_seq(),
            ColumnFamily::Ledger,
            &ledger_range(0, u64::MAX),
        )?
        .len())
}

fn ensure_no_legacy_series_state<C>(vault: &AsterVault<C>) -> IngestResult<()>
where
    C: Clock,
{
    crate::registry::ensure_no_legacy_series_registry(vault)?;
    ensure_no_legacy_node_maps(vault)
}

pub(crate) fn ensure_no_legacy_node_maps<C>(vault: &AsterVault<C>) -> IngestResult<()>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let legacy_rows = vault
        .scan_cf_range_at(
            snapshot,
            ColumnFamily::Graph,
            &prefix_range(LEGACY_NODE_MAP_PREFIX_V1),
        )?
        .len();
    if legacy_rows != 0 {
        return Err(IngestError::refused(
            ASTRO_SERIES_ID_V1_REBUILD_REQUIRED,
            format!("vault contains collision-prone v1 node-map state: rows={legacy_rows}"),
            SERIES_ID_V1_REBUILD_REMEDIATION,
        ));
    }
    Ok(())
}

/// Memoizes `sha256(project)` so the delta key-derivation helpers hash each distinct
/// project string once per import instead of once per row (#380). The preserved-row
/// detection loops derive a Graph CF key per candidate row; recomputing the 32-byte
/// project digest on every call was a pure-key-derivation floor (~42ms at 10k/40k even
/// when zero rows are encoded). A cached hit is byte-identical to a fresh
/// `sha256_digest(project.as_bytes())` because the digest is a pure function of the
/// project bytes, so keys are unchanged.
#[derive(Default)]
struct ProjectDigestCache {
    entries: HashMap<String, [u8; 32]>,
}

impl ProjectDigestCache {
    fn digest(&mut self, project: &str) -> [u8; 32] {
        if let Some(found) = self.entries.get(project) {
            return *found;
        }
        let digest = sha256_digest(project.as_bytes());
        self.entries.insert(project.to_owned(), digest);
        digest
    }
}

fn graph_key(prefix: &[u8], project: &str, node_id: i64) -> IngestResult<Vec<u8>> {
    graph_key_with_digest(prefix, &sha256_digest(project.as_bytes()), node_id)
}

/// The node-keyed Graph CF key from a precomputed project digest (#380). Byte-identical
/// to `graph_key` because the same digest bytes are concatenated in the same order.
fn graph_key_with_digest(
    prefix: &[u8],
    project_digest: &[u8; 32],
    node_id: i64,
) -> IngestResult<Vec<u8>> {
    let node_id = u64::try_from(node_id)
        .map_err(|_| invalid_sqlite(format!("node id {node_id} cannot be encoded")))?;
    let mut key = Vec::with_capacity(prefix.len() + 32 + 8);
    key.extend_from_slice(prefix);
    key.extend_from_slice(project_digest);
    key.extend_from_slice(&node_id.to_be_bytes());
    Ok(key)
}

/// The project-only Graph CF key from a precomputed project digest (#380).
fn project_key_with_digest(prefix: &[u8], project_digest: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 32);
    key.extend_from_slice(prefix);
    key.extend_from_slice(project_digest);
    key
}

/// The discriminator-keyed Graph CF key from a precomputed project digest (#380). The
/// discriminator digest is content-derived (small path bytes) and left inline.
fn keyed_graph_key_with_digest(
    prefix: &[u8],
    project_digest: &[u8; 32],
    discriminator: &[u8],
) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 64);
    key.extend_from_slice(prefix);
    key.extend_from_slice(project_digest);
    key.extend_from_slice(&sha256_digest(discriminator));
    key
}

fn raw_edge_key(row: &CbmRawEdgeRow) -> IngestResult<Vec<u8>> {
    raw_edge_key_parts(&row.project, row.sqlite_edge_id)
}

/// The raw CBM edge Graph CF key from its project + sqlite edge id, without encoding the
/// row value (#372) — used to decide whether an internal-to-unchanged edge can be carried
/// forward and to fold its key into the "current" set for stale detection.
fn raw_edge_key_parts(project: &str, sqlite_edge_id: i64) -> IngestResult<Vec<u8>> {
    raw_edge_key_parts_with_digest(&sha256_digest(project.as_bytes()), sqlite_edge_id)
}

/// The raw CBM edge Graph CF key from a precomputed project digest (#380).
fn raw_edge_key_parts_with_digest(
    project_digest: &[u8; 32],
    sqlite_edge_id: i64,
) -> IngestResult<Vec<u8>> {
    let id = u64::try_from(sqlite_edge_id)
        .map_err(|_| invalid_sqlite(format!("edge id {sqlite_edge_id} cannot be encoded")))?;
    let mut key = Vec::with_capacity(CBM_EDGE_ROW_PREFIX.len() + 32 + 8);
    key.extend_from_slice(CBM_EDGE_ROW_PREFIX);
    key.extend_from_slice(project_digest);
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
    // Single admission oracle shared with the emission-vocabulary parity check
    // (SymbolLabel::from_cbm_label). Keeping the accepted roster in one place
    // means a new C-side label drifts in exactly one spot.
    SymbolLabel::from_cbm_label(value)
        .ok_or_else(|| invalid_sqlite(format!("unknown Codebase Memory MCP node label {value:?}")))
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

/// Pure I/O read-buffer size for streaming the SQLite fingerprint. This is an
/// implementation detail of how bytes are fed to SHA-256, not a threshold or measurement:
/// the fingerprint value is identical for any positive buffer size.
const FINGERPRINT_CHUNK_BYTES: usize = 1 << 20;

/// Streams the SQLite input through SHA-256 in bounded chunks.
///
/// Fingerprinting formerly read the entire dump into memory (`fs::read`), so a multi-GB
/// dump was held in full alongside the parsed graph. Streaming keeps peak memory bounded
/// by [`FINGERPRINT_CHUNK_BYTES`] while producing the identical digest.
fn fingerprint_sqlite_file(path: &Path) -> IngestResult<[u8; 32]> {
    use std::io::Read;
    let read_error = |error: std::io::Error| {
        invalid_sqlite(format!("read SQLite input {}: {error}", path.display()))
    };
    let mut file = fs::File::open(path).map_err(&read_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; FINGERPRINT_CHUNK_BYTES];
    loop {
        let read = file.read(&mut buffer).map_err(&read_error)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

/// Streams the byte content of a Codebase Memory MCP SQLite file and returns its
/// lower-hex SHA-256 fingerprint.
///
/// This is the exact content fingerprint persisted as a shadow import's
/// `vault_fingerprint` watermark (see [`SqliteImportReport::sqlite_fingerprint_sha256`],
/// which is `hex_lower` of the same digest computed at import time). Recomputing it
/// over the live source and comparing against that persisted watermark is how callers
/// verify shadow freshness from content rather than from mere artifact existence
/// (issue #93). Fails closed with [`ASTRO_INGEST_SQLITE_INVALID`] when the file cannot
/// be read.
pub fn fingerprint_sqlite_hex(path: impl AsRef<Path>) -> IngestResult<String> {
    Ok(hex_lower(&fingerprint_sqlite_file(path.as_ref())?))
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

fn quantization_gate_invalid(message: impl Into<String>) -> IngestError {
    IngestError::refused(
        ASTRO_QUANTIZATION_GATE_INVALID,
        message,
        QUANTIZATION_GATE_REMEDIATION,
    )
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
