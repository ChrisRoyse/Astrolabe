use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use astrolabe_domain::fsv::FsvAck;
use astrolabe_domain::{
    ASTRO_ANCHOR_CONFIDENCE_RANGE, ASTRO_PANEL_VERSION_ZERO, ASTRO_SOURCE_DRIFT,
    ASTRO_SYMBOL_IDENTITY_EMPTY, ASTRO_SYMBOL_NON_FINITE, AnchorEvidence, DomainError, EdgeKind,
    SERIES_ID_TAG, SYMBOL_CANONICAL_TAG, SeriesId, SymbolIdentity, SymbolLabel, SymbolRecord,
    cx_id_from_canonical, vault_salt,
};
use astrolabe_panel::semantic::{
    SEMANTIC_RULES, SemanticFamily, SemanticKind, SemanticValue, is_semantic_presence_slot,
    semantic_registry_sha256, semantic_rule, semantic_rule_by_slot,
};
use astrolabe_panel::{
    CURRENT_SEMANTIC_PANEL_VERSION, PANEL_V3_VERSION, PANEL_V4_VERSION, PanelDriver, PanelInput,
    SlotRuntime, default_panel_slots, panel_slot_manifest_sha256, slots_for_version,
    validate_slot_vector_contract,
};
use calyx_aster::cf::{ColumnFamily, base_key, ledger_key, ledger_range, prefix_range, slot_key};
use calyx_aster::mvcc::{is_tombstone_value, tombstone_value};
use calyx_aster::vault::input_store::InputRetention;
use calyx_aster::vault::{
    AsterVault, LedgerBoundGroupReceipt, LedgerBoundWriteGroup, encode, input_store,
};
use calyx_core::{
    AbsentReason, Clock, Constellation, CxFlags, CxId, InputRef, LedgerRef, Modality, Seq, SlotId,
    SlotVector,
};
use calyx_ledger::{ActorId, EntryKind, LedgerEntryInput, LedgerRow, SubjectId, decode};
use rusqlite::{Connection, OpenFlags, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    ASTRO_SERIES_ID_V1_REBUILD_REQUIRED, IngestError, IngestResult,
    SERIES_ID_V1_REBUILD_REMEDIATION, SeriesVersionInput, VaultMutationPlan,
    VaultMutationReadbackMetrics, ingest_series_batch,
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
/// Refusal code for a graph row whose exact-source reference, Blob-CF payload,
/// digest, length, or byte span fails independent readback.
pub const ASTRO_EXACT_SOURCE_INVALID: &str = "ASTRO_EXACT_SOURCE_INVALID";
/// Refusal code for a CBM semantic atom absent from the frozen semantic registry.
pub const ASTRO_SEMANTIC_COVERAGE_GAP: &str = "ASTRO_SEMANTIC_COVERAGE_GAP";

const SQLITE_REMEDIATION: &str = "Open a valid Codebase Memory MCP SQLite dump with nodes, edges, and optional node_vectors tables.";
const READBACK_REMEDIATION: &str = "Stop ingest, inspect the Aster vault, and rerun astrolabe verify --deep before trusting the batch.";
const QUANTIZATION_GATE_REMEDIATION: &str = "Provide measured recall, panel-bits, guard-FAR, and provenance for every requested quantization candidate.";
const LEGACY_CBM_EDGE_ROWS_REMEDIATION: &str = "Re-import the project from its Codebase Memory MCP SQLite dump so the vault persists complete astrolabe:cbm-edge:v1 raw edge rows before reading or lowering its graph snapshot.";
const MISSING_CBM_PROJECT_ROW_REMEDIATION: &str = "Re-import the project from its Codebase Memory MCP SQLite dump so the vault persists an astrolabe:cbm-project:v1 row, and confirm the requested project name matches an imported project before reading or lowering its graph snapshot.";
const EXACT_SOURCE_REMEDIATION: &str = "Preserve the vault, inspect the referenced cxinput:v1 Blob rows, and re-import the project from its exact CBM SQLite source before trusting graph source bytes.";
const SEMANTIC_COVERAGE_REMEDIATION: &str = "Preserve the prior Calyx generation, add or correct the exact versioned typed lens rule named by this refusal, rebuild the panel, and re-ingest the same CBM source.";
const NODE_MAP_PREFIX: &[u8] = b"astrolabe:node-map:v2:";
const LEGACY_NODE_MAP_PREFIX_V1: &[u8] = b"astrolabe:node-map:v1:";
const STRUCTURAL_NODE_PREFIX: &[u8] = b"astrolabe:structural-node:v1:";
const PROJECT_ROW_PREFIX: &[u8] = b"astrolabe:cbm-project:v1:";
const FILE_HASH_ROW_PREFIX: &[u8] = b"astrolabe:file-hash:v1:";
const PROJECT_SUMMARY_ROW_PREFIX: &[u8] = b"astrolabe:project-summary:v1:";
const TOKEN_VECTOR_ROW_PREFIX: &[u8] = b"astrolabe:token-vector:v1:";
const SEMANTIC_CONSTELLATION_ROW_PREFIX: &[u8] = b"astrolabe:semantic-constellation:v1:";
const SEMANTIC_COVERAGE_ROW_PREFIX: &[u8] = b"astrolabe:semantic-coverage:v1:";
const CBM_EDGE_ROW_PREFIX: &[u8] = b"astrolabe:cbm-edge:v1:";
pub(crate) const EDGE_ROW_PREFIX: &[u8] = b"astrolabe:edge:v1:";
/// Per-file digest manifest head and bounded identity chunks (#855).
const FILE_DIGEST_MANIFEST_V2_PREFIX: &[u8] = b"astrolabe:file-digest:v2:head:";
const FILE_DIGEST_CHUNK_V2_PREFIX: &[u8] = b"astrolabe:file-digest:v2:chunk:";
const SCHEMA_NODE_MAP: &str = "astrolabe-node-map-v4";
const LEGACY_SCHEMA_NODE_MAP_V3: &str = "astrolabe-node-map-v3";
const SCHEMA_SYMBOL_METADATA: &str = "astrolabe-sqlite-symbol-v3";
const SCHEMA_STRUCTURAL_NODE: &str = "astrolabe-structural-node-v3";
const LEGACY_SCHEMA_STRUCTURAL_NODE_V2: &str = "astrolabe-structural-node-v2";
const SCHEMA_EXACT_SOURCE_REF: &str = "astrolabe-exact-source-ref-v1";
const SCHEMA_PROJECT_ROW: &str = "astrolabe-cbm-project-v1";
pub const CBM_FILE_HASH_ROW_SCHEMA: &str = "astrolabe-file-hash-v1";
const SCHEMA_PROJECT_SUMMARY_ROW: &str = "astrolabe-project-summary-v1";
const SCHEMA_TOKEN_VECTOR_ROW: &str = "astrolabe-token-vector-v1";
const SCHEMA_SEMANTIC_CONSTELLATION_ROW: &str = "astrolabe.semantic-constellation.v1";
const SCHEMA_SEMANTIC_COVERAGE_ROW: &str = "astrolabe.semantic-coverage.v1";
const SEMANTIC_CANONICAL_TAG: &str = "astrolabe.cbm.semantic-constellation.v1";
/// Domain separator for panel-v4 node identity's complete semantic-input binding.
const NODE_SEMANTIC_IDENTITY_TAG: &str = "astrolabe.cbm.node-semantic-identity.v1";

fn semantic_coverage_refusal(
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> IngestError {
    IngestError::refused(ASTRO_SEMANTIC_COVERAGE_GAP, message, remediation)
}
const SCHEMA_CBM_EDGE_ROW: &str = "astrolabe-cbm-edge-v3";
pub(crate) const SCHEMA_EDGE_ROW: &str = "astrolabe-edge-v2";
const SCHEMA_FILE_DIGEST_ROW: &str = "astrolabe-file-digest-v1";
const SCHEMA_FILE_DIGEST_MANIFEST_V2: &str = "astrolabe-file-digest-manifest-v2";
const SCHEMA_FILE_DIGEST_CHUNK_V2: &str = "astrolabe-file-digest-chunk-v2";
/// 10,000 fixed-size identity triples serialize well below the 4 MiB verified
/// chunk ceiling. The exact serialized-byte assertion below is authoritative.
const FILE_DIGEST_CHUNK_SYMBOL_CAP: usize = 10_000;
const FILE_DIGEST_CHUNK_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Domain separator for the per-file content digest (#345). Bumped only when the set of
/// raw fields folded into the digest changes, so an old-domain digest can never be
/// compared against a new-domain one (a mismatch then fails open into full reconcile).
// v2 (#372): the digest additionally folds every raw edge whose SOURCE node lives in the
// file, so a matching digest proves the file's outgoing edges are byte-identical too —
// the soundness condition for carrying persisted edge rows forward without re-encoding.
// (An edge's properties, e.g. resolution strategy/candidates, can change when a THIRD file
// changes; folding edges into the source file's digest makes such a change invalidate the
// digest instead of being wrongly preserved.) v1 manifests mismatch and fail open into one
// labeled full reconcile. v3 folds the stable atom and byte-exact source
// contract, so an exact body/span change can never reuse a v2 identity. v4
// folds the complete local-name + preprocessing-context edge identity. v5
// additionally binds the independently measured generated URL-path column. v6
// binds the complete measured node semantic input into the node CxId.
const FILE_DIGEST_DOMAIN: &str = "astrolabe-file-digest-v6";
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
pub const CBM_SQLITE_SCHEMA_VERSION: i64 = 5;

/// Frozen semantic source-column contract for the seven CBM product tables.
/// `(name, declared_type, hidden)` is compared in exact `cid` order against
/// `pragma_table_xinfo`; an added, removed, reordered, retyped, or differently
/// generated column is schema drift and refuses before any source row is read.
const CBM_SEMANTIC_SOURCE_TABLES: &[(&str, &[(&str, &str, i64)])] = &[
    (
        "projects",
        &[
            ("name", "TEXT", 0),
            ("indexed_at", "TEXT", 0),
            ("root_path", "TEXT", 0),
        ],
    ),
    (
        "file_hashes",
        &[
            ("project", "TEXT", 0),
            ("rel_path", "TEXT", 0),
            ("sha256", "TEXT", 0),
            ("mtime_ns", "INTEGER", 0),
            ("size", "INTEGER", 0),
        ],
    ),
    (
        "nodes",
        &[
            ("id", "INTEGER", 0),
            ("project", "TEXT", 0),
            ("label", "TEXT", 0),
            ("name", "TEXT", 0),
            ("qualified_name", "TEXT", 0),
            ("file_path", "TEXT", 0),
            ("start_line", "INTEGER", 0),
            ("end_line", "INTEGER", 0),
            ("properties", "TEXT", 0),
            ("atom_id", "TEXT", 0),
            ("source_present", "INTEGER", 0),
            ("source_bytes", "BLOB", 0),
            ("source_sha256", "TEXT", 0),
            ("start_byte", "INTEGER", 0),
            ("end_byte", "INTEGER", 0),
        ],
    ),
    (
        "edges",
        &[
            ("id", "INTEGER", 0),
            ("project", "TEXT", 0),
            ("source_id", "INTEGER", 0),
            ("target_id", "INTEGER", 0),
            ("type", "TEXT", 0),
            ("properties", "TEXT", 0),
            ("url_path_gen", "TEXT", 2),
            ("local_name_gen", "TEXT", 2),
            ("preprocess_context_id_gen", "TEXT", 2),
        ],
    ),
    (
        "project_summaries",
        &[
            ("project", "TEXT", 0),
            ("summary", "TEXT", 0),
            ("source_hash", "TEXT", 0),
            ("created_at", "TEXT", 0),
            ("updated_at", "TEXT", 0),
        ],
    ),
    (
        "node_vectors",
        &[
            ("node_id", "INTEGER", 0),
            ("project", "TEXT", 0),
            ("vector", "BLOB", 0),
        ],
    ),
    (
        "token_vectors",
        &[
            ("id", "INTEGER", 0),
            ("project", "TEXT", 0),
            ("token", "TEXT", 0),
            ("vector", "BLOB", 0),
            ("idf", "INTEGER", 0),
        ],
    ),
];

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
    /// Content-addressed Blob rows structurally decoded inside the same physical
    /// stream that verified their commit digests.
    pub blob_rows_verified: usize,
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
    /// Blob rows named by the exact atomic commit receipt.
    pub expected_blob_rows: usize,
    /// Persisted rows delivered by Calyx's ordered readback stream.
    pub physical_rows_read_back: u64,
    /// Persisted value bytes observed by that stream.
    pub physical_bytes_read_back: u64,
    /// Column-family batches traversed under the one pinned snapshot.
    pub physical_read_batches: u64,
    /// Row-table, memtable, and SST sources consulted.
    pub physical_source_read_operations: u64,
    /// Immutable SST generations opened by the ordered plan.
    pub physical_sst_files_opened: u64,
    /// Maximum bytes allocated for the digest plan plus its borrowed ordering index.
    pub maximum_plan_bytes: u64,
    /// Maximum persisted value bytes retained at once by readback.
    pub maximum_readback_batch_bytes: u64,
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
    /// CBM node rows measured into constellations, including structural labels.
    pub constellation_inputs: usize,
    /// Non-node semantic source rows measured into typed constellations.
    pub semantic_constellation_inputs: usize,
    /// Structural-only nodes written as graph metadata rows, with no panel measurement.
    pub structural_only: usize,
    /// Imported `CxId`s that had no Base CF row before this run.
    pub new_cx_ids: usize,
    /// Imported `CxId`s already present in Base CF before this run.
    pub reused_cx_ids: usize,
    /// Non-node semantic constellations newly persisted in this generation.
    pub new_semantic_cx_ids: usize,
    /// Non-node semantic constellations reused from byte-identical source rows.
    pub reused_semantic_cx_ids: usize,
    /// Present semantic atoms proven classified by the coverage witness.
    pub semantic_present_atoms: u64,
    /// Present semantic atoms without a frozen typed lens. Always zero on success.
    pub semantic_uncovered_atoms: u64,
    /// SHA-256 of the exact persisted semantic coverage witness JSON.
    pub semantic_coverage_witness_sha256: [u8; 32],
    /// Graph CF rows whose bytes changed in this run.
    pub graph_rows_written: usize,
    /// Typed edge Graph CF rows whose bytes changed in this run.
    pub edge_rows_written: usize,
    /// Symbol versions presented to the durable series registry.
    pub series_inputs: usize,
    /// Registry/reverse/QN/recurrence rows changed by this run.
    pub series_mutated_rows: usize,
    /// Latest vault sequence after this import. Unchanged on a physical no-op.
    pub seq: Seq,
    /// Ledger sequence of this import's paired `EntryKind::Ingest` mutation.
    ///
    /// `None` means the authoritative write-set was empty and no vault or ledger
    /// mutation was committed. A no-op never invents an audit event.
    #[serde(default)]
    pub ledger_seq: Option<u64>,
    /// Ledger rows visible before this import began.
    pub ledger_rows_before: usize,
    /// Ledger rows visible after the import. Equal to
    /// [`Self::ledger_rows_before`] on an isolated physical no-op.
    pub ledger_rows_after: usize,
    /// Exact skipped-edge counters.
    pub edge_skips: EdgeSkipCounters,
    /// Measured quantization gate decision and raw guard-slot readback counts.
    pub quantization: SqliteImportQuantizationReport,
    /// Post-write CF readback verification counts.
    pub readback: SqliteImportReadback,
    /// Unforgeable full-readback witness when this import changed vault rows.
    /// An idempotent physical no-op carries labeled absence (`None`).
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

/// One historical admission prepared against a stable batch snapshot.
///
/// Preparation performs all parsing, panel measurement, CxId reuse checks, and
/// row encoding without mutating the vault. A non-empty result owns exactly one
/// `Ingest` group that may be interleaved with prepared Grounding groups inside
/// a larger ordered atomic commit.
pub struct PreparedHistoricalSymbolAdmission {
    locations: Vec<HistoricalSymbolLocation>,
    constellation_inputs: usize,
    constellations_written: usize,
    rows_written: usize,
    constellations_reused: usize,
    snapshot: Seq,
    group: Option<LedgerBoundWriteGroup>,
    expected_entry: Option<LedgerEntryInput>,
}

impl PreparedHistoricalSymbolAdmission {
    /// Exact snapshot against which this admission was prepared.
    pub const fn snapshot(&self) -> Seq {
        self.snapshot
    }

    /// Deterministically sorted historical symbol locations.
    pub fn locations(&self) -> &[HistoricalSymbolLocation] {
        &self.locations
    }

    /// Whether this admission owns a logical `Ingest` group.
    pub const fn has_write_group(&self) -> bool {
        self.group.is_some()
    }

    /// Moves the prepared `Ingest` group into an ordered commit window.
    pub fn take_write_group(&mut self) -> Option<LedgerBoundWriteGroup> {
        self.group.take()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct StagedHistoricalCx {
    canonical_hash: [u8; 32],
    semantic_hash: [u8; 32],
}

/// Mutable deduplication state for one bounded historical group-commit window.
///
/// The window is project-local and snapshot-bound. It prevents two prepared
/// groups from writing the same content-addressed Base/slot or retained-input
/// key while preserving each group's logical provenance entry and counts.
#[derive(Debug)]
pub struct HistoricalSymbolAdmissionBatch {
    snapshot: Seq,
    staged_cx: BTreeMap<CxId, StagedHistoricalCx>,
    staged_input_hashes: BTreeSet<[u8; 32]>,
}

impl HistoricalSymbolAdmissionBatch {
    /// Snapshot shared by every prepared group in this window.
    pub const fn snapshot(&self) -> Seq {
        self.snapshot
    }
}

/// Reusable invariant and measurement context for one ordered historical-admission pass.
///
/// A Git archaeology pass can admit hundreds of commit snapshots into the same live
/// vault. The legacy-layout scan, frozen panel validation, and retention lookup are
/// properties of that pass, not of each snapshot. Opening this session validates those
/// invariants once; [`Self::admit`] still validates every snapshot/options pair and
/// re-reads the manifest retention policy before mutation, so a changed vault contract
/// fails closed instead of silently reusing stale configuration.
#[derive(Debug)]
pub struct HistoricalSymbolAdmissionSession {
    panel_version: u32,
    driver: PanelDriver,
    retention: InputRetention,
}

impl HistoricalSymbolAdmissionSession {
    /// Opens one historical-admission pass against the current vault contract.
    pub fn open<C>(vault: &AsterVault<C>, panel_version: u32) -> IngestResult<Self>
    where
        C: Clock,
    {
        ensure_no_legacy_series_state(vault)?;
        Ok(Self {
            panel_version,
            driver: PanelDriver::new(panel_version)?,
            retention: vault.input_retention()?,
        })
    }

    /// Admits one snapshot while reusing the pass-owned panel driver and validated
    /// legacy-state decision.
    pub fn admit<C, R>(
        &self,
        snapshot: &CbmGraphSnapshot,
        vault: &AsterVault<C>,
        runtime: &R,
        options: &SqliteImportOptions,
    ) -> IngestResult<HistoricalSymbolAdmissionReport>
    where
        C: Clock,
        R: SlotRuntime + Sync,
    {
        if options.panel_version != self.panel_version {
            return Err(invalid_sqlite(format!(
                "historical admission session panel version {} does not match snapshot option {}",
                self.panel_version, options.panel_version
            )));
        }
        let current_retention = vault.input_retention()?;
        if current_retention != self.retention {
            return Err(invalid_sqlite(format!(
                "historical admission session retention changed from {} to {}; reopen the pass against the current manifest",
                self.retention.as_str(),
                current_retention.as_str()
            )));
        }
        let mut batch = self.begin_batch(vault)?;
        let mut prepared = self.prepare(snapshot, vault, runtime, options, &mut batch)?;
        let Some(group) = prepared.take_write_group() else {
            return prepared.complete(vault, batch.snapshot(), None, None);
        };
        let commit = vault.write_ledger_bound_groups_if_seq(batch.snapshot(), vec![group])?;
        let mut receipts = commit.groups;
        let receipt = receipts.pop().ok_or_else(|| {
            readback_mismatch("historical group commit returned no logical receipt")
        })?;
        if !receipts.is_empty() {
            return Err(readback_mismatch(format!(
                "historical single-group commit returned {} extra logical receipts",
                receipts.len()
            )));
        }
        vault.flush()?;
        let wanted = BTreeSet::from([receipt.ledger_ref.seq]);
        let (rows, _) = vault.read_physical_ledger_seqs(&wanted)?;
        prepared.complete(vault, commit.seq, Some(receipt), Some(&rows))
    }

    /// Starts one stable, bounded historical admission window.
    pub fn begin_batch<C>(
        &self,
        vault: &AsterVault<C>,
    ) -> IngestResult<HistoricalSymbolAdmissionBatch>
    where
        C: Clock,
    {
        let current_retention = vault.input_retention()?;
        if current_retention != self.retention {
            return Err(invalid_sqlite(format!(
                "historical admission session retention changed from {} to {}; reopen the pass against the current manifest",
                self.retention.as_str(),
                current_retention.as_str()
            )));
        }
        Ok(HistoricalSymbolAdmissionBatch {
            snapshot: vault.latest_seq(),
            staged_cx: BTreeMap::new(),
            staged_input_hashes: BTreeSet::new(),
        })
    }

    /// Prepares one snapshot into a caller-owned ordered commit window without
    /// writing, flushing, or independently reopening any persistent file.
    pub fn prepare<C, R>(
        &self,
        snapshot: &CbmGraphSnapshot,
        vault: &AsterVault<C>,
        runtime: &R,
        options: &SqliteImportOptions,
        batch: &mut HistoricalSymbolAdmissionBatch,
    ) -> IngestResult<PreparedHistoricalSymbolAdmission>
    where
        C: Clock,
        R: SlotRuntime + Sync,
    {
        if options.panel_version != self.panel_version {
            return Err(invalid_sqlite(format!(
                "historical admission session panel version {} does not match snapshot option {}",
                self.panel_version, options.panel_version
            )));
        }
        let current_retention = vault.input_retention()?;
        if current_retention != self.retention {
            return Err(invalid_sqlite(format!(
                "historical admission session retention changed from {} to {}; reopen the pass against the current manifest",
                self.retention.as_str(),
                current_retention.as_str()
            )));
        }
        let current = vault.latest_seq();
        if current != batch.snapshot {
            return Err(readback_mismatch(format!(
                "historical admission window snapshot {} drifted to {current} before commit; discard and rebuild the complete window",
                batch.snapshot
            )));
        }
        prepare_historical_symbol_snapshot_with_session(
            snapshot, vault, runtime, options, self, batch,
        )
    }
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
    /// Non-node semantic Graph rows bound to their exact Base constellation.
    pub semantic_constellation_rows: usize,
    /// Current per-project semantic coverage witnesses recomputed from Base state.
    pub semantic_coverage_witness_rows: usize,
    /// Concrete semantic Slot CF rows whose bytes, Base hash, shape, and norm agree.
    pub semantic_slot_rows: usize,
    /// Present semantic atoms recomputed from persisted Base slot rosters.
    pub semantic_coverage_present: u64,
    /// Present deterministic-encoder atoms recomputed from persisted state.
    pub semantic_coverage_encoded: u64,
    /// Present learned-embedder atoms recomputed from persisted state.
    pub semantic_coverage_embedded: u64,
    /// Present frozen imported-vector atoms recomputed from persisted state.
    pub semantic_coverage_imported_vectors: u64,
    /// Persisted semantic atoms with no frozen classification. Always zero on success.
    pub semantic_coverage_uncovered: u64,
}

#[derive(Debug, Clone)]
struct VerifiedSemanticBase {
    constellation: Constellation,
    slot_hashes: BTreeMap<SlotId, [u8; 32]>,
}

type ExpectedSemanticSlots = BTreeMap<SlotId, BTreeMap<CxId, [u8; 32]>>;

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
    atom_id: String,
    qualified_name: String,
    file_path: String,
    start_line: i64,
    end_line: i64,
    source_present: bool,
    source_bytes: Vec<u8>,
    source_sha256: String,
    start_byte: u64,
    end_byte: u64,
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
    url_path_gen: String,
    local_name_gen: String,
    preprocess_context_id_gen: String,
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
    semantic_source_schema_sha256: [u8; 32],
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

/// v2 head for one source file's digest/identity manifest. The identities live
/// in ordered chunk rows so one pathological generated source file can never
/// manufacture an over-memtable Graph value.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct FileDigestManifestV2 {
    schema: String,
    project: String,
    file_path: String,
    panel_version: u32,
    domain: String,
    digest: String,
    symbol_count: usize,
    chunk_count: usize,
    symbols_sha256: String,
}

/// One ordered bounded piece of a v2 file digest identity manifest.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct FileDigestChunkV2 {
    schema: String,
    project: String,
    file_path: String,
    chunk_index: usize,
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
    atom_id: String,
    label: SymbolLabel,
    name: String,
    source_sha256: String,
    start_byte: u64,
    end_byte: u64,
    symbol: SymbolRecord,
    node_vector_sha256: Option<[u8; 32]>,
    node_vector_bytes: Option<usize>,
    properties_json: String,
    node_vector: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct PreparedConstellation {
    node_id: i64,
    atom_id: String,
    name: String,
    properties_json: String,
    node_vector: Option<Vec<u8>>,
    symbol: SymbolRecord,
    identity: SymbolIdentity,
    constellation: Constellation,
    semantic_value_slots: Vec<SlotId>,
}

#[derive(Debug, Clone)]
struct PreparedLiveSymbol {
    node_id: i64,
    atom_id: String,
    name: String,
    properties_json: String,
    node_vector: Option<Vec<u8>>,
    symbol: SymbolRecord,
    identity: SymbolIdentity,
    semantic_value_slots: Vec<SlotId>,
    /// Present only when this content-addressed identity was not already in Base.
    /// Reused live symbols retain their graph identity without re-running 22 lenses.
    measured: Option<Constellation>,
}

#[derive(Debug, Clone)]
struct PreparedSemanticConstellation {
    family: SemanticFamily,
    source_key: String,
    links: Vec<CxId>,
    canonical_input_bytes: Vec<u8>,
    input_hash: [u8; 32],
    cx_id: CxId,
    slot_ids: Vec<SlotId>,
    measured: Option<Constellation>,
}

#[derive(Debug, Clone)]
struct SemanticInputRow {
    family: SemanticFamily,
    source_key: String,
    links: Vec<CxId>,
    values: BTreeMap<SlotId, SemanticValue>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct SemanticConstellationGraphRow {
    schema: String,
    project: String,
    family: String,
    source_key: String,
    panel_version: u32,
    cx_id: CxId,
    input_hash_blake3: String,
    registry_sha256: String,
    sqlite_fingerprint_sha256: String,
    slot_ids: Vec<u16>,
    links: Vec<CxId>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct SemanticCoverageRuleCount {
    family: String,
    path: String,
    source_type: String,
    kind: String,
    slot_id: u16,
    present: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct SemanticCoverageFamilyCount {
    family: String,
    constellations: u64,
    present: u64,
    encoded: u64,
    embedded: u64,
    imported_vector: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct SemanticCoverageWitness {
    schema: String,
    project: String,
    panel_version: u32,
    registry_sha256: String,
    source_schema_sha256: String,
    sqlite_fingerprint_sha256: String,
    slot_manifest_sha256: String,
    constellations: u64,
    present: u64,
    encoded: u64,
    embedded: u64,
    imported_vector: u64,
    uncovered: u64,
    families: Vec<SemanticCoverageFamilyCount>,
    rules: Vec<SemanticCoverageRuleCount>,
}

/// Encodes the coverage witness with one explicit recursive object-key order.
///
/// Coverage bytes are stored in Graph CF and independently reconstructed from
/// the typed witness embedded in the ingest Ledger payload.  Graph preparation
/// also passes every row through [`append_import_fingerprint`], which parses and
/// re-encodes JSON.  A direct struct serialization therefore cannot be the byte
/// contract: struct field order and JSON object-key order are different.  Keep
/// both durable views and every verifier on this single canonical encoding.
fn semantic_coverage_canonical_bytes(witness: &SemanticCoverageWitness) -> IngestResult<Vec<u8>> {
    fn sort_objects(value: Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.into_iter().map(sort_objects).collect()),
            Value::Object(object) => {
                let mut entries = object.into_iter().collect::<Vec<_>>();
                entries.sort_by(|left, right| left.0.cmp(&right.0));
                let mut sorted = serde_json::Map::new();
                for (key, value) in entries {
                    sorted.insert(key, sort_objects(value));
                }
                Value::Object(sorted)
            }
            scalar => scalar,
        }
    }

    let value = serde_json::to_value(witness)?;
    Ok(serde_json::to_vec(&sort_objects(value))?)
}

#[derive(Debug, Default)]
struct SemanticCoverageAccumulator {
    family_constellations: BTreeMap<SemanticFamily, u64>,
    rule_present: BTreeMap<u16, u64>,
}

impl SemanticCoverageAccumulator {
    fn observe_slots(&mut self, family: SemanticFamily, slots: &[SlotId]) -> IngestResult<()> {
        *self.family_constellations.entry(family).or_default() += 1;
        for slot_id in slots {
            let rule = semantic_rule_by_slot(*slot_id).ok_or_else(|| {
                semantic_coverage_refusal(
                    format!("coverage observed unregistered slot {slot_id}"),
                    "Repair the frozen registry before publication and re-ingest the preserved source.",
                )
            })?;
            if rule.family != family {
                return Err(semantic_coverage_refusal(
                    format!(
                        "coverage observation for {} contains {} slot {slot_id}",
                        family.as_str(),
                        rule.family.as_str()
                    ),
                    "Repair typed row construction before publication and re-ingest the preserved source.",
                ));
            }
            *self.rule_present.entry(rule.value_slot).or_default() += 1;
        }
        Ok(())
    }

    fn observe(
        &mut self,
        family: SemanticFamily,
        values: &BTreeMap<SlotId, SemanticValue>,
    ) -> IngestResult<()> {
        self.observe_slots(family, &values.keys().copied().collect::<Vec<_>>())?;
        for (slot_id, value) in values {
            let rule = semantic_rule_by_slot(*slot_id).ok_or_else(|| {
                semantic_coverage_refusal(
                    format!("coverage observed unregistered slot {slot_id}"),
                    "Repair the frozen registry before publication and re-ingest the preserved source.",
                )
            })?;
            if rule.family != family || rule.source_type != value.source_type() {
                return Err(semantic_coverage_refusal(
                    format!(
                        "coverage observation for {} slot {slot_id} disagrees with the registry",
                        family.as_str()
                    ),
                    "Repair typed row construction before publication and re-ingest the preserved source.",
                ));
            }
        }
        Ok(())
    }

    fn finish(
        self,
        project: &str,
        panel_version: u32,
        semantic_source_schema_sha256: [u8; 32],
        sqlite_fingerprint: [u8; 32],
    ) -> IngestResult<SemanticCoverageWitness> {
        let mut rules = Vec::with_capacity(SEMANTIC_RULES.len());
        let mut families = Vec::new();
        let mut total_present = 0_u64;
        let mut total_encoded = 0_u64;
        let mut total_embedded = 0_u64;
        let mut total_imported = 0_u64;
        for family in SemanticFamily::ALL {
            let mut present = 0_u64;
            let mut encoded = 0_u64;
            let mut embedded = 0_u64;
            let mut imported_vector = 0_u64;
            for rule in SEMANTIC_RULES.iter().filter(|rule| rule.family == family) {
                let count = self
                    .rule_present
                    .get(&rule.value_slot)
                    .copied()
                    .unwrap_or(0);
                present += count;
                match rule.kind {
                    SemanticKind::LatentCode | SemanticKind::LatentProse => embedded += count,
                    SemanticKind::ImportedVector => imported_vector += count,
                    _ => encoded += count,
                }
                rules.push(SemanticCoverageRuleCount {
                    family: family.as_str().to_string(),
                    path: rule.path.to_string(),
                    source_type: rule.source_type.as_str().to_string(),
                    kind: rule.kind.as_str().to_string(),
                    slot_id: rule.value_slot,
                    present: count,
                });
            }
            total_present += present;
            total_encoded += encoded;
            total_embedded += embedded;
            total_imported += imported_vector;
            families.push(SemanticCoverageFamilyCount {
                family: family.as_str().to_string(),
                constellations: self
                    .family_constellations
                    .get(&family)
                    .copied()
                    .unwrap_or(0),
                present,
                encoded,
                embedded,
                imported_vector,
            });
        }
        let classified = total_encoded + total_embedded + total_imported;
        let uncovered = total_present.checked_sub(classified).ok_or_else(|| {
            semantic_coverage_refusal(
                "classified semantic atoms exceed present atoms",
                "Repair coverage accounting before publication and re-ingest the preserved source.",
            )
        })?;
        if uncovered != 0 || classified != total_present {
            return Err(semantic_coverage_refusal(
                format!(
                    "present={total_present} encoded={total_encoded} embedded={total_embedded} imported_vector={total_imported} uncovered={uncovered}"
                ),
                "Add frozen lens rules until uncovered is exactly zero, rebuild the panel, and re-ingest the preserved source.",
            ));
        }
        let slot_manifest_sha256 = panel_slot_manifest_sha256(panel_version)?;
        Ok(SemanticCoverageWitness {
            schema: SCHEMA_SEMANTIC_COVERAGE_ROW.to_string(),
            project: project.to_string(),
            panel_version,
            registry_sha256: hex_lower(&semantic_registry_sha256()),
            source_schema_sha256: hex_lower(&semantic_source_schema_sha256),
            sqlite_fingerprint_sha256: hex_lower(&sqlite_fingerprint),
            slot_manifest_sha256: hex_lower(&slot_manifest_sha256),
            constellations: self.family_constellations.values().sum(),
            present: total_present,
            encoded: total_encoded,
            embedded: total_embedded,
            imported_vector: total_imported,
            uncovered,
            families,
            rules,
        })
    }
}

#[derive(Debug, Clone)]
struct PreparedBatch {
    constellations: Vec<PreparedLiveSymbol>,
    semantic_constellations: Vec<PreparedSemanticConstellation>,
    semantic_coverage: SemanticCoverageWitness,
    graph_rows: Vec<(Vec<u8>, Vec<u8>)>,
    edge_rows: Vec<PreparedEdgeRow>,
    structural_only: usize,
    sqlite_edges: usize,
    edge_skips: EdgeSkipCounters,
    /// Exact source payloads referenced by v4/v3 node rows. Non-structural
    /// payloads remain owned by their prepared constellation and are addressed
    /// by index; structural payloads move here when their temporary node is
    /// consumed. The map therefore adds no full-corpus source clone.
    exact_sources: BTreeMap<[u8; 32], PreparedExactSource>,
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
enum PreparedExactSource {
    Constellation(usize),
    Structural(Vec<u8>),
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
    atom_id: String,
    qualified_name: String,
    label: String,
    cx_id: CxId,
    series_id: SeriesId,
    file_path: String,
    commit: String,
    name: String,
    start_line: i64,
    end_line: i64,
    source_present: bool,
    /// Legacy v3 inline payload. New v4 rows always omit it and use
    /// `source_ref`; retaining this decode field makes historical state explicit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    source_bytes: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_ref: Option<ExactSourceRef>,
    source_sha256: String,
    start_byte: u64,
    end_byte: u64,
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
    atom_id: String,
    qualified_name: String,
    label: String,
    name: String,
    file_path: String,
    commit: String,
    start_line: i64,
    end_line: i64,
    source_present: bool,
    /// Legacy v2 inline payload. New v3 rows always omit it and use
    /// `source_ref`; retaining this decode field makes historical state explicit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    source_bytes: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_ref: Option<ExactSourceRef>,
    source_sha256: String,
    start_byte: u64,
    end_byte: u64,
    #[serde(default)]
    properties_json: Option<String>,
    #[serde(default)]
    node_vector: Option<Vec<u8>>,
}

/// Small, self-describing pointer from a Graph row to the chunked Blob-CF
/// exact-source payload. The duplicated typed pointer and byte length are
/// independently checked against the addressing hash and graph span on read.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct ExactSourceRef {
    schema: String,
    input_hash_blake3: [u8; 32],
    pointer: String,
    byte_len: u64,
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
    #[serde(default)]
    pub(crate) preprocess_context_id_gen: String,
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
    pub url_path_gen: String,
    pub local_name_gen: String,
    #[serde(default)]
    pub preprocess_context_id_gen: String,
    pub commit: String,
    pub sqlite_fingerprint_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmGraphNode {
    pub source_node_id: i64,
    pub project: String,
    pub label: String,
    pub name: String,
    pub atom_id: String,
    pub qualified_name: String,
    pub file_path: String,
    pub start_line: i64,
    pub end_line: i64,
    pub source_present: bool,
    pub source_bytes: Vec<u8>,
    pub source_sha256: String,
    pub start_byte: u64,
    pub end_byte: u64,
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
    pub url_path_gen: String,
    pub local_name_gen: String,
    pub preprocess_context_id_gen: String,
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
    semantic_constellation_inputs: u64,
    structural_only: u64,
    new_cx_ids: u64,
    reused_cx_ids: u64,
    new_semantic_cx_ids: u64,
    reused_semantic_cx_ids: u64,
    semantic_coverage: SemanticCoverageWitness,
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
    new_semantic_cx_ids: usize,
    reused_semantic_cx_ids: usize,
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
    let semantic_source_schema_sha256 = semantic_sqlite_source_schema_sha256(&connection)?;
    let raw_metadata = read_metadata_rows(&connection, options)?;
    let raw_nodes = read_nodes(&connection, &options.project)?;
    let raw_edges = read_edges(&connection, &options.project)?;
    let semantic_child_rows = raw_metadata.file_hashes.len()
        + raw_metadata.project_summaries.len()
        + raw_metadata.token_vectors.len()
        + raw_nodes.len()
        + raw_edges.len();
    if raw_metadata.projects.is_empty() && semantic_child_rows != 0 {
        return Err(IngestError::refused(
            ASTRO_MISSING_CBM_PROJECT_ROW,
            format!(
                "SQLite source for project {:?} contains {semantic_child_rows} semantic child rows but no exact projects row",
                options.project
            ),
            "Rebuild the Codebase Memory SQLite from source so its exact projects row and every semantic child family are committed together; Astrolabe never synthesizes missing source state.",
        ));
    }
    import_raw_cbm_rows_to_vault(
        vault,
        runtime,
        options,
        RawCbmImportInput {
            metadata: raw_metadata,
            nodes: raw_nodes,
            edges: raw_edges,
            sqlite_fingerprint,
            semantic_source_schema_sha256,
            ledger_rows_before,
        },
    )
}

/// Open the CBM source SQLite read-only with the #76 SQLITE_BUSY retry window.
/// The exact current file extent is requested for memory-mapped reads so the
/// supervised row readback shares OS-backed database pages with other local MCP
/// processes instead of copying the same corpus into each process's page cache.
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
    connection
        .pragma_update(None, "temp_store", "MEMORY")
        .map_err(|error| {
            invalid_sqlite(format!("set SQLite temporary storage to memory: {error}"))
        })?;
    let sqlite_bytes = std::fs::metadata(&open_path)
        .map_err(|error| invalid_sqlite(format!("read SQLite input extent: {error}")))?
        .len();
    let requested_mmap = i64::try_from(sqlite_bytes)
        .map_err(|_| invalid_sqlite("SQLite input extent exceeds signed 64-bit mmap range"))?;
    if requested_mmap > 0 {
        connection
            .pragma_update(None, "mmap_size", requested_mmap)
            .map_err(|error| invalid_sqlite(format!("set SQLite mmap extent: {error}")))?;
        let observed_mmap = connection
            .pragma_query_value(None, "mmap_size", |row| row.get::<_, i64>(0))
            .map_err(|error| invalid_sqlite(format!("read back SQLite mmap extent: {error}")))?;
        if observed_mmap <= 0 || observed_mmap > requested_mmap {
            return Err(invalid_sqlite(format!(
                "SQLite mmap extent readback {observed_mmap} is not positive and bounded by the requested database extent {requested_mmap}"
            )));
        }
    }
    validate_cbm_source_schema(&connection)?;
    Ok(connection)
}

fn validate_cbm_source_schema(connection: &Connection) -> IngestResult<()> {
    let user_version: i64 = connection
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|error| invalid_sqlite(format!("read CBM SQLite user_version: {error}")))?;
    if user_version != CBM_SQLITE_SCHEMA_VERSION {
        return Err(invalid_sqlite(format!(
            "CBM_ATOM_SCHEMA_REBUILD_REQUIRED: SQLite user_version is {user_version}, expected {CBM_SQLITE_SCHEMA_VERSION}; rebuild the legacy identity store from source"
        )));
    }

    for (table, expected) in CBM_SEMANTIC_SOURCE_TABLES {
        let mut statement = connection
            .prepare("SELECT name, \"type\", hidden FROM pragma_table_xinfo(?1) ORDER BY cid")
            .map_err(|error| {
                invalid_sqlite(format!(
                    "inspect frozen semantic source table {table:?}: {error}"
                ))
            })?;
        let actual = statement
            .query_map(params![table], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|error| {
                invalid_sqlite(format!(
                    "query frozen semantic source table {table:?}: {error}"
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                invalid_sqlite(format!(
                    "read frozen semantic source table {table:?}: {error}"
                ))
            })?;
        let expected = expected
            .iter()
            .map(|(name, declared_type, hidden)| {
                ((*name).to_string(), (*declared_type).to_string(), *hidden)
            })
            .collect::<Vec<_>>();
        if actual != expected {
            return Err(invalid_sqlite(format!(
                "CBM_SEMANTIC_SCHEMA_DRIFT: table {table:?} columns differ from the frozen semantic contract; expected {expected:?}, observed {actual:?}; add typed lens rules and version the source contract in the same change before importing this schema"
            )));
        }
    }

    let mut indexes = connection
        .prepare("SELECT name FROM pragma_index_list('nodes') WHERE \"unique\"=1 ORDER BY name")
        .map_err(|error| invalid_sqlite(format!("inspect nodes identity indexes: {error}")))?;
    let names = indexes
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| invalid_sqlite(format!("query nodes identity indexes: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invalid_sqlite(format!("read nodes identity index: {error}")))?;
    let mut atom_unique = false;
    let mut collapsed_qn_unique = false;
    for name in names {
        let mut columns = connection
            .prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")
            .map_err(|error| invalid_sqlite(format!("inspect nodes index {name:?}: {error}")))?;
        let columns = columns
            .query_map([&name], |row| row.get::<_, String>(0))
            .map_err(|error| invalid_sqlite(format!("query nodes index {name:?}: {error}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| invalid_sqlite(format!("read nodes index {name:?}: {error}")))?;
        atom_unique |= columns.len() == 2 && columns[0] == "project" && columns[1] == "atom_id";
        collapsed_qn_unique |=
            columns.len() == 2 && columns[0] == "project" && columns[1] == "qualified_name";
    }
    if !atom_unique || collapsed_qn_unique {
        return Err(invalid_sqlite(
            "CBM_ATOM_SCHEMA_REBUILD_REQUIRED: nodes must enforce UNIQUE(project, atom_id) and qualified_name must be non-unique; rebuild from source",
        ));
    }
    let mut edge_indexes = connection
        .prepare("SELECT name FROM pragma_index_list('edges') WHERE \"unique\"=1 ORDER BY name")
        .map_err(|error| invalid_sqlite(format!("inspect edges identity indexes: {error}")))?;
    let edge_index_names = edge_indexes
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| invalid_sqlite(format!("query edges identity indexes: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invalid_sqlite(format!("read edges identity index: {error}")))?;
    let expected = [
        "source_id",
        "target_id",
        "type",
        "local_name_gen",
        "preprocess_context_id_gen",
    ];
    let mut exact_edge_unique = false;
    for name in edge_index_names {
        let mut columns = connection
            .prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")
            .map_err(|error| invalid_sqlite(format!("inspect edges index {name:?}: {error}")))?;
        let columns = columns
            .query_map([&name], |row| row.get::<_, String>(0))
            .map_err(|error| invalid_sqlite(format!("query edges index {name:?}: {error}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| invalid_sqlite(format!("read edges index {name:?}: {error}")))?;
        exact_edge_unique |= columns.iter().map(String::as_str).eq(expected);
    }
    if !exact_edge_unique {
        return Err(invalid_sqlite(
            "CBM_EDGE_SCHEMA_REBUILD_REQUIRED: edges must enforce UNIQUE(source_id, target_id, type, local_name_gen, preprocess_context_id_gen); rebuild from exact source",
        ));
    }
    Ok(())
}

fn semantic_sqlite_source_schema_sha256(connection: &Connection) -> IngestResult<[u8; 32]> {
    const SOURCE_SCHEMA_QUERY: &str = "SELECT type, name, tbl_name, COALESCE(sql, '') \
        FROM sqlite_schema \
        WHERE tbl_name IN ('projects', 'file_hashes', 'nodes', 'edges', \
                           'project_summaries', 'node_vectors', 'token_vectors') \
        ORDER BY type, name";
    let user_version: i64 = connection
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|error| invalid_sqlite(format!("read semantic source user_version: {error}")))?;
    let mut canonical = Vec::new();
    append_semantic_frame(
        &mut canonical,
        b"astrolabe.cbm.sqlite-semantic-source-schema.v2",
    );
    append_semantic_frame(&mut canonical, &user_version.to_be_bytes());
    let mut statement = connection
        .prepare(SOURCE_SCHEMA_QUERY)
        .map_err(|error| invalid_sqlite(format!("prepare semantic source schema read: {error}")))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| invalid_sqlite(format!("query semantic source schema: {error}")))?;
    let mut row_count = 0_u64;
    for row in rows {
        let (kind, name, table, sql) = row
            .map_err(|error| invalid_sqlite(format!("read semantic source schema row: {error}")))?;
        append_semantic_frame(&mut canonical, kind.as_bytes());
        append_semantic_frame(&mut canonical, name.as_bytes());
        append_semantic_frame(&mut canonical, table.as_bytes());
        append_semantic_frame(&mut canonical, sql.as_bytes());
        row_count += 1;
    }
    if row_count == 0 {
        return Err(invalid_sqlite(
            "semantic source schema contains none of the registered CBM source tables",
        ));
    }
    append_semantic_frame(&mut canonical, &row_count.to_be_bytes());
    Ok(sha256_digest(&canonical))
}

fn snapshot_semantic_source_schema_sha256() -> [u8; 32] {
    sha256_digest(
        b"astrolabe.cbm.direct-snapshot.semantic-source-schema.v2\0\
projects{name:text,indexed_at:text,root_path:text}\0\
file_hashes{project:text,rel_path:text,sha256:text,mtime_ns:i64,size:i64}\0\
nodes{id:i64,project:text,label:text,name:text,atom_id:text,qualified_name:text,file_path:text,start_line:i64,end_line:i64,source_present:bool,source_bytes:bytes,source_sha256:text,start_byte:u64,end_byte:u64,properties:json,node_vector:optional<i8x768>}\0\
edges{id:i64,project:text,source_id:i64,target_id:i64,type:text,properties:json,url_path_gen:text,local_name_gen:text,preprocess_context_id_gen:text}\0\
project_summaries{project:text,summary:text,source_hash:text,created_at:text,updated_at:text}\0\
node_vectors{node_id:i64,project:text,vector:i8x768}\0\
token_vectors{id:i64,project:text,token:text,vector:i8x768,idf:i64}",
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
    ensure_no_legacy_series_state(vault)?;
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
    let prior_manifest = read_file_digest_manifest(&existing_graph, &options.project)?;
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
        input.semantic_source_schema_sha256,
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
    let mut new_semantic_cx_ids = 0;
    let mut reused_semantic_cx_ids = 0;
    for prepared_cx in &prepared.semantic_constellations {
        if prepared_cx.measured.is_some() {
            new_semantic_cx_ids += 1;
        } else {
            reused_semantic_cx_ids += 1;
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
            new_semantic_cx_ids,
            reused_semantic_cx_ids,
            graph_rows_written: changes.graph_rows_written,
            edge_rows_written: changes.edge_rows_written,
        },
    )?;
    let (ledger_ref, fsv, readback, graph_rows_written, edge_rows_written, write_timing_ms) =
        write_import_rows(
            vault,
            &prepared,
            input.sqlite_fingerprint,
            payload,
            options.quantization_gate.as_ref(),
            &changes,
            &existing_graph,
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
    let semantic_coverage_witness_sha256 = sha256_digest(semantic_coverage_bytes(&prepared)?);

    Ok(SqliteImportReport {
        sqlite_fingerprint_sha256: input.sqlite_fingerprint,
        sqlite_nodes,
        sqlite_node_vectors,
        sqlite_edges: prepared.sqlite_edges,
        constellation_inputs: prepared.constellations.len(),
        semantic_constellation_inputs: prepared.semantic_constellations.len(),
        structural_only: prepared.structural_only,
        new_cx_ids,
        reused_cx_ids,
        new_semantic_cx_ids,
        reused_semantic_cx_ids,
        semantic_present_atoms: prepared.semantic_coverage.present,
        semantic_uncovered_atoms: prepared.semantic_coverage.uncovered,
        semantic_coverage_witness_sha256,
        graph_rows_written,
        edge_rows_written,
        series_inputs,
        series_mutated_rows,
        seq: vault.latest_seq(),
        ledger_seq: ledger_ref.as_ref().map(|reference| reference.seq),
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
    validate_complete_snapshot_project(snapshot)?;
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
    validate_complete_snapshot_project(snapshot)?;
    let convert_start = std::time::Instant::now();
    let raw_metadata = snapshot_metadata_rows(snapshot)?;
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
            semantic_source_schema_sha256: snapshot_semantic_source_schema_sha256(),
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
    let session = HistoricalSymbolAdmissionSession::open(vault, options.panel_version)?;
    session.admit(snapshot, vault, runtime, options)
}

fn prepare_historical_symbol_snapshot_with_session<C, R>(
    snapshot: &CbmGraphSnapshot,
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    session: &HistoricalSymbolAdmissionSession,
    batch: &mut HistoricalSymbolAdmissionBatch,
) -> IngestResult<PreparedHistoricalSymbolAdmission>
where
    C: Clock,
    R: SlotRuntime + Sync,
{
    validate_options(options)?;
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

    // #446: historical symbols retain their canonical input bytes under the
    // same vault-manifest knob as the live import path.
    let mut prepared = prepare_historical_constellations_parallel(
        vault,
        runtime,
        options,
        &session.driver,
        non_structural,
        session.retention,
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
    let snapshot_seq = batch.snapshot;
    let mut rows = Vec::new();
    let mut constellations_written = 0usize;
    let mut constellations_reused = 0usize;
    // #446: mirrors the live import path — input rows commit atomically with
    // their historical Base records under the vault's declared retention knob.
    let mut new_staged_input_hashes = BTreeSet::new();
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
    let mut new_staged_cx = BTreeMap::new();
    for symbol in &prepared {
        let cx_id = symbol.identity.cx_id;
        let key = base_key(cx_id);
        let canonical_hash = *blake3::hash(&symbol.identity.canonical_input_bytes).as_bytes();
        let semantic_hash = historical_constellation_semantic_hash(symbol)?;
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
        if let Some(prior) = new_staged_cx
            .get(&cx_id)
            .or_else(|| batch.staged_cx.get(&cx_id))
        {
            if prior.canonical_hash != canonical_hash || prior.semantic_hash != semantic_hash {
                return Err(invalid_sqlite(format!(
                    "historical CxId {cx_id} maps incompatible canonical or measured content in one commit window \
                     (canonical BLAKE3 {} vs {}, semantic BLAKE3 {} vs {}); refusing to clobber the first write",
                    hex_lower(&prior.canonical_hash),
                    hex_lower(&canonical_hash),
                    hex_lower(&prior.semantic_hash),
                    hex_lower(&semantic_hash),
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
        if session.retention == InputRetention::Persist
            && !batch
                .staged_input_hashes
                .contains(&symbol.constellation.input_ref.hash)
            && new_staged_input_hashes.insert(symbol.constellation.input_ref.hash)
        {
            for row in input_store::encode_input_rows(
                &symbol.constellation.input_ref.hash,
                &symbol.identity.canonical_input_bytes,
            )? {
                rows.push((row.cf, row.key, row.value));
            }
        }
        new_staged_cx.insert(
            cx_id,
            StagedHistoricalCx {
                canonical_hash,
                semantic_hash,
            },
        );
        constellations_written += 1;
    }
    let rows_written = rows.len();
    let constellation_inputs = prepared.len();
    if rows.is_empty() {
        return Ok(PreparedHistoricalSymbolAdmission {
            locations,
            constellation_inputs,
            constellations_written,
            rows_written,
            constellations_reused,
            snapshot: snapshot_seq,
            group: None,
            expected_entry: None,
        });
    }

    let location_digest = historical_location_digest(&locations);
    let payload = serde_json::to_vec(&HistoricalSymbolIngestLedgerPayload {
        schema: HISTORICAL_SYMBOL_INGEST_LEDGER_SCHEMA.to_string(),
        project_hash_sha256: hex_lower(&sha256_digest(options.project.as_bytes())),
        commit_hash_sha256: hex_lower(&sha256_digest(options.commit.as_bytes())),
        location_digest: hex_lower(blake3::hash(&location_digest).as_bytes()),
        constellation_inputs: constellation_inputs as u64,
        constellations_written: constellations_written as u64,
        rows_written: rows_written as u64,
        constellations_reused: constellations_reused as u64,
    })?;
    let subject = SubjectId::Query(blake3::hash(&location_digest).as_bytes().to_vec());
    let actor = ActorId::Service(ASTROLABE_INGEST_ACTOR.to_string());
    let entry = LedgerEntryInput::new(EntryKind::Ingest, subject.clone(), payload, actor.clone());
    batch.staged_cx.extend(new_staged_cx);
    batch.staged_input_hashes.extend(new_staged_input_hashes);

    Ok(PreparedHistoricalSymbolAdmission {
        locations,
        constellation_inputs,
        constellations_written,
        rows_written,
        constellations_reused,
        snapshot: snapshot_seq,
        group: Some(LedgerBoundWriteGroup::new(rows, entry.clone())),
        expected_entry: Some(entry),
    })
}

impl PreparedHistoricalSymbolAdmission {
    /// Finalizes this admission from its exact group receipt and a separately
    /// opened physical Ledger row map.
    pub fn complete<C>(
        self,
        vault: &AsterVault<C>,
        commit_seq: Seq,
        receipt: Option<LedgerBoundGroupReceipt>,
        ledger_rows: Option<&BTreeMap<u64, LedgerRow>>,
    ) -> IngestResult<HistoricalSymbolAdmissionReport>
    where
        C: Clock,
    {
        let (ledger_ref, fsv) = match (self.expected_entry, receipt, ledger_rows) {
            (None, None, None) => (None, None),
            (Some(expected), Some(receipt), Some(rows)) => {
                let physical = rows.get(&receipt.ledger_ref.seq).ok_or_else(|| {
                    readback_mismatch(format!(
                        "physical Ledger readback omitted historical Ingest seq {}",
                        receipt.ledger_ref.seq
                    ))
                })?;
                let entry = decode(&physical.bytes)?;
                if !entry.verify()
                    || entry.seq != receipt.ledger_ref.seq
                    || entry.entry_hash != receipt.ledger_ref.hash
                    || entry.kind != expected.kind
                    || entry.subject != expected.subject
                    || entry.payload != expected.payload
                    || entry.actor != expected.actor
                {
                    return Err(readback_mismatch(format!(
                        "historical Ingest seq {} failed exact hash/kind/subject/payload/actor physical readback",
                        receipt.ledger_ref.seq
                    )));
                }
                let mut plan = VaultMutationPlan::new(
                    "admit_historical_symbol_snapshot",
                    EntryKind::Ingest,
                    &expected.actor,
                    &expected.subject,
                );
                for row in &receipt.data_row_digests {
                    if row.tombstoned {
                        plan.push_tombstoned_hash(row.cf, row.key.clone(), row.value_blake3);
                    } else {
                        plan.push_content_hash(row.cf, row.key.clone(), row.value_blake3);
                    }
                }
                let ack = plan.verify_committed_with_ledger_bytes(
                    vault,
                    commit_seq,
                    &receipt.ledger_ref,
                    &physical.bytes,
                )?;
                (Some(receipt.ledger_ref), Some(ack))
            }
            _ => {
                return Err(readback_mismatch(
                    "historical admission completion received an incomplete or unexpected receipt/readback tuple",
                ));
            }
        };
        Ok(HistoricalSymbolAdmissionReport {
            locations: self.locations,
            constellation_inputs: self.constellation_inputs,
            constellations_written: self.constellations_written,
            rows_written: self.rows_written,
            constellations_reused: self.constellations_reused,
            seq: commit_seq,
            ledger_ref,
            fsv,
        })
    }
}

fn historical_constellation_semantic_hash(
    prepared: &PreparedConstellation,
) -> IngestResult<[u8; 32]> {
    let constellation = &prepared.constellation;
    let mut bytes = Vec::new();
    let vault_id = constellation.vault_id.to_string();
    for field in [
        constellation.cx_id.as_bytes().as_slice(),
        vault_id.as_bytes(),
        constellation.input_ref.hash.as_slice(),
        prepared.identity.canonical_input_bytes.as_slice(),
    ] {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes.extend_from_slice(&constellation.panel_version.to_be_bytes());
    bytes.push(u8::from(constellation.input_ref.redacted));
    let modality = serde_json::to_vec(&constellation.modality)?;
    bytes.extend_from_slice(&(modality.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&modality);
    for (name, value) in &constellation.scalars {
        bytes.extend_from_slice(&(name.len() as u64).to_be_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&value.to_bits().to_be_bytes());
    }
    for (slot, vector) in &constellation.slots {
        bytes.extend_from_slice(&slot.0.to_be_bytes());
        let encoded = encode::encode_slot_vector(vector)?;
        bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    for key in [
        "astrolabe_schema",
        "qualified_name",
        "label",
        "symbol_canonical_schema",
        "series_id_schema",
        "series_id",
        "input_hash_blake3",
    ] {
        let value = constellation.metadata.get(key).ok_or_else(|| {
            invalid_sqlite(format!(
                "prepared historical constellation {} omitted semantic metadata {key}",
                prepared.identity.cx_id
            ))
        })?;
        bytes.extend_from_slice(&(key.len() as u64).to_be_bytes());
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    Ok(*blake3::hash(&bytes).as_bytes())
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
    let mut differences = Vec::new();
    if decoded.cx_id != prepared.identity.cx_id {
        differences.push(format!(
            "cx_id persisted={} prepared={}",
            decoded.cx_id, prepared.identity.cx_id
        ));
    }
    if decoded.vault_id != prepared.constellation.vault_id {
        differences.push(format!(
            "vault_id persisted={:?} prepared={:?}",
            decoded.vault_id, prepared.constellation.vault_id
        ));
    }
    if decoded.panel_version != prepared.constellation.panel_version {
        differences.push(format!(
            "panel_version persisted={} prepared={}",
            decoded.panel_version, prepared.constellation.panel_version
        ));
    }
    if decoded.input_ref.hash != prepared.constellation.input_ref.hash {
        differences.push(format!(
            "input_hash persisted={} prepared={}",
            hex_lower(&decoded.input_ref.hash),
            hex_lower(&prepared.constellation.input_ref.hash)
        ));
    }
    if decoded.input_ref.redacted != prepared.constellation.input_ref.redacted {
        differences.push(format!(
            "input_redacted persisted={} prepared={}",
            decoded.input_ref.redacted, prepared.constellation.input_ref.redacted
        ));
    }
    if decoded.modality != prepared.constellation.modality {
        differences.push(format!(
            "modality persisted={:?} prepared={:?}",
            decoded.modality, prepared.constellation.modality
        ));
    }
    if decoded.scalars != prepared.constellation.scalars {
        for key in decoded
            .scalars
            .keys()
            .chain(prepared.constellation.scalars.keys())
            .collect::<BTreeSet<_>>()
        {
            let persisted = decoded.scalars.get(key);
            let prepared = prepared.constellation.scalars.get(key);
            if persisted != prepared {
                differences.push(format!(
                    "scalar.{key} persisted={persisted:?} prepared={prepared:?}"
                ));
            }
        }
    }
    if !differences.is_empty() {
        return Err(readback_mismatch(format!(
            "preexisting historical Base CF fields differ for {}: {}",
            prepared.identity.cx_id,
            differences.join("; ")
        )));
    }
    for key in [
        "astrolabe_schema",
        "qualified_name",
        "label",
        "symbol_canonical_schema",
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

fn validate_complete_snapshot_project(snapshot: &CbmGraphSnapshot) -> IngestResult<()> {
    let child_rows = snapshot.nodes.len()
        + snapshot.edges.len()
        + snapshot.file_hashes.len()
        + snapshot.project_summaries.len()
        + snapshot.token_vectors.len();
    if snapshot.projects.is_empty() && child_rows != 0 {
        return Err(IngestError::refused(
            ASTRO_MISSING_CBM_PROJECT_ROW,
            format!(
                "row-sink snapshot for project {:?} contains {child_rows} semantic child rows but no exact project row",
                snapshot.project
            ),
            "Make the CBM producer carry its exact projects row in the same complete snapshot; Astrolabe never synthesizes missing semantic source state.",
        ));
    }
    if snapshot.projects.len() > 1 {
        return Err(invalid_sqlite(format!(
            "row-sink snapshot for project {:?} contains {} project rows; one CBM SQLite source must contain at most its one exact project row",
            snapshot.project,
            snapshot.projects.len()
        )));
    }
    for (family, row_project) in snapshot
        .projects
        .iter()
        .map(|row| ("project", row.project.as_str()))
        .chain(
            snapshot
                .nodes
                .iter()
                .map(|row| ("node", row.project.as_str())),
        )
        .chain(
            snapshot
                .edges
                .iter()
                .map(|row| ("edge", row.project.as_str())),
        )
        .chain(
            snapshot
                .file_hashes
                .iter()
                .map(|row| ("file_hash", row.project.as_str())),
        )
        .chain(
            snapshot
                .project_summaries
                .iter()
                .map(|row| ("project_summary", row.project.as_str())),
        )
        .chain(
            snapshot
                .token_vectors
                .iter()
                .map(|row| ("token_vector", row.project.as_str())),
        )
    {
        if row_project != snapshot.project {
            return Err(invalid_sqlite(format!(
                "row-sink {family} row belongs to project {row_project:?}, not snapshot project {:?}; refusing to filter a semantic source row",
                snapshot.project
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
            "PRAGMA user_version = 5;
             CREATE TABLE projects (
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
               atom_id TEXT NOT NULL,
               source_present INTEGER NOT NULL CHECK(source_present IN (0,1)),
               source_bytes BLOB,
               source_sha256 TEXT NOT NULL DEFAULT '',
               start_byte INTEGER NOT NULL DEFAULT 0,
               end_byte INTEGER NOT NULL DEFAULT 0,
               CHECK((source_present = 0 AND source_bytes IS NULL AND source_sha256 = '' AND
                 start_byte = 0 AND end_byte = 0) OR (source_present = 1 AND source_bytes IS NOT NULL
                 AND length(source_sha256) = 64 AND end_byte >= start_byte AND
                 length(source_bytes) = end_byte - start_byte)),
               UNIQUE(project, atom_id)
             );
             CREATE INDEX idx_nodes_qn ON nodes(project, qualified_name);
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
               preprocess_context_id_gen TEXT GENERATED ALWAYS AS (
                 coalesce(CAST(json_extract(properties,'$.preprocess_context_id') AS TEXT),'')),
               CHECK(type != 'IMPORTS' OR json_type(properties,'$.local_name') IS NULL OR
                 json_type(properties,'$.local_name') IN ('null','text')),
               CHECK(json_type(properties,'$.preprocess_context_id') IS NULL OR
                 json_type(properties,'$.preprocess_context_id') IN ('null','text')),
               UNIQUE(source_id, target_id, type, local_name_gen, preprocess_context_id_gen)
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

    for project in &snapshot.projects {
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
        let source_value = node.source_present.then_some(node.source_bytes.as_slice());
        let start_byte = i64::try_from(node.start_byte).map_err(|_| {
            invalid_sqlite(format!(
                "row-sink node atom {} start_byte {} exceeds SQLite INTEGER range",
                node.atom_id, node.start_byte
            ))
        })?;
        let end_byte = i64::try_from(node.end_byte).map_err(|_| {
            invalid_sqlite(format!(
                "row-sink node atom {} end_byte {} exceeds SQLite INTEGER range",
                node.atom_id, node.end_byte
            ))
        })?;
        connection.execute(
            "INSERT INTO nodes(id, project, label, name, qualified_name, file_path, start_line, end_line, properties, atom_id, source_present, source_bytes, source_sha256, start_byte, end_byte)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
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
                node.atom_id,
                i64::from(node.source_present),
                source_value,
                node.source_sha256,
                start_byte,
                end_byte,
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

fn snapshot_metadata_rows(snapshot: &CbmGraphSnapshot) -> IngestResult<RawMetadataRows> {
    let mut projects = Vec::new();
    for project in &snapshot.projects {
        validate_snapshot_schema(
            &project.schema,
            SCHEMA_PROJECT_ROW,
            "row-sink project metadata",
        )?;
        projects.push(RawProjectRow {
            name: project.project.clone(),
            indexed_at: project.indexed_at.clone(),
            root_path: project.root_path.clone(),
        });
    }

    let mut file_hashes = Vec::new();
    for file_hash in &snapshot.file_hashes {
        validate_snapshot_schema(
            &file_hash.schema,
            CBM_FILE_HASH_ROW_SCHEMA,
            "row-sink file hash metadata",
        )?;
        file_hashes.push(RawFileHashRow {
            project: file_hash.project.clone(),
            rel_path: file_hash.rel_path.clone(),
            sha256: file_hash.sha256.clone(),
            mtime_ns: file_hash.mtime_ns,
            size: file_hash.size,
        });
    }
    file_hashes.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));

    let mut project_summaries = Vec::new();
    for summary in &snapshot.project_summaries {
        validate_snapshot_schema(
            &summary.schema,
            SCHEMA_PROJECT_SUMMARY_ROW,
            "row-sink project summary metadata",
        )?;
        project_summaries.push(RawProjectSummaryRow {
            project: summary.project.clone(),
            summary: summary.summary.clone(),
            source_hash: summary.source_hash.clone(),
            created_at: summary.created_at.clone(),
            updated_at: summary.updated_at.clone(),
        });
    }
    project_summaries.sort_by(|left, right| left.project.cmp(&right.project));

    let mut token_vectors = Vec::new();
    for token_vector in &snapshot.token_vectors {
        validate_snapshot_schema(
            &token_vector.schema,
            SCHEMA_TOKEN_VECTOR_ROW,
            "row-sink token vector metadata",
        )?;
        token_vectors.push(RawTokenVectorRow {
            id: token_vector.id,
            project: token_vector.project.clone(),
            token: token_vector.token.clone(),
            vector: token_vector.vector.clone(),
            idf: token_vector.idf,
        });
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
    let nodes = snapshot.nodes.iter().collect::<Vec<_>>();
    let mut rows = parallel_map(nodes, workers, |node| {
        if node.project != project {
            return Err(invalid_sqlite(format!(
                "row-sink node {} belongs to project {:?}, expected {project:?}; refusing to filter a semantic source row",
                node.source_node_id, node.project
            )));
        }
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
            atom_id: node.atom_id.clone(),
            qualified_name: node.qualified_name.clone(),
            file_path: node.file_path.clone(),
            start_line: node.start_line,
            end_line: node.end_line,
            source_present: node.source_present,
            source_bytes: node.source_bytes.clone(),
            source_sha256: node.source_sha256.clone(),
            start_byte: node.start_byte,
            end_byte: node.end_byte,
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
    let edges = snapshot.edges.iter().collect::<Vec<_>>();
    let mut rows = parallel_map(edges, workers, |edge| {
        if edge.project != project {
            return Err(invalid_sqlite(format!(
                "row-sink edge {} belongs to project {:?}, expected {project:?}; refusing to filter a semantic source row",
                edge.sqlite_edge_id, edge.project
            )));
        }
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
        let expected_local_name =
            row_sink_local_name_gen(&edge.edge_type, &properties, edge.sqlite_edge_id)?;
        if edge.local_name_gen != expected_local_name {
            return Err(invalid_sqlite(format!(
                "row-sink edge {} local_name_gen {:?} does not match properties-derived {:?}",
                edge.sqlite_edge_id, edge.local_name_gen, expected_local_name
            )));
        }
        let expected_url_path = row_sink_url_path_gen(&properties, edge.sqlite_edge_id)?;
        if edge.url_path_gen != expected_url_path {
            return Err(invalid_sqlite(format!(
                "row-sink edge {} url_path_gen {:?} does not match properties-derived {:?}",
                edge.sqlite_edge_id, edge.url_path_gen, expected_url_path
            )));
        }
        let preprocess_context_id_gen =
            row_sink_preprocess_context_id_gen(&properties, edge.sqlite_edge_id)?;
        Ok(RawEdgeRow {
            id: edge.sqlite_edge_id,
            project: edge.project.clone(),
            source_id: edge.source_node_id,
            target_id: edge.target_node_id,
            edge_type: edge.edge_type.clone(),
            properties,
            properties_json: edge.properties_json.clone(),
            url_path_gen: edge.url_path_gen.clone(),
            local_name_gen: edge.local_name_gen.clone(),
            preprocess_context_id_gen,
        })
    })?;
    rows.sort_by(|left, right| {
        left.source_id
            .cmp(&right.source_id)
            .then_with(|| left.target_id.cmp(&right.target_id))
            .then_with(|| left.edge_type.cmp(&right.edge_type))
            .then_with(|| left.local_name_gen.cmp(&right.local_name_gen))
            .then_with(|| {
                left.preprocess_context_id_gen
                    .cmp(&right.preprocess_context_id_gen)
            })
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

fn edge_identity_text_property(
    properties: &Value,
    key: &str,
    edge_id: i64,
) -> IngestResult<String> {
    match properties.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(value) => Err(invalid_sqlite(format!(
            "edge {edge_id} identity property {key:?} must be text or null, observed {value}"
        ))),
    }
}

fn row_sink_local_name_gen(
    edge_type: &str,
    properties: &Value,
    edge_id: i64,
) -> IngestResult<String> {
    if edge_type == "IMPORTS" {
        edge_identity_text_property(properties, "local_name", edge_id)
    } else {
        Ok(String::new())
    }
}

fn row_sink_url_path_gen(properties: &Value, edge_id: i64) -> IngestResult<String> {
    edge_identity_text_property(properties, "url_path", edge_id)
}

fn row_sink_preprocess_context_id_gen(properties: &Value, edge_id: i64) -> IngestResult<String> {
    edge_identity_text_property(properties, "preprocess_context_id", edge_id)
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
        .chain(
            prepared
                .semantic_constellations
                .iter()
                .filter_map(|prepared| prepared.measured.as_ref()),
        )
        .map(|constellation| {
            constellation
                .slots
                .keys()
                .filter(|slot| gate.guard_slots.contains(&slot.get()))
                .count()
        })
        .sum()
}

fn read_nodes(connection: &Connection, expected_project: &str) -> IngestResult<Vec<RawNodeRow>> {
    let mut vectors = read_node_vectors(connection, expected_project)?;
    let mut statement = connection
        .prepare(
            "SELECT id, project, label, name, qualified_name, \
             COALESCE(file_path, ''), COALESCE(start_line, 0), \
             COALESCE(end_line, 0), COALESCE(properties, '{}'), atom_id, \
             source_present, source_bytes, source_sha256, start_byte, end_byte \
             FROM nodes ORDER BY id",
        )
        .map_err(|error| invalid_sqlite(format!("prepare nodes query: {error}")))?;
    let rows = statement
        .query_map([], |row| {
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
                row.get::<_, String>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, i64>(13)?,
                row.get::<_, i64>(14)?,
            ))
        })
        .map_err(|error| invalid_sqlite(format!("query nodes: {error}")))?;

    let mut out = Vec::new();
    for row in rows {
        let (
            id,
            row_project,
            label,
            name,
            qualified_name,
            file_path,
            start_line,
            end_line,
            properties_json,
            atom_id,
            source_present,
            source_bytes,
            source_sha256,
            start_byte,
            end_byte,
        ) = row.map_err(|error| {
            invalid_sqlite(format!(
                "read nodes row: {error}; a non-UTF-8 text column violates the \
                 cbm_json_escape UTF-8 write contract (#493) — the DB was written \
                 by a pre-contract indexer; delete the store and re-index with a \
                 current binary"
            ))
        })?;
        if row_project != expected_project {
            return Err(invalid_sqlite(format!(
                "node {id} belongs to project {row_project:?}, expected {expected_project:?}"
            )));
        }
        if atom_id.len() != 64
            || !atom_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid_sqlite(format!(
                "node {id} atom_id is not one canonical 64-digit hexadecimal source identity; rebuild this collapsed legacy store"
            )));
        }
        if source_present != 0 && source_present != 1 {
            return Err(invalid_sqlite(format!(
                "node {id} source_present must be exactly zero or one, got {source_present}"
            )));
        }
        if start_byte < 0 || end_byte < 0 {
            return Err(invalid_sqlite(format!(
                "node {id} has a negative exact-source byte span {start_byte}..{end_byte}"
            )));
        }
        let source_present = source_present == 1;
        let start_byte = u64::try_from(start_byte)
            .map_err(|_| invalid_sqlite(format!("node {id} start_byte is out of range")))?;
        let end_byte = u64::try_from(end_byte)
            .map_err(|_| invalid_sqlite(format!("node {id} end_byte is out of range")))?;
        let source_bytes = match (source_present, source_bytes) {
            (true, Some(bytes)) => bytes,
            (true, None) => {
                return Err(invalid_sqlite(format!(
                    "node {id} declares exact source but source_bytes is NULL"
                )));
            }
            (false, None) => Vec::new(),
            (false, Some(_)) => {
                return Err(invalid_sqlite(format!(
                    "node {id} has source bytes while source_present is zero"
                )));
            }
        };
        if source_present {
            if end_byte < start_byte || end_byte - start_byte != source_bytes.len() as u64 {
                return Err(invalid_sqlite(format!(
                    "node {id} source length {} does not equal its exact span {start_byte}..{end_byte}",
                    source_bytes.len()
                )));
            }
            let actual_sha256 = hex_lower(&sha256_digest(&source_bytes));
            if source_sha256 != actual_sha256 {
                return Err(invalid_sqlite(format!(
                    "node {id} source_sha256 mismatch: stored {source_sha256}, actual {actual_sha256}"
                )));
            }
        } else if !source_sha256.is_empty() || start_byte != 0 || end_byte != 0 {
            return Err(invalid_sqlite(format!(
                "node {id} has source metadata while source_present is zero"
            )));
        }
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
            project: row_project,
            label,
            name,
            atom_id,
            qualified_name,
            file_path,
            start_line,
            end_line,
            source_present,
            source_bytes,
            source_sha256,
            start_byte,
            end_byte,
            properties,
            properties_json,
            node_vector: vectors.remove(&id),
        });
    }
    if !vectors.is_empty() {
        return Err(invalid_sqlite(format!(
            "node_vectors contains {} orphan row(s) whose node_id is absent from nodes; refusing to discard generated vectors",
            vectors.len()
        )));
    }
    Ok(out)
}

fn read_node_vectors(
    connection: &Connection,
    expected_project: &str,
) -> IngestResult<HashMap<i64, Vec<u8>>> {
    if !table_exists(connection, "node_vectors")? {
        return Ok(HashMap::new());
    }
    let mut statement = connection
        .prepare("SELECT node_id, project, vector FROM node_vectors")
        .map_err(|error| invalid_sqlite(format!("prepare node_vectors query: {error}")))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|error| invalid_sqlite(format!("query node_vectors: {error}")))?;
    let mut out = HashMap::new();
    for row in rows {
        let (node_id, row_project, vector) =
            row.map_err(|error| invalid_sqlite(format!("read node_vectors row: {error}")))?;
        if row_project != expected_project {
            return Err(invalid_sqlite(format!(
                "node vector {node_id} belongs to project {row_project:?}, expected {expected_project:?}"
            )));
        }
        out.insert(node_id, vector);
    }
    Ok(out)
}

fn read_edges(connection: &Connection, expected_project: &str) -> IngestResult<Vec<RawEdgeRow>> {
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
             COALESCE(url_path_gen, ''), local_name_gen, preprocess_context_id_gen \
             FROM edges",
        )
        .map_err(|error| invalid_sqlite(format!("prepare edges query: {error}")))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(|error| invalid_sqlite(format!("query edges: {error}")))?;

    let mut out = Vec::new();
    for row in rows {
        let (
            id,
            row_project,
            source_id,
            target_id,
            edge_type,
            properties_json,
            url_path_gen,
            local_name_gen,
            preprocess_context_id_gen,
        ) = row.map_err(|error| {
            invalid_sqlite(format!(
                "read edges row: {error}; a non-UTF-8 text column violates the \
                     cbm_json_escape UTF-8 write contract (#493) — the DB was written \
                     by a pre-contract indexer; delete the store and re-index with a \
                     current binary"
            ))
        })?;
        if row_project != expected_project {
            return Err(invalid_sqlite(format!(
                "edge {id} belongs to project {row_project:?}, expected {expected_project:?}"
            )));
        }
        let properties = serde_json::from_str::<Value>(&properties_json).map_err(|error| {
            invalid_sqlite(format!("edge {id} properties JSON is invalid: {error}"))
        })?;
        if !properties.is_object() {
            return Err(invalid_sqlite(format!(
                "edge {id} properties JSON must be an object"
            )));
        }
        let expected_local_name = row_sink_local_name_gen(&edge_type, &properties, id)?;
        if local_name_gen != expected_local_name {
            return Err(invalid_sqlite(format!(
                "edge {id} persisted local_name_gen {local_name_gen:?} differs from properties-derived {expected_local_name:?}"
            )));
        }
        let expected_url_path = row_sink_url_path_gen(&properties, id)?;
        if url_path_gen != expected_url_path {
            return Err(invalid_sqlite(format!(
                "edge {id} persisted url_path_gen {url_path_gen:?} differs from properties-derived {expected_url_path:?}"
            )));
        }
        let expected_context = row_sink_preprocess_context_id_gen(&properties, id)?;
        if preprocess_context_id_gen != expected_context {
            return Err(invalid_sqlite(format!(
                "edge {id} persisted preprocess_context_id_gen {preprocess_context_id_gen:?} differs from properties-derived {expected_context:?}"
            )));
        }
        out.push(RawEdgeRow {
            id,
            project: row_project,
            source_id,
            target_id,
            edge_type,
            properties,
            properties_json,
            url_path_gen,
            local_name_gen,
            preprocess_context_id_gen,
        });
    }
    out.sort_by(|left, right| {
        left.source_id
            .cmp(&right.source_id)
            .then_with(|| left.target_id.cmp(&right.target_id))
            .then_with(|| left.edge_type.cmp(&right.edge_type))
            .then_with(|| left.local_name_gen.cmp(&right.local_name_gen))
            .then_with(|| {
                left.preprocess_context_id_gen
                    .cmp(&right.preprocess_context_id_gen)
            })
            .then_with(|| left.id.cmp(&right.id))
    });
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
    pub atom_id: String,
    pub qualified_name: String,
    pub file_path: String,
    pub start_line: i64,
    pub end_line: i64,
    pub source_present: bool,
    pub source_bytes: Vec<u8>,
    pub source_sha256: String,
    pub start_byte: u64,
    pub end_byte: u64,
    pub properties_json: String,
    pub node_vector: Option<Vec<u8>>,
}

/// A CBM pipeline edge row read back from a persisted CBM SQLite `edges` table.
///
/// Mirrors `cbm_gbuf_row_edge_t` plus the schema-v5 generated identity readback.
/// `local_name_gen` is the `local_name` property of an `IMPORTS` edge (empty
/// otherwise); `preprocess_context_id_gen` is the context property for every
/// edge (empty when absent).
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
    pub preprocess_context_id_gen: String,
}

/// An exact CBM `file_hashes` row read from the persisted source snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbmSqlitePipelineFileHash {
    pub project: String,
    pub rel_path: String,
    pub sha256: String,
    pub mtime_ns: i64,
    pub size: i64,
}

/// The full CBM pipeline row stream for one project, read back from its persisted
/// CBM SQLite (`<project>.db`) — the out-of-process equivalent of the in-process
/// FFI row sink (#405).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbmSqlitePipelineRows {
    pub project: String,
    pub projects: Vec<CbmProjectRow>,
    pub nodes: Vec<CbmSqlitePipelineNode>,
    pub edges: Vec<CbmSqlitePipelineEdge>,
    pub file_hashes: Vec<CbmSqlitePipelineFileHash>,
    pub project_summaries: Vec<CbmProjectSummaryRow>,
    pub token_vectors: Vec<CbmTokenVectorRow>,
    pub graph_schema_version: u32,
}

fn validate_pipeline_project(connection: &Connection, expected_project: &str) -> IngestResult<()> {
    let mut statement = connection
        .prepare("SELECT name FROM projects")
        .map_err(|error| invalid_sqlite(format!("prepare pipeline project query: {error}")))?;
    let projects = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| invalid_sqlite(format!("query pipeline project: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invalid_sqlite(format!("read pipeline project: {error}")))?;
    if projects.len() != 1 || projects[0] != expected_project {
        return Err(invalid_sqlite(format!(
            "pipeline SQLite must contain exactly project {expected_project:?}, observed {projects:?}"
        )));
    }
    Ok(())
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
/// while project, summary, node-vector, and token-vector rows preserve the complete
/// semantic source that the legacy FFI row sink could not carry. Fails closed with a labeled
/// `ASTRO_INGEST_SQLITE_INVALID` error on any malformed input (missing tables,
/// non-object properties JSON).
pub fn read_cbm_sqlite_pipeline_rows(
    sqlite_path: &Path,
    project: &str,
) -> IngestResult<CbmSqlitePipelineRows> {
    let connection = open_cbm_source_connection(sqlite_path)?;
    validate_pipeline_project(&connection, project)?;
    let raw_projects = read_projects(&connection, project)?;
    let raw_nodes = read_nodes(&connection, project)?;
    let raw_edges = read_edges(&connection, project)?;
    let raw_file_hashes = read_file_hashes(&connection, project)?;
    let raw_project_summaries = read_project_summaries(&connection, project)?;
    let raw_token_vectors = read_token_vectors(&connection, project)?;
    let projects = raw_projects
        .into_iter()
        .map(|row| CbmProjectRow {
            schema: SCHEMA_PROJECT_ROW.to_string(),
            project: row.name,
            indexed_at: row.indexed_at,
            root_path: row.root_path,
            commit: String::new(),
            sqlite_fingerprint_sha256: String::new(),
        })
        .collect();
    let nodes = raw_nodes
        .into_iter()
        .map(|node| CbmSqlitePipelineNode {
            id: node.id,
            project: node.project,
            label: node.label,
            name: node.name,
            atom_id: node.atom_id,
            qualified_name: node.qualified_name,
            file_path: node.file_path,
            start_line: node.start_line,
            end_line: node.end_line,
            source_present: node.source_present,
            source_bytes: node.source_bytes,
            source_sha256: node.source_sha256,
            start_byte: node.start_byte,
            end_byte: node.end_byte,
            properties_json: node.properties_json,
            node_vector: node.node_vector,
        })
        .collect();
    let edges = raw_edges
        .into_iter()
        .map(|edge| CbmSqlitePipelineEdge {
            id: edge.id,
            project: edge.project,
            source_id: edge.source_id,
            target_id: edge.target_id,
            edge_type: edge.edge_type,
            properties_json: edge.properties_json,
            url_path_gen: edge.url_path_gen,
            local_name_gen: edge.local_name_gen,
            preprocess_context_id_gen: edge.preprocess_context_id_gen,
        })
        .collect();
    let file_hashes = raw_file_hashes
        .into_iter()
        .map(|file_hash| CbmSqlitePipelineFileHash {
            project: file_hash.project,
            rel_path: file_hash.rel_path,
            sha256: file_hash.sha256,
            mtime_ns: file_hash.mtime_ns,
            size: file_hash.size,
        })
        .collect();
    let project_summaries = raw_project_summaries
        .into_iter()
        .map(|row| CbmProjectSummaryRow {
            schema: SCHEMA_PROJECT_SUMMARY_ROW.to_string(),
            project: row.project,
            summary: row.summary,
            source_hash: row.source_hash,
            created_at: row.created_at,
            updated_at: row.updated_at,
            commit: String::new(),
            sqlite_fingerprint_sha256: String::new(),
        })
        .collect();
    let token_vectors = raw_token_vectors
        .into_iter()
        .map(|row| CbmTokenVectorRow {
            schema: SCHEMA_TOKEN_VECTOR_ROW.to_string(),
            id: row.id,
            project: row.project,
            token: row.token,
            vector: row.vector,
            idf: row.idf,
            commit: String::new(),
            sqlite_fingerprint_sha256: String::new(),
        })
        .collect();
    Ok(CbmSqlitePipelineRows {
        project: project.to_string(),
        projects,
        nodes,
        edges,
        file_hashes,
        project_summaries,
        token_vectors,
        graph_schema_version: CBM_SQLITE_SCHEMA_VERSION as u32,
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
) -> IngestResult<RawMetadataRows> {
    Ok(RawMetadataRows {
        projects: read_projects(connection, &options.project)?,
        file_hashes: read_file_hashes(connection, &options.project)?,
        project_summaries: read_project_summaries(connection, &options.project)?,
        token_vectors: read_token_vectors(connection, &options.project)?,
    })
}

fn read_projects(connection: &Connection, project: &str) -> IngestResult<Vec<RawProjectRow>> {
    if !table_exists(connection, "projects")? {
        return Err(invalid_sqlite(
            "required SQLite projects table is absent; refusing to synthesize semantic project state",
        ));
    }
    let mut statement = connection
        .prepare("SELECT name, indexed_at, root_path FROM projects ORDER BY name")
        .map_err(|error| invalid_sqlite(format!("prepare projects query: {error}")))?;
    let rows = statement
        .query_map([], |row| {
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
        return Ok(Vec::new());
    }
    if out.len() != 1 || out[0].name != project {
        return Err(invalid_sqlite(format!(
            "CBM SQLite must contain only requested project {project:?}, observed project rows {:?}; refusing to omit another project's semantic state",
            out.iter().map(|row| row.name.as_str()).collect::<Vec<_>>()
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
             FROM file_hashes ORDER BY project, rel_path",
        )
        .map_err(|error| invalid_sqlite(format!("prepare file_hashes query: {error}")))?;
    let rows = statement
        .query_map([], |row| {
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
        let row = row.map_err(|error| invalid_sqlite(format!("read file_hashes row: {error}")))?;
        if row.project != project {
            return Err(invalid_sqlite(format!(
                "file_hashes row {:?} belongs to project {:?}, expected {project:?}; refusing to omit another project's semantic state",
                row.rel_path, row.project
            )));
        }
        out.push(row);
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
             FROM project_summaries ORDER BY project",
        )
        .map_err(|error| invalid_sqlite(format!("prepare project_summaries query: {error}")))?;
    let rows = statement
        .query_map([], |row| {
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
        let row =
            row.map_err(|error| invalid_sqlite(format!("read project_summaries row: {error}")))?;
        if row.project != project {
            return Err(invalid_sqlite(format!(
                "project_summaries row belongs to project {:?}, expected {project:?}; refusing to omit another project's semantic state",
                row.project
            )));
        }
        out.push(row);
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
             FROM token_vectors ORDER BY project, id",
        )
        .map_err(|error| invalid_sqlite(format!("prepare token_vectors query: {error}")))?;
    let rows = statement
        .query_map([], |row| {
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
        let row =
            row.map_err(|error| invalid_sqlite(format!("read token_vectors row: {error}")))?;
        if row.project != project {
            return Err(invalid_sqlite(format!(
                "token_vectors row {} belongs to project {:?}, expected {project:?}; refusing to omit another project's semantic state",
                row.id, row.project
            )));
        }
        out.push(row);
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
        // #501/#473: canonical content is the byte-exact source column read from the
        // persisted CBM store. Missing source stays explicitly absent (empty canonical
        // source for structural/synthetic nodes); it is never replaced by a signature,
        // properties fingerprint, lossy text decode, or another proxy.
        let source_snippet = raw.source_bytes.clone();
        let expected_source_blake3 = raw
            .source_present
            .then(|| *blake3::hash(&source_snippet).as_bytes());

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
        symbol.symbol_name = raw.name.clone();
        symbol.source_present = raw.source_present;
        symbol.expected_source_snippet_blake3 = expected_source_blake3;
        symbol.scalars = scalar_properties(&raw.properties)?;
        symbol
            .scalars
            .insert("start_line".to_string(), f64::from(start_line));
        symbol
            .scalars
            .insert("end_line".to_string(), f64::from(end_line));
        symbol
            .scalars
            .insert("start_byte".to_string(), raw.start_byte as f64);
        symbol
            .scalars
            .insert("end_byte".to_string(), raw.end_byte as f64);
        symbol.properties_json = raw.properties_json.clone();
        symbol.anchors = anchor_evidence(&raw.properties, raw.id)?;

        let node_vector_sha256 = raw.node_vector.as_ref().map(|bytes| sha256_digest(bytes));
        symbol.semantic_vector_sha256 = node_vector_sha256;
        let node_vector_bytes = raw.node_vector.as_ref().map(Vec::len);
        out.push(ExtractedNode {
            id: raw.id,
            atom_id: raw.atom_id,
            label,
            name: raw.name,
            source_sha256: raw.source_sha256,
            start_byte: raw.start_byte,
            end_byte: raw.end_byte,
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
    semantic_source_schema_sha256: [u8; 32],
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
        nodes,
        digest_reuse,
        retention,
    )?;
    constellations.sort_by_key(|prepared| prepared.node_id);
    let mut coverage = SemanticCoverageAccumulator::default();
    for prepared in &constellations {
        coverage.observe_slots(SemanticFamily::Node, &prepared.semantic_value_slots)?;
    }
    let semantic_inputs =
        build_non_node_semantic_inputs(&metadata, &edges, &constellations, options.panel_version)?;
    let (semantic_constellations, semantic_graph_rows) = prepare_non_node_semantic_constellations(
        vault,
        runtime,
        options,
        &driver,
        semantic_inputs,
        sqlite_fingerprint,
        existing_graph,
        &mut preserved_keys,
        &mut coverage,
        retention,
    )?;
    timing_ms.push((
        "prepare_live_symbols",
        phase_start.elapsed().as_millis() as u64,
    ));
    phase_start = std::time::Instant::now();

    // Metadata rows. File-hash rows for unchanged files are carried forward from persisted
    // bytes rather than re-encoded (#372); their keys join `preserved_keys`.
    let mut graph_rows = metadata_graph_rows(
        options,
        &metadata,
        sqlite_fingerprint,
        unchanged_files,
        existing_graph,
        &mut preserved_keys,
        &mut encode_skip,
        &mut project_digests,
    )?;
    graph_rows.extend(semantic_graph_rows);
    let coverage_witness = coverage.finish(
        &options.project,
        options.panel_version,
        semantic_source_schema_sha256,
        sqlite_fingerprint,
    )?;
    graph_rows.push((
        project_key_with_digest(
            SEMANTIC_COVERAGE_ROW_PREFIX,
            &project_digests.digest(&options.project),
        ),
        semantic_coverage_canonical_bytes(&coverage_witness)?,
    ));
    // Node-map rows. A digest-reused symbol must already have the exact persisted
    // row implied by that digest. Absence is vault corruption or an invalid reuse
    // classification; synthesizing a replacement would hide the broken state.
    let mut to_encode = Vec::new();
    let mut encoded_constellation_indices = Vec::new();
    for (constellation_index, prepared) in constellations.iter().enumerate() {
        if digest_reuse.contains_key(&prepared.node_id) {
            let key = node_map_reuse_key(prepared, &mut project_digests)?;
            if !existing_graph.contains_key(&key) {
                return Err(IngestError::InvalidInput(format!(
                    "ASTRO_DIGEST_REUSE_NODE_MAP_MISSING: digest-reused node {} atom {} has no persisted node-map row {}; remediation: preserve the vault and rebuild the project from source",
                    prepared.node_id,
                    prepared.atom_id,
                    hex_lower(&key)
                )));
            }
            encode_skip.node_map_rows_preserved += 1;
            preserved_keys.insert(key);
            continue;
        }
        if prepared.symbol.source_present {
            encoded_constellation_indices.push(constellation_index);
        }
        to_encode.push(prepared);
    }
    encode_skip.node_map_rows_encoded = to_encode.len();
    let node_map_rows = parallel_map(to_encode, options.workers, |prepared| {
        node_map_graph_row(options, prepared)
    })?;
    graph_rows.extend(node_map_rows);
    // #980: structural labels are real measured constellations. The legacy
    // structural-only projection count is therefore exactly zero and no edge is
    // excluded merely because one endpoint is Project/Branch/Folder.
    let structural_only = 0;
    let structural_node_ids = BTreeSet::new();
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

    let mut exact_sources = BTreeMap::new();
    for constellation_index in encoded_constellation_indices {
        register_exact_source(
            &mut exact_sources,
            &constellations,
            PreparedExactSource::Constellation(constellation_index),
            &constellations[constellation_index].symbol.qualified_name,
        )?;
    }
    Ok(PreparedBatch {
        constellations,
        semantic_constellations,
        semantic_coverage: coverage_witness,
        graph_rows,
        edge_rows,
        structural_only,
        sqlite_edges,
        edge_skips,
        exact_sources,
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

fn prepared_exact_source_bytes<'a>(
    source: &'a PreparedExactSource,
    constellations: &'a [PreparedLiveSymbol],
) -> IngestResult<&'a [u8]> {
    match source {
        PreparedExactSource::Constellation(index) => constellations
            .get(*index)
            .map(|prepared| prepared.symbol.source_snippet_bytes.as_slice())
            .ok_or_else(|| {
                IngestError::InvalidInput(format!(
                    "prepared exact-source constellation index {index} is out of range"
                ))
            }),
        PreparedExactSource::Structural(bytes) => Ok(bytes),
    }
}

fn register_exact_source(
    sources: &mut BTreeMap<[u8; 32], PreparedExactSource>,
    constellations: &[PreparedLiveSymbol],
    candidate: PreparedExactSource,
    qualified_name: &str,
) -> IngestResult<()> {
    let hash = *blake3::hash(prepared_exact_source_bytes(&candidate, constellations)?).as_bytes();
    if let Some(existing) = sources.get(&hash) {
        if prepared_exact_source_bytes(existing, constellations)?
            != prepared_exact_source_bytes(&candidate, constellations)?
        {
            return Err(IngestError::InvalidInput(format!(
                "exact-source BLAKE3 collision while preparing symbol {qualified_name}"
            )));
        }
        return Ok(());
    }
    sources.insert(hash, candidate);
    Ok(())
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
        if key.starts_with(SEMANTIC_COVERAGE_ROW_PREFIX) {
            if existing_bytes == planned {
                *planned = existing_bytes.clone();
            }
            return Ok(());
        }
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
/// persisted graph/base/slot rows — id, project, label, name, stable atom, qualified name,
/// file path, line span, byte-exact source contract, properties JSON, and node vector —
/// plus, for every edge whose SOURCE node
/// lives in this file, the edge's raw fields (id, endpoints, type, properties JSON,
/// url_path_gen, local_name_gen, preprocess_context_id_gen). Everything is length-prefixed so no field
/// boundary is ambiguous,
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
        section(&mut hasher, node.atom_id.as_bytes());
        section(&mut hasher, node.qualified_name.as_bytes());
        section(&mut hasher, node.file_path.as_bytes());
        section(&mut hasher, &node.start_line.to_be_bytes());
        section(&mut hasher, &node.end_line.to_be_bytes());
        section(&mut hasher, &[u8::from(node.source_present)]);
        section(&mut hasher, &node.source_bytes);
        section(&mut hasher, node.source_sha256.as_bytes());
        section(&mut hasher, &node.start_byte.to_be_bytes());
        section(&mut hasher, &node.end_byte.to_be_bytes());
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
        section(&mut hasher, edge.url_path_gen.as_bytes());
        section(&mut hasher, edge.local_name_gen.as_bytes());
        section(&mut hasher, edge.preprocess_context_id_gen.as_bytes());
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

/// Reads the persisted bounded v2 per-file digest manifest for `project` out of the one
/// shared pre-commit Graph CF scan (#345, #855). Other projects' namespaced rows are
/// ignored. A v2 row belonging to this project is an integrity contract: malformed,
/// incomplete, duplicate, or over-cap state refuses admission rather than silently
/// reconciling from an unverifiable identity map.
fn read_file_digest_manifest(
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    project: &str,
) -> IngestResult<BTreeMap<String, FileDigestRow>> {
    let project_digest = sha256_digest(project.as_bytes());
    let mut heads = BTreeMap::<String, FileDigestManifestV2>::new();
    let mut chunks = BTreeMap::<String, BTreeMap<usize, FileDigestChunkV2>>::new();
    for (key, value) in existing_graph {
        if manifest_v2_key_belongs_to_project(key, FILE_DIGEST_MANIFEST_V2_PREFIX, &project_digest)
        {
            let head = serde_json::from_slice::<FileDigestManifestV2>(value).map_err(|error| {
                invalid_sqlite(format!(
                    "decode v2 file-digest manifest head for project {project:?}: {error}"
                ))
            })?;
            if head.schema != SCHEMA_FILE_DIGEST_MANIFEST_V2 || head.project != project {
                return Err(invalid_sqlite(format!(
                    "v2 file-digest manifest head has unexpected schema/project for {project:?}: schema={:?}, project={:?}",
                    head.schema, head.project
                )));
            }
            if heads.insert(head.file_path.clone(), head).is_some() {
                return Err(invalid_sqlite(format!(
                    "duplicate v2 file-digest manifest heads for project {project:?}"
                )));
            }
        } else if manifest_v2_key_belongs_to_project(
            key,
            FILE_DIGEST_CHUNK_V2_PREFIX,
            &project_digest,
        ) {
            if value.len() > FILE_DIGEST_CHUNK_MAX_BYTES {
                return Err(invalid_sqlite(format!(
                    "persisted v2 file-digest chunk for project {project:?} is {} bytes, above the {} byte Graph-row cap",
                    value.len(),
                    FILE_DIGEST_CHUNK_MAX_BYTES
                )));
            }
            let chunk = serde_json::from_slice::<FileDigestChunkV2>(value).map_err(|error| {
                invalid_sqlite(format!(
                    "decode v2 file-digest manifest chunk for project {project:?}: {error}"
                ))
            })?;
            if chunk.schema != SCHEMA_FILE_DIGEST_CHUNK_V2 || chunk.project != project {
                return Err(invalid_sqlite(format!(
                    "v2 file-digest manifest chunk has unexpected schema/project for {project:?}: schema={:?}, project={:?}",
                    chunk.schema, chunk.project
                )));
            }
            if chunk.symbols.is_empty() || chunk.symbols.len() > FILE_DIGEST_CHUNK_SYMBOL_CAP {
                return Err(invalid_sqlite(format!(
                    "v2 file-digest manifest chunk {:?} index {} has invalid symbol count {}",
                    chunk.file_path,
                    chunk.chunk_index,
                    chunk.symbols.len()
                )));
            }
            if chunks
                .entry(chunk.file_path.clone())
                .or_default()
                .insert(chunk.chunk_index, chunk)
                .is_some()
            {
                return Err(invalid_sqlite(format!(
                    "duplicate v2 file-digest manifest chunk for project {project:?}"
                )));
            }
        }
    }
    let mut manifest = BTreeMap::new();
    for (file_path, head) in heads {
        let file_chunks = chunks.remove(&file_path).unwrap_or_default();
        if file_chunks.len() != head.chunk_count {
            return Err(invalid_sqlite(format!(
                "v2 file-digest manifest {file_path:?} declares {} chunks but has {}",
                head.chunk_count,
                file_chunks.len()
            )));
        }
        let mut symbols = Vec::with_capacity(head.symbol_count);
        for index in 0..head.chunk_count {
            let Some(chunk) = file_chunks.get(&index) else {
                return Err(invalid_sqlite(format!(
                    "v2 file-digest manifest {file_path:?} is missing chunk {index}"
                )));
            };
            symbols.extend(chunk.symbols.iter().cloned());
        }
        if symbols.len() != head.symbol_count
            || hex_lower(&sha256_digest(&serde_json::to_vec(&symbols)?)) != head.symbols_sha256
        {
            return Err(invalid_sqlite(format!(
                "v2 file-digest manifest {file_path:?} failed exact symbol count/hash readback"
            )));
        }
        manifest.insert(
            file_path.clone(),
            FileDigestRow {
                schema: SCHEMA_FILE_DIGEST_ROW.to_string(),
                project: head.project,
                file_path,
                panel_version: head.panel_version,
                domain: head.domain,
                digest: head.digest,
                symbols,
            },
        );
    }
    if let Some((file_path, chunks)) = chunks.into_iter().next() {
        return Err(invalid_sqlite(format!(
            "v2 file-digest manifest has {} orphan chunks for {file_path:?}",
            chunks.len()
        )));
    }
    Ok(manifest)
}

fn manifest_v2_key_belongs_to_project(
    key: &[u8],
    prefix: &[u8],
    project_digest: &[u8; 32],
) -> bool {
    key.len() == prefix.len() + 64
        && key.starts_with(prefix)
        && key[prefix.len()..prefix.len() + 32] == *project_digest
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

/// Builds bounded v2 per-file digest manifest rows. The head records one file's
/// full digest and identity count; ordered chunks retain every identity without
/// allowing one generated source file to manufacture an over-memtable Graph row.
#[allow(clippy::too_many_arguments)]
fn file_digest_manifest_rows(
    options: &SqliteImportOptions,
    constellations: &[PreparedLiveSymbol],
    new_digests: &BTreeMap<String, String>,
    _unchanged_files: &BTreeSet<String>,
    _existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    _preserved_keys: &mut BTreeSet<Vec<u8>>,
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
        let mut symbols = symbols_by_file
            .remove(file_path.as_str())
            .unwrap_or_default();
        symbols.sort_by_key(|symbol| symbol.node_id);
        let symbols_sha256 = hex_lower(&sha256_digest(&serde_json::to_vec(&symbols)?));
        let chunk_count = symbols.len().div_ceil(FILE_DIGEST_CHUNK_SYMBOL_CAP);
        let head = FileDigestManifestV2 {
            schema: SCHEMA_FILE_DIGEST_MANIFEST_V2.to_string(),
            project: options.project.clone(),
            file_path: file_path.clone(),
            panel_version: options.panel_version,
            domain: FILE_DIGEST_DOMAIN.to_string(),
            digest: digest.clone(),
            symbol_count: symbols.len(),
            chunk_count,
            symbols_sha256,
        };
        rows.push((
            keyed_graph_key_with_digest(
                FILE_DIGEST_MANIFEST_V2_PREFIX,
                &project_digest,
                file_path.as_bytes(),
            ),
            serde_json::to_vec(&head)?,
        ));
        for (chunk_index, chunk_symbols) in symbols.chunks(FILE_DIGEST_CHUNK_SYMBOL_CAP).enumerate()
        {
            let chunk = FileDigestChunkV2 {
                schema: SCHEMA_FILE_DIGEST_CHUNK_V2.to_string(),
                project: options.project.clone(),
                file_path: file_path.clone(),
                chunk_index,
                symbols: chunk_symbols.to_vec(),
            };
            let bytes = serde_json::to_vec(&chunk)?;
            if bytes.len() > FILE_DIGEST_CHUNK_MAX_BYTES {
                return Err(invalid_sqlite(format!(
                    "file digest chunk {file_path:?} index {chunk_index} is {} bytes, above the {} byte bounded Graph-row cap",
                    bytes.len(),
                    FILE_DIGEST_CHUNK_MAX_BYTES
                )));
            }
            let mut discriminator = Vec::with_capacity(file_path.len() + 8);
            discriminator.extend_from_slice(file_path.as_bytes());
            discriminator.extend_from_slice(&(chunk_index as u64).to_be_bytes());
            rows.push((
                keyed_graph_key_with_digest(
                    FILE_DIGEST_CHUNK_V2_PREFIX,
                    &project_digest,
                    &discriminator,
                ),
                bytes,
            ));
        }
        encode_skip.manifest_rows_encoded += 1;
    }
    Ok(rows)
}

#[allow(clippy::too_many_arguments)]
fn metadata_graph_rows(
    options: &SqliteImportOptions,
    metadata: &RawMetadataRows,
    sqlite_fingerprint: [u8; 32],
    unchanged_files: &BTreeSet<String>,
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    preserved_keys: &mut BTreeSet<Vec<u8>>,
    encode_skip: &mut EncodeSkipReport,
    project_digests: &mut ProjectDigestCache,
) -> IngestResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let fingerprint = hex_lower(&sqlite_fingerprint);
    let mut rows = Vec::new();
    for project in &metadata.projects {
        let row = CbmProjectRow {
            schema: SCHEMA_PROJECT_ROW.to_string(),
            project: project.name.clone(),
            indexed_at: project.indexed_at.clone(),
            root_path: project.root_path.clone(),
            commit: options.commit.clone(),
            sqlite_fingerprint_sha256: fingerprint.clone(),
        };
        rows.push((
            project_key_with_digest(PROJECT_ROW_PREFIX, &project_digests.digest(&row.project)),
            serde_json::to_vec(&row)?,
        ));
    }
    for file_hash in &metadata.file_hashes {
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
            schema: CBM_FILE_HASH_ROW_SCHEMA.to_string(),
            project: file_hash.project.clone(),
            rel_path: file_hash.rel_path.clone(),
            sha256: file_hash.sha256.clone(),
            mtime_ns: file_hash.mtime_ns,
            size: file_hash.size,
            commit: options.commit.clone(),
            sqlite_fingerprint_sha256: fingerprint.clone(),
        };
        encode_skip.file_hash_rows_encoded += 1;
        rows.push((key, serde_json::to_vec(&row)?));
    }
    for summary in &metadata.project_summaries {
        let row = CbmProjectSummaryRow {
            schema: SCHEMA_PROJECT_SUMMARY_ROW.to_string(),
            project: summary.project.clone(),
            summary: summary.summary.clone(),
            source_hash: summary.source_hash.clone(),
            created_at: summary.created_at.clone(),
            updated_at: summary.updated_at.clone(),
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
    for token_vector in &metadata.token_vectors {
        let row = CbmTokenVectorRow {
            schema: SCHEMA_TOKEN_VECTOR_ROW.to_string(),
            id: token_vector.id,
            project: token_vector.project.clone(),
            token: token_vector.token.clone(),
            vector: token_vector.vector.clone(),
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
            url_path_gen: edge.url_path_gen.clone(),
            local_name_gen: edge.local_name_gen.clone(),
            preprocess_context_id_gen: edge.preprocess_context_id_gen.clone(),
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
        // so its persisted typed row (same src/dst CxIds and complete identity key, same
        // content-derived fields) is unchanged (#372). Carry it forward from persisted bytes
        // and fold its key into the "current" set; fail open to the encode path if its key is
        // absent. The whole-vault `verify_chain` covers provenance, mirroring #345's Base skip.
        if digest_reuse.contains_key(&edge.source_id)
            && digest_reuse.contains_key(&edge.target_id)
            && let Ok(key) = edge_graph_key(
                src,
                dst,
                kind,
                &edge.local_name_gen,
                &edge.preprocess_context_id_gen,
            )
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
            preprocess_context_id_gen: edge.preprocess_context_id_gen,
            weight,
            props: edge.properties,
            properties_json: Some(edge.properties_json),
            provenance: zero_ledger_ref(),
            commit: options.commit.clone(),
        };
        let key = edge_graph_key(
            row.src,
            row.dst,
            kind,
            &row.local_name_gen,
            &row.preprocess_context_id_gen,
        )?;
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
    // Keep each node as an independently stealable indexed Rayon item. The former
    // one-static-chunk-per-worker plan made source-heavy repository regions a long
    // serial tail: workers that finished light chunks could not help with the
    // remaining expensive chunks. `parallel_map`'s indexed collect preserves exact
    // input order while the global pre-attached pool dynamically balances nodes.
    parallel_map(nodes, worker_count, |node| {
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
}

fn prepare_historical_constellations_parallel<C, R>(
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
    let worker_count = options.workers.min(nodes.len()).max(1);
    parallel_map(nodes, worker_count, |node| {
        let semantic_values = node_semantic_values(&node)?;
        let identity = node_symbol_identity(&node, &semantic_values, options.panel_version)?;
        prepare_constellation(
            vault,
            runtime,
            options,
            driver,
            node,
            identity,
            semantic_values,
            retention,
        )
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
    let semantic_values = node_semantic_values(&node)?;
    let semantic_value_slots = semantic_values.keys().copied().collect::<Vec<_>>();
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
            atom_id: node.atom_id,
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
            semantic_value_slots,
            measured: None,
        });
    }
    let mut node = node;
    node.symbol.available_slots = options
        .available_slots
        .iter()
        .map(|slot| slot.get())
        .collect();
    let identity = node_symbol_identity(&node, &semantic_values, options.panel_version)?;
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
            atom_id: node.atom_id,
            name: node.name,
            properties_json: node.properties_json,
            node_vector: node.node_vector,
            symbol: node.symbol,
            identity,
            semantic_value_slots,
            measured: None,
        });
    }
    let prepared = prepare_constellation(
        vault,
        runtime,
        options,
        driver,
        node,
        identity,
        semantic_values,
        retention,
    )?;
    Ok(PreparedLiveSymbol {
        node_id: prepared.node_id,
        atom_id: prepared.atom_id,
        name: prepared.name,
        properties_json: prepared.properties_json,
        node_vector: prepared.node_vector,
        symbol: prepared.symbol,
        identity: prepared.identity,
        semantic_value_slots: prepared.semantic_value_slots,
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

fn insert_semantic_value(
    values: &mut BTreeMap<SlotId, SemanticValue>,
    family: SemanticFamily,
    path: &str,
    value: SemanticValue,
) -> IngestResult<()> {
    let source_type = value.source_type();
    let rule = semantic_rule(family, path, source_type).ok_or_else(|| {
        IngestError::refused(
            ASTRO_SEMANTIC_COVERAGE_GAP,
            format!(
                "unregistered CBM semantic atom family={} path={path:?} type={}",
                family.as_str(),
                source_type.as_str()
            ),
            SEMANTIC_COVERAGE_REMEDIATION,
        )
    })?;
    if values.insert(SlotId::new(rule.value_slot), value).is_some() {
        return Err(IngestError::refused(
            ASTRO_SEMANTIC_COVERAGE_GAP,
            format!(
                "duplicate semantic value slot S{} for family={} path={path:?}",
                rule.value_slot,
                family.as_str()
            ),
            "Keep every atomic path bound to one collision-free frozen slot, rebuild the panel, and re-ingest the preserved source.",
        ));
    }
    Ok(())
}

fn insert_observed_semantic_value(
    values: &mut BTreeMap<SlotId, SemanticValue>,
    family: SemanticFamily,
    row_identity: &str,
    path: &str,
    value: SemanticValue,
) -> IngestResult<()> {
    let source_type = value.source_type();
    if semantic_rule(family, path, source_type).is_none() {
        let expected = SEMANTIC_RULES
            .iter()
            .filter(|rule| rule.family == family && rule.path == path)
            .map(|rule| {
                format!(
                    "S{}:{}:{}:{:?}",
                    rule.value_slot,
                    rule.slot_key,
                    rule.source_type.as_str(),
                    rule.kind.shape()
                )
            })
            .collect::<Vec<_>>();
        return Err(IngestError::refused(
            ASTRO_SEMANTIC_COVERAGE_GAP,
            format!(
                "{row_identity} has unregistered semantic atom family={} path={path:?} observed_type={} expected_lenses={expected:?}",
                family.as_str(),
                source_type.as_str()
            ),
            SEMANTIC_COVERAGE_REMEDIATION,
        ));
    }
    insert_semantic_value(values, family, path, value)
}

fn semantic_json_number(
    number: &serde_json::Number,
    row_identity: &str,
    path: &str,
) -> IngestResult<SemanticValue> {
    if let Some(value) = number.as_i64() {
        return Ok(SemanticValue::Integer(value));
    }
    if let Some(value) = number.as_f64()
        && value.is_finite()
    {
        return Ok(SemanticValue::Real(value));
    }
    Err(IngestError::refused(
        ASTRO_SEMANTIC_COVERAGE_GAP,
        format!("{row_identity} atom {path} is not a finite signed-integer or real JSON number"),
        "Preserve the source value, add its exact finite numeric type to the versioned semantic registry, rebuild the panel, and re-ingest without coercion.",
    ))
}

fn append_semantic_frame(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn append_semantic_value(out: &mut Vec<u8>, value: &SemanticValue) {
    append_semantic_frame(out, value.source_type().as_str().as_bytes());
    match value {
        SemanticValue::Boolean(value) => append_semantic_frame(out, &[u8::from(*value)]),
        SemanticValue::Integer(value) => append_semantic_frame(out, &value.to_be_bytes()),
        SemanticValue::IntegerArray(values) => {
            append_semantic_frame(out, &(values.len() as u64).to_be_bytes());
            for value in values {
                append_semantic_frame(out, &value.to_be_bytes());
            }
        }
        SemanticValue::Real(value) => append_semantic_frame(out, &value.to_bits().to_be_bytes()),
        SemanticValue::Text(value) => append_semantic_frame(out, value.as_bytes()),
        SemanticValue::TextArray(values) => {
            append_semantic_frame(out, &(values.len() as u64).to_be_bytes());
            for value in values {
                append_semantic_frame(out, value.as_bytes());
            }
        }
        SemanticValue::BlobI8x768(value) => append_semantic_frame(out, value),
    }
}

fn semantic_canonical_input_bytes(
    family: SemanticFamily,
    source_key: &str,
    values: &BTreeMap<SlotId, SemanticValue>,
) -> IngestResult<Vec<u8>> {
    if source_key.trim().is_empty() {
        return Err(semantic_coverage_refusal(
            format!("{} semantic row has an empty source key", family.as_str()),
            "Bind every source row to its exact primary key and re-ingest the preserved source.",
        ));
    }
    let mut out = Vec::new();
    append_semantic_frame(&mut out, SEMANTIC_CANONICAL_TAG.as_bytes());
    append_semantic_frame(&mut out, family.as_str().as_bytes());
    append_semantic_frame(&mut out, source_key.as_bytes());
    append_semantic_frame(&mut out, &(values.len() as u64).to_be_bytes());
    for (slot_id, value) in values {
        let rule = semantic_rule_by_slot(*slot_id).ok_or_else(|| {
            semantic_coverage_refusal(
                format!("canonical semantic row contains unregistered slot {slot_id}"),
                "Repair the frozen registry before identity derivation and re-ingest the preserved source.",
            )
        })?;
        if rule.family != family || rule.source_type != value.source_type() {
            return Err(semantic_coverage_refusal(
                format!(
                    "canonical {} row slot {slot_id} disagrees with frozen family/type",
                    family.as_str()
                ),
                "Repair typed row construction before identity derivation and re-ingest the preserved source.",
            ));
        }
        append_semantic_frame(&mut out, &slot_id.get().to_be_bytes());
        append_semantic_value(&mut out, value);
    }
    Ok(out)
}

/// Derives a node identity from every byte that can affect its measured panel.
///
/// Panel v3 introduced exhaustive semantic measurement after the original
/// symbol canonical contract had already frozen. That left values such as the
/// source-generation-local node id outside CxId: two rows could therefore share
/// one CxId while carrying different frozen slot bytes. Panel v4 preserves the
/// stable logical [`SeriesId`] but appends a domain-separated digest of the exact
/// ordered semantic input to the canonical version bytes before deriving CxId.
/// The digest avoids duplicating large source/prose atoms already present in the
/// symbol canonical bytes and exact semantic sidecars.
fn node_symbol_identity(
    node: &ExtractedNode,
    semantic_values: &BTreeMap<SlotId, SemanticValue>,
    panel_version: u32,
) -> IngestResult<SymbolIdentity> {
    let mut identity = node.symbol.identity(panel_version)?;
    if panel_version < PANEL_V4_VERSION {
        return Ok(identity);
    }
    let semantic = semantic_canonical_input_bytes(
        SemanticFamily::Node,
        node.atom_id.as_str(),
        semantic_values,
    )?;
    append_semantic_frame(
        &mut identity.canonical_input_bytes,
        NODE_SEMANTIC_IDENTITY_TAG.as_bytes(),
    );
    append_semantic_frame(
        &mut identity.canonical_input_bytes,
        &sha256_digest(&semantic),
    );
    identity.cx_id = cx_id_from_canonical(
        &identity.canonical_input_bytes,
        panel_version,
        identity.vault_salt.as_bytes(),
    )?;
    Ok(identity)
}

fn semantic_exact_sidecars(
    values: &BTreeMap<SlotId, SemanticValue>,
) -> IngestResult<(BTreeMap<String, f64>, BTreeMap<String, String>)> {
    let mut scalars = BTreeMap::new();
    let mut metadata = BTreeMap::new();
    for (slot_id, value) in values {
        let rule = semantic_rule_by_slot(*slot_id).ok_or_else(|| {
            semantic_coverage_refusal(
                format!("sidecar construction contains unregistered slot {slot_id}"),
                "Repair the frozen registry and re-ingest the preserved source.",
            )
        })?;
        let exact = match value {
            SemanticValue::Boolean(value) => {
                scalars.insert(rule.path.to_string(), if *value { 1.0 } else { 0.0 });
                value.to_string()
            }
            SemanticValue::Integer(value) => {
                let as_f64 = *value as f64;
                if as_f64 as i64 == *value {
                    scalars.insert(rule.path.to_string(), as_f64);
                }
                value.to_string()
            }
            SemanticValue::IntegerArray(values) => serde_json::to_string(values)?,
            SemanticValue::Real(value) => {
                if !value.is_finite() {
                    return Err(semantic_coverage_refusal(
                        format!("{} is non-finite", rule.path),
                        "Repair the source value before measurement and retry the unchanged import.",
                    ));
                }
                scalars.insert(rule.path.to_string(), *value);
                value.to_string()
            }
            SemanticValue::Text(value) => value.clone(),
            SemanticValue::TextArray(values) => serde_json::to_string(values)?,
            SemanticValue::BlobI8x768(bytes) => hex_lower(&sha256_digest(bytes)),
        };
        metadata.insert(format!("semantic.exact.{}", rule.path), exact);
    }
    Ok((scalars, metadata))
}

fn semantic_modality(values: &BTreeMap<SlotId, SemanticValue>) -> IngestResult<Modality> {
    for slot_id in values.keys() {
        let rule = semantic_rule_by_slot(*slot_id).ok_or_else(|| {
            semantic_coverage_refusal(
                format!("modality construction contains unregistered slot {slot_id}"),
                "Repair the frozen registry and re-ingest the preserved source.",
            )
        })?;
        if matches!(
            rule.kind,
            SemanticKind::LatentCode | SemanticKind::LatentProse
        ) {
            return Ok(Modality::Mixed);
        }
    }
    Ok(Modality::Structured)
}

#[allow(clippy::too_many_arguments)]
fn measure_semantic_constellation<C, R>(
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    driver: &PanelDriver,
    family: SemanticFamily,
    source_key: String,
    links: Vec<CxId>,
    values: BTreeMap<SlotId, SemanticValue>,
    retention: InputRetention,
) -> IngestResult<PreparedSemanticConstellation>
where
    C: Clock,
    R: SlotRuntime,
{
    let canonical_input_bytes = semantic_canonical_input_bytes(family, &source_key, &values)?;
    let mut slot_ids = Vec::with_capacity(values.len() + 1);
    slot_ids.push(family.presence_slot());
    slot_ids.extend(values.keys().copied());
    slot_ids.sort_unstable();
    slot_ids.dedup();
    let project_salt = vault_salt(&options.project)?;
    let cx_id = cx_id_from_canonical(
        &canonical_input_bytes,
        options.panel_version,
        project_salt.as_bytes(),
    )?;
    let input_hash = *blake3::hash(&canonical_input_bytes).as_bytes();
    let (scalars, mut metadata) = semantic_exact_sidecars(&values)?;
    let modality = semantic_modality(&values)?;
    metadata.insert("semantic.family".to_string(), family.as_str().to_string());
    metadata.insert("semantic.source_key".to_string(), source_key.clone());
    metadata.insert("input_hash_blake3".to_string(), hex_lower(&input_hash));
    let readout = driver
        .measure(
            &PanelInput::with_available_slots(SymbolLabel::Project, std::iter::empty())
                .with_scalars(scalars)
                .with_semantic_values(family, values)
                .with_legacy_slots_enabled(false),
            runtime,
        )
        .map_err(|error| {
            IngestError::refused(
                error.code(),
                format!(
                    "{} semantic row source_key={source_key:?} slots={slot_ids:?} failed frozen lens measurement: {}",
                    family.as_str(),
                    error.message()
                ),
                error.remediation(),
            )
        })?;
    let input_ref = match retention {
        InputRetention::Persist => InputRef {
            hash: input_hash,
            pointer: Some(input_store::input_pointer(&input_hash)),
            redacted: false,
        },
        InputRetention::Redact => InputRef {
            hash: input_hash,
            pointer: Some(format!(
                "cbm-sqlite://semantic/{}/{}",
                family.as_str(),
                source_key
            )),
            redacted: true,
        },
    };
    let constellation = Constellation {
        cx_id,
        vault_id: vault.vault_id(),
        panel_version: options.panel_version,
        created_at: 0,
        input_ref,
        modality,
        slots: readout.slots,
        scalars: readout.scalars,
        metadata,
        anchors: Vec::new(),
        provenance: zero_ledger_ref(),
        flags: CxFlags {
            ungrounded: true,
            degraded: false,
            novel_region: false,
            redacted_input: retention == InputRetention::Redact,
        },
    };
    constellation.validate_schema()?;
    let measured_slot_ids = constellation.slots.keys().copied().collect::<Vec<_>>();
    if measured_slot_ids != slot_ids {
        return Err(semantic_coverage_refusal(
            format!(
                "measured {} row {source_key:?} emitted slot roster {:?}, expected {:?}",
                family.as_str(),
                measured_slot_ids,
                slot_ids
            ),
            "Repair panel dispatch before publication and re-ingest the preserved source.",
        ));
    }
    Ok(PreparedSemanticConstellation {
        family,
        source_key,
        links,
        canonical_input_bytes,
        input_hash,
        cx_id,
        slot_ids,
        measured: Some(constellation),
    })
}

fn node_semantic_values(node: &ExtractedNode) -> IngestResult<BTreeMap<SlotId, SemanticValue>> {
    let family = SemanticFamily::Node;
    let mut values = BTreeMap::new();
    let node_id = node.id;
    let start_byte = i64::try_from(node.start_byte).map_err(|_| {
        invalid_sqlite(format!(
            "node {node_id} start_byte {} exceeds semantic integer range",
            node.start_byte
        ))
    })?;
    let end_byte = i64::try_from(node.end_byte).map_err(|_| {
        invalid_sqlite(format!(
            "node {node_id} end_byte {} exceeds semantic integer range",
            node.end_byte
        ))
    })?;
    insert_semantic_value(&mut values, family, "id", SemanticValue::Integer(node.id))?;
    insert_semantic_value(
        &mut values,
        family,
        "project",
        SemanticValue::Text(node.symbol.project.clone()),
    )?;
    insert_semantic_value(
        &mut values,
        family,
        "label",
        SemanticValue::Text(node.symbol.label.clone()),
    )?;
    insert_semantic_value(
        &mut values,
        family,
        "name",
        SemanticValue::Text(node.name.clone()),
    )?;
    insert_semantic_value(
        &mut values,
        family,
        "atom_id",
        SemanticValue::Text(node.atom_id.clone()),
    )?;
    insert_semantic_value(
        &mut values,
        family,
        "qualified_name",
        SemanticValue::Text(node.symbol.qualified_name.clone()),
    )?;
    insert_semantic_value(
        &mut values,
        family,
        "file_path",
        SemanticValue::Text(node.symbol.rel_file_path.clone()),
    )?;
    insert_semantic_value(
        &mut values,
        family,
        "start_line",
        SemanticValue::Integer(i64::from(node.symbol.start_line)),
    )?;
    insert_semantic_value(
        &mut values,
        family,
        "end_line",
        SemanticValue::Integer(i64::from(node.symbol.end_line)),
    )?;
    insert_semantic_value(
        &mut values,
        family,
        "source_present",
        SemanticValue::Boolean(node.symbol.source_present),
    )?;
    if node.symbol.source_present {
        let source = String::from_utf8(node.symbol.source_snippet_bytes.clone()).map_err(|error| {
            invalid_sqlite(format!(
                "node {node_id} exact source bytes are not UTF-8 for the frozen code embedder: {error}"
            ))
        })?;
        insert_semantic_value(
            &mut values,
            family,
            "source_bytes",
            SemanticValue::Text(source),
        )?;
    }
    insert_semantic_value(
        &mut values,
        family,
        "source_sha256",
        SemanticValue::Text(node.source_sha256.clone()),
    )?;
    insert_semantic_value(
        &mut values,
        family,
        "start_byte",
        SemanticValue::Integer(start_byte),
    )?;
    insert_semantic_value(
        &mut values,
        family,
        "end_byte",
        SemanticValue::Integer(end_byte),
    )?;

    let properties = node.symbol.properties_json.parse::<Value>()?;
    let object = properties.as_object().ok_or_else(|| {
        semantic_coverage_refusal(
            format!("node {node_id} properties are not an object"),
            "Rebuild the CBM SQLite source with object-valued properties and retry the unchanged import.",
        )
    })?;
    for (key, raw) in object {
        let base_path = format!("properties.{key}");
        match raw {
            Value::Bool(value) => insert_observed_semantic_value(
                &mut values,
                family,
                &format!("node {node_id}"),
                &base_path,
                SemanticValue::Boolean(*value),
            )?,
            Value::Number(number) => {
                let value = semantic_json_number(number, &format!("node {node_id}"), &base_path)?;
                insert_observed_semantic_value(
                    &mut values,
                    family,
                    &format!("node {node_id}"),
                    &base_path,
                    value,
                )?;
            }
            Value::String(value) => insert_observed_semantic_value(
                &mut values,
                family,
                &format!("node {node_id}"),
                &base_path,
                SemanticValue::Text(value.clone()),
            )?,
            Value::Array(items) => {
                let child_path = format!("{base_path}[]");
                let mut strings = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    let value = item.as_str().ok_or_else(|| {
                        semantic_coverage_refusal(
                            format!(
                                "node {node_id} atom {child_path}[{index}] is not text"
                            ),
                            "Add an explicit typed child-path rule for the observed schema, rebuild the panel, and retry the unchanged import.",
                        )
                    })?;
                    strings.push(value.to_string());
                }
                insert_observed_semantic_value(
                    &mut values,
                    family,
                    &format!("node {node_id}"),
                    &child_path,
                    SemanticValue::TextArray(strings),
                )?;
            }
            Value::Null => {}
            Value::Object(_) => {
                return Err(semantic_coverage_refusal(
                    format!("node {node_id} atom {base_path} has unsupported JSON type object"),
                    "Decompose the value into explicit typed child-path rules, rebuild the panel, and retry the unchanged import.",
                ));
            }
        }
    }
    if let Some(vector) = &node.node_vector {
        insert_semantic_value(
            &mut values,
            family,
            "node_vector",
            SemanticValue::BlobI8x768(vector.clone()),
        )?;
    }
    Ok(values)
}

fn semantic_values_from_fields(
    family: SemanticFamily,
    fields: impl IntoIterator<Item = (&'static str, SemanticValue)>,
) -> IngestResult<BTreeMap<SlotId, SemanticValue>> {
    let mut values = BTreeMap::new();
    for (path, value) in fields {
        insert_semantic_value(&mut values, family, path, value)?;
    }
    Ok(values)
}

fn edge_semantic_values(edge: &RawEdgeRow) -> IngestResult<BTreeMap<SlotId, SemanticValue>> {
    let family = SemanticFamily::Edge;
    let mut values = semantic_values_from_fields(
        family,
        [
            ("id", SemanticValue::Integer(edge.id)),
            ("project", SemanticValue::Text(edge.project.clone())),
            ("source_id", SemanticValue::Integer(edge.source_id)),
            ("target_id", SemanticValue::Integer(edge.target_id)),
            ("type", SemanticValue::Text(edge.edge_type.clone())),
            (
                "local_name_gen",
                SemanticValue::Text(edge.local_name_gen.clone()),
            ),
            (
                "preprocess_context_id_gen",
                SemanticValue::Text(edge.preprocess_context_id_gen.clone()),
            ),
            (
                "url_path_gen",
                SemanticValue::Text(edge.url_path_gen.clone()),
            ),
        ],
    )?;
    let object = edge.properties.as_object().ok_or_else(|| {
        semantic_coverage_refusal(
            format!("edge {} properties are not an object", edge.id),
            "Rebuild the CBM SQLite source with object-valued properties and retry the unchanged import.",
        )
    })?;
    for (key, raw) in object {
        let base_path = format!("properties.{key}");
        match raw {
            Value::Null => {}
            Value::Bool(value) => insert_observed_semantic_value(
                &mut values,
                family,
                &format!("edge {}", edge.id),
                &base_path,
                SemanticValue::Boolean(*value),
            )?,
            Value::Number(number) => {
                let value = semantic_json_number(number, &format!("edge {}", edge.id), &base_path)?;
                insert_observed_semantic_value(
                    &mut values,
                    family,
                    &format!("edge {}", edge.id),
                    &base_path,
                    value,
                )?;
            }
            Value::String(value) => insert_observed_semantic_value(
                &mut values,
                family,
                &format!("edge {}", edge.id),
                &base_path,
                SemanticValue::Text(value.clone()),
            )?,
            Value::Array(items) if key == "args" => {
                let argument_count = i64::try_from(items.len()).map_err(|_| {
                    semantic_coverage_refusal(
                        format!(
                            "edge {} properties.args length exceeds signed integer range",
                            edge.id
                        ),
                        "Repair the source row before semantic publication and retry the unchanged import.",
                    )
                })?;
                insert_semantic_value(
                    &mut values,
                    family,
                    "properties.args.count",
                    SemanticValue::Integer(argument_count),
                )?;
                let mut integers = Vec::new();
                let mut expressions = Vec::new();
                let mut keys = Vec::new();
                let mut raw_values = Vec::new();
                for (index, item) in items.iter().enumerate() {
                    let child = item.as_object().ok_or_else(|| {
                        semantic_coverage_refusal(
                            format!(
                                "edge {} atom properties.args[{index}] is not an object",
                                edge.id
                            ),
                            "Decompose the observed array item into frozen typed child paths, rebuild the panel, and retry the unchanged import.",
                        )
                    })?;
                    for (child_key, child_value) in child {
                        match (child_key.as_str(), child_value) {
                            ("i", Value::Number(number)) => integers.push(
                                number.as_i64().ok_or_else(|| {
                                    semantic_coverage_refusal(
                                        format!(
                                            "edge {} atom properties.args[{index}].i is not a signed integer",
                                            edge.id
                                        ),
                                        "Version the registry with its exact numeric type, rebuild the panel, and retry the unchanged import.",
                                    )
                                })?,
                            ),
                            ("e", Value::String(value)) => expressions.push(value.clone()),
                            ("k", Value::String(value)) => keys.push(value.clone()),
                            ("v", Value::String(value)) => raw_values.push(value.clone()),
                            (_, Value::Null) => {}
                            _ => {
                                return Err(semantic_coverage_refusal(
                                    format!(
                                        "edge {} has unregistered atom properties.args[{index}].{child_key} with JSON type {}",
                                        edge.id,
                                        match child_value {
                                            Value::Null => "null",
                                            Value::Bool(_) => "boolean",
                                            Value::Number(_) => "number",
                                            Value::String(_) => "text",
                                            Value::Array(_) => "array",
                                            Value::Object(_) => "object",
                                        }
                                    ),
                                    "Add an exact typed child-path rule, rebuild the panel, and retry the unchanged import.",
                                ));
                            }
                        }
                    }
                }
                if !integers.is_empty() {
                    insert_semantic_value(
                        &mut values,
                        family,
                        "properties.args[].i",
                        SemanticValue::IntegerArray(integers),
                    )?;
                }
                if !expressions.is_empty() {
                    insert_semantic_value(
                        &mut values,
                        family,
                        "properties.args[].e",
                        SemanticValue::TextArray(expressions),
                    )?;
                }
                if !keys.is_empty() {
                    insert_semantic_value(
                        &mut values,
                        family,
                        "properties.args[].k",
                        SemanticValue::TextArray(keys),
                    )?;
                }
                if !raw_values.is_empty() {
                    insert_semantic_value(
                        &mut values,
                        family,
                        "properties.args[].v",
                        SemanticValue::TextArray(raw_values),
                    )?;
                }
            }
            Value::Array(_) | Value::Object(_) => {
                return Err(semantic_coverage_refusal(
                    format!(
                        "edge {} atom {base_path} has an unregistered nested shape",
                        edge.id
                    ),
                    "Decompose it into exact frozen typed child-path rules, rebuild the panel, and retry the unchanged import.",
                ));
            }
        }
    }
    Ok(values)
}

fn build_non_node_semantic_inputs(
    metadata: &RawMetadataRows,
    edges: &[RawEdgeRow],
    nodes: &[PreparedLiveSymbol],
    panel_version: u32,
) -> IngestResult<Vec<SemanticInputRow>> {
    let node_cx = nodes
        .iter()
        .map(|node| (node.node_id, node.identity.cx_id))
        .collect::<BTreeMap<_, _>>();
    let mut rows = Vec::new();
    let mut project_cx = BTreeMap::new();
    for project in &metadata.projects {
        let values = semantic_values_from_fields(
            SemanticFamily::Project,
            [
                ("name", SemanticValue::Text(project.name.clone())),
                (
                    "indexed_at",
                    SemanticValue::Text(project.indexed_at.clone()),
                ),
                ("root_path", SemanticValue::Text(project.root_path.clone())),
            ],
        )?;
        let canonical =
            semantic_canonical_input_bytes(SemanticFamily::Project, &project.name, &values)?;
        let salt = vault_salt(&project.name)?;
        let cx_id = cx_id_from_canonical(&canonical, panel_version, salt.as_bytes())?;
        project_cx.insert(project.name.clone(), cx_id);
        rows.push(SemanticInputRow {
            family: SemanticFamily::Project,
            source_key: project.name.clone(),
            links: Vec::new(),
            values,
        });
    }
    let project_link = |project: &str, family: SemanticFamily, source_key: &str| {
        project_cx
            .get(project)
            .copied()
            .map(|cx_id| vec![cx_id])
            .ok_or_else(|| {
                semantic_coverage_refusal(
                    format!(
                        "{} row {source_key:?} references missing project {project:?}",
                        family.as_str()
                    ),
                    "Repair the CBM project relation before semantic publication and retry the unchanged import.",
                )
            })
    };
    for file in &metadata.file_hashes {
        rows.push(SemanticInputRow {
            family: SemanticFamily::FileHash,
            source_key: file.rel_path.clone(),
            links: project_link(&file.project, SemanticFamily::FileHash, &file.rel_path)?,
            values: semantic_values_from_fields(
                SemanticFamily::FileHash,
                [
                    ("project", SemanticValue::Text(file.project.clone())),
                    ("rel_path", SemanticValue::Text(file.rel_path.clone())),
                    ("sha256", SemanticValue::Text(file.sha256.clone())),
                    ("mtime_ns", SemanticValue::Integer(file.mtime_ns)),
                    ("size", SemanticValue::Integer(file.size)),
                ],
            )?,
        });
    }
    for summary in &metadata.project_summaries {
        rows.push(SemanticInputRow {
            family: SemanticFamily::ProjectSummary,
            source_key: summary.project.clone(),
            links: project_link(
                &summary.project,
                SemanticFamily::ProjectSummary,
                &summary.project,
            )?,
            values: semantic_values_from_fields(
                SemanticFamily::ProjectSummary,
                [
                    ("project", SemanticValue::Text(summary.project.clone())),
                    ("summary", SemanticValue::Text(summary.summary.clone())),
                    (
                        "source_hash",
                        SemanticValue::Text(summary.source_hash.clone()),
                    ),
                    (
                        "created_at",
                        SemanticValue::Text(summary.created_at.clone()),
                    ),
                    (
                        "updated_at",
                        SemanticValue::Text(summary.updated_at.clone()),
                    ),
                ],
            )?,
        });
    }
    for token in &metadata.token_vectors {
        rows.push(SemanticInputRow {
            family: SemanticFamily::TokenVector,
            source_key: token.id.to_string(),
            links: project_link(
                &token.project,
                SemanticFamily::TokenVector,
                &token.id.to_string(),
            )?,
            values: semantic_values_from_fields(
                SemanticFamily::TokenVector,
                [
                    ("id", SemanticValue::Integer(token.id)),
                    ("project", SemanticValue::Text(token.project.clone())),
                    ("token", SemanticValue::Text(token.token.clone())),
                    ("vector", SemanticValue::BlobI8x768(token.vector.clone())),
                    ("idf", SemanticValue::Integer(token.idf)),
                ],
            )?,
        });
    }
    for node in nodes {
        if let Some(vector) = &node.node_vector {
            rows.push(SemanticInputRow {
                family: SemanticFamily::NodeVector,
                source_key: node.node_id.to_string(),
                links: vec![node.identity.cx_id],
                values: semantic_values_from_fields(
                    SemanticFamily::NodeVector,
                    [
                        ("node_id", SemanticValue::Integer(node.node_id)),
                        ("project", SemanticValue::Text(node.symbol.project.clone())),
                        ("vector", SemanticValue::BlobI8x768(vector.clone())),
                    ],
                )?,
            });
        }
    }
    for edge in edges {
        let src = node_cx.get(&edge.source_id).copied().ok_or_else(|| {
            semantic_coverage_refusal(
                format!(
                    "edge {} source node {} has no constellation",
                    edge.id, edge.source_id
                ),
                "Repair the CBM relation before semantic publication and retry the unchanged import.",
            )
        })?;
        let dst = node_cx.get(&edge.target_id).copied().ok_or_else(|| {
            semantic_coverage_refusal(
                format!(
                    "edge {} target node {} has no constellation",
                    edge.id, edge.target_id
                ),
                "Repair the CBM relation before semantic publication and retry the unchanged import.",
            )
        })?;
        rows.push(SemanticInputRow {
            family: SemanticFamily::Edge,
            source_key: edge.id.to_string(),
            links: vec![src, dst],
            values: edge_semantic_values(edge)?,
        });
    }
    Ok(rows)
}

fn semantic_constellation_graph_key(
    project_digest: &[u8; 32],
    family: SemanticFamily,
    source_key: &str,
) -> Vec<u8> {
    let mut discriminator = Vec::new();
    append_semantic_frame(&mut discriminator, family.as_str().as_bytes());
    append_semantic_frame(&mut discriminator, source_key.as_bytes());
    keyed_graph_key_with_digest(
        SEMANTIC_CONSTELLATION_ROW_PREFIX,
        project_digest,
        &discriminator,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_non_node_semantic_constellations<C, R>(
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    driver: &PanelDriver,
    inputs: Vec<SemanticInputRow>,
    sqlite_fingerprint: [u8; 32],
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    preserved_keys: &mut BTreeSet<Vec<u8>>,
    coverage: &mut SemanticCoverageAccumulator,
    retention: InputRetention,
) -> IngestResult<(Vec<PreparedSemanticConstellation>, Vec<(Vec<u8>, Vec<u8>)>)>
where
    C: Clock,
    R: SlotRuntime + Sync,
{
    let project_digest = sha256_digest(options.project.as_bytes());
    let registry_sha256 = hex_lower(&semantic_registry_sha256());
    let fingerprint = hex_lower(&sqlite_fingerprint);
    let project_salt = vault_salt(&options.project)?;
    let mut reused = Vec::new();
    let mut to_measure = Vec::new();
    for input in inputs {
        coverage.observe(input.family, &input.values)?;
        let canonical_input_bytes =
            semantic_canonical_input_bytes(input.family, &input.source_key, &input.values)?;
        let cx_id = cx_id_from_canonical(
            &canonical_input_bytes,
            options.panel_version,
            project_salt.as_bytes(),
        )?;
        let mut slot_ids = Vec::with_capacity(input.values.len() + 1);
        slot_ids.push(input.family.presence_slot());
        slot_ids.extend(input.values.keys().copied());
        slot_ids.sort_unstable();
        slot_ids.dedup();
        let input_hash = *blake3::hash(&canonical_input_bytes).as_bytes();
        let graph_row = SemanticConstellationGraphRow {
            schema: SCHEMA_SEMANTIC_CONSTELLATION_ROW.to_string(),
            project: options.project.clone(),
            family: input.family.as_str().to_string(),
            source_key: input.source_key.clone(),
            panel_version: options.panel_version,
            cx_id,
            input_hash_blake3: hex_lower(&input_hash),
            registry_sha256: registry_sha256.clone(),
            sqlite_fingerprint_sha256: fingerprint.clone(),
            slot_ids: slot_ids.iter().map(|slot| slot.get()).collect(),
            links: input.links.clone(),
        };
        let key =
            semantic_constellation_graph_key(&project_digest, input.family, &input.source_key);
        let mut expected = serde_json::to_vec(&graph_row)?;
        append_import_fingerprint(&mut expected, sqlite_fingerprint)?;
        let semantically_unchanged = existing_graph
            .get(&key)
            .map(|persisted| {
                Ok::<bool, IngestError>(
                    graph_semantic_json(persisted)? == graph_semantic_json(&expected)?,
                )
            })
            .transpose()?
            .unwrap_or(false);
        if semantically_unchanged {
            preserved_keys.insert(key);
            reused.push(PreparedSemanticConstellation {
                family: input.family,
                source_key: input.source_key,
                links: input.links,
                canonical_input_bytes: Vec::new(),
                input_hash,
                cx_id,
                slot_ids,
                measured: None,
            });
        } else {
            to_measure.push((input, cx_id, slot_ids, key, expected));
        }
    }
    let measured = parallel_map(
        to_measure,
        options.workers,
        |(input, expected_cx, expected_slots, key, value)| {
            let prepared = measure_semantic_constellation(
                vault,
                runtime,
                options,
                driver,
                input.family,
                input.source_key,
                input.links,
                input.values,
                retention,
            )?;
            if prepared.cx_id != expected_cx {
                return Err(semantic_coverage_refusal(
                    format!(
                        "{} semantic identity changed between planning and measurement",
                        prepared.family.as_str()
                    ),
                    "Preserve the source, repair nondeterministic canonicalization, and retry the unchanged import.",
                ));
            }
            if prepared.slot_ids != expected_slots {
                return Err(semantic_coverage_refusal(
                    format!(
                        "{} semantic slot roster changed between planning and measurement",
                        prepared.family.as_str()
                    ),
                    "Preserve the source, repair nondeterministic panel dispatch, and retry the unchanged import.",
                ));
            }
            Ok((prepared, (key, value)))
        },
    )?;
    let mut graph_rows = Vec::with_capacity(measured.len());
    for (prepared, graph_row) in measured {
        reused.push(prepared);
        graph_rows.push(graph_row);
    }
    reused.sort_by(|left, right| {
        left.family
            .cmp(&right.family)
            .then_with(|| left.source_key.cmp(&right.source_key))
    });
    graph_rows.sort_by(|left, right| left.0.cmp(&right.0));
    Ok((reused, graph_rows))
}

fn prepare_constellation<C, R>(
    vault: &AsterVault<C>,
    runtime: &R,
    options: &SqliteImportOptions,
    driver: &PanelDriver,
    node: ExtractedNode,
    identity: SymbolIdentity,
    semantic_values: BTreeMap<SlotId, SemanticValue>,
    retention: InputRetention,
) -> IngestResult<PreparedConstellation>
where
    C: Clock,
    R: SlotRuntime,
{
    let semantic_value_slots = semantic_values.keys().copied().collect::<Vec<_>>();
    let legacy_slots_enabled = !node.label.is_structural();
    let mut input = PanelInput::with_available_slots(node.label, options.available_slots.clone())
        .with_scalars(node.symbol.scalars.clone())
        .with_semantic_values(SemanticFamily::Node, semantic_values)
        .with_legacy_slots_enabled(legacy_slots_enabled);
    input.source_bytes = node.symbol.source_snippet_bytes.clone();
    input.symbol_name = node.symbol.symbol_name.clone();
    input.qualified_name = node.symbol.qualified_name.clone();
    input.rel_file_path = node.symbol.rel_file_path.clone();
    input.language = node.symbol.language.clone();
    input.signature = node.symbol.signature.clone();
    input.properties = serde_json::from_str(&node.symbol.properties_json)?;
    let readout = driver.measure(&input, runtime).map_err(|error| {
        IngestError::refused(
            error.code(),
            format!(
                "node semantic row id={} qualified_name={:?} slots={semantic_value_slots:?} failed frozen lens measurement: {}",
                node.id,
                node.symbol.qualified_name,
                error.message()
            ),
            error.remediation(),
        )
    })?;
    // #980: retain the exact complete property object. Every present atom is now
    // independently encoded, but the source bytes remain the reconstruction
    // authority for the zero-gap witness and schema-drift audit.
    let properties_json = node.properties_json.clone();
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
        atom_id: node.atom_id,
        name: node.name,
        properties_json,
        node_vector: node.node_vector,
        symbol: node.symbol,
        identity,
        constellation,
        semantic_value_slots,
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
    metadata.insert(
        "symbol_canonical_schema".to_string(),
        SYMBOL_CANONICAL_TAG.to_string(),
    );
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
    let (source_present, source_ref, source_sha256, start_byte, end_byte) =
        symbol_exact_source_contract(&prepared.symbol)?;
    let row = NodeMapRow {
        schema: SCHEMA_NODE_MAP.to_string(),
        series_id_schema: SERIES_ID_TAG.to_string(),
        project: prepared.symbol.project.clone(),
        node_id: prepared.node_id,
        atom_id: prepared.atom_id.clone(),
        qualified_name: prepared.symbol.qualified_name.clone(),
        label: prepared.symbol.label.clone(),
        cx_id: prepared.identity.cx_id,
        series_id: prepared.identity.series_id,
        file_path: prepared.symbol.rel_file_path.clone(),
        commit: options.commit.clone(),
        name: prepared.name.clone(),
        start_line: i64::from(prepared.symbol.start_line),
        end_line: i64::from(prepared.symbol.end_line),
        source_present,
        source_bytes: Vec::new(),
        source_ref,
        source_sha256,
        start_byte,
        end_byte,
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
    let (source_present, source_ref, source_sha256, start_byte, end_byte) =
        symbol_exact_source_contract(&node.symbol)?;
    let row = StructuralNodeRow {
        schema: SCHEMA_STRUCTURAL_NODE.to_string(),
        project: node.symbol.project.clone(),
        node_id: node.id,
        atom_id: node.atom_id.clone(),
        qualified_name: node.symbol.qualified_name.clone(),
        label: node.symbol.label.clone(),
        name: node.name.clone(),
        file_path: node.symbol.rel_file_path.clone(),
        commit: options.commit.clone(),
        start_line: i64::from(node.symbol.start_line),
        end_line: i64::from(node.symbol.end_line),
        source_present,
        source_bytes: Vec::new(),
        source_ref,
        source_sha256,
        start_byte,
        end_byte,
        properties_json: Some(node.properties_json.clone()),
        node_vector: node.node_vector.clone(),
    };
    Ok((
        graph_key(STRUCTURAL_NODE_PREFIX, &node.symbol.project, node.id)?,
        serde_json::to_vec(&row)?,
    ))
}

fn symbol_exact_source_contract(
    symbol: &SymbolRecord,
) -> IngestResult<(bool, Option<ExactSourceRef>, String, u64, u64)> {
    let scalar_u64 = |name: &str| -> IngestResult<u64> {
        let value = symbol.scalars.get(name).copied().ok_or_else(|| {
            IngestError::InvalidInput(format!(
                "symbol {} is missing required {name} exact-source scalar",
                symbol.qualified_name
            ))
        })?;
        if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > u64::MAX as f64 {
            return Err(IngestError::InvalidInput(format!(
                "symbol {} has invalid {name} exact-source scalar {value}",
                symbol.qualified_name
            )));
        }
        Ok(value as u64)
    };
    let source_present = symbol.source_present;
    let start_byte = scalar_u64("start_byte")?;
    let end_byte = scalar_u64("end_byte")?;
    if source_present {
        if end_byte < start_byte
            || end_byte - start_byte != symbol.source_snippet_bytes.len() as u64
        {
            return Err(IngestError::InvalidInput(format!(
                "symbol {} exact source length {} disagrees with span {start_byte}..{end_byte}",
                symbol.qualified_name,
                symbol.source_snippet_bytes.len()
            )));
        }
        let input_hash = *blake3::hash(&symbol.source_snippet_bytes).as_bytes();
        Ok((
            true,
            Some(ExactSourceRef {
                schema: SCHEMA_EXACT_SOURCE_REF.to_string(),
                input_hash_blake3: input_hash,
                pointer: input_store::input_pointer(&input_hash),
                byte_len: symbol.source_snippet_bytes.len() as u64,
            }),
            hex_lower(&sha256_digest(&symbol.source_snippet_bytes)),
            start_byte,
            end_byte,
        ))
    } else {
        if !symbol.source_snippet_bytes.is_empty() || start_byte != 0 || end_byte != 0 {
            return Err(IngestError::InvalidInput(format!(
                "symbol {} carries source bytes or a span without source presence",
                symbol.qualified_name
            )));
        }
        Ok((false, None, String::new(), 0, 0))
    }
}

fn graph_row_exact_source_ref(key: &[u8], value: &[u8]) -> IngestResult<Option<ExactSourceRef>> {
    let (schema, source_present, source_bytes, source_ref) = if key.starts_with(NODE_MAP_PREFIX) {
        let row: NodeMapRow = decode_graph_row(key, value)?;
        (
            row.schema,
            row.source_present,
            row.source_bytes,
            row.source_ref,
        )
    } else if key.starts_with(STRUCTURAL_NODE_PREFIX) {
        let row: StructuralNodeRow = decode_graph_row(key, value)?;
        (
            row.schema,
            row.source_present,
            row.source_bytes,
            row.source_ref,
        )
    } else {
        return Ok(None);
    };
    let modern = schema == SCHEMA_NODE_MAP || schema == SCHEMA_STRUCTURAL_NODE;
    if !modern {
        return Ok(None);
    }
    if !source_bytes.is_empty() {
        return Err(IngestError::InvalidInput(format!(
            "modern graph row schema {schema} inlines exact source bytes"
        )));
    }
    match (source_present, source_ref) {
        (true, Some(reference)) => {
            if reference.schema != SCHEMA_EXACT_SOURCE_REF
                || reference.pointer != input_store::input_pointer(&reference.input_hash_blake3)
            {
                return Err(IngestError::InvalidInput(format!(
                    "modern graph row schema {schema} has a malformed exact-source reference"
                )));
            }
            Ok(Some(reference))
        }
        (false, None) => Ok(None),
        (true, None) => Err(IngestError::InvalidInput(format!(
            "modern graph row schema {schema} declares exact source without a reference"
        ))),
        (false, Some(_)) => Err(IngestError::InvalidInput(format!(
            "modern graph row schema {schema} references source while source_present=false"
        ))),
    }
}

fn supported_node_map_schema(schema: &str) -> bool {
    schema == SCHEMA_NODE_MAP || schema == LEGACY_SCHEMA_NODE_MAP_V3
}

fn supported_structural_node_schema(schema: &str) -> bool {
    schema == SCHEMA_STRUCTURAL_NODE || schema == LEGACY_SCHEMA_STRUCTURAL_NODE_V2
}

#[allow(clippy::too_many_arguments)]
fn read_exact_source_at<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    row_kind: &str,
    node_id: i64,
    schema: &str,
    modern_schema: &str,
    legacy_schema: &str,
    source_present: bool,
    inline_source_bytes: &[u8],
    source_ref: Option<&ExactSourceRef>,
    source_sha256: &str,
    start_byte: u64,
    end_byte: u64,
) -> IngestResult<Vec<u8>>
where
    C: Clock,
{
    let invalid = |detail: String| {
        IngestError::refused(
            ASTRO_EXACT_SOURCE_INVALID,
            format!("{row_kind} node {node_id}: {detail}"),
            EXACT_SOURCE_REMEDIATION,
        )
    };
    if schema != modern_schema && schema != legacy_schema {
        return Err(invalid(format!("unsupported schema {schema}")));
    }
    if !source_present {
        if !inline_source_bytes.is_empty()
            || source_ref.is_some()
            || !source_sha256.is_empty()
            || start_byte != 0
            || end_byte != 0
        {
            return Err(invalid(
                "source_present=false carries source payload, reference, digest, or span".into(),
            ));
        }
        return Ok(Vec::new());
    }
    if end_byte < start_byte {
        return Err(invalid(format!(
            "source span {start_byte}..{end_byte} is reversed"
        )));
    }
    let expected_len = end_byte - start_byte;
    let bytes = if schema == modern_schema {
        if !inline_source_bytes.is_empty() {
            return Err(invalid(
                "modern row inlines source bytes instead of using Blob-CF key/value separation"
                    .into(),
            ));
        }
        let reference = source_ref.ok_or_else(|| {
            invalid("modern row declares source without an exact-source reference".into())
        })?;
        if reference.schema != SCHEMA_EXACT_SOURCE_REF {
            return Err(invalid(format!(
                "exact-source reference has schema {}",
                reference.schema
            )));
        }
        let expected_pointer = input_store::input_pointer(&reference.input_hash_blake3);
        if reference.pointer != expected_pointer {
            return Err(invalid(format!(
                "exact-source pointer {:?} does not match its BLAKE3 address",
                reference.pointer
            )));
        }
        if reference.byte_len != expected_len {
            return Err(invalid(format!(
                "exact-source reference length {} disagrees with span length {expected_len}",
                reference.byte_len
            )));
        }
        input_store::reassemble_and_verify(&reference.input_hash_blake3, |key| {
            vault.read_cf_at(snapshot, ColumnFamily::Blob, key)
        })
        .map_err(|error| invalid(format!("Blob-CF exact-source readback failed: {error}")))?
    } else {
        if source_ref.is_some() {
            return Err(invalid(
                "legacy inline row unexpectedly carries an exact-source reference".into(),
            ));
        }
        inline_source_bytes.to_vec()
    };
    if bytes.len() as u64 != expected_len {
        return Err(invalid(format!(
            "source payload length {} disagrees with span length {expected_len}",
            bytes.len()
        )));
    }
    let actual_sha256 = hex_lower(&sha256_digest(&bytes));
    if source_sha256 != actual_sha256 {
        return Err(invalid(format!(
            "source SHA-256 {source_sha256:?} does not match persisted bytes {actual_sha256}"
        )));
    }
    Ok(bytes)
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
        && row.preprocess_context_id_gen == prepared.row.preprocess_context_id_gen
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

struct ImportSemanticReadback<'a> {
    prepared: &'a PreparedBatch,
    prepared_by_cx: BTreeMap<CxId, &'a PreparedLiveSymbol>,
    semantic_by_cx: BTreeMap<CxId, &'a PreparedSemanticConstellation>,
    graph_writes: BTreeMap<&'a [u8], &'a [u8]>,
    edge_writes: BTreeMap<&'a [u8], &'a PreparedEdgeRow>,
    ledger_ref: &'a LedgerRef,
    base_rows_verified: usize,
    slot_rows_verified: usize,
    graph_rows_verified: usize,
    edge_rows_verified: usize,
    raw_guard_slot_rows_verified: usize,
    blob_rows_verified: usize,
    expected_base_rows: usize,
    expected_slot_rows: usize,
    expected_graph_rows: usize,
    expected_edge_rows: usize,
    expected_raw_guard_slot_rows: usize,
    expected_blob_rows: usize,
}

impl<'a> ImportSemanticReadback<'a> {
    fn new(
        prepared: &'a PreparedBatch,
        quantization_gate: Option<&QuantizationGateConfig>,
        changes: &'a GraphRowChanges,
        existing_graph: &'a BTreeMap<Vec<u8>, Vec<u8>>,
        ledger_ref: &'a LedgerRef,
        expected_blob_rows: usize,
    ) -> IngestResult<Self> {
        let graph_writes = changes
            .graph_writes
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice()))
            .collect::<BTreeMap<_, _>>();
        let edge_writes_by_key = changes
            .edge_writes
            .iter()
            .map(|(key, _)| key.as_slice())
            .collect::<BTreeSet<_>>();
        let edge_writes = prepared
            .edge_rows
            .iter()
            .filter(|edge| edge_writes_by_key.contains(edge.key.as_slice()))
            .map(|edge| (edge.key.as_slice(), edge))
            .collect::<BTreeMap<_, _>>();
        if edge_writes.len() != changes.edge_writes.len() {
            return Err(readback_mismatch(format!(
                "semantic readback planned {} typed edge writes but the commit delta names {}",
                edge_writes.len(),
                changes.edge_writes.len()
            )));
        }

        let mut graph_rows_verified = 0;
        for (key, expected) in &prepared.graph_rows {
            if graph_writes.contains_key(key.as_slice()) {
                continue;
            }
            if existing_graph.get(key.as_slice()) != Some(expected) {
                return Err(readback_mismatch(format!(
                    "unwritten Graph CF row {} diverged from the shared persisted pre-commit scan",
                    hex_lower(key)
                )));
            }
            graph_rows_verified += 1;
        }
        let mut edge_rows_verified = 0;
        for edge in &prepared.edge_rows {
            if edge_writes.contains_key(edge.key.as_slice()) {
                continue;
            }
            if !changes.unchanged_edge_keys.contains(&edge.key)
                || !existing_graph.contains_key(&edge.key)
            {
                return Err(readback_mismatch(format!(
                    "typed edge {} is neither in the commit nor proven unchanged",
                    hex_lower(&edge.key)
                )));
            }
            edge_rows_verified += 1;
            graph_rows_verified += 1;
        }

        let prepared_by_cx = prepared
            .constellations
            .iter()
            .map(|prepared| (prepared.identity.cx_id, prepared))
            .collect::<BTreeMap<_, _>>();
        if prepared_by_cx.len() != prepared.constellations.len() {
            return Err(readback_mismatch(
                "prepared node constellations contain a duplicate CxId",
            ));
        }
        let semantic_by_cx = prepared
            .semantic_constellations
            .iter()
            .map(|prepared| (prepared.cx_id, prepared))
            .collect::<BTreeMap<_, _>>();
        if semantic_by_cx.len() != prepared.semantic_constellations.len() {
            return Err(readback_mismatch(
                "prepared semantic constellations contain a duplicate CxId",
            ));
        }
        if prepared_by_cx
            .keys()
            .any(|cx_id| semantic_by_cx.contains_key(cx_id))
        {
            return Err(readback_mismatch(
                "node and non-node semantic constellations collide on a CxId",
            ));
        }
        let base_rows_verified = prepared
            .constellations
            .iter()
            .filter(|prepared| prepared.measured.is_none())
            .count()
            + prepared
                .semantic_constellations
                .iter()
                .filter(|prepared| prepared.measured.is_none())
                .count();
        Ok(Self {
            prepared,
            prepared_by_cx,
            semantic_by_cx,
            graph_writes,
            edge_writes,
            ledger_ref,
            base_rows_verified,
            slot_rows_verified: 0,
            graph_rows_verified,
            edge_rows_verified,
            raw_guard_slot_rows_verified: 0,
            blob_rows_verified: 0,
            expected_base_rows: prepared.constellations.len()
                + prepared.semantic_constellations.len(),
            expected_slot_rows: prepared
                .constellations
                .iter()
                .filter_map(|prepared| prepared.measured.as_ref())
                .chain(
                    prepared
                        .semantic_constellations
                        .iter()
                        .filter_map(|prepared| prepared.measured.as_ref()),
                )
                .map(|constellation| constellation.slots.len())
                .sum(),
            expected_graph_rows: prepared.graph_rows.len() + prepared.edge_rows.len(),
            expected_edge_rows: prepared.edge_rows.len(),
            expected_raw_guard_slot_rows: quantization_gate
                .map(|gate| expected_raw_guard_slot_rows(prepared, gate))
                .unwrap_or(0),
            expected_blob_rows,
        })
    }

    fn observe(
        &mut self,
        cf: ColumnFamily,
        key: &[u8],
        persisted: Option<&[u8]>,
    ) -> IngestResult<()> {
        let Some(bytes) = persisted else {
            return Ok(());
        };
        if is_tombstone_value(bytes) {
            return Ok(());
        }
        match cf {
            ColumnFamily::Base => {
                let decoded = encode::decode_constellation_base(bytes)?;
                if let Some(prepared) = self.prepared_by_cx.get(&decoded.cx_id) {
                    let expected = prepared.measured.as_ref().ok_or_else(|| {
                        readback_mismatch(format!(
                            "reused constellation {} unexpectedly appeared in the commit readback",
                            decoded.cx_id
                        ))
                    })?;
                    verify_live_base_fields(&decoded, prepared, expected)?;
                } else if let Some(prepared) = self.semantic_by_cx.get(&decoded.cx_id) {
                    let expected = prepared.measured.as_ref().ok_or_else(|| {
                        readback_mismatch(format!(
                            "reused semantic constellation {} unexpectedly appeared in the commit readback",
                            decoded.cx_id
                        ))
                    })?;
                    verify_semantic_base_fields(&decoded, prepared, expected)?;
                } else {
                    return Err(readback_mismatch(format!(
                        "committed Base row {} is absent from the prepared import",
                        decoded.cx_id
                    )));
                }
                if decoded.provenance != *self.ledger_ref {
                    return Err(readback_mismatch(format!(
                        "Base row {} provenance differs from the exact commit ledger reference",
                        decoded.cx_id
                    )));
                }
                self.base_rows_verified += 1;
            }
            ColumnFamily::Slot { slot, kind } => {
                let cx_id = cx_id_from_row_key("Slot", key)?;
                let constellation = if let Some(prepared) = self.prepared_by_cx.get(&cx_id) {
                    prepared.measured.as_ref()
                } else if let Some(prepared) = self.semantic_by_cx.get(&cx_id) {
                    prepared.measured.as_ref()
                } else {
                    return Err(readback_mismatch(format!(
                        "committed slot {slot} row names unprepared constellation {cx_id}"
                    )));
                }
                .ok_or_else(|| {
                    readback_mismatch(format!(
                        "committed slot {slot} row belongs to reused constellation {cx_id}"
                    ))
                })?;
                let expected = constellation.slots.get(&slot).ok_or_else(|| {
                    readback_mismatch(format!(
                        "committed slot {slot} has no prepared vector for {cx_id}"
                    ))
                })?;
                match kind {
                    calyx_aster::cf::SlotFamilyKind::Quantized => {
                        let decoded = encode::decode_slot_vector(bytes)?;
                        if &decoded != expected {
                            return Err(readback_mismatch(format!(
                                "slot {slot} bytes decoded to a different vector for {cx_id}"
                            )));
                        }
                        self.slot_rows_verified += 1;
                    }
                    calyx_aster::cf::SlotFamilyKind::Raw => {
                        if bytes != encode::encode_slot_vector(expected)?.as_slice() {
                            return Err(readback_mismatch(format!(
                                "guard raw slot {slot} CF bytes changed for {cx_id}"
                            )));
                        }
                        self.raw_guard_slot_rows_verified += 1;
                    }
                }
            }
            ColumnFamily::Blob => {
                if !input_store::verify_encoded_input_row(key, bytes)? {
                    return Err(readback_mismatch(format!(
                        "import committed non-input-store Blob row {}",
                        hex_lower(key)
                    )));
                }
                self.blob_rows_verified += 1;
            }
            ColumnFamily::Graph => {
                if let Some(prepared_edge) = self.edge_writes.get(key) {
                    let decoded =
                        serde_json::from_slice::<EdgeGraphRow>(bytes).map_err(|error| {
                            readback_mismatch(format!("decode edge Graph CF row: {error}"))
                        })?;
                    if !edge_row_matches_prepared(&decoded, prepared_edge)
                        || decoded.provenance != *self.ledger_ref
                    {
                        return Err(readback_mismatch(
                            "edge Graph CF row fields or provenance changed after import",
                        ));
                    }
                    self.edge_rows_verified += 1;
                    self.graph_rows_verified += 1;
                } else if let Some(expected) = self.graph_writes.get(key) {
                    if bytes != *expected {
                        return Err(readback_mismatch("Graph CF row bytes changed after import"));
                    }
                    if let Some(reference) = graph_row_exact_source_ref(key, bytes)? {
                        let prepared_source = self
                            .prepared
                            .exact_sources
                            .get(&reference.input_hash_blake3)
                            .ok_or_else(|| {
                                readback_mismatch(format!(
                                    "written Graph row references unowned exact source {}",
                                    hex_lower(&reference.input_hash_blake3)
                                ))
                            })?;
                        let source = prepared_exact_source_bytes(
                            prepared_source,
                            &self.prepared.constellations,
                        )?;
                        if source.len() as u64 != reference.byte_len
                            || blake3::hash(source).as_bytes() != &reference.input_hash_blake3
                        {
                            return Err(readback_mismatch(format!(
                                "Graph row exact-source contract differs for {}",
                                hex_lower(&reference.input_hash_blake3)
                            )));
                        }
                    }
                    self.graph_rows_verified += 1;
                } else {
                    return Err(readback_mismatch(format!(
                        "live Graph row {} was not named by the semantic commit plan",
                        hex_lower(key)
                    )));
                }
            }
            other => {
                return Err(readback_mismatch(format!(
                    "SQLite import committed unexpected {} row {}",
                    other.name(),
                    hex_lower(key)
                )));
            }
        }
        Ok(())
    }

    fn finish(self, physical: VaultMutationReadbackMetrics) -> IngestResult<SqliteImportReadback> {
        if self.base_rows_verified != self.expected_base_rows
            || self.slot_rows_verified != self.expected_slot_rows
            || self.graph_rows_verified != self.expected_graph_rows
            || self.edge_rows_verified != self.expected_edge_rows
            || self.raw_guard_slot_rows_verified != self.expected_raw_guard_slot_rows
            || self.blob_rows_verified != self.expected_blob_rows
        {
            return Err(readback_mismatch(format!(
                "readback verified counts differ: base={}/{}, slot={}/{}, graph={}/{}, edge={}/{}, raw_guard={}/{}, blob={}/{}",
                self.base_rows_verified,
                self.expected_base_rows,
                self.slot_rows_verified,
                self.expected_slot_rows,
                self.graph_rows_verified,
                self.expected_graph_rows,
                self.edge_rows_verified,
                self.expected_edge_rows,
                self.raw_guard_slot_rows_verified,
                self.expected_raw_guard_slot_rows,
                self.blob_rows_verified,
                self.expected_blob_rows,
            )));
        }
        Ok(SqliteImportReadback {
            base_rows_verified: self.base_rows_verified,
            slot_rows_verified: self.slot_rows_verified,
            graph_rows_verified: self.graph_rows_verified,
            edge_rows_verified: self.edge_rows_verified,
            raw_guard_slot_rows_verified: self.raw_guard_slot_rows_verified,
            blob_rows_verified: self.blob_rows_verified,
            expected_base_rows: self.expected_base_rows,
            expected_slot_rows: self.expected_slot_rows,
            expected_graph_rows: self.expected_graph_rows,
            expected_edge_rows: self.expected_edge_rows,
            expected_raw_guard_slot_rows: self.expected_raw_guard_slot_rows,
            expected_blob_rows: self.expected_blob_rows,
            physical_rows_read_back: physical.rows_read_back,
            physical_bytes_read_back: physical.bytes_read_back,
            physical_read_batches: physical.read_batches,
            physical_source_read_operations: physical.source_read_operations,
            physical_sst_files_opened: physical.sst_files_opened,
            maximum_plan_bytes: physical.max_plan_bytes,
            maximum_readback_batch_bytes: physical.max_readback_batch_bytes,
        })
    }
}

fn cx_id_from_row_key(kind: &str, key: &[u8]) -> IngestResult<CxId> {
    let bytes: [u8; 16] = key.try_into().map_err(|_| {
        readback_mismatch(format!(
            "{kind} CF key is {} bytes, expected one 16-byte CxId",
            key.len()
        ))
    })?;
    Ok(CxId::from_bytes(bytes))
}

/// Outcome of [`write_import_rows`]: the paired ledger ref (absent exactly when
/// no mutation was committed), the committed-state FSV ack (also absent on that
/// physical no-op), fused semantic readback, graph rows written, edge rows
/// written, and labeled sub-phase timings.
type ImportWriteOutcome = (
    Option<LedgerRef>,
    Option<FsvAck>,
    SqliteImportReadback,
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
    existing_graph: &BTreeMap<Vec<u8>, Vec<u8>>,
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
    for prepared_cx in &prepared.semantic_constellations {
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
                    &prepared_cx.canonical_input_bytes,
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

    // Exact source for modern Graph rows uses the same content-addressed Blob
    // store as canonical panel inputs. Only references introduced or changed by
    // this commit need admission; an unchanged graph row already points at its
    // previously ledger-paired payload. Existing content-addressed payloads are
    // independently reconstructed before reuse, while missing payloads join
    // this exact atomic batch as fixed-size chunks plus terminal manifest.
    let mut changed_exact_source_hashes = BTreeSet::new();
    for (key, value) in &changes.graph_writes {
        if let Some(source_ref) = graph_row_exact_source_ref(key, value)? {
            changed_exact_source_hashes.insert(source_ref.input_hash_blake3);
        }
    }
    for input_hash in changed_exact_source_hashes {
        let prepared_source = prepared.exact_sources.get(&input_hash).ok_or_else(|| {
            IngestError::InvalidInput(format!(
                "Graph row references exact source {} but the prepared batch does not own its bytes",
                hex_lower(&input_hash)
            ))
        })?;
        let source_bytes = prepared_exact_source_bytes(prepared_source, &prepared.constellations)?;
        if blake3::hash(source_bytes).as_bytes() != &input_hash {
            return Err(IngestError::InvalidInput(format!(
                "prepared exact source {} no longer matches its BLAKE3 address",
                hex_lower(&input_hash)
            )));
        }
        if !staged_input_hashes.insert(input_hash) {
            continue;
        }
        if vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Blob,
                &input_store::input_manifest_key(&input_hash),
            )?
            .is_some()
        {
            let persisted = input_store::reassemble_and_verify(&input_hash, |key| {
                vault.read_cf_at(snapshot, ColumnFamily::Blob, key)
            })?;
            if persisted != source_bytes {
                return Err(IngestError::InvalidInput(format!(
                    "persisted exact source {} differs from the prepared bytes",
                    hex_lower(&input_hash)
                )));
            }
            continue;
        }
        for row in input_store::encode_input_rows(&input_hash, source_bytes)? {
            rows.push((row.cf, row.key, row.value));
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
        let no_commit_ref = zero_ledger_ref();
        let readback = ImportSemanticReadback::new(
            prepared,
            quantization_gate,
            changes,
            existing_graph,
            &no_commit_ref,
            0,
        )?
        .finish(VaultMutationReadbackMetrics::default())?;
        return Ok((
            None,
            None,
            readback,
            graph_rows_written,
            edge_rows_written,
            write_timing_ms,
        ));
    }

    let subject = SubjectId::Query(sqlite_fingerprint.to_vec());
    let actor = ActorId::Service(ASTROLABE_INGEST_ACTOR.to_string());
    // Deriving the ledger seq from a pre-commit `ledger_row_count` is a TOCTOU under the
    // supported cross-process concurrency: an interleaved append from another process
    // would make a fixed index point at someone else's entry. Instead, capture the commit
    // snapshot seq returned by the atomic group commit and read the newest ledger row as
    // of exactly that snapshot — later concurrent commits live at higher seqs and are
    // invisible here, so the entry recovered is unambiguously this run's record.
    let commit = vault.write_cf_batch_with_ledger_entry_with_row_digests(
        rows,
        EntryKind::Ingest,
        subject.clone(),
        payload,
        actor.clone(),
    )?;
    let commit_seq = commit.seq;
    let ledger_ref = commit.ledger_ref.clone();
    write_timing_ms.push((
        "write_import_rows.group_commit",
        sub_phase.elapsed().as_millis() as u64,
    ));
    sub_phase = std::time::Instant::now();
    let mut fsv_plan = VaultMutationPlan::new("sqlite_import", EntryKind::Ingest, &actor, &subject);
    let expected_blob_rows = commit
        .data_row_digests
        .iter()
        .filter(|row| row.cf == ColumnFamily::Blob)
        .count();
    for row in commit.data_row_digests {
        if row.tombstoned {
            fsv_plan.push_tombstoned_hash(row.cf, row.key, row.value_blake3);
        } else {
            fsv_plan.push_content_hash(row.cf, row.key, row.value_blake3);
        }
    }
    vault.flush()?;
    write_timing_ms.push((
        "write_import_rows.checkpoint_flush",
        sub_phase.elapsed().as_millis() as u64,
    ));
    sub_phase = std::time::Instant::now();
    let mut semantic = ImportSemanticReadback::new(
        prepared,
        quantization_gate,
        changes,
        existing_graph,
        &ledger_ref,
        expected_blob_rows,
    )?;
    let (fsv, physical) = fsv_plan.verify_committed_with_ledger_ref_observed(
        vault,
        commit_seq,
        &ledger_ref,
        |_, cf, key, persisted| semantic.observe(cf, key, persisted),
    )?;
    let readback = semantic.finish(physical)?;
    write_timing_ms.push((
        "write_import_rows.fsv_verify",
        sub_phase.elapsed().as_millis() as u64,
    ));
    Ok((
        Some(ledger_ref),
        Some(fsv),
        readback,
        graph_rows_written,
        edge_rows_written,
        write_timing_ms,
    ))
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
        "symbol_canonical_schema",
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

fn verify_semantic_base_fields(
    decoded: &Constellation,
    prepared: &PreparedSemanticConstellation,
    expected: &Constellation,
) -> IngestResult<()> {
    if decoded.cx_id != prepared.cx_id
        || decoded.vault_id != expected.vault_id
        || decoded.panel_version != expected.panel_version
        || decoded.created_at != expected.created_at
        || decoded.input_ref != expected.input_ref
        || decoded.modality != expected.modality
        || decoded.scalars != expected.scalars
        || decoded.metadata != expected.metadata
        || decoded.anchors != expected.anchors
        || decoded.flags != expected.flags
    {
        return Err(readback_mismatch(format!(
            "semantic Base CF fields differ for {} row {:?} ({})",
            prepared.family.as_str(),
            prepared.source_key,
            prepared.cx_id
        )));
    }
    if decoded.input_ref.hash != prepared.input_hash {
        return Err(readback_mismatch(format!(
            "semantic Base CF input hash differs for {} row {:?} ({})",
            prepared.family.as_str(),
            prepared.source_key,
            prepared.cx_id
        )));
    }
    Ok(())
}

fn decode_verified_semantic_base(
    vault_id: calyx_core::VaultId,
    cx_id: CxId,
    bytes: &[u8],
    context: &str,
) -> IngestResult<VerifiedSemanticBase> {
    let record = encode::BaseRecord::decode_for_key(cx_id, bytes)?;
    let constellation = record.constellation().clone();
    if constellation.vault_id != vault_id {
        return Err(readback_mismatch(format!(
            "{context} Base row {cx_id} belongs to vault {} instead of {}",
            constellation.vault_id, vault_id
        )));
    }
    let roster = slots_for_version(constellation.panel_version)?;
    for slot_id in record.slot_hashes().keys() {
        if !roster.iter().any(|spec| spec.slot_id() == *slot_id) {
            return Err(readback_mismatch(format!(
                "{context} Base row {cx_id} references slot {slot_id} outside frozen panel version {}",
                constellation.panel_version
            )));
        }
    }
    Ok(VerifiedSemanticBase {
        constellation,
        slot_hashes: record.slot_hashes().clone(),
    })
}

fn read_verified_semantic_base<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    cx_id: CxId,
    context: &str,
) -> IngestResult<VerifiedSemanticBase>
where
    C: Clock,
{
    let bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Base, &base_key(cx_id))?
        .ok_or_else(|| {
            readback_mismatch(format!(
                "{context} points to missing Base row {cx_id}; preserve the vault and re-import from the exact SQLite source"
            ))
        })?;
    decode_verified_semantic_base(vault.vault_id(), cx_id, &bytes, context)
}

fn register_expected_semantic_slots(
    base: &VerifiedSemanticBase,
    family: SemanticFamily,
    allow_legacy_slots: bool,
    expected: &mut ExpectedSemanticSlots,
) -> IngestResult<Vec<SlotId>> {
    let mut presence_seen = false;
    let mut value_slots = Vec::new();
    for (slot_id, hash) in &base.slot_hashes {
        if is_semantic_presence_slot(*slot_id) {
            if *slot_id != family.presence_slot() {
                return Err(readback_mismatch(format!(
                    "Base row {} for family {} carries wrong presence slot {slot_id}",
                    base.constellation.cx_id,
                    family.as_str()
                )));
            }
            presence_seen = true;
        } else if let Some(rule) = semantic_rule_by_slot(*slot_id) {
            if rule.family != family {
                return Err(readback_mismatch(format!(
                    "Base row {} for family {} carries {} value slot {slot_id}",
                    base.constellation.cx_id,
                    family.as_str(),
                    rule.family.as_str()
                )));
            }
            value_slots.push(*slot_id);
        } else if allow_legacy_slots {
            continue;
        } else {
            return Err(readback_mismatch(format!(
                "semantic Base row {} for family {} carries non-semantic slot {slot_id}",
                base.constellation.cx_id,
                family.as_str()
            )));
        }

        if let Some(prior) = expected
            .entry(*slot_id)
            .or_default()
            .insert(base.constellation.cx_id, *hash)
            && prior != *hash
        {
            return Err(readback_mismatch(format!(
                "semantic slot {slot_id} for Base row {} has conflicting immutable hashes",
                base.constellation.cx_id
            )));
        }
    }
    if !presence_seen {
        return Err(readback_mismatch(format!(
            "Base row {} for family {} has no required presence slot {}",
            base.constellation.cx_id,
            family.as_str(),
            family.presence_slot()
        )));
    }
    value_slots.sort_unstable();
    Ok(value_slots)
}

fn verify_semantic_slot_rows<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    expected: &mut ExpectedSemanticSlots,
    errors: &mut Vec<String>,
) -> IngestResult<usize>
where
    C: Clock,
{
    let mut verified = 0_usize;
    for (slot_id, expected_rows) in expected {
        for (key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::slot(*slot_id))? {
            let Ok(raw_cx_id) = <[u8; 16]>::try_from(key.as_slice()) else {
                errors.push(format!(
                    "semantic slot {slot_id} has non-CxId key {}",
                    hex_lower(&key)
                ));
                continue;
            };
            let cx_id = CxId::from_bytes(raw_cx_id);
            let expected_hash = expected_rows.remove(&cx_id);
            if let Some(expected_hash) = expected_hash {
                let actual_hash = *blake3::hash(&bytes).as_bytes();
                if actual_hash != expected_hash {
                    errors.push(format!(
                        "semantic slot {slot_id} row {cx_id} BLAKE3 {} differs from immutable Base hash {}",
                        hex_lower(&actual_hash),
                        hex_lower(&expected_hash)
                    ));
                }
            }

            match encode::decode_slot_vector(&bytes) {
                Ok(vector) => {
                    match encode::encode_slot_vector(&vector) {
                        Ok(canonical) if canonical != bytes => errors.push(format!(
                            "semantic slot {slot_id} row {cx_id} is not in canonical vector encoding"
                        )),
                        Err(error) => errors.push(format!(
                            "semantic slot {slot_id} row {cx_id} cannot be canonically re-encoded: {error}"
                        )),
                        _ => {}
                    }
                    if matches!(&vector, SlotVector::Absent { .. }) {
                        errors.push(format!(
                            "semantic slot {slot_id} row {cx_id} stores Absent instead of a concrete vector"
                        ));
                    }
                    if let Err(error) = validate_slot_vector_contract(*slot_id, &vector) {
                        errors.push(format!(
                            "semantic slot {slot_id} row {cx_id} violates {}: {}; remediation: {}",
                            error.code(),
                            error.message(),
                            error.remediation()
                        ));
                    }
                    if expected_hash.is_some() {
                        verified += 1;
                    }
                }
                Err(error) => errors.push(format!(
                    "decode semantic slot {slot_id} row {cx_id}: {error}"
                )),
            }
        }
        if !expected_rows.is_empty() {
            let samples = expected_rows
                .keys()
                .take(8)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            errors.push(format!(
                "semantic slot {slot_id} is missing {} Base-referenced physical row(s); first CxIds: {samples}",
                expected_rows.len()
            ));
        }
    }
    Ok(verified)
}

fn parse_lower_hex_32(value: &str, field: &str) -> IngestResult<[u8; 32]> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(readback_mismatch(format!(
            "{field} must be exactly 64 lowercase hexadecimal characters, got {value:?}"
        )));
    }
    let mut out = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).expect("hex pair is ASCII");
        out[index] = u8::from_str_radix(pair, 16).expect("hex pair was validated");
    }
    Ok(out)
}

const fn expected_semantic_link_count(family: SemanticFamily) -> usize {
    match family {
        SemanticFamily::Project => 0,
        SemanticFamily::Edge => 2,
        SemanticFamily::FileHash
        | SemanticFamily::ProjectSummary
        | SemanticFamily::NodeVector
        | SemanticFamily::TokenVector => 1,
        SemanticFamily::Node => 0,
    }
}

fn verify_semantic_constellation_row<C>(
    vault: &AsterVault<C>,
    snapshot: Seq,
    key: &[u8],
    row: &SemanticConstellationGraphRow,
) -> IngestResult<(SemanticFamily, VerifiedSemanticBase)>
where
    C: Clock,
{
    if row.schema != SCHEMA_SEMANTIC_CONSTELLATION_ROW {
        return Err(readback_mismatch(format!(
            "semantic constellation {} has wrong schema {:?}",
            hex_lower(key),
            row.schema
        )));
    }
    if row.project.trim().is_empty() || row.source_key.trim().is_empty() {
        return Err(readback_mismatch(format!(
            "semantic constellation {} has an empty project or source key",
            hex_lower(key)
        )));
    }
    let family = SemanticFamily::from_manifest_str(&row.family).ok_or_else(|| {
        readback_mismatch(format!(
            "semantic constellation {} has unknown family {:?}",
            hex_lower(key),
            row.family
        ))
    })?;
    if family == SemanticFamily::Node {
        return Err(readback_mismatch(format!(
            "semantic constellation {} duplicates a node; node semantics must be bound through the node-map Base row",
            hex_lower(key)
        )));
    }
    if row.panel_version != CURRENT_SEMANTIC_PANEL_VERSION {
        return Err(readback_mismatch(format!(
            "semantic constellation {} uses panel version {}, expected {}",
            hex_lower(key),
            row.panel_version,
            CURRENT_SEMANTIC_PANEL_VERSION
        )));
    }
    if row.registry_sha256 != hex_lower(&semantic_registry_sha256()) {
        return Err(readback_mismatch(format!(
            "semantic constellation {} registry hash does not match the frozen registry",
            hex_lower(key)
        )));
    }
    let input_hash = parse_lower_hex_32(
        &row.input_hash_blake3,
        "semantic constellation input_hash_blake3",
    )?;
    parse_lower_hex_32(
        &row.sqlite_fingerprint_sha256,
        "semantic constellation sqlite_fingerprint_sha256",
    )?;
    let expected_key = semantic_constellation_graph_key(
        &sha256_digest(row.project.as_bytes()),
        family,
        &row.source_key,
    );
    if key != expected_key {
        return Err(readback_mismatch(format!(
            "semantic constellation {} key does not match project/family/source identity",
            hex_lower(key)
        )));
    }
    if row.links.len() != expected_semantic_link_count(family) {
        return Err(readback_mismatch(format!(
            "semantic constellation {} family {} has {} links, expected {}",
            hex_lower(key),
            family.as_str(),
            row.links.len(),
            expected_semantic_link_count(family)
        )));
    }
    let base = read_verified_semantic_base(
        vault,
        snapshot,
        row.cx_id,
        &format!("semantic constellation {}", hex_lower(key)),
    )?;
    if base.constellation.panel_version != row.panel_version
        || base.constellation.input_ref.hash != input_hash
        || base
            .constellation
            .metadata
            .get("semantic.family")
            .map(String::as_str)
            != Some(family.as_str())
        || base
            .constellation
            .metadata
            .get("semantic.source_key")
            .map(String::as_str)
            != Some(row.source_key.as_str())
        || base
            .constellation
            .metadata
            .get("input_hash_blake3")
            .map(String::as_str)
            != Some(row.input_hash_blake3.as_str())
    {
        return Err(readback_mismatch(format!(
            "semantic constellation {} Graph identity disagrees with Base {}",
            hex_lower(key),
            row.cx_id
        )));
    }
    let graph_slots = row
        .slot_ids
        .iter()
        .copied()
        .map(SlotId::new)
        .collect::<Vec<_>>();
    if graph_slots.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(readback_mismatch(format!(
            "semantic constellation {} slot roster is not strictly increasing",
            hex_lower(key)
        )));
    }
    if graph_slots != base.slot_hashes.keys().copied().collect::<Vec<_>>() {
        return Err(readback_mismatch(format!(
            "semantic constellation {} Graph slot roster disagrees with Base {}",
            hex_lower(key),
            row.cx_id
        )));
    }
    Ok((family, base))
}

fn verify_semantic_coverage_row(key: &[u8], bytes: &[u8]) -> IngestResult<SemanticCoverageWitness> {
    let witness = serde_json::from_slice::<SemanticCoverageWitness>(bytes)?;
    if witness.schema != SCHEMA_SEMANTIC_COVERAGE_ROW
        || witness.project.trim().is_empty()
        || witness.panel_version != CURRENT_SEMANTIC_PANEL_VERSION
    {
        return Err(readback_mismatch(format!(
            "semantic coverage {} has wrong schema, empty project, or panel version {}",
            hex_lower(key),
            witness.panel_version
        )));
    }
    if semantic_coverage_canonical_bytes(&witness)? != bytes {
        return Err(readback_mismatch(format!(
            "semantic coverage {} is not the canonical persisted witness encoding",
            hex_lower(key)
        )));
    }
    let expected_key = project_key_with_digest(
        SEMANTIC_COVERAGE_ROW_PREFIX,
        &sha256_digest(witness.project.as_bytes()),
    );
    if key != expected_key {
        return Err(readback_mismatch(format!(
            "semantic coverage {} key does not match project {:?}",
            hex_lower(key),
            witness.project
        )));
    }
    if witness.registry_sha256 != hex_lower(&semantic_registry_sha256())
        || witness.slot_manifest_sha256
            != hex_lower(&panel_slot_manifest_sha256(witness.panel_version)?)
    {
        return Err(readback_mismatch(format!(
            "semantic coverage {} does not bind the current registry and panel manifest",
            hex_lower(key)
        )));
    }
    parse_lower_hex_32(
        &witness.source_schema_sha256,
        "semantic coverage source_schema_sha256",
    )?;
    parse_lower_hex_32(
        &witness.sqlite_fingerprint_sha256,
        "semantic coverage sqlite_fingerprint_sha256",
    )?;
    let classified = witness
        .encoded
        .checked_add(witness.embedded)
        .and_then(|value| value.checked_add(witness.imported_vector))
        .ok_or_else(|| readback_mismatch("semantic coverage classified count overflow"))?;
    if witness.uncovered != 0 || witness.present != classified {
        return Err(readback_mismatch(format!(
            "semantic coverage {} violates present={} = encoded={} + embedded={} + imported_vector={} with uncovered={}",
            hex_lower(key),
            witness.present,
            witness.encoded,
            witness.embedded,
            witness.imported_vector,
            witness.uncovered
        )));
    }
    Ok(witness)
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
    let mut expected_semantic_slots = ExpectedSemanticSlots::new();
    let mut verified_bases = BTreeMap::<CxId, VerifiedSemanticBase>::new();
    let mut coverage_by_project = BTreeMap::<String, SemanticCoverageAccumulator>::new();
    let mut semantic_rows = Vec::<SemanticConstellationGraphRow>::new();
    let mut coverage_rows = BTreeMap::<String, (SemanticCoverageWitness, Vec<u8>)>::new();

    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(NODE_MAP_PREFIX),
    )? {
        match serde_json::from_slice::<NodeMapRow>(&value) {
            Ok(row) => {
                counts.node_map_rows += 1;
                if !supported_node_map_schema(&row.schema) {
                    errors.push(format!("node map {} has wrong schema", hex_lower(&key)));
                    continue;
                }
                if let Err(error) = read_exact_source_at(
                    vault,
                    snapshot,
                    "node-map",
                    row.node_id,
                    &row.schema,
                    SCHEMA_NODE_MAP,
                    LEGACY_SCHEMA_NODE_MAP_V3,
                    row.source_present,
                    &row.source_bytes,
                    row.source_ref.as_ref(),
                    &row.source_sha256,
                    row.start_byte,
                    row.end_byte,
                ) {
                    errors.push(format!(
                        "node map {} exact source: {error}",
                        hex_lower(&key)
                    ));
                }
                if row.series_id_schema != SERIES_ID_TAG {
                    errors.push(format!(
                        "node map {} has wrong SeriesId schema",
                        hex_lower(&key)
                    ));
                    continue;
                }
                match vault.read_cf_at(snapshot, ColumnFamily::Base, &base_key(row.cx_id))? {
                    Some(base) => match decode_verified_semantic_base(
                        vault.vault_id(),
                        row.cx_id,
                        &base,
                        "node map",
                    ) {
                        Ok(verified) => {
                            counts.constellation_rows += 1;
                            verify_node_map_matches_base(&row, &verified.constellation, errors);
                            if verified.constellation.panel_version >= PANEL_V3_VERSION {
                                if verified.constellation.panel_version
                                    != CURRENT_SEMANTIC_PANEL_VERSION
                                {
                                    errors.push(format!(
                                        "node map {} uses unverified semantic panel version {}",
                                        row.node_id, verified.constellation.panel_version
                                    ));
                                } else {
                                    match register_expected_semantic_slots(
                                        &verified,
                                        SemanticFamily::Node,
                                        true,
                                        &mut expected_semantic_slots,
                                    ) {
                                        Ok(value_slots) => {
                                            if let Err(error) = coverage_by_project
                                                .entry(row.project.clone())
                                                .or_default()
                                                .observe_slots(SemanticFamily::Node, &value_slots)
                                            {
                                                errors.push(format!(
                                                    "node map {} semantic coverage: {error}",
                                                    row.node_id
                                                ));
                                            }
                                        }
                                        Err(error) => errors.push(format!(
                                            "node map {} semantic Base row: {error}",
                                            row.node_id
                                        )),
                                    }
                                }
                            }
                            verified_bases.entry(row.cx_id).or_insert(verified);
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
                if !supported_structural_node_schema(&row.schema) {
                    errors.push(format!(
                        "structural node {} has wrong schema",
                        hex_lower(&key)
                    ));
                } else if let Err(error) = read_exact_source_at(
                    vault,
                    snapshot,
                    "structural",
                    row.node_id,
                    &row.schema,
                    SCHEMA_STRUCTURAL_NODE,
                    LEGACY_SCHEMA_STRUCTURAL_NODE_V2,
                    row.source_present,
                    &row.source_bytes,
                    row.source_ref.as_ref(),
                    &row.source_sha256,
                    row.start_byte,
                    row.end_byte,
                ) {
                    errors.push(format!(
                        "structural node {} exact source: {error}",
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
        &prefix_range(SEMANTIC_CONSTELLATION_ROW_PREFIX),
    )? {
        match serde_json::from_slice::<SemanticConstellationGraphRow>(&value) {
            Ok(row) => match verify_semantic_constellation_row(vault, snapshot, &key, &row) {
                Ok((family, verified)) => {
                    match register_expected_semantic_slots(
                        &verified,
                        family,
                        false,
                        &mut expected_semantic_slots,
                    ) {
                        Ok(value_slots) => {
                            if let Err(error) = coverage_by_project
                                .entry(row.project.clone())
                                .or_default()
                                .observe_slots(family, &value_slots)
                            {
                                errors.push(format!(
                                    "semantic constellation {} coverage: {error}",
                                    hex_lower(&key)
                                ));
                            }
                        }
                        Err(error) => errors.push(format!(
                            "semantic constellation {} Base roster: {error}",
                            hex_lower(&key)
                        )),
                    }
                    counts.semantic_constellation_rows += 1;
                    verified_bases.entry(row.cx_id).or_insert(verified);
                    semantic_rows.push(row);
                }
                Err(error) => errors.push(format!(
                    "verify semantic constellation {}: {error}",
                    hex_lower(&key)
                )),
            },
            Err(error) => errors.push(format!(
                "decode semantic constellation {}: {error}",
                hex_lower(&key)
            )),
        }
    }

    for row in &semantic_rows {
        let Some(family) = SemanticFamily::from_manifest_str(&row.family) else {
            continue;
        };
        for link in &row.links {
            let Some(target) = verified_bases.get(link) else {
                errors.push(format!(
                    "semantic {} row {:?} links Base {link} without a verified current graph identity",
                    family.as_str(),
                    row.source_key
                ));
                continue;
            };
            if target.constellation.panel_version != row.panel_version {
                errors.push(format!(
                    "semantic {} row {:?} links Base {link} at panel version {} instead of {}",
                    family.as_str(),
                    row.source_key,
                    target.constellation.panel_version,
                    row.panel_version
                ));
            }
            match family {
                SemanticFamily::FileHash
                | SemanticFamily::ProjectSummary
                | SemanticFamily::TokenVector => {
                    if target
                        .constellation
                        .metadata
                        .get("semantic.family")
                        .map(String::as_str)
                        != Some(SemanticFamily::Project.as_str())
                        || target
                            .constellation
                            .metadata
                            .get("semantic.source_key")
                            .map(String::as_str)
                            != Some(row.project.as_str())
                    {
                        errors.push(format!(
                            "semantic {} row {:?} link {link} is not its project constellation",
                            family.as_str(),
                            row.source_key
                        ));
                    }
                }
                SemanticFamily::NodeVector | SemanticFamily::Edge => {
                    if target
                        .constellation
                        .metadata
                        .get("astrolabe_schema")
                        .map(String::as_str)
                        != Some(SCHEMA_SYMBOL_METADATA)
                        || target
                            .constellation
                            .metadata
                            .get("project")
                            .map(String::as_str)
                            != Some(row.project.as_str())
                    {
                        errors.push(format!(
                            "semantic {} row {:?} link {link} is not a node constellation in project {:?}",
                            family.as_str(),
                            row.source_key,
                            row.project
                        ));
                    }
                }
                SemanticFamily::Project | SemanticFamily::Node => {}
            }
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

    for (key, value) in vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(SEMANTIC_COVERAGE_ROW_PREFIX),
    )? {
        match verify_semantic_coverage_row(&key, &value) {
            Ok(witness) => {
                if coverage_rows
                    .insert(witness.project.clone(), (witness, value))
                    .is_some()
                {
                    errors.push(format!(
                        "project semantic coverage key {} duplicates an existing project witness",
                        hex_lower(&key)
                    ));
                }
            }
            Err(error) => errors.push(format!(
                "verify semantic coverage {}: {error}",
                hex_lower(&key)
            )),
        }
    }

    let mut ledger_coverage = BTreeMap::<String, BTreeSet<Vec<u8>>>::new();
    for (key, bytes) in
        vault.scan_cf_range_at(snapshot, ColumnFamily::Ledger, &ledger_range(0, u64::MAX))?
    {
        let entry = match decode(&bytes) {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!(
                    "decode ledger row {} while binding semantic coverage: {error}",
                    hex_lower(&key)
                ));
                continue;
            }
        };
        let Ok(payload) = serde_json::from_slice::<Value>(&entry.payload) else {
            continue;
        };
        if payload.get("schema").and_then(Value::as_str) != Some(SCHEMA_LEDGER) {
            continue;
        }
        let Some(value) = payload.get("semantic_coverage") else {
            continue;
        };
        match serde_json::from_value::<SemanticCoverageWitness>(value.clone()) {
            Ok(witness) => match semantic_coverage_canonical_bytes(&witness) {
                Ok(canonical) => {
                    ledger_coverage
                        .entry(witness.project.clone())
                        .or_default()
                        .insert(canonical);
                }
                Err(error) => errors.push(format!(
                    "encode semantic coverage from ledger seq {}: {error}",
                    entry.seq
                )),
            },
            Err(error) => errors.push(format!(
                "decode semantic coverage from ledger seq {}: {error}",
                entry.seq
            )),
        }
    }

    for (project, (witness, bytes)) in &coverage_rows {
        let accumulator = coverage_by_project.remove(project).unwrap_or_default();
        let source_schema = parse_lower_hex_32(
            &witness.source_schema_sha256,
            "semantic coverage source_schema_sha256",
        )?;
        let sqlite_fingerprint = parse_lower_hex_32(
            &witness.sqlite_fingerprint_sha256,
            "semantic coverage sqlite_fingerprint_sha256",
        )?;
        match accumulator.finish(
            project,
            witness.panel_version,
            source_schema,
            sqlite_fingerprint,
        ) {
            Ok(recomputed) if recomputed != *witness => errors.push(format!(
                "semantic coverage for project {project:?} does not equal counts independently reconstructed from persisted Base slot rosters"
            )),
            Err(error) => errors.push(format!(
                "recompute semantic coverage for project {project:?}: {error}"
            )),
            _ => {}
        }
        if !ledger_coverage
            .get(project)
            .is_some_and(|ledger_rows| ledger_rows.contains(bytes))
        {
            errors.push(format!(
                "semantic coverage for project {project:?} is not byte-identical to any intact ingest ledger payload"
            ));
        }
        counts.semantic_coverage_witness_rows += 1;
        counts.semantic_coverage_present = counts
            .semantic_coverage_present
            .checked_add(witness.present)
            .ok_or_else(|| readback_mismatch("semantic coverage present count overflow"))?;
        counts.semantic_coverage_encoded = counts
            .semantic_coverage_encoded
            .checked_add(witness.encoded)
            .ok_or_else(|| readback_mismatch("semantic coverage encoded count overflow"))?;
        counts.semantic_coverage_embedded = counts
            .semantic_coverage_embedded
            .checked_add(witness.embedded)
            .ok_or_else(|| readback_mismatch("semantic coverage embedded count overflow"))?;
        counts.semantic_coverage_imported_vectors = counts
            .semantic_coverage_imported_vectors
            .checked_add(witness.imported_vector)
            .ok_or_else(|| readback_mismatch("semantic coverage imported count overflow"))?;
        counts.semantic_coverage_uncovered = counts
            .semantic_coverage_uncovered
            .checked_add(witness.uncovered)
            .ok_or_else(|| readback_mismatch("semantic coverage uncovered count overflow"))?;
    }
    for project in coverage_by_project.keys() {
        errors.push(format!(
            "project {project:?} has exhaustive semantic Base rows but no coverage witness"
        ));
    }
    counts.semantic_slot_rows =
        verify_semantic_slot_rows(vault, snapshot, &mut expected_semantic_slots, errors)?;

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
        if !supported_node_map_schema(&row.schema) {
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
        let needs_base_decode = panel_version.is_none();
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
        let source_bytes = read_exact_source_at(
            vault,
            snapshot,
            "node-map",
            row.node_id,
            &row.schema,
            SCHEMA_NODE_MAP,
            LEGACY_SCHEMA_NODE_MAP_V3,
            row.source_present,
            &row.source_bytes,
            row.source_ref.as_ref(),
            &row.source_sha256,
            row.start_byte,
            row.end_byte,
        )?;
        let properties_json = row.properties_json.unwrap_or_else(|| "{}".to_string());
        ensure_json_object_text(&properties_json, "node properties")?;
        nodes.push(CbmGraphNode {
            source_node_id: row.node_id,
            project: row.project,
            label: row.label,
            name: row.name,
            atom_id: row.atom_id,
            qualified_name: row.qualified_name,
            file_path: row.file_path,
            start_line: row.start_line,
            end_line: row.end_line,
            source_present: row.source_present,
            source_bytes,
            source_sha256: row.source_sha256,
            start_byte: row.start_byte,
            end_byte: row.end_byte,
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
        if !supported_structural_node_schema(&row.schema) {
            return Err(IngestError::InvalidInput(format!(
                "structural node row {} has wrong schema {}",
                row.node_id, row.schema
            )));
        }
        let source_bytes = read_exact_source_at(
            vault,
            snapshot,
            "structural",
            row.node_id,
            &row.schema,
            SCHEMA_STRUCTURAL_NODE,
            LEGACY_SCHEMA_STRUCTURAL_NODE_V2,
            row.source_present,
            &row.source_bytes,
            row.source_ref.as_ref(),
            &row.source_sha256,
            row.start_byte,
            row.end_byte,
        )?;
        let properties_json = row.properties_json.unwrap_or_else(|| "{}".to_string());
        ensure_json_object_text(&properties_json, "structural node properties")?;
        nodes.push(CbmGraphNode {
            source_node_id: row.node_id,
            project: row.project,
            label: row.label,
            name: row.name,
            atom_id: row.atom_id,
            qualified_name: row.qualified_name,
            file_path: row.file_path,
            start_line: row.start_line,
            end_line: row.end_line,
            source_present: row.source_present,
            source_bytes,
            source_sha256: row.source_sha256,
            start_byte: row.start_byte,
            end_byte: row.end_byte,
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
        let properties = serde_json::from_str::<Value>(&row.properties_json)?;
        let expected_url_path = row_sink_url_path_gen(&properties, row.sqlite_edge_id)?;
        if row.url_path_gen != expected_url_path {
            return Err(IngestError::InvalidInput(format!(
                "raw edge row {} url_path_gen {:?} differs from properties-derived {:?}",
                row.sqlite_edge_id, row.url_path_gen, expected_url_path
            )));
        }
        Ok(CbmGraphEdge {
            sqlite_edge_id: row.sqlite_edge_id,
            project: row.project,
            source_node_id: row.source_node_id,
            target_node_id: row.target_node_id,
            src: None,
            dst: None,
            edge_type: row.edge_type,
            url_path_gen: row.url_path_gen,
            local_name_gen: row.local_name_gen,
            preprocess_context_id_gen: row.preprocess_context_id_gen,
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
            .then_with(|| {
                left.preprocess_context_id_gen
                    .cmp(&right.preprocess_context_id_gen)
            })
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
        |row: &CbmFileHashRow| (&row.schema, CBM_FILE_HASH_ROW_SCHEMA, &row.project),
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
/// Reads every supported modern or historical node-map row of `project` from
/// the vault Graph CF
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
        if !supported_node_map_schema(&row.schema) {
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

/// Global stable source-atom identity to CxId mapping across every persisted
/// node-map row. Atom ids are primary identities and therefore must be unique;
/// any duplicate refuses instead of introducing an ambiguity channel downstream.
pub(crate) fn read_global_atom_cx_ids<C>(
    vault: &AsterVault<C>,
) -> IngestResult<BTreeMap<String, CxId>>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let mut resolved = BTreeMap::new();
    for row in read_graph_rows::<C, NodeMapRow>(vault, snapshot, NODE_MAP_PREFIX)? {
        if !supported_node_map_schema(&row.schema) {
            return Err(IngestError::InvalidInput(format!(
                "node map row {} has wrong schema {}",
                row.node_id, row.schema
            )));
        }
        if row.atom_id.trim().is_empty() {
            return Err(IngestError::InvalidInput(format!(
                "node map row {} ({:?}) has an empty stable atom id",
                row.node_id, row.qualified_name
            )));
        }
        if let Some(existing) = resolved.insert(row.atom_id.clone(), row.cx_id) {
            return Err(IngestError::InvalidInput(format!(
                "stable atom id {:?} maps to multiple node-map CxIds: {} and {}",
                row.atom_id, existing, row.cx_id
            )));
        }
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
        if row.project != project || !supported_node_map_schema(&row.schema) {
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
    } else {
        match row_sink_local_name_gen(&row.edge_type, &row.props, row.sqlite_edge_id) {
            Ok(expected) if expected != row.local_name_gen => errors.push(format!(
                "edge row {} local_name_gen differs from properties",
                hex_lower(key)
            )),
            Err(error) => errors.push(format!(
                "edge row {} has invalid local-name identity: {error}",
                hex_lower(key)
            )),
            _ => {}
        }
        match row_sink_preprocess_context_id_gen(&row.props, row.sqlite_edge_id) {
            Ok(expected) if expected != row.preprocess_context_id_gen => errors.push(format!(
                "edge row {} preprocess_context_id_gen differs from properties",
                hex_lower(key)
            )),
            Err(error) => errors.push(format!(
                "edge row {} has invalid preprocessing-context identity: {error}",
                hex_lower(key)
            )),
            _ => {}
        }
    }
    if let Some(kind) = EdgeKind::from_cbm_type(&row.edge_type) {
        match edge_graph_key(
            row.src,
            row.dst,
            kind,
            &row.local_name_gen,
            &row.preprocess_context_id_gen,
        ) {
            Ok(expected) if expected != key => errors.push(format!(
                "edge row {} key does not encode its complete identity",
                hex_lower(key)
            )),
            Err(error) => errors.push(format!(
                "edge row {} identity key cannot be derived: {error}",
                hex_lower(key)
            )),
            _ => {}
        }
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
        ("symbol_canonical_schema", SYMBOL_CANONICAL_TAG),
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

fn semantic_coverage_bytes(prepared: &PreparedBatch) -> IngestResult<&[u8]> {
    let mut matches = prepared
        .graph_rows
        .iter()
        .filter(|(key, _)| key.starts_with(SEMANTIC_COVERAGE_ROW_PREFIX));
    let (_, bytes) = matches.next().ok_or_else(|| {
        readback_mismatch("prepared import has no semantic coverage witness Graph row")
    })?;
    if matches.next().is_some() {
        return Err(readback_mismatch(
            "prepared import has multiple semantic coverage witness Graph rows",
        ));
    }
    Ok(bytes)
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
        .iter()
        .map(|prepared| prepared.identity.cx_id)
        .chain(
            prepared
                .semantic_constellations
                .iter()
                .map(|prepared| prepared.cx_id),
        )
        .min()
        .map(|cx_id| cx_id.to_string());
    let last = prepared
        .constellations
        .iter()
        .map(|prepared| prepared.identity.cx_id)
        .chain(
            prepared
                .semantic_constellations
                .iter()
                .map(|prepared| prepared.cx_id),
        )
        .max()
        .map(|cx_id| cx_id.to_string());
    let payload = IngestLedgerPayload {
        schema: SCHEMA_LEDGER.to_string(),
        sqlite_fingerprint_sha256: hex_lower(&sqlite_fingerprint),
        project_hash_sha256: hex_lower(&sha256_digest(options.project.as_bytes())),
        commit_hash_sha256: hex_lower(&sha256_digest(options.commit.as_bytes())),
        sqlite_nodes: (prepared.constellations.len() + prepared.structural_only) as u64,
        sqlite_node_vectors: stats.sqlite_node_vectors as u64,
        sqlite_edges: prepared.sqlite_edges as u64,
        constellation_inputs: prepared.constellations.len() as u64,
        semantic_constellation_inputs: prepared.semantic_constellations.len() as u64,
        structural_only: prepared.structural_only as u64,
        new_cx_ids: stats.new_cx_ids as u64,
        reused_cx_ids: stats.reused_cx_ids as u64,
        new_semantic_cx_ids: stats.new_semantic_cx_ids as u64,
        reused_semantic_cx_ids: stats.reused_semantic_cx_ids as u64,
        semantic_coverage: prepared.semantic_coverage.clone(),
        graph_rows_written: stats.graph_rows_written as u64,
        edge_inputs: prepared.edge_rows.len() as u64,
        edge_rows_written: stats.edge_rows_written as u64,
        edge_dangling_skipped: prepared.edge_skips.dangling as u64,
        edge_structural_endpoint_skipped: prepared.edge_skips.structural_endpoint as u64,
        expected_base_rows: (prepared.constellations.len() + prepared.semantic_constellations.len())
            as u64,
        expected_slot_rows: prepared
            .constellations
            .iter()
            .filter_map(|prepared| prepared.measured.as_ref())
            .chain(
                prepared
                    .semantic_constellations
                    .iter()
                    .filter_map(|prepared| prepared.measured.as_ref()),
            )
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
    preprocess_context_id_gen: &str,
) -> IngestResult<Vec<u8>> {
    let local_len = u32::try_from(local_name_gen.len()).map_err(|_| {
        invalid_sqlite("edge local_name_gen is too long to encode into Graph CF key")
    })?;
    let context_len = u32::try_from(preprocess_context_id_gen.len()).map_err(|_| {
        invalid_sqlite("edge preprocess_context_id_gen is too long to encode into Graph CF key")
    })?;
    let mut key = Vec::with_capacity(
        EDGE_ROW_PREFIX.len()
            + 16
            + 16
            + 2
            + 4
            + local_name_gen.len()
            + 4
            + preprocess_context_id_gen.len(),
    );
    key.extend_from_slice(EDGE_ROW_PREFIX);
    key.extend_from_slice(src.as_bytes());
    key.extend_from_slice(dst.as_bytes());
    key.extend_from_slice(&kind.code().to_be_bytes());
    key.extend_from_slice(&local_len.to_be_bytes());
    key.extend_from_slice(local_name_gen.as_bytes());
    key.extend_from_slice(&context_len.to_be_bytes());
    key.extend_from_slice(preprocess_context_id_gen.as_bytes());
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
        | SymbolLabel::EnvVar
        | SymbolLabel::ParseDiagnostic
        | SymbolLabel::RuntimeModuleRequest => Modality::Structured,
        SymbolLabel::Project | SymbolLabel::Branch | SymbolLabel::Folder => Modality::Structured,
        _ => Modality::Code,
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
