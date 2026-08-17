//! Controlled-N authenticated point-read cost evidence for the parent manual
//! FSV artifact (#564, #1064 PC-01/02/03/04/05/09/37/38/41/43).
//!
//! R is the only column-shape variable: 1,024, 8,192, and 49,496 rows are
//! nested prefixes of the same exact C-code-poly stream. D=768, ScalarInt8,
//! slot/lens identity, vault id/salt, CPU backend, held-out query, k=1, U=1,
//! and M=3 stay fixed. The first two generations are built fresh by the real
//! Registry admission path. The last is the preserved r14 production
//! generation produced from every non-held-out source row.
//!
//! The measured product operation is `CompressedSlotIndex::read_at`. Calling-
//! thread allocator traffic and wall latency run in separate loops. An
//! independent retained Aster plan reads only the exact manifest, primary, and
//! membership-proof values; `bytes_read_back` is reported strictly as logical
//! persisted value bytes, never as OS or device bytes. One warmup precedes each
//! three-sample loop. Allocation tuples are deterministic evidence; latency is
//! deliberately non-invariant and is not compared across processes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::Write;
use std::time::Instant;

use calyx_aster::mvcc::{OrderedReadbackMetrics, is_tombstone_value};
use calyx_aster::vault::OrderedCfRead;
use calyx_core::CalyxError;
use calyx_registry::CompressedGenerationIdentity;
use serde::{Deserialize, Serialize};

use super::*;

const POINT_COST_PRODUCTION_VAULT_ENV: &str =
    "ASTROLABE_COMPRESSION_FSV_POINT_COST_PRODUCTION_VAULT";
const POINT_COST_SCHEMA: &str = "astrolabe.compression-point-read-cost.v1";
const POINT_COST_READBACK_SCHEMA: &str = "astrolabe.compression-point-read-cost-readback.v1";
const POINT_COST_DIRECTORY: &str = "point-read-cost";
const POINT_COST_REPORT: &str = "report.json";
const POINT_COST_READBACK_REPORT: &str = "readback.json";
const PREFIX_ROWS: [u32; 2] = [1_024, 8_192];
const ALL_ROWS: [u32; 3] = [1_024, 8_192, PRODUCTION_CORPUS_ROWS];
const COST_SAMPLES: u32 = MEASURED_RUNS;
const EXPECTED_PRODUCTION_DB_BYTES: u64 = 565_575_680;
const EXPECTED_PRODUCTION_DB_SHA256: &str =
    "7659afe3314a7ef8ef06c729b6e3bf0946a1438bde3f3ebd8081494622eb70f8";
const POINT_COST_VAULT_DEPENDENCY_SCOPE: &str = "root CURRENT, MANIFEST, manifest-*.json, ROUTER_HANDOFF, and residency.json presence/bytes; wal/**; locks/**; panel/**; registry/**; codebooks/**; cf/compression/**; cf/slot_93/**";
const POINT_COST_VAULT_EXCLUDED_PATHS: &str = "every other vault path, including Base, Ledger, Time, raw, non-slot_93, and unrelated root trees; these are outside the selected read-only point operation and are neither opened nor hashed";
const POINT_COST_ROOT_DEPENDENCY_FILES: [&str; 4] =
    ["CURRENT", "MANIFEST", "ROUTER_HANDOFF", "residency.json"];
const POINT_COST_DEPENDENCY_DIRECTORIES: [&str; 7] = [
    "wal",
    "locks",
    "panel",
    "registry",
    "codebooks",
    "cf/compression",
    "cf/slot_93",
];

struct ThreadCountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: ThreadCountingAllocator = ThreadCountingAllocator;

thread_local! {
    static COUNTING_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATION_COUNTERS: Cell<AllocationTuple> = const { Cell::new(AllocationTuple::ZERO) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AllocationTuple {
    allocation_calls: u64,
    allocation_requested_bytes: u64,
    zeroed_allocation_calls: u64,
    zeroed_allocation_requested_bytes: u64,
    reallocation_calls: u64,
    reallocation_old_bytes: u64,
    reallocation_new_bytes: u64,
    deallocation_calls: u64,
    deallocation_layout_bytes: u64,
    overflowed: bool,
}

impl AllocationTuple {
    const ZERO: Self = Self {
        allocation_calls: 0,
        allocation_requested_bytes: 0,
        zeroed_allocation_calls: 0,
        zeroed_allocation_requested_bytes: 0,
        reallocation_calls: 0,
        reallocation_old_bytes: 0,
        reallocation_new_bytes: 0,
        deallocation_calls: 0,
        deallocation_layout_bytes: 0,
        overflowed: false,
    };

    fn add(target: &mut u64, amount: usize, overflowed: &mut bool) {
        let amount = u64::try_from(amount).unwrap_or(u64::MAX);
        match target.checked_add(amount) {
            Some(total) => *target = total,
            None => {
                *target = u64::MAX;
                *overflowed = true;
            }
        }
    }

    fn increment(target: &mut u64, overflowed: &mut bool) {
        match target.checked_add(1) {
            Some(total) => *target = total,
            None => {
                *target = u64::MAX;
                *overflowed = true;
            }
        }
    }
}

unsafe impl GlobalAlloc for ThreadCountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(|counters| {
                let mut overflowed = counters.overflowed;
                AllocationTuple::increment(&mut counters.allocation_calls, &mut overflowed);
                AllocationTuple::add(
                    &mut counters.allocation_requested_bytes,
                    layout.size(),
                    &mut overflowed,
                );
                counters.overflowed = overflowed;
            });
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(|counters| {
                let mut overflowed = counters.overflowed;
                AllocationTuple::increment(&mut counters.zeroed_allocation_calls, &mut overflowed);
                AllocationTuple::add(
                    &mut counters.zeroed_allocation_requested_bytes,
                    layout.size(),
                    &mut overflowed,
                );
                counters.overflowed = overflowed;
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record_allocation(|counters| {
            let mut overflowed = counters.overflowed;
            AllocationTuple::increment(&mut counters.deallocation_calls, &mut overflowed);
            AllocationTuple::add(
                &mut counters.deallocation_layout_bytes,
                layout.size(),
                &mut overflowed,
            );
            counters.overflowed = overflowed;
        });
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            record_allocation(|counters| {
                let mut overflowed = counters.overflowed;
                AllocationTuple::increment(&mut counters.reallocation_calls, &mut overflowed);
                AllocationTuple::add(
                    &mut counters.reallocation_old_bytes,
                    layout.size(),
                    &mut overflowed,
                );
                AllocationTuple::add(
                    &mut counters.reallocation_new_bytes,
                    new_size,
                    &mut overflowed,
                );
                counters.overflowed = overflowed;
            });
        }
        new_pointer
    }
}

fn record_allocation(update: impl FnOnce(&mut AllocationTuple)) {
    let _ = COUNTING_ALLOCATIONS.try_with(|enabled| {
        if enabled.get() {
            let _ = ALLOCATION_COUNTERS.try_with(|cell| {
                let mut counters = cell.get();
                update(&mut counters);
                cell.set(counters);
            });
        }
    });
}

fn count_allocations<T>(operation: impl FnOnce() -> T) -> (T, AllocationTuple) {
    COUNTING_ALLOCATIONS.with(|enabled| {
        assert!(!enabled.get(), "allocation measurement cannot be nested");
        ALLOCATION_COUNTERS.with(|counters| counters.set(AllocationTuple::ZERO));
        enabled.set(true);
    });
    let result = operation();
    COUNTING_ALLOCATIONS.with(|enabled| enabled.set(false));
    let counters = ALLOCATION_COUNTERS.with(Cell::get);
    (result, counters)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ProductionTruth {
    path: PathBuf,
    database_bytes: u64,
    database_sha256_before: String,
    database_sha256_after: String,
    project: String,
    source_rows: u32,
    compressed_rows: u32,
    dimension: u32,
    blob_bytes: u64,
    first_node_id: i64,
    point_node_id: i64,
    last_node_id: i64,
    row_stream_sha256: String,
    sqlite_query_only: i64,
}

struct SourcePreflight {
    truth: ProductionTruth,
    first_vector: Vec<f32>,
    prefix_sha256_by_rows: BTreeMap<u32, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct VaultInventory {
    dependency_scope: String,
    excluded_paths: String,
    files: u64,
    bytes: u64,
    compression_cf_files: u64,
    compression_cf_bytes: u64,
    primary_cf_files: u64,
    primary_cf_bytes: u64,
    tree_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SelectedValueEvidence {
    role: String,
    column_family: String,
    key_hex: String,
    value_bytes: u64,
    value_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OrderedLogicalMetrics {
    session_snapshot_seq: u64,
    requested_keys: u64,
    rows_read_back: u64,
    logical_value_bytes_read_back: u64,
    read_batches: u64,
    source_read_operations: u64,
    sst_files_opened: u64,
    unique_sst_generations: u64,
    sst_key_probes: u64,
    sst_map_reuses: u64,
    sst_exact_route_lookups: u64,
    sst_exact_route_hits: u64,
    sst_fallback_file_key_checks: u64,
    plan_index_bytes: u64,
    max_readback_batch_bytes: u64,
}

impl From<OrderedReadbackMetrics> for OrderedLogicalMetrics {
    fn from(metrics: OrderedReadbackMetrics) -> Self {
        Self {
            session_snapshot_seq: metrics.session_snapshot_seq,
            requested_keys: metrics.requested_keys,
            rows_read_back: metrics.rows_read_back,
            logical_value_bytes_read_back: metrics.bytes_read_back,
            read_batches: metrics.read_batches,
            source_read_operations: metrics.source_read_operations,
            sst_files_opened: metrics.sst_files_opened,
            unique_sst_generations: metrics.unique_sst_generations,
            sst_key_probes: metrics.sst_key_probes,
            sst_map_reuses: metrics.sst_map_reuses,
            sst_exact_route_lookups: metrics.sst_exact_route_lookups,
            sst_exact_route_hits: metrics.sst_exact_route_hits,
            sst_fallback_file_key_checks: metrics.sst_fallback_file_key_checks,
            plan_index_bytes: metrics.plan_index_bytes,
            max_readback_batch_bytes: metrics.max_readback_batch_bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ColumnDeterministicEvidence {
    rows_r: u32,
    dimension_d: u32,
    vault_path: PathBuf,
    vault_inventory_before: VaultInventory,
    vault_inventory_after: VaultInventory,
    compression_cf_physical_file_count: u64,
    compression_cf_physical_file_bytes: u64,
    primary_cf_physical_file_count: u64,
    primary_cf_physical_file_bytes: u64,
    source_prefix_sha256: String,
    selected_column_families: Vec<String>,
    snapshot: Seq,
    slot_id: u16,
    slot_key: String,
    lens_id: String,
    codec: StoredSlotCodec,
    codec_context_sha256: String,
    query_cx_id: String,
    point_cx_id: String,
    receipt_sha256: String,
    receipt_source_values_sha256: String,
    receipt_query_cx_id: String,
    receipt_backend: String,
    receipt_k: u32,
    receipt_warmups_u: u32,
    receipt_measured_m: u32,
    generation: CompressedGenerationIdentity,
    decoded_values: usize,
    decoded_sha256: String,
    selected_values: Vec<SelectedValueEvidence>,
    selected_logical_value_bytes: u64,
    manifest_plan_metrics: OrderedLogicalMetrics,
    primary_and_proof_plan_metrics: OrderedLogicalMetrics,
    ordered_logical_metrics: OrderedLogicalMetrics,
    allocation_scope: String,
    allocation_samples: Vec<AllocationTuple>,
    allocation_tuples_identical: bool,
    allocation_warmups_u: u32,
    allocation_measured_m: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ColumnEvidence {
    deterministic: ColumnDeterministicEvidence,
    latency_scope: String,
    latency_warmups_u: u32,
    latency_measured_m: u32,
    latency_samples_ns: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PointCostReport {
    schema: String,
    production_truth: ProductionTruth,
    cost_function: String,
    controlled_variable: String,
    loop_invariant: String,
    latency_claim: String,
    vault_id: String,
    vault_salt_sha256: String,
    backend: String,
    k: u32,
    warmups_u: u32,
    measured_m: u32,
    columns: Vec<ColumnEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PointCostReadback {
    schema: String,
    source_report_path: PathBuf,
    source_report_sha256: String,
    source_deterministic_sha256: String,
    fresh_deterministic_sha256: String,
    deterministic_evidence_equal: bool,
    production_truth: ProductionTruth,
    fresh_latency_samples_ns: Vec<Vec<u64>>,
}

#[derive(Clone)]
struct MeasurementInvariant {
    held_out_raw: Vec<u8>,
    point_raw: Vec<u8>,
}

pub(super) fn exercise(root: &Path) -> AnyResult<()> {
    let root = canonicalize_existing_or_prospective_directory(root)?;
    let directory = root.join(POINT_COST_DIRECTORY);
    require(
        !directory.exists(),
        format!(
            "point-read cost root already exists: {}",
            directory.display()
        ),
    )?;
    let production_vault = required_production_vault()?;
    require_disjoint_point_cost_roots(&directory, &production_vault)?;
    fs::create_dir_all(&directory)?;
    let directory = fs::canonicalize(directory)?;
    require_disjoint_point_cost_roots(&directory, &production_vault)?;
    let source = preflight_source()?;
    let invariant = measurement_invariant(&source);
    for rows in PREFIX_ROWS {
        let source_prefix_sha256 = source
            .prefix_sha256_by_rows
            .get(&rows)
            .ok_or_else(|| format!("source preflight omitted R={rows} prefix SHA-256"))?;
        build_prefix_generation(
            &directory.join(format!("r-{rows}")),
            rows,
            &source,
            &invariant,
            source_prefix_sha256,
        )?;
    }
    let report = collect_report(&directory, &production_vault, source, &invariant)?;
    let report_path = directory.join(POINT_COST_REPORT);
    let report_sha256 = write_json(&report_path, &report)?;
    println!(
        "{}",
        json!({
            "event": "compression_point_read_cost_success",
            "schema": POINT_COST_SCHEMA,
            "report_path": report_path,
            "report_sha256": report_sha256,
            "rows_r": ALL_ROWS,
            "dimension_d": PRODUCTION_DIM,
            "codec": StoredSlotCodec::ScalarInt8,
            "allocation_tuples_deterministic": true,
            "latency_non_invariant": true,
        })
    );
    Ok(())
}

pub(super) fn readback(root: &Path) -> AnyResult<()> {
    let directory = root.join(POINT_COST_DIRECTORY);
    require(
        directory.is_dir(),
        format!("point-read cost root is absent: {}", directory.display()),
    )?;
    let directory = fs::canonicalize(directory)?;
    let production_vault = required_production_vault()?;
    require_disjoint_point_cost_roots(&directory, &production_vault)?;
    let report_path = directory.join(POINT_COST_REPORT);
    let report_bytes = fs::read(&report_path)?;
    let report: PointCostReport = serde_json::from_slice(&report_bytes)?;
    require(
        report.schema == POINT_COST_SCHEMA && json_bytes(&report)? == report_bytes,
        "point-read cost report schema or canonical bytes differ",
    )?;
    let source_report_sha256 = sha256_hex(&report_bytes);
    let source_deterministic_sha256 = deterministic_report_sha256(&report)?;
    let source = preflight_source()?;
    let invariant = measurement_invariant(&source);
    let fresh = collect_report(&directory, &production_vault, source, &invariant)?;
    require(
        fresh.production_truth == report.production_truth,
        "production source truth changed in fresh readback",
    )?;
    require(
        fresh.schema == report.schema
            && fresh.cost_function == report.cost_function
            && fresh.controlled_variable == report.controlled_variable
            && fresh.loop_invariant == report.loop_invariant
            && fresh.latency_claim == report.latency_claim
            && fresh.vault_id == report.vault_id
            && fresh.vault_salt_sha256 == report.vault_salt_sha256
            && fresh.backend == report.backend
            && fresh.k == report.k
            && fresh.warmups_u == report.warmups_u
            && fresh.measured_m == report.measured_m
            && fresh.columns.len() == report.columns.len()
            && fresh
                .columns
                .iter()
                .zip(&report.columns)
                .all(|(left, right)| {
                    left.deterministic == right.deterministic
                        && left.latency_scope == right.latency_scope
                        && left.latency_warmups_u == right.latency_warmups_u
                        && left.latency_measured_m == right.latency_measured_m
                }),
        "deterministic point-read cost evidence changed in fresh process",
    )?;
    let fresh_deterministic_sha256 = deterministic_report_sha256(&fresh)?;
    require(
        fresh_deterministic_sha256 == source_deterministic_sha256,
        "canonical deterministic point-read projection changed in fresh process",
    )?;
    let readback = PointCostReadback {
        schema: POINT_COST_READBACK_SCHEMA.to_string(),
        source_report_path: report_path.clone(),
        source_report_sha256: source_report_sha256.clone(),
        source_deterministic_sha256: source_deterministic_sha256.clone(),
        fresh_deterministic_sha256: fresh_deterministic_sha256.clone(),
        deterministic_evidence_equal: true,
        production_truth: fresh.production_truth,
        fresh_latency_samples_ns: fresh
            .columns
            .into_iter()
            .map(|column| column.latency_samples_ns)
            .collect(),
    };
    let readback_path = directory.join(POINT_COST_READBACK_REPORT);
    require(
        !readback_path.exists(),
        format!(
            "point-cost readback already exists: {}",
            readback_path.display()
        ),
    )?;
    let readback_sha256 = write_json(&readback_path, &readback)?;
    println!(
        "{}",
        json!({
            "event": "compression_point_read_cost_readback_success",
            "schema": POINT_COST_READBACK_SCHEMA,
            "source_report_path": report_path,
            "source_report_sha256": source_report_sha256,
            "source_deterministic_sha256": source_deterministic_sha256,
            "fresh_deterministic_sha256": fresh_deterministic_sha256,
            "readback_path": readback_path,
            "readback_sha256": readback_sha256,
            "deterministic_evidence_equal": true,
            "latency_excluded_from_equality": true,
        })
    );
    Ok(())
}

fn collect_report(
    directory: &Path,
    production_vault: &Path,
    mut source: SourcePreflight,
    invariant: &MeasurementInvariant,
) -> AnyResult<PointCostReport> {
    let mut columns = Vec::with_capacity(ALL_ROWS.len());
    for rows in PREFIX_ROWS {
        let source_prefix_sha256 = source
            .prefix_sha256_by_rows
            .get(&rows)
            .ok_or_else(|| format!("source preflight omitted R={rows} prefix SHA-256"))?;
        columns.push(measure_column(
            &directory.join(format!("r-{rows}")).join("vault"),
            rows,
            invariant,
            source_prefix_sha256,
        )?);
    }
    let production_prefix_sha256 = source
        .prefix_sha256_by_rows
        .get(&PRODUCTION_CORPUS_ROWS)
        .ok_or("source preflight omitted production prefix SHA-256")?;
    columns.push(measure_column(
        production_vault,
        PRODUCTION_CORPUS_ROWS,
        invariant,
        production_prefix_sha256,
    )?);
    validate_controlled_columns(&columns)?;
    source.truth.database_sha256_after = sha256_file(&source.truth.path)?;
    require(
        source.truth.database_sha256_after == source.truth.database_sha256_before,
        "production SQLite source changed during point-read cost FSV",
    )?;
    Ok(PointCostReport {
        schema: POINT_COST_SCHEMA.to_string(),
        production_truth: source.truth,
        cost_function: "for one retained selected-CF handle, let U_c and U_s be the distinct exact keys indexed for Compression and slot_93, F_c and F_s their immutable-file counts, B_m/B_p/B_h the selected manifest/primary/proof value bytes, and G the selected immutable generations. The exact read_at path has Q_c=2 and Q_s=1: it performs three B-tree exact-route lookups whose route objects borrow already-validated lookup keys, requires three hits and zero fallback file/key checks, and does not loop over F_c or F_s. In-handle CPU is O(2*log(U_c)+log(U_s)+B_m+B_p+B_h+D); transient plan/value memory is O(Q+G+B_m+B_p+B_h+D) for fixed Q=3, while the retained route index adds O(U_c+U_s) references without cloning corpus key bytes. Cold selected-handle open is outside every measured loop: it still validates P_c+P_s selected SST bytes and inserts E_c+E_s lookup entries in O(P_c+P_s+E_c*log(U_c)+E_s*log(U_s)), so this report makes no cold-open or end-to-end MCP bound; #876 owns that remaining physical-open/repeated-verification cost. It retains separate manifest and primary+proof metrics, exact selected-value/proof sizes, and exact calling-thread allocation tuples observed only at R=1024,8192,49496; it makes no asymptotic allocation or wall-time claim and performs no R-row primary materialization".to_string(),
        controlled_variable: "R only: nested exact C-code-poly prefixes 1024 < 8192 < 49496; D=768, ScalarInt8, slot/lens, vault identity/salt, held-out query, point key, CPU backend, k=1, U=1, and M=3 are invariant. One ordered SQL preflight pass updates a fixed four hashers (one full-stream plus three prefix identities) while retaining only the first decoded vector".to_string(),
        loop_invariant: "within each measured loop: exact artifact process, canonical vault path, selected Compression+slot_93 roster, one fixed snapshot, Panel/Registry/lens/codec context, manifest/generation/membership roots, CxId/key and proof key; the generation-derived snapshot may differ across R, and only allocation event counters or elapsed clock ticks are observed within a loop".to_string(),
        latency_claim: "latency loop is separate from allocation counting, runs after one warmup, and records wall nanoseconds only; OS cache and host load are uncontrolled, so latency is non-invariant descriptive evidence and no cross-run speedup is claimed".to_string(),
        vault_id: VAULT_ID.to_string(),
        vault_salt_sha256: sha256_hex(VAULT_SALT),
        backend: "cpu".to_string(),
        k: 1,
        warmups_u: WARMUP_RUNS,
        measured_m: COST_SAMPLES,
        columns,
    })
}

fn validate_controlled_columns(columns: &[ColumnEvidence]) -> AnyResult<()> {
    require(
        columns.len() == ALL_ROWS.len()
            && columns
                .iter()
                .zip(ALL_ROWS)
                .all(|(column, rows)| column.deterministic.rows_r == rows),
        "point-cost columns are not the exact increasing R roster",
    )?;
    let first = &columns[0].deterministic;
    for column in columns.iter().skip(1).map(|column| &column.deterministic) {
        require(
            column.dimension_d == first.dimension_d
                && column.slot_id == first.slot_id
                && column.slot_key == first.slot_key
                && column.lens_id == first.lens_id
                && column.codec == first.codec
                && column.codec_context_sha256 == first.codec_context_sha256
                && column.query_cx_id == first.query_cx_id
                && column.point_cx_id == first.point_cx_id
                && column.decoded_sha256 == first.decoded_sha256
                && column.receipt_query_cx_id == first.receipt_query_cx_id
                && column.receipt_backend == first.receipt_backend
                && column.receipt_k == first.receipt_k
                && column.receipt_warmups_u == first.receipt_warmups_u
                && column.receipt_measured_m == first.receipt_measured_m
                && column.selected_column_families == first.selected_column_families,
            "point-cost invariant changed between R columns",
        )?;
    }
    require(
        columns.windows(2).all(|pair| {
            pair[0].deterministic.primary_cf_physical_file_bytes
                < pair[1].deterministic.primary_cf_physical_file_bytes
        }),
        "primary CF physical file bytes did not increase with R",
    )?;
    let manifest_bytes = selected_role_bytes(first, "generation_manifest")?;
    let primary_bytes = selected_role_bytes(first, "compressed_primary")?;
    let mut proof_bytes = Vec::with_capacity(columns.len());
    let mut primary_sha256s = Vec::with_capacity(columns.len());
    for column in columns {
        let deterministic = &column.deterministic;
        decode_hex_32(&deterministic.source_prefix_sha256)?;
        decode_hex_32(&deterministic.receipt_source_values_sha256)?;
        let current_primary_sha256 = selected_role_sha256(deterministic, "compressed_primary")?;
        decode_hex_32(current_primary_sha256)?;
        let current_manifest_bytes = selected_role_bytes(deterministic, "generation_manifest")?;
        let current_primary_bytes = selected_role_bytes(deterministic, "compressed_primary")?;
        let current_proof_bytes = selected_role_bytes(deterministic, "membership_proof")?;
        let primary_and_proof_bytes = current_primary_bytes
            .checked_add(current_proof_bytes)
            .ok_or("primary+proof logical byte count overflow")?;
        require(
            current_manifest_bytes == manifest_bytes
                && current_primary_bytes == primary_bytes
                && deterministic.compression_cf_physical_file_count > 0
                && deterministic.primary_cf_physical_file_count > 0
                && deterministic.selected_values.len() == 3
                && deterministic.manifest_plan_metrics.requested_keys == 1
                && deterministic.manifest_plan_metrics.rows_read_back == 1
                && deterministic
                    .manifest_plan_metrics
                    .logical_value_bytes_read_back
                    == current_manifest_bytes
                && deterministic.manifest_plan_metrics.read_batches == 1
                && deterministic.manifest_plan_metrics.sst_exact_route_lookups == 1
                && deterministic.manifest_plan_metrics.sst_exact_route_hits == 1
                && deterministic
                    .manifest_plan_metrics
                    .sst_fallback_file_key_checks
                    == 0
                && deterministic.manifest_plan_metrics.sst_files_opened
                    == deterministic.manifest_plan_metrics.unique_sst_generations
                && deterministic.primary_and_proof_plan_metrics.requested_keys == 2
                && deterministic.primary_and_proof_plan_metrics.rows_read_back == 2
                && deterministic
                    .primary_and_proof_plan_metrics
                    .logical_value_bytes_read_back
                    == primary_and_proof_bytes
                && deterministic.primary_and_proof_plan_metrics.read_batches == 2
                && deterministic
                    .primary_and_proof_plan_metrics
                    .sst_exact_route_lookups
                    == 2
                && deterministic
                    .primary_and_proof_plan_metrics
                    .sst_exact_route_hits
                    == 2
                && deterministic
                    .primary_and_proof_plan_metrics
                    .sst_fallback_file_key_checks
                    == 0
                && deterministic
                    .primary_and_proof_plan_metrics
                    .sst_files_opened
                    == deterministic
                        .primary_and_proof_plan_metrics
                        .unique_sst_generations
                && deterministic.ordered_logical_metrics.requested_keys == 3
                && deterministic.ordered_logical_metrics.rows_read_back == 3
                && deterministic.ordered_logical_metrics.read_batches == 3
                && deterministic
                    .ordered_logical_metrics
                    .sst_exact_route_lookups
                    == 3
                && deterministic.ordered_logical_metrics.sst_exact_route_hits == 3
                && deterministic
                    .ordered_logical_metrics
                    .sst_fallback_file_key_checks
                    == 0
                && deterministic
                    .ordered_logical_metrics
                    .logical_value_bytes_read_back
                    == deterministic.selected_logical_value_bytes,
            "controlled point-read selected-row contract changed",
        )?;
        proof_bytes.push(current_proof_bytes);
        primary_sha256s.push(current_primary_sha256.to_string());
    }
    require(
        proof_bytes.windows(2).all(|pair| pair[0] < pair[1]),
        "membership-proof logical bytes did not increase with Merkle height",
    )?;
    require(
        columns.windows(2).all(|pair| {
            pair[0].deterministic.source_prefix_sha256 != pair[1].deterministic.source_prefix_sha256
                && pair[0].deterministic.receipt_source_values_sha256
                    != pair[1].deterministic.receipt_source_values_sha256
        }) && primary_sha256s.windows(2).all(|pair| pair[0] != pair[1]),
        "increasing source prefixes, persisted source-value sets, or authenticated primary envelopes did not retain distinct exact hashes",
    )?;
    Ok(())
}

fn selected_role_bytes(column: &ColumnDeterministicEvidence, role: &str) -> AnyResult<u64> {
    column
        .selected_values
        .iter()
        .find(|row| row.role == role)
        .map(|row| row.value_bytes)
        .ok_or_else(|| format!("selected point plan omitted role {role}").into())
}

fn selected_role_sha256<'a>(
    column: &'a ColumnDeterministicEvidence,
    role: &str,
) -> AnyResult<&'a str> {
    column
        .selected_values
        .iter()
        .find(|row| row.role == role)
        .map(|row| row.value_sha256.as_str())
        .ok_or_else(|| format!("selected point plan omitted role {role}").into())
}

fn build_prefix_generation(
    root: &Path,
    rows_r: u32,
    source: &SourcePreflight,
    invariant: &MeasurementInvariant,
    expected_source_prefix_sha256: &str,
) -> AnyResult<()> {
    require(
        !root.exists() && PREFIX_ROWS.contains(&rows_r),
        format!("invalid or pre-existing prefix root: {}", root.display()),
    )?;
    fs::create_dir_all(root)?;
    let vault_dir = root.join("vault");
    let mut registry = Registry::new();
    let registered = register_dim(
        &mut registry,
        "issues-557-564-c-code-poly-int8",
        PRODUCTION_SLOT,
        QuantPolicy::ScalarInt8,
        PRODUCTION_DIM,
    )?;
    let panel = panel_for_slots([registered.slot.clone()]);
    let vault = open_write_vault(&vault_dir, &panel)?;
    persist_single_slot_panel(&vault_dir, &registry, &panel)?;
    let query_cx_id = vault.cx_id_for_input(&invariant.held_out_raw, PANEL_VERSION);
    let point_cx_id = vault.cx_id_for_input(&invariant.point_raw, PANEL_VERSION);

    let connection = Connection::open_with_flags(
        PRODUCTION_DB,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.pragma_update(None, "query_only", true)?;
    connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
    let mut statement = connection.prepare(
        "SELECT node_id, project, vector FROM node_vectors WHERE project = ?1 ORDER BY node_id ASC LIMIT ?2",
    )?;
    let limit = i64::from(rows_r)
        .checked_add(1)
        .ok_or("prefix query limit overflow")?;
    let mut source_rows = statement.query(params![PRODUCTION_PROJECT, limit])?;
    let mut scanned = 0_u32;
    let mut ingested = 0_u32;
    let mut chunk_rows = 0_usize;
    let mut stream: Option<StreamIngester<SystemClock>> = None;
    let mut stream_hash = Sha256::new();
    stream_hash.update(b"issues-557-564-point-read-prefix-v1");
    stream_hash.update(rows_r.to_be_bytes());
    while let Some(row) = source_rows.next()? {
        let node_id: i64 = row.get(0)?;
        let project: String = row.get(1)?;
        let blob: Vec<u8> = row.get(2)?;
        require(
            project == PRODUCTION_PROJECT && blob.len() == PRODUCTION_DIM as usize,
            "prefix source row violated project/dimension",
        )?;
        production_stream_hash_row(&mut stream_hash, node_id, &project, &blob);
        let values = decode_cbm_i8_vector(&blob)?;
        scanned = scanned
            .checked_add(1)
            .ok_or("prefix scanned row count overflow")?;
        if scanned == 1 {
            require(
                node_id == source.truth.first_node_id
                    && values == source.first_vector
                    && vault.cx_id_for_input(&invariant.held_out_raw, PANEL_VERSION) == query_cx_id,
                "prefix held-out row differs from production preflight",
            )?;
            continue;
        }
        let input = production_input(node_id, registered.slot.slot_id, values);
        let cx_id = vault.cx_id_for_input(&input.raw_bytes, input.panel_version);
        if ingested == 0 {
            require(
                node_id == source.truth.point_node_id && cx_id == point_cx_id,
                "prefix first corpus row differs from invariant point identity",
            )?;
        }
        if stream.is_none() {
            stream = Some(StreamIngester::new(
                Arc::clone(&vault),
                BackpressureGuard::new(256, 0),
            ));
        }
        stream
            .as_ref()
            .ok_or("prefix stream disappeared")?
            .send(input, EpochSecs(60_000 + i64::from(ingested)))?;
        ingested = ingested
            .checked_add(1)
            .ok_or("prefix ingested row count overflow")?;
        chunk_rows += 1;
        if chunk_rows == 256 {
            let stats = stream
                .take()
                .ok_or("prefix stream chunk disappeared")?
                .drain_and_close()?;
            require(
                stats.ingested == chunk_rows,
                "prefix stream chunk lost rows",
            )?;
            chunk_rows = 0;
        }
    }
    if let Some(stream) = stream {
        let stats = stream.drain_and_close()?;
        require(
            stats.ingested == chunk_rows,
            "prefix final stream lost rows",
        )?;
    }
    drop(source_rows);
    drop(statement);
    connection.execute_batch("COMMIT")?;
    drop(connection);
    require(
        scanned == rows_r + 1
            && ingested == rows_r
            && hex(&stream_hash.clone().finalize()) == expected_source_prefix_sha256,
        "prefix did not consume the exact hash-bound held-out + R ordered rows",
    )?;

    let query = CompressionQuery {
        cx_id: query_cx_id,
        values: source.first_vector.clone(),
    };
    let work = exact_work_plan(
        &[candidate_work_spec(
            &registered.slot,
            rows_r,
            PRODUCTION_DIM,
        )?],
        1,
    )?;
    let candidate = registry.build_and_evaluate_compression_candidate(
        &vault,
        &registered.slot,
        candidate_request_with_k(vec![query], 1, work.limits.clone(), production_gates()),
    )?;
    require(
        candidate.generation.stored_codec == StoredSlotCodec::ScalarInt8
            && candidate.generation.rows.len() == rows_r as usize
            && candidate.generation.fallback_reason.is_none(),
        "prefix candidate changed codec, row count, or fallback state",
    )?;
    require_unpublished_candidate(&candidate.evaluation)?;
    require_v3_work_plan(&candidate.evaluation.receipt, &work)?;
    require(
        candidate.evaluation.receipt.requested_backend == BackendKind::Cpu
            && candidate.evaluation.receipt.observed_backend == BackendKind::Cpu
            && candidate.evaluation.receipt.k == 1
            && candidate.evaluation.receipt.warmup_runs == WARMUP_RUNS
            && candidate.evaluation.receipt.measured_runs == MEASURED_RUNS
            && candidate.evaluation.receipt.queries.len() == 1
            && candidate.evaluation.receipt.queries[0].query_cx_id == query_cx_id,
        "prefix receipt changed backend/query/k/U/M invariants",
    )?;
    let generation_seq = candidate
        .generation
        .snapshot
        .ok_or("prefix candidate generation snapshot missing")?;
    let index = registry.compressed_slot_index(&vault, &registered.slot)?;
    let identity = index.generation_identity_at(generation_seq)?;
    require(
        identity.row_count == rows_r
            && identity.raw_dim == PRODUCTION_DIM
            && identity.stored_dim == PRODUCTION_DIM
            && identity.codec == StoredSlotCodec::ScalarInt8,
        "prefix generation identity differs after durable build",
    )?;
    println!(
        "{}",
        json!({
            "event": "compression_point_read_prefix_built",
            "rows_r": rows_r,
            "dimension_d": PRODUCTION_DIM,
            "codec": StoredSlotCodec::ScalarInt8,
            "query_cx_id": query_cx_id,
            "point_cx_id": point_cx_id,
            "generation": identity,
            "receipt_sha256": candidate.evaluation.receipt_sha256,
            "source_prefix_sha256": hex(&stream_hash.finalize()),
            "backend": "cpu",
            "k": 1,
            "warmups_u": WARMUP_RUNS,
            "measured_m": MEASURED_RUNS,
        })
    );
    drop(index);
    drop(vault);
    Ok(())
}

fn measure_column(
    vault_dir: &Path,
    rows_r: u32,
    invariant: &MeasurementInvariant,
    source_prefix_sha256: &str,
) -> AnyResult<ColumnEvidence> {
    let vault_dir = fs::canonicalize(vault_dir)?;
    let inventory_before = vault_inventory(&vault_dir)?;
    let compression_cf_physical_file_count = inventory_before.compression_cf_files;
    let compression_cf_physical_file_bytes = inventory_before.compression_cf_bytes;
    let primary_cf_physical_file_count = inventory_before.primary_cf_files;
    let primary_cf_physical_file_bytes = inventory_before.primary_cf_bytes;
    let state = load_vault_panel_state(&vault_dir)?;
    let slot = panel_slot(&state, PRODUCTION_SLOT)?.clone();
    require(
        state.panel.version == PANEL_VERSION
            && slot.slot_key.key() == "issues-557-564-c-code-poly-int8-slot"
            && slot.shape == SlotShape::Dense(PRODUCTION_DIM)
            && slot.quant == QuantPolicy::ScalarInt8,
        "point-cost Panel slot differs from invariant D/codec/lens contract",
    )?;
    let vault_id: VaultId = VAULT_ID.parse()?;
    let selected_cfs = vec![ColumnFamily::Compression, ColumnFamily::slot(slot.slot_id)];
    let selected_names = selected_cfs
        .iter()
        .map(|cf| cf.name().to_string())
        .collect::<Vec<_>>();
    let vault = AsterVault::<SystemClock>::open(
        &vault_dir,
        vault_id,
        VAULT_SALT.to_vec(),
        VaultOptions {
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(selected_cfs),
            ..VaultOptions::default()
        },
    )?;
    let snapshot = vault.latest_seq();
    let query_cx_id = vault.cx_id_for_input(&invariant.held_out_raw, PANEL_VERSION);
    let point_cx_id = vault.cx_id_for_input(&invariant.point_raw, PANEL_VERSION);
    let index = state.registry.compressed_slot_index(&vault, &slot)?;
    let generation = index.generation_identity_at(snapshot)?;
    require(
        generation.row_count == rows_r
            && generation.codec == StoredSlotCodec::ScalarInt8
            && generation.raw_dim == PRODUCTION_DIM
            && generation.stored_dim == PRODUCTION_DIM,
        "point-cost generation differs from expected R/D/codec",
    )?;
    let status = state.registry.compression_admission_status(&vault, &slot)?;
    let latest = status
        .latest_evaluation
        .as_ref()
        .ok_or("point-cost generation has no latest evaluation receipt")?;
    let receipt = &latest.receipt;
    require(
        receipt.corpus_rows == rows_r
            && receipt.requested_backend == BackendKind::Cpu
            && receipt.observed_backend == BackendKind::Cpu
            && receipt.codec == generation.codec
            && receipt.raw_dim == generation.raw_dim
            && receipt.stored_dim == generation.stored_dim
            && receipt.codec_context_sha256 == generation.codec_context_sha256
            && receipt.generation_sha256 == generation.generation_sha256
            && receipt.raw_generation_sha256 == generation.raw_generation_sha256
            && receipt.membership_sha256 == generation.membership_sha256
            && receipt.source_values_sha256.len() == 64
            && receipt.k == 1
            && receipt.warmup_runs == WARMUP_RUNS
            && receipt.measured_runs == MEASURED_RUNS
            && receipt.queries.len() == 1
            && receipt.queries[0].query_cx_id == query_cx_id,
        "point-cost persisted receipt changed backend/query/k/U/M invariants",
    )?;

    for _ in 0..WARMUP_RUNS {
        let vector = index.read_at(point_cx_id, snapshot)?;
        require_dense_shape(&vector)?;
    }
    let mut allocation_samples = Vec::with_capacity(COST_SAMPLES as usize);
    let mut decoded_sha256 = None;
    for sample in 0..COST_SAMPLES {
        let (result, allocation) = count_allocations(|| index.read_at(point_cx_id, snapshot));
        let vector = result?;
        let digest = require_dense_shape(&vector)?;
        if let Some(expected) = &decoded_sha256 {
            require(
                expected == &digest,
                format!("allocation sample {sample} changed decoded vector bytes"),
            )?;
        } else {
            decoded_sha256 = Some(digest);
        }
        require(!allocation.overflowed, "allocation tuple overflowed")?;
        allocation_samples.push(allocation);
    }
    let allocation_tuples_identical = allocation_samples.windows(2).all(|pair| pair[0] == pair[1]);
    require(
        allocation_tuples_identical,
        format!("R={rows_r} allocation tuples changed across identical point reads"),
    )?;

    for _ in 0..WARMUP_RUNS {
        let vector = index.read_at(point_cx_id, snapshot)?;
        require_dense_shape(&vector)?;
    }
    let mut latency_samples_ns = Vec::with_capacity(COST_SAMPLES as usize);
    for sample in 0..COST_SAMPLES {
        let started = Instant::now();
        let vector = index.read_at(point_cx_id, snapshot)?;
        let elapsed = u64::try_from(started.elapsed().as_nanos())
            .map_err(|_| "point-read latency exceeds u64 nanoseconds")?;
        let digest = require_dense_shape(&vector)?;
        require(
            elapsed > 0 && decoded_sha256.as_ref() == Some(&digest),
            format!("latency sample {sample} was zero or changed decoded vector bytes"),
        )?;
        latency_samples_ns.push(elapsed);
    }

    let (selected_values, manifest_metrics, primary_and_proof_metrics, metrics) =
        selected_logical_values(&vault, slot.slot_id, point_cx_id, snapshot)?;
    let selected_logical_value_bytes = selected_values.iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(value.value_bytes)
            .ok_or("selected logical byte count overflow")
    })?;
    require(
        selected_values.len() == 3
            && metrics.session_snapshot_seq == snapshot
            && metrics.requested_keys == 3
            && metrics.rows_read_back == 3
            && metrics.read_batches == 3
            && metrics.bytes_read_back == selected_logical_value_bytes,
        "ordered logical point-read metrics differ from exact three-row plan",
    )?;
    require(
        manifest_metrics.sst_exact_route_lookups == 1
            && manifest_metrics.sst_exact_route_hits == 1
            && manifest_metrics.sst_fallback_file_key_checks == 0,
        format!("R={rows_r} manifest plan did not use one exact route without fallback"),
    )?;
    require(
        primary_and_proof_metrics.sst_exact_route_lookups == 2
            && primary_and_proof_metrics.sst_exact_route_hits == 2
            && primary_and_proof_metrics.sst_fallback_file_key_checks == 0,
        format!("R={rows_r} primary/proof plan did not use two exact routes without fallback"),
    )?;
    require(
        metrics.sst_exact_route_lookups == 3
            && metrics.sst_exact_route_hits == 3
            && metrics.sst_fallback_file_key_checks == 0,
        format!("R={rows_r} aggregate plan did not use three exact routes without fallback"),
    )?;
    drop(index);
    drop(vault);
    let inventory_after = vault_inventory(&vault_dir)?;
    require(
        inventory_after == inventory_before,
        format!("R={rows_r} vault bytes changed during read-only point-cost exercise"),
    )?;
    Ok(ColumnEvidence {
        deterministic: ColumnDeterministicEvidence {
            rows_r,
            dimension_d: PRODUCTION_DIM,
            vault_path: vault_dir,
            vault_inventory_before: inventory_before,
            vault_inventory_after: inventory_after,
            compression_cf_physical_file_count,
            compression_cf_physical_file_bytes,
            primary_cf_physical_file_count,
            primary_cf_physical_file_bytes,
            source_prefix_sha256: source_prefix_sha256.to_string(),
            selected_column_families: selected_names,
            snapshot,
            slot_id: slot.slot_id.get(),
            slot_key: slot.slot_key.key().to_string(),
            lens_id: slot.lens_id.to_string(),
            codec: generation.codec,
            codec_context_sha256: generation.codec_context_sha256.clone(),
            query_cx_id: query_cx_id.to_string(),
            point_cx_id: point_cx_id.to_string(),
            receipt_sha256: latest.receipt_sha256.clone(),
            receipt_source_values_sha256: receipt.source_values_sha256.clone(),
            receipt_query_cx_id: receipt.queries[0].query_cx_id.to_string(),
            receipt_backend: format!("{:?}/{:?}", receipt.requested_backend, receipt.observed_backend),
            receipt_k: receipt.k,
            receipt_warmups_u: receipt.warmup_runs,
            receipt_measured_m: receipt.measured_runs,
            generation,
            decoded_values: PRODUCTION_DIM as usize,
            decoded_sha256: decoded_sha256.ok_or("decoded point digest missing")?,
            selected_values,
            selected_logical_value_bytes,
            manifest_plan_metrics: manifest_metrics.into(),
            primary_and_proof_plan_metrics: primary_and_proof_metrics.into(),
            ordered_logical_metrics: metrics.into(),
            allocation_scope: "exact GlobalAlloc calls and requested layout bytes on the calling thread only while the real CompressedSlotIndex::read_at executes; vault/Panel/Registry/codec construction, allocator internals, OS pages, and other threads are excluded".to_string(),
            allocation_samples,
            allocation_tuples_identical,
            allocation_warmups_u: WARMUP_RUNS,
            allocation_measured_m: COST_SAMPLES,
        },
        latency_scope: "separate Instant wall-nanosecond loop around read_at after one warmup; allocation counting disabled; OS cache/load uncontrolled and non-invariant".to_string(),
        latency_warmups_u: WARMUP_RUNS,
        latency_measured_m: COST_SAMPLES,
        latency_samples_ns,
    })
}

fn selected_logical_values(
    vault: &AsterVault<SystemClock>,
    slot_id: SlotId,
    cx_id: CxId,
    snapshot: Seq,
) -> AnyResult<(
    Vec<SelectedValueEvidence>,
    OrderedReadbackMetrics,
    OrderedReadbackMetrics,
    OrderedReadbackMetrics,
)> {
    let manifest_key = compression_manifest_key(slot_id);
    let primary_key = slot_key(cx_id);
    let proof_key = compression_membership_proof_key(slot_id, cx_id);
    let session = vault.sst_read_session_at(snapshot)?;
    let mut selected = Vec::with_capacity(3);
    let manifest_plan = [OrderedCfRead::new(
        0,
        ColumnFamily::Compression,
        &manifest_key,
    )];
    let manifest_metrics = session.visit_ordered_cf_plan::<CalyxError, _>(
        &manifest_plan,
        |ordinal, cf, key, value| {
            capture_selected_value(
                &mut selected,
                &["generation_manifest"],
                ordinal,
                cf,
                key,
                value,
            )
        },
    )?;
    let row_plan = [
        OrderedCfRead::new(0, ColumnFamily::slot(slot_id), &primary_key),
        OrderedCfRead::new(1, ColumnFamily::Compression, &proof_key),
    ];
    let row_metrics =
        session.visit_ordered_cf_plan::<CalyxError, _>(&row_plan, |ordinal, cf, key, value| {
            capture_selected_value(
                &mut selected,
                &["compressed_primary", "membership_proof"],
                ordinal,
                cf,
                key,
                value,
            )
        })?;
    let mut aggregate_metrics = manifest_metrics;
    aggregate_metrics.checked_merge(row_metrics)?;
    Ok((selected, manifest_metrics, row_metrics, aggregate_metrics))
}

fn capture_selected_value(
    output: &mut Vec<SelectedValueEvidence>,
    roles: &[&str],
    ordinal: usize,
    cf: ColumnFamily,
    key: &[u8],
    value: Option<&[u8]>,
) -> Result<(), CalyxError> {
    let role = roles.get(ordinal).ok_or_else(|| {
        CalyxError::aster_corrupt_shard(format!(
            "point-read callback returned unexpected ordinal {ordinal}"
        ))
    })?;
    let value = value.ok_or_else(|| {
        CalyxError::aster_corrupt_shard(format!(
            "point-read selected absent {role} in {}",
            cf.name()
        ))
    })?;
    if is_tombstone_value(value) {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "point-read selected tombstoned {role} in {}",
            cf.name()
        )));
    }
    output.push(SelectedValueEvidence {
        role: (*role).to_string(),
        column_family: cf.name().to_string(),
        key_hex: hex(key),
        value_bytes: value.len() as u64,
        value_sha256: sha256_hex(value),
    });
    Ok(())
}

fn require_dense_shape(vector: &SlotVector) -> AnyResult<String> {
    let SlotVector::Dense { dim, data } = vector else {
        return Err("point read returned a non-dense vector".into());
    };
    require(
        *dim == PRODUCTION_DIM && data.len() == PRODUCTION_DIM as usize,
        "point read returned wrong D=768 shape",
    )?;
    let mut hasher = Sha256::new();
    hasher.update(b"issues-557-564-point-read-decoded-f32-v1");
    hasher.update(dim.to_be_bytes());
    for value in data {
        hasher.update(value.to_bits().to_be_bytes());
    }
    Ok(hex(&hasher.finalize()))
}

fn preflight_source() -> AnyResult<SourcePreflight> {
    let path = PathBuf::from(PRODUCTION_DB);
    require(path.is_file(), "production C-code-poly database is absent")?;
    let database_bytes = fs::metadata(&path)?.len();
    let database_sha256 = sha256_file(&path)?;
    require(
        database_bytes == EXPECTED_PRODUCTION_DB_BYTES
            && database_sha256 == EXPECTED_PRODUCTION_DB_SHA256,
        "production database bytes/SHA-256 differ from the exact r14 source identity",
    )?;
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.pragma_update(None, "query_only", true)?;
    let query_only: i64 = connection.pragma_query_value(None, "query_only", |row| row.get(0))?;
    connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
    let source = preflight_point_cost_source(
        &connection,
        &path,
        database_bytes,
        database_sha256,
        query_only,
    )?;
    connection.execute_batch("COMMIT")?;
    drop(connection);
    require(
        source.truth.source_rows == PRODUCTION_ROWS
            && source.truth.dimension == PRODUCTION_DIM
            && source.truth.blob_bytes == u64::from(PRODUCTION_ROWS) * u64::from(PRODUCTION_DIM)
            && source.truth.first_node_id < source.truth.point_node_id
            && query_only == 1,
        "production source truth differs from exact C-code-poly contract",
    )?;
    Ok(source)
}

fn preflight_point_cost_source(
    connection: &Connection,
    path: &Path,
    database_bytes: u64,
    database_sha256: String,
    query_only: i64,
) -> AnyResult<SourcePreflight> {
    let schema: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='node_vectors'",
        [],
        |row| row.get(0),
    )?;
    require(
        schema.contains("node_id INTEGER PRIMARY KEY")
            && schema.contains("project TEXT NOT NULL")
            && schema.contains("vector BLOB NOT NULL")
            && query_only == 1,
        "point-cost source schema or query-only boundary differs from the exact contract",
    )?;
    let mut prefix_hashers = BTreeMap::new();
    for rows_r in ALL_ROWS {
        let mut hasher = Sha256::new();
        hasher.update(b"issues-557-564-point-read-prefix-v1");
        hasher.update(rows_r.to_be_bytes());
        prefix_hashers.insert(rows_r, hasher);
    }
    let mut stream_hasher = Sha256::new();
    stream_hasher.update(b"issues-557-564-c-code-poly-row-stream-v1");
    let mut statement = connection
        .prepare("SELECT node_id, project, vector FROM node_vectors ORDER BY node_id ASC")?;
    let mut rows = statement.query([])?;
    let mut count = 0_u32;
    let mut blob_bytes = 0_u64;
    let mut first_node_id = None;
    let mut point_node_id = None;
    let mut last_node_id = None;
    let mut first_vector = None;
    while let Some(row) = rows.next()? {
        let node_id: i64 = row.get(0)?;
        let project: String = row.get(1)?;
        let blob: Vec<u8> = row.get(2)?;
        require(
            project == PRODUCTION_PROJECT
                && blob.len() == PRODUCTION_DIM as usize
                && last_node_id.is_none_or(|previous| previous < node_id)
                && !blob.iter().any(|byte| *byte == 0x80),
            format!("point-cost preflight row {node_id} violated project/dimension/order/int8"),
        )?;
        count = count
            .checked_add(1)
            .ok_or("point-cost preflight row count overflow")?;
        blob_bytes = blob_bytes
            .checked_add(u64::try_from(blob.len())?)
            .ok_or("point-cost preflight blob byte count overflow")?;
        production_stream_hash_row(&mut stream_hasher, node_id, &project, &blob);
        for (rows_r, hasher) in &mut prefix_hashers {
            if count <= *rows_r + 1 {
                production_stream_hash_row(hasher, node_id, &project, &blob);
            }
        }
        if count == 1 {
            first_node_id = Some(node_id);
            first_vector = Some(decode_cbm_i8_vector(&blob)?);
        } else if count == 2 {
            point_node_id = Some(node_id);
        }
        last_node_id = Some(node_id);
    }
    drop(rows);
    drop(statement);
    let expected_blob_bytes = u64::from(PRODUCTION_ROWS)
        .checked_mul(u64::from(PRODUCTION_DIM))
        .ok_or("point-cost expected blob-byte count overflow")?;
    require(
        count == PRODUCTION_ROWS
            && blob_bytes == expected_blob_bytes
            && prefix_hashers.len() == ALL_ROWS.len(),
        format!(
            "point-cost source is not exact {PRODUCTION_ROWS}x{PRODUCTION_DIM}: rows={count} blob_bytes={blob_bytes}"
        ),
    )?;
    let prefix_sha256_by_rows: BTreeMap<u32, String> = prefix_hashers
        .into_iter()
        .map(|(rows_r, hasher)| (rows_r, hex(&hasher.finalize())))
        .collect();
    Ok(SourcePreflight {
        truth: ProductionTruth {
            path: path.to_path_buf(),
            database_bytes,
            database_sha256_before: database_sha256,
            database_sha256_after: String::new(),
            project: PRODUCTION_PROJECT.to_string(),
            source_rows: count,
            compressed_rows: PRODUCTION_CORPUS_ROWS,
            dimension: PRODUCTION_DIM,
            blob_bytes,
            first_node_id: first_node_id.ok_or("point-cost first node id missing")?,
            point_node_id: point_node_id.ok_or("point-cost point node id missing")?,
            last_node_id: last_node_id.ok_or("point-cost last node id missing")?,
            row_stream_sha256: hex(&stream_hasher.finalize()),
            sqlite_query_only: query_only,
        },
        first_vector: first_vector.ok_or("point-cost first vector missing")?,
        prefix_sha256_by_rows,
    })
}

fn measurement_invariant(source: &SourcePreflight) -> MeasurementInvariant {
    MeasurementInvariant {
        held_out_raw: format!("C-code-poly/node_vectors/{}", source.truth.first_node_id)
            .into_bytes(),
        point_raw: format!("C-code-poly/node_vectors/{}", source.truth.point_node_id).into_bytes(),
    }
}

fn required_production_vault() -> AnyResult<PathBuf> {
    let value = std::env::var(POINT_COST_PRODUCTION_VAULT_ENV)
        .map_err(|_| format!("{POINT_COST_PRODUCTION_VAULT_ENV} must be set"))?;
    let path = fs::canonicalize(value)?;
    require(
        path.is_dir(),
        format!("preserved production vault is absent: {}", path.display()),
    )?;
    Ok(path)
}

fn canonicalize_existing_or_prospective_directory(path: &Path) -> AnyResult<PathBuf> {
    let mut cursor = path;
    let mut suffix = Vec::<std::ffi::OsString>::new();
    loop {
        match fs::canonicalize(cursor) {
            Ok(mut canonical) => {
                require(
                    canonical.is_dir(),
                    format!(
                        "prospective point-cost ancestor is not a directory: {}",
                        canonical.display()
                    ),
                )?;
                for component in suffix.into_iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let component = cursor.file_name().ok_or_else(|| {
                    format!(
                        "prospective point-cost path has no existing ancestor: {}",
                        path.display()
                    )
                })?;
                suffix.push(component.to_os_string());
                cursor = cursor.parent().ok_or_else(|| {
                    format!(
                        "prospective point-cost path has no parent: {}",
                        path.display()
                    )
                })?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn require_disjoint_point_cost_roots(
    point_cost_root: &Path,
    production_vault: &Path,
) -> AnyResult<()> {
    require(
        !production_vault.starts_with(point_cost_root)
            && !point_cost_root.starts_with(production_vault),
        format!(
            "canonical point-cost and preserved production-vault roots must be disjoint: point_cost={} production={}",
            point_cost_root.display(),
            production_vault.display()
        ),
    )
}

fn vault_inventory(root: &Path) -> AnyResult<VaultInventory> {
    require(
        root.is_dir(),
        format!("point-cost vault root is absent: {}", root.display()),
    )?;
    let (mut paths, mut scope_states) = selected_vault_dependency_paths(root)?;
    paths.sort();
    require(
        !paths.windows(2).any(|pair| pair[0] == pair[1]),
        "point-cost dependency inventory selected a duplicate physical path",
    )?;
    scope_states.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"issues-557-564-point-read-vault-dependencies-v2");
    for value in [
        POINT_COST_VAULT_DEPENDENCY_SCOPE,
        POINT_COST_VAULT_EXCLUDED_PATHS,
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    for state in &scope_states {
        hasher.update((state.len() as u64).to_be_bytes());
        hasher.update(state.as_bytes());
    }
    let mut bytes = 0_u64;
    let mut compression_cf_files = 0_u64;
    let mut compression_cf_bytes = 0_u64;
    let mut primary_cf_files = 0_u64;
    let mut primary_cf_bytes = 0_u64;
    let compression_prefix = Path::new("cf").join("compression");
    let primary_prefix = Path::new("cf").join("slot_93");
    for path in &paths {
        let metadata = fs::symlink_metadata(path)?;
        require(
            metadata.file_type().is_file(),
            format!(
                "point-cost dependency inventory path is not a regular file: {}",
                path.display()
            ),
        )?;
        let relative = path.strip_prefix(root)?;
        let relative_path = relative.to_string_lossy().replace('\\', "/");
        bytes = bytes
            .checked_add(metadata.len())
            .ok_or("vault inventory byte count overflow")?;
        if relative.starts_with(&compression_prefix) {
            compression_cf_files = compression_cf_files
                .checked_add(1)
                .ok_or("Compression CF physical file count overflow")?;
            compression_cf_bytes = compression_cf_bytes
                .checked_add(metadata.len())
                .ok_or("Compression CF physical byte count overflow")?;
        }
        if relative.starts_with(&primary_prefix) {
            primary_cf_files = primary_cf_files
                .checked_add(1)
                .ok_or("primary CF physical file count overflow")?;
            primary_cf_bytes = primary_cf_bytes
                .checked_add(metadata.len())
                .ok_or("primary CF physical byte count overflow")?;
        }
        let sha256 = sha256_file(path)?;
        hasher.update((relative_path.len() as u64).to_be_bytes());
        hasher.update(relative_path.as_bytes());
        hasher.update(metadata.len().to_be_bytes());
        hasher.update(sha256.as_bytes());
    }
    Ok(VaultInventory {
        dependency_scope: POINT_COST_VAULT_DEPENDENCY_SCOPE.to_string(),
        excluded_paths: POINT_COST_VAULT_EXCLUDED_PATHS.to_string(),
        files: u64::try_from(paths.len())?,
        bytes,
        compression_cf_files,
        compression_cf_bytes,
        primary_cf_files,
        primary_cf_bytes,
        tree_sha256: hex(&hasher.finalize()),
    })
}

fn selected_vault_dependency_paths(root: &Path) -> AnyResult<(Vec<PathBuf>, Vec<String>)> {
    let mut paths = Vec::new();
    let mut scope_states = Vec::new();
    for relative in POINT_COST_ROOT_DEPENDENCY_FILES {
        collect_dependency_scope_path(
            root,
            Path::new(relative),
            false,
            &mut paths,
            &mut scope_states,
        )?;
    }
    scope_states.push("glob:manifest-*.json".to_string());
    let mut manifests = fs::read_dir(root)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(|entry| {
            let name = entry.file_name();
            let selected = name
                .to_str()
                .is_some_and(|name| name.starts_with("manifest-") && name.ends_with(".json"));
            selected.then(|| PathBuf::from(name))
        })
        .collect::<Vec<_>>();
    manifests.sort();
    for relative in manifests {
        collect_dependency_scope_path(root, &relative, false, &mut paths, &mut scope_states)?;
    }
    for relative in POINT_COST_DEPENDENCY_DIRECTORIES {
        collect_dependency_scope_path(
            root,
            Path::new(relative),
            true,
            &mut paths,
            &mut scope_states,
        )?;
    }
    Ok((paths, scope_states))
}

fn collect_dependency_scope_path(
    root: &Path,
    relative: &Path,
    recursive: bool,
    paths: &mut Vec<PathBuf>,
    scope_states: &mut Vec<String>,
) -> AnyResult<()> {
    let path = root.join(relative);
    let label = relative.to_string_lossy().replace('\\', "/");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            scope_states.push(format!("absent:{label}"));
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    require(
        !metadata_is_reparse_point(&metadata),
        format!(
            "point-cost dependency inventory refuses a reparse path: {}",
            path.display()
        ),
    )?;
    if recursive {
        require(
            metadata.is_dir(),
            format!(
                "point-cost dependency inventory expected a directory: {}",
                path.display()
            ),
        )?;
        scope_states.push(format!("directory:{label}"));
        collect_dependency_files(root, &path, paths)?;
    } else {
        require(
            metadata.is_file(),
            format!(
                "point-cost dependency inventory expected a regular file: {}",
                path.display()
            ),
        )?;
        scope_states.push(format!("file:{label}"));
        paths.push(path);
    }
    Ok(())
}

fn collect_dependency_files(
    root: &Path,
    current: &Path,
    paths: &mut Vec<PathBuf>,
) -> AnyResult<()> {
    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        require(
            !metadata_is_reparse_point(&metadata),
            format!(
                "point-cost dependency inventory refuses a reparse path: {}",
                path.display()
            ),
        )?;
        if metadata.is_dir() {
            collect_dependency_files(root, &path, paths)?;
        } else if metadata.is_file() {
            require(
                path.starts_with(root),
                format!(
                    "point-cost dependency inventory escaped its vault root: {}",
                    path.display()
                ),
            )?;
            paths.push(path);
        } else {
            return Err(format!(
                "point-cost dependency inventory refuses a special file: {}",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn deterministic_report_sha256(report: &PointCostReport) -> AnyResult<String> {
    let mut projection = report.clone();
    for column in &mut projection.columns {
        column.latency_samples_ns.clear();
    }
    Ok(sha256_hex(&json_bytes(&projection)?))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> AnyResult<String> {
    require(
        !path.exists(),
        format!("refusing to overwrite {}", path.display()),
    )?;
    let bytes = json_bytes(value)?;
    let mut file = File::options().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(sha256_hex(&bytes))
}

fn json_bytes<T: Serialize>(value: &T) -> AnyResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
