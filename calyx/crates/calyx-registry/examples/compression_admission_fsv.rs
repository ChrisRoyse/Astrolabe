//! Manual Full State Verification for compressed production reads and physical
//! admission (#557/#564).
//!
//! This is a real durable-vault exercise, not a unit-test harness. `exercise`
//! creates one fresh issue-owned vault, streams known vectors through Aster,
//! persists the exact Panel/Registry interpretation, produces three immutable
//! compressed generations with real codecs, executes their packed scorers, and
//! persists two admitted candidate receipts, publishes only their exact-rational
//! winner selection, and retains one deliberate gate refusal. It also exercises
//! the real D=4096 boundary and four isolated, durably corrupted vault copies.
//! `readback` is a separate-process, read-only inspection of the same bytes.
//! `production` consumes the real read-only C-code-poly node-vector database.
//! `prepare_mcp` produces a real uncompressed two-candidate shadow vault and
//! `_config.db`; `readback_mcp` independently inspects it after an MCP call.
//!
//! Source of truth: the reopened Aster primary/raw/Compression/Ledger column
//! families, immutable manifest and membership-proof rows, physical Ledger
//! view, and every regular file below the vault root. The readback phase hashes
//! those bytes independently and proves that read-only inspection changed no
//! file.
//!
//! Cost boundary (#1064 PC-02/03/05/35/41): the fixed manual fixture is
//! R=8 rows, D=32 coefficients, Q=2 held-out queries, U=1 warmup, M=3 measured
//! runs, and S=5 slots. The optional production leg preflights an exact
//! 49,497-row database, removes one exact row for Q=1, and measures
//! R=49,496, D=768, U=1, M=3; physical B is read from the real receipt, never
//! extrapolated. The small fixture makes no production cost claim. Admission
//! is O(B + R*D + Q*R*D + (U+M)*Q*R*D); direct packed search is O(R*D);
//! resolved point/batch reads are bounded by the requested CxIds plus their
//! proofs; whole-column verification is O(R*D + B_column).
//! Panel/Registry state and query values are invariant for the complete run and
//! are loaded once per process. The final filesystem audit is FSV-only O(F+B)
//! over file count F and retained bytes B; it is not reachable from production.
//!
//! Build/stage the real example with the canonical native launcher, then run
//! the same staged artifact twice through `scripts/native-fsv-run.ps1`:
//!
//! ```text
//! ASTROLABE_COMPRESSION_FSV_MODE=exercise
//! ASTROLABE_COMPRESSION_FSV_ROOT=C:\code\Astrolabe\.tmp\manual-fsv\issues-557-564\<run-id>
//! ASTROLABE_COMPRESSION_FSV_MODE=readback
//! ASTROLABE_COMPRESSION_FSV_ROOT=C:\code\Astrolabe\.tmp\manual-fsv\issues-557-564\<run-id>
//! ASTROLABE_COMPRESSION_FSV_MODE=production
//! ASTROLABE_COMPRESSION_FSV_ROOT=C:\code\Astrolabe\.tmp\manual-fsv\issues-557-564\<run-id>
//! ASTROLABE_COMPRESSION_FSV_MODE=prepare_mcp
//! ASTROLABE_COMPRESSION_FSV_ROOT=C:\code\Astrolabe\.tmp\manual-fsv\issues-557-564\<run-id>
//! ASTROLABE_COMPRESSION_FSV_MODE=readback_mcp
//! ASTROLABE_COMPRESSION_FSV_ROOT=C:\code\Astrolabe\.tmp\manual-fsv\issues-557-564\<run-id>
//! ```

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use calyx_aster::cf::{
    ColumnFamily, base_key, compression_admission_evaluation_pointer_key,
    compression_admission_pointer_key, compression_admission_receipt_key, compression_manifest_key,
    compression_membership_proof_key, compression_membership_proof_prefix_range, slot_key,
};
use calyx_aster::compression_lifecycle::CALYX_COMPRESSION_LIFECYCLE_INVALID;
use calyx_aster::dedup::{DedupPolicy, EpochSecs, IngestInput};
use calyx_aster::ledger_view::AsterLedgerCfStore;
use calyx_aster::stream::{BackpressureGuard, StreamIngester};
use calyx_aster::vault::{
    AsterVault, PhysicalCommitComponentRole, PhysicalCommitInventory, SlotVectorResolver,
    VaultOptions, encode,
};
use calyx_aster::wal::{Wal, WalOptions};
use calyx_core::{
    Asymmetry, CxId, LensId, Modality, Panel, QuantPolicy, Seq, Slot, SlotId, SlotResource,
    SlotShape, SlotState, SlotVector, SystemClock, VaultId,
};
use calyx_forge::BackendKind;
use calyx_ledger::{EntryKind, LedgerCfStore, VerifyResult, verify_chain};
use calyx_registry::{
    AlgorithmicLens, CALYX_VECTOR_COMPRESSION_INVALID, COMPRESSED_SLOT_TAG,
    COMPRESSION_ADMISSION_SCHEMA, CompressionAdmissionGates, CompressionAdmissionReadback,
    CompressionAdmissionReceipt, CompressionAdmissionVerdict, CompressionAdmissionWorkLimits,
    CompressionCandidateEvaluationRequest, CompressionCandidateReference, CompressionQuery,
    LensRuntime, LensSpec, Registry, StoredSlotCodec, VaultPanelState, load_vault_panel_state,
    persist_vault_panel_state,
};
use rusqlite::{Connection, OpenFlags, params};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DIM: u32 = 32;
const ROWS: usize = 8;
const PANEL_VERSION: u32 = 557_564;
const K: u32 = 2;
const WARMUP_RUNS: u32 = 1;
const MEASURED_RUNS: u32 = 3;
const TQ35_SLOT: u16 = 81;
const INT8_SLOT: u16 = 82;
const REFUSAL_SLOT: u16 = 83;
const UNSUPPORTED_SLOT: u16 = 84;
const EMPTY_SLOT: u16 = 85;
const MAX_DIM_SLOT: u16 = 91;
const OVER_LIMIT_DIM_SLOT: u16 = 92;
const PRODUCTION_SLOT: u16 = 93;
const MAX_SUPPORTED_DIM: u32 = 4096;
const OVER_LIMIT_DIM: u32 = 4097;
const PRODUCTION_ROWS: u32 = 49_497;
const PRODUCTION_CORPUS_ROWS: u32 = PRODUCTION_ROWS - 1;
const PRODUCTION_DIM: u32 = 768;
const PRODUCTION_PROJECT: &str = "C-code-poly";
const PRODUCTION_DB: &str = r"C:\Users\hotra\.cache\codebase-memory-mcp\C-code-poly.db";
const MCP_PROJECT: &str = "issues-557-564-compression-admission-fsv";
const VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const VAULT_SALT: &[u8] = b"issues-557-564-compression-admission-fsv";
const ROOT_ENV: &str = "ASTROLABE_COMPRESSION_FSV_ROOT";
const MODE_ENV: &str = "ASTROLABE_COMPRESSION_FSV_MODE";
const ADMISSION_MARKER: &str = COMPRESSION_ADMISSION_SCHEMA;

type AnyResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone)]
struct Registered {
    slot: Slot,
}

#[derive(Clone)]
struct KnownQuery {
    query: CompressionQuery,
    expected_top_k: Vec<CxId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct SlotStateReadback {
    seq: Seq,
    primary_rows: usize,
    primary_sha256: String,
    raw_rows: usize,
    raw_sha256: String,
    manifest_sha256: Option<String>,
    proof_rows: usize,
    proofs_sha256: String,
    latest_evaluation: Option<String>,
    current_admission: Option<String>,
    compression_rows: usize,
    compression_sha256: String,
    ledger_rows: usize,
    ledger_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct FileReadback {
    relative_path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct LivePhysicalComponentEvidence {
    identity: String,
    role: String,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct LivePhysicalInventoryEvidence {
    seq: Seq,
    manifest_seq: u64,
    column_families: Vec<String>,
    rows: usize,
    components: Vec<LivePhysicalComponentEvidence>,
    total_physical_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct PersistedSlotEvidence {
    slot_id: u16,
    codec: StoredSlotCodec,
    manifest_bytes: usize,
    manifest_sha256: String,
    primary_bytes: usize,
    primary_sha256: String,
    raw_bytes: usize,
    raw_sha256: String,
    proof_bytes: usize,
    proof_sha256: String,
    current_receipt_sha256: Option<String>,
    latest_receipt_sha256: String,
    verdict: CompressionAdmissionVerdict,
    allocation_scope: String,
    materialized_primary_rows_per_packed_search: u64,
    materialized_primary_bytes_per_packed_search: u64,
    packed_result_buffers_returned: u64,
    build_elapsed_ns: u64,
    vram_applicability: String,
    working_set_bytes_after: u64,
    immutable_physical_components_verified: usize,
}

fn main() {
    if let Err(error) = run() {
        println!(
            "{}",
            json!({
                "event": "compression_admission_fsv_failure",
                "error": error.to_string(),
            })
        );
        std::process::exit(1);
    }
}

fn run() -> AnyResult<()> {
    let workspace = std::env::current_dir()?;
    let root = issue_root(&workspace)?;
    let mode = std::env::var(MODE_ENV).map_err(|_| {
        format!(
            "{MODE_ENV} must be exactly `exercise`, `readback`, `production`, `prepare_mcp`, or `readback_mcp`"
        )
    })?;
    println!(
        "{}",
        json!({
            "event": "fsv_context",
            "mode": mode,
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "artifact": std::env::current_exe()?,
            "workspace": workspace,
            "fixture_root": root,
            "cost_boundary": {
                "rows_r": ROWS,
                "dimension_d": DIM,
                "held_out_queries_q": 2,
                "warmups_u": WARMUP_RUNS,
                "measured_runs_m": MEASURED_RUNS,
                "slots_s": 5,
                "production_r_d_q_u_m_b": "unknown for compressed generations; fixture is not a cost measurement",
            },
        })
    );
    match mode.as_str() {
        "exercise" => exercise(&root),
        "readback" => readback(&root),
        "production" => production(&root),
        "prepare_mcp" => prepare_mcp(&root),
        "readback_mcp" => readback_mcp(&root),
        other => Err(format!(
            "{MODE_ENV}={other:?}; expected `exercise`, `readback`, `production`, `prepare_mcp`, or `readback_mcp`"
        )
        .into()),
    }
}

fn exercise(root: &Path) -> AnyResult<()> {
    require(
        !root.exists(),
        format!("exercise root already exists: {}", root.display()),
    )?;
    fs::create_dir_all(root)?;
    let vault_dir = root.join("vault");
    let (registry, slots) = registry_and_slots()?;
    let panel = panel_for_slots(slots.iter().map(|registered| registered.slot.clone()));
    let vault = open_write_vault(&vault_dir, &panel)?;
    let panel_before = load_vault_panel_state(&vault_dir)?;
    require(
        panel_before.panel == panel && panel_before.registry_snapshot.is_none(),
        "fresh vault did not persist its exact Panel before Registry publication",
    )?;
    let persisted = persist_vault_panel_state(&vault_dir, &panel, &registry)?;
    let loaded = load_vault_panel_state(&vault_dir)?;
    require(loaded.panel == panel, "persisted Panel readback differs")?;
    require(
        loaded.registry_snapshot.is_some(),
        "persisted Registry snapshot is absent",
    )?;
    println!(
        "{}",
        json!({
            "event": "panel_registry_persisted",
            "before": {
                "panel_version": panel_before.panel.version,
                "slot_ids": panel_before.panel.slots.iter().map(|slot| slot.slot_id.get()).collect::<Vec<_>>(),
                "registry_snapshot_present": false,
            },
            "after": {
                "panel_version": loaded.panel.version,
                "slot_ids": loaded.panel.slots.iter().map(|slot| slot.slot_id.get()).collect::<Vec<_>>(),
                "manifest_seq": persisted.manifest_seq,
                "durable_seq": persisted.durable_seq,
                "panel_blake3": persisted.panel_ref.blake3_hex,
                "registry_blake3": persisted.registry_ref.blake3_hex,
            },
        })
    );

    let before_ingest = vault.latest_seq();
    let ingester = StreamIngester::new(Arc::clone(&vault), BackpressureGuard::new(64, 0));
    for row in 0..ROWS {
        ingester.send(
            ingest_event(row, &[TQ35_SLOT, INT8_SLOT, REFUSAL_SLOT, UNSUPPORTED_SLOT]),
            EpochSecs(10_000 + row as i64),
        )?;
    }
    let ingest = ingester.drain_and_close()?;
    vault.flush_with_report()?;
    require(ingest.ingested == ROWS, "stream ingest row count differs")?;
    let cx_ids = corpus_ids(&vault);
    let queries = known_queries(&vault, &cx_ids);

    println!(
        "{}",
        json!({
            "event": "stream_ingest_state",
            "before": { "seq": before_ingest },
            "after": {
                "seq": vault.latest_seq(),
                "ingested": ingest.ingested,
                "batches": ingest.batches,
                "cx_ids": cx_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
            },
        })
    );

    let tq35 = exact_registered(&slots, TQ35_SLOT)?;
    let int8 = exact_registered(&slots, INT8_SLOT)?;
    let refusal = exact_registered(&slots, REFUSAL_SLOT)?;
    let unsupported = exact_registered(&slots, UNSUPPORTED_SLOT)?;
    let empty = exact_registered(&slots, EMPTY_SLOT)?;

    let empty_corpus_before = slot_state(&vault, empty.slot.slot_id)?;
    let empty_corpus_error = registry
        .build_and_evaluate_compression_candidate(
            &vault,
            &empty.slot,
            candidate_request(
                query_inputs(&queries),
                exact_work_limits_for(1, DIM, DIM, queries.len())?,
                passing_gates(),
            ),
        )
        .expect_err("empty persisted candidate corpus must be refused");
    let empty_corpus_after = slot_state(&vault, empty.slot.slot_id)?;
    require(
        empty_corpus_before == empty_corpus_after,
        "empty-corpus refusal changed durable state",
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_empty_input_corpus_refused",
            "error": { "code": empty_corpus_error.code, "message": empty_corpus_error.message },
            "before": empty_corpus_before,
            "after": empty_corpus_after,
        })
    );

    // Unsupported TurboQuant-3.0 is a hard pre-mutation refusal. There is no
    // codec substitution and no raw-sidecar write.
    let unsupported_before = slot_state(&vault, unsupported.slot.slot_id)?;
    let unsupported_error = registry
        .build_and_evaluate_compression_candidate(
            &vault,
            &unsupported.slot,
            candidate_request(
                query_inputs(&queries),
                exact_work_limits_for(ROWS as u32, DIM, DIM, queries.len())?,
                passing_gates(),
            ),
        )
        .expect_err("unsupported TurboQuant level must be refused");
    let unsupported_after = slot_state(&vault, unsupported.slot.slot_id)?;
    require(
        unsupported_error.code == CALYX_VECTOR_COMPRESSION_INVALID
            && unsupported_before == unsupported_after,
        "unsupported codec refusal changed durable state",
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_unsupported_level_refused",
            "error": { "code": unsupported_error.code, "message": unsupported_error.message },
            "before": unsupported_before,
            "after": unsupported_after,
        })
    );

    let tq35_request = candidate_request(
        query_inputs(&queries),
        exact_work_limits_for(ROWS as u32, DIM, DIM, queries.len())?,
        passing_gates(),
    );

    let empty_before = slot_state(&vault, tq35.slot.slot_id)?;
    let mut empty_request = tq35_request.clone();
    empty_request.queries.clear();
    let empty_error = registry
        .build_and_evaluate_compression_candidate(&vault, &tq35.slot, empty_request)
        .expect_err("empty held-out query set must be refused");
    let empty_after = slot_state(&vault, tq35.slot.slot_id)?;
    require(
        empty_before == empty_after,
        "empty-query refusal changed durable state",
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_empty_queries_refused",
            "error": { "code": empty_error.code, "message": empty_error.message },
            "before": empty_before,
            "after": empty_after,
        })
    );

    let backend_before = slot_state(&vault, tq35.slot.slot_id)?;
    let mut cuda_request = tq35_request.clone();
    cuda_request.requested_backend = BackendKind::Cuda;
    let cuda_error = registry
        .build_and_evaluate_compression_candidate(&vault, &tq35.slot, cuda_request)
        .expect_err("unsupported CUDA packed backend must be refused");
    let backend_after = slot_state(&vault, tq35.slot.slot_id)?;
    require(
        backend_before == backend_after,
        "unsupported backend refusal changed durable state",
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_unsupported_backend_refused",
            "error": { "code": cuda_error.code, "message": cuda_error.message },
            "before": backend_before,
            "after": backend_after,
        })
    );

    let tq35_admission_before = slot_state(&vault, tq35.slot.slot_id)?;
    let tq35_candidate =
        registry.build_and_evaluate_compression_candidate(&vault, &tq35.slot, tq35_request)?;
    let tq35_report = &tq35_candidate.generation;
    require(
        tq35_report.stored_codec == StoredSlotCodec::TurboQuantBits3p5
            && tq35_report.fallback_reason.is_none(),
        "TurboQuant-3.5 generation was substituted",
    )?;
    let tq35_generation_seq = tq35_report.snapshot.ok_or("TQ3.5 snapshot missing")?;
    verify_direct_search(&registry, &vault, &tq35.slot, tq35_generation_seq, &queries)?;

    let tq35_index = registry.compressed_slot_index(&vault, &tq35.slot)?;
    let tq35_identity = tq35_index.generation_identity_at(tq35_generation_seq)?;
    let tq35_limits = exact_work_limits(&tq35_identity, queries.len())?;
    let (tq35_inventory, tq35_physical) =
        live_generation_inventory(&vault, &vault_dir, tq35.slot.slot_id, tq35_generation_seq)?;
    let tq35_admission = tq35_candidate.evaluation;
    require_unpublished_candidate(&tq35_admission)?;
    require_receipt_matches_inventory(&tq35_admission.receipt, &tq35_inventory)?;
    require(
        tq35_admission.receipt.work_limits == tq35_limits,
        "TQ3.5 receipt did not retain its exact work boundary",
    )?;
    let tq35_admission_after = slot_state(&vault, tq35.slot.slot_id)?;
    println!(
        "{}",
        json!({
            "event": "maximum_declared_work_boundary_admitted",
            "slot": TQ35_SLOT,
            "codec": tq35_report.stored_codec,
            "before": tq35_admission_before,
            "after": tq35_admission_after,
            "limits": tq35_limits,
            "observed_work": tq35_admission.receipt.work,
            "pre_admission_physical_inventory": tq35_physical,
            "allocation_materialization": tq35_admission.receipt.allocations,
            "process_resources": tq35_admission.receipt.resources,
            "receipt_sha256": tq35_admission.receipt_sha256,
            "physical_bytes": tq35_admission.receipt.total_physical_bytes,
        })
    );

    let int8_candidate = registry.build_and_evaluate_compression_candidate(
        &vault,
        &int8.slot,
        candidate_request(
            query_inputs(&queries),
            exact_work_limits_for(ROWS as u32, DIM, DIM, queries.len())?,
            passing_gates(),
        ),
    )?;
    let int8_report = &int8_candidate.generation;
    require(
        int8_report.stored_codec == StoredSlotCodec::ScalarInt8
            && int8_report.fallback_reason.is_none(),
        "ScalarInt8 generation was substituted",
    )?;
    let int8_generation_seq = int8_report.snapshot.ok_or("ScalarInt8 snapshot missing")?;
    verify_direct_search(&registry, &vault, &int8.slot, int8_generation_seq, &queries)?;
    let int8_identity = registry
        .compressed_slot_index(&vault, &int8.slot)?
        .generation_identity_at(int8_generation_seq)?;
    let int8_limits = exact_work_limits(&int8_identity, queries.len())?;
    let (int8_inventory, int8_physical) =
        live_generation_inventory(&vault, &vault_dir, int8.slot.slot_id, int8_generation_seq)?;
    let int8_admission = int8_candidate.evaluation;
    require_unpublished_candidate(&int8_admission)?;
    require_receipt_matches_inventory(&int8_admission.receipt, &int8_inventory)?;
    require(
        int8_admission.receipt.work_limits == int8_limits,
        "ScalarInt8 receipt did not retain its exact work boundary",
    )?;
    println!(
        "{}",
        json!({
            "event": "second_codec_evaluated_without_publication",
            "slot": INT8_SLOT,
            "codec": int8_report.stored_codec,
            "receipt_sha256": int8_admission.receipt_sha256,
            "verdict": int8_admission.receipt.verdict,
            "physical_bytes": int8_admission.receipt.total_physical_bytes,
            "pre_admission_physical_inventory": int8_physical,
        })
    );

    let selection_before_tq = slot_state(&vault, tq35.slot.slot_id)?;
    let selection_before_int8 = slot_state(&vault, int8.slot.slot_id)?;
    require(
        selection_before_tq.current_admission.is_none()
            && selection_before_int8.current_admission.is_none(),
        "passing candidates were published before multi-candidate selection",
    )?;
    let selected = registry.select_compression_candidate(
        &vault,
        &[
            CompressionCandidateReference {
                slot: tq35.slot.clone(),
                receipt_sha256: decode_hex_32(&tq35_admission.receipt_sha256)?,
            },
            CompressionCandidateReference {
                slot: int8.slot.clone(),
                receipt_sha256: decode_hex_32(&int8_admission.receipt_sha256)?,
            },
        ],
    )?;
    require_admitted(&selected)?;
    let selection = selected
        .receipt
        .candidate_selection
        .as_ref()
        .ok_or("selected receipt omitted its full candidate set")?;
    let expected_winner = if exact_physical_ratio_precedes(
        &tq35_admission.receipt,
        &tq35_admission.receipt_sha256,
        &int8_admission.receipt,
        &int8_admission.receipt_sha256,
    )? {
        TQ35_SLOT
    } else {
        INT8_SLOT
    };
    require(
        selection.winner_slot_id == expected_winner
            && selected.receipt.slot_id == expected_winner
            && selection.candidates.len() == 2,
        "persisted candidate-set selection did not choose the exact-rational physical winner",
    )?;
    let selection_after_tq = slot_state(&vault, tq35.slot.slot_id)?;
    let selection_after_int8 = slot_state(&vault, int8.slot.slot_id)?;
    let tq_is_current =
        selection_after_tq.current_admission.as_deref() == Some(selected.receipt_sha256.as_str());
    let int8_is_current =
        selection_after_int8.current_admission.as_deref() == Some(selected.receipt_sha256.as_str());
    require(
        tq_is_current ^ int8_is_current,
        "selection did not publish exactly one winner current pointer",
    )?;
    println!(
        "{}",
        json!({
            "event": "multi_codec_most_aggressive_selection",
            "before": { "tq35": selection_before_tq, "scalar_int8": selection_before_int8 },
            "after": { "tq35": selection_after_tq, "scalar_int8": selection_after_int8 },
            "selection_receipt_sha256": selected.receipt_sha256,
            "selection": selection,
            "build": selected.receipt.build,
            "placement": selected.receipt.placement,
            "allocations": selected.receipt.allocations,
        })
    );

    let refusal_before = slot_state(&vault, refusal.slot.slot_id)?;
    require(
        refusal_before.current_admission.is_none() && refusal_before.latest_evaluation.is_none(),
        "fresh gate-refusal slot unexpectedly had prior admission state",
    )?;
    let mut refusal_gates = passing_gates();
    refusal_gates.maximum_total_physical_bytes = 1;
    let refusal_candidate = registry.build_and_evaluate_compression_candidate(
        &vault,
        &refusal.slot,
        candidate_request(
            query_inputs(&queries),
            exact_work_limits_for(ROWS as u32, DIM, DIM, queries.len())?,
            refusal_gates,
        ),
    )?;
    let refusal_report = &refusal_candidate.generation;
    require(
        refusal_report.stored_codec == StoredSlotCodec::TurboQuantBits2p5
            && refusal_report.fallback_reason.is_none(),
        "gate-refusal generation was substituted",
    )?;
    let refusal_generation_seq = refusal_report.snapshot.ok_or("refusal snapshot missing")?;
    let refusal_identity = registry
        .compressed_slot_index(&vault, &refusal.slot)?
        .generation_identity_at(refusal_generation_seq)?;
    let (refusal_inventory, refusal_physical) = live_generation_inventory(
        &vault,
        &vault_dir,
        refusal.slot.slot_id,
        refusal_generation_seq,
    )?;
    let refusal_readback = refusal_candidate.evaluation;
    require(
        refusal_readback.receipt.work_limits
            == exact_work_limits(&refusal_identity, queries.len())?,
        "refusal receipt did not retain its exact work boundary",
    )?;
    require_receipt_matches_inventory(&refusal_readback.receipt, &refusal_inventory)?;
    require(
        refusal_readback.receipt.verdict == CompressionAdmissionVerdict::Refused
            && !refusal_readback.current
            && refusal_readback.pointer_commit_seq.is_none(),
        "deliberately failing physical-byte gate moved current admission",
    )?;
    let refusal_after = slot_state(&vault, refusal.slot.slot_id)?;
    require(
        refusal_before.current_admission.is_none()
            && refusal_after.current_admission.is_none()
            && refusal_after.manifest_sha256.is_some()
            && refusal_after.primary_rows == ROWS
            && refusal_after.raw_rows == ROWS
            && refusal_after.proof_rows == ROWS,
        "failed gates published a current admission or did not retain the evaluated generation",
    )?;
    require(
        refusal_after.latest_evaluation.as_deref()
            == Some(refusal_readback.receipt_sha256.as_str()),
        "failed gate receipt was not retained as latest evaluation",
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_gate_refusal_persisted_without_promotion",
            "before": refusal_before,
            "after": refusal_after,
            "receipt_sha256": refusal_readback.receipt_sha256,
            "verdict": refusal_readback.receipt.verdict,
            "failed_gates": refusal_readback.receipt.gate_observations.iter().filter(|gate| !gate.passed).collect::<Vec<_>>(),
            "pre_admission_physical_inventory": refusal_physical,
            "evaluated_generation_created_and_retained": true,
            "current_pointer_unchanged": true,
            "current_pointer_case": "absent_to_absent; admitted_to_unchanged requires retained-generation re-evaluation and is not claimed",
            "expected_state_change": "compressed generation, immutable refusal receipt, latest-evaluation pointer, and paired generation/admission Ledger rows",
        })
    );

    // A proof byte cannot be changed outside a complete generation transition.
    let proof_key = compression_membership_proof_key(tq35.slot.slot_id, cx_ids[0]);
    let proof_before = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::Compression, &proof_key)?
        .ok_or("TQ3.5 membership proof missing before corruption probe")?;
    let mut malformed_proof = proof_before.clone();
    let last = malformed_proof
        .last_mut()
        .ok_or("membership proof unexpectedly empty")?;
    *last ^= 0x80;
    let corrupt_before = slot_state(&vault, tq35.slot.slot_id)?;
    let proof_error = vault
        .write_cf(
            ColumnFamily::Compression,
            proof_key.clone(),
            malformed_proof,
        )
        .expect_err("isolated malformed membership proof must be refused");
    let corrupt_after = slot_state(&vault, tq35.slot.slot_id)?;
    let proof_after = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::Compression, &proof_key)?
        .ok_or("TQ3.5 membership proof missing after refusal")?;
    require(
        proof_error.code == CALYX_COMPRESSION_LIFECYCLE_INVALID
            && corrupt_before == corrupt_after
            && proof_before == proof_after,
        "malformed proof refusal did not preserve exact state",
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_malformed_membership_proof_refused",
            "error": { "code": proof_error.code, "message": proof_error.message },
            "before": corrupt_before,
            "after": corrupt_after,
            "proof_sha256_before": sha256_hex(&proof_before),
            "proof_sha256_after": sha256_hex(&proof_after),
        })
    );

    // Wrong frozen Panel/Registry interpretation is refused before reading a
    // compressed vector, and cannot mutate the durable generation.
    let wrong_context_before = slot_state(&vault, tq35.slot.slot_id)?;
    let mut wrong_context = loaded.clone();
    wrong_context
        .panel
        .slots
        .iter_mut()
        .find(|slot| slot.slot_id == tq35.slot.slot_id)
        .ok_or("TQ3.5 slot absent from loaded panel")?
        .lens_id = LensId::from_bytes([0xEE; 16]);
    let wrong_context_error = wrong_context
        .resolve_slot_vector_at(&vault, vault.latest_seq(), cx_ids[0], tq35.slot.slot_id)
        .expect_err("wrong manifest-backed Registry context must be refused");
    let wrong_context_after = slot_state(&vault, tq35.slot.slot_id)?;
    require(
        wrong_context_before == wrong_context_after,
        "wrong-context refusal changed durable state",
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_wrong_context_refused",
            "error": { "code": wrong_context_error.code, "message": wrong_context_error.message },
            "before": wrong_context_before,
            "after": wrong_context_after,
        })
    );

    vault.flush_with_report()?;
    let corruption_copies = snapshot_corruption_copies(&vault, root)?;
    drop(vault);
    persisted_corruption_edges(&corruption_copies)?;
    dimension_boundary_fsv(root)?;
    let persisted = verify_persisted_state(&vault_dir)?;
    println!(
        "{}",
        json!({
            "event": "exercise_reopen_verified",
            "source_of_truth": "fresh read-only Aster handle, raw CF point/range reads, physical Ledger view, and filesystem byte ranges",
            "slots": persisted,
            "fixture_root": root,
        })
    );
    println!(
        "{}",
        json!({
            "event": "compression_admission_fsv_exercise_success",
            "issues": [557, 564],
            "fixture_root": root,
            "next_required_mode": "readback",
        })
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum PersistedCorruption {
    PrimaryRow,
    MembershipProof,
    ManifestMembershipRoot,
    WrongKeyProofBinding,
}

impl PersistedCorruption {
    fn name(self) -> &'static str {
        match self {
            Self::PrimaryRow => "primary_row",
            Self::MembershipProof => "membership_proof",
            Self::ManifestMembershipRoot => "manifest_membership_root",
            Self::WrongKeyProofBinding => "wrong_key_proof_binding",
        }
    }

    fn expected_diagnostic(self) -> &'static str {
        match self {
            Self::PrimaryRow => "compressed slot SHA-256 mismatch",
            Self::MembershipProof => "compressed membership proof SHA-256 mismatch",
            Self::ManifestMembershipRoot => {
                "compressed membership proof root does not match its generation manifest"
            }
            Self::WrongKeyProofBinding => "compressed membership proof CxId",
        }
    }
}

fn snapshot_corruption_copies(
    vault: &AsterVault<SystemClock>,
    root: &Path,
) -> AnyResult<Vec<(PersistedCorruption, PathBuf)>> {
    let source_seq = vault.latest_seq();
    let source_state = slot_state(vault, SlotId::new(TQ35_SLOT))?;
    let mut copies = Vec::new();
    for kind in [
        PersistedCorruption::PrimaryRow,
        PersistedCorruption::MembershipProof,
        PersistedCorruption::ManifestMembershipRoot,
        PersistedCorruption::WrongKeyProofBinding,
    ] {
        let destination = root.join(format!("corrupt-{}-vault", kind.name()));
        vault.copy_durable_snapshot_to(&destination)?;
        let copied = open_read_vault_for_slots(&destination, &[SlotId::new(TQ35_SLOT)])?;
        let copied_state = slot_state(&copied, SlotId::new(TQ35_SLOT))?;
        require(
            copied_state == source_state,
            format!("{} snapshot logical state differs from source", kind.name()),
        )?;
        drop(copied);
        println!(
            "{}",
            json!({
                "event": "persisted_corruption_copy_prepared",
                "probe": kind.name(),
                "source_seq": source_seq,
                "destination": destination,
                "state": copied_state,
                "files": disk_inventory(&destination)?,
            })
        );
        copies.push((kind, destination));
    }
    Ok(copies)
}

fn persisted_corruption_edges(copies: &[(PersistedCorruption, PathBuf)]) -> AnyResult<()> {
    for (kind, directory) in copies {
        persisted_corruption_edge(*kind, directory)?;
    }
    Ok(())
}

fn persisted_corruption_edge(kind: PersistedCorruption, directory: &Path) -> AnyResult<()> {
    let state = load_vault_panel_state(directory)?;
    let slot = panel_slot(&state, TQ35_SLOT)?.clone();
    let before_vault = open_read_vault_for_slots(directory, &[slot.slot_id])?;
    let before = slot_state(&before_vault, slot.slot_id)?;
    let cx_ids = corpus_ids(&before_vault);
    let first = cx_ids[0];
    let second = cx_ids[1];
    let (cf, key, mut value) = match kind {
        PersistedCorruption::PrimaryRow => (
            ColumnFamily::slot(slot.slot_id),
            slot_key(first),
            required_row(
                &before_vault,
                before.seq,
                ColumnFamily::slot(slot.slot_id),
                &slot_key(first),
                "source primary row",
            )?,
        ),
        PersistedCorruption::MembershipProof => (
            ColumnFamily::Compression,
            compression_membership_proof_key(slot.slot_id, first),
            required_row(
                &before_vault,
                before.seq,
                ColumnFamily::Compression,
                &compression_membership_proof_key(slot.slot_id, first),
                "source membership proof",
            )?,
        ),
        PersistedCorruption::ManifestMembershipRoot => (
            ColumnFamily::Compression,
            compression_manifest_key(slot.slot_id),
            required_row(
                &before_vault,
                before.seq,
                ColumnFamily::Compression,
                &compression_manifest_key(slot.slot_id),
                "source compression manifest",
            )?,
        ),
        PersistedCorruption::WrongKeyProofBinding => (
            ColumnFamily::Compression,
            compression_membership_proof_key(slot.slot_id, second),
            required_row(
                &before_vault,
                before.seq,
                ColumnFamily::Compression,
                &compression_membership_proof_key(slot.slot_id, first),
                "source proof for wrong-key binding",
            )?,
        ),
    };
    let value_before = before_vault.read_cf_at(before.seq, cf, &key)?;
    let files_before = disk_inventory(directory)?;
    drop(before_vault);

    match kind {
        PersistedCorruption::PrimaryRow | PersistedCorruption::MembershipProof => {
            let byte = value
                .last_mut()
                .ok_or_else(|| format!("{} source value is empty", kind.name()))?;
            *byte ^= 0x80;
        }
        PersistedCorruption::ManifestMembershipRoot => {
            rewrite_manifest_membership_root(&mut value)?;
        }
        PersistedCorruption::WrongKeyProofBinding => {}
    }
    require(
        value_before.as_deref() != Some(value.as_slice()),
        format!("{} mutation did not change its target value", kind.name()),
    )?;
    println!(
        "{}",
        json!({
            "event": "persisted_corruption_before",
            "probe": kind.name(),
            "directory": directory,
            "before": before,
            "target_cf": cf.name(),
            "target_key_sha256": sha256_hex(&key),
            "target_value_sha256_before": value_before.as_deref().map(sha256_hex),
            "target_value_sha256_to_commit": sha256_hex(&value),
            "files": files_before,
        })
    );

    let payload = encode::encode_write_batch(&[encode::WriteRow {
        cf,
        key: key.clone(),
        value: value.clone(),
    }])?;
    let mut wal = Wal::open(directory.join("wal"), WalOptions::default())?;
    let wal_tip_before = wal.durable_tip_seq()?;
    require(
        wal_tip_before == before.seq,
        format!(
            "{} copied WAL tip {wal_tip_before} differs from logical seq {}",
            kind.name(),
            before.seq
        ),
    )?;
    let append = wal.append(&payload)?;
    require(
        append.seq == before.seq + 1,
        format!(
            "{} corruption commit sequence is not contiguous",
            kind.name()
        ),
    )?;
    let segment_after_append = sha256_file(&append.segment_path)?;
    drop(wal);

    let reopened = open_read_vault_for_slots(directory, &[slot.slot_id])?;
    let after = slot_state(&reopened, slot.slot_id)?;
    require(
        after.seq == append.seq,
        format!(
            "{} fresh reopen did not replay corruption commit",
            kind.name()
        ),
    )?;
    let persisted_value = required_row(
        &reopened,
        after.seq,
        cf,
        &key,
        "persisted corruption target",
    )?;
    require(
        persisted_value == value,
        format!("{} committed target bytes differ after reopen", kind.name()),
    )?;
    let verification_error = state
        .registry
        .compressed_slot_index(&reopened, &slot)?
        .verify_at(after.seq)
        .expect_err("persisted corruption must fail fresh Registry verification");
    require(
        verification_error.code == CALYX_VECTOR_COMPRESSION_INVALID
            && verification_error
                .message
                .contains(kind.expected_diagnostic()),
        format!(
            "{} returned unexpected diagnostic [{}] {}",
            kind.name(),
            verification_error.code,
            verification_error.message
        ),
    )?;
    let files_after = disk_inventory(directory)?;
    println!(
        "{}",
        json!({
            "event": "persisted_corruption_after",
            "probe": kind.name(),
            "directory": directory,
            "source_of_truth": "fresh read-only Aster reopen after one fsync-backed CXLWAL2 corruption commit",
            "wal": {
                "seq_before": wal_tip_before,
                "committed_seq": append.seq,
                "segment": append.segment_path,
                "start_offset": append.start_offset,
                "end_offset": append.end_offset,
                "segment_sha256_after_append": segment_after_append,
            },
            "before": before,
            "after": after,
            "persisted_target_value_sha256": sha256_hex(&persisted_value),
            "diagnostic": {
                "code": verification_error.code,
                "message": verification_error.message,
                "expected_substring": kind.expected_diagnostic(),
            },
            "files": files_after,
            "restored": false,
        })
    );
    drop(reopened);
    Ok(())
}

fn rewrite_manifest_membership_root(bytes: &mut [u8]) -> AnyResult<()> {
    const PREFIX_BYTES: usize = 184;
    const TOTAL_BYTES: usize = 216;
    const MEMBERSHIP_ROOT_OFFSET: usize = 120;
    require(
        bytes.len() == TOTAL_BYTES && &bytes[..4] == b"CSMF" && bytes[4] == 3,
        "membership-root corruption requires an exact CSMF-v3 manifest",
    )?;
    bytes[MEMBERSHIP_ROOT_OFFSET] ^= 0x80;
    let mut hasher = Sha256::new();
    hasher.update(b"calyx-registry-compression-manifest-v3");
    hasher.update((PREFIX_BYTES as u64).to_be_bytes());
    hasher.update(&bytes[..PREFIX_BYTES]);
    let digest: [u8; 32] = hasher.finalize().into();
    bytes[PREFIX_BYTES..].copy_from_slice(&digest);
    Ok(())
}

fn dimension_boundary_fsv(root: &Path) -> AnyResult<()> {
    maximum_dimension_success(root)?;
    over_limit_dimension_refusal(root)
}

fn maximum_dimension_success(root: &Path) -> AnyResult<()> {
    let directory = root.join("maximum-dimension");
    let vault_dir = directory.join("vault");
    fs::create_dir_all(&directory)?;
    let mut registry = Registry::new();
    let registered = register_dim(
        &mut registry,
        "issues-557-564-max-d4096",
        MAX_DIM_SLOT,
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 7,
        },
        MAX_SUPPORTED_DIM,
    )?;
    let panel = panel_for_slots([registered.slot.clone()]);
    let vault = open_write_vault(&vault_dir, &panel)?;
    persist_single_slot_panel(&vault_dir, &registry, &panel)?;

    let inputs = (0..2)
        .map(|row| dimension_input("max-d4096", row, registered.slot.slot_id, MAX_SUPPORTED_DIM))
        .collect::<AnyResult<Vec<_>>>()?;
    let cx_ids = inputs
        .iter()
        .map(|input| vault.cx_id_for_input(&input.raw_bytes, input.panel_version))
        .collect::<Vec<_>>();
    let before_ingest = slot_state(&vault, registered.slot.slot_id)?;
    let ingester = StreamIngester::new(Arc::clone(&vault), BackpressureGuard::new(2, 0));
    for (row, input) in inputs.into_iter().enumerate() {
        ingester.send(input, EpochSecs(20_000 + row as i64))?;
    }
    let stats = ingester.drain_and_close()?;
    require(
        stats.ingested == 2,
        "D=4096 ingest did not persist two rows",
    )?;
    let after_ingest = slot_state(&vault, registered.slot.slot_id)?;

    let query_values = dimension_query_values(MAX_SUPPORTED_DIM)?;
    let query = CompressionQuery {
        cx_id: vault.cx_id_for_input(b"issues-557-564-max-d4096-held-out", PANEL_VERSION),
        values: query_values.clone(),
    };
    let before_compression = slot_state(&vault, registered.slot.slot_id)?;
    let candidate = registry.build_and_evaluate_compression_candidate(
        &vault,
        &registered.slot,
        candidate_request_with_k(
            vec![query.clone()],
            1,
            exact_work_limits_for(2, MAX_SUPPORTED_DIM, MAX_SUPPORTED_DIM, 1)?,
            passing_gates(),
        ),
    )?;
    require(
        candidate.generation.stored_codec == StoredSlotCodec::TurboQuantBits3p5
            && candidate.generation.fallback_reason.is_none(),
        "D=4096 build substituted its requested codec",
    )?;
    require_unpublished_candidate(&candidate.evaluation)?;
    let generation_seq = candidate
        .generation
        .snapshot
        .ok_or("D=4096 generation snapshot missing")?;
    let index = registry.compressed_slot_index(&vault, &registered.slot)?;
    index.verify_at(generation_seq)?;
    let point = index.read_at(cx_ids[0], generation_seq)?;
    require(
        point
            .as_dense()
            .is_some_and(|values| values.len() == MAX_SUPPORTED_DIM as usize),
        "D=4096 point read returned the wrong dense shape",
    )?;
    let hits = index.search_at(&query_values, 1, generation_seq)?;
    require(
        hits.first().map(|hit| hit.cx_id) == Some(cx_ids[0]),
        "D=4096 directionally distinct mixture query returned the wrong top-1 row",
    )?;
    let after_compression = slot_state(&vault, registered.slot.slot_id)?;
    let manifest = required_row(
        &vault,
        generation_seq,
        ColumnFamily::Compression,
        &compression_manifest_key(registered.slot.slot_id),
        "D=4096 manifest",
    )?;
    let proof = required_row(
        &vault,
        generation_seq,
        ColumnFamily::Compression,
        &compression_membership_proof_key(registered.slot.slot_id, cx_ids[0]),
        "D=4096 membership proof",
    )?;
    let primary = required_row(
        &vault,
        generation_seq,
        ColumnFamily::slot(registered.slot.slot_id),
        &slot_key(cx_ids[0]),
        "D=4096 primary row",
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_maximum_supported_dimension_success",
            "dimension": MAX_SUPPORTED_DIM,
            "rows": 2,
            "query_count": 1,
            "before_ingest": before_ingest,
            "after_ingest": after_ingest,
            "before_compression": before_compression,
            "after_compression": after_compression,
            "known_expected_top1": cx_ids[0],
            "actual_top1": hits[0].cx_id,
            "manifest": { "bytes": manifest.len(), "sha256": sha256_hex(&manifest) },
            "proof": { "bytes": proof.len(), "sha256": sha256_hex(&proof) },
            "primary": { "bytes": primary.len(), "sha256": sha256_hex(&primary) },
            "receipt_sha256": candidate.evaluation.receipt_sha256,
            "receipt": candidate.evaluation.receipt,
        })
    );
    drop(index);
    drop(vault);

    let reopened = open_read_vault_for_slots(&vault_dir, &[registered.slot.slot_id])?;
    let reopened_seq = reopened.latest_seq();
    let reopened_state = slot_state(&reopened, registered.slot.slot_id)?;
    let reopened_index = registry.compressed_slot_index(&reopened, &registered.slot)?;
    reopened_index.verify_at(reopened_seq)?;
    let reopened_hits = reopened_index.search_at(&query_values, 1, reopened_seq)?;
    let reopened_point = reopened_index.read_at(cx_ids[0], reopened_seq)?;
    require(
        reopened_hits.first().map(|hit| hit.cx_id) == Some(cx_ids[0])
            && reopened_point
                .as_dense()
                .is_some_and(|values| values.len() == MAX_SUPPORTED_DIM as usize),
        "fresh D=4096 reopen failed point/search verification",
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_maximum_supported_dimension_reopen",
            "source_of_truth": "fresh read-only Aster point/proof/manifest/search readback",
            "state": reopened_state,
            "actual_top1": reopened_hits[0].cx_id,
            "files": disk_inventory(&vault_dir)?,
        })
    );
    Ok(())
}

fn over_limit_dimension_refusal(root: &Path) -> AnyResult<()> {
    let directory = root.join("over-limit-dimension");
    let vault_dir = directory.join("vault");
    fs::create_dir_all(&directory)?;
    let mut registry = Registry::new();
    let registered = register_dim(
        &mut registry,
        "issues-557-564-over-limit-d4097",
        OVER_LIMIT_DIM_SLOT,
        QuantPolicy::TurboQuant {
            bits_per_channel_x2: 7,
        },
        OVER_LIMIT_DIM,
    )?;
    let panel = panel_for_slots([registered.slot.clone()]);
    let vault = open_write_vault(&vault_dir, &panel)?;
    persist_single_slot_panel(&vault_dir, &registry, &panel)?;
    let inputs = (0..2)
        .map(|row| {
            dimension_input(
                "over-limit-d4097",
                row,
                registered.slot.slot_id,
                OVER_LIMIT_DIM,
            )
        })
        .collect::<AnyResult<Vec<_>>>()?;
    let ingester = StreamIngester::new(Arc::clone(&vault), BackpressureGuard::new(2, 0));
    for (row, input) in inputs.into_iter().enumerate() {
        ingester.send(input, EpochSecs(30_000 + row as i64))?;
    }
    require(
        ingester.drain_and_close()?.ingested == 2,
        "D=4097 source ingest did not persist two rows",
    )?;
    let query = CompressionQuery {
        cx_id: vault.cx_id_for_input(b"issues-557-564-over-limit-held-out", PANEL_VERSION),
        values: dimension_query_values(OVER_LIMIT_DIM)?,
    };
    let before = slot_state(&vault, registered.slot.slot_id)?;
    let files_before = disk_inventory(&vault_dir)?;
    let error = registry
        .build_and_evaluate_compression_candidate(
            &vault,
            &registered.slot,
            candidate_request_with_k(
                vec![query],
                1,
                exact_work_limits_for(2, OVER_LIMIT_DIM, OVER_LIMIT_DIM, 1)?,
                passing_gates(),
            ),
        )
        .expect_err("D=4097 codec build must fail before compression mutation");
    let after = slot_state(&vault, registered.slot.slot_id)?;
    let files_after = disk_inventory(&vault_dir)?;
    require(
        error.code == CALYX_VECTOR_COMPRESSION_INVALID
            && error.message.contains("1..=4096")
            && before == after
            && files_before == files_after,
        "D=4097 refusal did not preserve exact durable state or boundary diagnostic",
    )?;
    println!(
        "{}",
        json!({
            "event": "edge_over_limit_dimension_refused_before_mutation",
            "dimension": OVER_LIMIT_DIM,
            "maximum_supported_dimension": MAX_SUPPORTED_DIM,
            "error": { "code": error.code, "message": error.message },
            "before": before,
            "after": after,
            "files_before": files_before,
            "files_after": files_after,
            "mutation": false,
        })
    );
    Ok(())
}

fn panel_for_slots(slots: impl IntoIterator<Item = Slot>) -> Panel {
    Panel {
        version: PANEL_VERSION,
        slots: slots.into_iter().collect(),
        created_at: 1_725_000_000_000,
        kernel_ref: None,
        guard_ref: None,
    }
}

fn persist_single_slot_panel(
    vault_dir: &Path,
    registry: &Registry,
    panel: &Panel,
) -> AnyResult<()> {
    require(
        panel.slots.len() == 1,
        "single-slot Panel persistence received a multi-slot Panel",
    )?;
    persist_vault_panel_state(vault_dir, panel, registry)?;
    let loaded = load_vault_panel_state(vault_dir)?;
    require(
        loaded.panel == *panel && loaded.registry_snapshot.is_some(),
        "single-slot Panel/Registry persisted readback differs",
    )
}

fn dimension_input(label: &str, row: usize, slot_id: SlotId, dim: u32) -> AnyResult<IngestInput> {
    Ok(IngestInput::new(
        format!("issues-557-564-{label}-row-{row}").into_bytes(),
        PANEL_VERSION,
        Modality::Text,
    )
    .with_slot(
        slot_id,
        SlotVector::Dense {
            dim,
            data: dimension_row_values(row, dim)?,
        },
    ))
}

fn dimension_row_values(row: usize, dim: u32) -> AnyResult<Vec<f32>> {
    let mut values = vec![0.0; dim as usize];
    let value = values.get_mut(row).ok_or_else(|| {
        format!("dimension fixture row {row} is outside the declared dimension {dim}")
    })?;
    *value = 1.0;
    Ok(values)
}

fn dimension_query_values(dim: u32) -> AnyResult<Vec<f32>> {
    if dim < 2 {
        return Err(
            "directionally distinct dimension query requires at least two dimensions".into(),
        );
    }
    let mut values = vec![0.0; dim as usize];
    values[0] = 4.0;
    values[1] = 1.0;
    Ok(values)
}

#[derive(Clone, Debug, Serialize)]
struct ProductionSourceEvidence {
    path: PathBuf,
    database_bytes: u64,
    database_sha256: String,
    project: String,
    rows: u32,
    dimension: u32,
    blob_bytes: u64,
    first_node_id: i64,
    last_node_id: i64,
    row_stream_sha256: String,
    query_only: i64,
}

fn production(root: &Path) -> AnyResult<()> {
    require(
        !root.exists(),
        format!("production root already exists: {}", root.display()),
    )?;
    let source_path = PathBuf::from(PRODUCTION_DB);
    require(
        source_path.is_file(),
        format!(
            "production source database is absent: {}",
            source_path.display()
        ),
    )?;
    let database_bytes = fs::metadata(&source_path)?.len();
    let database_sha256_before = sha256_file(&source_path)?;
    let connection = Connection::open_with_flags(
        &source_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.pragma_update(None, "query_only", true)?;
    let query_only: i64 = connection.pragma_query_value(None, "query_only", |row| row.get(0))?;
    require(
        query_only == 1,
        "production SQLite handle is not query_only",
    )?;
    connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
    let (source, first_vector) = preflight_production_source(
        &connection,
        &source_path,
        database_bytes,
        database_sha256_before.clone(),
        query_only,
    )?;
    println!(
        "{}",
        json!({
            "event": "production_source_preflight_complete",
            "source": source,
            "source_domain": "C-code-poly.db node_vectors: already-int8 codebase-memory-mcp vectors decoded as signed i8 / 127.0; not current Astrolabe and not original F32",
            "mutation_before_preflight": false,
        })
    );

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
    let before_ingest = slot_state(&vault, registered.slot.slot_id)?;
    let held_out_raw = format!("C-code-poly/node_vectors/{}", source.first_node_id).into_bytes();
    let held_out_cx_id = vault.cx_id_for_input(&held_out_raw, PANEL_VERSION);

    let mut statement = connection.prepare(
        "SELECT node_id, project, vector FROM node_vectors WHERE project = ?1 ORDER BY node_id ASC",
    )?;
    let mut rows = statement.query(params![PRODUCTION_PROJECT])?;
    let mut stream: Option<StreamIngester<SystemClock>> = None;
    let mut chunk_rows = 0_usize;
    let mut scanned = 0_u32;
    let mut ingested = 0_u32;
    let mut batches = 0_usize;
    let mut first_corpus_cx_id = None;
    let mut first_corpus_vector = None;
    let mut previous_node_id = None;
    let mut stream_hash = Sha256::new();
    stream_hash.update(b"issues-557-564-c-code-poly-row-stream-v1");
    while let Some(row) = rows.next()? {
        let node_id: i64 = row.get(0)?;
        let project: String = row.get(1)?;
        let blob: Vec<u8> = row.get(2)?;
        require(
            project == PRODUCTION_PROJECT
                && blob.len() == PRODUCTION_DIM as usize
                && previous_node_id.is_none_or(|previous| previous < node_id),
            format!("production ingest source row {node_id} violated project/dimension/order"),
        )?;
        previous_node_id = Some(node_id);
        production_stream_hash_row(&mut stream_hash, node_id, &project, &blob);
        let values = decode_cbm_i8_vector(&blob)?;
        scanned = scanned
            .checked_add(1)
            .ok_or("production scan row count overflow")?;
        let input = production_input(node_id, registered.slot.slot_id, values.clone());
        let cx_id = vault.cx_id_for_input(&input.raw_bytes, input.panel_version);
        if node_id == source.first_node_id {
            require(
                scanned == 1 && values == first_vector && cx_id == held_out_cx_id,
                "production held-out row does not match preflight first vector",
            )?;
            continue;
        }
        require(
            cx_id != held_out_cx_id,
            format!("production corpus row {node_id} aliases held-out source identity"),
        )?;
        first_corpus_vector.get_or_insert_with(|| values.clone());
        first_corpus_cx_id.get_or_insert(cx_id);
        if stream.is_none() {
            stream = Some(StreamIngester::new(
                Arc::clone(&vault),
                BackpressureGuard::new(256, 0),
            ));
        }
        stream
            .as_ref()
            .ok_or("production stream disappeared")?
            .send(input, EpochSecs(40_000 + i64::from(ingested)))?;
        ingested = ingested
            .checked_add(1)
            .ok_or("production row count overflow")?;
        chunk_rows += 1;
        if chunk_rows == 256 {
            let stats = stream
                .take()
                .ok_or("production stream chunk disappeared")?
                .drain_and_close()?;
            require(
                stats.ingested == chunk_rows,
                "production stream chunk lost rows",
            )?;
            batches = batches
                .checked_add(stats.batches)
                .ok_or("production batch count overflow")?;
            chunk_rows = 0;
        }
    }
    if let Some(stream) = stream {
        let stats = stream.drain_and_close()?;
        require(
            stats.ingested == chunk_rows,
            "production final stream chunk lost rows",
        )?;
        batches = batches
            .checked_add(stats.batches)
            .ok_or("production batch count overflow")?;
    }
    drop(rows);
    drop(statement);
    let ingested_stream_sha256 = hex(&stream_hash.finalize());
    require(
        scanned == PRODUCTION_ROWS
            && ingested == PRODUCTION_CORPUS_ROWS
            && ingested_stream_sha256 == source.row_stream_sha256,
        "production ingest did not consume the exact preflighted source snapshot",
    )?;
    let first_corpus_cx_id =
        first_corpus_cx_id.ok_or("production source produced no corpus CxId")?;
    let first_corpus_vector =
        first_corpus_vector.ok_or("production source produced no corpus vector")?;
    let after_ingest = slot_state(&vault, registered.slot.slot_id)?;
    let held_out_absent_from_base = vault
        .read_cf_at(
            after_ingest.seq,
            ColumnFamily::Base,
            &base_key(held_out_cx_id),
        )?
        .is_none();
    let held_out_absent_from_slot = vault
        .read_cf_at(
            after_ingest.seq,
            ColumnFamily::slot(registered.slot.slot_id),
            &slot_key(held_out_cx_id),
        )?
        .is_none();
    require(
        after_ingest.primary_rows == PRODUCTION_CORPUS_ROWS as usize
            && after_ingest.raw_rows == 0
            && after_ingest.manifest_sha256.is_none()
            && held_out_absent_from_base
            && held_out_absent_from_slot,
        "production streamed source is not an exact uncompressed primary column",
    )?;

    let query = CompressionQuery {
        cx_id: held_out_cx_id,
        values: first_vector.clone(),
    };
    require(
        query.cx_id != first_corpus_cx_id,
        "production held-out query overlaps corpus identity",
    )?;
    let before_evaluation = slot_state(&vault, registered.slot.slot_id)?;
    let candidate = registry.build_and_evaluate_compression_candidate(
        &vault,
        &registered.slot,
        candidate_request_with_k(
            vec![query.clone()],
            1,
            exact_work_limits_for(PRODUCTION_CORPUS_ROWS, PRODUCTION_DIM, PRODUCTION_DIM, 1)?,
            production_gates(),
        ),
    )?;
    require(
        candidate.generation.stored_codec == StoredSlotCodec::ScalarInt8
            && candidate.generation.fallback_reason.is_none(),
        "production ScalarInt8 candidate was substituted",
    )?;
    require_unpublished_candidate(&candidate.evaluation)?;
    let generation_seq = candidate
        .generation
        .snapshot
        .ok_or("production generation snapshot missing")?;
    let observation = candidate
        .evaluation
        .receipt
        .queries
        .first()
        .ok_or("production receipt omitted Q=1 observation")?;
    require(
        observation.exact_top_k.len() == 1
            && observation.packed_top_k.len() == 1
            && observation.exact_top_k[0].cx_id == observation.packed_top_k[0].cx_id,
        "production Q=1 exact/packed top-1 differs",
    )?;
    let expected_top1 = observation.exact_top_k[0].cx_id;
    let index = registry.compressed_slot_index(&vault, &registered.slot)?;
    index.verify_at(generation_seq)?;
    let live_hits = index.search_at(&query.values, 1, generation_seq)?;
    require(
        live_hits.first().map(|hit| hit.cx_id) == Some(expected_top1),
        "production direct packed search differs from receipt truth",
    )?;
    let after_evaluation = slot_state(&vault, registered.slot.slot_id)?;
    println!(
        "{}",
        json!({
            "event": "production_c_code_poly_candidate_evaluated",
            "source": source,
            "source_domain": "C-code-poly.db node_vectors: already-int8 codebase-memory-mcp vectors decoded as signed i8 / 127.0; not current Astrolabe and not original F32",
            "cost_boundary": {
                "source_database_rows": PRODUCTION_ROWS,
                "held_out_rows": 1,
                "rows_r": PRODUCTION_CORPUS_ROWS,
                "split_arithmetic": format!("{} - 1 = {}", PRODUCTION_ROWS, PRODUCTION_CORPUS_ROWS),
                "dimension_d": PRODUCTION_DIM,
                "queries_q": 1,
                "warmups_u": WARMUP_RUNS,
                "measured_runs_m": MEASURED_RUNS,
                "preflight_source_scans": 1,
                "streaming_ingest_source_scans": 1,
                "stream_chunk_rows": 256,
                "registry_build_materialization": "Registry contract materializes one raw corpus and encoded candidate; driver retains no full duplicate corpus",
            },
            "before_ingest": before_ingest,
            "after_ingest": after_ingest,
            "before_evaluation": before_evaluation,
            "after_evaluation": after_evaluation,
            "stream_batches": batches,
            "query_cx_id": query.cx_id,
            "held_out_source_node_id": source.first_node_id,
            "held_out_source_raw_sha256": sha256_hex(&held_out_raw),
            "held_out_absent_from_base": held_out_absent_from_base,
            "held_out_absent_from_candidate_slot": held_out_absent_from_slot,
            "expected_and_packed_top1": expected_top1,
            "receipt_sha256": candidate.evaluation.receipt_sha256,
            "receipt": production_receipt_summary(&candidate.evaluation.receipt),
        })
    );
    drop(index);
    drop(vault);
    connection.execute_batch("COMMIT")?;
    drop(connection);

    let database_sha256_after = sha256_file(&source_path)?;
    require(
        database_sha256_after == database_sha256_before
            && fs::metadata(&source_path)?.len() == database_bytes,
        "read-only production source database bytes changed during FSV",
    )?;
    let reopened = open_read_vault_for_slots_and_base(&vault_dir, &[registered.slot.slot_id])?;
    let reopened_seq = reopened.latest_seq();
    let reopened_held_out_base =
        reopened.read_cf_at(reopened_seq, ColumnFamily::Base, &base_key(held_out_cx_id))?;
    let reopened_held_out_slot = reopened.read_cf_at(
        reopened_seq,
        ColumnFamily::slot(registered.slot.slot_id),
        &slot_key(held_out_cx_id),
    )?;
    require(
        reopened_held_out_base.is_none() && reopened_held_out_slot.is_none(),
        "production held-out source identity exists in the reopened Base or candidate corpus",
    )?;
    let reopened_index = registry.compressed_slot_index(&reopened, &registered.slot)?;
    reopened_index.verify_at(reopened_seq)?;
    let point = reopened_index.read_at(first_corpus_cx_id, reopened_seq)?;
    require(
        point
            .as_dense()
            .is_some_and(|values| values.len() == PRODUCTION_DIM as usize),
        "production point read has wrong dimension after restart",
    )?;
    let raw = required_row(
        &reopened,
        reopened_seq,
        ColumnFamily::slot_raw(registered.slot.slot_id),
        &slot_key(first_corpus_cx_id),
        "production first raw sidecar",
    )?;
    require(
        encode::decode_slot_vector(&raw)?
            == SlotVector::Dense {
                dim: PRODUCTION_DIM,
                data: first_corpus_vector,
            },
        "production persisted raw truth differs from first SQLite vector",
    )?;
    let restarted_hits = reopened_index.search_at(&query.values, 1, reopened_seq)?;
    require(
        restarted_hits.first().map(|hit| hit.cx_id) == Some(expected_top1),
        "production packed Q=1 result changed after restart",
    )?;
    let status = registry.compression_admission_status(&reopened, &registered.slot)?;
    let latest = status
        .latest_evaluation
        .as_ref()
        .ok_or("production receipt missing after restart")?;
    require_unpublished_candidate(latest)?;
    let immutable_components = verify_immutable_receipt_components(&vault_dir, &latest.receipt)?;
    println!(
        "{}",
        json!({
            "event": "production_c_code_poly_restart_verified",
            "source_of_truth": "fresh read-only Aster point/raw/proof/manifest/search/receipt reads plus unchanged read-only SQLite file hash",
            "source_database_sha256_before": database_sha256_before,
            "source_database_sha256_after": database_sha256_after,
            "state": slot_state(&reopened, registered.slot.slot_id)?,
            "point_cx_id": first_corpus_cx_id,
            "held_out_query_cx_id": held_out_cx_id,
            "held_out_absent_from_reopened_base": reopened_held_out_base.is_none(),
            "held_out_absent_from_reopened_candidate_slot": reopened_held_out_slot.is_none(),
            "point_dimension": PRODUCTION_DIM,
            "point_raw_bytes": raw.len(),
            "point_raw_sha256": sha256_hex(&raw),
            "packed_top1": restarted_hits[0],
            "receipt_sha256": latest.receipt_sha256,
            "receipt": production_receipt_summary(&latest.receipt),
            "immutable_physical_components_verified": immutable_components,
            "files": disk_inventory(&vault_dir)?,
        })
    );
    Ok(())
}

fn preflight_production_source(
    connection: &Connection,
    path: &Path,
    database_bytes: u64,
    database_sha256: String,
    query_only: i64,
) -> AnyResult<(ProductionSourceEvidence, Vec<f32>)> {
    let schema: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='node_vectors'",
        [],
        |row| row.get(0),
    )?;
    require(
        schema.contains("node_id INTEGER PRIMARY KEY")
            && schema.contains("project TEXT NOT NULL")
            && schema.contains("vector BLOB NOT NULL"),
        "production node_vectors schema differs from the CBM source contract",
    )?;
    let mut statement = connection
        .prepare("SELECT node_id, project, vector FROM node_vectors ORDER BY node_id ASC")?;
    let mut rows = statement.query([])?;
    let mut count = 0_u32;
    let mut blob_bytes = 0_u64;
    let mut first_node_id = None;
    let mut last_node_id = None;
    let mut first_vector = None;
    let mut stream_hash = Sha256::new();
    stream_hash.update(b"issues-557-564-c-code-poly-row-stream-v1");
    while let Some(row) = rows.next()? {
        let node_id: i64 = row.get(0)?;
        let project: String = row.get(1)?;
        let blob: Vec<u8> = row.get(2)?;
        require(
            project == PRODUCTION_PROJECT
                && blob.len() == PRODUCTION_DIM as usize
                && last_node_id.is_none_or(|previous| previous < node_id),
            format!("production preflight row {node_id} violated project/dimension/order"),
        )?;
        require(
            !blob.iter().any(|byte| *byte == 0x80),
            format!("production preflight row {node_id} contains forbidden int8 -128"),
        )?;
        production_stream_hash_row(&mut stream_hash, node_id, &project, &blob);
        if first_vector.is_none() {
            first_vector = Some(decode_cbm_i8_vector(&blob)?);
            first_node_id = Some(node_id);
        }
        last_node_id = Some(node_id);
        count = count
            .checked_add(1)
            .ok_or("production preflight row count overflow")?;
        blob_bytes = blob_bytes
            .checked_add(blob.len() as u64)
            .ok_or("production preflight blob byte count overflow")?;
    }
    let expected_blob_bytes = u64::from(PRODUCTION_ROWS)
        .checked_mul(u64::from(PRODUCTION_DIM))
        .ok_or("production expected blob-byte count overflow")?;
    require(
        count == PRODUCTION_ROWS && blob_bytes == expected_blob_bytes,
        format!(
            "production source is not exact {PRODUCTION_ROWS}x{PRODUCTION_DIM}: rows={count} blob_bytes={blob_bytes}"
        ),
    )?;
    Ok((
        ProductionSourceEvidence {
            path: path.to_path_buf(),
            database_bytes,
            database_sha256,
            project: PRODUCTION_PROJECT.to_string(),
            rows: count,
            dimension: PRODUCTION_DIM,
            blob_bytes,
            first_node_id: first_node_id.ok_or("production first node id missing")?,
            last_node_id: last_node_id.ok_or("production last node id missing")?,
            row_stream_sha256: hex(&stream_hash.finalize()),
            query_only,
        },
        first_vector.ok_or("production first vector missing")?,
    ))
}

fn production_stream_hash_row(hasher: &mut Sha256, node_id: i64, project: &str, blob: &[u8]) {
    hasher.update(node_id.to_be_bytes());
    hasher.update((project.len() as u64).to_be_bytes());
    hasher.update(project.as_bytes());
    hasher.update((blob.len() as u64).to_be_bytes());
    hasher.update(blob);
}

fn decode_cbm_i8_vector(blob: &[u8]) -> AnyResult<Vec<f32>> {
    require(
        blob.len() == PRODUCTION_DIM as usize,
        "CBM node vector does not have 768 bytes",
    )?;
    require(
        !blob.iter().any(|byte| *byte == 0x80),
        "CBM node vector contains -128 outside its [-127,127] source contract",
    )?;
    Ok(blob
        .iter()
        .map(|byte| f32::from(*byte as i8) / 127.0)
        .collect())
}

fn production_input(node_id: i64, slot_id: SlotId, values: Vec<f32>) -> IngestInput {
    IngestInput::new(
        format!("C-code-poly/node_vectors/{node_id}").into_bytes(),
        PANEL_VERSION,
        Modality::Text,
    )
    .with_metadata("source_project", PRODUCTION_PROJECT)
    .with_metadata("source_node_id", node_id.to_string())
    .with_slot(
        slot_id,
        SlotVector::Dense {
            dim: PRODUCTION_DIM,
            data: values,
        },
    )
}

fn production_gates() -> CompressionAdmissionGates {
    CompressionAdmissionGates {
        minimum_recall_at_k: 1.0,
        maximum_mean_cosine_error: 0.02,
        maximum_cosine_error: 0.05,
        maximum_p99_latency_ns: 120_000_000_000,
        maximum_total_physical_bytes: 2 * 1024 * 1024 * 1024,
        maximum_working_set_bytes: 64 * 1024 * 1024 * 1024,
        maximum_materialized_primary_bytes_per_query: 512 * 1024 * 1024,
    }
}

fn production_receipt_summary(receipt: &CompressionAdmissionReceipt) -> Value {
    json!({
        "schema": receipt.schema,
        "slot_id": receipt.slot_id,
        "codec": receipt.codec,
        "level": receipt.level,
        "generation_seq": receipt.generation_seq,
        "corpus_rows": receipt.corpus_rows,
        "raw_dim": receipt.raw_dim,
        "stored_dim": receipt.stored_dim,
        "source_values_sha256": receipt.source_values_sha256,
        "query_values_sha256": receipt.query_values_sha256,
        "exact_ground_truth_sha256": receipt.exact_ground_truth_sha256,
        "build": receipt.build,
        "placement": receipt.placement,
        "physical_components": receipt.physical_components,
        "total_physical_bytes": receipt.total_physical_bytes,
        "effective_bits_per_value": receipt.effective_bits_per_value,
        "primary_value_bytes": receipt.primary_value_bytes,
        "queries": receipt.queries,
        "reconstruction_count": receipt.reconstruction.len(),
        "mean_reconstruction_cosine_error": receipt.mean_reconstruction_cosine_error,
        "max_reconstruction_cosine_error": receipt.max_reconstruction_cosine_error,
        "latency_p50_ns": receipt.latency_p50_ns,
        "latency_p95_ns": receipt.latency_p95_ns,
        "latency_p99_ns": receipt.latency_p99_ns,
        "allocations": receipt.allocations,
        "resources": receipt.resources,
        "work_limits": receipt.work_limits,
        "work": receipt.work,
        "gates": receipt.gates,
        "gate_observations": receipt.gate_observations,
        "verdict": receipt.verdict,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct McpConfigReadback {
    query_only: i64,
    rows: BTreeMap<String, String>,
    database_bytes: u64,
    database_sha256: String,
}

fn prepare_mcp(root: &Path) -> AnyResult<()> {
    require(
        !root.exists(),
        format!("prepare_mcp root already exists: {}", root.display()),
    )?;
    fs::create_dir_all(root)?;
    let cache_dir = root.join("cache");
    let vault_dir = root.join("vault");
    fs::create_dir_all(&cache_dir)?;
    let (registry, slots) = registry_and_slots()?;
    let panel = panel_for_slots(slots.iter().map(|registered| registered.slot.clone()));
    let vault = open_write_vault(&vault_dir, &panel)?;
    persist_vault_panel_state(&vault_dir, &panel, &registry)?;
    let loaded = load_vault_panel_state(&vault_dir)?;
    require(
        loaded.panel == panel && loaded.registry_snapshot.is_some(),
        "prepare_mcp Panel/Registry readback differs",
    )?;
    let tq35 = exact_registered(&slots, TQ35_SLOT)?;
    let int8 = exact_registered(&slots, INT8_SLOT)?;
    let before_tq35 = slot_state(&vault, tq35.slot.slot_id)?;
    let before_int8 = slot_state(&vault, int8.slot.slot_id)?;
    let ingester = StreamIngester::new(Arc::clone(&vault), BackpressureGuard::new(ROWS, 0));
    for row in 0..ROWS {
        ingester.send(
            ingest_event(row, &[TQ35_SLOT, INT8_SLOT]),
            EpochSecs(50_000 + row as i64),
        )?;
    }
    let stats = ingester.drain_and_close()?;
    require(stats.ingested == ROWS, "prepare_mcp raw ingest lost rows")?;
    vault.flush_with_report()?;
    let (after_tq35, tq_rows) = raw_unmanifested_slot_state(&vault_dir, &vault, tq35.slot.slot_id)?;
    let (after_int8, int8_rows) =
        raw_unmanifested_slot_state(&vault_dir, &vault, int8.slot.slot_id)?;
    require_mcp_raw_candidate(&tq_rows, &after_tq35, tq35.slot.slot_id)?;
    require_mcp_raw_candidate(&int8_rows, &after_int8, int8.slot.slot_id)?;
    require(
        tq_rows == int8_rows,
        "prepare_mcp candidate slots do not contain identical raw source rows",
    )?;
    let cx_ids = corpus_ids(&vault);
    let queries = known_queries(&vault, &cx_ids);
    let request = candidate_request(
        query_inputs(&queries),
        exact_work_limits_for(ROWS as u32, DIM, DIM, queries.len())?,
        passing_gates(),
    );
    let request_args = json!({
        "project": MCP_PROJECT,
        "mode": "commission_compression_candidates",
        "candidate_slot_ids": [TQ35_SLOT, INT8_SLOT],
        "candidate_request": request.clone(),
    });
    let mcp_input = json!({
        "project": MCP_PROJECT,
        "cache_dir": cache_dir,
        "candidate_slot_ids": [TQ35_SLOT, INT8_SLOT],
        "candidate_request": request,
    });
    let request_path = root.join("mcp-commission-request.json");
    let request_bytes = serde_json::to_vec_pretty(&request_args)?;
    fs::write(&request_path, &request_bytes)?;
    let request_readback: Value = serde_json::from_slice(&fs::read(&request_path)?)?;
    require(
        request_readback == request_args,
        "mcp commission request readback differs from written arguments",
    )?;
    let input_path = root.join("mcp-input.json");
    let input_bytes = serde_json::to_vec_pretty(&mcp_input)?;
    fs::write(&input_path, &input_bytes)?;
    let input_readback: Value = serde_json::from_slice(&fs::read(&input_path)?)?;
    require(
        input_readback == mcp_input,
        "canonical MCP dispatcher input readback differs from written input",
    )?;

    let config_path = cache_dir.join("_config.db");
    write_mcp_config(&config_path, &vault_dir)?;
    let config = read_mcp_config(&config_path, &vault_dir)?;
    drop(vault);
    let reopened = open_read_vault_for_primary_slots(
        &vault_dir,
        &[SlotId::new(TQ35_SLOT), SlotId::new(INT8_SLOT)],
    )?;
    let (reopened_tq35, tq35_primary) =
        raw_unmanifested_slot_state(&vault_dir, &reopened, SlotId::new(TQ35_SLOT))?;
    let (reopened_int8, int8_primary) =
        raw_unmanifested_slot_state(&vault_dir, &reopened, SlotId::new(INT8_SLOT))?;
    require_mcp_raw_candidate(&tq35_primary, &reopened_tq35, SlotId::new(TQ35_SLOT))?;
    require_mcp_raw_candidate(&int8_primary, &reopened_int8, SlotId::new(INT8_SLOT))?;
    println!(
        "{}",
        json!({
            "event": "mcp_prepare_complete",
            "project": MCP_PROJECT,
            "cache_dir": cache_dir,
            "config_db": config_path,
            "vault_dir": vault_dir,
            "slot_ids": [TQ35_SLOT, INT8_SLOT],
            "before": { "tq35": before_tq35, "scalar_int8": before_int8 },
            "after": { "tq35": after_tq35, "scalar_int8": after_int8 },
            "fresh_reopen": { "tq35": reopened_tq35, "scalar_int8": reopened_int8 },
            "config": config,
            "mcp_input_path": input_path,
            "mcp_input_sha256": sha256_hex(&input_bytes),
            "mcp_input": input_readback,
            "request_path": request_path,
            "request_sha256": sha256_hex(&request_bytes),
            "request_arguments": request_readback,
            "source_of_truth": "fresh read-only Aster raw primary/Compression/Ledger reads, read-only query_only _config.db rows, and request-file byte readback",
            "files": disk_inventory(root)?,
        })
    );
    Ok(())
}

fn readback_mcp(root: &Path) -> AnyResult<()> {
    require(
        root.is_dir(),
        format!("readback_mcp root is absent: {}", root.display()),
    )?;
    let cache_dir = root.join("cache");
    let config_path = cache_dir.join("_config.db");
    let vault_dir = root.join("vault");
    let input_path = root.join("mcp-input.json");
    let request_path = root.join("mcp-commission-request.json");
    let result_path = root.join("mcp-dispatch-result.json");
    require(
        result_path.is_file(),
        format!(
            "readback_mcp requires the completed dispatcher result at {}",
            result_path.display()
        ),
    )?;
    let files_before = disk_inventory(root)?;
    let config = read_mcp_config(&config_path, &vault_dir)?;
    let input: Value = serde_json::from_slice(&fs::read(&input_path)?)?;
    let request: Value = serde_json::from_slice(&fs::read(&request_path)?)?;
    require(
        input.get("project").and_then(Value::as_str) == Some(MCP_PROJECT)
            && input.get("cache_dir").and_then(Value::as_str)
                == Some(cache_dir.to_string_lossy().as_ref())
            && request.get("project").and_then(Value::as_str) == Some(MCP_PROJECT)
            && request.get("mode").and_then(Value::as_str)
                == Some("commission_compression_candidates"),
        "readback_mcp input/request do not name the fixed cache/project/commission mode",
    )?;
    let result_bytes = fs::read(&result_path)?;
    let dispatch_result: Value = serde_json::from_slice(&result_bytes)?;
    let panel = load_vault_panel_state(&vault_dir)?;
    require(
        panel.panel.version == PANEL_VERSION && panel.registry_snapshot.is_some(),
        "readback_mcp Panel/Registry state is missing",
    )?;
    let vault = open_read_vault_for_slots(
        &vault_dir,
        &[SlotId::new(TQ35_SLOT), SlotId::new(INT8_SLOT)],
    )?;
    let snapshot = vault.latest_seq();
    let cx_ids = corpus_ids(&vault);
    let queries = known_queries(&vault, &cx_ids);
    let mut physical_slots = Vec::new();
    let mut current_receipts = Vec::new();
    for slot_id in [TQ35_SLOT, INT8_SLOT] {
        let slot = panel_slot(&panel, slot_id)?;
        let index = panel.registry.compressed_slot_index(&vault, slot)?;
        index.verify_at(snapshot)?;
        verify_direct_search(&panel.registry, &vault, slot, snapshot, &queries)?;
        let status = panel.registry.compression_admission_status(&vault, slot)?;
        let latest = status
            .latest_evaluation
            .as_ref()
            .ok_or_else(|| format!("MCP-commissioned slot {slot_id} has no latest receipt"))?;
        require(
            latest.receipt.verdict == CompressionAdmissionVerdict::Admitted
                && latest.active_generation_current,
            format!("MCP-commissioned slot {slot_id} latest receipt is not active/admitted"),
        )?;
        if let Some(current) = status.current_admission.as_ref() {
            require_current_status(current)?;
            current_receipts.push(current.receipt_sha256.clone());
        }
        physical_slots.push(json!({
            "slot_id": slot_id,
            "state": slot_state(&vault, slot.slot_id)?,
            "status": status,
            "point": index.read_at(cx_ids[0], snapshot)?,
        }));
    }
    require(
        current_receipts.len() == 1,
        "readback_mcp did not find exactly one selected current receipt",
    )?;
    require(
        json_contains_string(&dispatch_result, &current_receipts[0]),
        "dispatcher result does not name the independently read current receipt",
    )?;
    let ledger_store = AsterLedgerCfStore::open(&vault_dir)?;
    let ledger_rows = ledger_store.scan()?;
    let chain = verify_chain(&ledger_store, 0..ledger_rows.len() as u64)?;
    require(
        matches!(chain, VerifyResult::Intact { count } if count == ledger_rows.len() as u64),
        format!("readback_mcp physical Ledger is not intact: {chain:?}"),
    )?;
    drop(ledger_store);
    drop(vault);
    let files_after = disk_inventory(root)?;
    require(
        files_before == files_after,
        "readback_mcp changed persisted root files",
    )?;
    println!(
        "{}",
        json!({
            "event": "mcp_readback_complete",
            "project": MCP_PROJECT,
            "source_of_truth": "independent read-only Aster primary/raw/manifest/proof/receipt/pointer/Ledger reads and query_only SQLite config reads; dispatcher JSON is comparison-only",
            "config": config,
            "mcp_input": input,
            "request": request,
            "dispatch_result_path": result_path,
            "dispatch_result_sha256": sha256_hex(&result_bytes),
            "dispatch_result": dispatch_result,
            "snapshot": snapshot,
            "slots": physical_slots,
            "selected_current_receipt_sha256": current_receipts[0],
            "physical_ledger": format!("{chain:?}"),
            "physical_ledger_rows": ledger_rows.len(),
            "physical_ledger_sha256": ledger_rows_sha256(&ledger_rows),
            "files_before": files_before,
            "files_after": files_after,
            "disk_unchanged_during_readback": true,
        })
    );
    Ok(())
}

fn require_mcp_raw_candidate(
    primary: &[(Vec<u8>, Vec<u8>)],
    state: &SlotStateReadback,
    slot_id: SlotId,
) -> AnyResult<()> {
    require(
        state.primary_rows == ROWS
            && state.raw_rows == 0
            && state.manifest_sha256.is_none()
            && state.proof_rows == 0
            && state.latest_evaluation.is_none()
            && state.current_admission.is_none(),
        format!(
            "MCP candidate slot {} is not raw and unmanifested",
            slot_id.get()
        ),
    )?;
    for (_, value) in primary {
        require(
            value.first().copied() != Some(COMPRESSED_SLOT_TAG)
                && encode::decode_slot_vector(value).is_ok(),
            format!(
                "MCP candidate slot {} contains a non-raw primary row",
                slot_id.get()
            ),
        )?;
    }
    Ok(())
}

fn write_mcp_config(path: &Path, vault_dir: &Path) -> AnyResult<()> {
    require(!path.exists(), "prepare_mcp config database already exists")?;
    let mut connection = Connection::open(path)?;
    let transaction = connection.transaction()?;
    transaction
        .execute_batch("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")?;
    let prefix = format!("astrolabe.calyx.{MCP_PROJECT}");
    for (key, value) in [
        (prefix.clone(), "shadow".to_string()),
        (
            format!("{prefix}.vault_dir"),
            vault_dir.to_string_lossy().into_owned(),
        ),
        (format!("{prefix}.vault_id"), VAULT_ID.to_string()),
        (
            format!("{prefix}.vault_salt"),
            std::str::from_utf8(VAULT_SALT)?.to_string(),
        ),
    ] {
        transaction.execute(
            "INSERT INTO config(key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
    }
    transaction.commit()?;
    connection.close().map_err(|(_, error)| error)?;
    Ok(())
}

fn read_mcp_config(path: &Path, vault_dir: &Path) -> AnyResult<McpConfigReadback> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.pragma_update(None, "query_only", true)?;
    let query_only: i64 = connection.pragma_query_value(None, "query_only", |row| row.get(0))?;
    require(query_only == 1, "MCP config readback is not query_only")?;
    let prefix = format!("astrolabe.calyx.{MCP_PROJECT}");
    let expected = BTreeMap::from([
        (prefix.clone(), "shadow".to_string()),
        (
            format!("{prefix}.vault_dir"),
            vault_dir.to_string_lossy().into_owned(),
        ),
        (format!("{prefix}.vault_id"), VAULT_ID.to_string()),
        (
            format!("{prefix}.vault_salt"),
            std::str::from_utf8(VAULT_SALT)?.to_string(),
        ),
    ]);
    let mut statement = connection
        .prepare("SELECT key, value FROM config WHERE key = ?1 OR key LIKE ?2 ORDER BY key ASC")?;
    let rows = statement
        .query_map(params![prefix, format!("{prefix}.%")], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    require(
        rows == expected,
        "MCP config persisted rows differ from exact expected values",
    )?;
    drop(statement);
    drop(connection);
    Ok(McpConfigReadback {
        query_only,
        rows,
        database_bytes: fs::metadata(path)?.len(),
        database_sha256: sha256_file(path)?,
    })
}

fn json_contains_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected || value.contains(expected),
        Value::Array(values) => values
            .iter()
            .any(|value| json_contains_string(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| json_contains_string(value, expected)),
        _ => false,
    }
}

fn readback(root: &Path) -> AnyResult<()> {
    require(
        root.is_dir(),
        format!("readback root is absent: {}", root.display()),
    )?;
    let vault_dir = root.join("vault");
    let files_before = disk_inventory(&vault_dir)?;
    let before_digest = sha256_hex(&serde_json::to_vec(&files_before)?);
    let slots = verify_persisted_state(&vault_dir)?;

    let physical = AsterLedgerCfStore::open(&vault_dir)?;
    let ledger_rows = physical.scan()?;
    let verified = verify_chain(&physical, 0..ledger_rows.len() as u64)?;
    require(
        matches!(verified, VerifyResult::Intact { count } if count == ledger_rows.len() as u64),
        format!("physical Ledger chain is not intact: {verified:?}"),
    )?;
    let ledger_evidence = ledger_rows
        .iter()
        .map(|row| {
            let entry = calyx_ledger::decode(&row.bytes)?;
            Ok(json!({
                "seq": row.seq,
                "kind": format!("{:?}", entry.kind),
                "entry_hash": hex(&entry.entry_hash),
                "value_bytes": row.bytes.len(),
                "value_sha256": sha256_hex(&row.bytes),
            }))
        })
        .collect::<AnyResult<Vec<_>>>()?;
    let physical_ledger_sha256 = ledger_rows_sha256(&ledger_rows);
    drop(physical);

    let files_after = disk_inventory(&vault_dir)?;
    let after_digest = sha256_hex(&serde_json::to_vec(&files_after)?);
    require(
        files_before == files_after,
        "read-only verification changed the on-disk file inventory",
    )?;
    println!(
        "{}",
        json!({
            "event": "independent_process_full_state_readback",
            "source_of_truth": "separate process reopened selected Aster CFs read-only, verified raw persisted bytes, reopened the physical Ledger chain, and hashed every vault file before/after",
            "slots": slots,
            "physical_ledger": format!("{verified:?}"),
            "physical_ledger_rows": ledger_rows.len(),
            "physical_ledger_sha256": physical_ledger_sha256,
            "physical_ledger_entries": ledger_evidence,
            "files": files_after,
            "file_inventory_sha256_before": before_digest,
            "file_inventory_sha256_after": after_digest,
            "disk_unchanged_during_readback": true,
        })
    );
    println!(
        "{}",
        json!({
            "event": "compression_admission_fsv_readback_success",
            "issues": [557, 564],
            "fixture_root": root,
        })
    );
    Ok(())
}

fn verify_persisted_state(vault_dir: &Path) -> AnyResult<Vec<PersistedSlotEvidence>> {
    let state = load_vault_panel_state(vault_dir)?;
    require(
        state.panel.version == PANEL_VERSION,
        "reopened panel version differs",
    )?;
    let vault = open_read_vault(vault_dir)?;
    let snapshot = vault.latest_seq();
    let cx_ids = corpus_ids(&vault);
    let queries = known_queries(&vault, &cx_ids);
    let tq_status = state
        .registry
        .compression_admission_status(&vault, panel_slot(&state, TQ35_SLOT)?)?;
    let int8_status = state
        .registry
        .compression_admission_status(&vault, panel_slot(&state, INT8_SLOT)?)?;
    let current_slots = [
        (TQ35_SLOT, tq_status.current_admission.as_ref()),
        (INT8_SLOT, int8_status.current_admission.as_ref()),
    ]
    .into_iter()
    .filter_map(|(slot_id, current)| current.map(|readback| (slot_id, readback)))
    .collect::<Vec<_>>();
    require(
        current_slots.len() == 1 && current_slots[0].1.receipt.candidate_selection.is_some(),
        "reopened state does not contain exactly one selected multi-codec winner",
    )?;
    let selected_slot_id = current_slots[0].0;

    let mut evidence = Vec::new();
    for (slot_id, codec, expected_verdict) in [
        (
            TQ35_SLOT,
            StoredSlotCodec::TurboQuantBits3p5,
            CompressionAdmissionVerdict::Admitted,
        ),
        (
            INT8_SLOT,
            StoredSlotCodec::ScalarInt8,
            CompressionAdmissionVerdict::Admitted,
        ),
        (
            REFUSAL_SLOT,
            StoredSlotCodec::TurboQuantBits2p5,
            CompressionAdmissionVerdict::Refused,
        ),
    ] {
        let slot = panel_slot(&state, slot_id)?;
        let index = state.registry.compressed_slot_index(&vault, slot)?;
        index.verify_at(snapshot)?;
        verify_direct_search(&state.registry, &vault, slot, snapshot, &queries)?;

        let point = state
            .resolve_slot_vector_at(&vault, snapshot, cx_ids[0], slot.slot_id)?
            .ok_or_else(|| format!("resolved point row missing for slot {slot_id}"))?;
        let batch = state.resolve_slot_vectors_at(
            &vault,
            snapshot,
            slot.slot_id,
            &[cx_ids[2], cx_ids[0], cx_ids[7]],
        )?;
        let column = state.resolve_slot_column_at(&vault, snapshot, slot.slot_id)?;
        require(
            batch.len() == 3
                && batch[0].0 == cx_ids[2]
                && batch[1].0 == cx_ids[0]
                && batch[2].0 == cx_ids[7]
                && batch.iter().all(|(_, vector)| vector.is_some()),
            format!("resolved batch order/value mismatch for slot {slot_id}"),
        )?;
        require(
            column.len() == ROWS
                && column
                    .windows(2)
                    .all(|pair| pair[0].0.as_bytes() < pair[1].0.as_bytes()),
            format!("resolved whole-column mismatch for slot {slot_id}"),
        )?;
        let indexed = index.read_at(cx_ids[0], snapshot)?;
        require(
            point == indexed,
            format!("central resolver differs from Registry point read for slot {slot_id}"),
        )?;

        let manifest = required_row(
            &vault,
            snapshot,
            ColumnFamily::Compression,
            &compression_manifest_key(slot.slot_id),
            "compression manifest",
        )?;
        let primary = required_row(
            &vault,
            snapshot,
            ColumnFamily::slot(slot.slot_id),
            &slot_key(cx_ids[0]),
            "compressed primary",
        )?;
        let raw = required_row(
            &vault,
            snapshot,
            ColumnFamily::slot_raw(slot.slot_id),
            &slot_key(cx_ids[0]),
            "raw sidecar",
        )?;
        let proof = required_row(
            &vault,
            snapshot,
            ColumnFamily::Compression,
            &compression_membership_proof_key(slot.slot_id, cx_ids[0]),
            "membership proof",
        )?;
        require(
            primary.first().copied() == Some(COMPRESSED_SLOT_TAG)
                && raw.first().copied() != Some(COMPRESSED_SLOT_TAG),
            format!("primary/raw representation discriminator mismatch for slot {slot_id}"),
        )?;
        let raw_vector = encode::decode_slot_vector(&raw)?;
        require(
            raw_vector == dense_vector(0),
            format!("raw sidecar bytes differ from known source vector for slot {slot_id}"),
        )?;

        let admission = state.registry.compression_admission_status(&vault, slot)?;
        let latest = admission
            .latest_evaluation
            .as_ref()
            .ok_or_else(|| format!("slot {slot_id} latest evaluation missing"))?;
        let expected_current = slot_id == selected_slot_id;
        require(
            latest.receipt.verdict == expected_verdict
                && latest.active_generation_current
                && latest.receipt.codec == codec
                && latest.current == expected_current,
            format!("slot {slot_id} latest admission receipt mismatch"),
        )?;
        require(
            admission.current_admission.is_some() == expected_current,
            format!("slot {slot_id} current-admission presence mismatch"),
        )?;
        let latest_digest = decode_hex_32(&latest.receipt_sha256)?;
        let latest_pointer = required_row(
            &vault,
            snapshot,
            ColumnFamily::Compression,
            &compression_admission_evaluation_pointer_key(slot.slot_id),
            "latest-evaluation pointer",
        )?;
        require(
            latest_pointer.as_slice() == latest_digest.as_slice(),
            format!("slot {slot_id} latest pointer differs from receipt digest"),
        )?;
        let current_pointer = vault.read_cf_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_admission_pointer_key(slot.slot_id),
        )?;
        require(
            current_pointer.is_some() == expected_current
                && current_pointer
                    .as_deref()
                    .is_none_or(|pointer| pointer == latest_digest.as_slice()),
            format!("slot {slot_id} current pointer differs from expected receipt"),
        )?;
        let receipt_bytes = required_row(
            &vault,
            snapshot,
            ColumnFamily::Compression,
            &compression_admission_receipt_key(slot.slot_id, latest_digest),
            "admission receipt",
        )?;
        require(
            sha256(&receipt_bytes) == latest_digest,
            format!("slot {slot_id} receipt key/value SHA-256 mismatch"),
        )?;
        let decoded_receipt: CompressionAdmissionReceipt = serde_json::from_slice(&receipt_bytes)?;
        require(
            decoded_receipt == latest.receipt
                && decoded_receipt.schema == COMPRESSION_ADMISSION_SCHEMA,
            format!("slot {slot_id} raw receipt differs from validated status receipt"),
        )?;
        let immutable_verified = verify_immutable_receipt_components(vault_dir, &decoded_receipt)?;
        evidence.push(PersistedSlotEvidence {
            slot_id,
            codec,
            manifest_bytes: manifest.len(),
            manifest_sha256: sha256_hex(&manifest),
            primary_bytes: primary.len(),
            primary_sha256: sha256_hex(&primary),
            raw_bytes: raw.len(),
            raw_sha256: sha256_hex(&raw),
            proof_bytes: proof.len(),
            proof_sha256: sha256_hex(&proof),
            current_receipt_sha256: current_pointer.map(|bytes| hex(&bytes)),
            latest_receipt_sha256: latest.receipt_sha256.clone(),
            verdict: expected_verdict,
            allocation_scope: decoded_receipt.allocations.scope.clone(),
            materialized_primary_rows_per_packed_search: decoded_receipt
                .allocations
                .materialized_primary_rows_per_packed_search,
            materialized_primary_bytes_per_packed_search: decoded_receipt
                .allocations
                .materialized_primary_bytes_per_packed_search,
            packed_result_buffers_returned: decoded_receipt
                .allocations
                .packed_result_buffers_returned,
            build_elapsed_ns: decoded_receipt.build.elapsed_ns,
            vram_applicability: match &decoded_receipt.placement.vram {
                calyx_registry::CompressionVramObservation::NotApplicable { .. } => {
                    "not_applicable".to_string()
                }
                calyx_registry::CompressionVramObservation::ProviderObserved { .. } => {
                    "provider_observed".to_string()
                }
            },
            working_set_bytes_after: decoded_receipt.resources.working_set_bytes_after,
            immutable_physical_components_verified: immutable_verified,
        });
    }

    let unsupported = panel_slot(&state, UNSUPPORTED_SLOT)?;
    let (unsupported_state, unsupported_primary) =
        raw_unmanifested_slot_state(vault_dir, &vault, unsupported.slot_id)?;
    require(
        unsupported_state.primary_rows == ROWS
            && unsupported_state.raw_rows == 0
            && unsupported_state.manifest_sha256.is_none()
            && unsupported_state.proof_rows == 0
            && unsupported_state.latest_evaluation.is_none()
            && unsupported_state.current_admission.is_none(),
        "unsupported codec slot did not remain an unmanifested raw column",
    )?;
    let unsupported_primary = unsupported_primary.into_iter().collect::<BTreeMap<_, _>>();
    for (row, cx_id) in cx_ids.iter().copied().enumerate() {
        let bytes = unsupported_primary
            .get(&slot_key(cx_id))
            .ok_or("unsupported-slot raw primary is absent")?;
        require(
            bytes.first().copied() != Some(COMPRESSED_SLOT_TAG)
                && encode::decode_slot_vector(bytes)? == dense_vector(row),
            format!("unsupported slot primary row {row} differs from its known raw input"),
        )?;
    }

    let ledger_rows = vault.scan_cf_at(snapshot, ColumnFamily::Ledger)?;
    for slot_evidence in &evidence {
        require_admission_ledger_binding(
            &ledger_rows,
            slot_evidence.slot_id,
            &slot_evidence.latest_receipt_sha256,
            "evaluation",
            slot_evidence.verdict,
        )?;
        if slot_evidence.current_receipt_sha256.is_some() {
            require_admission_ledger_binding(
                &ledger_rows,
                slot_evidence.slot_id,
                &slot_evidence.latest_receipt_sha256,
                "publish",
                slot_evidence.verdict,
            )?;
        }
    }
    drop(vault);

    let physical = AsterLedgerCfStore::open(vault_dir)?;
    let physical_rows = physical.scan()?;
    let chain = verify_chain(&physical, 0..physical_rows.len() as u64)?;
    require(
        matches!(chain, VerifyResult::Intact { count } if count == physical_rows.len() as u64),
        format!("reopened physical Ledger chain is not intact: {chain:?}"),
    )?;
    Ok(evidence)
}

fn registry_and_slots() -> AnyResult<(Registry, Vec<Registered>)> {
    let mut registry = Registry::new();
    let slots = vec![
        register(
            &mut registry,
            "issues-557-564-tq35",
            TQ35_SLOT,
            QuantPolicy::TurboQuant {
                bits_per_channel_x2: 7,
            },
        )?,
        register(
            &mut registry,
            "issues-557-564-empty",
            EMPTY_SLOT,
            QuantPolicy::ScalarInt8,
        )?,
        register(
            &mut registry,
            "issues-557-564-int8",
            INT8_SLOT,
            QuantPolicy::ScalarInt8,
        )?,
        register(
            &mut registry,
            "issues-557-564-refusal",
            REFUSAL_SLOT,
            QuantPolicy::TurboQuant {
                bits_per_channel_x2: 5,
            },
        )?,
        register(
            &mut registry,
            "issues-557-564-unsupported",
            UNSUPPORTED_SLOT,
            QuantPolicy::TurboQuant {
                bits_per_channel_x2: 6,
            },
        )?,
    ];
    Ok((registry, slots))
}

fn register(
    registry: &mut Registry,
    name: &str,
    slot_id: u16,
    quant: QuantPolicy,
) -> AnyResult<Registered> {
    register_dim(registry, name, slot_id, quant, DIM)
}

fn register_dim(
    registry: &mut Registry,
    name: &str,
    slot_id: u16,
    quant: QuantPolicy,
    dim: u32,
) -> AnyResult<Registered> {
    let lens = AlgorithmicLens::one_hot(name, Modality::Text, dim);
    let contract = lens.contract().clone();
    let spec = LensSpec {
        name: contract.name().to_string(),
        runtime: LensRuntime::Algorithmic {
            kind: format!("one_hot:{dim}"),
        },
        output: contract.shape(),
        modality: contract.modality(),
        weights_sha256: contract.weights_sha256(),
        corpus_hash: contract.corpus_hash(),
        norm_policy: contract.norm_policy(),
        max_batch: None,
        axis: Some("issues-557-564-physical-admission".to_string()),
        asymmetry: Asymmetry::None,
        quant_default: quant,
        truncate_dim: None,
        recall_delta: 0.0,
        retrieval_only: false,
        excluded_from_dedup: false,
    };
    let lens_id = registry.register_frozen_with_spec(lens, contract, spec)?;
    let id = SlotId::new(slot_id);
    Ok(Registered {
        slot: Slot {
            slot_id: id,
            slot_key: id.with_key(format!("{name}-slot")),
            lens_id,
            shape: SlotShape::Dense(dim),
            modality: Modality::Text,
            asymmetry: Asymmetry::None,
            quant,
            resource: SlotResource::default(),
            axis: Some("issues-557-564-physical-admission".to_string()),
            retrieval_only: false,
            excluded_from_dedup: false,
            bits_about: BTreeMap::new(),
            state: SlotState::Active,
            added_at_panel_version: PANEL_VERSION,
        },
    })
}

fn candidate_request(
    queries: Vec<CompressionQuery>,
    work_limits: CompressionAdmissionWorkLimits,
    gates: CompressionAdmissionGates,
) -> CompressionCandidateEvaluationRequest {
    candidate_request_with_k(queries, K, work_limits, gates)
}

fn candidate_request_with_k(
    queries: Vec<CompressionQuery>,
    k: u32,
    work_limits: CompressionAdmissionWorkLimits,
    gates: CompressionAdmissionGates,
) -> CompressionCandidateEvaluationRequest {
    CompressionCandidateEvaluationRequest {
        requested_backend: BackendKind::Cpu,
        queries,
        k,
        warmup_runs: WARMUP_RUNS,
        measured_runs: MEASURED_RUNS,
        work_limits,
        gates,
    }
}

fn exact_work_limits_for(
    rows: u32,
    raw_dim: u32,
    stored_dim: u32,
    query_count: usize,
) -> AnyResult<CompressionAdmissionWorkLimits> {
    let rows = u64::from(rows);
    let queries = u64::try_from(query_count)?;
    let packed_searches = u64::from(WARMUP_RUNS + MEASURED_RUNS)
        .checked_mul(queries)
        .ok_or("packed-search boundary overflow")?;
    let exact_pairs = rows
        .checked_mul(queries)
        .ok_or("exact-pair boundary overflow")?;
    let packed_pairs = rows
        .checked_mul(packed_searches)
        .ok_or("packed-pair boundary overflow")?;
    let pairwise = exact_pairs
        .checked_add(packed_pairs)
        .and_then(|value| value.checked_add(rows))
        .ok_or("pairwise boundary overflow")?;
    let coefficients = exact_pairs
        .checked_mul(u64::from(raw_dim))
        .and_then(|value| {
            packed_pairs
                .checked_mul(u64::from(stored_dim))
                .and_then(|packed| value.checked_add(packed))
        })
        .and_then(|value| {
            rows.checked_mul(u64::from(raw_dim) + u64::from(stored_dim))
                .and_then(|reconstruction| value.checked_add(reconstruction))
        })
        .ok_or("coefficient boundary overflow")?;
    Ok(CompressionAdmissionWorkLimits {
        maximum_corpus_rows: rows,
        maximum_held_out_queries: queries,
        maximum_total_packed_searches: packed_searches,
        maximum_pairwise_score_evaluations: pairwise,
        maximum_coefficient_evaluations: coefficients,
    })
}

fn exact_work_limits(
    generation: &calyx_registry::CompressedGenerationIdentity,
    query_count: usize,
) -> AnyResult<CompressionAdmissionWorkLimits> {
    exact_work_limits_for(
        generation.row_count,
        generation.raw_dim,
        generation.stored_dim,
        query_count,
    )
}

fn passing_gates() -> CompressionAdmissionGates {
    CompressionAdmissionGates {
        minimum_recall_at_k: 1.0,
        maximum_mean_cosine_error: 0.5,
        maximum_cosine_error: 0.75,
        maximum_p99_latency_ns: 10_000_000_000,
        maximum_total_physical_bytes: 64 * 1024 * 1024,
        maximum_working_set_bytes: 64 * 1024 * 1024 * 1024,
        maximum_materialized_primary_bytes_per_query: 4 * 1024 * 1024,
    }
}

fn require_admitted(readback: &CompressionAdmissionReadback) -> AnyResult<()> {
    require(
        readback.receipt.verdict == CompressionAdmissionVerdict::Admitted
            && readback.current
            && readback.active_generation_current
            && readback.receipt_commit_seq.is_some()
            && readback.receipt_ledger.is_some()
            && readback.pointer_commit_seq.is_some()
            && readback.pointer_ledger.is_some(),
        "admitted receipt was not physically published and promoted",
    )
}

fn require_current_status(readback: &CompressionAdmissionReadback) -> AnyResult<()> {
    require(
        readback.receipt.verdict == CompressionAdmissionVerdict::Admitted
            && readback.current
            && readback.active_generation_current
            && readback.receipt.candidate_selection.is_some()
            && readback.receipt_commit_seq.is_none()
            && readback.receipt_ledger.is_none()
            && readback.pointer_commit_seq.is_none()
            && readback.pointer_ledger.is_none(),
        "current status did not prove a selected active admission or unexpectedly claimed mutation-only publication references",
    )
}

fn require_unpublished_candidate(readback: &CompressionAdmissionReadback) -> AnyResult<()> {
    require(
        readback.receipt.verdict == CompressionAdmissionVerdict::Admitted
            && !readback.current
            && readback.active_generation_current
            && readback.receipt_commit_seq.is_some()
            && readback.receipt_ledger.is_some()
            && readback.pointer_commit_seq.is_none()
            && readback.pointer_ledger.is_none()
            && readback.receipt.candidate_selection.is_none(),
        "passing candidate evaluation was published before selection",
    )
}

fn exact_physical_ratio_precedes(
    left: &CompressionAdmissionReceipt,
    left_receipt_sha256: &str,
    right: &CompressionAdmissionReceipt,
    right_receipt_sha256: &str,
) -> AnyResult<bool> {
    let left_cross = u128::from(left.total_physical_bytes)
        .checked_mul(u128::from(right.logical_values))
        .ok_or("left physical-ratio cross product overflow")?;
    let right_cross = u128::from(right.total_physical_bytes)
        .checked_mul(u128::from(left.logical_values))
        .ok_or("right physical-ratio cross product overflow")?;
    if left_cross != right_cross {
        return Ok(left_cross < right_cross);
    }
    Ok((
        codec_rank(left.codec),
        left.level.as_bytes(),
        left.slot_id,
        left_receipt_sha256,
    ) < (
        codec_rank(right.codec),
        right.level.as_bytes(),
        right.slot_id,
        right_receipt_sha256,
    ))
}

fn codec_rank(codec: StoredSlotCodec) -> u8 {
    match codec {
        StoredSlotCodec::TurboQuantBits2p5 => 0,
        StoredSlotCodec::TurboQuantBits3p5 => 1,
        StoredSlotCodec::Binary => 2,
        StoredSlotCodec::MxFp4 => 3,
        StoredSlotCodec::ScalarInt8 => 4,
        StoredSlotCodec::MxFp8 => 5,
        StoredSlotCodec::RawF32 => 6,
    }
}

fn verify_direct_search(
    registry: &Registry,
    vault: &AsterVault<SystemClock>,
    slot: &Slot,
    snapshot: Seq,
    queries: &[KnownQuery],
) -> AnyResult<()> {
    let index = registry.compressed_slot_index(vault, slot)?;
    for known in queries {
        let hits = index.search_at(&known.query.values, K as usize, snapshot)?;
        let actual = hits.iter().map(|hit| hit.cx_id).collect::<Vec<_>>();
        require(
            actual == known.expected_top_k,
            format!(
                "slot {} packed top-k differs for held-out query {}: expected {:?}, got {:?}",
                slot.slot_id.get(),
                known.query.cx_id,
                known.expected_top_k,
                actual
            ),
        )?;
    }
    Ok(())
}

fn slot_state(vault: &AsterVault<SystemClock>, slot_id: SlotId) -> AnyResult<SlotStateReadback> {
    let seq = vault.latest_seq();
    let primary = vault.scan_cf_at(seq, ColumnFamily::slot(slot_id))?;
    let raw = vault.scan_cf_at(seq, ColumnFamily::slot_raw(slot_id))?;
    slot_state_from_rows(vault, slot_id, seq, &primary, &raw)
}

fn raw_unmanifested_slot_state(
    vault_dir: &Path,
    vault: &AsterVault<SystemClock>,
    slot_id: SlotId,
) -> AnyResult<(SlotStateReadback, Vec<(Vec<u8>, Vec<u8>)>)> {
    let raw_cf_path = vault_dir
        .join("cf")
        .join(ColumnFamily::slot_raw(slot_id).name());
    match fs::symlink_metadata(&raw_cf_path) {
        Ok(_) => {
            return Err(format!(
                "raw/unmanifested slot {} unexpectedly has a physical sidecar namespace at {}",
                slot_id.get(),
                raw_cf_path.display()
            )
            .into());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "inspect raw sidecar namespace {}: {error}",
                raw_cf_path.display()
            )
            .into());
        }
    }
    let seq = vault.latest_seq();
    let primary = vault.scan_cf_at(seq, ColumnFamily::slot(slot_id))?;
    let state = slot_state_from_rows(vault, slot_id, seq, &primary, &[])?;
    Ok((state, primary))
}

fn slot_state_from_rows(
    vault: &AsterVault<SystemClock>,
    slot_id: SlotId,
    seq: Seq,
    primary: &[(Vec<u8>, Vec<u8>)],
    raw: &[(Vec<u8>, Vec<u8>)],
) -> AnyResult<SlotStateReadback> {
    let proofs = vault.scan_cf_range_at(
        seq,
        ColumnFamily::Compression,
        &compression_membership_proof_prefix_range(slot_id),
    )?;
    let compression = vault.scan_cf_at(seq, ColumnFamily::Compression)?;
    let ledger = vault.scan_cf_at(seq, ColumnFamily::Ledger)?;
    let manifest = vault.read_cf_at(
        seq,
        ColumnFamily::Compression,
        &compression_manifest_key(slot_id),
    )?;
    let latest = vault.read_cf_at(
        seq,
        ColumnFamily::Compression,
        &compression_admission_evaluation_pointer_key(slot_id),
    )?;
    let current = vault.read_cf_at(
        seq,
        ColumnFamily::Compression,
        &compression_admission_pointer_key(slot_id),
    )?;
    Ok(SlotStateReadback {
        seq,
        primary_rows: primary.len(),
        primary_sha256: rows_sha256(primary),
        raw_rows: raw.len(),
        raw_sha256: rows_sha256(raw),
        manifest_sha256: manifest.as_ref().map(|bytes| sha256_hex(bytes)),
        proof_rows: proofs.len(),
        proofs_sha256: rows_sha256(&proofs),
        latest_evaluation: latest.map(|bytes| hex(&bytes)),
        current_admission: current.map(|bytes| hex(&bytes)),
        compression_rows: compression.len(),
        compression_sha256: rows_sha256(&compression),
        ledger_rows: ledger.len(),
        ledger_sha256: rows_sha256(&ledger),
    })
}

fn verify_immutable_receipt_components(
    vault_dir: &Path,
    receipt: &CompressionAdmissionReceipt,
) -> AnyResult<usize> {
    let immutable = receipt
        .physical_components
        .iter()
        .filter(|component| {
            component.role == "wal_record"
                || component.role.starts_with("durable_sst:")
                || component.role.starts_with("immutable_manifest:")
        })
        .collect::<Vec<_>>();
    require(
        immutable
            .iter()
            .any(|component| component.role == "wal_record")
            && immutable
                .iter()
                .any(|component| component.role.starts_with("durable_sst:"))
            && immutable
                .iter()
                .any(|component| component.role.starts_with("immutable_manifest:")),
        "receipt lacks an immutable WAL/SST/manifest physical component",
    )?;
    for component in &immutable {
        require(
            component.container == "vault",
            format!(
                "untiered FSV receipt uses unexpected container {}",
                component.container
            ),
        )?;
        let relative = safe_relative_path(&component.relative_path)?;
        let observed = sha256_file_range(
            &vault_dir.join(relative),
            component.offset,
            component.length,
        )?;
        require(
            observed == component.sha256,
            format!(
                "immutable physical component hash mismatch for {}@{}+{}",
                component.relative_path, component.offset, component.length
            ),
        )?;
    }
    Ok(immutable.len())
}

fn live_generation_inventory(
    vault: &AsterVault<SystemClock>,
    vault_dir: &Path,
    slot_id: SlotId,
    seq: Seq,
) -> AnyResult<(PhysicalCommitInventory, LivePhysicalInventoryEvidence)> {
    let expected_cfs = [
        ColumnFamily::slot(slot_id),
        ColumnFamily::slot_raw(slot_id),
        ColumnFamily::Compression,
        ColumnFamily::Ledger,
        ColumnFamily::TimeIndex,
    ];
    let inventory = vault.physical_commit_inventory(seq, &expected_cfs)?;
    let mut components = Vec::with_capacity(inventory.components.len());
    for component in &inventory.components {
        require(
            component.container.name() == "vault",
            format!(
                "untiered live inventory uses unexpected container {}",
                component.container.name()
            ),
        )?;
        let relative = safe_relative_path(&component.relative_path)?;
        let observed = sha256_file_range(
            &vault_dir.join(relative),
            component.offset,
            component.length,
        )?;
        require(
            observed == component.sha256_hex(),
            format!(
                "live physical component hash mismatch for {}",
                component.canonical_identity()
            ),
        )?;
        components.push(LivePhysicalComponentEvidence {
            identity: component.canonical_identity(),
            role: physical_role(&component.role),
            sha256: observed,
        });
    }
    let evidence = LivePhysicalInventoryEvidence {
        seq: inventory.seq,
        manifest_seq: inventory.manifest_seq,
        column_families: inventory
            .column_families
            .iter()
            .map(|cf| cf.name().to_string())
            .collect(),
        rows: inventory.rows.len(),
        components,
        total_physical_bytes: inventory.total_physical_bytes,
    };
    Ok((inventory, evidence))
}

fn require_receipt_matches_inventory(
    receipt: &CompressionAdmissionReceipt,
    inventory: &PhysicalCommitInventory,
) -> AnyResult<()> {
    let actual = receipt
        .physical_components
        .iter()
        .map(|component| {
            format!(
                "{}/{}@{}+{}|{}|{}",
                component.container,
                component.relative_path,
                component.offset,
                component.length,
                component.sha256,
                component.role,
            )
        })
        .collect::<Vec<_>>();
    let expected = inventory
        .components
        .iter()
        .map(|component| {
            format!(
                "{}|{}|{}",
                component.canonical_identity(),
                component.sha256_hex(),
                physical_role(&component.role),
            )
        })
        .collect::<Vec<_>>();
    require(
        actual == expected
            && receipt.total_physical_bytes == inventory.total_physical_bytes
            && receipt.manifest_seq == inventory.manifest_seq,
        "persisted admission receipt differs from the independently read live physical inventory",
    )
}

fn physical_role(role: &PhysicalCommitComponentRole) -> String {
    match role {
        PhysicalCommitComponentRole::WalRecord => "wal_record".to_string(),
        PhysicalCommitComponentRole::DurableSst {
            cf,
            sst_index,
            entries,
        } => format!(
            "durable_sst:cf={}:index={sst_index}:entries={entries}",
            cf.name()
        ),
        PhysicalCommitComponentRole::CurrentPointer => "current_pointer".to_string(),
        PhysicalCommitComponentRole::ImmutableManifest { manifest_seq } => {
            format!("immutable_manifest:seq={manifest_seq}")
        }
        PhysicalCommitComponentRole::ManifestMirror { manifest_seq } => {
            format!("manifest_mirror:seq={manifest_seq}")
        }
        PhysicalCommitComponentRole::RouterHandoff { manifest_seq } => {
            format!("router_handoff:seq={manifest_seq}")
        }
    }
}

fn require_admission_ledger_binding(
    rows: &[(Vec<u8>, Vec<u8>)],
    slot_id: u16,
    receipt_sha256: &str,
    phase: &str,
    verdict: CompressionAdmissionVerdict,
) -> AnyResult<()> {
    let expected_verdict = serde_json::to_value(verdict)?;
    let mut matches = 0;
    for (key, bytes) in rows {
        let entry = calyx_ledger::decode(bytes)?;
        require(
            key.as_slice() == entry.seq.to_be_bytes().as_slice(),
            "Ledger CF key differs from decoded sequence",
        )?;
        if entry.kind != EntryKind::Admission {
            continue;
        }
        let payload: Value = serde_json::from_slice(&entry.payload)?;
        if payload.get("marker") == Some(&Value::String(ADMISSION_MARKER.to_string()))
            && payload.get("slot_id").and_then(Value::as_u64) == Some(u64::from(slot_id))
            && payload.get("receipt_sha256").and_then(Value::as_str) == Some(receipt_sha256)
            && payload.get("phase").and_then(Value::as_str) == Some(phase)
            && payload.get("verdict") == Some(&expected_verdict)
        {
            matches += 1;
        }
    }
    require(
        matches == 1,
        format!(
            "expected exactly one Admission Ledger binding for slot={slot_id} receipt={receipt_sha256} phase={phase}, found {matches}"
        ),
    )
}

fn panel_slot(state: &VaultPanelState, slot_id: u16) -> AnyResult<&Slot> {
    let matching = state
        .panel
        .slots
        .iter()
        .filter(|slot| slot.slot_id == SlotId::new(slot_id))
        .collect::<Vec<_>>();
    require(
        matching.len() == 1,
        format!("panel contains {} copies of slot {slot_id}", matching.len()),
    )?;
    Ok(matching[0])
}

fn exact_registered(slots: &[Registered], slot_id: u16) -> AnyResult<&Registered> {
    let matches = slots
        .iter()
        .filter(|registered| registered.slot.slot_id == SlotId::new(slot_id))
        .collect::<Vec<_>>();
    require(
        matches.len() == 1,
        format!(
            "registered slot roster contains {} copies of {slot_id}",
            matches.len()
        ),
    )?;
    Ok(matches[0])
}

fn required_row(
    vault: &AsterVault<SystemClock>,
    snapshot: Seq,
    cf: ColumnFamily,
    key: &[u8],
    name: &str,
) -> AnyResult<Vec<u8>> {
    vault
        .read_cf_at(snapshot, cf, key)?
        .ok_or_else(|| format!("{name} is absent from {}", cf.name()).into())
}

fn open_write_vault(dir: &Path, panel: &Panel) -> AnyResult<Arc<AsterVault<SystemClock>>> {
    fs::create_dir_all(dir)?;
    let vault_id: VaultId = VAULT_ID.parse()?;
    Ok(Arc::new(AsterVault::open(
        dir,
        vault_id,
        VAULT_SALT.to_vec(),
        VaultOptions {
            dedup_policy: Some(DedupPolicy::Off),
            panel: Some(panel.clone()),
            ..VaultOptions::default()
        },
    )?))
}

fn open_read_vault(dir: &Path) -> AnyResult<Arc<AsterVault<SystemClock>>> {
    open_read_vault_for_slot_layout(
        dir,
        &[
            SlotId::new(TQ35_SLOT),
            SlotId::new(INT8_SLOT),
            SlotId::new(REFUSAL_SLOT),
            SlotId::new(UNSUPPORTED_SLOT),
        ],
        &[
            SlotId::new(TQ35_SLOT),
            SlotId::new(INT8_SLOT),
            SlotId::new(REFUSAL_SLOT),
        ],
        false,
    )
}

fn open_read_vault_for_slots(
    dir: &Path,
    slots: &[SlotId],
) -> AnyResult<Arc<AsterVault<SystemClock>>> {
    open_read_vault_for_slot_layout(dir, slots, slots, false)
}

fn open_read_vault_for_primary_slots(
    dir: &Path,
    slots: &[SlotId],
) -> AnyResult<Arc<AsterVault<SystemClock>>> {
    open_read_vault_for_slot_layout(dir, slots, &[], false)
}

fn open_read_vault_for_slots_and_base(
    dir: &Path,
    slots: &[SlotId],
) -> AnyResult<Arc<AsterVault<SystemClock>>> {
    open_read_vault_for_slot_layout(dir, slots, slots, true)
}

fn open_read_vault_for_slot_layout(
    dir: &Path,
    primary_slots: &[SlotId],
    raw_sidecar_slots: &[SlotId],
    include_base: bool,
) -> AnyResult<Arc<AsterVault<SystemClock>>> {
    for raw_slot in raw_sidecar_slots {
        require(
            primary_slots.contains(raw_slot),
            format!(
                "raw-sidecar slot {} is absent from the selected primary roster",
                raw_slot.get()
            ),
        )?;
    }
    let vault_id: VaultId = VAULT_ID.parse()?;
    let mut selected = vec![ColumnFamily::Compression, ColumnFamily::Ledger];
    if include_base {
        selected.push(ColumnFamily::Base);
    }
    for slot in primary_slots {
        selected.push(ColumnFamily::slot(*slot));
    }
    for slot in raw_sidecar_slots {
        selected.push(ColumnFamily::slot_raw(*slot));
    }
    Ok(Arc::new(AsterVault::open(
        dir,
        vault_id,
        VAULT_SALT.to_vec(),
        VaultOptions {
            dedup_policy: Some(DedupPolicy::Off),
            restore_mvcc_rows: false,
            restore_ledger_hook: false,
            read_only: true,
            selected_cfs: Some(selected),
            ..VaultOptions::default()
        },
    )?))
}

fn ingest_event(row: usize, slots: &[u16]) -> IngestInput {
    let mut event = IngestInput::new(
        format!("issues-557-564-corpus-row-{row}").into_bytes(),
        PANEL_VERSION,
        Modality::Text,
    );
    for slot in slots {
        event = event.with_slot(SlotId::new(*slot), dense_vector(row));
    }
    event
}

fn corpus_ids(vault: &AsterVault<SystemClock>) -> Vec<CxId> {
    (0..ROWS)
        .map(|row| {
            let event = ingest_event(row, &[TQ35_SLOT, INT8_SLOT, REFUSAL_SLOT, UNSUPPORTED_SLOT]);
            vault.cx_id_for_input(&event.raw_bytes, event.panel_version)
        })
        .collect()
}

fn known_queries(vault: &AsterVault<SystemClock>, cx_ids: &[CxId]) -> Vec<KnownQuery> {
    let mut descending = vec![0.0_f32; DIM as usize];
    let mut ascending = vec![0.0_f32; DIM as usize];
    for row in 0..ROWS {
        // A 4x gap between adjacent known scores makes both expected top-2
        // orders strict even after the deliberately lossy packed codecs.
        descending[row] = 4_u32.pow((ROWS - row - 1) as u32) as f32;
        ascending[row] = 4_u32.pow(row as u32) as f32;
    }
    vec![
        KnownQuery {
            query: CompressionQuery {
                cx_id: vault.cx_id_for_input(b"issues-557-564-held-out-descending", PANEL_VERSION),
                values: descending,
            },
            expected_top_k: vec![cx_ids[0], cx_ids[1]],
        },
        KnownQuery {
            query: CompressionQuery {
                cx_id: vault.cx_id_for_input(b"issues-557-564-held-out-ascending", PANEL_VERSION),
                values: ascending,
            },
            expected_top_k: vec![cx_ids[7], cx_ids[6]],
        },
    ]
}

fn query_inputs(queries: &[KnownQuery]) -> Vec<CompressionQuery> {
    queries.iter().map(|known| known.query.clone()).collect()
}

fn dense_vector(row: usize) -> SlotVector {
    let mut data = vec![0.0_f32; DIM as usize];
    data[row] = 1.0;
    SlotVector::Dense { dim: DIM, data }
}

fn issue_root(workspace: &Path) -> AnyResult<PathBuf> {
    let raw = std::env::var_os(ROOT_ENV)
        .ok_or_else(|| format!("{ROOT_ENV} must name a fresh issue-scoped evidence directory"))?;
    let supplied = PathBuf::from(raw);
    require(
        supplied.components().all(|component| {
            !matches!(component, Component::ParentDir | Component::RootDir)
                || supplied.is_absolute()
        }),
        format!("{ROOT_ENV} contains an invalid parent/root component"),
    )?;
    require(
        !supplied
            .components()
            .any(|component| matches!(component, Component::ParentDir)),
        format!("{ROOT_ENV} must not contain `..`"),
    )?;
    let root = if supplied.is_absolute() {
        supplied
    } else {
        workspace.join(supplied)
    };
    let allowed = workspace
        .join(".tmp")
        .join("manual-fsv")
        .join("issues-557-564");
    require(
        root.starts_with(&allowed) && root != allowed,
        format!(
            "{ROOT_ENV} must be a child of {}, got {}",
            allowed.display(),
            root.display()
        ),
    )?;
    Ok(root)
}

fn disk_inventory(root: &Path) -> AnyResult<Vec<FileReadback>> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let metadata = fs::symlink_metadata(&path)?;
            require(
                metadata.file_type().is_file(),
                format!("inventory path is not a regular file: {}", path.display()),
            )?;
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            Ok(FileReadback {
                relative_path: relative,
                bytes: metadata.len(),
                sha256: sha256_file(&path)?,
            })
        })
        .collect()
}

fn collect_files(root: &Path, current: &Path, output: &mut Vec<PathBuf>) -> AnyResult<()> {
    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(format!("vault inventory refuses symlink: {}", path.display()).into());
        }
        if metadata.is_dir() {
            collect_files(root, &path, output)?;
        } else if metadata.is_file() {
            require(
                path.starts_with(root),
                format!("inventory path escaped root: {}", path.display()),
            )?;
            output.push(path);
        } else {
            return Err(format!("vault inventory refuses special file: {}", path.display()).into());
        }
    }
    Ok(())
}

fn safe_relative_path(value: &str) -> AnyResult<PathBuf> {
    let path = PathBuf::from(value.replace('/', "\\"));
    require(
        !path.is_absolute()
            && path.components().all(|component| {
                !matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            }),
        format!("physical component path is not relative: {value}"),
    )?;
    Ok(path)
}

fn rows_sha256(rows: &[(Vec<u8>, Vec<u8>)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"issues-557-564-cf-rows-v1");
    for (key, value) in rows {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key);
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    hex(&hasher.finalize())
}

fn ledger_rows_sha256(rows: &[calyx_ledger::LedgerRow]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"issues-557-564-physical-ledger-rows-v1");
    for row in rows {
        hasher.update(row.seq.to_be_bytes());
        hasher.update((row.bytes.len() as u64).to_be_bytes());
        hasher.update(&row.bytes);
    }
    hex(&hasher.finalize())
}

fn sha256_file(path: &Path) -> AnyResult<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

fn sha256_file_range(path: &Path, offset: u64, length: u64) -> AnyResult<String> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut remaining = length;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))?;
        let read = file.read(&mut buffer[..requested])?;
        require(
            read != 0,
            format!(
                "physical component {} ended before offset {offset} length {length}",
                path.display()
            ),
        )?;
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(hex(&hasher.finalize()))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&sha256(bytes))
}

fn decode_hex_32(value: &str) -> AnyResult<[u8; 32]> {
    require(value.len() == 64, "SHA-256 hex must have 64 digits")?;
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn require(condition: bool, message: impl Into<String>) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
