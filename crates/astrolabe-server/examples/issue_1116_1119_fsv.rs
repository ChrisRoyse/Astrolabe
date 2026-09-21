//! Manual Full State Verification for landed #1116-#1119 behavior.
//!
//! `execute` creates and indexes one real committed Rust repository through the
//! production shadow pipeline, then exercises fused search, complete
//! architecture clustering, latent discovery, and association discovery.
//! `association-publish` consumes only exact externally captured provider
//! receipts. Run it twice: the first call publishes the first two generations
//! and exports the third request roster; the second publishes the third and
//! proves bounded current+previous retention plus exact retired tombstones.
//! `transport` sends real NDJSON JSON-RPC through the production MCP transport.
//! `readback` is a separate process that opens SQLite and Aster again and
//! verifies the physical rows, manifests, ledger, clustering projection and
//! receipts, and independently recomputed validation arithmetic. This is not a
//! test. `fast-semantic-edge` and `fast-semantic-readback` separately prove that
//! a real fast-mode/NULL-eligible CBM Project still publishes the universal
//! panel-derived S20/composite kernel generation without CBM vector rows.
//! `unavailable-corpus-edge` and `unavailable-corpus-readback` use a separate
//! real one-function moderate-mode corpus to prove the physical
//! `unavailable_corpus`/S208 boundary and independent-process readback.
//!
//! SIM terminal-attestation FSV runs after the shipping index call and before
//! the ordinary cache-hit repeat. It point-reads all four family markers and
//! their exact Ledger rows from the real indexed vault, independently hashes
//! every sorted raw family key/value byte, and proves the family LedgerRefs
//! carried by the persisted composite CSR. Byte-identical vault clones then
//! exercise, in order, true no-delta reuse, absent-marker bootstrap, malformed
//! marker refusal, stale marker refusal, and the exact stale-sequence derived
//! publication primitive. `readback` reopens those physical clone generations
//! in a separate process. These fixture-scale `O(E_f)` scans are PC-04 FSV
//! readback only and establish no production-cost claim (#1064 PC-16/24/37/38/
//! 41; generation-time PC-J4).
//!
//! The `transport` mode also sends the closed native `detect_changes` v2 request
//! with all four caller bounds, then deterministically settles the complete
//! post-augmentation public-result byte count and exercises its exact success
//! plus one-byte-below refusal. `readback` reexecutes both in a separate process.
//! That clean, bounded real-fixture observation is correctness evidence only,
//! not a production-cost measurement (#1064 PC-16/24/37/38/41).
//!
//! The real repository fixture has a baseline commit followed by one genuine
//! bug-fix commit. Oracle FSV independently reads the resulting v5 corpus rows,
//! layout marker, corpus Ledger entry, post-label kernel identity, automatic
//! gate row, and gate Ledger entry. The fixture intentionally has no fabricated
//! `ci:` TestPass/TESTS evidence: `predict_impact mode=backtest` must therefore
//! expose the real failed automatic attestation, while changed-symbol predict
//! and grounded `detect_changes` refuse with that persisted admission code.
//! `oracle-absent-edge` and `oracle-stale-edge` exercise isolated byte-cloned
//! vaults; the ordinary association evaluator capture requirement is unchanged.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use astrolabe_bridge::{
    CbmToolRunner, CbmVerifiedWorkerBinding, CbmWorkerCapabilityJobSnapshot, WindowsFileIdentity,
    capture_windows_file_identity, cbm_project_name_from_path, configured_cbm_host_binary_path,
    initialize_cbm_host_process_with_verified_worker, publish_file_no_replace_write_through,
    set_cbm_cache_dir,
};
use astrolabe_kernel::CrossValidationReport;
use astrolabe_oracle::{
    ORACLE_CORPUS_LAYOUT_SCHEMA, ORACLE_CORPUS_LEDGER_SCHEMA, ORACLE_OCCURRENCE_ROW_SCHEMA,
    ORACLE_PRECEDES_ROW_SCHEMA, raw_oracle_rows, read_git_change_inputs_at,
    read_occurrence_rows_at, read_oracle_corpus_binding_at, read_precedes_edges,
};
use astrolabe_weave::search_index::SlotIndexManifest;
use astrolabe_weave::{
    SimilarityFamily, SimilarityNode, SimilarityPlannerConfig, WeaveMutation, WeaveSlotSource,
    read_complete_association_state_at,
};
use calyx_aster::cf::{
    ColumnFamily, KeyRange, compression_manifest_key, full_content_hash, ledger_key, prefix_range,
    slot_key,
};
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::{AsterVault, OrderedCfRead, VaultOptions, decode_strict_raw_slot_value};
use calyx_core::{Clock, CxId, FixedClock, LedgerRef, SlotId, SlotVector, VaultId};
use calyx_ledger::{ActorId, EntryKind, SubjectId, decode as decode_ledger};
use calyx_registry::CompressedGenerationIdentity;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[path = "../worker_source_generation.rs"]
mod worker_source_generation;

const GENERATION_OBSERVED_AT_MS: u64 = 1_787_300_000_000;
const REPARSE_POINT_ATTRIBUTE: u32 = 0x400;
const SEMANTIC_COVERAGE_PREFIX: &[u8] = b"astrolabe:semantic-coverage:v1:";
const WORKER_CAPABILITY_SCHEMA: &str = "astrolabe.index-worker-capability.v3";
const WORKER_ARGV_SCHEMA: &str = "astrolabe.index-worker-argv.v2";
const WORKER_PROGRESS_SCHEMA: &str = "cbm.worker-progress.v1";
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const STAGED_ABORT_SLOT: u16 = 1;
const STAGED_ABORT_ACTOR: &str = "astrolabe-issue-1147-staged-slot-mutator";
const STAGED_ABORT_BARRIER_ENV: &str = "ASTRO_MANUAL_FSV_WEAVE_BINDING_BARRIER";
const STAGED_ABORT_BARRIER_ARM_SCHEMA: &str = "astrolabe.manual-fsv.weave-source-barrier-arm.v1";
const STAGED_ABORT_BARRIER_READY_SCHEMA: &str =
    "astrolabe.manual-fsv.weave-source-barrier-ready.v1";
const STAGED_ABORT_BARRIER_ACK_SCHEMA: &str = "astrolabe.manual-fsv.weave-source-barrier-ack.v1";
const STAGED_ABORT_BARRIER_WAIT_MS: u64 = 20 * 60 * 1_000;
const STAGED_ABORT_BARRIER_POLL_MS: u64 = 25;
const STAGED_ABORT_TOOL_FAULT_SCHEMA: &str = "astrolabe.tool_fault/v1";
const STAGED_ABORT_PRESERVED_SCHEMA: &str = "astrolabe.shadow-preserved-stage.v4";
const STAGED_ABORT_PRESERVED_INVENTORY_SCHEMA: &str =
    "astrolabe.shadow-preserved-stage.inventory.v1";
const STAGED_ABORT_SHADOW_VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const DISCOVERY_FSV_CAPTURE_SCHEMA: &str = "astrolabe.manual-fsv.association_external_capture.v1";
const DISCOVERY_FSV_REQUEST_SCHEMA: &str = "astrolabe.manual-fsv.association_external_requests.v1";
const DISCOVERY_FSV_WAVE_SCHEMA: &str = "astrolabe.manual-fsv.association_publish_wave.v1";
const DISCOVERY_PREFIX_V3: &str = "astrolabe:association-discovery:v3:";
const DISCOVERY_PERSISTED_SCHEMA_V3: &str = "astrolabe.association_discovery.persisted.v3";
const DISCOVERY_PREPARED_SCHEMA_V4: &str = "astrolabe.association_discovery.prepared.v4";
const DISCOVERY_FINAL_SCHEMA_V4: &str = "astrolabe.association_discovery.final.v4";
const DISCOVERY_RECEIPT_SCHEMA_V2: &str = "astrolabe.association_discovery.evaluator_receipt.v2";
const DISCOVERY_CAPTURE_SCHEMA_V1: &str =
    "astrolabe.association_discovery.trusted_external_capture.v1";
const DISCOVERY_RESPONSE_SCHEMA_V1: &str = "astrolabe.association_discovery.evaluator_response.v1";
const SIM_SOURCE_ATTESTATION_SCHEMA: &str = "astrolabe.sim_source_attestation.v1";
const SIM_SOURCE_ATTESTATION_LEDGER_SCHEMA: &str = "astrolabe.sim_source_attestation_ledger.v1";
const SIM_SOURCE_ATTESTATION_PREFIX: &[u8] = b"astrolabe:sim-source-attestation:v1:";
const SIM_SOURCE_ATTESTATION_SUBJECT_PREFIX: &str = "astrolabe-sim-source-attestation:v1";
const SIM_FAMILY_DUMP_SCHEMA: &[u8] = b"astrolabe.sim_family_persisted_dump.v1";
const SIM_SCENARIO_ACTOR: &str = "astrolabe-manual-fsv-sim-terminal";
const SIM_CAS_RACE_KEY: &[u8] = b"astrolabe:manual-fsv:sim-cas-race:v1";
const DETECT_CHANGES_FSV_DEPTH: u64 = 2;
const DETECT_CHANGES_FSV_CHANGED_FILE_MAX: u64 = 64;
const DETECT_CHANGES_FSV_IMPACT_MAX_SYMBOLS: u64 = 256;
const DETECT_CHANGES_FSV_REACH_MAX_NODES_PER_SYMBOL: u64 = 128;
const DETECT_CHANGES_FSV_RESULT_MAX_BYTES: u64 = 1_048_576;
const ORACLE_CORPUS_LAYOUT_KEY: &[u8] = b"astrolabe:oracle-corpus-layout:v5";
const ORACLE_OCCURRENCE_PREFIX: &[u8] = b"astrolabe:oracle-occurrence:v5:";
const ORACLE_PRECEDES_PREFIX: &[u8] = b"astrolabe:oracle-precedes:v3:";
const ORACLE_CHANGE_PREFIX: &[u8] = b"astrolabe:oracle-change:v1:";
const ORACLE_GATE_CURRENT_PREFIX: &[u8] = b"astrolabe:oracle-gate-current:v1:";
const ORACLE_GATE_GENERATION_PREFIX: &[u8] = b"astrolabe:oracle-gate-generation:v1:";
const ORACLE_GATE_ATTESTATION_SCHEMA: &str = "astrolabe.oracle_gate_attestation.v1";
const ORACLE_GATE_POINTER_SCHEMA: &str = "astrolabe.oracle_gate_pointer.v1";
const ORACLE_GATE_LEDGER_SCHEMA: &str = "astrolabe.oracle_gate_ledger.v1";
const ORACLE_CORPUS_ACTOR: &str = "astrolabe-oracle-corpus-generation";
const ORACLE_GATE_ACTOR: &str = "astrolabe-oracle-gate-generation";
const ORACLE_FAILED_ADMISSION: &str = "ASTRO_ORACLE_BACKTEST_ADMISSION_REQUIRED";
const ORACLE_NOT_BEATEN: &str = "ASTRO_ORACLE_BACKTEST_NOT_BEATEN";
const ORACLE_GATE_ABSENT: &str = "ASTRO_ORACLE_GATE_ABSENT";
const ORACLE_GATE_STALE: &str = "ASTRO_ORACLE_GATE_STALE";
const ORACLE_DETECT_GROUNDING_DEFICIT: &str = "ASTRO_DETECT_CHANGES_GROUNDING_DEFICIT";
const ORACLE_ABSENT_MUTATION_KEY: &[u8] = b"astrolabe:manual-fsv:oracle-gate-absent:v1";
const ORACLE_STALE_MUTATION_KEY: &[u8] = b"astrolabe:manual-fsv:oracle-gate-stale:v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FsvSimSourceAttestation {
    schema: String,
    family: String,
    row_count: u64,
    total_bytes: u64,
    content_blake3: String,
    ledger_seq: u64,
    ledger_hash: String,
    actor: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FsvSimSourceAttestationLedgerPayload {
    schema: String,
    family: String,
    row_count: u64,
    total_bytes: u64,
    content_blake3: String,
}

#[derive(Clone, Debug)]
struct FsvSimFamilyState {
    marker_key: Vec<u8>,
    marker_bytes: Vec<u8>,
    marker: FsvSimSourceAttestation,
    ledger_ref: LedgerRef,
    rows: Vec<(Vec<u8>, Vec<u8>, astrolabe_weave::SimEdgeGraphRow)>,
}

#[derive(Clone, Debug)]
struct FsvSimTerminalState {
    receipt: Value,
    families: BTreeMap<SimilarityFamily, FsvSimFamilyState>,
}

#[derive(Clone, Debug)]
struct FsvSimProjectionContributor {
    family: SimilarityFamily,
    ledger_ref: LedgerRef,
    weight_bits: u32,
    source_atom_id: String,
    target_atom_id: String,
}

type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

fn fail(code: &str, message: impl std::fmt::Display, remediation: &str) -> ! {
    eprintln!("code={code} message={message} remediation={remediation}");
    std::process::exit(1);
}

fn require(condition: bool, code: &str, message: impl std::fmt::Display) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(format!("{code}: {message}").into())
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn cluster_hash_u64(digest: &mut Sha256, value: u64) {
    digest.update(value.to_be_bytes());
}

fn cluster_hash_text(digest: &mut Sha256, value: &str) {
    cluster_hash_u64(digest, value.len() as u64);
    digest.update(value.as_bytes());
}

fn cluster_hash_f64(digest: &mut Sha256, value: f64) {
    cluster_hash_u64(digest, value.to_bits());
}

fn finish_cluster_hash(digest: Sha256) -> String {
    format!("{:x}", digest.finalize())
}

fn add_cluster_result_size(size: &mut u64, increment: u64) -> AnyResult<()> {
    *size = size.checked_add(increment).ok_or_else(|| {
        "ISSUE_1149_CLUSTER_RESULT_SIZE_OVERFLOW: canonical result size overflow".into()
    })?;
    Ok(())
}

fn add_cluster_result_text(size: &mut u64, value: &str) -> AnyResult<()> {
    add_cluster_result_size(size, 8)?;
    add_cluster_result_size(size, u64::try_from(value.len())?)
}

fn add_cluster_result_hash_text(digest: &mut Sha256, size: &mut u64, value: &str) -> AnyResult<()> {
    cluster_hash_text(digest, value);
    add_cluster_result_text(size, value)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> AnyResult<Vec<u8>> {
    require(
        value.len().is_multiple_of(2),
        "ISSUE_1116_1119_HEX_LENGTH_INVALID",
        value,
    )?;
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn file_sha256(path: &Path) -> AnyResult<(u64, String)> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                digest.update(&buffer[..read]);
                bytes = bytes
                    .checked_add(read as u64)
                    .ok_or("file byte count overflow")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let digest = digest.finalize();
    Ok((bytes, hex_lower(&digest)))
}

fn optional_file_state(path: &Path) -> AnyResult<Value> {
    match file_sha256(path) {
        Ok((bytes, digest)) => Ok(json!({
            "exists": true,
            "bytes": bytes,
            "sha256": digest,
        })),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(json!({"exists": false, "bytes": 0, "sha256": null}))
        }
        Err(error) => Err(error),
    }
}

fn shipping_astrolabe_executable() -> AnyResult<(PathBuf, Value)> {
    let current = std::env::current_exe()?;
    let current_metadata = fs::symlink_metadata(&current)?;
    require(
        current_metadata.is_file()
            && current_metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1116_1119_CURRENT_EXE_INVALID",
        current.display(),
    )?;
    let examples_dir = current
        .parent()
        .ok_or("ISSUE_1116_1119_CURRENT_EXE_PARENT_MISSING")?;
    require(
        examples_dir
            .file_name()
            .is_some_and(|name| name == "examples"),
        "ISSUE_1116_1119_CURRENT_EXE_LAYOUT_INVALID",
        current.display(),
    )?;
    let debug_dir = examples_dir
        .parent()
        .ok_or("ISSUE_1116_1119_TARGET_DIR_MISSING")?;
    let target_dir = debug_dir
        .parent()
        .ok_or("ISSUE_1116_1119_TARGET_ROOT_MISSING")?;
    require(
        target_dir.file_name().is_some_and(|name| name == "target"),
        "ISSUE_1116_1119_TARGET_ROOT_INVALID",
        target_dir.display(),
    )?;
    for directory in [target_dir, debug_dir, examples_dir] {
        let metadata = fs::symlink_metadata(directory)?;
        require(
            metadata.is_dir() && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
            "ISSUE_1116_1119_TARGET_LAYOUT_INVALID",
            directory.display(),
        )?;
    }
    let shipping = debug_dir.join("astrolabe.exe");
    let metadata = fs::symlink_metadata(&shipping)?;
    require(
        metadata.is_file() && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1116_1119_SHIPPING_HOST_INVALID",
        shipping.display(),
    )?;
    let (bytes, digest) = file_sha256(&shipping)?;
    require(
        bytes > 0,
        "ISSUE_1116_1119_SHIPPING_HOST_EMPTY",
        shipping.display(),
    )?;
    let observed_metadata = fs::symlink_metadata(&shipping)?;
    require(
        observed_metadata.is_file()
            && observed_metadata.file_attributes() == metadata.file_attributes()
            && observed_metadata.len() == metadata.len()
            && observed_metadata.last_write_time() == metadata.last_write_time(),
        "ISSUE_1116_1119_SHIPPING_HOST_CHANGED_DURING_HASH",
        shipping.display(),
    )?;
    let state = json!({
        "path": shipping,
        "bytes": bytes,
        "sha256": digest,
        "file_attributes": observed_metadata.file_attributes(),
        "last_write_filetime_100ns": observed_metadata.last_write_time(),
    });
    Ok((shipping, state))
}

fn current_driver_artifact_state() -> AnyResult<Value> {
    let path = std::env::current_exe()?;
    let metadata = fs::symlink_metadata(&path)?;
    require(
        metadata.is_file() && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1116_1119_DRIVER_ARTIFACT_INVALID",
        path.display(),
    )?;
    let (bytes, digest) = file_sha256(&path)?;
    let identity = capture_windows_file_identity(&path)?;
    require(
        identity.bytes == bytes,
        "ISSUE_1116_1119_DRIVER_ARTIFACT_IDENTITY_MISMATCH",
        path.display(),
    )?;
    Ok(json!({
        "path": path,
        "bytes": bytes,
        "sha256": digest,
        "identity": identity,
    }))
}

fn supervisor_should_wrap() -> bool {
    // SAFETY: this getter reads one process-global startup role flag and accepts
    // no pointers. All calls occur on the process's single initialization thread.
    unsafe { cbm_sys::cbm_index_supervisor_should_wrap() }
}

fn validate_verified_worker_binding(
    binding: &CbmVerifiedWorkerBinding,
    shipping: &Path,
) -> AnyResult<WindowsFileIdentity> {
    let physical_identity = capture_windows_file_identity(shipping)?;
    let (_, physical_sha256) = file_sha256(shipping)?;
    let capability_timeout_ms = astrolabe_domain::knobs::worker_capability_timeout_ms();
    let capability_timeout_micros = u64::from(capability_timeout_ms)
        .checked_mul(1_000)
        .ok_or("ISSUE_1146_CAPABILITY_TIMEOUT_MICROS_OVERFLOW")?;
    let expected_entrypoint = [
        "cli",
        "--index-worker",
        "index_repository",
        "--args-file",
        "{args_path}",
        "--response-out",
        "{response_path}",
        "--worker-progress-out",
        "{progress_path}",
        "--worker-progress-attempt",
        "{attempt_sha256}",
    ];
    let expected_pre_spawn = CbmWorkerCapabilityJobSnapshot {
        accounting_before_total_processes: 0,
        accounting_before_active_processes: 0,
        accounting_before_total_terminated_processes: 0,
        total_processes: 0,
        active_processes: 0,
        total_terminated_processes: 0,
        assigned_processes: 0,
        listed_processes: 0,
        listed_process_id: None,
    };
    let expected_suspended = CbmWorkerCapabilityJobSnapshot {
        accounting_before_total_processes: 1,
        accounting_before_active_processes: 1,
        accounting_before_total_terminated_processes: 0,
        total_processes: 1,
        active_processes: 1,
        total_terminated_processes: 0,
        assigned_processes: 1,
        listed_processes: 1,
        listed_process_id: Some(binding.capability_observation.child_pid),
    };
    let expected_terminal = CbmWorkerCapabilityJobSnapshot {
        accounting_before_total_processes: 1,
        accounting_before_active_processes: 0,
        accounting_before_total_terminated_processes: 0,
        total_processes: 1,
        active_processes: 0,
        total_terminated_processes: 0,
        assigned_processes: 0,
        listed_processes: 0,
        listed_process_id: None,
    };
    require(
        binding.configured_path == shipping
            && binding.retained_identity == physical_identity
            && binding.capability.artifact_identity == physical_identity
            && binding.capability.schema == WORKER_CAPABILITY_SCHEMA
            && binding.capability.worker_argv_schema == WORKER_ARGV_SCHEMA
            && binding.capability.progress_schema == WORKER_PROGRESS_SCHEMA
            && binding.capability.progress_schema_version == 1
            && binding
                .capability
                .worker_argv_template
                .iter()
                .map(String::as_str)
                .eq(expected_entrypoint)
            && binding.capability.worker_cache_arg == "_astrolabe_worker_cache_dir"
            && binding.capability.transition_grant_arg == "_astrolabe_project_transition_writer"
            && binding.capability.package_version == env!("CARGO_PKG_VERSION")
            && binding.capability.source_generation_schema
                == worker_source_generation::SOURCE_GENERATION_SCHEMA
            && binding.capability.source_generation_schema
                == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SCHEMA
            && binding.capability.source_generation_sha256
                == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256
            && capability_timeout_ms > 0
            && binding.capability_observation.child_pid > 0
            && binding.capability_observation.primary_thread_id > 0
            && binding.capability_observation.resume_previous_suspend_count == 1
            && binding.capability_observation.timeout_ms == capability_timeout_ms
            && binding.capability_observation.elapsed_micros > 0
            && binding.capability_observation.elapsed_micros <= capability_timeout_micros
            && binding.capability_observation.stdout_bytes > 0
            && binding.capability_observation.stderr_bytes == 0
            && binding.capability_observation.job_empty_readbacks == 2
            && binding.capability_observation.job_pre_spawn_snapshot == expected_pre_spawn
            && binding.capability_observation.job_suspended_snapshot == expected_suspended
            && binding.capability_observation.job_terminal_snapshot == expected_terminal
            && binding.artifact_sha256 == physical_sha256
            && !binding.capability.challenge.trim().is_empty(),
        "ISSUE_1146_VERIFIED_WORKER_BINDING_INVALID",
        format!("binding={binding:?} physical={physical_identity:?}"),
    )?;
    Ok(physical_identity)
}

fn verified_worker_stable_fields_equal(
    left: &CbmVerifiedWorkerBinding,
    right: &CbmVerifiedWorkerBinding,
) -> bool {
    left.configured_path == right.configured_path
        && left.retained_identity == right.retained_identity
        && left.capability.schema == right.capability.schema
        && left.capability.worker_argv_schema == right.capability.worker_argv_schema
        && left.capability.progress_schema == right.capability.progress_schema
        && left.capability.progress_schema_version == right.capability.progress_schema_version
        && left.capability.worker_argv_template == right.capability.worker_argv_template
        && left.capability.worker_cache_arg == right.capability.worker_cache_arg
        && left.capability.transition_grant_arg == right.capability.transition_grant_arg
        && left.capability.package_version == right.capability.package_version
        && left.capability.source_generation_schema == right.capability.source_generation_schema
        && left.capability.source_generation_sha256 == right.capability.source_generation_sha256
        && left.capability.artifact_identity == right.capability.artifact_identity
        && left.artifact_sha256 == right.artifact_sha256
}

fn write_new_readback(path: &Path, bytes: &[u8]) -> AnyResult<Value> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let observed = fs::read(path)?;
    require(
        observed == bytes,
        "ISSUE_1116_1119_FILE_READBACK_MISMATCH",
        path.display(),
    )?;
    Ok(json!({
        "path": path,
        "bytes": observed.len(),
        "sha256": sha256(&observed),
    }))
}

fn write_existing_readback(path: &Path, bytes: &[u8]) -> AnyResult<Value> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1116_1119_EXISTING_FILE_INVALID",
        path.display(),
    )?;
    let mut file = OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let observed = fs::read(path)?;
    require(
        observed == bytes,
        "ISSUE_1116_1119_EXISTING_FILE_READBACK_MISMATCH",
        path.display(),
    )?;
    Ok(json!({
        "path": path,
        "bytes": observed.len(),
        "sha256": sha256(&observed),
    }))
}

fn write_new_atomic_readback(path: &Path, bytes: &[u8]) -> AnyResult<Value> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut pending_name = path.as_os_str().to_os_string();
    pending_name.push(".pending");
    let pending = PathBuf::from(pending_name);
    require(
        !path.try_exists()? && !pending.try_exists()?,
        "ISSUE_1147_BARRIER_PUBLICATION_PREEXISTS",
        json!({
            "final": path,
            "final_present": path.try_exists()?,
            "pending": pending,
            "pending_present": pending.try_exists()?,
        }),
    )?;
    let pending_receipt = write_new_readback(&pending, bytes)?;
    let pending_metadata = fs::symlink_metadata(&pending)?;
    require(
        pending_metadata.is_file()
            && pending_metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1147_BARRIER_PENDING_NOT_ORDINARY",
        pending.display(),
    )?;
    publish_file_no_replace_write_through(&pending, path)?;
    let metadata = fs::symlink_metadata(path)?;
    let observed = fs::read(path)?;
    require(
        metadata.is_file()
            && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0
            && observed == bytes
            && !pending.try_exists()?,
        "ISSUE_1147_BARRIER_ATOMIC_READBACK_MISMATCH",
        json!({
            "final": path,
            "final_bytes": observed.len(),
            "final_sha256": sha256(&observed),
            "pending": pending,
            "pending_present": pending.try_exists()?,
        }),
    )?;
    Ok(json!({
        "path": path,
        "bytes": observed.len(),
        "sha256": sha256(&observed),
        "pending": pending_receipt,
        "pending_absent_after_publish": true,
    }))
}

fn collect_tree(root: &Path, current: &Path, rows: &mut Vec<Value>) -> AnyResult<()> {
    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        require(
            metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
            "ISSUE_1116_1119_TREE_REPARSE_REFUSED",
            path.display(),
        )?;
        if metadata.is_dir() {
            rows.push(json!({
                "path": path.strip_prefix(root)?.to_string_lossy().replace('\\', "/"),
                "type": "directory",
                "bytes": 0,
                "sha256": null,
            }));
            collect_tree(root, &path, rows)?;
        } else {
            require(
                metadata.is_file(),
                "ISSUE_1116_1119_TREE_ENTRY_INVALID",
                path.display(),
            )?;
            let (bytes, digest) = file_sha256(&path)?;
            rows.push(json!({
                "path": path.strip_prefix(root)?.to_string_lossy().replace('\\', "/"),
                "type": "file",
                "bytes": bytes,
                "sha256": digest,
            }));
        }
    }
    Ok(())
}

fn tree_state(root: &Path) -> AnyResult<Value> {
    if !root.try_exists()? {
        return Ok(json!({
            "exists": false,
            "file_count": 0,
            "directory_count": 0,
            "bytes": 0,
            "sha256": null,
        }));
    }
    let root_metadata = fs::symlink_metadata(root)?;
    require(
        root_metadata.is_dir() && root_metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1116_1119_TREE_ROOT_INVALID",
        root.display(),
    )?;
    let mut rows = Vec::new();
    collect_tree(root, root, &mut rows)?;
    let file_count = rows
        .iter()
        .filter(|row| row["type"] == Value::String("file".to_string()))
        .count();
    let directory_count = rows
        .iter()
        .filter(|row| row["type"] == Value::String("directory".to_string()))
        .count();
    let mut bytes = 0_u64;
    for row in &rows {
        bytes = bytes
            .checked_add(row["bytes"].as_u64().ok_or("tree row has no bytes")?)
            .ok_or("tree byte count overflow")?;
    }
    Ok(json!({
        "exists": true,
        "file_count": file_count,
        "directory_count": directory_count,
        "bytes": bytes,
        "sha256": sha256(&serde_json::to_vec(&rows)?),
    }))
}

fn copy_ordinary_tree(source: &Path, destination: &Path) -> AnyResult<()> {
    let source_metadata = fs::symlink_metadata(source)?;
    require(
        source_metadata.is_dir()
            && source_metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0
            && !destination.try_exists()?,
        "ISSUE_1116_1119_SIM_CLONE_BOUNDARY_INVALID",
        json!({"source": source, "destination": destination}),
    )?;
    fs::create_dir(destination)?;
    let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        require(
            metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
            "ISSUE_1116_1119_SIM_CLONE_REPARSE_REFUSED",
            source_path.display(),
        )?;
        if metadata.is_dir() {
            copy_ordinary_tree(&source_path, &destination_path)?;
        } else {
            require(
                metadata.is_file(),
                "ISSUE_1116_1119_SIM_CLONE_MEMBER_INVALID",
                source_path.display(),
            )?;
            let copied = fs::copy(&source_path, &destination_path)?;
            require(
                copied == metadata.len(),
                "ISSUE_1116_1119_SIM_CLONE_FILE_LENGTH_MISMATCH",
                json!({
                    "source": source_path,
                    "destination": destination_path,
                    "expected_bytes": metadata.len(),
                    "copied_bytes": copied,
                }),
            )?;
        }
    }
    Ok(())
}

fn clone_ordinary_tree_exact(source: &Path, destination: &Path) -> AnyResult<Value> {
    let source_before = tree_state(source)?;
    copy_ordinary_tree(source, destination)?;
    let source_after = tree_state(source)?;
    let destination_state = tree_state(destination)?;
    require(
        source_before == source_after && destination_state == source_before,
        "ISSUE_1116_1119_SIM_CLONE_READBACK_MISMATCH",
        json!({
            "source": source,
            "destination": destination,
            "source_before": source_before,
            "source_after": source_after,
            "destination_state": destination_state,
        }),
    )?;
    Ok(json!({
        "source": source,
        "destination": destination,
        "source_before": source_before,
        "source_after": source_after,
        "destination_state": destination_state,
        "byte_identical_at_clone": true,
    }))
}

fn readonly_sqlite(path: &Path) -> AnyResult<Connection> {
    let uri = format!("file:{}?mode=ro", path.to_string_lossy().replace('\\', "/"));
    Ok(Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}

fn config_rows(cache: &Path, project: &str) -> AnyResult<(String, BTreeMap<String, String>)> {
    let connection = readonly_sqlite(&cache.join("_config.db"))?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let prefix = format!("astrolabe.calyx.{project}");
    let descendants = format!("{prefix}.%");
    let mut statement = connection
        .prepare("SELECT key, value FROM config WHERE key = ?1 OR key LIKE ?2 ORDER BY key")?;
    let rows = statement
        .query_map([prefix.as_str(), descendants.as_str()], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<Result<BTreeMap<String, String>, _>>()?;
    Ok((integrity, rows))
}

fn vault_identity(
    cache: &Path,
    project: &str,
) -> AnyResult<(BTreeMap<String, String>, PathBuf, VaultId, String)> {
    let (integrity, rows) = config_rows(cache, project)?;
    require(
        integrity == "ok",
        "ISSUE_1116_1119_CONFIG_INTEGRITY_FAILED",
        integrity,
    )?;
    let prefix = format!("astrolabe.calyx.{project}");
    require(
        rows.get(&prefix).is_some_and(|dial| dial == "shadow"),
        "ISSUE_1116_1119_SHADOW_DIAL_MISSING",
        &prefix,
    )?;
    let vault_dir = PathBuf::from(
        rows.get(&format!("{prefix}.vault_dir"))
            .ok_or("persisted vault_dir is missing")?,
    );
    let vault_id = VaultId::from_str(
        rows.get(&format!("{prefix}.vault_id"))
            .ok_or("persisted vault_id is missing")?,
    )?;
    let vault_salt = rows
        .get(&format!("{prefix}.vault_salt"))
        .cloned()
        .ok_or("persisted vault_salt is missing")?;
    Ok((rows, vault_dir, vault_id, vault_salt))
}

fn open_vault_selected(
    cache: &Path,
    project: &str,
    selected_cfs: Vec<ColumnFamily>,
) -> AnyResult<(AsterVault, PathBuf)> {
    let (_, vault_dir, vault_id, vault_salt) = vault_identity(cache, project)?;
    let vault = AsterVault::open(
        &vault_dir,
        vault_id,
        vault_salt.into_bytes(),
        VaultOptions {
            read_only: true,
            restore_ledger_hook: false,
            restore_mvcc_rows: false,
            selected_cfs: Some(selected_cfs),
            ..VaultOptions::default()
        },
    )?;
    Ok((vault, vault_dir))
}

fn open_vault(cache: &Path, project: &str) -> AnyResult<(AsterVault, PathBuf)> {
    open_vault_selected(
        cache,
        project,
        vec![
            ColumnFamily::Assay,
            ColumnFamily::Graph,
            ColumnFamily::Kernel,
            ColumnFamily::Kv,
            ColumnFamily::Ledger,
            ColumnFamily::XTerm,
        ],
    )
}

fn open_lowering_vault(cache: &Path, project: &str) -> AnyResult<(AsterVault, PathBuf)> {
    open_vault_selected(
        cache,
        project,
        vec![
            ColumnFamily::Base,
            ColumnFamily::Blob,
            ColumnFamily::Graph,
            ColumnFamily::Kernel,
            ColumnFamily::Kv,
            ColumnFamily::Recurrence,
        ],
    )
}

fn open_kernel_generation_readback_vault(
    cache: &Path,
    project: &str,
) -> AnyResult<(AsterVault, PathBuf)> {
    open_vault_selected(
        cache,
        project,
        vec![
            ColumnFamily::Anchors,
            ColumnFamily::Compression,
            ColumnFamily::Graph,
            ColumnFamily::Kernel,
            ColumnFamily::Kv,
            ColumnFamily::Ledger,
            ColumnFamily::slot(astrolabe_weave::SLOT_NAME_SEMANTIC),
        ],
    )
}

fn sim_family_sort_index(family: SimilarityFamily) -> u8 {
    match family {
        SimilarityFamily::Struct => 0,
        SimilarityFamily::Semantic => 1,
        SimilarityFamily::Api => 2,
        SimilarityFamily::Profile => 3,
    }
}

fn sim_family_row_prefix(family: SimilarityFamily) -> Vec<u8> {
    let mut prefix = astrolabe_weave::SIM_EDGE_ROW_PREFIX.to_vec();
    prefix.push(sim_family_sort_index(family));
    prefix
}

fn sim_source_attestation_key(family: SimilarityFamily) -> Vec<u8> {
    let mut key = SIM_SOURCE_ATTESTATION_PREFIX.to_vec();
    key.extend_from_slice(family.wire_name().as_bytes());
    key
}

fn sim_hash_frame(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn parse_lower_hash_32(value: &str, field: &str) -> AnyResult<[u8; 32]> {
    let decoded = decode_hex(value)?;
    let hash = <[u8; 32]>::try_from(decoded.as_slice())
        .map_err(|_| format!("{field} must contain exactly 32 lowercase-hex bytes"))?;
    require(
        value == hex_lower(&hash),
        "ISSUE_1116_1119_SIM_HASH_NONCANONICAL",
        json!({"field": field, "value": value}),
    )?;
    Ok(hash)
}

fn sim_scenario_column_families() -> Vec<ColumnFamily> {
    let mut selected = vec![
        ColumnFamily::Base,
        ColumnFamily::Compression,
        ColumnFamily::Graph,
        ColumnFamily::Kernel,
        ColumnFamily::Kv,
        ColumnFamily::Ledger,
        ColumnFamily::Recurrence,
        ColumnFamily::TimeIndex,
    ];
    selected.extend(
        SimilarityFamily::ALL
            .into_iter()
            .map(|family| ColumnFamily::slot(family.slot())),
    );
    selected
}

fn sim_scenario_column_family_names() -> Vec<String> {
    sim_scenario_column_families()
        .iter()
        .map(ColumnFamily::name)
        .collect()
}

fn open_sim_scenario_vault(
    vault_path: &Path,
    vault_id: VaultId,
    vault_salt: &[u8],
    read_only: bool,
) -> AnyResult<AsterVault<FixedClock>> {
    Ok(AsterVault::open_with_clock(
        vault_path,
        vault_id,
        vault_salt.to_vec(),
        VaultOptions {
            read_only,
            restore_ledger_hook: !read_only,
            restore_mvcc_rows: false,
            selected_cfs: Some(sim_scenario_column_families()),
            writable_selected_cfs: !read_only,
            ..VaultOptions::default()
        },
        FixedClock::new(GENERATION_OBSERVED_AT_MS),
    )?)
}

fn physical_cf_point_read<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    cf: ColumnFamily,
    key: &[u8],
) -> AnyResult<(Option<Vec<u8>>, Value)>
where
    C: Clock,
{
    let reads = [OrderedCfRead::new(0, cf, key)];
    let mut visited = false;
    let mut physical_value = None::<Vec<u8>>;
    let metrics = vault.visit_ordered_cf_plan_at(
        snapshot,
        &reads,
        |ordinal, observed_cf, observed_key, value| -> AnyResult<()> {
            require(
                !visited && ordinal == 0 && observed_cf == cf && observed_key == key,
                "ISSUE_1116_1119_SIM_PHYSICAL_POINT_IDENTITY_MISMATCH",
                json!({
                    "expected_cf": cf.name(),
                    "expected_key_hex": hex_lower(key),
                    "observed_ordinal": ordinal,
                    "observed_cf": observed_cf.name(),
                    "observed_key_hex": hex_lower(observed_key),
                }),
            )?;
            visited = true;
            physical_value = value.map(ToOwned::to_owned);
            Ok(())
        },
    )?;
    let physical_bytes = physical_value.as_ref().map_or(0, Vec::len);
    require(
        visited
            && metrics.session_snapshot_seq == snapshot
            && metrics.requested_keys == 1
            && metrics.rows_read_back == 1
            && metrics.bytes_read_back == u64::try_from(physical_bytes)?
            && metrics.read_batches == 1
            && metrics.source_read_operations > 0
            && metrics.sst_files_opened == metrics.unique_sst_generations,
        "ISSUE_1116_1119_SIM_PHYSICAL_POINT_METRICS_INVALID",
        format!("{metrics:#?}"),
    )?;
    let receipt = json!({
        "snapshot_seq": metrics.session_snapshot_seq,
        "cf": cf.name(),
        "key_hex": hex_lower(key),
        "requested_keys": metrics.requested_keys,
        "rows_read_back": metrics.rows_read_back,
        "bytes_read_back": metrics.bytes_read_back,
        "read_batches": metrics.read_batches,
        "source_read_operations": metrics.source_read_operations,
        "sst_files_opened": metrics.sst_files_opened,
        "unique_sst_generations": metrics.unique_sst_generations,
        "sst_key_probes": metrics.sst_key_probes,
        "sst_exact_route_lookups": metrics.sst_exact_route_lookups,
        "sst_exact_route_hits": metrics.sst_exact_route_hits,
        "sst_fallback_file_key_checks": metrics.sst_fallback_file_key_checks,
        "value_state": physical_value.as_ref().map_or("absent", |value| {
            if value == &tombstone_value() {
                "tombstone"
            } else {
                "live"
            }
        }),
        "value_bytes": physical_bytes,
        "value_sha256": physical_value.as_ref().map(|value| sha256(value)),
    });
    Ok((physical_value, receipt))
}

fn physical_ledger_point_read<C>(
    vault: &AsterVault<C>,
    seq: u64,
    logical_bytes: &[u8],
) -> AnyResult<(Vec<u8>, Value)>
where
    C: Clock,
{
    let wanted = BTreeSet::from([seq]);
    let (rows, trace) = vault.read_physical_ledger_seqs(&wanted)?;
    let resolved = trace.tiers.iter().map(|tier| tier.resolved).sum::<usize>();
    let complete_scan_wanted = trace
        .tiers
        .iter()
        .filter(|tier| tier.tier == "complete_scan")
        .map(|tier| tier.wanted)
        .sum::<usize>();
    let row = rows
        .get(&seq)
        .ok_or("ISSUE_1116_1119_SIM_PHYSICAL_LEDGER_ROW_MISSING")?;
    require(
        rows.len() == 1
            && resolved == 1
            && complete_scan_wanted == 0
            && row.seq == seq
            && row.bytes == logical_bytes,
        "ISSUE_1116_1119_SIM_PHYSICAL_LEDGER_POINT_MISMATCH",
        json!({
            "seq": seq,
            "row_count": rows.len(),
            "resolved": resolved,
            "complete_scan_wanted": complete_scan_wanted,
            "logical_sha256": sha256(logical_bytes),
            "physical_sha256": sha256(&row.bytes),
            "trace": trace,
        }),
    )?;
    let normalized_tiers = trace
        .tiers
        .iter()
        .map(|tier| {
            json!({
                "tier": tier.tier,
                "wanted": tier.wanted,
                "resolved": tier.resolved,
                "files_opened": tier.files_opened,
            })
        })
        .collect::<Vec<_>>();
    Ok((
        row.bytes.clone(),
        json!({
            "seq": seq,
            "row_bytes": row.bytes.len(),
            "row_sha256": sha256(&row.bytes),
            "resolved": resolved,
            "complete_scan_wanted": complete_scan_wanted,
            "tiers": normalized_tiers,
            "manifest_wal_aware_exact_point_read": true,
        }),
    ))
}

fn oracle_project_key(prefix: &[u8], project: &str) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(blake3::hash(project.as_bytes()).as_bytes());
    key
}

fn oracle_gate_attestation_key(project: &str, attestation_id: &str) -> Vec<u8> {
    let mut key = oracle_project_key(ORACLE_GATE_GENERATION_PREFIX, project);
    key.extend_from_slice(attestation_id.as_bytes());
    key
}

fn is_oracle_content_key(key: &[u8]) -> bool {
    key == ORACLE_CORPUS_LAYOUT_KEY
        || key.starts_with(ORACLE_OCCURRENCE_PREFIX)
        || key.starts_with(ORACLE_PRECEDES_PREFIX)
        || key.starts_with(ORACLE_CHANGE_PREFIX)
}

/// Independent physical Oracle readback. This is fixture-scale `O(R log R)`
/// over Oracle-owned rows only plus fixed pointer/manifest/Ledger point reads;
/// it establishes no production timing claim (#1064 PC-04/07/16/38/41).
fn oracle_generation_state(cache: &Path, project: &str) -> AnyResult<Value> {
    let (vault, vault_dir) = open_kernel_generation_readback_vault(cache, project)?;
    let lease = vault.retain_latest_snapshot();
    let snapshot = lease.seq();
    let binding = read_oracle_corpus_binding_at(&vault, snapshot)?;
    let changes = read_git_change_inputs_at(&vault, snapshot)?;
    let occurrences = read_occurrence_rows_at(&vault, snapshot)?;
    let precedes = read_precedes_edges(&vault)?;
    let raw_rows = raw_oracle_rows(&vault)?;
    let propagated_labels = astrolabe_ingest::read_propagated_label_rows(&vault)?;
    require(
        raw_rows.iter().all(|(key, _)| is_oracle_content_key(key))
            && raw_rows.len()
                == changes
                    .len()
                    .checked_add(occurrences.len())
                    .and_then(|count| count.checked_add(precedes.len()))
                    .and_then(|count| count.checked_add(1))
                    .ok_or("ISSUE_1116_1119_ORACLE_ROW_COUNT_OVERFLOW")?
            && binding.schema == "astrolabe.oracle_corpus.binding.v1"
            && binding.change_count == changes.len()
            && binding.occurrence_count == occurrences.len()
            && binding.edge_count == precedes.len()
            && binding.change_count > 0
            && binding.mapped_change_event_count > 0
            && !propagated_labels.is_empty(),
        "ISSUE_1116_1119_ORACLE_CORPUS_READBACK_INVALID",
        json!({
            "binding":binding,
            "changes":changes.len(),
            "occurrences":occurrences.len(),
            "precedes":precedes.len(),
            "raw_rows":raw_rows.len(),
            "propagated_labels":propagated_labels.len(),
        }),
    )?;

    let layout_key = decode_hex(&binding.layout_key_hex)?;
    let (layout_bytes, physical_layout) =
        physical_cf_point_read(&vault, snapshot, ColumnFamily::Kv, &layout_key)?;
    let layout_bytes = layout_bytes.ok_or("ISSUE_1116_1119_ORACLE_LAYOUT_ABSENT")?;
    let layout: Value = serde_json::from_slice(&layout_bytes)?;
    require(
        layout_key == ORACLE_CORPUS_LAYOUT_KEY
            && layout["schema"] == ORACLE_CORPUS_LAYOUT_SCHEMA
            && serde_json::to_vec(&layout)? == layout_bytes
            && binding.layout_bytes == u64::try_from(layout_bytes.len())?
            && binding.layout_blake3 == blake3::hash(&layout_bytes).to_hex().to_string()
            && layout["change_count"] == binding.change_count
            && layout["mapped_change_event_count"] == binding.mapped_change_event_count
            && layout["occurrence_count"] == binding.occurrence_count
            && layout["edge_count"] == binding.edge_count
            && layout["content_rows_hash"] == binding.content_rows_hash
            && layout["corpus_dump_hash"] == binding.corpus_dump_hash,
        "ISSUE_1116_1119_ORACLE_LAYOUT_MISMATCH",
        json!({"binding":binding,"layout":layout}),
    )?;

    let raw_row_receipts = raw_rows
        .iter()
        .map(|(key, value)| {
            json!({
                "key_hex":hex_lower(key),
                "value_bytes":value.len(),
                "value_sha256":sha256(value),
            })
        })
        .collect::<Vec<_>>();
    let raw_rows_hash = sha256(&serde_json::to_vec(&raw_row_receipts)?);

    let ledger_rows = vault.scan_cf_at(snapshot, ColumnFamily::Ledger)?;
    let mut corpus_ledger = Vec::new();
    for (key, bytes) in &ledger_rows {
        let entry = decode_ledger(bytes)?;
        let payload = serde_json::from_slice::<Value>(&entry.payload).ok();
        if matches!(&entry.actor, ActorId::Service(actor) if actor == ORACLE_CORPUS_ACTOR)
            && payload
                .as_ref()
                .is_some_and(|value| value["schema"] == ORACLE_CORPUS_LEDGER_SCHEMA)
            && payload
                .as_ref()
                .is_some_and(|value| value["corpus_dump_hash"] == binding.corpus_dump_hash)
        {
            corpus_ledger.push((key, bytes, entry, payload.expect("payload checked")));
        }
    }
    let [(corpus_ledger_key, corpus_ledger_bytes, corpus_entry, corpus_payload)] =
        corpus_ledger.as_slice()
    else {
        return Err(format!(
            "ISSUE_1116_1119_ORACLE_CORPUS_LEDGER_CARDINALITY: expected one current corpus Ledger row, observed {}",
            corpus_ledger.len()
        )
        .into());
    };
    require(
        corpus_entry.verify()
            && corpus_ledger_key.as_slice() == ledger_key(corpus_entry.seq)
            && corpus_entry.kind == EntryKind::Score
            && matches!(&corpus_entry.subject, SubjectId::Query(subject) if subject == format!("astrolabe-oracle-corpus:{}", binding.corpus_dump_hash).as_bytes())
            && corpus_payload["schema"] == ORACLE_CORPUS_LEDGER_SCHEMA
            && corpus_payload["change_count"] == binding.change_count
            && corpus_payload["mapped_change_event_count"] == binding.mapped_change_event_count
            && corpus_payload["occurrence_count"] == binding.occurrence_count
            && corpus_payload["edge_count"] == binding.edge_count
            && corpus_payload["content_rows_hash"] == binding.content_rows_hash
            && corpus_payload["source_binding"] == json!(binding.source_binding)
            && serde_json::to_vec(corpus_payload)? == corpus_entry.payload,
        "ISSUE_1116_1119_ORACLE_CORPUS_LEDGER_MISMATCH",
        corpus_payload,
    )?;
    let (physical_corpus_ledger_bytes, physical_corpus_ledger) =
        physical_ledger_point_read(&vault, corpus_entry.seq, corpus_ledger_bytes)?;

    let pointer_key = oracle_project_key(ORACLE_GATE_CURRENT_PREFIX, project);
    let (pointer_bytes, physical_pointer) =
        physical_cf_point_read(&vault, snapshot, ColumnFamily::Kernel, &pointer_key)?;
    let pointer_bytes = pointer_bytes.ok_or("ISSUE_1116_1119_ORACLE_GATE_POINTER_ABSENT")?;
    let pointer: Value = serde_json::from_slice(&pointer_bytes)?;
    let attestation_id = pointer["current"]["attestation_id"]
        .as_str()
        .filter(|value| value.len() == 64)
        .ok_or("ISSUE_1116_1119_ORACLE_GATE_ATTESTATION_ID_INVALID")?;
    let attestation_key = oracle_gate_attestation_key(project, attestation_id);
    let (attestation_bytes, physical_attestation) =
        physical_cf_point_read(&vault, snapshot, ColumnFamily::Kernel, &attestation_key)?;
    let attestation_bytes =
        attestation_bytes.ok_or("ISSUE_1116_1119_ORACLE_GATE_ATTESTATION_ABSENT")?;
    let attestation: Value = serde_json::from_slice(&attestation_bytes)?;
    let body = &attestation["body"];
    let body_bytes = serde_json::to_vec(body)?;
    let expected_attestation_id = hex_lower(&full_content_hash([
        b"astrolabe.oracle-gate-body.v1".as_slice(),
        body_bytes.as_slice(),
    ]));
    let gate_ledger_ref: LedgerRef = serde_json::from_value(attestation["ledger_ref"].clone())?;
    require(
        pointer["schema"] == ORACLE_GATE_POINTER_SCHEMA
            && pointer["project"] == project
            && serde_json::to_vec(&pointer)? == pointer_bytes
            && pointer["current"]["attestation_key_hex"] == hex_lower(&attestation_key)
            && pointer["current"]["attestation_blake3"]
                == blake3::hash(&attestation_bytes).to_hex().to_string()
            && pointer["current"]["commit_seq"] == gate_ledger_ref.seq
            && pointer["current"]["ledger_ref"] == attestation["ledger_ref"]
            && attestation["schema"] == ORACLE_GATE_ATTESTATION_SCHEMA
            && attestation["attestation_id"] == expected_attestation_id
            && attestation_id == expected_attestation_id
            && serde_json::to_vec(&attestation)? == attestation_bytes
            && body["schema"] == ORACLE_GATE_ATTESTATION_SCHEMA
            && body["project"] == project
            && body["corpus"] == json!(binding),
        "ISSUE_1116_1119_ORACLE_GATE_ROW_MISMATCH",
        json!({"pointer":pointer,"attestation":attestation}),
    )?;

    let gate_ledger_bytes = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Ledger,
            &ledger_key(gate_ledger_ref.seq),
        )?
        .ok_or("ISSUE_1116_1119_ORACLE_GATE_LEDGER_ABSENT")?;
    let gate_entry = decode_ledger(&gate_ledger_bytes)?;
    let gate_payload: Value = serde_json::from_slice(&gate_entry.payload)?;
    require(
        gate_entry.verify()
            && gate_entry.seq == gate_ledger_ref.seq
            && gate_entry.entry_hash == gate_ledger_ref.hash
            && gate_entry.kind == EntryKind::Score
            && matches!(&gate_entry.actor, ActorId::Service(actor) if actor == ORACLE_GATE_ACTOR)
            && matches!(&gate_entry.subject, SubjectId::Query(subject) if subject == format!("astrolabe-oracle-gate:{project}:{attestation_id}").as_bytes())
            && gate_payload["schema"] == ORACLE_GATE_LEDGER_SCHEMA
            && gate_payload["project"] == project
            && gate_payload["attestation_id"] == attestation_id
            && gate_payload["body_blake3"] == blake3::hash(&body_bytes).to_hex().to_string()
            && gate_payload["admitted"] == body["admitted"]
            && gate_payload["refusal_code"] == body["refusal_code"]
            && serde_json::to_vec(&gate_payload)? == gate_entry.payload,
        "ISSUE_1116_1119_ORACLE_GATE_LEDGER_MISMATCH",
        gate_payload,
    )?;
    let (physical_gate_ledger_bytes, physical_gate_ledger) =
        physical_ledger_point_read(&vault, gate_entry.seq, &gate_ledger_bytes)?;

    let scope_id = format!("repo:{project}");
    let kernel =
        astrolabe_weave::read_current_kernel_generation_header(&vault, project, &scope_id)?
            .ok_or("ISSUE_1116_1119_ORACLE_CURRENT_KERNEL_ABSENT")?;
    let manifest_bytes = serde_json::to_vec(&kernel.manifest)?;
    let graph_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let anchors_generation = vault.cf_content_generation(ColumnFamily::Anchors)?;
    let kv_generation = vault.cf_content_generation(ColumnFamily::Kv)?;
    require(
        body["kernel"]["generation_id"] == kernel.manifest.generation_id
            && body["kernel"]["source_generation_identity"]
                == kernel.manifest.source_generation_identity
            && body["kernel"]["manifest_key_hex"] == kernel.pointer.current.manifest_key_hex
            && body["kernel"]["manifest_blake3"]
                == blake3::hash(&manifest_bytes).to_hex().to_string()
            && body["kernel"]["commit_seq"] == kernel.pointer.current.commit_seq
            && body["kernel"]["source_binding"] == json!(kernel.manifest.generation_source_binding)
            && body["graph_content_generation"] == graph_generation
            && body["anchors_content_generation"] == anchors_generation
            && body["corpus"]["source_binding"]["graph_content_generation"] == graph_generation
            && body["corpus"]["source_binding"]["anchors_content_generation"] == anchors_generation
            && body["kernel"]["source_binding"]["graph_content_generation"] == graph_generation
            && body["kernel"]["source_binding"]["anchors_content_generation"] == anchors_generation
            && body["kernel"]["source_binding"]["anchor_metadata_content_generation"]
                == kv_generation,
        "ISSUE_1116_1119_ORACLE_POST_LABEL_KERNEL_IDENTITY_MISMATCH",
        json!({
            "body":body,
            "kernel_manifest":kernel.manifest,
            "kernel_pointer":kernel.pointer,
            "graph_generation":graph_generation,
            "anchors_generation":anchors_generation,
            "kv_generation":kv_generation,
        }),
    )?;
    let admitted = body["admitted"]
        .as_bool()
        .ok_or("ISSUE_1116_1119_ORACLE_GATE_ADMISSION_INVALID")?;
    let refusal_code = body["refusal_code"]
        .as_str()
        .ok_or("ISSUE_1116_1119_ORACLE_GATE_REFUSAL_CODE_MISSING")?;
    let cases = body["backtest"]["cases"]
        .as_u64()
        .ok_or("ISSUE_1116_1119_ORACLE_BACKTEST_CASE_COUNT_MISSING")?;
    require(
        !admitted
            && matches!(refusal_code, ORACLE_FAILED_ADMISSION | ORACLE_NOT_BEATEN)
            && ((cases == 0 && refusal_code == ORACLE_FAILED_ADMISSION)
                || (cases > 0 && refusal_code == ORACLE_NOT_BEATEN)),
        "ISSUE_1116_1119_ORACLE_GATE_EXPECTED_HONEST_REFUSAL_MISSING",
        body["backtest"].clone(),
    )?;
    lease.record_progress();
    require(
        vault.latest_seq() == snapshot
            && physical_corpus_ledger_bytes == *corpus_ledger_bytes
            && physical_gate_ledger_bytes == gate_ledger_bytes,
        "ISSUE_1116_1119_ORACLE_READ_EPOCH_MOVED",
        json!({"snapshot":snapshot,"latest":vault.latest_seq()}),
    )?;
    Ok(json!({
        "schema":"astrolabe.issue-1116-1119.oracle-generation-state.v1",
        "vault_dir":vault_dir,
        "snapshot_seq":snapshot,
        "corpus":{
            "binding":binding,
            "layout":layout,
            "layout_physical":physical_layout,
            "change_count":changes.len(),
            "changes":changes,
            "occurrence_count":occurrences.len(),
            "occurrence_rows_sha256":sha256(&serde_json::to_vec(&occurrences.iter().map(|row| (&row.key,&row.row)).collect::<Vec<_>>())?),
            "precedes_count":precedes.len(),
            "precedes_rows_sha256":sha256(&serde_json::to_vec(&precedes.iter().map(|row| (&row.key,&row.row)).collect::<Vec<_>>())?),
            "raw_owned_row_count":raw_rows.len(),
            "raw_owned_rows_sha256":raw_rows_hash,
            "raw_owned_rows":raw_row_receipts,
            "ledger":{
                "seq":corpus_entry.seq,
                "entry_hash":hex_lower(&corpus_entry.entry_hash),
                "payload":corpus_payload,
                "physical":physical_corpus_ledger,
            },
        },
        "post_label_kernel":{
            "scope_id":scope_id,
            "generation_id":kernel.manifest.generation_id,
            "source_generation_identity":kernel.manifest.source_generation_identity,
            "manifest_key_hex":kernel.pointer.current.manifest_key_hex,
            "manifest_blake3":blake3::hash(&manifest_bytes).to_hex().to_string(),
            "commit_seq":kernel.pointer.current.commit_seq,
            "source_binding":kernel.manifest.generation_source_binding,
            "propagated_label_row_count":propagated_labels.len(),
            "propagated_label_rows_sha256":sha256(&serde_json::to_vec(&propagated_labels.iter().map(|row| (&row.key,&row.row)).collect::<Vec<_>>())?),
            "current_graph_content_generation":graph_generation,
            "current_anchors_content_generation":anchors_generation,
            "current_kv_content_generation":kv_generation,
            "gate_identity_equal":true,
        },
        "gate":{
            "pointer_key_hex":hex_lower(&pointer_key),
            "pointer":pointer,
            "pointer_physical":physical_pointer,
            "attestation_key_hex":hex_lower(&attestation_key),
            "attestation":attestation,
            "attestation_physical":physical_attestation,
            "ledger":{
                "seq":gate_entry.seq,
                "entry_hash":hex_lower(&gate_entry.entry_hash),
                "payload":gate_payload,
                "physical":physical_gate_ledger,
            },
            "admitted":admitted,
            "refusal_code":refusal_code,
            "case_count":cases,
        },
        "cost_boundary":{
            "operation":"manual Full State Verification only",
            "fixture":"Oracle-owned Kv roster scan, propagated-label Kernel prefix scan, Ledger FSV scan plus fixed gate/kernel point reads",
            "production_n":192873,
            "production_e":328899,
            "production_r":"reported by raw_owned_row_count; fixture is not production cost evidence",
            "defect_classes":["PC-04","PC-07","PC-16","PC-38","PC-41","PC-43"],
            "invariant":"one retained snapshot and one exact corpus/projection/post-label-kernel/gate identity",
        },
        "physical_marker_rows_kernel_and_both_ledger_entries_read_back":true,
        "no_synthetic_ci_or_gate_evidence":true,
    }))
}

fn physical_sim_graph_surface<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    raw_rows: &[(Vec<u8>, Vec<u8>)],
    raw_markers: &[(Vec<u8>, Vec<u8>)],
) -> AnyResult<Value>
where
    C: Clock,
{
    let mut logical = BTreeMap::<Vec<u8>, Option<Vec<u8>>>::new();
    for (key, value) in raw_rows.iter().chain(raw_markers) {
        require(
            logical.insert(key.clone(), Some(value.clone())).is_none(),
            "ISSUE_1116_1119_SIM_PHYSICAL_GRAPH_PLAN_DUPLICATE",
            hex_lower(key),
        )?;
    }
    for family in SimilarityFamily::ALL {
        let key = sim_source_attestation_key(family);
        let value = vault.read_cf_at(snapshot, ColumnFamily::Graph, &key)?;
        if let Some(scanned) = logical.insert(key.clone(), value.clone()) {
            require(
                scanned == value,
                "ISSUE_1116_1119_SIM_MARKER_SCAN_POINT_MISMATCH",
                family.wire_name(),
            )?;
        }
    }
    let cas_value = vault.read_cf_at(snapshot, ColumnFamily::Graph, SIM_CAS_RACE_KEY)?;
    require(
        logical
            .insert(SIM_CAS_RACE_KEY.to_vec(), cas_value)
            .is_none(),
        "ISSUE_1116_1119_SIM_CAS_KEY_COLLISION",
        hex_lower(SIM_CAS_RACE_KEY),
    )?;
    let keys = logical.keys().cloned().collect::<Vec<_>>();
    let reads = keys
        .iter()
        .enumerate()
        .map(|(ordinal, key)| OrderedCfRead::new(ordinal, ColumnFamily::Graph, key))
        .collect::<Vec<_>>();
    let mut observed = vec![None::<Vec<u8>>; reads.len()];
    let mut seen = vec![false; reads.len()];
    let metrics = vault.visit_ordered_cf_plan_at(
        snapshot,
        &reads,
        |ordinal, cf, key, value| -> AnyResult<()> {
            require(
                ordinal < keys.len()
                    && !seen[ordinal]
                    && cf == ColumnFamily::Graph
                    && key == keys[ordinal],
                "ISSUE_1116_1119_SIM_PHYSICAL_GRAPH_IDENTITY_MISMATCH",
                json!({
                    "ordinal": ordinal,
                    "cf": cf.name(),
                    "key_hex": hex_lower(key),
                }),
            )?;
            seen[ordinal] = true;
            observed[ordinal] = value.map(ToOwned::to_owned);
            Ok(())
        },
    )?;
    require(
        seen.iter().all(|value| *value)
            && metrics.session_snapshot_seq == snapshot
            && metrics.requested_keys == u64::try_from(keys.len())?
            && metrics.rows_read_back == u64::try_from(keys.len())?
            && metrics.read_batches == 1
            && metrics.source_read_operations > 0
            && metrics.sst_files_opened == metrics.unique_sst_generations,
        "ISSUE_1116_1119_SIM_PHYSICAL_GRAPH_METRICS_INVALID",
        format!("{metrics:#?}"),
    )?;
    let mut rows = Vec::with_capacity(keys.len());
    let tombstone = tombstone_value();
    let mut physical_bytes = 0_u64;
    for (ordinal, key) in keys.iter().enumerate() {
        let expected = logical
            .get(key)
            .ok_or("ISSUE_1116_1119_SIM_PHYSICAL_GRAPH_EXPECTATION_MISSING")?;
        let physical = &observed[ordinal];
        require(
            expected
                .as_ref()
                .is_some_and(|value| physical.as_ref() == Some(value))
                || (expected.is_none()
                    && physical
                        .as_deref()
                        .is_none_or(|value| value == tombstone.as_slice())),
            "ISSUE_1116_1119_SIM_PHYSICAL_GRAPH_VALUE_MISMATCH",
            json!({
                "key_hex": hex_lower(key),
                "logical_sha256": expected.as_ref().map(|value| sha256(value)),
                "physical_sha256": physical.as_ref().map(|value| sha256(value)),
            }),
        )?;
        physical_bytes = physical_bytes
            .checked_add(u64::try_from(physical.as_ref().map_or(0, Vec::len))?)
            .ok_or("ISSUE_1116_1119_SIM_PHYSICAL_GRAPH_BYTE_COUNT_OVERFLOW")?;
        rows.push(json!({
            "key_hex": hex_lower(key),
            "logical_state": if expected.is_some() { "live" } else { "absent" },
            "physical_state": physical.as_ref().map_or("absent", |value| {
                if value == &tombstone { "tombstone" } else { "live" }
            }),
            "physical_value_bytes": physical.as_ref().map_or(0, Vec::len),
            "physical_value_sha256": physical.as_ref().map(|value| sha256(value)),
        }));
    }
    require(
        metrics.bytes_read_back == physical_bytes,
        "ISSUE_1116_1119_SIM_PHYSICAL_GRAPH_BYTE_METRICS_MISMATCH",
        json!({"metrics": metrics.bytes_read_back, "recomputed": physical_bytes}),
    )?;
    Ok(json!({
        "snapshot_seq": snapshot,
        "cf": "graph",
        "rows": rows,
        "requested_keys": metrics.requested_keys,
        "rows_read_back": metrics.rows_read_back,
        "bytes_read_back": metrics.bytes_read_back,
        "read_batches": metrics.read_batches,
        "source_read_operations": metrics.source_read_operations,
        "sst_files_opened": metrics.sst_files_opened,
        "unique_sst_generations": metrics.unique_sst_generations,
        "sst_key_probes": metrics.sst_key_probes,
        "sst_exact_route_lookups": metrics.sst_exact_route_lookups,
        "sst_exact_route_hits": metrics.sst_exact_route_hits,
        "sst_fallback_file_key_checks": metrics.sst_fallback_file_key_checks,
        "exact_sim_rows_four_markers_and_cas_key_physically_point_read": true,
    }))
}

fn raw_sim_terminal_surface<C>(vault: &AsterVault<C>) -> AnyResult<Value>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let graph_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let ledger_generation = vault.cf_content_generation(ColumnFamily::Ledger)?;
    let kernel_generation = vault.cf_content_generation(ColumnFamily::Kernel)?;
    let raw_rows = vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(astrolabe_weave::SIM_EDGE_ROW_PREFIX),
    )?;
    let raw_markers = vault.scan_cf_range_at(
        snapshot,
        ColumnFamily::Graph,
        &prefix_range(SIM_SOURCE_ATTESTATION_PREFIX),
    )?;
    let physical_graph = physical_sim_graph_surface(vault, snapshot, &raw_rows, &raw_markers)?;
    let rows = raw_rows
        .iter()
        .map(|(key, value)| {
            json!({
                "key_hex": hex_lower(key),
                "value_bytes": value.len(),
                "value_sha256": sha256(value),
                "value_blake3": blake3::hash(value).to_hex().to_string(),
            })
        })
        .collect::<Vec<_>>();
    let markers = raw_markers
        .iter()
        .map(|(key, value)| {
            json!({
                "key_hex": hex_lower(key),
                "value_bytes": value.len(),
                "value_sha256": sha256(value),
                "value_blake3": blake3::hash(value).to_hex().to_string(),
                "value_hex": hex_lower(value),
            })
        })
        .collect::<Vec<_>>();
    let ledger_key_bytes = ledger_key(snapshot);
    let ledger_bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Ledger, &ledger_key_bytes)?
        .ok_or("ISSUE_1116_1119_SIM_LATEST_LEDGER_ROW_MISSING")?;
    let ledger_entry = decode_ledger(&ledger_bytes)?;
    let (physical_ledger_bytes, physical_ledger) =
        physical_ledger_point_read(vault, snapshot, &ledger_bytes)?;
    require(
        ledger_entry.verify()
            && ledger_entry.seq == snapshot
            && physical_ledger_bytes == ledger_bytes,
        "ISSUE_1116_1119_SIM_LATEST_LEDGER_SEQUENCE_MISMATCH",
        json!({"snapshot": snapshot, "entry_seq": ledger_entry.seq}),
    )?;
    Ok(json!({
        "schema": "astrolabe.issue-1116-1119.sim-raw-terminal-surface.v1",
        "snapshot_seq": snapshot,
        "graph_cf_generation": graph_generation,
        "ledger_cf_generation": ledger_generation,
        "kernel_cf_generation": kernel_generation,
        "sim_rows": rows,
        "sim_rows_count": rows.len(),
        "sim_rows_sha256": sha256(&serde_json::to_vec(&rows)?),
        "markers": markers,
        "marker_count": markers.len(),
        "markers_sha256": sha256(&serde_json::to_vec(&markers)?),
        "physical_graph": physical_graph,
        "latest_ledger": {
            "key_hex": hex_lower(&ledger_key_bytes),
            "value_bytes": ledger_bytes.len(),
            "value_sha256": sha256(&ledger_bytes),
            "seq": ledger_entry.seq,
            "entry_hash": hex_lower(&ledger_entry.entry_hash),
            "kind": ledger_entry.kind,
            "subject": ledger_entry.subject,
            "actor": ledger_entry.actor,
            "payload_bytes": ledger_entry.payload.len(),
            "payload_sha256": sha256(&ledger_entry.payload),
            "physical_point_read": physical_ledger,
        },
        "narrow_exact_cfs": sim_scenario_column_family_names(),
        "mvcc_rows_restored": false,
    }))
}

fn physical_sim_graph_row(surface: &Value, key: &[u8]) -> AnyResult<Value> {
    let key_hex = hex_lower(key);
    surface["physical_graph"]["rows"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["key_hex"].as_str() == Some(key_hex.as_str()))
        })
        .cloned()
        .ok_or_else(|| {
            format!("ISSUE_1116_1119_SIM_PHYSICAL_GRAPH_ROW_MISSING: key={key_hex}").into()
        })
}

fn read_sim_terminal_attestations<C>(
    vault: &AsterVault<C>,
    project: &str,
    require_projection: bool,
) -> AnyResult<FsvSimTerminalState>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let graph_generation = vault.cf_content_generation(ColumnFamily::Graph)?;
    let ledger_generation = vault.cf_content_generation(ColumnFamily::Ledger)?;
    let kernel_generation = vault.cf_content_generation(ColumnFamily::Kernel)?;
    let mut families = BTreeMap::new();
    let mut family_receipts = Vec::new();
    for family in SimilarityFamily::ALL {
        let prefix = sim_family_row_prefix(family);
        let raw_rows =
            vault.scan_cf_range_at(snapshot, ColumnFamily::Graph, &prefix_range(&prefix))?;
        let mut hasher = blake3::Hasher::new();
        sim_hash_frame(&mut hasher, SIM_FAMILY_DUMP_SCHEMA);
        let mut total_bytes = 0_u64;
        let mut previous_key = None::<Vec<u8>>;
        let mut rows = Vec::with_capacity(raw_rows.len());
        let mut row_receipts = Vec::with_capacity(raw_rows.len());
        for (key, value) in raw_rows {
            require(
                previous_key
                    .as_deref()
                    .is_none_or(|previous| previous < key.as_slice()),
                "ISSUE_1116_1119_SIM_FAMILY_ROWS_NOT_SORTED",
                json!({"family": family.wire_name(), "key_hex": hex_lower(&key)}),
            )?;
            previous_key = Some(key.clone());
            let row: astrolabe_weave::SimEdgeGraphRow = serde_json::from_slice(&value)?;
            require(
                row.schema == astrolabe_weave::SCHEMA_SIM_EDGE_ROW
                    && row.family == family.wire_name()
                    && row.similarity_family() == Some(family)
                    && row.slot == family.slot().get()
                    && row.etype == family.graph_edge_kind().code()
                    && row.metric == "cosine"
                    && row.weight().is_finite()
                    && (0.0..=1.0).contains(&row.weight())
                    && row.threshold().is_finite()
                    && (0.0..=1.0).contains(&row.threshold())
                    && key
                        == astrolabe_weave::sim_edge_graph_key(
                            family,
                            &row.source_id,
                            &row.target_id,
                        ),
                "ISSUE_1116_1119_SIM_FAMILY_ROW_INVALID",
                json!({
                    "family": family.wire_name(),
                    "key_hex": hex_lower(&key),
                    "row": row,
                }),
            )?;
            sim_hash_frame(&mut hasher, &key);
            sim_hash_frame(&mut hasher, &value);
            let key_bytes = u64::try_from(key.len())?;
            let value_bytes = u64::try_from(value.len())?;
            total_bytes = total_bytes
                .checked_add(key_bytes)
                .and_then(|total| total.checked_add(value_bytes))
                .ok_or("ISSUE_1116_1119_SIM_FAMILY_BYTE_COUNT_OVERFLOW")?;
            row_receipts.push(json!({
                "key_hex": hex_lower(&key),
                "value_bytes": value.len(),
                "value_sha256": sha256(&value),
                "source_atom_id": row.source_id,
                "target_atom_id": row.target_id,
                "etype": row.etype,
                "weight_bits": row.weight_bits,
            }));
            rows.push((key, value, row));
        }
        let row_count = u64::try_from(rows.len())?;
        let content_blake3 = hasher.finalize().to_hex().to_string();
        let marker_key = sim_source_attestation_key(family);
        let logical_marker_bytes = vault
            .read_cf_at(snapshot, ColumnFamily::Graph, &marker_key)?
            .ok_or_else(|| {
                format!(
                    "ISSUE_1116_1119_SIM_TERMINAL_MARKER_MISSING: {}",
                    family.wire_name()
                )
            })?;
        let (physical_marker_bytes, physical_marker) =
            physical_cf_point_read(vault, snapshot, ColumnFamily::Graph, &marker_key)?;
        let marker_bytes = physical_marker_bytes.ok_or_else(|| {
            format!(
                "ISSUE_1116_1119_SIM_TERMINAL_MARKER_PHYSICALLY_MISSING: {}",
                family.wire_name()
            )
        })?;
        require(
            marker_bytes == logical_marker_bytes,
            "ISSUE_1116_1119_SIM_TERMINAL_MARKER_LOGICAL_PHYSICAL_MISMATCH",
            json!({
                "family": family.wire_name(),
                "logical_sha256": sha256(&logical_marker_bytes),
                "physical_sha256": sha256(&marker_bytes),
            }),
        )?;
        let marker: FsvSimSourceAttestation = serde_json::from_slice(&marker_bytes)?;
        let canonical_marker_bytes = serde_json::to_vec(&marker)?;
        let marker_hash = parse_lower_hash_32(&marker.ledger_hash, "marker.ledger_hash")?;
        let marker_content_hash =
            parse_lower_hash_32(&marker.content_blake3, "marker.content_blake3")?;
        require(
            canonical_marker_bytes == marker_bytes
                && marker.schema == SIM_SOURCE_ATTESTATION_SCHEMA
                && marker.family == family.wire_name()
                && marker.row_count == row_count
                && marker.total_bytes == total_bytes
                && marker.content_blake3 == content_blake3
                && hex_lower(&marker_content_hash) == marker.content_blake3
                && marker.ledger_seq > 0
                && !marker.actor.trim().is_empty(),
            "ISSUE_1116_1119_SIM_TERMINAL_MARKER_MISMATCH",
            json!({
                "family": family.wire_name(),
                "marker": marker,
                "observed": {
                    "row_count": row_count,
                    "total_bytes": total_bytes,
                    "content_blake3": content_blake3,
                },
            }),
        )?;
        let ledger_key_bytes = ledger_key(marker.ledger_seq);
        let ledger_bytes = vault
            .read_cf_at(snapshot, ColumnFamily::Ledger, &ledger_key_bytes)?
            .ok_or_else(|| {
                format!(
                    "ISSUE_1116_1119_SIM_TERMINAL_LEDGER_MISSING: family={} seq={}",
                    family.wire_name(),
                    marker.ledger_seq
                )
            })?;
        let (physical_ledger_bytes, physical_ledger) =
            physical_ledger_point_read(vault, marker.ledger_seq, &ledger_bytes)?;
        let entry = decode_ledger(&ledger_bytes)?;
        let payload: FsvSimSourceAttestationLedgerPayload = serde_json::from_slice(&entry.payload)?;
        let expected_payload = FsvSimSourceAttestationLedgerPayload {
            schema: SIM_SOURCE_ATTESTATION_LEDGER_SCHEMA.to_string(),
            family: family.wire_name().to_string(),
            row_count,
            total_bytes,
            content_blake3: content_blake3.clone(),
        };
        let expected_subject = SubjectId::Query(
            format!(
                "{SIM_SOURCE_ATTESTATION_SUBJECT_PREFIX}:{}:{row_count}:{total_bytes}:{content_blake3}",
                family.wire_name()
            )
            .into_bytes(),
        );
        require(
            entry.verify()
                && physical_ledger_bytes == ledger_bytes
                && entry.seq == marker.ledger_seq
                && entry.entry_hash == marker_hash
                && payload == expected_payload
                && entry.payload == serde_json::to_vec(&expected_payload)?
                && entry.kind == EntryKind::Ingest
                && entry.subject == expected_subject
                && entry.actor == ActorId::Service(marker.actor.clone()),
            "ISSUE_1116_1119_SIM_TERMINAL_LEDGER_MISMATCH",
            json!({
                "family": family.wire_name(),
                "marker": marker,
                "ledger_key_hex": hex_lower(&ledger_key_bytes),
                "ledger_entry_seq": entry.seq,
                "ledger_entry_hash": hex_lower(&entry.entry_hash),
                "ledger_payload": payload,
            }),
        )?;
        let ledger_ref = LedgerRef {
            seq: entry.seq,
            hash: entry.entry_hash,
        };
        family_receipts.push(json!({
            "family": family.wire_name(),
            "family_sort_index": sim_family_sort_index(family),
            "row_count": row_count,
            "total_key_value_bytes": total_bytes,
            "content_blake3": content_blake3,
            "rows": row_receipts,
            "marker": {
                "key_hex": hex_lower(&marker_key),
                "value_bytes": marker_bytes.len(),
                "value_sha256": sha256(&marker_bytes),
                "decoded": marker,
                "canonical_bytes_equal": true,
                "physical_point_read": physical_marker,
            },
            "ledger": {
                "key_hex": hex_lower(&ledger_key_bytes),
                "value_bytes": ledger_bytes.len(),
                "value_sha256": sha256(&ledger_bytes),
                "seq": entry.seq,
                "entry_hash": hex_lower(&entry.entry_hash),
                "payload_sha256": sha256(&entry.payload),
                "exact_kind_subject_payload_actor_ref": true,
                "physical_point_read": physical_ledger,
            },
            "sorted_raw_key_value_blake3_recomputed": true,
            "physical_marker_and_ledger_point_reads": true,
        }));
        require(
            families
                .insert(
                    family,
                    FsvSimFamilyState {
                        marker_key,
                        marker_bytes,
                        marker,
                        ledger_ref,
                        rows,
                    },
                )
                .is_none(),
            "ISSUE_1116_1119_SIM_FAMILY_DUPLICATE",
            family.wire_name(),
        )?;
    }
    require(
        families.len() == SimilarityFamily::ALL.len(),
        "ISSUE_1116_1119_SIM_FAMILY_ROSTER_INCOMPLETE",
        families.len(),
    )?;
    let projection = if require_projection {
        sim_projection_family_refs(vault, snapshot, project, &families)?
    } else {
        Value::Null
    };
    require(
        vault.latest_seq() == snapshot
            && vault.cf_content_generation(ColumnFamily::Graph)? == graph_generation
            && vault.cf_content_generation(ColumnFamily::Ledger)? == ledger_generation
            && vault.cf_content_generation(ColumnFamily::Kernel)? == kernel_generation,
        "ISSUE_1116_1119_SIM_TERMINAL_READ_EPOCH_MOVED",
        json!({
            "expected_snapshot": snapshot,
            "observed_snapshot": vault.latest_seq(),
            "expected_graph_generation": graph_generation,
            "observed_graph_generation": vault.cf_content_generation(ColumnFamily::Graph)?,
            "expected_ledger_generation": ledger_generation,
            "observed_ledger_generation": vault.cf_content_generation(ColumnFamily::Ledger)?,
            "expected_kernel_generation": kernel_generation,
            "observed_kernel_generation": vault.cf_content_generation(ColumnFamily::Kernel)?,
        }),
    )?;
    Ok(FsvSimTerminalState {
        receipt: json!({
            "schema": "astrolabe.issue-1116-1119.sim-terminal-attestation-state.v1",
            "read_snapshot_seq": snapshot,
            "graph_cf_generation": graph_generation,
            "ledger_cf_generation": ledger_generation,
            "kernel_cf_generation": kernel_generation,
            "families": family_receipts,
            "projection": projection,
            "family_count": families.len(),
            "cost_boundary": {
                "operation": "manual Full State Verification only",
                "fixture_scan": "one independent O(E_f) digest pass plus the named production CSR/deep-verification passes at O(N+E), four ordered physical marker point reads, and four manifest/WAL-aware physical Ledger point reads",
                "production_n": 192873,
                "production_e": 328899,
                "production_measurement_date": "2026-08-08",
                "fixture_is_not_cost_evidence": true,
                "defect_classes": ["PC-04", "PC-16", "PC-24", "PC-37", "PC-38", "PC-41", "PC-J4"],
                "invariant": "one retained snapshot, fixed four-family roster, exact raw key/value bytes and marker/Ledger identity",
            },
            "narrow_exact_cfs": sim_scenario_column_family_names(),
            "mvcc_rows_restored": false,
        }),
        families,
    })
}

fn sim_projection_family_refs<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    project: &str,
    families: &BTreeMap<SimilarityFamily, FsvSimFamilyState>,
) -> AnyResult<Value>
where
    C: Clock,
{
    let compact = astrolabe_ingest::read_cbm_compact_graph_snapshot(vault, project)?;
    require(
        compact.receipt.snapshot_seq == snapshot,
        "ISSUE_1116_1119_SIM_PROJECTION_COMPACT_SNAPSHOT_MISMATCH",
        json!({"expected": snapshot, "observed": compact.receipt.snapshot_seq}),
    )?;
    let atom_cx_ids = compact
        .nodes
        .iter()
        .map(|node| (node.atom_id.clone(), node.cx_id))
        .collect::<BTreeMap<_, _>>();
    require(
        atom_cx_ids.len() == compact.nodes.len(),
        "ISSUE_1116_1119_SIM_PROJECTION_ATOM_MAP_AMBIGUOUS",
        compact.nodes.len(),
    )?;
    let projection = astrolabe_ingest::read_graph_projection_csr_at(
        vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        snapshot,
    )?
    .ok_or("ISSUE_1116_1119_SIM_KERNEL_PROJECTION_MISSING")?;
    let deep = astrolabe_ingest::verify_composite_kernel_projection(vault)?;
    let mut groups = BTreeMap::<(CxId, CxId, u16), Vec<FsvSimProjectionContributor>>::new();
    let mut source_rows = 0usize;
    for (family, state) in families {
        for (key, _, row) in &state.rows {
            let src = *atom_cx_ids.get(&row.source_id).ok_or_else(|| {
                format!(
                    "ISSUE_1116_1119_SIM_PROJECTION_SOURCE_UNRESOLVED: family={} atom={:?}",
                    family.wire_name(),
                    row.source_id
                )
            })?;
            let dst = *atom_cx_ids.get(&row.target_id).ok_or_else(|| {
                format!(
                    "ISSUE_1116_1119_SIM_PROJECTION_TARGET_UNRESOLVED: family={} atom={:?}",
                    family.wire_name(),
                    row.target_id
                )
            })?;
            groups
                .entry((src, dst, row.etype))
                .or_default()
                .push(FsvSimProjectionContributor {
                    family: *family,
                    ledger_ref: state.ledger_ref.clone(),
                    weight_bits: row.weight_bits,
                    source_atom_id: row.source_id.clone(),
                    target_atom_id: row.target_id.clone(),
                });
            source_rows = source_rows
                .checked_add(1)
                .ok_or("ISSUE_1116_1119_SIM_PROJECTION_ROW_COUNT_OVERFLOW")?;
            require(
                key == &astrolabe_weave::sim_edge_graph_key(
                    *family,
                    &row.source_id,
                    &row.target_id,
                ),
                "ISSUE_1116_1119_SIM_PROJECTION_SOURCE_KEY_MISMATCH",
                hex_lower(key),
            )?;
        }
    }
    let mut group_receipts = Vec::with_capacity(groups.len());
    let mut contributed = BTreeMap::<SimilarityFamily, usize>::new();
    let mut carried = BTreeMap::<SimilarityFamily, usize>::new();
    for ((src, dst, etype), contributors) in &groups {
        let winner = contributors
            .iter()
            .max_by(|left, right| {
                (left.ledger_ref.seq, left.ledger_ref.hash)
                    .cmp(&(right.ledger_ref.seq, right.ledger_ref.hash))
            })
            .ok_or("ISSUE_1116_1119_SIM_PROJECTION_GROUP_EMPTY")?;
        for contributor in contributors {
            *contributed.entry(contributor.family).or_default() += 1;
        }
        *carried.entry(winner.family).or_default() += 1;
        let src_index = projection
            .nodes
            .binary_search_by(|node| node.id.cmp(src))
            .map_err(|_| format!("ISSUE_1116_1119_SIM_PROJECTION_SOURCE_NODE_MISSING: {src}"))?;
        let edge = projection.edges
            [projection.offsets[src_index]..projection.offsets[src_index + 1]]
            .iter()
            .find(|edge| edge.dst == *dst && edge.etype == *etype)
            .ok_or_else(|| {
                format!("ISSUE_1116_1119_SIM_PROJECTION_EDGE_MISSING: {src}->{dst} etype={etype}")
            })?;
        require(
            edge.ledger_seq == winner.ledger_ref.seq && edge.ledger_hash == winner.ledger_ref.hash,
            "ISSUE_1116_1119_SIM_PROJECTION_LEDGER_REF_MISMATCH",
            json!({
                "src": src,
                "dst": dst,
                "etype": etype,
                "expected": winner.ledger_ref,
                "observed": edge.ledger_ref(),
            }),
        )?;
        group_receipts.push(json!({
            "source_cx_id": src,
            "target_cx_id": dst,
            "etype": etype,
            "contributors": contributors.iter().map(|contributor| json!({
                "family": contributor.family.wire_name(),
                "source_atom_id": contributor.source_atom_id,
                "target_atom_id": contributor.target_atom_id,
                "weight_bits": contributor.weight_bits,
                "family_terminal_ledger_ref": contributor.ledger_ref,
            })).collect::<Vec<_>>(),
            "deterministic_greatest_ref_family": winner.family.wire_name(),
            "physical_csr_ledger_ref": {
                "seq": edge.ledger_seq,
                "hash": hex_lower(&edge.ledger_hash),
            },
            "exact_family_ref_resolution": true,
        }));
    }
    let family_ref_counts = SimilarityFamily::ALL
        .into_iter()
        .map(|family| {
            let row_count = families
                .get(&family)
                .map_or(0, |state| state.rows.len());
            json!({
                "family": family.wire_name(),
                "source_row_count": row_count,
                "contributing_projection_groups": contributed.get(&family).copied().unwrap_or(0),
                "csr_groups_physically_carrying_family_ref": carried.get(&family).copied().unwrap_or(0),
                "terminal_ledger_ref": families.get(&family).map(|state| &state.ledger_ref),
                "zero_rows_requires_no_csr_ref": row_count == 0,
            })
        })
        .collect::<Vec<_>>();
    require(
        deep.snapshot_seq == snapshot
            && deep.csr_present
            && deep.source_sim_edge_rows == source_rows
            && deep.projected_similarity_edge_count == groups.len()
            && projection.source_fingerprint_blake3
                == parse_lower_hash_32(
                    &deep.source_fingerprint_blake3,
                    "projection.source_fingerprint_blake3",
                )?,
        "ISSUE_1116_1119_SIM_PROJECTION_DEEP_READBACK_MISMATCH",
        json!({
            "snapshot": snapshot,
            "source_rows": source_rows,
            "groups": groups.len(),
            "deep": deep,
        }),
    )?;
    Ok(json!({
        "projection": "kernel_graph",
        "source_fingerprint_blake3": deep.source_fingerprint_blake3,
        "source_sim_edge_rows": source_rows,
        "projected_similarity_edge_count": groups.len(),
        "family_ref_counts": family_ref_counts,
        "groups": group_receipts,
        "dedup_contract": "per (source_cx_id,target_cx_id,etype), the physical CSR carries the deterministic greatest exact family terminal (seq,hash)",
        "raw_family_to_physical_csr_refs_verified": true,
        "complete_projection_deep_readback": deep,
    }))
}

fn load_real_similarity_nodes<C>(
    vault: &AsterVault<C>,
    vault_panel_root: &Path,
    project: &str,
) -> AnyResult<(Vec<SimilarityNode>, Value)>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let compact = astrolabe_ingest::read_cbm_compact_graph_snapshot(vault, project)?;
    require(
        compact.receipt.snapshot_seq == snapshot && !compact.nodes.is_empty(),
        "ISSUE_1116_1119_SIM_REAL_SOURCE_INVALID",
        json!({"snapshot": snapshot, "receipt": compact.receipt}),
    )?;
    let mut nodes = compact
        .nodes
        .iter()
        .map(|node| SimilarityNode::new(node.atom_id.clone(), node.qualified_name.clone()))
        .collect::<Vec<_>>();
    let cx_ids = compact
        .nodes
        .iter()
        .map(|node| node.cx_id)
        .collect::<Vec<_>>();
    let slot_source = WeaveSlotSource::open(
        snapshot,
        Some(vault_panel_root),
        Some(astrolabe_panel::CURRENT_SEMANTIC_PANEL_VERSION),
    )?;
    let mut bindings = Vec::new();
    for family in SimilarityFamily::ALL {
        let read_snapshot = vault.latest_seq();
        require(
            read_snapshot == snapshot,
            "ISSUE_1116_1119_SIM_REAL_SOURCE_MOVED",
            json!({"expected": snapshot, "observed": read_snapshot}),
        )?;
        let binding = slot_source.bind_latest_at(vault, read_snapshot, family.slot())?;
        let resolved =
            slot_source.resolve_many_bound_at(vault, read_snapshot, &binding, &cx_ids)?;
        require(
            resolved.len() == nodes.len()
                && resolved
                    .iter()
                    .zip(&cx_ids)
                    .all(|((observed, _), expected)| observed == expected),
            "ISSUE_1116_1119_SIM_REAL_SLOT_ROSTER_MISMATCH",
            json!({
                "family": family.wire_name(),
                "nodes": nodes.len(),
                "resolved": resolved.len(),
            }),
        )?;
        let mut vector_count = 0usize;
        for (index, (_, vector)) in resolved.into_iter().enumerate() {
            if let Some(vector) = vector {
                nodes[index].slots.insert(family.slot(), vector);
                vector_count += 1;
            }
        }
        bindings.push(json!({
            "family": family.wire_name(),
            "slot": family.slot().get(),
            "slot_cf_generation": binding.slot_cf_generation,
            "compression_cf_generation": binding.compression_cf_generation,
            "compressed_generation_identity": binding.compressed_generation_identity,
            "requested_node_count": nodes.len(),
            "resolved_vector_count": vector_count,
        }));
    }
    require(
        vault.latest_seq() == snapshot,
        "ISSUE_1116_1119_SIM_REAL_SOURCE_FINAL_EPOCH_MISMATCH",
        json!({"expected": snapshot, "observed": vault.latest_seq()}),
    )?;
    let receipt = json!({
        "schema": "astrolabe.issue-1116-1119.sim-real-source.v1",
        "snapshot_seq": snapshot,
        "project": project,
        "compact_graph": compact.receipt,
        "node_count": nodes.len(),
        "slot_bindings": bindings,
        "source": "real indexed compact Graph roster plus exact persisted S1/S4/S18/S21 representations",
        "fabricated_source_rows": 0,
    });
    Ok((nodes, receipt))
}

fn commit_sim_fault_row<C>(
    vault: &AsterVault<C>,
    case: &str,
    key: Vec<u8>,
    value: Vec<u8>,
) -> AnyResult<(LedgerRef, Value)>
where
    C: Clock,
{
    let before_seq = vault.latest_seq();
    let tombstoned = value == tombstone_value();
    let payload = serde_json::to_vec(&json!({
        "schema": "astrolabe.issue-1116-1119.sim-terminal-fault-action.v1",
        "case": case,
        "before_seq": before_seq,
        "key_hex": hex_lower(&key),
        "value_bytes": value.len(),
        "value_sha256": sha256(&value),
    }))?;
    let subject =
        SubjectId::Query(format!("astrolabe-manual-fsv-sim-terminal:{case}").into_bytes());
    let actor = ActorId::Service(SIM_SCENARIO_ACTOR.to_string());
    let commit = vault.write_cf_batch_with_ledger_entry_with_row_digests(
        [(ColumnFamily::Graph, key.clone(), value.clone())],
        EntryKind::Admin,
        subject.clone(),
        payload.clone(),
        actor.clone(),
    )?;
    require(
        commit.seq
            == before_seq
                .checked_add(1)
                .ok_or("ISSUE_1116_1119_SIM_FAULT_SEQUENCE_OVERFLOW")?
            && commit.data_row_digests.len() == 1
            && commit.data_row_digests[0].cf == ColumnFamily::Graph
            && commit.data_row_digests[0].key == key
            && commit.data_row_digests[0].value_blake3 == *blake3::hash(&value).as_bytes()
            && commit.data_row_digests[0].tombstoned == tombstoned,
        "ISSUE_1116_1119_SIM_FAULT_COMMIT_RECEIPT_INVALID",
        format!("{commit:#?}"),
    )?;
    let observed = vault.read_cf_at(commit.seq, ColumnFamily::Graph, &key)?;
    require(
        if tombstoned {
            observed.is_none()
        } else {
            observed.as_deref() == Some(value.as_slice())
        },
        "ISSUE_1116_1119_SIM_FAULT_DATA_READBACK_MISMATCH",
        json!({
            "case": case,
            "key_hex": hex_lower(&key),
            "expected_tombstone": tombstoned,
            "observed": observed.as_ref().map(|bytes| sha256(bytes)),
        }),
    )?;
    let ledger_key_bytes = ledger_key(commit.ledger_ref.seq);
    let ledger_bytes = vault
        .read_cf_at(commit.seq, ColumnFamily::Ledger, &ledger_key_bytes)?
        .ok_or("ISSUE_1116_1119_SIM_FAULT_LEDGER_MISSING")?;
    let ledger_entry = decode_ledger(&ledger_bytes)?;
    require(
        ledger_entry.verify()
            && ledger_entry.seq == commit.ledger_ref.seq
            && ledger_entry.entry_hash == commit.ledger_ref.hash
            && ledger_entry.kind == EntryKind::Admin
            && ledger_entry.subject == subject
            && ledger_entry.payload == payload
            && ledger_entry.actor == actor,
        "ISSUE_1116_1119_SIM_FAULT_LEDGER_MISMATCH",
        json!({
            "case": case,
            "commit_ref": commit.ledger_ref,
            "entry_seq": ledger_entry.seq,
            "entry_hash": hex_lower(&ledger_entry.entry_hash),
        }),
    )?;
    let expected_cfs = [
        ColumnFamily::Ledger,
        ColumnFamily::Graph,
        ColumnFamily::TimeIndex,
    ];
    let inventory = vault.physical_wal_commit_inventory(commit.seq, &expected_cfs)?;
    let graph_row = inventory
        .rows
        .iter()
        .find(|row| row.cf == ColumnFamily::Graph && row.key == key)
        .ok_or("ISSUE_1116_1119_SIM_FAULT_PHYSICAL_GRAPH_ROW_MISSING")?;
    let ledger_row = inventory
        .rows
        .iter()
        .find(|row| row.cf == ColumnFamily::Ledger && row.key == ledger_key_bytes)
        .ok_or("ISSUE_1116_1119_SIM_FAULT_PHYSICAL_LEDGER_ROW_MISSING")?;
    let mut expected_time_index_key = Vec::with_capacity(16);
    expected_time_index_key.extend_from_slice(&GENERATION_OBSERVED_AT_MS.to_be_bytes());
    expected_time_index_key.extend_from_slice(&commit.seq.to_be_bytes());
    let time_index_row = inventory
        .rows
        .iter()
        .find(|row| row.cf == ColumnFamily::TimeIndex && row.key == expected_time_index_key)
        .ok_or("ISSUE_1116_1119_SIM_FAULT_PHYSICAL_TIME_INDEX_ROW_MISSING")?;
    require(
        inventory.seq == commit.seq
            && inventory.wal_replay_floor_seq < commit.seq
            && inventory.column_families == expected_cfs
            && inventory.rows.len() == 3
            && graph_row.value_length == u64::try_from(value.len())?
            && graph_row.value_sha256_hex() == sha256(&value)
            && graph_row.tombstoned == tombstoned
            && ledger_row.value_length == u64::try_from(ledger_bytes.len())?
            && ledger_row.value_sha256_hex() == sha256(&ledger_bytes)
            && !ledger_row.tombstoned
            && time_index_row.value_length == 1
            && time_index_row.value_sha256_hex() == sha256(&[0_u8])
            && !time_index_row.tombstoned,
        "ISSUE_1116_1119_SIM_FAULT_WAL_INVENTORY_MISMATCH",
        format!("{inventory:#?}"),
    )?;
    vault.flush()?;
    Ok((
        commit.ledger_ref.clone(),
        json!({
            "case": case,
            "before_seq": before_seq,
            "commit_seq": commit.seq,
            "data": {
                "cf": "graph",
                "key_hex": hex_lower(&key),
                "value_bytes": value.len(),
                "value_sha256": sha256(&value),
                "tombstoned": tombstoned,
                "logical_readback": observed.map(|bytes| json!({
                    "bytes": bytes.len(),
                    "sha256": sha256(&bytes),
                })),
            },
            "ledger": {
                "key_hex": hex_lower(&ledger_key_bytes),
                "value_bytes": ledger_bytes.len(),
                "value_sha256": sha256(&ledger_bytes),
                "ledger_ref": commit.ledger_ref,
                "exact_kind_subject_payload_actor_ref": true,
            },
            "wal": {
                "record_identity": inventory.wal_record.canonical_identity(),
                "offset": inventory.wal_record.offset,
                "length": inventory.wal_record.length,
                "sha256": inventory.wal_record.sha256_hex(),
                "time_index_key_hex": hex_lower(&expected_time_index_key),
                "time_index_value_sha256": sha256(&[0_u8]),
                "three_exact_graph_ledger_time_index_rows": true,
            },
            "flushed_before_action_surface": true,
        }),
    ))
}

fn persist_real_similarity_family<C>(
    vault: &AsterVault<C>,
    run_root: &Path,
    project: &str,
    nodes: &[SimilarityNode],
    family: SimilarityFamily,
    config: &SimilarityPlannerConfig,
    global_dump_hasher: &mut blake3::Hasher,
) -> calyx_core::Result<astrolabe_weave::SimilarityPersistReport>
where
    C: Clock,
{
    let source_slot_generation = vault.cf_content_generation(ColumnFamily::slot(family.slot()))?;
    let compression_generation = vault.cf_content_generation(ColumnFamily::Compression)?;
    let plan = astrolabe_weave::plan_similarity_family_run(
        vault,
        run_root.join(family.wire_name().to_ascii_lowercase()),
        format!(
            "manual-fsv-project={project};slot={};slot_generation={source_slot_generation};compression_generation={compression_generation};source=real-indexed-vault-clone",
            family.slot().get(),
        ),
        nodes,
        family,
        config,
    )?;
    astrolabe_weave::persist_similarity_family_run(
        vault,
        plan,
        global_dump_hasher,
        "astrolabe-shadow-weave",
    )
}

fn sim_persist_report_receipt(
    family: SimilarityFamily,
    report: &astrolabe_weave::SimilarityPersistReport,
) -> Value {
    json!({
        "family": family.wire_name(),
        "edge_count": report.edge_count,
        "rows_written": report.rows_written,
        "rows_unchanged": report.rows_unchanged,
        "rows_tombstoned": report.rows_tombstoned,
        "edge_dump_hash": report.edge_dump_hash,
        "terminal_attestation_published": report.terminal_attestation_published,
        "terminal_family_row_count": report.terminal_family_row_count,
        "terminal_family_bytes": report.terminal_family_bytes,
        "terminal_family_content_blake3": report.terminal_family_content_blake3,
        "ledger_refs": report.ledger_refs,
        "fsv": report.fsv,
        "bounded_run": report.run,
        "changed_lowered_inputs": report.changed_lowered_inputs(),
        "timing_labels": report
            .timing_ms
            .0
            .iter()
            .map(|(label, _)| *label)
            .collect::<Vec<_>>(),
    })
}

fn exercise_sim_no_delta(
    vault_path: &Path,
    vault_id: VaultId,
    vault_salt: &[u8],
    project: &str,
) -> AnyResult<Value> {
    let vault = open_sim_scenario_vault(vault_path, vault_id, vault_salt, false)?;
    let before_raw = raw_sim_terminal_surface(&vault)?;
    let before = read_sim_terminal_attestations(&vault, project, true)?;
    let (nodes, source) = load_real_similarity_nodes(&vault, vault_path, project)?;
    let config = SimilarityPlannerConfig::resolve_runtime()?;
    let run_root = vault_path
        .parent()
        .ok_or("ISSUE_1116_1119_SIM_NO_DELTA_PARENT_MISSING")?
        .join("no-delta-runs");
    fs::create_dir(&run_root)?;
    let mut global_dump_hasher = blake3::Hasher::new();
    let mut reports = Vec::new();
    for family in SimilarityFamily::ALL {
        let report = persist_real_similarity_family(
            &vault,
            &run_root,
            project,
            &nodes,
            family,
            &config,
            &mut global_dump_hasher,
        )?;
        let expected = before
            .families
            .get(&family)
            .ok_or("ISSUE_1116_1119_SIM_NO_DELTA_FAMILY_MISSING")?;
        require(
            report.rows_written == 0
                && report.rows_tombstoned == 0
                && report.rows_unchanged == report.edge_count
                && !report.terminal_attestation_published
                && report.terminal_family_row_count == u64::try_from(expected.rows.len())?
                && report.terminal_family_bytes == expected.marker.total_bytes
                && report.terminal_family_content_blake3 == expected.marker.content_blake3
                && report.ledger_refs == [expected.ledger_ref.clone()]
                && report.fsv.is_empty()
                && report.run.mutation_groups == 0
                && report.run.final_rows_read_back == report.edge_count
                && report.run.final_bytes_read_back == expected.marker.total_bytes
                && !report.changed_lowered_inputs(),
            "ISSUE_1116_1119_SIM_NO_DELTA_REPORT_INVALID",
            sim_persist_report_receipt(family, &report),
        )?;
        reports.push(sim_persist_report_receipt(family, &report));
    }
    let after = read_sim_terminal_attestations(&vault, project, true)?;
    let after_raw = raw_sim_terminal_surface(&vault)?;
    require(
        after.receipt == before.receipt && after_raw == before_raw,
        "ISSUE_1116_1119_SIM_NO_DELTA_MUTATED_STATE",
        json!({
            "before": before.receipt,
            "after": after.receipt,
            "before_raw": before_raw,
            "after_raw": after_raw,
        }),
    )?;
    vault.flush()?;
    Ok(json!({
        "schema": "astrolabe.issue-1116-1119.sim-no-delta.v1",
        "vault_path": vault_path,
        "source": source,
        "before": before.receipt,
        "reports": reports,
        "after": after.receipt,
        "raw_before": before_raw,
        "raw_after": after_raw,
        "exact_marker_and_ledger_ref_reused": true,
        "vault_sequence_and_cf_generations_unchanged": true,
        "all_changed_lowered_inputs_false": true,
        "mutation_ack_count": 0,
    }))
}

fn exercise_sim_bootstrap(
    vault_path: &Path,
    vault_id: VaultId,
    vault_salt: &[u8],
    project: &str,
) -> AnyResult<Value> {
    let vault = open_sim_scenario_vault(vault_path, vault_id, vault_salt, false)?;
    let before = read_sim_terminal_attestations(&vault, project, true)?;
    let before_raw = raw_sim_terminal_surface(&vault)?;
    let family = SimilarityFamily::ALL
        .into_iter()
        .find(|candidate| {
            before
                .families
                .get(candidate)
                .is_some_and(|state| !state.rows.is_empty())
        })
        .unwrap_or(SimilarityFamily::Semantic);
    let before_family = before
        .families
        .get(&family)
        .ok_or("ISSUE_1116_1119_SIM_BOOTSTRAP_FAMILY_MISSING")?;
    let (_, removal) = commit_sim_fault_row(
        &vault,
        "absent-marker-bootstrap-remove",
        before_family.marker_key.clone(),
        tombstone_value(),
    )?;
    let absent = raw_sim_terminal_surface(&vault)?;
    let absent_physical_marker = physical_sim_graph_row(&absent, &before_family.marker_key)?;
    require(
        vault
            .read_cf_at(
                vault.latest_seq(),
                ColumnFamily::Graph,
                &before_family.marker_key,
            )?
            .is_none()
            && absent["marker_count"].as_u64()
                == u64::try_from(SimilarityFamily::ALL.len() - 1).ok()
            && absent_physical_marker["logical_state"] == "absent"
            && absent_physical_marker["physical_state"] == "tombstone"
            && absent_physical_marker["physical_value_sha256"] == sha256(&tombstone_value()),
        "ISSUE_1116_1119_SIM_BOOTSTRAP_MARKER_NOT_ABSENT",
        json!({
            "surface": absent,
            "physical_marker": absent_physical_marker,
        }),
    )?;
    let (nodes, source) = load_real_similarity_nodes(&vault, vault_path, project)?;
    let config = SimilarityPlannerConfig::resolve_runtime()?;
    let run_root = vault_path
        .parent()
        .ok_or("ISSUE_1116_1119_SIM_BOOTSTRAP_PARENT_MISSING")?
        .join("bootstrap-runs");
    fs::create_dir(&run_root)?;
    let mut global_dump_hasher = blake3::Hasher::new();
    let report = persist_real_similarity_family(
        &vault,
        &run_root,
        project,
        &nodes,
        family,
        &config,
        &mut global_dump_hasher,
    )?;
    let after = read_sim_terminal_attestations(&vault, project, false)?;
    let after_raw = raw_sim_terminal_surface(&vault)?;
    let after_family = after
        .families
        .get(&family)
        .ok_or("ISSUE_1116_1119_SIM_BOOTSTRAP_AFTER_FAMILY_MISSING")?;
    let before_physical_marker = physical_sim_graph_row(&before_raw, &before_family.marker_key)?;
    let after_physical_marker = physical_sim_graph_row(&after_raw, &before_family.marker_key)?;
    require(
        report.rows_written == 0
            && report.rows_tombstoned == 0
            && report.rows_unchanged == report.edge_count
            && report.terminal_attestation_published
            && report.terminal_family_row_count == u64::try_from(after_family.rows.len())?
            && report.terminal_family_bytes == after_family.marker.total_bytes
            && report.terminal_family_content_blake3 == after_family.marker.content_blake3
            && report.ledger_refs == [after_family.ledger_ref.clone()]
            && report.fsv.len() == 1
            && report.run.mutation_groups == 0
            && report.run.final_rows_read_back == report.edge_count
            && report.run.final_bytes_read_back == after_family.marker.total_bytes
            && report.changed_lowered_inputs()
            && before_family.marker.row_count == after_family.marker.row_count
            && before_family.marker.total_bytes == after_family.marker.total_bytes
            && before_family.marker.content_blake3 == after_family.marker.content_blake3
            && before_family.ledger_ref != after_family.ledger_ref
            && before_raw != absent
            && absent != after_raw
            && before_physical_marker["logical_state"] == "live"
            && before_physical_marker["physical_state"] == "live"
            && before_physical_marker["physical_value_sha256"]
                == sha256(&before_family.marker_bytes)
            && after_physical_marker["logical_state"] == "live"
            && after_physical_marker["physical_state"] == "live"
            && after_physical_marker["physical_value_sha256"] == sha256(&after_family.marker_bytes),
        "ISSUE_1116_1119_SIM_BOOTSTRAP_REPORT_INVALID",
        json!({
            "family": family.wire_name(),
            "before_family": before_family.marker,
            "after_family": after_family.marker,
            "report": sim_persist_report_receipt(family, &report),
        }),
    )?;
    let projection_error = match astrolabe_ingest::read_graph_projection_csr_at(
        &vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        vault.latest_seq(),
    ) {
        Err(error) => error,
        Ok(value) => {
            return Err(format!(
                "ISSUE_1116_1119_SIM_BOOTSTRAP_PROJECTION_UNEXPECTEDLY_CURRENT: {value:?}"
            )
            .into());
        }
    };
    require(
        projection_error.code() == Some(astrolabe_ingest::ASTRO_GRAPH_PROJECTION_CORRUPT),
        "ISSUE_1116_1119_SIM_BOOTSTRAP_PROJECTION_ERROR_INVALID",
        &projection_error,
    )?;
    vault.flush()?;
    Ok(json!({
        "schema": "astrolabe.issue-1116-1119.sim-marker-bootstrap.v1",
        "vault_path": vault_path,
        "family": family.wire_name(),
        "source": source,
        "before": before.receipt,
        "removal": removal,
        "absent": absent,
        "physical_marker_transition": {
            "before": before_physical_marker,
            "absent": absent_physical_marker,
            "after": after_physical_marker,
            "physical_absence_is_exact_tombstone": true,
        },
        "report": sim_persist_report_receipt(family, &report),
        "after": after.receipt,
        "raw_before": before_raw,
        "raw_after": after_raw,
        "projection_invalidation": {
            "code": projection_error.code(),
            "message": projection_error.message(),
            "remediation": projection_error.remediation(),
            "stale_projection_never_served": true,
        },
        "terminal_marker_published": true,
        "changed_lowered_inputs": true,
    }))
}

fn exercise_sim_invalid_marker(
    vault_path: &Path,
    vault_id: VaultId,
    vault_salt: &[u8],
    project: &str,
    stale: bool,
) -> AnyResult<Value> {
    let case = if stale {
        "stale-marker"
    } else {
        "malformed-marker"
    };
    let vault = open_sim_scenario_vault(vault_path, vault_id, vault_salt, false)?;
    let terminal_before = read_sim_terminal_attestations(&vault, project, true)?;
    let before = raw_sim_terminal_surface(&vault)?;
    let family = SimilarityFamily::Struct;
    let family_before = terminal_before
        .families
        .get(&family)
        .ok_or("ISSUE_1116_1119_SIM_INVALID_MARKER_FAMILY_MISSING")?;
    let invalid_bytes = if stale {
        let mut marker = family_before.marker.clone();
        marker.row_count = marker
            .row_count
            .checked_add(1)
            .ok_or("ISSUE_1116_1119_SIM_STALE_MARKER_COUNT_OVERFLOW")?;
        serde_json::to_vec(&marker)?
    } else {
        b"{\"schema\":\"astrolabe.sim_source_attestation.v1\",\"family\":".to_vec()
    };
    let (_, action_receipt) = commit_sim_fault_row(
        &vault,
        case,
        family_before.marker_key.clone(),
        invalid_bytes.clone(),
    )?;
    let action = raw_sim_terminal_surface(&vault)?;
    let (nodes, source) = load_real_similarity_nodes(&vault, vault_path, project)?;
    let config = SimilarityPlannerConfig::resolve_runtime()?;
    let run_root = vault_path
        .parent()
        .ok_or("ISSUE_1116_1119_SIM_INVALID_MARKER_PARENT_MISSING")?
        .join(format!("{case}-runs"));
    fs::create_dir(&run_root)?;
    let mut global_dump_hasher = blake3::Hasher::new();
    let result = persist_real_similarity_family(
        &vault,
        &run_root,
        project,
        &nodes,
        family,
        &config,
        &mut global_dump_hasher,
    );
    let error = match result {
        Err(error) => error,
        Ok(report) => {
            return Err(format!(
                "ISSUE_1116_1119_SIM_INVALID_MARKER_UNEXPECTED_SUCCESS: case={case}; report={}",
                sim_persist_report_receipt(family, &report)
            )
            .into());
        }
    };
    let after = raw_sim_terminal_surface(&vault)?;
    let marker_after = vault
        .read_cf_at(
            vault.latest_seq(),
            ColumnFamily::Graph,
            &family_before.marker_key,
        )?
        .ok_or("ISSUE_1116_1119_SIM_INVALID_MARKER_DISAPPEARED")?;
    let before_physical_marker = physical_sim_graph_row(&before, &family_before.marker_key)?;
    let action_physical_marker = physical_sim_graph_row(&action, &family_before.marker_key)?;
    let after_physical_marker = physical_sim_graph_row(&after, &family_before.marker_key)?;
    require(
        error.code == astrolabe_weave::ASTRO_SIM_EDGE_ROW_CORRUPT
            && error.message.contains("terminal source marker")
            && error.message.contains(family.wire_name())
            && marker_after == invalid_bytes
            && before != action
            && action == after
            && before_physical_marker["logical_state"] == "live"
            && before_physical_marker["physical_state"] == "live"
            && before_physical_marker["physical_value_sha256"]
                == sha256(&family_before.marker_bytes)
            && action_physical_marker["logical_state"] == "live"
            && action_physical_marker["physical_state"] == "live"
            && action_physical_marker["physical_value_sha256"] == sha256(&invalid_bytes)
            && after_physical_marker == action_physical_marker,
        "ISSUE_1116_1119_SIM_INVALID_MARKER_REFUSAL_INVALID",
        json!({
            "case": case,
            "error": error.to_string(),
            "before": before,
            "action": action,
            "after": after,
            "marker_after_sha256": sha256(&marker_after),
        }),
    )?;
    vault.flush()?;
    Ok(json!({
        "schema": "astrolabe.issue-1116-1119.sim-invalid-marker-refusal.v1",
        "case": case,
        "vault_path": vault_path,
        "family": family.wire_name(),
        "source": source,
        "before": before,
        "action": action,
        "action_receipt": action_receipt,
        "after": after,
        "error": {
            "code": error.code,
            "message": error.message,
            "remediation": error.remediation,
        },
        "invalid_marker": {
            "bytes": invalid_bytes.len(),
            "sha256": sha256(&invalid_bytes),
            "hex": hex_lower(&invalid_bytes),
            "stale_but_canonical": stale,
        },
        "physical_marker_transition": {
            "before": before_physical_marker,
            "action": action_physical_marker,
            "after": after_physical_marker,
            "refused_persist_preserved_exact_physical_action_bytes": true,
        },
        "database_surface_unchanged_by_refused_persist": true,
    }))
}

fn exercise_sim_sequence_cas(
    vault_path: &Path,
    vault_id: VaultId,
    vault_salt: &[u8],
    project: &str,
) -> AnyResult<Value> {
    let vault = open_sim_scenario_vault(vault_path, vault_id, vault_salt, false)?;
    let terminal_before = read_sim_terminal_attestations(&vault, project, true)?;
    let before = raw_sim_terminal_surface(&vault)?;
    let expected_seq = vault.latest_seq();
    let family = SimilarityFamily::Semantic;
    let family_before = terminal_before
        .families
        .get(&family)
        .ok_or("ISSUE_1116_1119_SIM_CAS_FAMILY_MISSING")?;
    let race_value = serde_json::to_vec(&json!({
        "schema": "astrolabe.issue-1116-1119.sim-cas-race.v1",
        "expected_seq": expected_seq,
        "family": family.wire_name(),
    }))?;
    let (_, race_commit) = commit_sim_fault_row(
        &vault,
        "terminal-sequence-race",
        SIM_CAS_RACE_KEY.to_vec(),
        race_value.clone(),
    )?;
    let action = raw_sim_terminal_surface(&vault)?;
    let callback_invoked = AtomicBool::new(false);
    let marker_key = family_before.marker_key.clone();
    let marker_family = family.wire_name().to_string();
    let marker_row_count = family_before.marker.row_count;
    let marker_total_bytes = family_before.marker.total_bytes;
    let marker_content_blake3 = family_before.marker.content_blake3.clone();
    let marker_actor = family_before.marker.actor.clone();
    let cas_payload = FsvSimSourceAttestationLedgerPayload {
        schema: SIM_SOURCE_ATTESTATION_LEDGER_SCHEMA.to_string(),
        family: marker_family.clone(),
        row_count: marker_row_count,
        total_bytes: marker_total_bytes,
        content_blake3: marker_content_blake3.clone(),
    };
    let cas_subject = SubjectId::Query(
        format!(
            "{SIM_SOURCE_ATTESTATION_SUBJECT_PREFIX}:{marker_family}:{marker_row_count}:{marker_total_bytes}:{marker_content_blake3}"
        )
        .into_bytes(),
    );
    let result = vault.write_cf_batch_with_ledger_entry_with_row_digests_and_derived_if_seq(
        expected_seq,
        Vec::<(ColumnFamily, Vec<u8>, Vec<u8>)>::new(),
        EntryKind::Ingest,
        cas_subject,
        serde_json::to_vec(&cas_payload)?,
        ActorId::Service(marker_actor.clone()),
        |ledger_ref, _| {
            callback_invoked.store(true, Ordering::Release);
            let marker = FsvSimSourceAttestation {
                schema: SIM_SOURCE_ATTESTATION_SCHEMA.to_string(),
                family: marker_family,
                row_count: marker_row_count,
                total_bytes: marker_total_bytes,
                content_blake3: marker_content_blake3,
                ledger_seq: ledger_ref.seq,
                ledger_hash: hex_lower(&ledger_ref.hash),
                actor: marker_actor,
            };
            let bytes = serde_json::to_vec(&marker).map_err(|error| calyx_core::CalyxError {
                code: astrolabe_weave::ASTRO_SIM_EDGE_ROW_CORRUPT,
                message: format!("encode manual-FSV terminal marker: {error}"),
                remediation: "repair terminal SIM marker encoding before publication",
            })?;
            Ok((vec![(ColumnFamily::Graph, marker_key, bytes)], ()))
        },
    );
    let error = match result {
        Err(error) => error,
        Ok((commit, ())) => {
            return Err(
                format!("ISSUE_1116_1119_SIM_CAS_UNEXPECTED_SUCCESS: commit={commit:#?}").into(),
            );
        }
    };
    let after = raw_sim_terminal_surface(&vault)?;
    let marker_after = vault
        .read_cf_at(
            vault.latest_seq(),
            ColumnFamily::Graph,
            &family_before.marker_key,
        )?
        .ok_or("ISSUE_1116_1119_SIM_CAS_MARKER_MISSING_AFTER")?;
    let race_after = vault
        .read_cf_at(vault.latest_seq(), ColumnFamily::Graph, SIM_CAS_RACE_KEY)?
        .ok_or("ISSUE_1116_1119_SIM_CAS_RACE_ROW_MISSING_AFTER")?;
    let before_physical_marker = physical_sim_graph_row(&before, &family_before.marker_key)?;
    let action_physical_marker = physical_sim_graph_row(&action, &family_before.marker_key)?;
    let after_physical_marker = physical_sim_graph_row(&after, &family_before.marker_key)?;
    let before_physical_race = physical_sim_graph_row(&before, SIM_CAS_RACE_KEY)?;
    let action_physical_race = physical_sim_graph_row(&action, SIM_CAS_RACE_KEY)?;
    let after_physical_race = physical_sim_graph_row(&after, SIM_CAS_RACE_KEY)?;
    require(
        error.code == "CALYX_ASTER_SEQUENCE_CONFLICT"
            && !callback_invoked.load(Ordering::Acquire)
            && marker_after == family_before.marker_bytes
            && race_after == race_value
            && expected_seq < vault.latest_seq()
            && before != action
            && action == after
            && before_physical_marker["logical_state"] == "live"
            && before_physical_marker["physical_state"] == "live"
            && before_physical_marker["physical_value_sha256"]
                == sha256(&family_before.marker_bytes)
            && action_physical_marker == before_physical_marker
            && after_physical_marker == action_physical_marker
            && before_physical_race["logical_state"] == "absent"
            && before_physical_race["physical_state"] == "absent"
            && action_physical_race["logical_state"] == "live"
            && action_physical_race["physical_state"] == "live"
            && action_physical_race["physical_value_sha256"] == sha256(&race_value)
            && after_physical_race == action_physical_race,
        "ISSUE_1116_1119_SIM_CAS_REFUSAL_INVALID",
        json!({
            "expected_seq": expected_seq,
            "observed_seq": vault.latest_seq(),
            "callback_invoked": callback_invoked.load(Ordering::Acquire),
            "error": error,
            "before": before,
            "action": action,
            "after": after,
        }),
    )?;
    vault.flush()?;
    Ok(json!({
        "schema": "astrolabe.issue-1116-1119.sim-terminal-sequence-cas.v1",
        "vault_path": vault_path,
        "family": family.wire_name(),
        "expected_seq": expected_seq,
        "race_commit": race_commit,
        "before": before,
        "action": action,
        "after": after,
        "error": {
            "code": error.code,
            "message": error.message,
            "remediation": error.remediation,
        },
        "physical_marker_and_race_transition": {
            "marker_before": before_physical_marker,
            "marker_action": action_physical_marker,
            "marker_after": after_physical_marker,
            "race_before": before_physical_race,
            "race_action": action_physical_race,
            "race_after": after_physical_race,
            "failed_cas_preserved_exact_physical_action_state": true,
        },
        "exact_shipping_terminal_subject_payload_actor_and_derived_marker_callback": true,
        "derived_callback_invoked": false,
        "terminal_marker_bytes_unchanged": true,
        "database_surface_unchanged_by_refused_cas": true,
    }))
}

fn exercise_sim_terminal_attestation_contract(
    cache: &Path,
    project: &str,
    payload: &Path,
) -> AnyResult<Value> {
    let (_, source_vault, vault_id, vault_salt) = vault_identity(cache, project)?;
    let source_vault = source_vault.canonicalize()?;
    let source = open_sim_scenario_vault(&source_vault, vault_id, vault_salt.as_bytes(), true)?;
    let primary = read_sim_terminal_attestations(&source, project, true)?;
    let primary_raw = raw_sim_terminal_surface(&source)?;
    drop(source);

    let scenario_root = payload.join("sim-terminal-attestation");
    fs::create_dir(&scenario_root)?;
    let scenario_names = ["no-delta", "bootstrap", "malformed", "stale", "cas"];
    let mut clone_receipts = BTreeMap::new();
    let mut paths = BTreeMap::new();
    for name in scenario_names {
        let scenario = scenario_root.join(name);
        fs::create_dir(&scenario)?;
        let vault_path = scenario.join("vault");
        let clone = clone_ordinary_tree_exact(&source_vault, &vault_path)?;
        clone_receipts.insert(name, clone);
        paths.insert(name, vault_path);
    }
    let no_delta = exercise_sim_no_delta(
        paths["no-delta"].as_path(),
        vault_id,
        vault_salt.as_bytes(),
        project,
    )?;
    let bootstrap = exercise_sim_bootstrap(
        paths["bootstrap"].as_path(),
        vault_id,
        vault_salt.as_bytes(),
        project,
    )?;
    let malformed = exercise_sim_invalid_marker(
        paths["malformed"].as_path(),
        vault_id,
        vault_salt.as_bytes(),
        project,
        false,
    )?;
    let stale = exercise_sim_invalid_marker(
        paths["stale"].as_path(),
        vault_id,
        vault_salt.as_bytes(),
        project,
        true,
    )?;
    let cas = exercise_sim_sequence_cas(
        paths["cas"].as_path(),
        vault_id,
        vault_salt.as_bytes(),
        project,
    )?;
    Ok(json!({
        "schema": "astrolabe.issue-1116-1119.sim-terminal-attestation-fsv.v1",
        "runtime_mode": "execute after real shipping index_repository and before ordinary unchanged/cache-hit repeat",
        "runtime_order": [
            "primary physical marker/Ledger/family/CSR readback",
            "true no-delta exact marker/ref reuse",
            "absent-marker bootstrap publication and projection invalidation",
            "malformed-marker refusal",
            "stale-marker refusal",
            "stale-sequence derived publication refusal"
        ],
        "source_vault": source_vault,
        "scenario_root": scenario_root,
        "primary": primary.receipt,
        "primary_raw": primary_raw,
        "clones": clone_receipts,
        "no_delta": no_delta,
        "bootstrap": bootstrap,
        "malformed": malformed,
        "stale": stale,
        "sequence_cas": cas,
        "real_source_only": true,
        "mock_or_fabricated_source_rows": 0,
        "primary_vault_mutated": false,
        "fixture_scale_not_production_cost_evidence": true,
    }))
}

fn sim_terminal_family_identities(receipt: &Value) -> AnyResult<Value> {
    let families = receipt["families"]
        .as_array()
        .ok_or("ISSUE_1116_1119_SIM_FAMILY_RECEIPTS_MISSING")?;
    Ok(Value::Array(
        families
            .iter()
            .map(|family| {
                json!({
                    "family": family["family"],
                    "family_sort_index": family["family_sort_index"],
                    "row_count": family["row_count"],
                    "total_key_value_bytes": family["total_key_value_bytes"],
                    "content_blake3": family["content_blake3"],
                    "rows": family["rows"],
                    "marker": {
                        "key_hex": family["marker"]["key_hex"],
                        "value_bytes": family["marker"]["value_bytes"],
                        "value_sha256": family["marker"]["value_sha256"],
                        "decoded": family["marker"]["decoded"],
                        "canonical_bytes_equal": family["marker"]["canonical_bytes_equal"],
                    },
                    "ledger": {
                        "key_hex": family["ledger"]["key_hex"],
                        "value_bytes": family["ledger"]["value_bytes"],
                        "value_sha256": family["ledger"]["value_sha256"],
                        "seq": family["ledger"]["seq"],
                        "entry_hash": family["ledger"]["entry_hash"],
                        "payload_sha256": family["ledger"]["payload_sha256"],
                        "exact_kind_subject_payload_actor_ref": family["ledger"]
                            ["exact_kind_subject_payload_actor_ref"],
                    },
                    "sorted_raw_key_value_blake3_recomputed": family
                        ["sorted_raw_key_value_blake3_recomputed"],
                    "physical_marker_and_ledger_point_reads": family
                        ["physical_marker_and_ledger_point_reads"],
                })
            })
            .collect(),
    ))
}

fn readback_sim_terminal_attestation_contract(
    cache: &Path,
    project: &str,
    payload: &Path,
    execution: &Value,
) -> AnyResult<Value> {
    let expected = &execution["sim_terminal_attestation"];
    require(
        expected["schema"] == "astrolabe.issue-1116-1119.sim-terminal-attestation-fsv.v1",
        "ISSUE_1116_1119_SIM_READBACK_EXECUTION_RECEIPT_INVALID",
        &expected["schema"],
    )?;
    let (_, source_vault, vault_id, vault_salt) = vault_identity(cache, project)?;
    let source_vault = source_vault.canonicalize()?;
    require(
        expected["source_vault"] == json!(source_vault),
        "ISSUE_1116_1119_SIM_READBACK_SOURCE_VAULT_MISMATCH",
        json!({"expected": expected["source_vault"], "observed": source_vault}),
    )?;
    let source = open_sim_scenario_vault(&source_vault, vault_id, vault_salt.as_bytes(), true)?;
    let primary = read_sim_terminal_attestations(&source, project, true)?;
    let primary_raw = raw_sim_terminal_surface(&source)?;
    drop(source);
    require(
        sim_terminal_family_identities(&primary.receipt)?
            == sim_terminal_family_identities(&expected["primary"])?
            && primary.receipt["graph_cf_generation"] == expected["primary"]["graph_cf_generation"]
            && primary.receipt["projection"]["source_fingerprint_blake3"]
                == expected["primary"]["projection"]["source_fingerprint_blake3"]
            && primary.receipt["projection"]["source_sim_edge_rows"]
                == expected["primary"]["projection"]["source_sim_edge_rows"]
            && primary.receipt["projection"]["projected_similarity_edge_count"]
                == expected["primary"]["projection"]["projected_similarity_edge_count"]
            && primary.receipt["projection"]["family_ref_counts"]
                == expected["primary"]["projection"]["family_ref_counts"]
            && primary.receipt["projection"]["groups"]
                == expected["primary"]["projection"]["groups"]
            && primary_raw == expected["primary_raw"],
        "ISSUE_1116_1119_SIM_PRIMARY_SEPARATE_READBACK_MISMATCH",
        json!({
            "execution": expected["primary"],
            "execution_raw": expected["primary_raw"],
            "readback": primary.receipt,
            "readback_raw": primary_raw,
        }),
    )?;

    let scenario_root = payload.join("sim-terminal-attestation");
    require(
        expected["scenario_root"] == json!(scenario_root),
        "ISSUE_1116_1119_SIM_READBACK_SCENARIO_ROOT_MISMATCH",
        json!({"expected": expected["scenario_root"], "observed": scenario_root}),
    )?;
    let no_delta_path = scenario_root.join("no-delta").join("vault");
    let no_delta_vault =
        open_sim_scenario_vault(&no_delta_path, vault_id, vault_salt.as_bytes(), true)?;
    let no_delta = read_sim_terminal_attestations(&no_delta_vault, project, true)?;
    let no_delta_raw = raw_sim_terminal_surface(&no_delta_vault)?;
    require(
        no_delta.receipt == expected["no_delta"]["after"]
            && no_delta_raw == expected["no_delta"]["raw_after"],
        "ISSUE_1116_1119_SIM_NO_DELTA_SEPARATE_READBACK_MISMATCH",
        json!({
            "execution": expected["no_delta"],
            "readback": no_delta.receipt,
            "raw": no_delta_raw,
        }),
    )?;
    drop(no_delta_vault);

    let bootstrap_path = scenario_root.join("bootstrap").join("vault");
    let bootstrap_vault =
        open_sim_scenario_vault(&bootstrap_path, vault_id, vault_salt.as_bytes(), true)?;
    let bootstrap = read_sim_terminal_attestations(&bootstrap_vault, project, false)?;
    let bootstrap_raw = raw_sim_terminal_surface(&bootstrap_vault)?;
    let bootstrap_projection_error = match astrolabe_ingest::read_graph_projection_csr_at(
        &bootstrap_vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        bootstrap_vault.latest_seq(),
    ) {
        Err(error) => error,
        Ok(value) => {
            return Err(format!(
                "ISSUE_1116_1119_SIM_BOOTSTRAP_READBACK_PROJECTION_UNEXPECTEDLY_CURRENT: {value:?}"
            )
            .into());
        }
    };
    require(
        bootstrap.receipt == expected["bootstrap"]["after"]
            && bootstrap_raw == expected["bootstrap"]["raw_after"]
            && bootstrap_projection_error.code()
                == Some(astrolabe_ingest::ASTRO_GRAPH_PROJECTION_CORRUPT),
        "ISSUE_1116_1119_SIM_BOOTSTRAP_SEPARATE_READBACK_MISMATCH",
        json!({
            "execution": expected["bootstrap"],
            "readback": bootstrap.receipt,
            "raw": bootstrap_raw,
            "projection_error": bootstrap_projection_error.to_string(),
        }),
    )?;
    drop(bootstrap_vault);

    let mut refusal_readbacks = BTreeMap::new();
    for (name, field) in [
        ("malformed", "malformed"),
        ("stale", "stale"),
        ("cas", "sequence_cas"),
    ] {
        let vault_path = scenario_root.join(name).join("vault");
        let vault = open_sim_scenario_vault(&vault_path, vault_id, vault_salt.as_bytes(), true)?;
        let raw = raw_sim_terminal_surface(&vault)?;
        require(
            raw == expected[field]["after"],
            "ISSUE_1116_1119_SIM_REFUSAL_SEPARATE_READBACK_MISMATCH",
            json!({"case": name, "expected": expected[field]["after"], "observed": raw}),
        )?;
        refusal_readbacks.insert(name, raw);
    }
    Ok(json!({
        "schema": "astrolabe.issue-1116-1119.sim-terminal-attestation-readback.v1",
        "runtime_mode": "separate readback process after association publication and transport",
        "source_vault": source_vault,
        "primary": primary.receipt,
        "primary_raw": primary_raw,
        "no_delta": no_delta.receipt,
        "no_delta_raw": no_delta_raw,
        "bootstrap": bootstrap.receipt,
        "bootstrap_raw": bootstrap_raw,
        "bootstrap_projection_refusal": {
            "code": bootstrap_projection_error.code(),
            "message": bootstrap_projection_error.message(),
            "remediation": bootstrap_projection_error.remediation(),
        },
        "refusal_surfaces": refusal_readbacks,
        "physical_clone_generations_reopened": 5,
        "primary_family_marker_ledger_and_projection_identity_unchanged": true,
        "fixture_scale_not_production_cost_evidence": true,
    }))
}

fn vector_bits_sha256(vector: &[f32]) -> String {
    let mut digest = Sha256::new();
    for value in vector {
        digest.update(value.to_bits().to_be_bytes());
    }
    format!("{digest:x}")
}

fn persisted_kernel_generation_receipt(
    rows: &BTreeMap<String, String>,
    project: &str,
) -> AnyResult<Value> {
    let key = format!("astrolabe.calyx.{project}.weave_json");
    let raw = rows
        .get(&key)
        .ok_or("ISSUE_1148_WEAVE_CONFIG_ROW_MISSING")?;
    let weave: Value = serde_json::from_str(raw)?;
    let receipt = weave
        .get("kernel_artifact")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or("ISSUE_1148_KERNEL_GENERATION_RECEIPT_MISSING")?;
    require(
        exact_json_object_fields(
            &receipt,
            &[
                "schema",
                "status",
                "published",
                "scope_id",
                "generation_id",
                "source_generation_identity",
                "members_hash",
                "member_count",
                "node_count",
                "graph_coverage",
                "compactness",
                "fvs_validity",
                "anchor_grounded",
                "source_identity",
                "source_identity_readback",
                "trusted_anchor_count",
                "rows_readback_verified",
                "readback_rows",
                "decoded_rows_verified",
                "ledger_paired",
                "commit_seq",
                "ledger_ref",
                "ledger_physical_tiers",
                "manifest",
                "pointer",
                "retired_generation_id",
                "query_admission",
                "member_index",
                "flush",
                "trust",
                "freshness",
                "provenance",
            ],
        ) && receipt["schema"] == "astrolabe.complete_kernel_generation_persist.v1"
            && receipt["status"] == "persisted"
            && exact_json_object_fields(
                &receipt["query_admission"],
                &["corpus_reused", "corpus", "graph_routed_report"],
            )
            && exact_json_object_fields(&receipt["member_index"], &["descriptor", "binding_count"])
            && exact_json_object_fields(
                &receipt["flush"],
                &["sst_files", "sst_entries", "sst_bytes"],
            ),
        "ISSUE_1148_KERNEL_GENERATION_RECEIPT_INVALID",
        &receipt,
    )?;
    Ok(receipt)
}

fn canonical_kernel_graph_bytes(graph: &astrolabe_kernel::KernelGraph) -> AnyResult<Vec<u8>> {
    let nodes = graph
        .nodes()
        .iter()
        .map(|node| {
            json!({
                "id": node.id,
                "frequency": node.frequency,
                "anchor_trust": node.anchor_trust,
            })
        })
        .collect::<Vec<_>>();
    let edges = graph
        .edges()
        .iter()
        .map(|edge| {
            json!({
                "src": edge.src,
                "dst": edge.dst,
                "weight_bits": edge.weight.to_bits(),
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::to_vec(&json!({
        "schema": "astrolabe.issue-1149.real-kernel-graph-state.v1",
        "nodes": nodes,
        "edges": edges,
    }))?)
}

fn kernel_graph_artifact_state(
    graph: &astrolabe_kernel::KernelGraph,
    artifact: &astrolabe_kernel::KernelArtifact,
) -> AnyResult<Value> {
    let graph_bytes = canonical_kernel_graph_bytes(graph)?;
    let artifact_bytes = artifact.kernel_json_bytes();
    let fvs_bytes = serde_json::to_vec(&artifact.fvs_validity)?;
    let source_bytes = serde_json::to_vec(&artifact.source_identity)?;
    Ok(json!({
        "graph": {
            "node_count": graph.node_count(),
            "edge_count": graph.edge_count(),
            "bytes": graph_bytes.len(),
            "sha256": sha256(&graph_bytes),
        },
        "artifact": {
            "bytes": artifact_bytes.len(),
            "sha256": sha256(&artifact_bytes),
            "members_hash": artifact.members_hash,
            "member_count": artifact.member_count,
        },
        "fvs": {
            "bytes": fvs_bytes.len(),
            "sha256": sha256(&fvs_bytes),
            "value": artifact.fvs_validity,
        },
        "source": {
            "bytes": source_bytes.len(),
            "sha256": sha256(&source_bytes),
            "value": artifact.source_identity,
        },
    }))
}

fn kernel_graph_artifact_bytes_match(
    graph: &astrolabe_kernel::KernelGraph,
    artifact: &astrolabe_kernel::KernelArtifact,
    expected_graph: &[u8],
    expected_artifact: &[u8],
    expected_fvs: &[u8],
    expected_source: &[u8],
) -> AnyResult<bool> {
    Ok(
        canonical_kernel_graph_bytes(graph)?.as_slice() == expected_graph
            && artifact.kernel_json_bytes().as_slice() == expected_artifact
            && serde_json::to_vec(&artifact.fvs_validity)?.as_slice() == expected_fvs
            && serde_json::to_vec(&artifact.source_identity)?.as_slice() == expected_source,
    )
}

fn verify_incremental_kernel_contracts(
    graph: &astrolabe_kernel::KernelGraph,
    artifact: &astrolabe_kernel::KernelArtifact,
) -> AnyResult<Value> {
    let before_graph_bytes = canonical_kernel_graph_bytes(graph)?;
    let before_artifact_bytes = artifact.kernel_json_bytes();
    let before_fvs_bytes = serde_json::to_vec(&artifact.fvs_validity)?;
    let before_source_bytes = serde_json::to_vec(&artifact.source_identity)?;
    let before = kernel_graph_artifact_state(graph, artifact)?;
    let first_node = graph
        .nodes()
        .first()
        .ok_or("ISSUE_1149_INCREMENTAL_REAL_GRAPH_EMPTY")?;
    let first_edge = graph
        .edges()
        .first()
        .ok_or("ISSUE_1149_INCREMENTAL_REAL_GRAPH_EDGELESS")?;
    let graph_ids = graph
        .nodes()
        .iter()
        .map(|node| node.id)
        .collect::<BTreeSet<_>>();
    let unknown_id = (0_u8..=u8::MAX)
        .map(|byte| CxId::from_bytes([byte; 16]))
        .find(|id| !graph_ids.contains(id))
        .ok_or("ISSUE_1149_INCREMENTAL_UNKNOWN_ID_UNAVAILABLE")?;
    let invalid_deltas = [
        (
            "kernel_delta_duplicate_frequency",
            astrolabe_kernel::GraphDelta {
                frequency_changes: vec![
                    (first_node.id, first_node.frequency),
                    (first_node.id, first_node.frequency),
                ],
                weight_changes: Vec::new(),
                structural: false,
            },
        ),
        (
            "kernel_delta_unknown_frequency",
            astrolabe_kernel::GraphDelta {
                frequency_changes: vec![(unknown_id, 1)],
                weight_changes: Vec::new(),
                structural: false,
            },
        ),
        (
            "kernel_delta_zero_frequency",
            astrolabe_kernel::GraphDelta {
                frequency_changes: vec![(first_node.id, 0)],
                weight_changes: Vec::new(),
                structural: false,
            },
        ),
        (
            "kernel_delta_nonfinite_weight",
            astrolabe_kernel::GraphDelta {
                frequency_changes: Vec::new(),
                weight_changes: vec![(first_edge.src, first_edge.dst, f32::NAN)],
                structural: false,
            },
        ),
    ];
    let mut invalid_receipts = Vec::new();
    for (case, delta) in invalid_deltas {
        println!(
            "{}",
            serde_json::to_string(&json!({"case":case,"phase":"before","state":before}))?
        );
        let error = match delta.apply(graph) {
            Err(error) => error,
            Ok(updated) => {
                return Err(format!(
                    "ISSUE_1149_INCREMENTAL_DELTA_UNEXPECTED_SUCCESS: case={case}; updated_graph_sha256={}",
                    sha256(&canonical_kernel_graph_bytes(&updated)?),
                )
                .into());
            }
        };
        let after = kernel_graph_artifact_state(graph, artifact)?;
        println!(
            "{}",
            serde_json::to_string(&json!({"case":case,"phase":"after","state":after}))?
        );
        require(
            error.code() == astrolabe_kernel::ASTRO_KERNEL_DELTA_INVALID
                && !error.message().trim().is_empty()
                && !error.remediation().trim().is_empty()
                && after == before
                && kernel_graph_artifact_bytes_match(
                    graph,
                    artifact,
                    &before_graph_bytes,
                    &before_artifact_bytes,
                    &before_fvs_bytes,
                    &before_source_bytes,
                )?,
            "ISSUE_1149_INCREMENTAL_DELTA_REFUSAL_INVALID",
            json!({"case":case,"error":error.to_string(),"before":before,"after":after}),
        )?;
        invalid_receipts.push(json!({
            "case": case,
            "code": error.code(),
            "message": error.message(),
            "remediation": error.remediation(),
            "before": before,
            "after": after,
            "graph_and_artifact_bytes_unchanged": true,
        }));
    }

    let betweenness = astrolabe_kernel::kernel_betweenness_cache(graph, &artifact.config)?;
    let structural_patch = astrolabe_kernel::GraphDelta {
        frequency_changes: vec![(first_node.id, first_node.frequency)],
        weight_changes: Vec::new(),
        structural: true,
    };
    let structural_patch_case = "kernel_delta_structural_with_patch";
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":structural_patch_case,"phase":"before","state":before})
        )?
    );
    let structural_patch_result = astrolabe_kernel::rebuild_dirty(
        graph,
        &structural_patch,
        &betweenness,
        &artifact.config,
        &artifact.scope_id,
    );
    let structural_patch_error = match structural_patch_result {
        Err(error) => error,
        Ok((rebuilt, report)) => {
            return Err(format!(
                "ISSUE_1149_INCREMENTAL_STRUCTURAL_PATCH_UNEXPECTED_SUCCESS: artifact_sha256={}; report={report:?}",
                sha256(&rebuilt.kernel_json_bytes()),
            )
            .into());
        }
    };
    let structural_patch_after = kernel_graph_artifact_state(graph, artifact)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":structural_patch_case,"phase":"after","state":structural_patch_after})
        )?
    );
    require(
        structural_patch_error.code() == astrolabe_kernel::ASTRO_KERNEL_DELTA_INVALID
            && structural_patch_after == before
            && kernel_graph_artifact_bytes_match(
                graph,
                artifact,
                &before_graph_bytes,
                &before_artifact_bytes,
                &before_fvs_bytes,
                &before_source_bytes,
            )?,
        "ISSUE_1149_INCREMENTAL_STRUCTURAL_PATCH_REFUSAL_INVALID",
        json!({
            "error": structural_patch_error.to_string(),
            "before": before,
            "after": structural_patch_after,
        }),
    )?;

    let structural_rebuild_case = "kernel_delta_structural_empty_patch_full_rebuild";
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":structural_rebuild_case,"phase":"before","state":before})
        )?
    );
    let structural_rebuild_delta = astrolabe_kernel::GraphDelta {
        frequency_changes: Vec::new(),
        weight_changes: Vec::new(),
        structural: true,
    };
    let (rebuilt, rebuild_report) = astrolabe_kernel::rebuild_dirty(
        graph,
        &structural_rebuild_delta,
        &betweenness,
        &artifact.config,
        &artifact.scope_id,
    )?;
    let rebuilt_state = kernel_graph_artifact_state(graph, &rebuilt)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":structural_rebuild_case,"phase":"after","state":rebuilt_state})
        )?
    );
    require(
        &rebuilt == artifact
            && rebuilt.kernel_json_bytes() == artifact.kernel_json_bytes()
            && serde_json::to_vec(&rebuilt.fvs_validity)?
                == serde_json::to_vec(&artifact.fvs_validity)?
            && serde_json::to_vec(&rebuilt.source_identity)?
                == serde_json::to_vec(&artifact.source_identity)?
            && rebuilt_state == before
            && rebuild_report.escalated
            && !rebuild_report.betweenness_reused
            && rebuild_report.affected_scc_count == rebuild_report.total_scc_count
            && rebuild_report.reprocessed_scc_count == rebuild_report.total_scc_count
            && rebuild_report.dirty_scc_ids
                == (0..rebuild_report.total_scc_count).collect::<Vec<_>>(),
        "ISSUE_1149_INCREMENTAL_STRUCTURAL_REBUILD_MISMATCH",
        json!({
            "before": before,
            "rebuilt": rebuilt_state,
            "report": {
                "escalated": rebuild_report.escalated,
                "betweenness_reused": rebuild_report.betweenness_reused,
                "dirty_scc_ids": rebuild_report.dirty_scc_ids,
                "affected_scc_count": rebuild_report.affected_scc_count,
                "reprocessed_scc_count": rebuild_report.reprocessed_scc_count,
                "total_scc_count": rebuild_report.total_scc_count,
            },
        }),
    )?;

    let blank_region_case = "kernel_region_blank_name";
    println!(
        "{}",
        serde_json::to_string(&json!({"case":blank_region_case,"phase":"before","state":before}))?
    );
    let blank_region_error =
        match astrolabe_kernel::build_region_graph(graph, &|_| " \t".to_string()) {
            Err(error) => error,
            Ok(region) => {
                return Err(format!(
                    "ISSUE_1149_REGION_BLANK_UNEXPECTED_SUCCESS: region_nodes={} region_edges={}",
                    region.graph.node_count(),
                    region.graph.edge_count(),
                )
                .into());
            }
        };
    let blank_region_after = kernel_graph_artifact_state(graph, artifact)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":blank_region_case,"phase":"after","state":blank_region_after})
        )?
    );
    require(
        blank_region_error.code() == astrolabe_kernel::ASTRO_KERNEL_REGION_GRAPH_INVALID
            && blank_region_after == before
            && kernel_graph_artifact_bytes_match(
                graph,
                artifact,
                &before_graph_bytes,
                &before_artifact_bytes,
                &before_fvs_bytes,
                &before_source_bytes,
            )?,
        "ISSUE_1149_REGION_BLANK_REFUSAL_INVALID",
        &blank_region_error,
    )?;

    let missing_endpoint_case = "kernel_region_missing_endpoint_admission";
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":missing_endpoint_case,"phase":"before","state":before})
        )?
    );
    let mut invalid_edges = graph.edges().to_vec();
    invalid_edges.push(astrolabe_kernel::KernelGraphEdge::new(
        first_node.id,
        unknown_id,
        1.0,
    ));
    let missing_endpoint_error =
        match astrolabe_kernel::KernelGraph::new(graph.nodes().to_vec(), invalid_edges) {
            Err(error) => error,
            Ok(invalid) => {
                return Err(format!(
                "ISSUE_1149_REGION_MISSING_ENDPOINT_UNEXPECTED_SUCCESS: invalid_graph_sha256={}",
                sha256(&canonical_kernel_graph_bytes(&invalid)?),
            )
            .into());
            }
        };
    let missing_endpoint_after = kernel_graph_artifact_state(graph, artifact)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":missing_endpoint_case,"phase":"after","state":missing_endpoint_after})
        )?
    );
    require(
        missing_endpoint_error.code() == astrolabe_kernel::ASTRO_KERNEL_GRAPH_INVALID
            && missing_endpoint_after == before
            && kernel_graph_artifact_bytes_match(
                graph,
                artifact,
                &before_graph_bytes,
                &before_artifact_bytes,
                &before_fvs_bytes,
                &before_source_bytes,
            )?,
        "ISSUE_1149_REGION_MISSING_ENDPOINT_ADMISSION_INVALID",
        &missing_endpoint_error,
    )?;

    Ok(json!({
        "schema": "astrolabe.issue-1149.incremental-kernel-real-graph-fsv.v1",
        "real_graph_source_state": before,
        "invalid_apply": invalid_receipts,
        "structural_nonempty_patch": {
            "code": structural_patch_error.code(),
            "message": structural_patch_error.message(),
            "remediation": structural_patch_error.remediation(),
            "before": before,
            "after": structural_patch_after,
            "graph_and_artifact_bytes_unchanged": true,
        },
        "structural_empty_patch_rebuild": {
            "report": {
                "escalated": rebuild_report.escalated,
                "betweenness_reused": rebuild_report.betweenness_reused,
                "dirty_scc_ids": rebuild_report.dirty_scc_ids,
                "affected_scc_count": rebuild_report.affected_scc_count,
                "reprocessed_scc_count": rebuild_report.reprocessed_scc_count,
                "total_scc_count": rebuild_report.total_scc_count,
            },
            "before": before,
            "after": rebuilt_state,
            "full_artifact_fvs_source_bytes_equal": true,
        },
        "region_blank_name": {
            "code": blank_region_error.code(),
            "message": blank_region_error.message(),
            "remediation": blank_region_error.remediation(),
            "before": before,
            "after": blank_region_after,
            "graph_and_artifact_bytes_unchanged": true,
        },
        "region_missing_endpoint": {
            "code": missing_endpoint_error.code(),
            "message": missing_endpoint_error.message(),
            "remediation": missing_endpoint_error.remediation(),
            "admission_layer": "KernelGraph::new",
            "build_region_graph_invoked": false,
            "reason": "KernelGraph is validated at construction, so a missing-endpoint value cannot exist for build_region_graph; bypassing that type invariant would fabricate an impossible production state",
            "before": before,
            "after": missing_endpoint_after,
            "graph_and_artifact_bytes_unchanged": true,
        },
        "betweenness_cache": betweenness,
        "fixture_scale_only_not_production_cost_evidence": true,
    }))
}

fn verify_complete_kernel_generation(
    cache: &Path,
    project: &str,
    expected_admission: &Value,
    persisted_receipt: &Value,
) -> AnyResult<Value> {
    let (vault, vault_dir) = open_kernel_generation_readback_vault(cache, project)?;
    let snapshot = vault.latest_seq();
    let scope_id = format!("repo:{project}");
    let current = astrolabe_weave::read_current_kernel_generation(&vault, project, &scope_id)?
        .ok_or("ISSUE_1148_CURRENT_KERNEL_GENERATION_MISSING")?;
    let projection = astrolabe_ingest::read_graph_projection_csr_at(
        &vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        snapshot,
    )?
    .ok_or("ISSUE_1148_KERNEL_GRAPH_PROJECTION_MISSING")?;
    let projection_readback = astrolabe_ingest::verify_composite_kernel_projection(&vault)?;
    require(
        projection_readback.csr_present
            && projection_readback.snapshot_seq == snapshot
            && projection_readback.node_count == projection.nodes.len()
            && projection_readback.edge_count == projection.edges.len()
            && projection_readback.source_fingerprint_blake3
                == hex_lower(&projection.source_fingerprint_blake3),
        "ISSUE_1149_KERNEL_GRAPH_PHYSICAL_REBUILD_MISMATCH",
        json!({
            "persisted_projection": projection,
            "independent_readback": projection_readback,
        }),
    )?;
    let anchor_trust = astrolabe_anchors::effective_anchor_trust_map_at(&vault, snapshot)?;
    let graph = astrolabe_ingest::kernel_graph_from_projection_csr(&projection, &anchor_trust)?;
    astrolabe_kernel::verify_kernel_source_projection_identity(
        &graph,
        &current.artifact.config,
        &current.artifact.source_identity,
    )?;
    let source_identity =
        astrolabe_kernel::kernel_source_identity(&graph, &current.artifact.config)?;
    require(
        source_identity == current.artifact.source_identity,
        "ISSUE_1149_KERNEL_SOURCE_IDENTITY_READBACK_MISMATCH",
        json!({
            "persisted": current.artifact.source_identity,
            "recomputed": source_identity,
        }),
    )?;
    let trusted_anchor_count = anchor_trust
        .values()
        .filter(|tag| matches!(tag, astrolabe_anchors::TrustTag::Trusted))
        .count();
    let physical_source_identity_readback = json!({
        "schema": "astrolabe.kernel_source_readback.v1",
        "read_snapshot_seq": snapshot,
        "source_identity": source_identity,
        "projection_source_fingerprint_blake3": hex_lower(&projection.source_fingerprint_blake3),
        "verified": true,
    });

    let mut graph_node_ids = graph.nodes().iter().map(|node| node.id).collect::<Vec<_>>();
    graph_node_ids.sort_unstable();
    require(
        !graph_node_ids.is_empty()
            && graph_node_ids.windows(2).all(|pair| pair[0] < pair[1])
            && graph_node_ids.len() == current.artifact.node_count,
        "ISSUE_1148_KERNEL_GRAPH_ROSTER_INVALID",
        json!({
            "graph_nodes": graph_node_ids.len(),
            "artifact_nodes": current.artifact.node_count,
        }),
    )?;
    let complete_vectors = astrolabe_weave::read_complete_kernel_s20_vectors_at(
        &vault,
        &vault_dir,
        current.manifest.panel_version,
        &graph_node_ids,
        &current.manifest.source_binding,
        current.manifest.semantic_dim,
        snapshot,
    )?;
    let graph_queries = current.query_corpus.graph_routed_queries();
    astrolabe_kernel::validate_graph_routed_recall_report(
        &current.graph_routed_report,
        &graph,
        &current.artifact,
        &complete_vectors,
        &graph_queries,
        &current.query_corpus.params,
    )?;
    astrolabe_weave::validate_kernel_recall_query_corpus_encoder(&current.query_corpus)?;

    let expected_query_rows = expected_admission["queries"]
        .as_array()
        .ok_or("ISSUE_1148_EXPECTED_QUERY_ROSTER_INVALID")?;
    let expected_queries = expected_query_rows
        .iter()
        .map(|row| {
            Ok((
                row["stable_id"]
                    .as_str()
                    .ok_or("expected query stable_id missing")?
                    .to_string(),
                (
                    row["source"]
                        .as_str()
                        .ok_or("expected query source missing")?
                        .to_string(),
                    row["content"]
                        .as_str()
                        .ok_or("expected query content missing")?
                        .to_string(),
                ),
            ))
        })
        .collect::<AnyResult<BTreeMap<_, _>>>()?;
    let persisted_queries = current
        .query_corpus
        .queries
        .iter()
        .map(|row| {
            (
                row.stable_id.clone(),
                (row.source.clone(), row.content.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expected_params = expected_admission
        .get("params")
        .ok_or("ISSUE_1148_EXPECTED_PARAMS_MISSING")?;
    let persisted_params = serde_json::to_value(&current.query_corpus.params)?;
    require(
        expected_queries == persisted_queries
            && persisted_params == *expected_params
            && current.query_corpus.queries.len() == 2
            && current.query_corpus.slot == astrolabe_weave::SLOT_NAME_SEMANTIC.get()
            && current.query_corpus.encoder.vector_dimension == 768
            && current.query_corpus.encoder.slot == astrolabe_weave::SLOT_NAME_SEMANTIC.get(),
        "ISSUE_1148_REAL_QUERY_CORPUS_READBACK_MISMATCH",
        json!({
            "expected_queries": expected_queries,
            "persisted_queries": persisted_queries,
            "expected_params": expected_params,
            "persisted_params": persisted_params,
            "corpus": current.query_corpus,
        }),
    )?;

    let artifact_member_ids = current
        .artifact
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    let binding_member_ids = current
        .index
        .bindings
        .iter()
        .map(|binding| binding.cx_id)
        .collect::<Vec<_>>();
    let manifest_logical_rows = current
        .manifest
        .rows
        .iter()
        .map(|row| row.logical_name.as_str())
        .collect::<BTreeSet<_>>();
    let expected_logical_rows = BTreeSet::from([
        "graph-routed-recall.json",
        "index.json",
        "kernel.json",
        "member-bindings.json",
        "member-descriptor.json",
        "members-hash",
        "real-query-corpus.json",
        "s20.hnsw",
    ]);
    let planned_exact = current
        .query_corpus
        .queries
        .len()
        .checked_mul(graph_node_ids.len())
        .ok_or("ISSUE_1148_EXACT_WORK_OVERFLOW")?;
    require(
        current.rows_verified == 18
            && current.artifact.fvs_count > 0
            && current.artifact.fvs_count == current.artifact.member_count
            && current.artifact.fvs_validity.method == astrolabe_kernel::FVS_VALIDITY_METHOD
            && current.artifact.fvs_validity.cyclic_scc_count > 0
            && current.artifact.fvs_validity.largest_cyclic_scc_node_count >= 2
            && current.artifact.fvs_validity.dfs_back_edge_count > 0
            && current.artifact.fvs_validity.residual_node_count + current.artifact.member_count
                == current.artifact.node_count
            && current.artifact.compactness.admitted
            && artifact_member_ids == binding_member_ids
            && current.index.descriptor.member_count == current.artifact.member_count
            && current.index.descriptor.indexed_member_count == current.artifact.member_count
            && current.index.descriptor.binding_count == current.artifact.member_count
            && current.index.descriptor.missing_vector_members.is_empty()
            && current.index.descriptor.semantic_dim == Some(current.manifest.semantic_dim)
            && current.index.descriptor.source_binding == current.manifest.source_binding
            && current.manifest.member_count == current.artifact.member_count
            && current.manifest.binding_count == current.artifact.member_count
            && current.manifest.indexed_member_count == current.artifact.member_count
            && current.manifest.rows.len() == expected_logical_rows.len()
            && manifest_logical_rows == expected_logical_rows
            && current.pointer.current.generation_id == current.manifest.generation_id
            && current.pointer.current.commit_seq == current.manifest.base_seq + 1
            && current.pointer.current.ledger_ref == current.manifest.ledger_ref
            && current.graph_routed_report.admitted
            && current.graph_routed_report.compactness_admitted
            && current.graph_routed_report.recall_permille == 1000
            && current.graph_routed_report.node_count == graph_node_ids.len()
            && current.graph_routed_report.vector_dimension
                == usize::try_from(current.manifest.semantic_dim)?
            && current.graph_routed_report.kernel_member_count == artifact_member_ids.len()
            && current.graph_routed_report.entry_member_ids == artifact_member_ids
            && current.graph_routed_report.queries.len() == graph_queries.len()
            && current
                .graph_routed_report
                .total_exact_distance_computations
                == planned_exact
            && complete_vectors.len() == graph_node_ids.len(),
        "ISSUE_1148_1149_COMPOSITE_KERNEL_READBACK_MISMATCH",
        json!({
            "artifact": current.artifact,
            "descriptor": current.index.descriptor,
            "manifest": current.manifest,
            "pointer": current.pointer,
            "graph_routed_report": current.graph_routed_report,
            "physical_s20_rows": complete_vectors.len(),
        }),
    )?;

    let ledger_bytes = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Ledger,
            &ledger_key(current.manifest.ledger_ref.seq),
        )?
        .ok_or("ISSUE_1148_KERNEL_GENERATION_LEDGER_ROW_MISSING")?;
    let ledger_entry = calyx_ledger::decode(&ledger_bytes)?;
    let ledger_payload: Value = serde_json::from_slice(&ledger_entry.payload)?;
    let ledger_payload: Value = serde_json::from_slice(&ledger_entry.payload)?;
    let payload_blake3 = blake3::hash(&ledger_entry.payload).to_hex().to_string();
    let wanted_ledger_seqs = BTreeSet::from([current.manifest.ledger_ref.seq]);
    let (physical_ledger_rows, physical_ledger_trace) =
        vault.read_physical_ledger_seqs(&wanted_ledger_seqs)?;
    let physical_ledger_row = physical_ledger_rows
        .get(&current.manifest.ledger_ref.seq)
        .ok_or("ISSUE_1148_PHYSICAL_KERNEL_LEDGER_ROW_MISSING")?;
    let physical_ledger_tiers = physical_ledger_trace
        .tiers
        .iter()
        .map(|tier| tier.tier.to_string())
        .collect::<Vec<_>>();
    require(
        ledger_entry.verify()
            && ledger_entry.seq == current.manifest.ledger_ref.seq
            && ledger_entry.entry_hash == current.manifest.ledger_ref.hash
            && ledger_entry.kind == EntryKind::Kernel
            && matches!(&ledger_entry.actor, ActorId::Service(actor) if actor == astrolabe_weave::KERNEL_GENERATION_ACTOR)
            && matches!(&ledger_entry.subject, SubjectId::Kernel(subject) if !subject.is_empty())
            && payload_blake3 == current.manifest.ledger_payload_blake3
            && ledger_payload["schema"] == astrolabe_weave::KERNEL_GENERATION_LEDGER_SCHEMA
            && ledger_payload["project"] == project
            && ledger_payload["scope_id"] == scope_id
            && ledger_payload["generation_id"] == current.manifest.generation_id
            && ledger_payload["source_generation_identity"]
                == current.manifest.source_generation_identity
            && ledger_payload["query_corpus_hash"] == current.manifest.query_corpus_hash
            && ledger_payload["graph_routed_report_hash"]
                == current.manifest.graph_routed_report_hash
            && ledger_payload["rows"] == serde_json::to_value(&current.manifest.rows)?
            && physical_ledger_row.seq == ledger_entry.seq
            && physical_ledger_row.bytes == ledger_bytes,
        "ISSUE_1148_KERNEL_GENERATION_LEDGER_READBACK_MISMATCH",
        json!({
            "ledger_ref": current.manifest.ledger_ref,
            "entry": ledger_entry,
            "payload": ledger_payload,
            "payload_blake3": payload_blake3,
            "physical_tiers": physical_ledger_tiers,
            "physical_row_bytes": physical_ledger_row.bytes.len(),
        }),
    )?;

    let receipt_readback_rows = persisted_receipt["readback_rows"]
        .as_array()
        .ok_or("ISSUE_1148_KERNEL_RECEIPT_READBACK_ROWS_INVALID")?;
    let mut physical_commit_rows = Vec::with_capacity(receipt_readback_rows.len());
    for row in receipt_readback_rows {
        let key_hex = row["key_hex"]
            .as_str()
            .ok_or("ISSUE_1148_KERNEL_RECEIPT_ROW_KEY_INVALID")?;
        let expected_bytes = row["bytes"]
            .as_u64()
            .ok_or("ISSUE_1148_KERNEL_RECEIPT_ROW_BYTES_INVALID")?;
        let expected_blake3 = row["blake3"]
            .as_str()
            .ok_or("ISSUE_1148_KERNEL_RECEIPT_ROW_BLAKE3_INVALID")?;
        let expected_tombstoned = row["tombstoned"]
            .as_bool()
            .ok_or("ISSUE_1148_KERNEL_RECEIPT_ROW_TOMBSTONE_INVALID")?;
        let key = decode_hex(key_hex)?;
        let value = vault
            .read_cf_at(snapshot, ColumnFamily::Kernel, &key)?
            .ok_or("ISSUE_1148_KERNEL_RECEIPT_ROW_PHYSICALLY_MISSING")?;
        let observed_blake3 = blake3::hash(&value).to_hex().to_string();
        require(
            !expected_tombstoned
                && u64::try_from(value.len())? == expected_bytes
                && observed_blake3 == expected_blake3,
            "ISSUE_1148_KERNEL_RECEIPT_ROW_PHYSICAL_MISMATCH",
            json!({
                "receipt": row,
                "observed_bytes": value.len(),
                "observed_blake3": observed_blake3,
            }),
        )?;
        physical_commit_rows.push(json!({
            "key_hex": key_hex,
            "bytes": value.len(),
            "blake3": observed_blake3,
            "tombstoned": false,
            "physical_point_read": true,
        }));
    }

    let artifact_json = serde_json::to_value(&current.artifact)?;
    let manifest_json = serde_json::to_value(&current.manifest)?;
    let pointer_json = serde_json::to_value(&current.pointer)?;
    let corpus_json = serde_json::to_value(&current.query_corpus)?;
    let report_json = serde_json::to_value(&current.graph_routed_report)?;
    let descriptor_json = serde_json::to_value(&current.index.descriptor)?;
    let expected_ledger_ref = json!({
        "seq": ledger_entry.seq,
        "entry_hash": hex_lower(&ledger_entry.entry_hash),
    });
    let expected_provenance = json!([
        format!("kernel-generation:{}", current.manifest.generation_id),
        "vault:ColumnFamily::Kernel+Ledger atomic pointer publication",
        "anchors:effective_anchor_trust_map_at(retained_snapshot)",
        "slot:S20 name_semantic complete KernelGraph roster",
        "astrolabe-kernel:graph_routed_recall(real_external_queries)",
    ]);
    require(
        persisted_receipt["published"] == Value::Bool(true)
            && persisted_receipt["scope_id"] == scope_id
            && persisted_receipt["generation_id"] == current.manifest.generation_id
            && persisted_receipt["source_generation_identity"]
                == current.manifest.source_generation_identity
            && persisted_receipt["members_hash"] == current.artifact.members_hash
            && persisted_receipt["member_count"] == u64::try_from(current.artifact.member_count)?
            && persisted_receipt["node_count"] == u64::try_from(current.artifact.node_count)?
            && persisted_receipt["graph_coverage"] == artifact_json["graph_coverage"]
            && persisted_receipt["compactness"] == artifact_json["compactness"]
            && persisted_receipt["fvs_validity"] == artifact_json["fvs_validity"]
            && persisted_receipt["anchor_grounded"] == artifact_json["anchor_grounded"]
            && persisted_receipt["source_identity"] == artifact_json["source_identity"]
            && exact_json_object_fields(
                &persisted_receipt["source_identity_readback"],
                &[
                    "schema",
                    "read_snapshot_seq",
                    "source_identity",
                    "projection_source_fingerprint_blake3",
                    "verified",
                ],
            )
            && persisted_receipt["source_identity_readback"]["schema"]
                == "astrolabe.kernel_source_readback.v1"
            && persisted_receipt["source_identity_readback"]["read_snapshot_seq"]
                .as_u64()
                .is_some_and(|readback_seq| {
                    readback_seq >= current.pointer.current.commit_seq && readback_seq <= snapshot
                })
            && persisted_receipt["source_identity_readback"]["source_identity"]
                == artifact_json["source_identity"]
            && persisted_receipt["source_identity_readback"]["projection_source_fingerprint_blake3"]
                == physical_source_identity_readback["projection_source_fingerprint_blake3"]
            && persisted_receipt["source_identity_readback"]["verified"] == Value::Bool(true)
            && persisted_receipt["trusted_anchor_count"] == u64::try_from(trusted_anchor_count)?
            && persisted_receipt["manifest"] == manifest_json
            && persisted_receipt["pointer"] == pointer_json
            && persisted_receipt["rows_readback_verified"]
                == u64::try_from(receipt_readback_rows.len())?
            && persisted_receipt["rows_readback_verified"] == 18
            && persisted_receipt["readback_rows"]
                == serde_json::to_value(
                    physical_commit_rows
                        .iter()
                        .map(|row| {
                            json!({
                                "key_hex": row["key_hex"],
                                "bytes": row["bytes"],
                                "blake3": row["blake3"],
                                "tombstoned": row["tombstoned"],
                            })
                        })
                        .collect::<Vec<_>>(),
                )?
            && persisted_receipt["query_admission"]["corpus_reused"] == Value::Bool(false)
            && persisted_receipt["query_admission"]["corpus"] == corpus_json
            && persisted_receipt["query_admission"]["graph_routed_report"] == report_json
            && persisted_receipt["member_index"]["descriptor"] == descriptor_json
            && persisted_receipt["member_index"]["binding_count"]
                == u64::try_from(current.index.bindings.len())?
            && persisted_receipt["decoded_rows_verified"] == u64::try_from(current.rows_verified)?
            && persisted_receipt["ledger_paired"] == Value::Bool(true)
            && persisted_receipt["commit_seq"] == current.pointer.current.commit_seq
            && persisted_receipt["ledger_ref"] == expected_ledger_ref
            && persisted_receipt["ledger_physical_tiers"]
                == serde_json::to_value(&physical_ledger_tiers)?
            && persisted_receipt["retired_generation_id"] == Value::Null
            && persisted_receipt["flush"]["sst_files"]
                .as_u64()
                .is_some_and(|value| value > 0)
            && persisted_receipt["flush"]["sst_entries"]
                .as_u64()
                .is_some_and(|value| value > 0)
            && persisted_receipt["flush"]["sst_bytes"]
                .as_u64()
                .is_some_and(|value| value > 0)
            && persisted_receipt["trust"] == artifact_json["trust"]
            && persisted_receipt["freshness"] == "fresh"
            && persisted_receipt["provenance"] == expected_provenance,
        "ISSUE_1148_KERNEL_PUBLISH_RECEIPT_PHYSICAL_MISMATCH",
        json!({
            "persisted_receipt": persisted_receipt,
            "artifact": artifact_json,
            "manifest": manifest_json,
            "pointer": pointer_json,
            "corpus": corpus_json,
            "report": report_json,
            "descriptor": descriptor_json,
            "physical_source_identity_readback": physical_source_identity_readback,
            "expected_ledger_ref": expected_ledger_ref,
            "physical_ledger_tiers": physical_ledger_tiers,
            "physical_commit_rows": physical_commit_rows,
        }),
    )?;

    let incremental_kernel = verify_incremental_kernel_contracts(&graph, &current.artifact)?;

    let s20_rows = complete_vectors
        .iter()
        .map(|(cx_id, vector)| {
            json!({
                "cx_id": cx_id,
                "dimension": vector.len(),
                "vector_bits_sha256": vector_bits_sha256(vector),
                "finite": vector.iter().all(|value| value.is_finite()),
                "nonzero": vector.iter().any(|value| *value != 0.0),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema": "astrolabe.issues-980-1148-1149.kernel-physical-readback.v1",
        "snapshot": snapshot,
        "scope_id": scope_id,
        "generation_id": current.manifest.generation_id,
        "source_generation_identity": current.manifest.source_generation_identity,
        "projection_source_fingerprint_blake3": hex_lower(&projection.source_fingerprint_blake3),
        "projection_physical_readback": projection_readback,
        "source_identity_physical_readback": physical_source_identity_readback,
        "artifact": artifact_json,
        "manifest": manifest_json,
        "pointer": pointer_json,
        "query_corpus": corpus_json,
        "graph_routed_report": report_json,
        "member_index": {
            "descriptor": descriptor_json,
            "bindings": current.index.bindings,
            "hnsw_checksum_readback_verified": true,
        },
        "s20_complete_graph_roster": {
            "graph_node_count": graph_node_ids.len(),
            "physical_vector_count": complete_vectors.len(),
            "vector_dimension": current.manifest.semantic_dim,
            "vector_roster_hash": current.graph_routed_report.vector_roster_hash,
            "rows": s20_rows,
            "independent_report_rebuild_equal": true,
        },
        "ledger": {
            "seq": ledger_entry.seq,
            "entry_hash": hex_lower(&ledger_entry.entry_hash),
            "row_bytes": ledger_bytes.len(),
            "row_sha256": sha256(&ledger_bytes),
            "payload_blake3": payload_blake3,
            "payload": ledger_payload,
            "physical_point_read": true,
            "physical_tiers": physical_ledger_tiers,
        },
        "publication_commit_rows": physical_commit_rows,
        "incremental_kernel": incremental_kernel,
        "persisted_weave_receipt_sha256": sha256(&serde_json::to_vec(persisted_receipt)?),
        "composite_rows_decoded_and_verified": current.rows_verified,
        "source_identity_recomputed": true,
        "query_encoder_recomputed": true,
        "fvs_residual_dag_proof_read_back": true,
    }))
}

fn sqlite_counts(cache: &Path, project: &str) -> AnyResult<Value> {
    let path = cache.join(format!("{project}.db"));
    let connection = readonly_sqlite(&path)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    require(
        integrity == "ok",
        "ISSUE_1116_1119_SQLITE_INTEGRITY_FAILED",
        json!({"path": path, "integrity": integrity}),
    )?;
    let semantic_project = read_moderate_semantic_project_state(&connection, project)?;
    let count = |table: &str| -> AnyResult<u64> {
        let sql = match table {
            "nodes" => "SELECT COUNT(*) FROM nodes",
            "edges" => "SELECT COUNT(*) FROM edges",
            "node_vectors" => "SELECT COUNT(*) FROM node_vectors",
            "token_vectors" => "SELECT COUNT(*) FROM token_vectors",
            _ => return Err(format!("unknown count table {table}").into()),
        };
        let count: i64 = connection.query_row(sql, [], |row| row.get(0))?;
        require(
            count >= 0,
            "ISSUE_1116_1119_SQLITE_NEGATIVE_COUNT",
            format!("table={table}; count={count}"),
        )?;
        u64::try_from(count).map_err(|error| {
            format!("ISSUE_1116_1119_SQLITE_COUNT_OVERFLOW: table={table}; {error}").into()
        })
    };
    Ok(json!({
        "integrity": integrity,
        "nodes": count("nodes")?,
        "edges": count("edges")?,
        "node_vectors": count("node_vectors")?,
        "token_vectors": count("token_vectors")?,
        "project": semantic_project_state_json(&semantic_project),
        "file": optional_file_state(&path)?,
    }))
}

fn sqlite_cluster_source_state(cache: &Path, project: &str) -> AnyResult<Value> {
    let path = cache.join(format!("{project}.db"));
    let connection = readonly_sqlite(&path)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let project_row_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM projects WHERE name = ?1",
        [project],
        |row| row.get(0),
    )?;
    let total_edge_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM edges WHERE project = ?1",
        [project],
        |row| row.get(0),
    )?;
    let raw_cluster_edge_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM edges WHERE project = ?1 AND type IN ('CALLS','IMPORTS')",
        [project],
        |row| row.get(0),
    )?;
    let orphan_cluster_edge_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM edges AS edge \
         LEFT JOIN nodes AS source ON source.id = edge.source_id AND source.project = edge.project \
         LEFT JOIN nodes AS target ON target.id = edge.target_id AND target.project = edge.project \
         WHERE edge.project = ?1 AND edge.type IN ('CALLS','IMPORTS') \
           AND (source.id IS NULL OR target.id IS NULL)",
        [project],
        |row| row.get(0),
    )?;
    let nodes = {
        let mut statement = connection.prepare(
            "SELECT id, atom_id, label, name, qualified_name, file_path \
             FROM nodes WHERE project = ?1 ORDER BY atom_id, id",
        )?;
        statement
            .query_map([project], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let edges = {
        let mut statement = connection.prepare(
            "SELECT edge.id, source.atom_id, target.atom_id, edge.type \
             FROM edges AS edge \
             JOIN nodes AS source ON source.id = edge.source_id AND source.project = edge.project \
             JOIN nodes AS target ON target.id = edge.target_id AND target.project = edge.project \
             WHERE edge.project = ?1 AND edge.type IN ('CALLS','IMPORTS') \
             ORDER BY source.atom_id, target.atom_id, edge.type, edge.id",
        )?;
        statement
            .query_map([project], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let physical_labels = {
        let mut statement = connection
            .prepare("SELECT DISTINCT label FROM nodes WHERE project = ?1 ORDER BY label")?;
        statement
            .query_map([project], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };

    let node_count = u64::try_from(nodes.len())?;
    let total_edge_count = u64::try_from(total_edge_count)?;
    let raw_cluster_edge_count = u64::try_from(raw_cluster_edge_count)?;
    let orphan_cluster_edge_count = u64::try_from(orphan_cluster_edge_count)?;
    let project_row_count = u64::try_from(project_row_count)?;
    let atom_ids = nodes
        .iter()
        .map(|row| row.1.as_str())
        .collect::<BTreeSet<_>>();
    let distinct_node_names = nodes
        .iter()
        .map(|row| row.3.as_str())
        .collect::<BTreeSet<_>>();
    let distinct_qualified_names = nodes
        .iter()
        .map(|row| row.4.as_str())
        .collect::<BTreeSet<_>>();
    let derived_labels = nodes
        .iter()
        .map(|row| row.2.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let calls_edge_count = u64::try_from(
        edges
            .iter()
            .filter(|(_, _, _, edge_type)| edge_type == "CALLS")
            .count(),
    )?;
    let imports_edge_count = u64::try_from(
        edges
            .iter()
            .filter(|(_, _, _, edge_type)| edge_type == "IMPORTS")
            .count(),
    )?;
    require(
        integrity == "ok"
            && project_row_count == 1
            && node_count > 1
            && raw_cluster_edge_count > 0
            && calls_edge_count >= 2
            && calls_edge_count
                .checked_add(imports_edge_count)
                .is_some_and(|count| count == raw_cluster_edge_count)
            && u64::try_from(edges.len()).ok() == Some(raw_cluster_edge_count)
            && orphan_cluster_edge_count == 0
            && atom_ids.len() == nodes.len()
            && physical_labels == derived_labels
            && nodes
                .iter()
                .all(|(_, atom_id, label, name, qualified_name, _)| {
                    !atom_id.is_empty()
                        && !label.is_empty()
                        && !name.is_empty()
                        && !qualified_name.is_empty()
                })
            && edges.iter().all(|(_, source, target, edge_type)| {
                !source.is_empty()
                    && !target.is_empty()
                    && matches!(edge_type.as_str(), "CALLS" | "IMPORTS")
            }),
        "ISSUE_1149_CLUSTER_SQLITE_SOURCE_INVALID",
        json!({
            "path": path,
            "integrity": integrity,
            "project_row_count": project_row_count,
            "node_count": node_count,
            "total_edge_count": total_edge_count,
            "raw_cluster_edge_count": raw_cluster_edge_count,
            "calls_edge_count": calls_edge_count,
            "imports_edge_count": imports_edge_count,
            "orphan_cluster_edge_count": orphan_cluster_edge_count,
            "unique_atom_ids": atom_ids.len(),
            "distinct_names": distinct_node_names.len(),
            "distinct_qualified_names": distinct_qualified_names.len(),
            "physical_labels": physical_labels,
            "derived_labels": derived_labels,
        }),
    )?;

    let mut label_hash = Sha256::new();
    cluster_hash_text(&mut label_hash, "cbm.architecture.cluster.labels.v3");
    for label in &physical_labels {
        cluster_hash_text(&mut label_hash, label);
    }
    let node_label_roster_sha256 = finish_cluster_hash(label_hash);

    let mut source_hash = Sha256::new();
    cluster_hash_text(&mut source_hash, "cbm.architecture.cluster.source.v3");
    cluster_hash_text(&mut source_hash, project);
    cluster_hash_text(&mut source_hash, "");
    cluster_hash_u64(&mut source_hash, node_count);
    for (_, atom_id, label, name, qualified_name, file_path) in &nodes {
        cluster_hash_text(&mut source_hash, atom_id);
        cluster_hash_text(&mut source_hash, label);
        cluster_hash_text(&mut source_hash, name);
        cluster_hash_text(&mut source_hash, qualified_name);
        cluster_hash_text(&mut source_hash, file_path);
    }
    cluster_hash_u64(&mut source_hash, raw_cluster_edge_count);
    for (_, source, target, edge_type) in &edges {
        cluster_hash_text(&mut source_hash, source);
        cluster_hash_text(&mut source_hash, target);
        cluster_hash_text(&mut source_hash, edge_type);
    }
    let source_sha256 = finish_cluster_hash(source_hash);

    let mut canonical_edges = BTreeMap::<(String, String, String), u64>::new();
    for (_, source, target, edge_type) in &edges {
        let multiplicity = canonical_edges
            .entry((source.clone(), target.clone(), edge_type.clone()))
            .or_default();
        *multiplicity = multiplicity
            .checked_add(1)
            .ok_or("ISSUE_1149_CLUSTER_EDGE_MULTIPLICITY_OVERFLOW")?;
    }
    let canonical_typed_edge_count = u64::try_from(canonical_edges.len())?;
    let duplicate_edge_count = raw_cluster_edge_count
        .checked_sub(canonical_typed_edge_count)
        .ok_or("ISSUE_1149_CLUSTER_EDGE_ACCOUNTING_UNDERFLOW")?;
    let self_loop_count = u64::try_from(
        canonical_edges
            .keys()
            .filter(|(source, target, _)| source == target)
            .count(),
    )?;
    let mut projection_hash = Sha256::new();
    cluster_hash_text(
        &mut projection_hash,
        "cbm.architecture.cluster.projection.v3",
    );
    cluster_hash_text(&mut projection_hash, project);
    cluster_hash_text(&mut projection_hash, "");
    cluster_hash_u64(&mut projection_hash, node_count);
    for (_, atom_id, label, name, qualified_name, file_path) in &nodes {
        cluster_hash_text(&mut projection_hash, atom_id);
        cluster_hash_text(&mut projection_hash, label);
        cluster_hash_text(&mut projection_hash, name);
        cluster_hash_text(&mut projection_hash, qualified_name);
        cluster_hash_text(&mut projection_hash, file_path);
    }
    cluster_hash_u64(&mut projection_hash, canonical_typed_edge_count);
    for ((source, target, edge_type), multiplicity) in &canonical_edges {
        cluster_hash_text(&mut projection_hash, source);
        cluster_hash_text(&mut projection_hash, target);
        cluster_hash_text(&mut projection_hash, edge_type);
        cluster_hash_u64(&mut projection_hash, *multiplicity);
    }
    let projection_sha256 = finish_cluster_hash(projection_hash);

    let node_rows = nodes
        .into_iter()
        .map(
            |(sqlite_id, atom_id, label, name, qualified_name, file_path)| {
                json!({
                    "sqlite_id": sqlite_id,
                    "atom_id": atom_id,
                    "label": label,
                    "name": name,
                    "qualified_name": qualified_name,
                    "file_path": file_path,
                })
            },
        )
        .collect::<Vec<_>>();
    let edge_rows = edges
        .into_iter()
        .map(|(sqlite_id, source_atom_id, target_atom_id, edge_type)| {
            json!({
                "sqlite_id": sqlite_id,
                "source_atom_id": source_atom_id,
                "target_atom_id": target_atom_id,
                "type": edge_type,
            })
        })
        .collect::<Vec<_>>();
    let canonical_edge_rows = canonical_edges
        .into_iter()
        .map(
            |((source_atom_id, target_atom_id, edge_type), multiplicity)| {
                json!({
                    "source_atom_id": source_atom_id,
                    "target_atom_id": target_atom_id,
                    "type": edge_type,
                    "multiplicity": multiplicity,
                })
            },
        )
        .collect::<Vec<_>>();
    let projection_rows_sha256 = sha256(&serde_json::to_vec(&json!({
        "nodes": &node_rows,
        "raw_edges": &edge_rows,
        "canonical_edges": &canonical_edge_rows,
    }))?);
    drop(connection);
    Ok(json!({
        "schema": "astrolabe.issue-1149.cluster-sqlite-source.v1",
        "project": project,
        "path": path,
        "integrity": integrity,
        "project_row_count": project_row_count,
        "node_count": node_count,
        "total_edge_count": total_edge_count,
        "calls_edge_count": calls_edge_count,
        "imports_edge_count": imports_edge_count,
        "cluster_edge_count": raw_cluster_edge_count,
        "orphan_cluster_edge_count": orphan_cluster_edge_count,
        "canonical_typed_edge_count": canonical_typed_edge_count,
        "duplicate_edge_count": duplicate_edge_count,
        "self_loop_count": self_loop_count,
        "node_label_count": physical_labels.len(),
        "node_labels": physical_labels,
        "node_label_roster_sha256": node_label_roster_sha256,
        "source_sha256": source_sha256,
        "projection_sha256": projection_sha256,
        "projection_rows_sha256": projection_rows_sha256,
        "nodes": node_rows,
        "raw_edges": edge_rows,
        "canonical_edges": canonical_edge_rows,
        "file": optional_file_state(&path)?,
        "physical_sqlite_projection_read": true,
    }))
}

fn verify_fixture_sqlite_rows(cache: &Path, project: &str, repo: &Path) -> AnyResult<Value> {
    let connection = readonly_sqlite(&cache.join(format!("{project}.db")))?;
    let mut node_statement = connection.prepare(
        "SELECT name, qualified_name, label, file_path, source_present, source_bytes, source_sha256 \
         FROM nodes WHERE project = ?1 AND name IN \
         ('normalize','alpha_bridge','beta_bridge','route') ORDER BY name",
    )?;
    let nodes = node_statement
        .query_map([project], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_names = BTreeSet::from(["alpha_bridge", "beta_bridge", "normalize", "route"]);
    let observed_names = nodes
        .iter()
        .map(|row| row.0.as_str())
        .collect::<BTreeSet<_>>();
    require(
        nodes.len() == expected_names.len()
            && observed_names == expected_names
            && nodes.iter().all(
                |(name, qualified_name, label, file_path, source_present, source_bytes, digest)| {
                    *source_present == 1
                        && !qualified_name.trim().is_empty()
                        && !label.trim().is_empty()
                        && file_path.replace('\\', "/").ends_with("src/lib.rs")
                        && source_bytes.as_ref().is_some_and(|bytes| {
                            !bytes.is_empty()
                                && sha256(bytes) == *digest
                                && std::str::from_utf8(bytes)
                                    .is_ok_and(|text| text.contains(&format!("fn {name}")))
                        })
                },
            ),
        "ISSUE_1116_1119_FIXTURE_NODE_ROWS_MISMATCH",
        json!({"expected": expected_names, "observed": observed_names}),
    )?;

    let mut edge_statement = connection.prepare(
        "SELECT source.name, target.name, edges.type \
         FROM edges \
         JOIN nodes AS source ON source.id = edges.source_id \
         JOIN nodes AS target ON target.id = edges.target_id \
         WHERE edges.project = ?1 AND source.name = 'route' \
           AND target.name IN ('alpha_bridge','beta_bridge') \
         ORDER BY target.name, edges.type",
    )?;
    let edges = edge_statement
        .query_map([project], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_edges = BTreeSet::from([
        ("route", "alpha_bridge", "CALLS"),
        ("route", "beta_bridge", "CALLS"),
    ]);
    let observed_edges = edges
        .iter()
        .map(|(source, target, edge_type)| (source.as_str(), target.as_str(), edge_type.as_str()))
        .collect::<BTreeSet<_>>();
    require(
        edges.len() == expected_edges.len() && observed_edges == expected_edges,
        "ISSUE_1116_1119_FIXTURE_EDGE_ROWS_MISMATCH",
        json!({"expected": expected_edges, "observed": observed_edges}),
    )?;

    let mut cycle_statement = connection.prepare(
        "SELECT source.name, target.name, edges.type \
         FROM edges \
         JOIN nodes AS source ON source.id = edges.source_id \
         JOIN nodes AS target ON target.id = edges.target_id \
         WHERE edges.project = ?1 AND source.name IN ('cycle_left','cycle_right') \
           AND target.name IN ('cycle_left','cycle_right') \
         ORDER BY source.name, target.name, edges.type",
    )?;
    let cycle_edges = cycle_statement
        .query_map([project], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_cycle_edges = BTreeSet::from([
        ("cycle_left", "cycle_right", "CALLS"),
        ("cycle_right", "cycle_left", "CALLS"),
    ]);
    let observed_cycle_edges = cycle_edges
        .iter()
        .map(|(source, target, edge_type)| (source.as_str(), target.as_str(), edge_type.as_str()))
        .collect::<BTreeSet<_>>();
    require(
        cycle_edges.len() == expected_cycle_edges.len()
            && observed_cycle_edges == expected_cycle_edges,
        "ISSUE_1149_FIXTURE_CYCLE_EDGE_ROWS_MISMATCH",
        json!({"expected": expected_cycle_edges, "observed": observed_cycle_edges}),
    )?;

    let (file_digest, file_size): (String, i64) = connection.query_row(
        "SELECT sha256, size FROM file_hashes WHERE project = ?1 AND rel_path = 'src/lib.rs'",
        [project],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (source_size, source_digest) = file_sha256(&repo.join("src/lib.rs"))?;
    require(
        file_size >= 0
            && u64::try_from(file_size).ok() == Some(source_size)
            && file_digest == source_digest,
        "ISSUE_1116_1119_FIXTURE_FILE_HASH_ROW_MISMATCH",
        json!({
            "db_sha256": file_digest,
            "db_size": file_size,
            "source_sha256": source_digest,
            "source_size": source_size,
        }),
    )?;
    Ok(json!({
        "nodes": nodes
            .into_iter()
            .map(|(name, qualified_name, label, file_path, _, source_bytes, source_sha256)| json!({
                "name": name,
                "qualified_name": qualified_name,
                "label": label,
                "file_path": file_path,
                "source_bytes": source_bytes.as_ref().map(Vec::len),
                "source_sha256": source_sha256,
            }))
            .collect::<Vec<_>>(),
        "edges": edges
            .into_iter()
            .map(|(source, target, edge_type)| json!({
                "source": source,
                "target": target,
                "type": edge_type,
            }))
            .collect::<Vec<_>>(),
        "cycle_edges": cycle_edges
            .into_iter()
            .map(|(source, target, edge_type)| json!({
                "source": source,
                "target": target,
                "type": edge_type,
            }))
            .collect::<Vec<_>>(),
        "file_hash": {
            "rel_path": "src/lib.rs",
            "bytes": source_size,
            "sha256": source_digest,
        },
        "known_input_expected_output_verified": true,
    }))
}

fn fixture_changed_symbol(cache: &Path, project: &str) -> AnyResult<Value> {
    let connection = readonly_sqlite(&cache.join(format!("{project}.db")))?;
    let mut statement = connection.prepare(
        "SELECT id, atom_id, name, qualified_name, label, file_path \
         FROM nodes WHERE project = ?1 AND name = 'normalize' ORDER BY id",
    )?;
    let rows = statement
        .query_map([project], |row| {
            Ok(json!({
                "node_id":row.get::<_, i64>(0)?,
                "atom_id":row.get::<_, String>(1)?,
                "name":row.get::<_, String>(2)?,
                "qualified_name":row.get::<_, String>(3)?,
                "label":row.get::<_, String>(4)?,
                "file":row.get::<_, String>(5)?.replace('\\', "/"),
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let [symbol] = rows.as_slice() else {
        return Err(format!(
            "ISSUE_1116_1119_CHANGED_SYMBOL_CARDINALITY: expected one normalize node, observed {}",
            rows.len()
        )
        .into());
    };
    require(
        symbol["node_id"].as_i64().is_some_and(|value| value > 0)
            && symbol["atom_id"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && symbol["qualified_name"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && symbol["label"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && symbol["file"] == "src/lib.rs",
        "ISSUE_1116_1119_CHANGED_SYMBOL_IDENTITY_INVALID",
        symbol,
    )?;
    Ok(symbol.clone())
}

fn physical_state(cache: &Path, project: &str) -> AnyResult<Value> {
    let (_, vault_dir, _, _) = vault_identity(cache, project)?;
    let sqlite = sqlite_counts(cache, project)?;
    let (vault, _) = open_vault(cache, project)?;
    let snapshot = vault.latest_seq();
    let complete = read_complete_association_state_at(&vault, snapshot)?;
    drop(vault);
    let search_manifest = cache.join(format!("{project}.astrolabe-search-index.v2.json"));
    let config_db = optional_file_state(&cache.join("_config.db"))?;
    let lowered_db = optional_file_state(&cache.join(format!("{project}.astrolabe-lowered.db")))?;
    let ledger_head = optional_file_state(&vault_dir.join("ledger_head").join("current.json"))?;
    let current = optional_file_state(&vault_dir.join("CURRENT"))?;
    let search_manifest_state = optional_file_state(&search_manifest)?;
    let vault_tree = tree_state(&vault_dir)?;
    let cache_tree = tree_state(cache)?;
    let state = json!({
        "config_db": config_db,
        "cache_tree": cache_tree,
        "sqlite": sqlite,
        "lowered_db": lowered_db,
        "vault_latest_seq": snapshot,
        "vault_tree": vault_tree,
        "ledger_head": ledger_head,
        "current": current,
        "complete_xterm": complete,
        "search_manifest": search_manifest_state,
    });
    Ok(json!({
        "sha256": sha256(&serde_json::to_vec(&state)?),
        "state": state,
    }))
}

fn physical_cf_snapshot_state(
    vault: &AsterVault,
    snapshot: u64,
    column_family: ColumnFamily,
) -> AnyResult<Value> {
    let rows = vault
        .scan_cf_at(snapshot, column_family)?
        .into_iter()
        .map(|(key, value)| {
            json!({
                "key_hex": hex_lower(&key),
                "value_bytes": value.len(),
                "value_sha256": sha256(&value),
            })
        })
        .collect::<Vec<_>>();
    let rows_sha256 = sha256(&serde_json::to_vec(&rows)?);
    Ok(json!({
        "column_family": column_family.name(),
        "content_generation": vault.cf_content_generation(column_family)?,
        "row_count": rows.len(),
        "rows_sha256": rows_sha256,
        "rows": rows,
    }))
}

fn edge_semantic_physical_state(
    cache: &Path,
    project: &str,
    expectation: SemanticProjectExpectation,
) -> AnyResult<Value> {
    let sqlite = sqlite_semantic_source_state(cache, project, expectation)?;
    let (config_integrity, config) = config_rows(cache, project)?;
    let (_, vault_dir, _, _) = vault_identity(cache, project)?;
    let optional_s208_cf = ColumnFamily::slot(SlotId::new(208));
    let optional_s208_dir = vault_dir.join("cf").join(optional_s208_cf.name());
    let optional_s208_metadata = match fs::symlink_metadata(&optional_s208_dir) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "ISSUE_980_EDGE_S208_DIRECTORY_UNREADABLE: path={}; error={error}; remediation: preserve the vault and repair the exact filesystem read fault before retrying",
                optional_s208_dir.display(),
            )
            .into());
        }
    };
    if let Some(metadata) = &optional_s208_metadata {
        require(
            metadata.is_dir() && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
            "ISSUE_980_EDGE_S208_DIRECTORY_INVALID",
            optional_s208_dir.display(),
        )?;
    }
    let mut selected_cfs = vec![
        ColumnFamily::Base,
        ColumnFamily::Graph,
        ColumnFamily::Kernel,
        ColumnFamily::Ledger,
        ColumnFamily::slot(astrolabe_weave::SLOT_NAME_SEMANTIC),
    ];
    if optional_s208_metadata.is_some() {
        selected_cfs.push(optional_s208_cf);
    }
    let (vault, _) = open_vault_selected(cache, project, selected_cfs)?;
    let snapshot = vault.latest_seq();
    let expected_s208_rows = match expectation {
        SemanticProjectExpectation::FastUnavailableMode => 0,
        SemanticProjectExpectation::ModerateUnavailableCorpus => 1,
        SemanticProjectExpectation::ModerateAvailable => {
            return Err("ISSUE_980_EDGE_EXPECTATION_INVALID: the edge-state reader accepts only unavailable_mode or unavailable_corpus".into());
        }
    };
    let optional_s208_state = if optional_s208_metadata.is_some() {
        let state = physical_cf_snapshot_state(&vault, snapshot, optional_s208_cf)?;
        require(
            state["row_count"] == expected_s208_rows,
            "ISSUE_980_EDGE_S208_ROWS_UNEXPECTED",
            json!({"expectation": format!("{expectation:?}"), "expected_rows": expected_s208_rows, "state": state}),
        )?;
        state
    } else {
        require(
            expected_s208_rows == 0,
            "ISSUE_980_EDGE_S208_DIRECTORY_UNEXPECTEDLY_ABSENT",
            json!({"expectation": format!("{expectation:?}"), "path": optional_s208_dir}),
        )?;
        json!({
            "column_family": optional_s208_cf.name(),
            "path": optional_s208_dir,
            "directory_exists": false,
            "row_count": 0,
            "physical_absence_verified": true,
        })
    };
    let state = json!({
        "config_integrity": config_integrity,
        "config_rows": config,
        "sqlite": sqlite,
        "vault_latest_seq": snapshot,
        "vault_tree": tree_state(&vault_dir)?,
        "base": physical_cf_snapshot_state(&vault, snapshot, ColumnFamily::Base)?,
        "graph": physical_cf_snapshot_state(&vault, snapshot, ColumnFamily::Graph)?,
        "kernel": physical_cf_snapshot_state(&vault, snapshot, ColumnFamily::Kernel)?,
        "slot_s20_name_semantic": physical_cf_snapshot_state(
            &vault,
            snapshot,
            ColumnFamily::slot(astrolabe_weave::SLOT_NAME_SEMANTIC),
        )?,
        "slot_s208_semantic_eligible_node_count": optional_s208_state,
        "ledger": physical_cf_snapshot_state(&vault, snapshot, ColumnFamily::Ledger)?,
    });
    Ok(json!({
        "sha256": sha256(&serde_json::to_vec(&state)?),
        "state": state,
    }))
}

fn verify_edge_kernel_generation(
    cache: &Path,
    project: &str,
    persisted_receipt: &Value,
) -> AnyResult<Value> {
    let (vault, _) = open_kernel_generation_readback_vault(cache, project)?;
    let snapshot = vault.latest_seq();
    let scope_id = format!("repo:{project}");
    let current = astrolabe_weave::read_current_kernel_generation(&vault, project, &scope_id)?
        .ok_or("ISSUE_980_EDGE_CURRENT_KERNEL_GENERATION_MISSING")?;
    let ledger_bytes = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Ledger,
            &ledger_key(current.manifest.ledger_ref.seq),
        )?
        .ok_or("ISSUE_980_EDGE_KERNEL_LEDGER_ROW_MISSING")?;
    let ledger_entry = calyx_ledger::decode(&ledger_bytes)?;
    let expected_ledger_ref = json!({
        "seq": ledger_entry.seq,
        "entry_hash": hex_lower(&ledger_entry.entry_hash),
    });
    let manifest = serde_json::to_value(&current.manifest)?;
    let pointer = serde_json::to_value(&current.pointer)?;
    let corpus = serde_json::to_value(&current.query_corpus)?;
    let report = serde_json::to_value(&current.graph_routed_report)?;
    require(
        persisted_receipt["published"] == Value::Bool(true)
            && persisted_receipt["scope_id"] == scope_id
            && persisted_receipt["generation_id"] == current.manifest.generation_id
            && persisted_receipt["member_count"] == u64::try_from(current.artifact.member_count)?
            && persisted_receipt["node_count"] == u64::try_from(current.artifact.node_count)?
            && current.artifact.member_count > 0
            && current.artifact.member_count < current.artifact.node_count
            && persisted_receipt["manifest"] == manifest
            && persisted_receipt["pointer"] == pointer
            && persisted_receipt["query_admission"]["corpus"] == corpus
            && persisted_receipt["query_admission"]["graph_routed_report"] == report
            && persisted_receipt["ledger_ref"] == expected_ledger_ref
            && persisted_receipt["ledger_paired"] == Value::Bool(true)
            && ledger_entry.verify()
            && ledger_entry.entry_hash == current.manifest.ledger_ref.hash
            && ledger_entry.seq == current.manifest.ledger_ref.seq
            && ledger_entry.kind == EntryKind::Kernel
            && matches!(&ledger_entry.actor, ActorId::Service(actor) if actor == astrolabe_weave::KERNEL_GENERATION_ACTOR)
            && matches!(&ledger_entry.subject, SubjectId::Kernel(subject) if !subject.is_empty())
            && ledger_payload["schema"] == astrolabe_weave::KERNEL_GENERATION_LEDGER_SCHEMA
            && ledger_payload["project"] == project
            && ledger_payload["scope_id"] == scope_id
            && ledger_payload["generation_id"] == current.manifest.generation_id,
        "ISSUE_980_EDGE_KERNEL_GENERATION_PHYSICAL_MISMATCH",
        json!({
            "receipt": persisted_receipt,
            "manifest": manifest,
            "pointer": pointer,
            "query_corpus": corpus,
            "graph_routed_report": report,
            "ledger_ref": expected_ledger_ref,
            "ledger_payload": ledger_payload,
        }),
    )?;
    Ok(json!({
        "snapshot": snapshot,
        "scope_id": scope_id,
        "generation_id": current.manifest.generation_id,
        "member_count": current.artifact.member_count,
        "node_count": current.artifact.node_count,
        "manifest": manifest,
        "pointer": pointer,
        "query_corpus": corpus,
        "graph_routed_report": report,
        "ledger": {
            "bytes": ledger_bytes.len(),
            "sha256": sha256(&ledger_bytes),
            "ref": expected_ledger_ref,
            "payload": ledger_payload,
            "verified": true,
        },
        "physical_current_generation_and_ledger_readback": true,
    }))
}

fn collect_fixture_namespace(root: &Path, current: &Path, rows: &mut Vec<Value>) -> AnyResult<()> {
    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        if current == root && entry.file_name() == ".git" {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        require(
            metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
            "ISSUE_1116_1119_FIXTURE_NAMESPACE_REPARSE",
            path.display(),
        )?;
        let relative = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        if metadata.is_dir() {
            rows.push(json!({"path": relative, "type": "directory"}));
            collect_fixture_namespace(root, &path, rows)?;
        } else if metadata.is_file() {
            let (bytes, digest) = file_sha256(&path)?;
            rows.push(json!({
                "path": relative,
                "type": "file",
                "bytes": bytes,
                "sha256": digest,
            }));
        } else {
            return Err(format!(
                "ISSUE_1116_1119_FIXTURE_NAMESPACE_TYPE_INVALID: {}",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn fixture_source_state(repo: &Path) -> AnyResult<Value> {
    let mut files = BTreeMap::new();
    for relative in ["Cargo.toml", "README.md", "src/lib.rs"] {
        let path = repo.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        require(
            metadata.is_file() && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
            "ISSUE_1116_1119_FIXTURE_SOURCE_INVALID",
            path.display(),
        )?;
        let (bytes, digest) = file_sha256(&path)?;
        files.insert(relative, json!({"bytes": bytes, "sha256": digest}));
    }
    let head = Command::new("git.exe")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()?;
    require(
        head.status.success(),
        "ISSUE_1116_1119_FIXTURE_SOURCE_HEAD_FAILED",
        String::from_utf8_lossy(&head.stderr),
    )?;
    let tracked = Command::new("git.exe")
        .args(["ls-files", "-z"])
        .current_dir(repo)
        .output()?;
    require(
        tracked.status.success(),
        "ISSUE_1116_1119_FIXTURE_TRACKED_ROSTER_FAILED",
        String::from_utf8_lossy(&tracked.stderr),
    )?;
    let tracked_files = tracked
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| std::str::from_utf8(entry).map(str::to_string))
        .collect::<Result<Vec<_>, _>>()?;
    require(
        tracked_files == ["Cargo.toml", "README.md", "src/lib.rs"],
        "ISSUE_1116_1119_FIXTURE_TRACKED_ROSTER_MISMATCH",
        format!("{tracked_files:?}"),
    )?;
    let status = Command::new("git.exe")
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .current_dir(repo)
        .output()?;
    require(
        status.status.success() && status.stdout.is_empty(),
        "ISSUE_1116_1119_FIXTURE_WORKTREE_NOT_CLEAN",
        format!(
            "status={} stderr={}",
            String::from_utf8_lossy(&status.stdout),
            String::from_utf8_lossy(&status.stderr)
        ),
    )?;
    let mut namespace = Vec::new();
    collect_fixture_namespace(repo, repo, &mut namespace)?;
    Ok(json!({
        "head": String::from_utf8(head.stdout)?.trim(),
        "files": files,
        "tracked_files": tracked_files,
        "worktree_clean": true,
        "namespace": namespace,
    }))
}

fn write_fixture(repo: &Path) -> AnyResult<Value> {
    require(
        !repo.try_exists()?,
        "ISSUE_1116_1119_REPO_PREEXISTS",
        repo.display(),
    )?;
    fs::create_dir_all(repo.join("src"))?;
    write_new_readback(
        &repo.join("Cargo.toml"),
        br#"[package]
name = "association-farm-fixture"
version = "0.1.0"
edition = "2024"

[lib]
path = "src/lib.rs"
"#,
    )?;
    write_new_readback(
        &repo.join("README.md"),
        b"# Association farm fixture\n\nA real Rust crate with overlapping structural and semantic neighborhoods.\n",
    )?;
    write_existing_readback(
        &repo.join("src").join("lib.rs"),
        br#"pub struct Reading {
    pub value: i64,
}

impl Reading {
    pub fn doubled(&self) -> i64 {
        twice(self.value)
    }
}

pub fn twice(value: i64) -> i64 {
    value * 2
}

pub fn normalize(value: i64) -> i64 {
    value.abs()
}

pub fn validate(value: i64) -> bool {
    normalize(value) <= 100
}

pub fn alpha_bridge(reading: &Reading) -> i64 {
    normalize(reading.doubled())
}

pub fn beta_bridge(reading: &Reading) -> i64 {
    let doubled = twice(reading.value);
    if validate(doubled) { doubled } else { 100 }
}

pub fn classify(reading: &Reading) -> &'static str {
    if validate(alpha_bridge(reading)) { "bounded" } else { "large" }
}

pub fn route(reading: &Reading) -> i64 {
    alpha_bridge(reading) + beta_bridge(reading)
}

pub fn cycle_left(value: i64) -> i64 {
    if value <= 0 { 0 } else { cycle_right(value - 1) }
}

pub fn cycle_right(value: i64) -> i64 {
    if value <= 0 { 0 } else { cycle_left(value - 1) }
}
"#,
    )?;
    let run = |args: &[&str]| -> AnyResult<()> {
        let output = Command::new("git.exe")
            .args(args)
            .current_dir(repo)
            .output()?;
        require(
            output.status.success(),
            "ISSUE_1116_1119_FIXTURE_GIT_FAILED",
            format!(
                "args={args:?} exit={:?} stdout={} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    };
    run(&["init", "-b", "main"])?;
    run(&["add", "--all"])?;
    run(&[
        "-c",
        "user.name=Astrolabe FSV",
        "-c",
        "user.email=astrolabe-fsv@invalid.local",
        "-c",
        "commit.gpgSign=false",
        "commit",
        "-m",
        "real association fixture baseline",
    ])?;
    let base_head = Command::new("git.exe")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()?;
    require(
        base_head.status.success(),
        "ISSUE_1116_1119_FIXTURE_BASE_HEAD_FAILED",
        String::from_utf8_lossy(&base_head.stderr),
    )?;
    let base_head = String::from_utf8(base_head.stdout)?.trim().to_string();
    write_new_readback(
        &repo.join("src").join("lib.rs"),
        br#"pub struct Reading {
    pub value: i64,
}

impl Reading {
    pub fn doubled(&self) -> i64 {
        twice(self.value)
    }
}

pub fn twice(value: i64) -> i64 {
    value * 2
}

pub fn normalize(value: i64) -> i64 {
    value.checked_abs().unwrap_or(i64::MAX)
}

pub fn validate(value: i64) -> bool {
    normalize(value) <= 100
}

pub fn alpha_bridge(reading: &Reading) -> i64 {
    normalize(reading.doubled())
}

pub fn beta_bridge(reading: &Reading) -> i64 {
    let doubled = twice(reading.value);
    if validate(doubled) { doubled } else { 100 }
}

pub fn classify(reading: &Reading) -> &'static str {
    if validate(alpha_bridge(reading)) { "bounded" } else { "large" }
}

pub fn route(reading: &Reading) -> i64 {
    alpha_bridge(reading) + beta_bridge(reading)
}

pub fn cycle_left(value: i64) -> i64 {
    if value <= 0 { 0 } else { cycle_right(value - 1) }
}

pub fn cycle_right(value: i64) -> i64 {
    if value <= 0 { 0 } else { cycle_left(value - 1) }
}
"#,
    )?;
    run(&["add", "src/lib.rs"])?;
    run(&[
        "-c",
        "user.name=Astrolabe FSV",
        "-c",
        "user.email=astrolabe-fsv@invalid.local",
        "-c",
        "commit.gpgSign=false",
        "commit",
        "-m",
        "fix bug #1119: handle minimum signed readings",
    ])?;
    let head = Command::new("git.exe")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()?;
    require(
        head.status.success(),
        "ISSUE_1116_1119_FIXTURE_HEAD_FAILED",
        String::from_utf8_lossy(&head.stderr),
    )?;
    let head = String::from_utf8(head.stdout)?.trim().to_string();
    require(
        is_canonical_git_oid(&base_head) && is_canonical_git_oid(&head) && base_head != head,
        "ISSUE_1116_1119_FIXTURE_CHANGE_GENERATION_INVALID",
        json!({"base_head":base_head,"head":head}),
    )?;
    Ok(json!({
        "base_head": base_head,
        "head": head,
        "changed_files": ["src/lib.rs"],
        "change_commit_message": "fix bug #1119: handle minimum signed readings",
        "tree": tree_state(repo)?,
        "source": fixture_source_state(repo)?,
    }))
}

fn write_unavailable_corpus_fixture(repo: &Path) -> AnyResult<Value> {
    require(
        !repo.try_exists()?,
        "ISSUE_980_UNAVAILABLE_CORPUS_REPO_PREEXISTS",
        repo.display(),
    )?;
    fs::create_dir_all(repo.join("src"))?;
    write_new_readback(
        &repo.join("Cargo.toml"),
        br#"[package]
name = "unavailable-corpus-fixture"
version = "0.1.0"
edition = "2024"

[lib]
path = "src/lib.rs"
"#,
    )?;
    write_new_readback(
        &repo.join("README.md"),
        b"# Unavailable corpus fixture\n\nA real Rust crate with exactly one semantic-eligible function.\n",
    )?;
    write_new_readback(
        &repo.join("src").join("lib.rs"),
        br#"pub struct Seed {
    pub remaining: u64,
}

pub fn singleton(seed: Seed) -> u64 {
    if seed.remaining == 0 {
        0
    } else {
        singleton(Seed {
            remaining: seed.remaining - 1,
        })
    }
}
"#,
    )?;
    let run = |args: &[&str]| -> AnyResult<()> {
        let output = Command::new("git.exe")
            .args(args)
            .current_dir(repo)
            .output()?;
        require(
            output.status.success(),
            "ISSUE_980_UNAVAILABLE_CORPUS_FIXTURE_GIT_FAILED",
            format!(
                "args={args:?} exit={:?} stdout={} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    };
    run(&["init", "-b", "main"])?;
    run(&["add", "--all"])?;
    run(&[
        "-c",
        "user.name=Astrolabe FSV",
        "-c",
        "user.email=astrolabe-fsv@invalid.local",
        "-c",
        "commit.gpgSign=false",
        "commit",
        "-m",
        "real unavailable corpus fixture",
    ])?;
    let head = Command::new("git.exe")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()?;
    require(
        head.status.success(),
        "ISSUE_980_UNAVAILABLE_CORPUS_FIXTURE_HEAD_FAILED",
        String::from_utf8_lossy(&head.stderr),
    )?;
    Ok(json!({
        "head": String::from_utf8(head.stdout)?.trim(),
        "tree": tree_state(repo)?,
        "source": fixture_source_state(repo)?,
        "expected_semantic_eligible_node_count": 1,
    }))
}

fn canonical_head() -> AnyResult<String> {
    let output = Command::new("git.exe")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()?;
    require(
        output.status.success(),
        "ISSUE_1116_1119_CANONICAL_HEAD_FAILED",
        String::from_utf8_lossy(&output.stderr),
    )?;
    let head = String::from_utf8(output.stdout)?.trim().to_string();
    require(
        head.len() == 40 && head.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "ISSUE_1116_1119_CANONICAL_HEAD_INVALID",
        &head,
    )?;
    Ok(head)
}

fn current_source_generation_sha256() -> AnyResult<String> {
    require(
        astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SCHEMA
            == worker_source_generation::SOURCE_GENERATION_SCHEMA,
        "ISSUE_1146_COMPILED_SOURCE_GENERATION_SCHEMA_DRIFT",
        astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SCHEMA,
    )?;
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent()
        .and_then(Path::parent)
        .ok_or("ISSUE_1146_WORKSPACE_ROOT_MISSING")?;
    let rerun_inputs = worker_source_generation::git_rerun_inputs(root)?;
    require(
        !rerun_inputs.is_empty()
            && rerun_inputs
                .iter()
                .all(|path| path.is_absolute() && !path.as_os_str().is_empty()),
        "ISSUE_1146_SOURCE_GENERATION_GIT_INPUTS_INVALID",
        format!("{rerun_inputs:?}"),
    )?;
    Ok(worker_source_generation::source_generation_sha256(root)?)
}

fn parse_tool_text(tool: &str, is_error: bool, text: &str) -> AnyResult<Value> {
    serde_json::from_str(text).map_err(|error| {
        let prefix = text.chars().take(160).collect::<String>();
        format!(
            "ISSUE_1116_1119_INNER_PAYLOAD_INVALID: tool={tool:?} isError={is_error} text_bytes={} text_sha256={} text_prefix={prefix:?} parse_error={error}; remediation: preserve the exact MCP response and repair the producer's structured tool envelope; never treat malformed or legacy prose as success",
            text.len(),
            sha256(text.as_bytes()),
        )
        .into()
    })
}

fn call_tool_with_raw(
    runner: &CbmToolRunner,
    tool: &str,
    arguments: &Value,
) -> AnyResult<(String, Value, Value)> {
    let raw = astrolabe_server::migration::handle_tool_raw(
        runner,
        tool,
        &serde_json::to_string(arguments)?,
    )?;
    let envelope: Value = serde_json::from_str(&raw).map_err(|error| -> Box<dyn Error + Send + Sync> {
        format!(
            "ISSUE_1116_1119_OUTER_ENVELOPE_INVALID: tool={tool:?} raw_bytes={} raw_sha256={} parse_error={error}; remediation: preserve the exact handler output and repair the MCP envelope producer",
            raw.len(),
            sha256(raw.as_bytes()),
        )
        .into()
    })?;
    let text = envelope["content"]
        .as_array()
        .filter(|content| content.len() == 1)
        .and_then(|content| content.first())
        .and_then(|content| content["text"].as_str())
        .ok_or("MCP envelope does not contain one text payload")?;
    let payload = parse_tool_text(tool, envelope["isError"] == Value::Bool(true), text)?;
    let compact_payload = serde_json::to_string(&payload)?;
    require(
        envelope["content"][0]["type"] == "text"
            && envelope["isError"].is_boolean()
            && envelope.get("structuredContent") == Some(&payload)
            && payload.is_object(),
        "ISSUE_1116_1119_STRUCTURED_CONTENT_MISMATCH",
        json!({
            "tool":tool,
            "isError":envelope["isError"],
            "text_bytes":text.len(),
            "text_sha256":sha256(text.as_bytes()),
            "compact_bytes":compact_payload.len(),
            "compact_sha256":sha256(compact_payload.as_bytes()),
            "envelope":envelope,
            "payload":payload,
        }),
    )?;
    Ok((raw, envelope, payload))
}

fn call_tool(runner: &CbmToolRunner, tool: &str, arguments: &Value) -> AnyResult<(Value, Value)> {
    let (_, envelope, payload) = call_tool_with_raw(runner, tool, arguments)?;
    Ok((envelope, payload))
}

fn expect_refusal(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    case: &str,
    tool: &str,
    arguments: &Value,
    expected_code: &str,
) -> AnyResult<Value> {
    let before = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "before", "state": before}))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": case,
            "phase": "action",
            "tool": tool,
            "request": arguments,
        }))?
    );
    let (envelope, payload) = call_tool(runner, tool, arguments)?;
    require(
        envelope["isError"] == Value::Bool(true)
            && payload["code"] == Value::String(expected_code.to_string())
            && payload["remediation"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()),
        "ISSUE_1116_1119_REFUSAL_MISMATCH",
        format!("case={case} payload={payload}"),
    )?;
    let after = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "after", "state": after}))?
    );
    require(
        before["sha256"] == after["sha256"],
        "ISSUE_1116_1119_REFUSAL_MUTATED_STATE",
        case,
    )?;
    Ok(json!({
        "case": case,
        "tool": tool,
        "expected_code": expected_code,
        "request": arguments,
        "response": payload,
        "before": before,
        "after": after,
        "state_unchanged": true,
    }))
}

fn architecture_cluster_request(
    project: &str,
    source: &Value,
    above_exact_bounds: bool,
) -> AnyResult<Value> {
    let nodes = source["node_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_SOURCE_NODE_COUNT_MISSING")?;
    let edges = source["cluster_edge_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_SOURCE_EDGE_COUNT_MISSING")?;
    let node_bound = if above_exact_bounds {
        nodes.checked_add(1)
    } else {
        Some(nodes)
    }
    .ok_or("ISSUE_1149_CLUSTER_NODE_BOUND_OVERFLOW")?;
    let edge_bound = if above_exact_bounds {
        edges.checked_add(1)
    } else {
        Some(edges)
    }
    .ok_or("ISSUE_1149_CLUSTER_EDGE_BOUND_OVERFLOW")?;
    require(
        nodes > 1 && edges > 0 && node_bound <= 2_147_483_647 && edge_bound <= 2_147_483_647,
        "ISSUE_1149_CLUSTER_REQUEST_BOUND_INVALID",
        json!({
            "nodes": nodes,
            "edges": edges,
            "node_bound": node_bound,
            "edge_bound": edge_bound,
        }),
    )?;
    Ok(json!({
        "project": project,
        "aspects": ["clusters"],
        "resolution": 1,
        "cluster_max_nodes": node_bound,
        "cluster_max_edges": edge_bound,
        "cluster_max_result_bytes": 1_048_576_u64,
        "cluster_max_move_visits": 65_536_u64,
    }))
}

fn cluster_top_package(qualified_name: &str) -> Option<&str> {
    let (_, suffix) = qualified_name.split_once('.')?;
    let package = suffix
        .split_once('.')
        .map_or(suffix, |(package, _)| package);
    (!package.is_empty()).then_some(package)
}

fn independently_recompute_cluster_semantics(
    source: &Value,
    response: &Value,
    atom_id_to_community: &BTreeMap<String, u64>,
) -> AnyResult<Value> {
    let source_nodes = source["nodes"]
        .as_array()
        .ok_or("ISSUE_1149_CLUSTER_SOURCE_NODES_MISSING")?;
    let canonical_edges = source["canonical_edges"]
        .as_array()
        .ok_or("ISSUE_1149_CLUSTER_CANONICAL_EDGES_MISSING")?;
    let clusters = response["clusters"]
        .as_array()
        .ok_or("ISSUE_1149_CLUSTER_RESULT_MISSING")?;
    let community_count = clusters.len();
    let mut node_names = BTreeMap::<String, String>::new();
    let mut node_packages = BTreeMap::<String, Option<String>>::new();
    let mut node_ordinals = BTreeMap::<String, usize>::new();
    let mut degree = BTreeMap::<String, u64>::new();
    for (ordinal, node) in source_nodes.iter().enumerate() {
        let atom_id = node["atom_id"]
            .as_str()
            .ok_or("ISSUE_1149_CLUSTER_SOURCE_ATOM_ID_MISSING")?;
        let name = node["name"]
            .as_str()
            .ok_or("ISSUE_1149_CLUSTER_SOURCE_NAME_MISSING")?;
        let qualified_name = node["qualified_name"]
            .as_str()
            .ok_or("ISSUE_1149_CLUSTER_SOURCE_QUALIFIED_NAME_MISSING")?;
        require(
            atom_id_to_community.contains_key(atom_id)
                && node_names
                    .insert(atom_id.to_string(), name.to_string())
                    .is_none()
                && node_ordinals.insert(atom_id.to_string(), ordinal).is_none(),
            "ISSUE_1149_CLUSTER_RECOMPUTE_NODE_ROSTER_INVALID",
            atom_id,
        )?;
        node_packages.insert(
            atom_id.to_string(),
            cluster_top_package(qualified_name).map(ToOwned::to_owned),
        );
        degree.insert(atom_id.to_string(), 0);
    }

    let mut internal = vec![0_u64; community_count];
    let mut boundary = vec![0_u64; community_count];
    let mut edge_types = vec![BTreeSet::<String>::new(); community_count];
    let mut folded = BTreeMap::<(String, String), u64>::new();
    for edge in canonical_edges {
        let source_atom = edge["source_atom_id"]
            .as_str()
            .ok_or("ISSUE_1149_CLUSTER_CANONICAL_SOURCE_MISSING")?;
        let target_atom = edge["target_atom_id"]
            .as_str()
            .ok_or("ISSUE_1149_CLUSTER_CANONICAL_TARGET_MISSING")?;
        let edge_type = edge["type"]
            .as_str()
            .ok_or("ISSUE_1149_CLUSTER_CANONICAL_TYPE_MISSING")?;
        let multiplicity = edge["multiplicity"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or("ISSUE_1149_CLUSTER_CANONICAL_MULTIPLICITY_INVALID")?;
        let source_community = usize::try_from(
            *atom_id_to_community
                .get(source_atom)
                .ok_or("ISSUE_1149_CLUSTER_CANONICAL_SOURCE_UNKNOWN")?,
        )?;
        let target_community = usize::try_from(
            *atom_id_to_community
                .get(target_atom)
                .ok_or("ISSUE_1149_CLUSTER_CANONICAL_TARGET_UNKNOWN")?,
        )?;
        require(
            source_community < community_count
                && target_community < community_count
                && matches!(edge_type, "CALLS" | "IMPORTS"),
            "ISSUE_1149_CLUSTER_CANONICAL_EDGE_INVALID",
            edge,
        )?;
        let (first, second) = if source_atom <= target_atom {
            (source_atom, target_atom)
        } else {
            (target_atom, source_atom)
        };
        let folded_weight = folded
            .entry((first.to_string(), second.to_string()))
            .or_default();
        *folded_weight = folded_weight
            .checked_add(multiplicity)
            .ok_or("ISSUE_1149_CLUSTER_FOLDED_WEIGHT_OVERFLOW")?;
        if source_atom == target_atom {
            let source_degree = degree
                .get_mut(source_atom)
                .ok_or("ISSUE_1149_CLUSTER_DEGREE_SOURCE_UNKNOWN")?;
            *source_degree = source_degree
                .checked_add(
                    multiplicity
                        .checked_mul(2)
                        .ok_or("ISSUE_1149_CLUSTER_SELF_DEGREE_OVERFLOW")?,
                )
                .ok_or("ISSUE_1149_CLUSTER_DEGREE_OVERFLOW")?;
        } else {
            for atom_id in [source_atom, target_atom] {
                let value = degree
                    .get_mut(atom_id)
                    .ok_or("ISSUE_1149_CLUSTER_DEGREE_ENDPOINT_UNKNOWN")?;
                *value = value
                    .checked_add(multiplicity)
                    .ok_or("ISSUE_1149_CLUSTER_DEGREE_OVERFLOW")?;
            }
        }
        edge_types[source_community].insert(edge_type.to_string());
        edge_types[target_community].insert(edge_type.to_string());
        if source_community == target_community {
            internal[source_community] = internal[source_community]
                .checked_add(multiplicity)
                .ok_or("ISSUE_1149_CLUSTER_INTERNAL_WEIGHT_OVERFLOW")?;
        } else {
            for community in [source_community, target_community] {
                boundary[community] = boundary[community]
                    .checked_add(multiplicity)
                    .ok_or("ISSUE_1149_CLUSTER_BOUNDARY_WEIGHT_OVERFLOW")?;
            }
        }
    }

    let weighted_undirected_edge_count = u64::try_from(folded.len())?;
    let folded_rows = folded
        .iter()
        .map(|((source, target), weight)| {
            json!({"source_atom_id": source, "target_atom_id": target, "weight": weight})
        })
        .collect::<Vec<_>>();
    require(
        response["cluster_receipt"]["weighted_undirected_edge_count"]
            == weighted_undirected_edge_count
            && response["cluster_receipt"]["undirected_fold_count"].as_u64()
                == source["canonical_typed_edge_count"]
                    .as_u64()
                    .and_then(|count| count.checked_sub(weighted_undirected_edge_count)),
        "ISSUE_1149_CLUSTER_UNDIRECTED_FOLD_MISMATCH",
        json!({"folded": folded_rows, "receipt": response["cluster_receipt"]}),
    )?;

    let mut adjacency = BTreeMap::<String, BTreeSet<String>>::new();
    for atom_id in node_names.keys() {
        adjacency.insert(atom_id.clone(), BTreeSet::new());
    }
    for ((source_atom, target_atom), weight) in &folded {
        require(
            *weight > 0,
            "ISSUE_1149_CLUSTER_FOLDED_ZERO_WEIGHT",
            json!([source_atom, target_atom]),
        )?;
        if source_atom != target_atom
            && atom_id_to_community[source_atom] == atom_id_to_community[target_atom]
        {
            adjacency
                .get_mut(source_atom)
                .ok_or("ISSUE_1149_CLUSTER_ADJACENCY_SOURCE_UNKNOWN")?
                .insert(target_atom.clone());
            adjacency
                .get_mut(target_atom)
                .ok_or("ISSUE_1149_CLUSTER_ADJACENCY_TARGET_UNKNOWN")?
                .insert(source_atom.clone());
        }
    }
    for community in 0..community_count {
        let members = atom_id_to_community
            .iter()
            .filter(|(_, value)| **value == u64::try_from(community).unwrap_or(u64::MAX))
            .map(|(atom_id, _)| atom_id.clone())
            .collect::<BTreeSet<_>>();
        let first = members
            .first()
            .ok_or("ISSUE_1149_CLUSTER_EMPTY_COMMUNITY")?
            .clone();
        let mut visited = BTreeSet::from([first.clone()]);
        let mut pending = vec![first];
        while let Some(atom_id) = pending.pop() {
            for neighbor in adjacency
                .get(&atom_id)
                .ok_or("ISSUE_1149_CLUSTER_ADJACENCY_NODE_UNKNOWN")?
            {
                if members.contains(neighbor) && visited.insert(neighbor.clone()) {
                    pending.push(neighbor.clone());
                }
            }
        }
        require(
            visited == members,
            "ISSUE_1149_CLUSTER_COMMUNITY_DISCONNECTED",
            json!({"community": community, "members": members, "visited": visited}),
        )?;
    }

    let mut expected_clusters = Vec::with_capacity(community_count);
    for (community, cluster) in clusters.iter().enumerate() {
        let member_atom_ids = atom_id_to_community
            .iter()
            .filter(|(_, value)| **value == u64::try_from(community).unwrap_or(u64::MAX))
            .map(|(atom_id, _)| atom_id.clone())
            .collect::<Vec<_>>();
        let mut ranked = member_atom_ids.clone();
        ranked.sort_by(|left, right| {
            degree[right]
                .cmp(&degree[left])
                .then_with(|| node_ordinals[left].cmp(&node_ordinals[right]))
        });
        let top_nodes = ranked
            .iter()
            .take(5)
            .map(|atom_id| node_names[atom_id].clone())
            .collect::<Vec<_>>();
        let mut package_members = BTreeMap::<String, u64>::new();
        for atom_id in &member_atom_ids {
            if let Some(package) = &node_packages[atom_id] {
                let count = package_members.entry(package.clone()).or_default();
                *count = count
                    .checked_add(1)
                    .ok_or("ISSUE_1149_CLUSTER_PACKAGE_COUNT_OVERFLOW")?;
            }
        }
        let packages = package_members.keys().cloned().collect::<Vec<_>>();
        let mut best_package = None::<(&String, u64)>;
        for (package, count) in &package_members {
            if best_package.is_none_or(|(_, best_count)| *count > best_count) {
                best_package = Some((package, *count));
            }
        }
        let label = best_package
            .map(|(package, _)| package.clone())
            .or_else(|| top_nodes.first().cloned())
            .ok_or("ISSUE_1149_CLUSTER_LABEL_SOURCE_MISSING")?;
        let denominator = internal[community]
            .checked_add(boundary[community])
            .ok_or("ISSUE_1149_CLUSTER_COHESION_DENOMINATOR_OVERFLOW")?;
        let cohesion = if denominator == 0 {
            0.0
        } else {
            internal[community] as f64 / denominator as f64
        };
        let expected = json!({
            "id": community,
            "label": label,
            "members": member_atom_ids.len(),
            "cohesion": cohesion,
            "member_atom_id_count": member_atom_ids.len(),
            "member_atom_ids": member_atom_ids,
            "top_nodes": top_nodes,
            "packages": packages,
            "edge_types": edge_types[community].iter().cloned().collect::<Vec<_>>(),
        });
        require(
            cluster == &expected,
            "ISSUE_1149_CLUSTER_INDEPENDENT_MATERIALIZATION_MISMATCH",
            json!({"community": community, "expected": expected, "actual": cluster}),
        )?;
        expected_clusters.push(expected);
    }

    let two_m = degree.values().try_fold(0_u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or("ISSUE_1149_CLUSTER_TOTAL_DEGREE_OVERFLOW")
    })? as f64;
    let resolution = response["cluster_receipt"]["resolution"]
        .as_f64()
        .ok_or("ISSUE_1149_CLUSTER_RESOLUTION_MISSING")?;
    let mut objective = 0.0;
    if two_m > 0.0 {
        for community in 0..community_count {
            let community_degree = atom_id_to_community
                .iter()
                .filter(|(_, value)| **value == u64::try_from(community).unwrap_or(u64::MAX))
                .try_fold(0_u64, |sum, (atom_id, _)| {
                    sum.checked_add(degree[atom_id])
                        .ok_or("ISSUE_1149_CLUSTER_COMMUNITY_DEGREE_OVERFLOW")
                })? as f64;
            let community_internal = internal[community] as f64 * 2.0;
            let fraction = community_degree / two_m;
            objective += community_internal / two_m - resolution * fraction * fraction;
        }
    }
    let receipt_objective = response["cluster_receipt"]["objective"]
        .as_f64()
        .ok_or("ISSUE_1149_CLUSTER_OBJECTIVE_MISSING")?;
    require(
        objective.to_bits() == receipt_objective.to_bits(),
        "ISSUE_1149_CLUSTER_OBJECTIVE_RECOMPUTE_MISMATCH",
        json!({"expected_bits": objective.to_bits(), "actual_bits": receipt_objective.to_bits()}),
    )?;
    Ok(json!({
        "schema": "astrolabe.issue-1149.cluster-independent-semantics.v1",
        "canonical_typed_edges": canonical_edges,
        "weighted_undirected_edges": folded_rows,
        "degree": degree,
        "internal_weight": internal,
        "boundary_weight": boundary,
        "communities": expected_clusters,
        "objective": objective,
        "objective_bits": objective.to_bits(),
        "connectivity_recomputed": true,
        "top_node_limit": 5,
        "exact_materialization_equal": true,
    }))
}

fn verify_architecture_cluster_response(
    project: &str,
    request: &Value,
    response: &Value,
    source: &Value,
    final_payload_bytes: u64,
    astrolabe_kernel_augmented: bool,
) -> AnyResult<Value> {
    let request_keys = request
        .as_object()
        .ok_or("ISSUE_1149_CLUSTER_REQUEST_NOT_OBJECT")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_request_keys = BTreeSet::from([
        "project",
        "aspects",
        "resolution",
        "cluster_max_nodes",
        "cluster_max_edges",
        "cluster_max_result_bytes",
        "cluster_max_move_visits",
    ]);
    require(
        request_keys == expected_request_keys
            && request["project"] == Value::String(project.to_string())
            && request["aspects"]
                == if astrolabe_kernel_augmented {
                    json!(["clusters", "kernel_context"])
                } else {
                    json!(["clusters"])
                },
        "ISSUE_1149_CLUSTER_REQUEST_NOT_EXPLICIT",
        request,
    )?;

    let receipt = response["cluster_receipt"]
        .as_object()
        .ok_or("ISSUE_1149_CLUSTER_RECEIPT_MISSING")?;
    let receipt_keys = receipt.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_receipt_keys = BTreeSet::from([
        "status",
        "algorithm",
        "algorithm_version",
        "projection_schema",
        "result_schema",
        "node_label_selection",
        "observed_node_label_count",
        "node_label_roster_sha256",
        "edge_type_roster",
        "seed",
        "objective_function",
        "move_rule",
        "refinement_rule",
        "aggregation_rule",
        "edge_transform",
        "resolution",
        "converged",
        "connectivity_verified",
        "complete_coverage_verified",
        "requested_node_count",
        "included_node_count",
        "excluded_node_count",
        "requested_edge_count",
        "included_edge_count",
        "excluded_edge_count",
        "canonical_typed_edge_count",
        "weighted_undirected_edge_count",
        "undirected_fold_count",
        "duplicate_edge_count",
        "self_loop_count",
        "community_count",
        "level_count",
        "level_bound",
        "move_visit_count",
        "move_visit_cap",
        "refine_visit_count",
        "refine_visit_bound",
        "refine_merge_count",
        "relabel_visit_count",
        "aggregate_visit_count",
        "allocation_attempt_count",
        "node_bound",
        "edge_bound",
        "result_byte_bound",
        "result_byte_bound_scope",
        "canonical_result_bytes",
        "architecture_payload_bytes",
        "move_phase_status",
        "refine_phase_status",
        "relabel_phase_status",
        "aggregate_phase_status",
        "readback_phase_status",
        "objective",
        "source_sha256",
        "projection_sha256",
        "result_sha256",
    ]);
    let node_count = source["node_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_SOURCE_NODE_COUNT_MISSING")?;
    let total_edge_count = source["total_edge_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_TOTAL_EDGE_COUNT_MISSING")?;
    let cluster_edge_count = source["cluster_edge_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_SOURCE_EDGE_COUNT_MISSING")?;
    let canonical_typed_edge_count = source["canonical_typed_edge_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_CANONICAL_EDGE_COUNT_MISSING")?;
    let weighted_undirected_edge_count =
        response["cluster_receipt"]["weighted_undirected_edge_count"]
            .as_u64()
            .ok_or("ISSUE_1149_CLUSTER_WEIGHTED_EDGE_COUNT_MISSING")?;
    let community_count = response["cluster_receipt"]["community_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_COMMUNITY_COUNT_MISSING")?;
    let move_visits = response["cluster_receipt"]["move_visit_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_MOVE_VISITS_MISSING")?;
    let refine_visits = response["cluster_receipt"]["refine_visit_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_REFINE_VISITS_MISSING")?;
    let refine_bound = response["cluster_receipt"]["refine_visit_bound"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_REFINE_BOUND_MISSING")?;
    let level_count = response["cluster_receipt"]["level_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_LEVEL_COUNT_MISSING")?;
    let request_move_visit_cap = request["cluster_max_move_visits"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_REQUEST_MOVE_CAP_MISSING")?;
    let request_result_byte_bound = request["cluster_max_result_bytes"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_REQUEST_RESULT_BOUND_MISSING")?;
    let architecture_payload_bytes = response["cluster_receipt"]["architecture_payload_bytes"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_ARCHITECTURE_PAYLOAD_BYTES_MISSING")?;
    let objective = response["cluster_receipt"]["objective"]
        .as_f64()
        .ok_or("ISSUE_1149_CLUSTER_OBJECTIVE_MISSING")?;
    let sha_is_canonical = |field: &str| {
        response["cluster_receipt"][field]
            .as_str()
            .is_some_and(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    && value != ZERO_SHA256
            })
    };
    require(
        receipt_keys == expected_receipt_keys
            && response["project"] == Value::String(project.to_string())
            && response["total_nodes"] == node_count
            && response["total_edges"] == total_edge_count
            && response.get("path").is_none()
            && response["cluster_receipt"]["status"] == "complete"
            && response["cluster_receipt"]["algorithm"] == "deterministic_leiden_variant"
            && response["cluster_receipt"]["algorithm_version"] == "3"
            && response["cluster_receipt"]["projection_schema"] == "cbm.architecture.cluster.v3"
            && response["cluster_receipt"]["result_schema"] == "cbm.architecture.cluster.result.v4"
            && response["cluster_receipt"]["node_label_selection"] == "all_indexed_labels"
            && response["cluster_receipt"]["edge_type_roster"] == "CALLS,IMPORTS"
            && response["cluster_receipt"]["seed"] == "none"
            && response["cluster_receipt"]["objective_function"] == "weighted_modularity_v1"
            && response["cluster_receipt"]["move_rule"] == "strict_gain_current_tie_lifo_empty"
            && response["cluster_receipt"]["refinement_rule"]
                == "well_connected_nonnegative_max_gain"
            && response["cluster_receipt"]["aggregation_rule"]
                == "refined_graph_move_partition_seed"
            && response["cluster_receipt"]["edge_transform"]
                == "typed_directed_runs_to_weighted_undirected_pairs"
            && response["cluster_receipt"]["resolution"].as_f64() == Some(1.0)
            && request["resolution"].as_u64() == Some(1)
            && response["cluster_receipt"]["converged"] == Value::Bool(true)
            && response["cluster_receipt"]["connectivity_verified"] == Value::Bool(true)
            && response["cluster_receipt"]["complete_coverage_verified"] == Value::Bool(true)
            && response["cluster_receipt"]["requested_node_count"] == node_count
            && response["cluster_receipt"]["included_node_count"] == node_count
            && response["cluster_receipt"]["excluded_node_count"] == 0
            && response["cluster_receipt"]["requested_edge_count"] == cluster_edge_count
            && response["cluster_receipt"]["included_edge_count"] == cluster_edge_count
            && response["cluster_receipt"]["excluded_edge_count"] == 0
            && response["cluster_receipt"]["canonical_typed_edge_count"]
                == canonical_typed_edge_count
            && response["cluster_receipt"]["duplicate_edge_count"]
                == source["duplicate_edge_count"]
            && response["cluster_receipt"]["self_loop_count"] == source["self_loop_count"]
            && weighted_undirected_edge_count > 0
            && weighted_undirected_edge_count <= canonical_typed_edge_count
            && response["cluster_receipt"]["undirected_fold_count"]
                .as_u64()
                .is_some_and(|count| {
                    canonical_typed_edge_count.checked_sub(weighted_undirected_edge_count)
                        == Some(count)
                })
            && community_count > 0
            && community_count <= node_count
            && level_count > 0
            && level_count <= node_count
            && response["cluster_receipt"]["level_bound"] == node_count
            && move_visits > 0
            && move_visits <= request_move_visit_cap
            && response["cluster_receipt"]["move_visit_cap"] == request["cluster_max_move_visits"]
            && refine_visits <= refine_bound
            && response["cluster_receipt"]["relabel_visit_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && response["cluster_receipt"]["allocation_attempt_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && response["cluster_receipt"]["node_bound"] == request["cluster_max_nodes"]
            && response["cluster_receipt"]["edge_bound"] == request["cluster_max_edges"]
            && response["cluster_receipt"]["result_byte_bound"]
                == request["cluster_max_result_bytes"]
            && response["cluster_receipt"]["result_byte_bound_scope"]
                == "c_architecture_payload_utf8"
            && response["cluster_receipt"]["canonical_result_bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes > 0)
            && architecture_payload_bytes > 0
            && architecture_payload_bytes <= request_result_byte_bound
            && final_payload_bytes <= request_result_byte_bound
            && if astrolabe_kernel_augmented {
                response["astrolabe"]["kernel_context"].is_object()
                    && architecture_payload_bytes < final_payload_bytes
            } else {
                response.get("astrolabe").is_none()
                    && architecture_payload_bytes == final_payload_bytes
            }
            && response["cluster_receipt"]["move_phase_status"] == "complete"
            && matches!(
                response["cluster_receipt"]["refine_phase_status"].as_str(),
                Some("complete" | "not_run")
            )
            && response["cluster_receipt"]["relabel_phase_status"] == "complete"
            && matches!(
                response["cluster_receipt"]["aggregate_phase_status"].as_str(),
                Some("complete" | "not_run")
            )
            && response["cluster_receipt"]["readback_phase_status"] == "complete"
            && objective.is_finite()
            && response["cluster_receipt"]["observed_node_label_count"]
                == source["node_label_count"]
            && response["cluster_receipt"]["node_label_roster_sha256"]
                == source["node_label_roster_sha256"]
            && response["cluster_receipt"]["source_sha256"] == source["source_sha256"]
            && response["cluster_receipt"]["projection_sha256"] == source["projection_sha256"]
            && sha_is_canonical("node_label_roster_sha256")
            && sha_is_canonical("source_sha256")
            && sha_is_canonical("projection_sha256")
            && sha_is_canonical("result_sha256"),
        "ISSUE_1149_CLUSTER_RECEIPT_INVALID",
        json!({
            "request": request,
            "source": source,
            "response": response,
            "expected_receipt_keys": expected_receipt_keys,
            "observed_receipt_keys": receipt_keys,
        }),
    )?;

    let clusters = response["clusters"]
        .as_array()
        .ok_or("ISSUE_1149_CLUSTER_RESULT_MISSING")?;
    require(
        u64::try_from(clusters.len()).ok() == Some(community_count),
        "ISSUE_1149_CLUSTER_RESULT_CARDINALITY_MISMATCH",
        json!({"clusters": clusters.len(), "receipt": community_count}),
    )?;
    let expected_cluster_keys = BTreeSet::from([
        "id",
        "label",
        "members",
        "cohesion",
        "member_atom_id_count",
        "member_atom_ids",
        "top_nodes",
        "packages",
        "edge_types",
    ]);
    let mut observed_atom_ids = Vec::new();
    let mut atom_id_to_community = BTreeMap::<String, u64>::new();
    let mut covered_nodes = 0_u64;
    for (index, cluster) in clusters.iter().enumerate() {
        let cluster_object = cluster
            .as_object()
            .ok_or("ISSUE_1149_CLUSTER_RESULT_ITEM_INVALID")?;
        let cluster_keys = cluster_object
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let cluster_id = cluster["id"]
            .as_u64()
            .ok_or("ISSUE_1149_CLUSTER_RESULT_ID_INVALID")?;
        let members = cluster["members"]
            .as_u64()
            .ok_or("ISSUE_1149_CLUSTER_RESULT_MEMBERS_INVALID")?;
        let cohesion = cluster["cohesion"]
            .as_f64()
            .ok_or("ISSUE_1149_CLUSTER_RESULT_COHESION_INVALID")?;
        let member_atom_id_count = cluster["member_atom_id_count"]
            .as_u64()
            .ok_or("ISSUE_1149_CLUSTER_MEMBER_ATOM_ID_COUNT_INVALID")?;
        let member_atom_ids = cluster["member_atom_ids"]
            .as_array()
            .ok_or("ISSUE_1149_CLUSTER_MEMBER_ATOM_IDS_INVALID")?;
        let top_nodes = cluster["top_nodes"]
            .as_array()
            .ok_or("ISSUE_1149_CLUSTER_TOP_NODES_INVALID")?;
        let packages = cluster["packages"]
            .as_array()
            .ok_or("ISSUE_1149_CLUSTER_PACKAGES_INVALID")?;
        let edge_types = cluster["edge_types"]
            .as_array()
            .ok_or("ISSUE_1149_CLUSTER_EDGE_TYPES_INVALID")?;
        let package_roster = packages
            .iter()
            .map(|value| value.as_str())
            .collect::<Option<Vec<_>>>();
        let edge_type_roster = edge_types
            .iter()
            .map(|value| value.as_str())
            .collect::<Option<Vec<_>>>();
        let member_atom_id_roster = member_atom_ids
            .iter()
            .map(|value| value.as_str())
            .collect::<Option<Vec<_>>>();
        let top_node_roster = top_nodes
            .iter()
            .map(|value| value.as_str())
            .collect::<Option<Vec<_>>>();
        require(
            cluster_keys == expected_cluster_keys
                && cluster_id == u64::try_from(index)?
                && members > 0
                && member_atom_id_count == members
                && u64::try_from(member_atom_ids.len()).ok() == Some(members)
                && member_atom_id_roster.as_ref().is_some_and(|roster| {
                    roster.iter().all(|value| !value.is_empty())
                        && roster.windows(2).all(|pair| pair[0] < pair[1])
                })
                && top_node_roster
                    .as_ref()
                    .is_some_and(|roster| roster.iter().all(|value| !value.is_empty()))
                && cluster["label"]
                    .as_str()
                    .is_some_and(|label| !label.is_empty())
                && cohesion.is_finite()
                && (0.0..=1.0).contains(&cohesion)
                && package_roster.as_ref().is_some_and(|roster| {
                    roster.iter().all(|value| !value.is_empty())
                        && roster.windows(2).all(|pair| pair[0] < pair[1])
                })
                && edge_type_roster.as_ref().is_some_and(|roster| {
                    roster
                        .iter()
                        .all(|value| matches!(*value, "CALLS" | "IMPORTS"))
                        && roster.windows(2).all(|pair| pair[0] < pair[1])
                }),
            "ISSUE_1149_CLUSTER_RESULT_ITEM_INCOMPLETE",
            cluster,
        )?;
        covered_nodes = covered_nodes
            .checked_add(members)
            .ok_or("ISSUE_1149_CLUSTER_COVERAGE_OVERFLOW")?;
        for atom_id in member_atom_ids {
            let atom_id = atom_id
                .as_str()
                .filter(|atom_id| !atom_id.is_empty())
                .ok_or("ISSUE_1149_CLUSTER_MEMBER_ATOM_ID_INVALID")?;
            require(
                atom_id_to_community
                    .insert(atom_id.to_string(), cluster_id)
                    .is_none(),
                "ISSUE_1149_CLUSTER_MEMBER_ATOM_ID_DUPLICATE",
                atom_id,
            )?;
            observed_atom_ids.push(atom_id.to_string());
        }
    }
    let source_nodes = source["nodes"]
        .as_array()
        .ok_or("ISSUE_1149_CLUSTER_SOURCE_NODES_MISSING")?;
    let mut expected_atom_ids = source_nodes
        .iter()
        .map(|node| {
            node["atom_id"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or("ISSUE_1149_CLUSTER_SOURCE_ATOM_ID_MISSING")
        })
        .collect::<Result<Vec<_>, _>>()?;
    expected_atom_ids.sort();
    observed_atom_ids.sort();
    require(
        covered_nodes == node_count
            && observed_atom_ids == expected_atom_ids
            && atom_id_to_community.len() == source_nodes.len(),
        "ISSUE_1149_CLUSTER_COMPLETE_ROSTER_MISMATCH",
        json!({
            "covered_nodes": covered_nodes,
            "expected_node_count": node_count,
            "expected_atom_ids": expected_atom_ids,
            "observed_atom_ids": observed_atom_ids,
        }),
    )?;
    let independent_semantics =
        independently_recompute_cluster_semantics(source, response, &atom_id_to_community)?;

    let mut result_hash = Sha256::new();
    let mut canonical_result_bytes = 0_u64;
    add_cluster_result_hash_text(
        &mut result_hash,
        &mut canonical_result_bytes,
        response["cluster_receipt"]["result_schema"]
            .as_str()
            .ok_or("ISSUE_1149_CLUSTER_RESULT_SCHEMA_MISSING")?,
    )?;
    for field in [
        "algorithm",
        "algorithm_version",
        "projection_schema",
        "node_label_selection",
        "edge_type_roster",
        "seed",
        "objective_function",
        "move_rule",
        "refinement_rule",
        "aggregation_rule",
        "edge_transform",
    ] {
        add_cluster_result_hash_text(
            &mut result_hash,
            &mut canonical_result_bytes,
            response["cluster_receipt"][field]
                .as_str()
                .ok_or("ISSUE_1149_CLUSTER_RESULT_RECEIPT_TEXT_MISSING")?,
        )?;
    }
    let resolution = response["cluster_receipt"]["resolution"]
        .as_f64()
        .ok_or("ISSUE_1149_CLUSTER_RESULT_RESOLUTION_MISSING")?;
    cluster_hash_f64(&mut result_hash, resolution);
    add_cluster_result_size(&mut canonical_result_bytes, 8)?;
    for field in [
        "node_label_roster_sha256",
        "source_sha256",
        "projection_sha256",
    ] {
        add_cluster_result_hash_text(
            &mut result_hash,
            &mut canonical_result_bytes,
            response["cluster_receipt"][field]
                .as_str()
                .ok_or("ISSUE_1149_CLUSTER_RESULT_HASH_INPUT_MISSING")?,
        )?;
    }
    cluster_hash_u64(&mut result_hash, node_count);
    add_cluster_result_size(&mut canonical_result_bytes, 8)?;
    for node in source_nodes {
        let atom_id = node["atom_id"]
            .as_str()
            .ok_or("ISSUE_1149_CLUSTER_RESULT_ATOM_ID_MISSING")?;
        let community = *atom_id_to_community
            .get(atom_id)
            .ok_or("ISSUE_1149_CLUSTER_RESULT_ASSIGNMENT_MISSING")?;
        add_cluster_result_hash_text(&mut result_hash, &mut canonical_result_bytes, atom_id)?;
        cluster_hash_u64(&mut result_hash, community);
        add_cluster_result_size(&mut canonical_result_bytes, 8)?;
    }
    cluster_hash_u64(&mut result_hash, community_count);
    add_cluster_result_size(&mut canonical_result_bytes, 8)?;
    for cluster in clusters {
        let id = cluster["id"]
            .as_u64()
            .ok_or("ISSUE_1149_CLUSTER_RESULT_ID_MISSING")?;
        let label = cluster["label"]
            .as_str()
            .ok_or("ISSUE_1149_CLUSTER_RESULT_LABEL_MISSING")?;
        let members = cluster["members"]
            .as_u64()
            .ok_or("ISSUE_1149_CLUSTER_RESULT_MEMBERS_MISSING")?;
        let cohesion = cluster["cohesion"]
            .as_f64()
            .ok_or("ISSUE_1149_CLUSTER_RESULT_COHESION_MISSING")?;
        cluster_hash_u64(&mut result_hash, id);
        add_cluster_result_size(&mut canonical_result_bytes, 8)?;
        add_cluster_result_hash_text(&mut result_hash, &mut canonical_result_bytes, label)?;
        cluster_hash_u64(&mut result_hash, members);
        add_cluster_result_size(&mut canonical_result_bytes, 8)?;
        cluster_hash_f64(&mut result_hash, cohesion);
        add_cluster_result_size(&mut canonical_result_bytes, 8)?;
        let member_atom_ids = cluster["member_atom_ids"]
            .as_array()
            .ok_or("ISSUE_1149_CLUSTER_RESULT_MEMBER_ROSTER_MISSING")?;
        cluster_hash_u64(&mut result_hash, u64::try_from(member_atom_ids.len())?);
        add_cluster_result_size(&mut canonical_result_bytes, 8)?;
        for atom_id in member_atom_ids {
            add_cluster_result_hash_text(
                &mut result_hash,
                &mut canonical_result_bytes,
                atom_id
                    .as_str()
                    .ok_or("ISSUE_1149_CLUSTER_RESULT_MEMBER_ATOM_ID_INVALID")?,
            )?;
        }
        for field in ["top_nodes", "packages", "edge_types"] {
            let roster = cluster[field]
                .as_array()
                .ok_or("ISSUE_1149_CLUSTER_RESULT_ROSTER_MISSING")?;
            cluster_hash_u64(&mut result_hash, u64::try_from(roster.len())?);
            add_cluster_result_size(&mut canonical_result_bytes, 8)?;
            for value in roster {
                add_cluster_result_hash_text(
                    &mut result_hash,
                    &mut canonical_result_bytes,
                    value
                        .as_str()
                        .ok_or("ISSUE_1149_CLUSTER_RESULT_ROSTER_TEXT_INVALID")?,
                )?;
            }
        }
    }
    let result_sha256 = finish_cluster_hash(result_hash);
    require(
        response["cluster_receipt"]["result_sha256"] == Value::String(result_sha256.clone())
            && response["cluster_receipt"]["canonical_result_bytes"] == canonical_result_bytes,
        "ISSUE_1149_CLUSTER_RESULT_RECEIPT_REBUILD_MISMATCH",
        json!({
            "computed_result_sha256": result_sha256,
            "receipt_result_sha256": response["cluster_receipt"]["result_sha256"],
            "computed_canonical_result_bytes": canonical_result_bytes,
            "receipt_canonical_result_bytes": response["cluster_receipt"]["canonical_result_bytes"],
        }),
    )?;
    Ok(json!({
        "source_sha256": response["cluster_receipt"]["source_sha256"],
        "projection_sha256": response["cluster_receipt"]["projection_sha256"],
        "result_sha256": result_sha256,
        "canonical_result_bytes": canonical_result_bytes,
        "architecture_payload_bytes": architecture_payload_bytes,
        "final_payload_bytes": final_payload_bytes,
        "result_byte_bound": request_result_byte_bound,
        "astrolabe_kernel_augmented": astrolabe_kernel_augmented,
        "node_count": node_count,
        "calls_edge_count": source["calls_edge_count"],
        "imports_edge_count": source["imports_edge_count"],
        "cluster_edge_count": cluster_edge_count,
        "canonical_typed_edge_count": canonical_typed_edge_count,
        "weighted_undirected_edge_count": weighted_undirected_edge_count,
        "community_count": community_count,
        "move_visit_count": move_visits,
        "independent_semantics": independent_semantics,
        "complete_cluster_and_receipt_rebuilt": true,
    }))
}

fn run_architecture_cluster_success(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    case: &str,
    request: &Value,
    source: &Value,
    astrolabe_kernel_augmented: bool,
) -> AnyResult<Value> {
    let before = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"before","state":before}))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": case,
            "phase": "action",
            "tool": "get_architecture",
            "request": request,
        }))?
    );
    let (raw, envelope, response) = call_tool_with_raw(runner, "get_architecture", request)?;
    require(
        envelope["isError"] != Value::Bool(true),
        "ISSUE_1149_CLUSTER_CALL_FAILED",
        json!({"case": case, "request": request, "response": response}),
    )?;
    let payload_text = envelope["content"][0]["text"]
        .as_str()
        .ok_or("ISSUE_1149_CLUSTER_PAYLOAD_TEXT_MISSING")?;
    let final_payload_bytes = u64::try_from(payload_text.len())?;
    let proof = verify_architecture_cluster_response(
        project,
        request,
        &response,
        source,
        final_payload_bytes,
        astrolabe_kernel_augmented,
    )?;
    let after = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"after","state":after}))?
    );
    require(
        before["sha256"] == after["sha256"],
        "ISSUE_1149_CLUSTER_READ_MUTATED_STATE",
        json!({"case": case, "before": before, "after": after}),
    )?;
    Ok(json!({
        "case": case,
        "request": request,
        "response": response,
        "proof": proof,
        "raw_envelope_bytes": raw.len(),
        "raw_envelope_sha256": sha256(raw.as_bytes()),
        "final_payload_bytes": final_payload_bytes,
        "final_payload_sha256": sha256(payload_text.as_bytes()),
        "before": before,
        "after": after,
        "state_unchanged": true,
    }))
}

fn settle_architecture_cluster_byte_bound(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    case_prefix: &str,
    request_template: &Value,
    source: &Value,
    initial_measurement: u64,
    astrolabe_kernel_augmented: bool,
) -> AnyResult<Value> {
    let mut candidate = initial_measurement;
    let mut rounds = Vec::new();
    for round in 1_u64..=20 {
        let mut request = request_template.clone();
        request["cluster_max_result_bytes"] = json!(candidate);
        let run = run_architecture_cluster_success(
            runner,
            cache,
            project,
            &format!("{case_prefix}_calibration_{round}"),
            &request,
            source,
            astrolabe_kernel_augmented,
        )?;
        let measured = run["proof"]["final_payload_bytes"]
            .as_u64()
            .ok_or("ISSUE_1149_CLUSTER_CALIBRATION_PAYLOAD_BYTES_MISSING")?;
        require(
            measured <= candidate,
            "ISSUE_1149_CLUSTER_EXACT_BOUND_CALIBRATION_GREW",
            json!({
                "case_prefix": case_prefix,
                "round": round,
                "candidate": candidate,
                "measured": measured,
                "run": run,
            }),
        )?;
        let settled = measured == candidate;
        rounds.push(json!({
            "round": round,
            "requested_bound": candidate,
            "measured_payload_bytes": measured,
            "run": run,
        }));
        if settled {
            return Ok(json!({
                "schema": "astrolabe.issue-1149.cluster-exact-byte-bound.v1",
                "bound": candidate,
                "round_count": rounds.len(),
                "rounds": rounds,
                "exact_byte_success": true,
            }));
        }
        candidate = measured;
    }
    Err(format!(
        "ISSUE_1149_CLUSTER_EXACT_BOUND_DID_NOT_SETTLE: case={case_prefix:?}; final_candidate={candidate}; remediation: preserve every response and repair deterministic payload byte accounting"
    )
    .into())
}

fn clone_cluster_fixture_database(
    cache: &Path,
    source_project: &str,
    fixture_project: &str,
) -> AnyResult<PathBuf> {
    let source = cache.join(format!("{source_project}.db"));
    let destination = cache.join(format!("{fixture_project}.db"));
    require(
        !destination.exists(),
        "ISSUE_1149_CLUSTER_FIXTURE_ALREADY_EXISTS",
        destination.display(),
    )?;
    let source_state = optional_file_state(&source)?;
    require(
        source_state["exists"] == Value::Bool(true),
        "ISSUE_1149_CLUSTER_FIXTURE_SOURCE_MISSING",
        source.display(),
    )?;
    let copied = fs::copy(&source, &destination)?;
    require(
        copied == source_state["bytes"].as_u64().unwrap_or(u64::MAX)
            && optional_file_state(&destination)?["sha256"] == source_state["sha256"],
        "ISSUE_1149_CLUSTER_FIXTURE_COPY_MISMATCH",
        json!({"source": source, "destination": destination}),
    )?;
    let connection = Connection::open(&destination)?;
    connection.pragma_update(None, "foreign_keys", false)?;
    let changed = connection.execute(
        "UPDATE projects SET name = ?1 WHERE name = ?2",
        [fixture_project, source_project],
    )?;
    require(
        changed == 1,
        "ISSUE_1149_CLUSTER_FIXTURE_PROJECT_RENAME_FAILED",
        fixture_project,
    )?;
    for table in [
        "file_hashes",
        "nodes",
        "edges",
        "project_summaries",
        "node_vectors",
        "token_vectors",
    ] {
        connection.execute(
            &format!("UPDATE {table} SET project = ?1 WHERE project = ?2"),
            [fixture_project, source_project],
        )?;
    }
    let source_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM projects WHERE name = ?1",
        [source_project],
        |row| row.get(0),
    )?;
    let fixture_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM projects WHERE name = ?1",
        [fixture_project],
        |row| row.get(0),
    )?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    require(
        source_rows == 0 && fixture_rows == 1 && integrity == "ok",
        "ISSUE_1149_CLUSTER_FIXTURE_RENAME_READBACK_FAILED",
        json!({
            "source_rows": source_rows,
            "fixture_rows": fixture_rows,
            "integrity": integrity,
        }),
    )?;
    drop(connection);
    let metadata = fs::symlink_metadata(&destination)?;
    require(
        metadata.is_file() && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1149_CLUSTER_FIXTURE_FILE_INVALID",
        destination.display(),
    )?;
    Ok(destination)
}

fn cluster_fixture_source_state(
    cache: &Path,
    project: &str,
    path_scope: Option<&str>,
) -> AnyResult<Value> {
    let path = cache.join(format!("{project}.db"));
    let connection = readonly_sqlite(&path)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let foreign_key_errors: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    let project_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM projects WHERE name = ?1",
        [project],
        |row| row.get(0),
    )?;
    let all_nodes = {
        let mut statement = connection.prepare(
            "SELECT id, atom_id, label, name, qualified_name, file_path FROM nodes \
             WHERE project = ?1 ORDER BY atom_id, id",
        )?;
        statement
            .query_map([project], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let in_scope = |file_path: &str| {
        path_scope.is_none_or(|scope| {
            file_path == scope
                || file_path
                    .strip_prefix(scope)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
    };
    let nodes = all_nodes
        .into_iter()
        .filter(|row| in_scope(&row.5))
        .collect::<Vec<_>>();
    let sqlite_to_atom = nodes
        .iter()
        .map(|row| (row.0, row.1.clone()))
        .collect::<BTreeMap<_, _>>();
    let raw_edges = {
        let mut statement = connection.prepare(
            "SELECT id, source_id, target_id, type FROM edges \
             WHERE project = ?1 AND type IN ('CALLS','IMPORTS') ORDER BY id",
        )?;
        statement
            .query_map([project], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let edges = raw_edges
        .iter()
        .filter_map(|(id, source_id, target_id, edge_type)| {
            Some(json!({
                "sqlite_id": id,
                "source_atom_id": sqlite_to_atom.get(source_id)?,
                "target_atom_id": sqlite_to_atom.get(target_id)?,
                "type": edge_type,
            }))
        })
        .collect::<Vec<_>>();
    let orphan_edges = raw_edges
        .iter()
        .filter(|(_, source_id, target_id, _)| {
            path_scope.is_none()
                && (!sqlite_to_atom.contains_key(source_id)
                    || !sqlite_to_atom.contains_key(target_id))
        })
        .count();
    let mut canonical = BTreeMap::<(String, String, String), u64>::new();
    for edge in &edges {
        let key = (
            edge["source_atom_id"]
                .as_str()
                .ok_or("ISSUE_1149_FIXTURE_EDGE_SOURCE_INVALID")?
                .to_string(),
            edge["target_atom_id"]
                .as_str()
                .ok_or("ISSUE_1149_FIXTURE_EDGE_TARGET_INVALID")?
                .to_string(),
            edge["type"]
                .as_str()
                .ok_or("ISSUE_1149_FIXTURE_EDGE_TYPE_INVALID")?
                .to_string(),
        );
        let count = canonical.entry(key).or_default();
        *count = count
            .checked_add(1)
            .ok_or("ISSUE_1149_FIXTURE_EDGE_MULTIPLICITY_OVERFLOW")?;
    }
    let canonical_edges = canonical
        .iter()
        .map(|((source, target, edge_type), multiplicity)| {
            json!({
                "source_atom_id": source,
                "target_atom_id": target,
                "type": edge_type,
                "multiplicity": multiplicity,
            })
        })
        .collect::<Vec<_>>();
    let duplicate_edge_count = edges
        .len()
        .checked_sub(canonical_edges.len())
        .ok_or("ISSUE_1149_FIXTURE_EDGE_ACCOUNTING_UNDERFLOW")?;
    let self_loop_count = canonical
        .keys()
        .filter(|(source, target, _)| source == target)
        .count();
    let node_rows = nodes
        .iter()
        .map(
            |(sqlite_id, atom_id, label, name, qualified_name, file_path)| {
                json!({
                    "sqlite_id": sqlite_id,
                    "atom_id": atom_id,
                    "label": label,
                    "name": name,
                    "qualified_name": qualified_name,
                    "file_path": file_path,
                })
            },
        )
        .collect::<Vec<_>>();
    drop(connection);
    require(
        integrity == "ok" && project_rows == 1,
        "ISSUE_1149_CLUSTER_FIXTURE_SQLITE_INVALID",
        json!({"project": project, "integrity": integrity, "project_rows": project_rows}),
    )?;
    Ok(json!({
        "project": project,
        "path_scope": path_scope,
        "integrity": integrity,
        "foreign_key_errors": foreign_key_errors,
        "node_count": node_rows.len(),
        "cluster_edge_count": edges.len(),
        "raw_cluster_edge_count": if path_scope.is_some() { edges.len() } else { raw_edges.len() },
        "canonical_typed_edge_count": canonical_edges.len(),
        "duplicate_edge_count": duplicate_edge_count,
        "self_loop_count": self_loop_count,
        "orphan_cluster_edge_count": orphan_edges,
        "nodes": node_rows,
        "raw_edges": edges,
        "canonical_edges": canonical_edges,
        "file": optional_file_state(&path)?,
        "physical_sqlite_read": true,
    }))
}

fn cluster_fixture_request(
    project: &str,
    source: &Value,
    path_scope: Option<&str>,
) -> AnyResult<Value> {
    let nodes = source["node_count"]
        .as_u64()
        .ok_or("ISSUE_1149_FIXTURE_NODE_COUNT_MISSING")?;
    let edges = source["raw_cluster_edge_count"]
        .as_u64()
        .ok_or("ISSUE_1149_FIXTURE_EDGE_COUNT_MISSING")?;
    let mut request = json!({
        "project": project,
        "aspects": ["clusters"],
        "resolution": 1,
        "cluster_max_nodes": nodes.max(1),
        "cluster_max_edges": edges.max(1),
        "cluster_max_result_bytes": 1_048_576_u64,
        "cluster_max_move_visits": 65_536_u64,
    });
    if let Some(path_scope) = path_scope {
        request["path"] = Value::String(path_scope.to_string());
    }
    Ok(request)
}

fn run_cluster_fixture_success(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    case: &str,
    path_scope: Option<&str>,
) -> AnyResult<Value> {
    let source = cluster_fixture_source_state(cache, project, path_scope)?;
    let request = cluster_fixture_request(project, &source, path_scope)?;
    let before = tree_state(cache)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "before", "state": before}))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "action", "request": request}))?
    );
    let (raw, envelope, response) = call_tool_with_raw(runner, "get_architecture", &request)?;
    let after = tree_state(cache)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "after", "state": after}))?
    );
    let clusters = response["clusters"]
        .as_array()
        .ok_or("ISSUE_1149_FIXTURE_CLUSTERS_MISSING")?;
    let node_count = source["node_count"]
        .as_u64()
        .ok_or("ISSUE_1149_FIXTURE_NODE_COUNT_MISSING")?;
    let edge_count = source["cluster_edge_count"]
        .as_u64()
        .ok_or("ISSUE_1149_FIXTURE_EDGE_COUNT_MISSING")?;
    require(
        envelope["isError"] != Value::Bool(true)
            && before["sha256"] == after["sha256"]
            && response["project"] == project
            && response["total_nodes"] == node_count
            && response["cluster_receipt"]["status"] == "complete"
            && response["cluster_receipt"]["requested_node_count"] == node_count
            && response["cluster_receipt"]["included_node_count"] == node_count
            && response["cluster_receipt"]["requested_edge_count"] == edge_count
            && response["cluster_receipt"]["included_edge_count"] == edge_count
            && response["cluster_receipt"]["complete_coverage_verified"] == Value::Bool(true)
            && clusters
                .iter()
                .filter_map(|cluster| cluster["members"].as_u64())
                .try_fold(0_u64, u64::checked_add)
                == Some(node_count),
        "ISSUE_1149_CLUSTER_FIXTURE_SUCCESS_INVALID",
        json!({"case": case, "source": source, "request": request, "response": response}),
    )?;
    let mut assignment = BTreeMap::<String, u64>::new();
    for cluster in clusters {
        let community = cluster["id"]
            .as_u64()
            .ok_or("ISSUE_1149_FIXTURE_COMMUNITY_ID_MISSING")?;
        for atom_id in cluster["member_atom_ids"]
            .as_array()
            .ok_or("ISSUE_1149_FIXTURE_MEMBER_ROSTER_MISSING")?
        {
            let atom_id = atom_id
                .as_str()
                .ok_or("ISSUE_1149_FIXTURE_MEMBER_ATOM_INVALID")?;
            require(
                assignment.insert(atom_id.to_string(), community).is_none(),
                "ISSUE_1149_FIXTURE_DUPLICATE_MEMBER",
                atom_id,
            )?;
        }
    }
    let semantics = independently_recompute_cluster_semantics(&source, &response, &assignment)?;
    let payload_text = envelope["content"][0]["text"]
        .as_str()
        .ok_or("ISSUE_1149_FIXTURE_PAYLOAD_TEXT_MISSING")?;
    Ok(json!({
        "case": case,
        "source": source,
        "request": request,
        "response": response,
        "independent_semantics": semantics,
        "raw_envelope_bytes": raw.len(),
        "raw_envelope_sha256": sha256(raw.as_bytes()),
        "final_payload_bytes": payload_text.len(),
        "final_payload_sha256": sha256(payload_text.as_bytes()),
        "before": before,
        "after": after,
        "state_unchanged": true,
    }))
}

fn run_cluster_fixture_refusal(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    case: &str,
    expected_code: &str,
) -> AnyResult<Value> {
    let source = cluster_fixture_source_state(cache, project, None)?;
    let request = cluster_fixture_request(project, &source, None)?;
    let before = tree_state(cache)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "before", "state": before}))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "action", "request": request}))?
    );
    let (raw, envelope, response) = call_tool_with_raw(runner, "get_architecture", &request)?;
    let after = tree_state(cache)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "after", "state": after}))?
    );
    require(
        envelope["isError"] == Value::Bool(true)
            && response["code"] == expected_code
            && response.get("clusters").is_none()
            && before["sha256"] == after["sha256"],
        "ISSUE_1149_CLUSTER_FIXTURE_REFUSAL_INVALID",
        json!({"case": case, "source": source, "request": request, "response": response}),
    )?;
    Ok(json!({
        "case": case,
        "source": source,
        "request": request,
        "response": response,
        "raw_envelope_bytes": raw.len(),
        "raw_envelope_sha256": sha256(raw.as_bytes()),
        "before": before,
        "after": after,
        "state_unchanged": true,
    }))
}

fn permute_cluster_fixture_node_ids(path: &Path, project: &str) -> AnyResult<Value> {
    let connection = Connection::open(path)?;
    connection.pragma_update(None, "foreign_keys", false)?;
    let ids = {
        let mut statement =
            connection.prepare("SELECT id FROM nodes WHERE project = ?1 ORDER BY id")?;
        statement
            .query_map([project], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    require(
        ids.len() > 1 && ids.iter().all(|id| *id > 0),
        "ISSUE_1149_CLUSTER_PERMUTATION_SOURCE_IDS_INVALID",
        &ids,
    )?;
    let mapping = ids
        .iter()
        .enumerate()
        .map(|(index, id)| -> AnyResult<(i64, i64)> { Ok((*id, -i64::try_from(index + 1)?)) })
        .collect::<AnyResult<BTreeMap<_, _>>>()?;
    connection.execute_batch(
        "CREATE TEMP TABLE issue_1149_node_id_map(old_id INTEGER PRIMARY KEY, new_id INTEGER UNIQUE NOT NULL);",
    )?;
    {
        let mut insert = connection
            .prepare("INSERT INTO issue_1149_node_id_map(old_id,new_id) VALUES(?1,?2)")?;
        for (old_id, new_id) in &mapping {
            insert.execute([old_id, new_id])?;
        }
    }
    for (table, column) in [
        ("edges", "source_id"),
        ("edges", "target_id"),
        ("node_vectors", "node_id"),
    ] {
        connection.execute(
            &format!(
                "UPDATE {table} SET {column} = (SELECT new_id FROM issue_1149_node_id_map WHERE old_id = {table}.{column}) \
                 WHERE {column} IN (SELECT old_id FROM issue_1149_node_id_map)"
            ),
            [],
        )?;
    }
    connection.execute(
        "UPDATE nodes SET id = (SELECT new_id FROM issue_1149_node_id_map WHERE old_id = nodes.id) \
         WHERE project = ?1",
        [project],
    )?;
    let observed = {
        let mut statement = connection
            .prepare("SELECT atom_id, id FROM nodes WHERE project = ?1 ORDER BY atom_id")?;
        statement
            .query_map([project], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let foreign_key_errors: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    require(
        foreign_key_errors == 0
            && integrity == "ok"
            && observed.iter().all(|(_, id)| *id < 0)
            && mapping.len() == observed.len(),
        "ISSUE_1149_CLUSTER_PERMUTATION_READBACK_INVALID",
        json!({"integrity": integrity, "foreign_key_errors": foreign_key_errors, "observed": observed}),
    )?;
    drop(connection);
    Ok(json!({
        "mapping": mapping,
        "observed_atom_id_to_sqlite_id": observed,
        "integrity": integrity,
        "foreign_key_errors": foreign_key_errors,
        "physical_sqlite_ids_permuted": true,
    }))
}

fn install_dense_six_cluster_fixture(path: &Path, project: &str) -> AnyResult<Value> {
    let before = optional_file_state(path)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"architecture_clusters_dense_six_physical_install",
            "phase":"before",
            "project":project,
            "state":before,
        }))?
    );
    let mut connection = Connection::open(path)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    let nodes = {
        let mut statement = connection.prepare(
            "SELECT id, atom_id FROM nodes WHERE project = ?1 ORDER BY atom_id, id LIMIT 6",
        )?;
        statement
            .query_map([project], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    require(
        nodes.len() == 6,
        "ISSUE_1149_DENSE_SIX_NODE_ROSTER_INVALID",
        json!({"project": project, "nodes": nodes}),
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"architecture_clusters_dense_six_physical_install",
            "phase":"action",
            "operation":"replace project edges with a complete directed six-node CALLS clique, one duplicate edge, and one self-loop",
            "project":project,
            "selected_nodes":nodes,
            "expected_raw_edges":32,
            "expected_canonical_typed_edges":31,
            "expected_duplicate_edges":1,
            "expected_self_loops":1,
        }))?
    );
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute("DELETE FROM edges WHERE project = ?1", [project])?;
    {
        let mut insert = transaction.prepare(
            "INSERT INTO edges(project,source_id,target_id,type,properties) \
             VALUES(?1,?2,?3,'CALLS','{}')",
        )?;
        for (source_index, (source_id, _)) in nodes.iter().enumerate() {
            for (target_index, (target_id, _)) in nodes.iter().enumerate() {
                if source_index != target_index {
                    insert.execute(rusqlite::params![project, source_id, target_id])?;
                }
            }
        }
        insert.execute(rusqlite::params![project, nodes[0].0, nodes[1].0])?;
        insert.execute(rusqlite::params![project, nodes[0].0, nodes[0].0])?;
    }
    transaction.commit()?;
    let raw_edge_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM edges WHERE project = ?1 AND type IN ('CALLS','IMPORTS')",
        [project],
        |row| row.get(0),
    )?;
    let duplicate_edge_count: i64 = connection.query_row(
        "SELECT COALESCE(SUM(multiplicity - 1),0) FROM (\
             SELECT COUNT(*) AS multiplicity FROM edges \
             WHERE project = ?1 AND type IN ('CALLS','IMPORTS') \
             GROUP BY source_id,target_id,type\
         )",
        [project],
        |row| row.get(0),
    )?;
    let self_loop_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM (\
             SELECT 1 FROM edges WHERE project = ?1 AND type IN ('CALLS','IMPORTS') \
             AND source_id = target_id GROUP BY source_id,target_id,type\
         )",
        [project],
        |row| row.get(0),
    )?;
    let foreign_key_errors: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    require(
        raw_edge_count == 32
            && duplicate_edge_count == 1
            && self_loop_count == 1
            && foreign_key_errors == 0
            && integrity == "ok",
        "ISSUE_1149_DENSE_SIX_PHYSICAL_WRITE_READBACK_INVALID",
        json!({
            "raw_edge_count": raw_edge_count,
            "duplicate_edge_count": duplicate_edge_count,
            "self_loop_count": self_loop_count,
            "foreign_key_errors": foreign_key_errors,
            "integrity": integrity,
        }),
    )?;
    drop(connection);
    let after = optional_file_state(path)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"architecture_clusters_dense_six_physical_install",
            "phase":"after",
            "project":project,
            "state":after,
        }))?
    );
    require(
        before["sha256"] != after["sha256"],
        "ISSUE_1149_DENSE_SIX_PHYSICAL_FILE_UNCHANGED",
        json!({"before":before,"after":after}),
    )?;
    Ok(json!({
        "selected_nodes": nodes,
        "selected_atom_ids": nodes.iter().map(|(_, atom_id)| atom_id).collect::<Vec<_>>(),
        "raw_edge_count": raw_edge_count,
        "canonical_typed_edge_count": 31,
        "duplicate_edge_count": duplicate_edge_count,
        "self_loop_count": self_loop_count,
        "foreign_key_errors": foreign_key_errors,
        "integrity": integrity,
        "before": before,
        "after": after,
        "complete_directed_six_node_calls_clique": true,
        "physical_sqlite_write_readback": true,
    }))
}

fn exercise_cluster_fixture_edges(
    runner: &CbmToolRunner,
    cache: &Path,
    source_project: &str,
) -> AnyResult<Value> {
    let fixture_name = |suffix: &str| format!("{source_project}_issue1149_{suffix}");

    let empty_project = fixture_name("empty");
    let empty_path = clone_cluster_fixture_database(cache, source_project, &empty_project)?;
    {
        let connection = Connection::open(&empty_path)?;
        connection.pragma_update(None, "foreign_keys", false)?;
        for table in [
            "edges",
            "node_vectors",
            "nodes",
            "token_vectors",
            "file_hashes",
            "project_summaries",
        ] {
            connection.execute(
                &format!("DELETE FROM {table} WHERE project = ?1"),
                [&empty_project],
            )?;
        }
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        require(
            integrity == "ok",
            "ISSUE_1149_EMPTY_FIXTURE_INTEGRITY_FAILED",
            integrity,
        )?;
    }
    let empty = run_cluster_fixture_success(
        runner,
        cache,
        &empty_project,
        "architecture_clusters_empty_physical_sqlite",
        None,
    )?;
    require(
        empty["source"]["node_count"] == 0
            && empty["source"]["cluster_edge_count"] == 0
            && empty["response"]["clusters"] == json!([])
            && empty["response"]["cluster_receipt"]["community_count"] == 0
            && empty["response"]["cluster_receipt"]["objective"].as_f64() == Some(0.0),
        "ISSUE_1149_EMPTY_FIXTURE_RESULT_INVALID",
        &empty,
    )?;

    let edgeless_project = fixture_name("edgeless");
    let edgeless_path = clone_cluster_fixture_database(cache, source_project, &edgeless_project)?;
    {
        let connection = Connection::open(&edgeless_path)?;
        connection.execute("DELETE FROM edges WHERE project = ?1", [&edgeless_project])?;
        let node_count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM nodes WHERE project = ?1",
            [&edgeless_project],
            |row| row.get(0),
        )?;
        require(
            node_count > 1,
            "ISSUE_1149_EDGELESS_FIXTURE_NODE_ROSTER_INVALID",
            node_count,
        )?;
    }
    let edgeless = run_cluster_fixture_success(
        runner,
        cache,
        &edgeless_project,
        "architecture_clusters_edgeless_physical_sqlite",
        None,
    )?;
    require(
        edgeless["source"]["cluster_edge_count"] == 0
            && edgeless["response"]["cluster_receipt"]["community_count"]
                == edgeless["source"]["node_count"]
            && edgeless["response"]["cluster_receipt"]["objective"].as_f64() == Some(0.0),
        "ISSUE_1149_EDGELESS_FIXTURE_RESULT_INVALID",
        &edgeless,
    )?;

    let dense_six_project = fixture_name("dense_six");
    let dense_six_path = clone_cluster_fixture_database(cache, source_project, &dense_six_project)?;
    let dense_six_action = install_dense_six_cluster_fixture(&dense_six_path, &dense_six_project)?;
    let dense_six = run_cluster_fixture_success(
        runner,
        cache,
        &dense_six_project,
        "architecture_clusters_dense_six_duplicate_self_loop",
        None,
    )?;
    let selected_dense_atoms = dense_six_action["selected_atom_ids"]
        .as_array()
        .ok_or("ISSUE_1149_DENSE_SIX_SELECTED_ATOMS_MISSING")?
        .iter()
        .map(|atom_id| -> AnyResult<String> {
            Ok(atom_id
                .as_str()
                .ok_or("ISSUE_1149_DENSE_SIX_SELECTED_ATOM_INVALID")?
                .to_string())
        })
        .collect::<AnyResult<BTreeSet<_>>>()?;
    let dense_cluster = dense_six["response"]["clusters"]
        .as_array()
        .ok_or("ISSUE_1149_DENSE_SIX_CLUSTERS_MISSING")?
        .iter()
        .find(|cluster| {
            cluster["member_atom_ids"]
                .as_array()
                .map(|members| {
                    members
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect::<BTreeSet<_>>()
                        == selected_dense_atoms
                })
                .unwrap_or(false)
        })
        .ok_or("ISSUE_1149_DENSE_SIX_COMMUNITY_MISSING")?;
    require(
        dense_six["source"]["cluster_edge_count"] == 32
            && dense_six["source"]["canonical_typed_edge_count"] == 31
            && dense_six["source"]["duplicate_edge_count"] == 1
            && dense_six["source"]["self_loop_count"] == 1
            && dense_six["source"]["foreign_key_errors"] == 0
            && dense_six["source"]["file"] == dense_six_action["after"]
            && dense_six["response"]["cluster_receipt"]["duplicate_edge_count"] == 1
            && dense_six["response"]["cluster_receipt"]["self_loop_count"] == 1
            && dense_cluster["members"] == 6
            && dense_cluster["member_atom_id_count"] == 6
            && dense_cluster["member_atom_ids"].as_array().map(Vec::len) == Some(6)
            && dense_cluster["top_nodes"].as_array().map(Vec::len) == Some(5),
        "ISSUE_1149_DENSE_SIX_RESULT_INVALID",
        json!({
            "action": dense_six_action,
            "source": dense_six["source"],
            "receipt": dense_six["response"]["cluster_receipt"],
            "cluster": dense_cluster,
        }),
    )?;

    let unknown_project = fixture_name("unknown_endpoint");
    let unknown_path = clone_cluster_fixture_database(cache, source_project, &unknown_project)?;
    {
        let connection = Connection::open(&unknown_path)?;
        connection.pragma_update(None, "foreign_keys", false)?;
        let maximum_id: i64 = connection.query_row(
            "SELECT MAX(id) FROM nodes WHERE project = ?1",
            [&unknown_project],
            |row| row.get(0),
        )?;
        let changed = connection.execute(
            "UPDATE edges SET target_id = ?1 WHERE id = (SELECT MIN(id) FROM edges WHERE project = ?2)",
            rusqlite::params![maximum_id.checked_add(1_000_000).ok_or("unknown endpoint overflow")?, unknown_project],
        )?;
        let foreign_key_errors: i64 =
            connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })?;
        require(
            changed == 1 && foreign_key_errors == 1,
            "ISSUE_1149_UNKNOWN_ENDPOINT_FIXTURE_NOT_PHYSICAL",
            json!({"changed": changed, "foreign_key_errors": foreign_key_errors}),
        )?;
    }
    let unknown_endpoint = run_cluster_fixture_refusal(
        runner,
        cache,
        &unknown_project,
        "architecture_clusters_unknown_physical_endpoint",
        "CBM_ARCH_CLUSTER_UNKNOWN_ENDPOINT",
    )?;
    require(
        unknown_endpoint["source"]["orphan_cluster_edge_count"] == 1
            && unknown_endpoint["source"]["foreign_key_errors"] == 1,
        "ISSUE_1149_UNKNOWN_ENDPOINT_FIXTURE_ROSTER_INVALID",
        &unknown_endpoint,
    )?;

    let permutation_project = fixture_name("permutation");
    let permutation_path =
        clone_cluster_fixture_database(cache, source_project, &permutation_project)?;
    let permutation_before = run_cluster_fixture_success(
        runner,
        cache,
        &permutation_project,
        "architecture_clusters_insertion_order_before_permutation",
        None,
    )?;
    let permutation_action =
        permute_cluster_fixture_node_ids(&permutation_path, &permutation_project)?;
    let permutation_after = run_cluster_fixture_success(
        runner,
        cache,
        &permutation_project,
        "architecture_clusters_insertion_order_after_permutation",
        None,
    )?;
    require(
        permutation_before["source"]["file"]["sha256"]
            != permutation_after["source"]["file"]["sha256"]
            && permutation_before["source"]["nodes"] != permutation_after["source"]["nodes"]
            && permutation_before["response"] == permutation_after["response"]
            && permutation_before["raw_envelope_sha256"]
                == permutation_after["raw_envelope_sha256"]
            && permutation_before["final_payload_sha256"]
                == permutation_after["final_payload_sha256"],
        "ISSUE_1149_CLUSTER_SQLITE_ID_PERMUTATION_DRIFT",
        json!({
            "before": permutation_before,
            "action": permutation_action,
            "after": permutation_after,
        }),
    )?;

    let literal_project = fixture_name("literal_path");
    let literal_path = clone_cluster_fixture_database(cache, source_project, &literal_project)?;
    let literal_scope = "issue1149%_literal";
    let literal_atom_ids = {
        let connection = Connection::open(&literal_path)?;
        connection.pragma_update(None, "foreign_keys", false)?;
        let nodes = {
            let mut statement = connection.prepare(
                "SELECT id, atom_id FROM nodes WHERE project = ?1 ORDER BY atom_id LIMIT 4",
            )?;
            statement
                .query_map([&literal_project], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        require(
            nodes.len() == 4,
            "ISSUE_1149_LITERAL_SCOPE_NODE_ROSTER_TOO_SMALL",
            nodes.len(),
        )?;
        connection.execute("DELETE FROM edges WHERE project = ?1", [&literal_project])?;
        connection.execute(
            "UPDATE nodes SET file_path = 'issue1149XXliteral/outside.rs' WHERE project = ?1",
            [&literal_project],
        )?;
        connection.execute(
            "UPDATE nodes SET file_path = ?1 WHERE id = ?2",
            rusqlite::params![format!("{literal_scope}/first.rs"), nodes[0].0],
        )?;
        connection.execute(
            "UPDATE nodes SET file_path = ?1 WHERE id = ?2",
            rusqlite::params![format!("{literal_scope}/second.rs"), nodes[1].0],
        )?;
        connection.execute(
            "INSERT INTO edges(project,source_id,target_id,type,properties) VALUES(?1,?2,?3,'CALLS','{}')",
            rusqlite::params![literal_project, nodes[0].0, nodes[1].0],
        )?;
        connection.execute(
            "INSERT INTO edges(project,source_id,target_id,type,properties) VALUES(?1,?2,?3,'CALLS','{}')",
            rusqlite::params![literal_project, nodes[2].0, nodes[3].0],
        )?;
        nodes
            .into_iter()
            .take(2)
            .map(|(_, atom_id)| atom_id)
            .collect::<BTreeSet<_>>()
    };
    let literal_path_isolation = run_cluster_fixture_success(
        runner,
        cache,
        &literal_project,
        "architecture_clusters_literal_percent_underscore_path",
        Some(literal_scope),
    )?;
    let returned_literal_atoms = literal_path_isolation["response"]["clusters"]
        .as_array()
        .ok_or("ISSUE_1149_LITERAL_SCOPE_CLUSTERS_MISSING")?
        .iter()
        .flat_map(|cluster| {
            cluster["member_atom_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
        })
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    require(
        literal_path_isolation["source"]["node_count"] == 2
            && literal_path_isolation["source"]["cluster_edge_count"] == 1
            && returned_literal_atoms == literal_atom_ids,
        "ISSUE_1149_LITERAL_SCOPE_ISOLATION_FAILED",
        json!({
            "expected": literal_atom_ids,
            "returned": returned_literal_atoms,
            "result": literal_path_isolation,
        }),
    )?;

    Ok(json!({
        "schema": "astrolabe.issue-1149.cluster-edge-fixtures.v1",
        "source_database": optional_file_state(&cache.join(format!("{source_project}.db")))?,
        "empty": empty,
        "edgeless": edgeless,
        "dense_six_duplicate_self_loop": {
            "action": dense_six_action,
            "run": dense_six,
            "member_count_above_top_node_cap": true,
            "exact_full_member_roster_count": 6,
            "exact_top_node_count": 5,
            "real_duplicate_and_self_loop": true,
        },
        "unknown_endpoint": unknown_endpoint,
        "permutation": {
            "before": permutation_before,
            "action": permutation_action,
            "after": permutation_after,
            "exact_raw_and_final_hashes_equal": true,
        },
        "literal_path_isolation": literal_path_isolation,
        "fixture_files": [empty_path, edgeless_path, dense_six_path, unknown_path, permutation_path, literal_path],
        "copied_real_indexed_database_schema": true,
        "zero_reparse_points": true,
    }))
}

fn expect_raw_architecture_refusal(
    runner: &CbmToolRunner,
    cache: &Path,
    case: &str,
    raw_arguments: &str,
    expected_code: &str,
) -> AnyResult<Value> {
    let before = tree_state(cache)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "before", "state": before}))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": case,
            "phase": "action",
            "raw_argument_bytes": raw_arguments.len(),
            "raw_argument_sha256": sha256(raw_arguments.as_bytes()),
        }))?
    );
    let raw_handler =
        astrolabe_server::migration::handle_tool_raw(runner, "get_architecture", raw_arguments)?;
    let handler_envelope: Value = serde_json::from_str(&raw_handler)?;
    let handler_payload = handler_envelope["structuredContent"].clone();
    let raw_jsonrpc = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1149,\"method\":\"tools/call\",\"params\":{{\"name\":\"get_architecture\",\"arguments\":{raw_arguments}}}}}"
    );
    let raw_jsonrpc_response =
        astrolabe_server::migration::handle_jsonrpc_raw(runner, &raw_jsonrpc)?
            .ok_or("ISSUE_1149_RAW_JSONRPC_RESPONSE_MISSING")?;
    let jsonrpc_response: Value = serde_json::from_str(&raw_jsonrpc_response)?;
    let jsonrpc_fault = if expected_code == "ASTRO_MCP_DUPLICATE_JSON_KEY" {
        &jsonrpc_response["error"]["data"]
    } else {
        &jsonrpc_response["result"]["structuredContent"]
    };
    let after = tree_state(cache)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "after", "state": after}))?
    );
    require(
        handler_envelope["isError"] == Value::Bool(true)
            && handler_payload["code"] == expected_code
            && jsonrpc_response["jsonrpc"] == "2.0"
            && jsonrpc_response["id"] == 1149
            && jsonrpc_fault["code"] == expected_code
            && before["sha256"] == after["sha256"],
        "ISSUE_1149_RAW_ARCHITECTURE_REFUSAL_INVALID",
        json!({
            "case": case,
            "expected_code": expected_code,
            "handler": handler_envelope,
            "jsonrpc": jsonrpc_response,
            "before": before,
            "after": after,
        }),
    )?;
    Ok(json!({
        "case": case,
        "expected_code": expected_code,
        "raw_arguments": {
            "bytes": raw_arguments.len(),
            "sha256": sha256(raw_arguments.as_bytes()),
            "text": raw_arguments,
        },
        "handler": {
            "bytes": raw_handler.len(),
            "sha256": sha256(raw_handler.as_bytes()),
            "response": handler_envelope,
        },
        "jsonrpc": {
            "request_bytes": raw_jsonrpc.len(),
            "request_sha256": sha256(raw_jsonrpc.as_bytes()),
            "response_bytes": raw_jsonrpc_response.len(),
            "response_sha256": sha256(raw_jsonrpc_response.as_bytes()),
            "response": jsonrpc_response,
        },
        "before": before,
        "after": after,
        "refused_before_native_physical_state_dispatch": true,
        "state_unchanged": true,
    }))
}

fn readback_cluster_fixture_edges(
    runner: &CbmToolRunner,
    cache: &Path,
    execution: &Value,
) -> AnyResult<Value> {
    let rerun_success = |field: &str, path_scope: Option<&str>| -> AnyResult<Value> {
        let expected = &execution[field];
        let project = expected["request"]["project"]
            .as_str()
            .ok_or("ISSUE_1149_FIXTURE_READBACK_PROJECT_MISSING")?;
        let observed = run_cluster_fixture_success(
            runner,
            cache,
            project,
            &format!("architecture_clusters_{field}_separate_process_readback"),
            path_scope,
        )?;
        require(
            observed["source"] == expected["source"]
                && observed["request"] == expected["request"]
                && observed["response"] == expected["response"]
                && observed["raw_envelope_sha256"] == expected["raw_envelope_sha256"]
                && observed["final_payload_sha256"] == expected["final_payload_sha256"],
            "ISSUE_1149_CLUSTER_FIXTURE_SEPARATE_READBACK_MISMATCH",
            json!({"field": field, "expected": expected, "observed": observed}),
        )?;
        Ok(observed)
    };
    let empty = rerun_success("empty", None)?;
    let edgeless = rerun_success("edgeless", None)?;
    let expected_dense = &execution["dense_six_duplicate_self_loop"]["run"];
    let dense_project = expected_dense["request"]["project"]
        .as_str()
        .ok_or("ISSUE_1149_DENSE_SIX_READBACK_PROJECT_MISSING")?;
    let dense_six_duplicate_self_loop = run_cluster_fixture_success(
        runner,
        cache,
        dense_project,
        "architecture_clusters_dense_six_separate_process_readback",
        None,
    )?;
    require(
        dense_six_duplicate_self_loop["source"] == expected_dense["source"]
            && dense_six_duplicate_self_loop["source"]["file"]
                == execution["dense_six_duplicate_self_loop"]["action"]["after"]
            && dense_six_duplicate_self_loop["request"] == expected_dense["request"]
            && dense_six_duplicate_self_loop["response"] == expected_dense["response"]
            && dense_six_duplicate_self_loop["raw_envelope_sha256"]
                == expected_dense["raw_envelope_sha256"]
            && dense_six_duplicate_self_loop["final_payload_sha256"]
                == expected_dense["final_payload_sha256"]
            && dense_six_duplicate_self_loop["source"]["duplicate_edge_count"] == 1
            && dense_six_duplicate_self_loop["source"]["self_loop_count"] == 1
            && dense_six_duplicate_self_loop["response"]["clusters"]
                .as_array()
                .is_some_and(|clusters| {
                    clusters.iter().any(|cluster| {
                        cluster["members"] == 6
                            && cluster["member_atom_ids"].as_array().map(Vec::len) == Some(6)
                            && cluster["top_nodes"].as_array().map(Vec::len) == Some(5)
                    })
                }),
        "ISSUE_1149_DENSE_SIX_SEPARATE_READBACK_MISMATCH",
        json!({"expected": expected_dense, "observed": dense_six_duplicate_self_loop}),
    )?;
    let expected_permutation = &execution["permutation"]["after"];
    let permutation_project = expected_permutation["request"]["project"]
        .as_str()
        .ok_or("ISSUE_1149_FIXTURE_READBACK_PERMUTATION_PROJECT_MISSING")?;
    let permutation = run_cluster_fixture_success(
        runner,
        cache,
        permutation_project,
        "architecture_clusters_permutation_separate_process_readback",
        None,
    )?;
    require(
        permutation["source"] == expected_permutation["source"]
            && permutation["request"] == expected_permutation["request"]
            && permutation["response"] == expected_permutation["response"]
            && permutation["raw_envelope_sha256"] == expected_permutation["raw_envelope_sha256"]
            && permutation["final_payload_sha256"] == expected_permutation["final_payload_sha256"],
        "ISSUE_1149_CLUSTER_PERMUTATION_SEPARATE_READBACK_MISMATCH",
        json!({"expected": expected_permutation, "observed": permutation}),
    )?;
    let literal_scope = execution["literal_path_isolation"]["request"]["path"]
        .as_str()
        .ok_or("ISSUE_1149_LITERAL_SCOPE_READBACK_PATH_MISSING")?;
    let literal_path_isolation = rerun_success("literal_path_isolation", Some(literal_scope))?;
    let expected_unknown = &execution["unknown_endpoint"];
    let unknown_project = expected_unknown["request"]["project"]
        .as_str()
        .ok_or("ISSUE_1149_UNKNOWN_READBACK_PROJECT_MISSING")?;
    let unknown_endpoint = run_cluster_fixture_refusal(
        runner,
        cache,
        unknown_project,
        "architecture_clusters_unknown_endpoint_separate_process_readback",
        "CBM_ARCH_CLUSTER_UNKNOWN_ENDPOINT",
    )?;
    require(
        unknown_endpoint["source"] == expected_unknown["source"]
            && unknown_endpoint["request"] == expected_unknown["request"]
            && unknown_endpoint["response"] == expected_unknown["response"]
            && unknown_endpoint["raw_envelope_sha256"] == expected_unknown["raw_envelope_sha256"],
        "ISSUE_1149_UNKNOWN_ENDPOINT_SEPARATE_READBACK_MISMATCH",
        json!({"expected": expected_unknown, "observed": unknown_endpoint}),
    )?;
    Ok(json!({
        "empty": empty,
        "edgeless": edgeless,
        "dense_six_duplicate_self_loop": dense_six_duplicate_self_loop,
        "unknown_endpoint": unknown_endpoint,
        "permutation": permutation,
        "literal_path_isolation": literal_path_isolation,
        "separate_process_physical_sqlite_reopen": true,
        "exact_raw_and_final_hashes_equal": true,
    }))
}

fn exercise_architecture_clusters(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
) -> AnyResult<Value> {
    let source_before = sqlite_cluster_source_state(cache, project)?;
    let exact_request = architecture_cluster_request(project, &source_before, false)?;
    let mut invalid_resolution_request = exact_request.clone();
    invalid_resolution_request["resolution"] = json!(0.0);
    let invalid_resolution = expect_refusal(
        runner,
        cache,
        project,
        "architecture_clusters_invalid_resolution",
        "get_architecture",
        &invalid_resolution_request,
        "ASTRO_ARCHITECTURE_CLUSTER_RESOLUTION_INVALID",
    )?;
    require(
        invalid_resolution["response"].get("clusters").is_none()
            && invalid_resolution["response"]
                .get("cluster_receipt")
                .is_none(),
        "ISSUE_1149_CLUSTER_INVALID_RESOLUTION_RETURNED_PARTIAL_RESULT",
        &invalid_resolution,
    )?;
    let raw_controls = "\"aspects\":[\"clusters\"],\"resolution\":1,\"cluster_max_nodes\":1,\"cluster_max_edges\":1,\"cluster_max_result_bytes\":1048576,\"cluster_max_move_visits\":65536";
    let duplicate_key = expect_raw_architecture_refusal(
        runner,
        cache,
        "architecture_clusters_raw_duplicate_project_key",
        &format!(
            "{{\"project\":\"issue1149_duplicate_first\",\"project\":\"issue1149_duplicate_second\",{raw_controls}}}"
        ),
        "ASTRO_MCP_DUPLICATE_JSON_KEY",
    )?;
    let embedded_nul_project = expect_raw_architecture_refusal(
        runner,
        cache,
        "architecture_clusters_raw_embedded_nul_project",
        &format!("{{\"project\":\"issue1149\\u0000project\",{raw_controls}}}"),
        "ASTRO_ARCHITECTURE_PROJECT_INVALID",
    )?;
    let embedded_nul_path = expect_raw_architecture_refusal(
        runner,
        cache,
        "architecture_clusters_raw_embedded_nul_path",
        &format!(
            "{{\"project\":{},\"path\":\"issue1149\\u0000path\",{raw_controls}}}",
            serde_json::to_string(project)?,
        ),
        "ASTRO_ARCHITECTURE_PATH_INVALID",
    )?;
    let too_many_aspects_arguments = serde_json::to_string(&json!({
        "project": project,
        "aspects": vec!["overview"; 27],
    }))?;
    let too_many_aspects = expect_raw_architecture_refusal(
        runner,
        cache,
        "architecture_clusters_raw_too_many_aspects",
        &too_many_aspects_arguments,
        "ASTRO_ARCHITECTURE_ASPECTS_TOO_MANY",
    )?;

    let node_count = source_before["node_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_SOURCE_NODE_COUNT_MISSING")?;
    let mut below_node_bound_request = exact_request.clone();
    below_node_bound_request["cluster_max_nodes"] = json!(node_count - 1);
    let below_node_bound = expect_refusal(
        runner,
        cache,
        project,
        "architecture_clusters_below_node_bound",
        "get_architecture",
        &below_node_bound_request,
        "CBM_ARCH_CLUSTER_NODE_BOUND_EXCEEDED",
    )?;
    let below_receipt = &below_node_bound["response"]["cluster_receipt"];
    require(
        below_node_bound["response"]["schema"] == "cbm.tool_fault/v1"
            && below_node_bound["response"]["status"] == "error"
            && below_node_bound["response"].get("clusters").is_none()
            && below_receipt["status"] == "refused"
            && below_receipt["error_code"] == "CBM_ARCH_CLUSTER_NODE_BOUND_EXCEEDED"
            && below_receipt["error_stage"] == "nodes"
            && below_receipt["requested_node_count"] == node_count
            && below_receipt["included_node_count"] == 0
            && below_receipt["node_bound"] == node_count - 1
            && below_receipt["edge_bound"] == exact_request["cluster_max_edges"]
            && below_receipt["move_visit_cap"] == exact_request["cluster_max_move_visits"]
            && below_receipt["result_byte_bound"] == exact_request["cluster_max_result_bytes"]
            && below_receipt["error_message"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && below_receipt["error_remediation"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
        "ISSUE_1149_CLUSTER_BELOW_BOUND_RECEIPT_INVALID",
        &below_node_bound,
    )?;
    let edge_count = source_before["cluster_edge_count"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_SOURCE_EDGE_COUNT_MISSING")?;
    let mut below_edge_bound_request = exact_request.clone();
    below_edge_bound_request["cluster_max_edges"] = json!(
        edge_count
            .checked_sub(1)
            .ok_or("ISSUE_1149_CLUSTER_EDGE_BOUND_UNDERFLOW")?
    );
    let below_edge_bound = expect_refusal(
        runner,
        cache,
        project,
        "architecture_clusters_below_edge_bound",
        "get_architecture",
        &below_edge_bound_request,
        "CBM_ARCH_CLUSTER_EDGE_BOUND_EXCEEDED",
    )?;
    require(
        below_edge_bound["response"]["cluster_receipt"]["requested_edge_count"] == edge_count
            && below_edge_bound["response"]["cluster_receipt"]["edge_bound"] == edge_count - 1
            && below_edge_bound["response"].get("clusters").is_none(),
        "ISSUE_1149_CLUSTER_BELOW_EDGE_BOUND_RECEIPT_INVALID",
        &below_edge_bound,
    )?;

    let mut move_cap_request = exact_request.clone();
    move_cap_request["cluster_max_move_visits"] = json!(1_u64);
    let move_cap_refusal = expect_refusal(
        runner,
        cache,
        project,
        "architecture_clusters_move_cap_exhausted",
        "get_architecture",
        &move_cap_request,
        "CBM_LEIDEN_MOVE_CAP_EXHAUSTED",
    )?;
    let move_cap_receipt = &move_cap_refusal["response"]["cluster_receipt"];
    require(
        move_cap_refusal["response"]["schema"] == "cbm.tool_fault/v1"
            && move_cap_refusal["response"]["status"] == "error"
            && move_cap_refusal["response"]["stage"] == "move"
            && move_cap_refusal["response"].get("clusters").is_none()
            && move_cap_receipt["status"] == "refused"
            && move_cap_receipt["error_code"] == "CBM_LEIDEN_MOVE_CAP_EXHAUSTED"
            && move_cap_receipt["error_stage"] == "move"
            && move_cap_receipt["move_visit_cap"] == 1
            && move_cap_receipt["move_visit_count"] == 1
            && move_cap_receipt["move_phase_status"] == "refused"
            && move_cap_receipt["included_node_count"] == node_count
            && move_cap_receipt["included_edge_count"] == edge_count
            && move_cap_receipt["error_message"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
            && move_cap_receipt["error_remediation"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
        "ISSUE_1149_CLUSTER_MOVE_CAP_REFUSAL_INVALID",
        &move_cap_refusal,
    )?;

    let exact = run_architecture_cluster_success(
        runner,
        cache,
        project,
        "architecture_clusters_exact_node_edge_bounds",
        &exact_request,
        &source_before,
        false,
    )?;
    let c_exact_byte_bound = settle_architecture_cluster_byte_bound(
        runner,
        cache,
        project,
        "architecture_clusters_c_payload_exact_byte_bound",
        &exact_request,
        &source_before,
        exact["proof"]["final_payload_bytes"]
            .as_u64()
            .ok_or("ISSUE_1149_CLUSTER_BASELINE_PAYLOAD_BYTES_MISSING")?,
        false,
    )?;
    let c_exact_bound = c_exact_byte_bound["bound"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_EXACT_C_BOUND_MISSING")?;
    let c_exact_run = c_exact_byte_bound["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .and_then(|round| round.get("run"))
        .ok_or("ISSUE_1149_CLUSTER_EXACT_C_RUN_MISSING")?;
    require(
        c_exact_bound > 1
            && c_exact_run["proof"]["architecture_payload_bytes"] == c_exact_bound
            && c_exact_run["proof"]["final_payload_bytes"] == c_exact_bound
            && c_exact_run["request"]["cluster_max_result_bytes"] == c_exact_bound,
        "ISSUE_1149_CLUSTER_EXACT_C_BOUND_NOT_EXACT",
        &c_exact_byte_bound,
    )?;
    let mut c_below_byte_request = exact_request.clone();
    c_below_byte_request["cluster_max_result_bytes"] = json!(c_exact_bound - 1);
    let c_below_byte_bound = expect_refusal(
        runner,
        cache,
        project,
        "architecture_clusters_c_payload_one_byte_below",
        "get_architecture",
        &c_below_byte_request,
        "CBM_ARCH_CLUSTER_SERIALIZED_RESULT_BOUND_EXCEEDED",
    )?;
    let c_below_receipt = &c_below_byte_bound["response"]["cluster_receipt"];
    require(
        c_below_byte_bound["response"].get("clusters").is_none()
            && c_below_receipt["status"] == "refused"
            && c_below_receipt["error_code"] == "CBM_ARCH_CLUSTER_SERIALIZED_RESULT_BOUND_EXCEEDED"
            && c_below_receipt["error_stage"] == "serialization"
            && c_below_receipt["result_schema"] == "cbm.architecture.cluster.result.v4"
            && c_below_receipt["result_byte_bound_scope"] == "c_architecture_payload_utf8"
            && c_below_receipt["result_byte_bound"] == c_exact_bound - 1
            && c_below_receipt["architecture_payload_bytes"] == c_exact_bound
            && c_below_receipt["canonical_result_bytes"]
                == c_exact_run["proof"]["canonical_result_bytes"]
            && c_below_receipt["result_sha256"] == c_exact_run["proof"]["result_sha256"],
        "ISSUE_1149_CLUSTER_C_ONE_BYTE_BELOW_RECEIPT_INVALID",
        &c_below_byte_bound,
    )?;

    let mut augmented_request = exact_request.clone();
    augmented_request["aspects"] = json!(["clusters", "kernel_context"]);
    let augmented = run_architecture_cluster_success(
        runner,
        cache,
        project,
        "architecture_clusters_augmented_wide_bound",
        &augmented_request,
        &source_before,
        true,
    )?;
    let augmented_exact_byte_bound = settle_architecture_cluster_byte_bound(
        runner,
        cache,
        project,
        "architecture_clusters_augmented_exact_byte_bound",
        &augmented_request,
        &source_before,
        augmented["proof"]["final_payload_bytes"]
            .as_u64()
            .ok_or("ISSUE_1149_CLUSTER_AUGMENTED_PAYLOAD_BYTES_MISSING")?,
        true,
    )?;
    let augmented_exact_bound = augmented_exact_byte_bound["bound"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_AUGMENTED_EXACT_BOUND_MISSING")?;
    let augmented_exact_run = augmented_exact_byte_bound["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .and_then(|round| round.get("run"))
        .ok_or("ISSUE_1149_CLUSTER_AUGMENTED_EXACT_RUN_MISSING")?;
    require(
        augmented_exact_bound > c_exact_bound
            && augmented_exact_run["proof"]["final_payload_bytes"] == augmented_exact_bound
            && augmented_exact_run["proof"]["architecture_payload_bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes < augmented_exact_bound)
            && augmented_exact_run["proof"]["result_sha256"]
                == c_exact_run["proof"]["result_sha256"],
        "ISSUE_1149_CLUSTER_AUGMENTED_EXACT_BOUND_NOT_EXACT",
        &augmented_exact_byte_bound,
    )?;
    let mut augmented_below_request = augmented_request.clone();
    augmented_below_request["cluster_max_result_bytes"] = json!(augmented_exact_bound - 1);
    let augmented_below_byte_bound = expect_refusal(
        runner,
        cache,
        project,
        "architecture_clusters_augmented_one_byte_below",
        "get_architecture",
        &augmented_below_request,
        "ASTRO_ARCHITECTURE_SERIALIZED_RESULT_BOUND_EXCEEDED",
    )?;
    require(
        augmented_below_byte_bound["response"]
            .get("clusters")
            .is_none()
            && augmented_below_byte_bound["response"]
                .get("cluster_receipt")
                .is_none()
            && augmented_below_byte_bound["response"]["observed_result_bytes"]
                == augmented_exact_bound
            && augmented_below_byte_bound["response"]["cluster_max_result_bytes"]
                == augmented_exact_bound - 1
            && augmented_below_byte_bound["response"]["measured_payload"] == "content[0].text",
        "ISSUE_1149_CLUSTER_AUGMENTED_ONE_BYTE_BELOW_REFUSAL_INVALID",
        &augmented_below_byte_bound,
    )?;

    let above_request = architecture_cluster_request(project, &source_before, true)?;
    let above = run_architecture_cluster_success(
        runner,
        cache,
        project,
        "architecture_clusters_above_node_edge_bounds",
        &above_request,
        &source_before,
        false,
    )?;
    let mut exact_normalized_to_above = exact["response"].clone();
    exact_normalized_to_above["cluster_receipt"]["node_bound"] =
        above["response"]["cluster_receipt"]["node_bound"].clone();
    exact_normalized_to_above["cluster_receipt"]["edge_bound"] =
        above["response"]["cluster_receipt"]["edge_bound"].clone();
    require(
        exact_normalized_to_above == above["response"]
            && exact["proof"]["source_sha256"] == above["proof"]["source_sha256"]
            && exact["proof"]["projection_sha256"] == above["proof"]["projection_sha256"]
            && exact["proof"]["result_sha256"] == above["proof"]["result_sha256"],
        "ISSUE_1149_CLUSTER_EXACT_ABOVE_BOUND_RESULT_DRIFT",
        json!({"exact": exact, "above": above}),
    )?;
    let source_after = sqlite_cluster_source_state(cache, project)?;
    require(
        source_after == source_before,
        "ISSUE_1149_CLUSTER_SQLITE_SOURCE_MUTATED",
        json!({"before": source_before, "after": source_after}),
    )?;
    let physical_edge_fixtures = exercise_cluster_fixture_edges(runner, cache, project)?;
    Ok(json!({
        "schema": "astrolabe.issue-1149.architecture-clusters-fsv.v2",
        "source": source_before,
        "invalid_resolution": invalid_resolution,
        "raw_refusals": {
            "duplicate_key": duplicate_key,
            "embedded_nul_project": embedded_nul_project,
            "embedded_nul_path": embedded_nul_path,
            "too_many_aspects": too_many_aspects,
        },
        "below_node_bound": below_node_bound,
        "below_edge_bound": below_edge_bound,
        "move_cap_refusal": move_cap_refusal,
        "exact": exact,
        "c_exact_byte_bound": c_exact_byte_bound,
        "c_below_byte_bound": c_below_byte_bound,
        "augmented": augmented,
        "augmented_exact_byte_bound": augmented_exact_byte_bound,
        "augmented_below_byte_bound": augmented_below_byte_bound,
        "above": above,
        "source_after": source_after,
        "source_unchanged": true,
        "physical_edge_fixtures": physical_edge_fixtures,
        "all_five_controls_explicit": true,
        "complete_clusters_only": true,
        "physical_atom_id_partition_verified": true,
        "byte_bound_coverage": {
            "c_payload_exact_success_and_one_byte_below_refusal": true,
            "rust_augmented_payload_exact_success_and_one_byte_below_refusal": true,
        },
        "all_requested_physical_edge_fixtures_covered": true,
    }))
}

fn exercise_malformed_lowering(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
) -> AnyResult<Value> {
    let prefix = format!("astrolabe.calyx.{project}");
    let source_key = format!("{prefix}.lowering_debounce_json");
    let observation_key = format!("{prefix}.lowering_malformed_observation_json");
    let fault_key = format!("{prefix}.lowering_malformed_fault_json");
    let (_, before_rows) = config_rows(cache, project)?;
    let valid_source = before_rows
        .get(&source_key)
        .ok_or("valid lowering status source row is absent")?;
    serde_json::from_str::<Value>(valid_source)?;
    require(
        !before_rows.contains_key(&observation_key) && !before_rows.contains_key(&fault_key),
        "ISSUE_1116_1119_MALFORMED_PRESTATE_DIRTY",
        project,
    )?;
    let before = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"malformed_lowering","phase":"before","state":before})
        )?
    );
    let malformed = "{broken";
    let mut connection = Connection::open(cache.join("_config.db"))?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute(
        "UPDATE config SET value = ?2 WHERE key = ?1",
        rusqlite::params![&source_key, malformed],
    )?;
    transaction.execute(
        "DELETE FROM config WHERE key = ?1 OR key = ?2",
        rusqlite::params![&observation_key, &fault_key],
    )?;
    transaction.commit()?;
    drop(connection);
    let (_, injected_rows) = config_rows(cache, project)?;
    require(
        injected_rows.get(&source_key).map(String::as_str) == Some(malformed)
            && !injected_rows.contains_key(&observation_key)
            && !injected_rows.contains_key(&fault_key),
        "ISSUE_1116_1119_MALFORMED_INJECTION_READBACK_FAILED",
        project,
    )?;
    let injected = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"malformed_lowering","phase":"injected","state":injected})
        )?
    );
    let (first_envelope, first) = call_tool(runner, "index_status", &json!({"project":project}))?;
    require(
        first_envelope["isError"] == Value::Bool(true)
            && first["code"] == "ASTRO_INDEX_STATUS_SHADOW_SUMMARY_FAILED"
            && first["cause"]
                .as_str()
                .is_some_and(|cause| cause.contains("ASTRO_LOWERING_STATUS_MALFORMED")),
        "ISSUE_1116_1119_MALFORMED_FIRST_OBSERVATION_FAILED",
        &first,
    )?;
    let (_, persisted_rows) = config_rows(cache, project)?;
    let observation_raw = persisted_rows
        .get(&observation_key)
        .ok_or("malformed observation row was not persisted")?;
    let fault_raw = persisted_rows
        .get(&fault_key)
        .ok_or("malformed terminal fault row was not persisted")?;
    let observation: Value = serde_json::from_str(observation_raw)?;
    let fault: Value = serde_json::from_str(fault_raw)?;
    require(
        persisted_rows.get(&source_key).map(String::as_str) == Some(malformed)
            && observation["schema"] == "astrolabe-lowering-malformed-observation-v1"
            && observation["source_sha256"] == sha256(malformed.as_bytes())
            && observation["fault_sha256"] == sha256(fault_raw.as_bytes())
            && fault["schema"] == "astrolabe-lowering-malformed-fault-v1"
            && fault["code"] == "ASTRO_LOWERING_STATUS_MALFORMED"
            && fault["terminal"] == Value::Bool(true)
            && fault["trust"] == "verified-terminal-refusal"
            && fault["source_sha256"] == sha256(malformed.as_bytes()),
        "ISSUE_1116_1119_MALFORMED_ROWS_INVALID",
        json!({"observation":&observation,"fault":&fault}),
    )?;
    let before_cached = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"malformed_lowering_cached","phase":"before","state":before_cached})
        )?
    );
    let (second_envelope, second) = call_tool(runner, "index_status", &json!({"project":project}))?;
    require(
        second_envelope["isError"] != Value::Bool(true) && second["lowering_debounce"] == fault,
        "ISSUE_1116_1119_MALFORMED_CACHED_READ_FAILED",
        &second,
    )?;
    let after_cached = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"malformed_lowering_cached","phase":"after","state":after_cached})
        )?
    );
    require(
        before_cached["sha256"] == after_cached["sha256"],
        "ISSUE_1116_1119_MALFORMED_CACHED_READ_MUTATED_STATE",
        project,
    )?;
    Ok(json!({
        "source_key": source_key,
        "source_raw": malformed,
        "source_sha256": sha256(malformed.as_bytes()),
        "observation_key": observation_key,
        "observation_raw": observation_raw,
        "fault_key": fault_key,
        "fault_raw": fault_raw,
        "first_response": first,
        "second_response": second,
        "before": before,
        "injected": injected,
        "before_cached": before_cached,
        "after_cached": after_cached,
        "cached_state_unchanged": true,
    }))
}

fn kernel_admission() -> Value {
    json!({
        "queries": [
            {
                "stable_id": "issue-1148-operator-query-001",
                "source": "manual-fsv-operator-query-log:issue-1148",
                "content": "cycle_left",
            },
            {
                "stable_id": "issue-1148-operator-query-002",
                "source": "manual-fsv-operator-query-log:issue-1148",
                "content": "cycle_right",
            },
        ],
        "params": {
            "top_k": 1,
            "expected_vector_dimension": 768,
            "entry_point_count": 1,
            "ef_search": 2,
            "max_route_distance_computations_per_query": 256,
            "max_exact_distance_computations": 512,
            "min_recall_permille": 1000,
            "max_kernel_member_fraction_permille": 999,
        },
    })
}

fn index_request(repo: &Path) -> Value {
    json!({
        "repo_path": repo,
        "mode": "moderate",
        "persistence": false,
        "calyx": "shadow",
        "generation_observed_at_ms": GENERATION_OBSERVED_AT_MS,
        "kernel_admission": kernel_admission(),
    })
}

fn fast_index_request(repo: &Path) -> Value {
    json!({
        "repo_path": repo,
        "mode": "fast",
        "persistence": false,
        "calyx": "shadow",
        "generation_observed_at_ms": GENERATION_OBSERVED_AT_MS,
        "kernel_admission": kernel_admission(),
    })
}

fn unavailable_corpus_kernel_admission() -> Value {
    json!({
        "queries": [
            {
                "stable_id": "issue-980-unavailable-corpus-query-001",
                "source": "manual-fsv-operator-query-log:issue-980-unavailable-corpus",
                "content": "singleton recursive countdown",
            },
            {
                "stable_id": "issue-980-unavailable-corpus-query-002",
                "source": "manual-fsv-operator-query-log:issue-980-unavailable-corpus",
                "content": "Seed remaining value",
            },
        ],
        "params": {
            "top_k": 1,
            "expected_vector_dimension": 768,
            "entry_point_count": 1,
            "ef_search": 2,
            "max_route_distance_computations_per_query": 256,
            "max_exact_distance_computations": 512,
            "min_recall_permille": 1000,
            "max_kernel_member_fraction_permille": 999,
        },
    })
}

fn unavailable_corpus_index_request(repo: &Path) -> Value {
    json!({
        "repo_path": repo,
        "mode": "moderate",
        "persistence": false,
        "calyx": "shadow",
        "generation_observed_at_ms": GENERATION_OBSERVED_AT_MS,
        "kernel_admission": unavailable_corpus_kernel_admission(),
    })
}

fn moderate_semantic_response_matches_sqlite(response: &Value, sqlite: &Value) -> bool {
    let semantic = &response["semantic_search"];
    let vector_readback = &response["semantic_vector_readback"];
    let project = &sqlite["project"];
    let Some(eligible) = semantic["eligible_node_count"].as_u64() else {
        return false;
    };
    let Some(node_vectors) = semantic["node_vector_count"].as_u64() else {
        return false;
    };
    let Some(token_vectors) = semantic["token_vector_count"].as_u64() else {
        return false;
    };
    response["index_mode"] == "moderate"
        && semantic["state"] == "available"
        && semantic["available"] == Value::Bool(true)
        && semantic["vector_dimension"] == 768
        && semantic["source"] == "projects.commit_manifest"
        && eligible >= 2
        && eligible == node_vectors
        && token_vectors > 0
        && vector_readback["source"] == "physical_vector_tables"
        && vector_readback["node_vector_count"] == node_vectors
        && vector_readback["node_vector_min_dimension"] == 768
        && vector_readback["node_vector_max_dimension"] == 768
        && vector_readback["token_vector_count"] == token_vectors
        && vector_readback["token_vector_min_dimension"] == 768
        && vector_readback["token_vector_max_dimension"] == 768
        && project["index_mode"] == "moderate"
        && project["semantic_state"] == "available"
        && project["semantic_vector_dimension"] == 768
        && project["semantic_eligible_node_count"] == eligible
        && project["node_vector_count"] == node_vectors
        && project["token_vector_count"] == token_vectors
        && sqlite["node_vectors"] == node_vectors
        && sqlite["token_vectors"] == token_vectors
}

fn fast_unavailable_semantic_response_matches_sqlite(
    response: &Value,
    sqlite_source: &Value,
) -> bool {
    let semantic = &response["semantic_search"];
    let vector_readback = &response["semantic_vector_readback"];
    let project = &sqlite_source["project"];
    response["index_mode"] == "fast"
        && semantic["state"] == "unavailable_mode"
        && semantic["available"] == Value::Bool(false)
        && semantic["vector_dimension"] == 768
        && semantic["eligible_node_count"] == Value::Null
        && semantic["node_vector_count"] == 0
        && semantic["token_vector_count"] == 0
        && semantic["source"] == "projects.commit_manifest"
        && vector_readback["source"] == "physical_vector_tables"
        && vector_readback["node_vector_count"] == 0
        && vector_readback["node_vector_min_dimension"] == -1
        && vector_readback["node_vector_max_dimension"] == -1
        && vector_readback["token_vector_count"] == 0
        && vector_readback["token_vector_min_dimension"] == -1
        && vector_readback["token_vector_max_dimension"] == -1
        && project["index_mode"] == "fast"
        && project["semantic_state"] == "unavailable_mode"
        && project["semantic_vector_dimension"] == 768
        && project["semantic_eligible_node_count"] == Value::Null
        && project["node_vector_count"] == 0
        && project["token_vector_count"] == 0
        && sqlite_source["family_constellations"]["node_vector"] == 0
        && sqlite_source["family_constellations"]["token_vector"] == 0
}

fn unavailable_corpus_semantic_response_matches_sqlite(
    response: &Value,
    sqlite_source: &Value,
) -> bool {
    let semantic = &response["semantic_search"];
    let vector_readback = &response["semantic_vector_readback"];
    let project = &sqlite_source["project"];
    response["index_mode"] == "moderate"
        && semantic["state"] == "unavailable_corpus"
        && semantic["available"] == Value::Bool(false)
        && semantic["vector_dimension"] == 768
        && semantic["eligible_node_count"] == 1
        && semantic["node_vector_count"] == 0
        && semantic["token_vector_count"] == 0
        && semantic["source"] == "projects.commit_manifest"
        && vector_readback["source"] == "physical_vector_tables"
        && vector_readback["node_vector_count"] == 0
        && vector_readback["node_vector_min_dimension"] == -1
        && vector_readback["node_vector_max_dimension"] == -1
        && vector_readback["token_vector_count"] == 0
        && vector_readback["token_vector_min_dimension"] == -1
        && vector_readback["token_vector_max_dimension"] == -1
        && project["index_mode"] == "moderate"
        && project["semantic_state"] == "unavailable_corpus"
        && project["semantic_vector_dimension"] == 768
        && project["semantic_eligible_node_count"] == 1
        && project["node_vector_count"] == 0
        && project["token_vector_count"] == 0
        && sqlite_source["family_constellations"]["node_vector"] == 0
        && sqlite_source["family_constellations"]["token_vector"] == 0
}

fn binding_edge_state(cache: &Path, project: &str) -> AnyResult<Value> {
    let project_db = cache.join(format!("{project}.db"));
    let lowered_db = cache.join(format!("{project}.astrolabe-lowered.db"));
    let archaeology_root = std::env::var_os("ASTRO_ARCHAEOLOGY_ROOT")
        .ok_or("ISSUE_1116_1119_ARCHAEOLOGY_ROOT_MISSING")?;
    Ok(json!({
        "archaeology": tree_state(Path::new(&archaeology_root))?,
        "cache_tree": tree_state(cache)?,
        "cache_top_level": cache_top_level_inventory(cache)?,
        "worker_binary_binding": configured_cbm_host_binary_path()?,
        "config": optional_file_state(&cache.join("_config.db"))?,
        "project_db": optional_file_state(&project_db)?,
        "project_db_wal": optional_file_state(&project_db.with_extension("db-wal"))?,
        "project_db_shm": optional_file_state(&project_db.with_extension("db-shm"))?,
        "lowered_db": optional_file_state(&lowered_db)?,
        "lowered_db_wal": optional_file_state(&lowered_db.with_extension("db-wal"))?,
        "lowered_db_shm": optional_file_state(&lowered_db.with_extension("db-shm"))?,
        "vault": tree_state(&cache.join(format!("{project}.astrolabe-vault")))?,
        "search_manifest": optional_file_state(&cache.join(format!("{project}.astrolabe-search-index.v2.json")))?,
        "publication_stage": tree_state(&cache.join(".astrolabe-shadow-publication"))?,
        "preserved_stage": tree_state(&cache.join(".astrolabe-shadow-preserved-stage"))?,
    }))
}

fn cache_top_level_inventory(cache: &Path) -> AnyResult<Vec<Value>> {
    if !cache.try_exists()? {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(cache)?;
    require(
        metadata.is_dir() && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1146_CACHE_ROOT_INVALID",
        cache.display(),
    )?;
    let mut rows = Vec::new();
    for entry in fs::read_dir(cache)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        require(
            metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
            "ISSUE_1146_CACHE_ENTRY_REPARSE",
            path.display(),
        )?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if metadata.is_file() {
            let (bytes, digest) = file_sha256(&path)?;
            rows.push(json!({"name":name,"type":"file","bytes":bytes,"sha256":digest}));
        } else if metadata.is_dir() {
            rows.push(json!({"name":name,"type":"directory"}));
        } else {
            return Err(format!("ISSUE_1146_CACHE_ENTRY_TYPE_INVALID: {}", path.display()).into());
        }
    }
    rows.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    Ok(rows)
}

fn binding_terminal_cache_inventory_valid(state: &Value, project: &str) -> bool {
    let Some(rows) = state["cache_top_level"].as_array() else {
        return false;
    };
    let zero_byte_files = BTreeSet::from([
        "_config.db-wal".to_string(),
        format!("{project}.astrolabe-lowered.lock.guard"),
        format!("{project}.astrolabe-shadow-import.lock.guard"),
    ]);
    let expected = BTreeSet::from([
        "_config.db".to_string(),
        "_config.db-shm".to_string(),
        "_config.db-wal".to_string(),
        format!("{project}.astrolabe-lowered.lock.guard"),
        format!("{project}.astrolabe-shadow-import.lock.guard"),
    ]);
    let observed = rows
        .iter()
        .filter_map(|row| row["name"].as_str().map(str::to_string))
        .collect::<BTreeSet<_>>();
    observed == expected
        && rows.iter().all(|row| {
            let Some(name) = row["name"].as_str() else {
                return false;
            };
            row["type"] == "file"
                && if zero_byte_files.contains(name) {
                    row["bytes"] == 0 && row["sha256"] == EMPTY_SHA256
                } else {
                    row["bytes"].as_u64().is_some_and(|bytes| bytes > 0)
                        && row["sha256"]
                            .as_str()
                            .is_some_and(|digest| digest.len() == 64)
                }
        })
}

fn binding_project_artifacts_absent(state: &Value) -> bool {
    [
        "project_db",
        "project_db_wal",
        "project_db_shm",
        "lowered_db",
        "lowered_db_wal",
        "lowered_db_shm",
        "vault",
        "search_manifest",
        "publication_stage",
        "preserved_stage",
    ]
    .into_iter()
    .all(|name| state[name]["exists"] == Value::Bool(false))
}

fn sqlite_family_member_path(db_path: &Path, suffix: &str) -> PathBuf {
    let mut path = db_path.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

fn transition_member_evidence(path: &Path) -> AnyResult<Value> {
    match fs::symlink_metadata(path) {
        Ok(before) => {
            require(
                before.is_file() && before.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
                "ISSUE_1116_1119_TRANSITION_MEMBER_INVALID",
                path.display(),
            )?;
            let (bytes, digest) = file_sha256(path)?;
            let after = fs::symlink_metadata(path)?;
            require(
                after.is_file()
                    && after.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0
                    && after.len() == before.len()
                    && after.len() == bytes
                    && after.file_attributes() == before.file_attributes()
                    && after.last_write_time() == before.last_write_time(),
                "ISSUE_1116_1119_TRANSITION_MEMBER_DRIFT",
                path.display(),
            )?;
            Ok(json!({
                "path": path,
                "present": true,
                "bytes": bytes,
                "sha256": digest,
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({
            "path": path,
            "present": false,
            "bytes": 0,
            "sha256": null,
        })),
        Err(error) => Err(error.into()),
    }
}

fn transition_family_evidence(db_path: &Path) -> AnyResult<Value> {
    Ok(json!({
        "db": transition_member_evidence(db_path)?,
        "wal": transition_member_evidence(&sqlite_family_member_path(db_path, "-wal"))?,
        "shm": transition_member_evidence(&sqlite_family_member_path(db_path, "-shm"))?,
    }))
}

fn absent_transition_family(db_path: &Path) -> Value {
    let absent = |path: PathBuf| {
        json!({
            "path": path,
            "present": false,
            "bytes": 0,
            "sha256": null,
        })
    };
    json!({
        "db": absent(db_path.to_path_buf()),
        "wal": absent(sqlite_family_member_path(db_path, "-wal")),
        "shm": absent(sqlite_family_member_path(db_path, "-shm")),
    })
}

fn ordered_config_rows(rows: &BTreeMap<String, String>) -> Vec<(String, String)> {
    rows.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn verify_weave_generation_receipt(
    rows: &BTreeMap<String, String>,
    project: &str,
) -> AnyResult<Value> {
    let key = format!("astrolabe.calyx.{project}.weave_json");
    let raw = rows
        .get(&key)
        .ok_or("ISSUE_1147_WEAVE_CONFIG_ROW_MISSING")?;
    let weave: Value = serde_json::from_str(raw)?;
    let source = &weave["weave_source"];
    let binding_seq = source["representation_binding_snapshot_seq"]
        .as_u64()
        .ok_or("ISSUE_1147_BINDING_SNAPSHOT_MISSING")?;
    let final_verification_seq = source["representation_final_verification_snapshot_seq"]
        .as_u64()
        .ok_or("ISSUE_1147_FINAL_VERIFICATION_SNAPSHOT_MISSING")?;
    let compression_generation = source["compression_cf_generation"]
        .as_u64()
        .ok_or("ISSUE_1147_COMPRESSION_GENERATION_MISSING")?;
    let slot_generation_rows = source["slot_cf_generations"]
        .as_array()
        .ok_or("ISSUE_1147_SLOT_GENERATIONS_MISSING")?;
    let mut slot_generations = BTreeMap::new();
    for entry in slot_generation_rows {
        let slot = u16::try_from(
            entry["slot"]
                .as_u64()
                .ok_or("ISSUE_1147_SLOT_GENERATION_ID_MISSING")?,
        )?;
        let generation = entry["generation_seq"]
            .as_u64()
            .ok_or("ISSUE_1147_SLOT_GENERATION_VALUE_MISSING")?;
        require(
            slot_generations.insert(slot, generation).is_none(),
            "ISSUE_1147_DUPLICATE_SLOT_GENERATION",
            entry,
        )?;
    }
    let slot_generation_rows_after = source["slot_cf_generations_after"]
        .as_array()
        .ok_or("ISSUE_1147_FINAL_SLOT_GENERATIONS_MISSING")?;
    let mut slot_generations_after = BTreeMap::new();
    for entry in slot_generation_rows_after {
        let slot = u16::try_from(
            entry["slot"]
                .as_u64()
                .ok_or("ISSUE_1147_FINAL_SLOT_GENERATION_ID_MISSING")?,
        )?;
        let generation = entry["generation_seq"]
            .as_u64()
            .ok_or("ISSUE_1147_FINAL_SLOT_GENERATION_VALUE_MISSING")?;
        require(
            slot_generations_after.insert(slot, generation).is_none(),
            "ISSUE_1147_DUPLICATE_FINAL_SLOT_GENERATION",
            entry,
        )?;
    }
    let representation_rows = source["slot_representation_bindings"]
        .as_array()
        .ok_or("ISSUE_1147_REPRESENTATION_BINDINGS_MISSING")?;
    let lowercase_sha = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    let mut representation_bindings = BTreeMap::new();
    for entry in representation_rows {
        let slot = u16::try_from(
            entry["slot"]
                .as_u64()
                .ok_or("ISSUE_1147_REPRESENTATION_SLOT_MISSING")?,
        )?;
        let representation = entry["representation"]
            .as_str()
            .ok_or("ISSUE_1147_REPRESENTATION_KIND_MISSING")?
            .to_string();
        let identity = entry
            .get("compression_generation_identity_sha256")
            .cloned()
            .unwrap_or(Value::Null);
        let representation_valid = match representation.as_str() {
            "aster_raw_slot_vector" => identity.is_null(),
            "registry_authenticated_compressed" => identity.as_str().is_some_and(lowercase_sha),
            _ => false,
        };
        require(
            representation_valid
                && representation_bindings
                    .insert(slot, (representation, identity))
                    .is_none(),
            "ISSUE_1147_REPRESENTATION_BINDING_INVALID",
            entry,
        )?;
    }
    let bound_slots = slot_generations.keys().copied().collect::<BTreeSet<_>>();
    require(
        !slot_generations.is_empty()
            && slot_generation_rows.len() == slot_generations.len()
            && slot_generation_rows_after.len() == slot_generations_after.len()
            && representation_rows.len() == representation_bindings.len()
            && slot_generations_after
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                == bound_slots
            && representation_bindings
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                == bound_slots
            && slot_generations_after == slot_generations
            && source["compression_cf_generation_after"].as_u64() == Some(compression_generation)
            && source["representation_bindings_verified_after"] == Value::Bool(true)
            && source["distinct_slot_count"].as_u64() == u64::try_from(slot_generations.len()).ok(),
        "ISSUE_1147_BINDING_ROSTER_MISMATCH",
        source,
    )?;
    require(
        source["compact_graph"]["snapshot_seq"].as_u64() == Some(binding_seq)
            && final_verification_seq >= binding_seq,
        "ISSUE_1147_BINDING_EPOCH_MISMATCH",
        source,
    )?;
    let scans = source["slot_scans"]
        .as_array()
        .filter(|scans| !scans.is_empty())
        .ok_or("ISSUE_1147_SLOT_SCANS_MISSING")?;
    let mut read_sequences = BTreeSet::new();
    let mut scanned_slots = BTreeSet::new();
    for scan in scans {
        let slot = u16::try_from(
            scan["slot"]
                .as_u64()
                .ok_or("ISSUE_1147_SCAN_SLOT_MISSING")?,
        )?;
        let read_seq = scan["read_snapshot_seq"]
            .as_u64()
            .ok_or("ISSUE_1147_SCAN_SEQUENCE_MISSING")?;
        let expected_generation = slot_generations
            .get(&slot)
            .ok_or("ISSUE_1147_SCAN_SLOT_NOT_BOUND")?;
        let expected_representation = representation_bindings
            .get(&slot)
            .ok_or("ISSUE_1147_SCAN_REPRESENTATION_NOT_BOUND")?;
        require(
            read_seq >= binding_seq
                && read_seq <= final_verification_seq
                && scan["source_cf_generation_seq"].as_u64() == Some(*expected_generation)
                && scan["compression_cf_generation_seq"].as_u64() == Some(compression_generation)
                && scan["representation"].as_str() == Some(expected_representation.0.as_str())
                && scan
                    .get("compression_generation_identity_sha256")
                    .cloned()
                    .unwrap_or(Value::Null)
                    == expected_representation.1,
            "ISSUE_1147_SCAN_BINDING_MISMATCH",
            scan,
        )?;
        read_sequences.insert(read_seq);
        scanned_slots.insert(slot);
    }
    let minimum_crossed_seq = binding_seq
        .checked_add(2)
        .ok_or("ISSUE_1147_DERIVED_SEQUENCE_CROSSING_OVERFLOW")?;
    require(
        source["slot_scan_count"].as_u64() == u64::try_from(scans.len()).ok()
            && scanned_slots == bound_slots
            && read_sequences
                .iter()
                .copied()
                .max()
                .is_some_and(|seq| seq >= minimum_crossed_seq)
            && read_sequences
                .iter()
                .copied()
                .max()
                .is_some_and(|seq| final_verification_seq >= seq),
        "ISSUE_1147_DERIVED_SEQUENCE_CROSSING_NOT_PROVEN",
        json!({"binding_seq": binding_seq, "final_verification_seq": final_verification_seq, "read_sequences": read_sequences, "bound_slots": bound_slots, "scanned_slots": scanned_slots}),
    )?;
    let complete = &weave["complete_associations"];
    let complete_source = &complete["source"];
    let hydration_first = complete_source["hydration_snapshot_first"]
        .as_u64()
        .ok_or("ISSUE_1147_COMPLETE_HYDRATION_FIRST_MISSING")?;
    let hydration_last = complete_source["hydration_snapshot_last"]
        .as_u64()
        .ok_or("ISSUE_1147_COMPLETE_HYDRATION_LAST_MISSING")?;
    let complete_binding_seq = complete_source["representation_binding_snapshot_seq"]
        .as_u64()
        .ok_or("ISSUE_1147_COMPLETE_BINDING_SNAPSHOT_MISSING")?;
    let complete_final_seq = complete_source["representation_final_verification_snapshot_seq"]
        .as_u64()
        .ok_or("ISSUE_1147_COMPLETE_FINAL_SNAPSHOT_MISSING")?;
    let hydration_snapshots = complete_source["hydration_snapshots"]
        .as_array()
        .filter(|snapshots| !snapshots.is_empty())
        .ok_or("ISSUE_1147_COMPLETE_HYDRATION_ROSTER_MISSING")?;
    let source_record_batches = complete_source["source_record_batches"]
        .as_u64()
        .filter(|count| *count > 0)
        .ok_or("ISSUE_1147_COMPLETE_SOURCE_BATCH_COUNT_INVALID")?;
    let source_record_batch_cap = complete_source["source_record_batch_cap"]
        .as_u64()
        .filter(|cap| *cap == 64)
        .ok_or("ISSUE_1147_COMPLETE_SOURCE_BATCH_CAP_INVALID")?;
    let source_scan_page_rows_cap = complete_source["source_scan_page_rows_cap"]
        .as_u64()
        .filter(|cap| *cap == 1_024)
        .ok_or("ISSUE_1147_COMPLETE_SOURCE_SCAN_CAP_INVALID")?;
    let source_records_loaded = complete_source["source_records_loaded"]
        .as_u64()
        .filter(|count| *count > 0)
        .ok_or("ISSUE_1147_COMPLETE_SOURCE_RECORD_COUNT_INVALID")?;
    let source_record_capacity = source_record_batches
        .checked_mul(source_record_batch_cap)
        .ok_or("ISSUE_1147_COMPLETE_SOURCE_BATCH_CAPACITY_OVERFLOW")?;
    let base_page_rows_high_water = complete_source["base_page_rows_high_water"]
        .as_u64()
        .filter(|rows| *rows > 0)
        .ok_or("ISSUE_1147_COMPLETE_BASE_PAGE_HIGH_WATER_INVALID")?;
    let base_rows = complete_source["base_rows"]
        .as_u64()
        .filter(|rows| *rows > 0)
        .ok_or("ISSUE_1147_COMPLETE_BASE_ROWS_INVALID")?;
    let base_scan_pages = complete_source["base_scan_pages"]
        .as_u64()
        .filter(|pages| *pages > 0)
        .ok_or("ISSUE_1147_COMPLETE_BASE_SCAN_PAGES_INVALID")?;
    let complete_generations = complete_source["source_cf_generations"]
        .as_object()
        .ok_or("ISSUE_1147_COMPLETE_GENERATIONS_MISSING")?;
    let complete_generations_after = complete_source["source_cf_generations_after"]
        .as_object()
        .ok_or("ISSUE_1147_COMPLETE_FINAL_GENERATIONS_MISSING")?;
    let complete_representations = complete_source["slot_representation_bindings"]
        .as_object()
        .filter(|bindings| !bindings.is_empty())
        .ok_or("ISSUE_1147_COMPLETE_REPRESENTATIONS_MISSING")?;
    let complete_compressed_identities = complete_source["compressed_generation_identities"]
        .as_object()
        .ok_or("ISSUE_1147_COMPLETE_COMPRESSED_IDENTITIES_MISSING")?;
    let mut complete_raw_slots = 0usize;
    let mut complete_slot_cfs = BTreeSet::new();
    let mut expected_compressed_identity_slots = BTreeSet::new();
    let mut complete_representation_by_slot = BTreeMap::new();
    for (slot, representation) in complete_representations {
        let slot_number = slot
            .strip_prefix('S')
            .ok_or("ISSUE_1147_COMPLETE_SLOT_NAME_INVALID")?
            .parse::<u16>()?;
        require(
            *slot == format!("S{slot_number}"),
            "ISSUE_1147_COMPLETE_SLOT_NAME_NONCANONICAL",
            slot,
        )?;
        complete_slot_cfs.insert(ColumnFamily::slot(SlotId::new(slot_number)).name());
        let representation = representation
            .as_str()
            .ok_or("ISSUE_1147_COMPLETE_REPRESENTATION_INVALID")?;
        require(
            complete_representation_by_slot
                .insert(slot_number, representation.to_string())
                .is_none()
                && slot.starts_with('S')
                && (representation == "aster-raw-slot-vector-v1"
                    || representation
                        .strip_prefix("registry-compressed:")
                        .is_some_and(lowercase_sha)),
            "ISSUE_1147_COMPLETE_REPRESENTATION_INVALID",
            json!({"slot":slot,"representation":representation}),
        )?;
        if representation == "aster-raw-slot-vector-v1" {
            complete_raw_slots += 1;
            require(
                !complete_compressed_identities.contains_key(slot),
                "ISSUE_1147_RAW_SLOT_HAS_COMPRESSED_IDENTITY",
                slot,
            )?;
        } else {
            expected_compressed_identity_slots.insert(slot.clone());
            require(
                complete_compressed_identities
                    .get(slot)
                    .and_then(Value::as_str)
                    == representation.strip_prefix("registry-compressed:"),
                "ISSUE_1147_COMPRESSED_IDENTITY_BINDING_MISMATCH",
                json!({"slot":slot,"representation":representation,"identities":complete_compressed_identities}),
            )?;
        }
    }
    let complete_generation_keys = complete_generations
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut expected_generation_keys = complete_slot_cfs;
    expected_generation_keys.insert(ColumnFamily::Base.name());
    expected_generation_keys.insert(ColumnFamily::Compression.name());
    let complete_identity_keys = complete_compressed_identities
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let hydration_values = hydration_snapshots
        .iter()
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| "ISSUE_1147_COMPLETE_HYDRATION_SEQUENCE_INVALID".into())
        })
        .collect::<AnyResult<Vec<_>>>()?;
    let expected_source_record_batches = source_records_loaded / source_record_batch_cap
        + u64::from(!source_records_loaded.is_multiple_of(source_record_batch_cap));
    let expected_base_scan_pages = base_rows / source_scan_page_rows_cap
        + u64::from(!base_rows.is_multiple_of(source_scan_page_rows_cap));
    let complete_commit_count = complete["commit_count"]
        .as_u64()
        .filter(|count| *count > 0)
        .ok_or("ISSUE_1147_COMPLETE_COMMIT_COUNT_INVALID")?;
    let minimum_complete_final_seq = complete_binding_seq
        .checked_add(complete_commit_count)
        .ok_or("ISSUE_1147_COMPLETE_FINAL_SEQUENCE_OVERFLOW")?;
    let complete_compression_generation = complete_generations
        .get("compression")
        .and_then(Value::as_u64)
        .ok_or("ISSUE_1147_COMPLETE_COMPRESSION_GENERATION_MISSING")?;
    let mut overlapping_binding_count = 0usize;
    let mut complete_bindings_match_outer = true;
    for (slot, complete_representation) in &complete_representation_by_slot {
        if let Some(outer_generation) = slot_generations.get(slot) {
            overlapping_binding_count += 1;
            let cf_name = ColumnFamily::slot(SlotId::new(*slot)).name();
            if complete_generations.get(&cf_name).and_then(Value::as_u64) != Some(*outer_generation)
            {
                complete_bindings_match_outer = false;
                continue;
            }
            let Some((outer_representation, outer_identity)) = representation_bindings.get(slot)
            else {
                complete_bindings_match_outer = false;
                continue;
            };
            let representation_matches = match outer_representation.as_str() {
                "aster_raw_slot_vector" => complete_representation == "aster-raw-slot-vector-v1",
                "registry_authenticated_compressed" => {
                    outer_identity.as_str().is_some_and(lowercase_sha)
                        && complete_representation
                            .strip_prefix("registry-compressed:")
                            .is_some_and(lowercase_sha)
                }
                _ => false,
            };
            complete_bindings_match_outer &= representation_matches;
        }
    }
    require(
        source_record_batches == expected_source_record_batches
            && hydration_values.len() == usize::try_from(expected_source_record_batches)?
            && source_records_loaded <= source_record_capacity
            && base_scan_pages == expected_base_scan_pages
            && base_page_rows_high_water <= source_scan_page_rows_cap
            && base_rows == complete["constellations_total"].as_u64().unwrap_or(0)
            && source_records_loaded
                == complete["constellations_recomputed"]
                    .as_u64()
                    .unwrap_or(u64::MAX)
            && complete_source["snapshot_seq"].as_u64() == Some(complete_binding_seq)
            && binding_seq <= complete_binding_seq
            && complete_binding_seq <= complete_final_seq
            && complete_final_seq <= final_verification_seq
            && complete_compression_generation == compression_generation
            && overlapping_binding_count > 0
            && complete_bindings_match_outer
            && complete_final_seq >= minimum_complete_final_seq
            && complete_generations == complete_generations_after
            && complete_generation_keys == expected_generation_keys
            && complete_identity_keys == expected_compressed_identity_slots
            && complete_source["representation_bindings_verified_after"] == Value::Bool(true)
            && complete_raw_slots > 0
            && hydration_values.first().copied() == Some(hydration_first)
            && hydration_values.last().copied() == Some(hydration_last)
            && hydration_values.windows(2).all(|pair| pair[0] <= pair[1])
            && hydration_values.iter().all(|snapshot| {
                *snapshot >= complete_binding_seq && *snapshot <= complete_final_seq
            })
            && hydration_first <= hydration_last
            && hydration_last <= complete_final_seq,
        "ISSUE_1147_COMPLETE_SOURCE_CONTRACT_MISSING",
        complete,
    )?;
    Ok(json!({
        "config_key": key,
        "raw_bytes": raw.len(),
        "raw_sha256": sha256(raw.as_bytes()),
        "binding_snapshot_seq": binding_seq,
        "read_snapshot_sequences": read_sequences,
        "slot_binding_count": slot_generations.len(),
        "slot_cf_generations": slot_generations,
        "slot_cf_generations_after": slot_generations_after,
        "compression_cf_generation": compression_generation,
        "compression_cf_generation_after": source["compression_cf_generation_after"],
        "all_scans_match_prewrite_bindings": true,
        "representations_verified_after": true,
        "complete_association": {
            "commit_count": complete_commit_count,
            "base_rows": base_rows,
            "base_scan_pages": base_scan_pages,
            "source_records_loaded": source_records_loaded,
            "source_record_batches": source_record_batches,
            "source_record_batch_cap": source_record_batch_cap,
            "source_scan_page_rows_cap": source_scan_page_rows_cap,
            "source_record_capacity": source_record_capacity,
            "base_page_rows_high_water": base_page_rows_high_water,
            "slot_batch_bytes_high_water": complete_source["slot_batch_bytes_high_water"],
            "readback_plan_bytes_high_water": complete_source["readback_plan_bytes_high_water"],
            "hydration_snapshot_count": hydration_values.len(),
            "hydration_snapshot_first": hydration_first,
            "hydration_snapshot_last": hydration_last,
            "hydration_snapshots": hydration_values,
            "representation_binding_snapshot_seq": complete_binding_seq,
            "representation_final_verification_snapshot_seq": complete_final_seq,
            "slot_representation_bindings": complete_representations,
            "source_cf_generations": complete_generations,
            "source_cf_generations_after": complete_generations_after,
            "raw_slot_count": complete_raw_slots,
            "compression_generation_bound": true,
            "representations_verified_after": true,
        },
    }))
}

fn capability_owner_identity(binding: &CbmVerifiedWorkerBinding) -> AnyResult<(u32, u64)> {
    let parts = binding.capability.challenge.split('-').collect::<Vec<_>>();
    require(
        parts.len() == 3,
        "ISSUE_1116_1119_CAPABILITY_CHALLENGE_INVALID",
        &binding.capability.challenge,
    )?;
    let pid = u32::from_str_radix(parts[0], 16)?;
    let process_start_utc_ticks = u64::from_str_radix(parts[1], 16)?;
    let _ordinal = u64::from_str_radix(parts[2], 16)?;
    require(
        pid > 0 && process_start_utc_ticks > 0,
        "ISSUE_1116_1119_CAPABILITY_OWNER_MISMATCH",
        &binding.capability.challenge,
    )?;
    Ok((pid, process_start_utc_ticks))
}

struct CompletedTransitionRequest<'a> {
    transition_key: &'a str,
    transition: &'a Value,
    project: &'a str,
    canonical_root: &'a Path,
    canonical_db: &'a Path,
    response_raw: &'a str,
    response_envelope: &'a Value,
    response_payload: &'a Value,
    family_after: &'a Value,
    binding: &'a CbmVerifiedWorkerBinding,
    expected_process_pid: u32,
    observation_path: Option<&'a Path>,
}

struct CompletedTransitionValidation {
    response_sha256: String,
    observation: Value,
    persisted_observation: Option<Value>,
}

const COMPLETED_TRANSITION_CHECK_NAMES: [&str; 26] = [
    "capability_owner_parse",
    "capability_current_process_pid",
    "transition_key",
    "schema",
    "phase",
    "generation",
    "project",
    "canonical_root",
    "canonical_db_path",
    "owner_pid",
    "owner_process_start_utc_ticks",
    "normalization_status",
    "normalization_before",
    "normalization_after",
    "normalization_holder_inventory_stable",
    "normalization_holder_count",
    "evidence_status",
    "response_hash_basis",
    "response_sha256",
    "raw_response_sha256",
    "response_sqlite_publication_started",
    "transition_sqlite_publication_started",
    "family_before",
    "family_after",
    "family_after_db_present",
    "family_after_db_nonempty",
];

fn validate_completed_transition(
    request: CompletedTransitionRequest<'_>,
) -> AnyResult<CompletedTransitionValidation> {
    let CompletedTransitionRequest {
        transition_key,
        transition,
        project,
        canonical_root,
        canonical_db,
        response_raw,
        response_envelope,
        response_payload,
        family_after,
        binding,
        expected_process_pid,
        observation_path,
    } = request;
    let expected_key = format!("astrolabe.calyx.{project}.project_transition_json");
    let response_sha256 = sha256(&serde_json::to_vec(response_envelope)?);
    let raw_response_sha256 = sha256(response_raw.as_bytes());
    let capability_owner = capability_owner_identity(binding);
    let capability_error = capability_owner
        .as_ref()
        .err()
        .map(std::string::ToString::to_string);
    let (owner_pid, owner_process_start_utc_ticks) = capability_owner.unwrap_or((0, 0));
    let generation = transition["generation"].as_str();
    let generation_valid = generation.is_some_and(|generation| {
        generation.len() == 64
            && generation
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    let expected_transition_key = expected_key.as_str();
    let expected_canonical_root = json!(canonical_root);
    let expected_canonical_db = json!(canonical_db);
    let expected_absent_family = absent_transition_family(canonical_db);
    let expected_response_sha256 = Value::String(response_sha256.clone());
    let expected_raw_response_sha256 = Value::String(raw_response_sha256.clone());
    let checks = [
        ("capability_owner_parse", capability_error.is_none()),
        (
            "capability_current_process_pid",
            owner_pid == expected_process_pid,
        ),
        ("transition_key", transition_key == expected_transition_key),
        (
            "schema",
            transition["schema"] == "astrolabe-project-transition-v1",
        ),
        ("phase", transition["phase"] == "terminal"),
        ("generation", generation_valid),
        (
            "project",
            transition["project"] == Value::String(project.to_string()),
        ),
        (
            "canonical_root",
            transition["canonical_root"] == expected_canonical_root,
        ),
        (
            "canonical_db_path",
            transition["canonical_db_path"] == expected_canonical_db,
        ),
        (
            "owner_pid",
            transition["owner"]["pid"].as_u64() == Some(u64::from(owner_pid)),
        ),
        (
            "owner_process_start_utc_ticks",
            transition["owner"]["process_start_utc_ticks"].as_u64()
                == Some(owner_process_start_utc_ticks),
        ),
        (
            "normalization_status",
            transition["normalization"]["status"] == "absent",
        ),
        (
            "normalization_before",
            transition["normalization"]["before"] == expected_absent_family,
        ),
        (
            "normalization_after",
            transition["normalization"]["after"] == expected_absent_family,
        ),
        (
            "normalization_holder_inventory_stable",
            transition["normalization"]["post_close_quiescence"]["holder_inventory_stable"]
                == Value::Bool(true),
        ),
        (
            "normalization_holder_count",
            transition["normalization"]["post_close_quiescence"]["holder_count"] == 0,
        ),
        (
            "evidence_status",
            transition["evidence"]["status"] == "completed",
        ),
        (
            "response_hash_basis",
            transition["evidence"]["response_hash_basis"] == "astrolabe.persisted-json-compact.v1",
        ),
        (
            "response_sha256",
            transition["evidence"]["response_sha256"] == expected_response_sha256,
        ),
        (
            "raw_response_sha256",
            transition["evidence"]["raw_response_sha256"] == expected_raw_response_sha256,
        ),
        (
            "response_sqlite_publication_started",
            response_payload["sqlite_publication_started"] == Value::Bool(true),
        ),
        (
            "transition_sqlite_publication_started",
            transition["evidence"]["sqlite_publication_started"] == Value::Bool(true),
        ),
        (
            "family_before",
            transition["evidence"]["family_before"] == expected_absent_family,
        ),
        (
            "family_after",
            transition["evidence"]["family_after"] == *family_after,
        ),
        (
            "family_after_db_present",
            family_after["db"]["present"] == Value::Bool(true),
        ),
        (
            "family_after_db_nonempty",
            family_after["db"]["bytes"]
                .as_u64()
                .is_some_and(|bytes| bytes > 0),
        ),
    ];
    let check_results = checks
        .iter()
        .map(|(name, passed)| json!({ "name": name, "passed": passed }))
        .collect::<Vec<_>>();
    require(
        checks.map(|(name, _)| name) == COMPLETED_TRANSITION_CHECK_NAMES,
        "ISSUE_1116_1119_COMPLETED_TRANSITION_CHECK_ROSTER_DRIFT",
        json!({
            "expected": COMPLETED_TRANSITION_CHECK_NAMES,
            "observed": checks.map(|(name, _)| name),
        }),
    )?;
    let failed_checks = checks
        .iter()
        .filter(|(_, passed)| !*passed)
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();
    let observation = json!({
        "schema": "astrolabe.issue-1116-1119.completed-transition-observation.v1",
        "binding": {
            "challenge": binding.capability.challenge,
            "owner_pid": owner_pid,
            "owner_process_start_utc_ticks": owner_process_start_utc_ticks,
            "expected_process_pid": expected_process_pid,
            "observer_process_pid": std::process::id(),
            "parse_error": capability_error,
        },
        "checks": check_results,
        "failed_checks": failed_checks,
        "expected": {
            "transition_key": expected_key,
            "canonical_root": expected_canonical_root,
            "canonical_db_path": expected_canonical_db,
            "normalization_family": expected_absent_family,
            "response_sha256": response_sha256,
            "raw_response_sha256": raw_response_sha256,
            "family_after": family_after,
        },
        "response": {
            "raw": response_raw,
            "raw_bytes": response_raw.len(),
            "raw_sha256": raw_response_sha256,
            "compact_sha256": response_sha256,
            "envelope": response_envelope,
            "payload": response_payload,
        },
        "transition": {
            "key": transition_key,
            "value": transition,
        },
    });
    let persisted_observation = observation_path
        .map(|path| {
            let bytes = serde_json::to_vec_pretty(&observation)?;
            let physical = write_new_atomic_readback(path, &bytes)?;
            Ok::<Value, Box<dyn Error + Send + Sync + 'static>>(json!({
                "physical": physical,
                "value": observation,
            }))
        })
        .transpose()?;
    require(
        failed_checks.is_empty(),
        "ISSUE_1116_1119_COMPLETED_TRANSITION_INVALID",
        json!({
            "observation": persisted_observation,
            "failed_checks": failed_checks,
            "expected": {
                "transition_key": expected_key,
                "canonical_root": expected_canonical_root,
                "canonical_db_path": expected_canonical_db,
                "owner": {
                    "pid": owner_pid,
                    "process_start_utc_ticks": owner_process_start_utc_ticks,
                },
                "normalization_family": expected_absent_family,
                "response_sha256": response_sha256.clone(),
                "raw_response_sha256": raw_response_sha256.clone(),
                "family_after": family_after,
            },
            "response_observation": {
                "raw_bytes": response_raw.len(),
                "raw_sha256": raw_response_sha256,
                "compact_sha256": response_sha256.clone(),
                "envelope": response_envelope,
                "payload": response_payload,
                "payload_sqlite_publication_started": response_payload["sqlite_publication_started"],
            },
            "transition": transition,
        }),
    )?;
    Ok(CompletedTransitionValidation {
        response_sha256,
        observation,
        persisted_observation,
    })
}

struct ReadCompletedTransitionRequest<'a> {
    cache: &'a Path,
    project: &'a str,
    canonical_root: &'a Path,
    canonical_db: &'a Path,
    response_raw: &'a str,
    response_envelope: &'a Value,
    response_payload: &'a Value,
    binding: &'a CbmVerifiedWorkerBinding,
    observation_path: Option<&'a Path>,
}

fn read_completed_transition(request: ReadCompletedTransitionRequest<'_>) -> AnyResult<Value> {
    let ReadCompletedTransitionRequest {
        cache,
        project,
        canonical_root,
        canonical_db,
        response_raw,
        response_envelope,
        response_payload,
        binding,
        observation_path,
    } = request;
    let (integrity, rows) = config_rows(cache, project)?;
    require(
        integrity == "ok",
        "ISSUE_1116_1119_TRANSITION_CONFIG_INTEGRITY_FAILED",
        &integrity,
    )?;
    let key = format!("astrolabe.calyx.{project}.project_transition_json");
    let raw = rows
        .get(&key)
        .ok_or("ISSUE_1116_1119_COMPLETED_TRANSITION_MISSING")?
        .clone();
    let transition: Value = serde_json::from_str(&raw)?;
    let family_after = transition_family_evidence(canonical_db)?;
    let validation = validate_completed_transition(CompletedTransitionRequest {
        transition_key: &key,
        transition: &transition,
        project,
        canonical_root,
        canonical_db,
        response_raw,
        response_envelope,
        response_payload,
        family_after: &family_after,
        binding,
        expected_process_pid: std::process::id(),
        observation_path,
    })?;
    Ok(json!({
        "key": key,
        "raw": raw,
        "sha256": sha256(raw.as_bytes()),
        "response_sha256": validation.response_sha256,
        "raw_response_sha256": sha256(response_raw.as_bytes()),
        "config_integrity": integrity,
        "config_row_count": rows.len(),
        "family_readback": family_after,
        "validation_observation": validation.persisted_observation,
    }))
}

fn validate_unbound_transition(
    transition_key: &str,
    transition: &Value,
    project: &str,
    canonical_root: &Path,
    canonical_db: &Path,
    response_raw: &str,
    response_envelope: &Value,
) -> AnyResult<(String, String)> {
    let expected_key = format!("astrolabe.calyx.{project}.project_transition_json");
    let reparsed_response: Value = serde_json::from_str(response_raw)?;
    let response_sha256 = sha256(&serde_json::to_vec(&reparsed_response)?);
    let raw_response_sha256 = sha256(response_raw.as_bytes());
    let absent_member = |path: &Path| {
        json!({
            "path": path,
            "present": false,
            "bytes": 0,
            "sha256": null,
        })
    };
    let expected_family = json!({
        "db": absent_member(canonical_db),
        "wal": absent_member(&canonical_db.with_extension("db-wal")),
        "shm": absent_member(&canonical_db.with_extension("db-shm")),
    });
    require(
        &reparsed_response == response_envelope
            && transition_key == expected_key
            && transition["schema"] == "astrolabe-project-transition-v1"
            && transition["phase"] == "terminal"
            && transition["project"] == Value::String(project.to_string())
            && transition["canonical_root"] == json!(canonical_root)
            && transition["canonical_db_path"] == json!(canonical_db)
            && transition["evidence"]["status"] == "failed"
            && transition["evidence"]["response_hash_basis"]
                == "astrolabe.persisted-json-compact.v1"
            && transition["evidence"]["response_sha256"] == Value::String(response_sha256.clone())
            && transition["evidence"]["raw_response_sha256"]
                == Value::String(raw_response_sha256.clone())
            && transition["evidence"]["sqlite_publication_started"].is_null()
            && transition["evidence"]["family_before"] == expected_family
            && transition["evidence"]["family_after"] == expected_family,
        "ISSUE_1146_TERMINAL_TRANSITION_INVALID",
        transition,
    )?;
    Ok((response_sha256, raw_response_sha256))
}

fn binding_edges(root: PathBuf) -> AnyResult<()> {
    require(
        !root.try_exists()?,
        "ISSUE_1146_EDGE_ROOT_PREEXISTS",
        root.display(),
    )?;
    fs::create_dir_all(&root)?;
    let source_generation = current_source_generation_sha256()?;
    require(
        source_generation == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256,
        "ISSUE_1146_COMPILED_SOURCE_GENERATION_DRIFT",
        &source_generation,
    )?;
    let cache = root.join("cache");
    let repo = root.join("real-rust-repo");
    let ordinary_directory = root.join("ordinary-directory");
    fs::create_dir(&cache)?;
    fs::create_dir(&ordinary_directory)?;
    let fixture = write_fixture(&repo)?;
    let observed_cache = set_cbm_cache_dir(&cache)?;
    require(
        observed_cache == cache,
        "ISSUE_1146_EDGE_CACHE_BINDING_MISMATCH",
        cache.display(),
    )?;
    let project = cbm_project_name_from_path(repo.to_str().ok_or("edge repo path is not UTF-8")?)?;

    let missing = root.join("missing-astrolabe.exe");
    let missing_before = binding_edge_state(&cache, &project)?;
    let missing_wrap_before = supervisor_should_wrap();
    let missing_input_before = optional_file_state(&missing)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"worker_binary_missing","phase":"before","state":missing_before,"input":missing_input_before,"supervisor_should_wrap":missing_wrap_before})
        )?
    );
    let missing_result =
        initialize_cbm_host_process_with_verified_worker(&missing, ZERO_SHA256, &source_generation);
    let missing_after = binding_edge_state(&cache, &project)?;
    let missing_wrap_after = supervisor_should_wrap();
    let missing_input_after = optional_file_state(&missing)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"worker_binary_missing","phase":"after","state":missing_after,"input":missing_input_after,"supervisor_should_wrap":missing_wrap_after})
        )?
    );
    let missing_error = match missing_result {
        Err(error) => error,
        Ok(binding) => {
            return Err(
                format!("ISSUE_1146_MISSING_PATH_UNEXPECTEDLY_SUCCEEDED: {binding:?}").into(),
            );
        }
    };
    require(
        missing_error.envelope().code == "ASTRO_CBM_WORKER_BINARY_MISSING"
            && !missing_error.envelope().message.trim().is_empty()
            && !missing_error.envelope().remediation.trim().is_empty()
            && configured_cbm_host_binary_path()?.is_none()
            && missing_before == missing_after
            && missing_before["cache_top_level"] == json!([])
            && missing_before["worker_binary_binding"].is_null()
            && !missing_wrap_before
            && !missing_wrap_after
            && missing_input_before == missing_input_after
            && missing_input_after["exists"] == Value::Bool(false),
        "ISSUE_1146_MISSING_PATH_NOT_REFUSED_PRISTINE",
        &missing_error,
    )?;

    let directory_before = binding_edge_state(&cache, &project)?;
    let directory_wrap_before = supervisor_should_wrap();
    let directory_input_before = cache_top_level_inventory(&ordinary_directory)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"worker_binary_directory","phase":"before","state":directory_before,"input":directory_input_before,"supervisor_should_wrap":directory_wrap_before})
        )?
    );
    let directory_result = initialize_cbm_host_process_with_verified_worker(
        &ordinary_directory,
        ZERO_SHA256,
        &source_generation,
    );
    let directory_after = binding_edge_state(&cache, &project)?;
    let directory_wrap_after = supervisor_should_wrap();
    let directory_input_after = cache_top_level_inventory(&ordinary_directory)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"worker_binary_directory","phase":"after","state":directory_after,"input":directory_input_after,"supervisor_should_wrap":directory_wrap_after})
        )?
    );
    let directory_error = match directory_result {
        Err(error) => error,
        Ok(binding) => {
            return Err(
                format!("ISSUE_1146_DIRECTORY_PATH_UNEXPECTEDLY_SUCCEEDED: {binding:?}").into(),
            );
        }
    };
    require(
        directory_error.envelope().code == "ASTRO_CBM_WORKER_BINARY_NOT_ORDINARY"
            && !directory_error.envelope().message.trim().is_empty()
            && !directory_error.envelope().remediation.trim().is_empty()
            && configured_cbm_host_binary_path()?.is_none()
            && directory_before == directory_after
            && directory_before["cache_top_level"] == json!([])
            && directory_before["worker_binary_binding"].is_null()
            && !directory_wrap_before
            && !directory_wrap_after
            && directory_input_before == directory_input_after
            && directory_input_after.is_empty(),
        "ISSUE_1146_DIRECTORY_PATH_NOT_REFUSED_PRISTINE",
        &directory_error,
    )?;

    // This deliberately simulates a host that violated startup ordering so the
    // real production supervisor's unbound admission can be observed directly.
    // SAFETY: these native startup functions have no caller-owned pointer
    // arguments. They reproduce the ordinary host's memory posture and set one
    // process-global host-role flag before any runner call is constructed.
    unsafe {
        cbm_sys::cbm_index_supervisor_mark_host();
        cbm_sys::cbm_cli_set_version(c"dev".as_ptr());
        let info = cbm_sys::cbm_system_info();
        let ram_fraction = cbm_sys::cbm_mem_ram_fraction_for_total(info.total_ram);
        cbm_sys::cbm_mem_init(ram_fraction);
    }
    require(
        supervisor_should_wrap(),
        "ISSUE_1146_MANUAL_HOST_ROLE_NOT_ACTIVE",
        "the deliberate unbound-host edge did not activate supervisor routing",
    )?;
    let runner = CbmToolRunner::new_default()?;
    let supervisor_before = binding_edge_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"supervisor_unbound","phase":"before","state":supervisor_before})
        )?
    );
    let (supervisor_raw, supervisor_envelope, supervisor_payload) =
        call_tool_with_raw(&runner, "index_repository", &index_request(&repo))?;
    let supervisor_after = binding_edge_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"supervisor_unbound","phase":"after","state":supervisor_after})
        )?
    );
    let supervisor_diagnostic = json!({
        "envelope": &supervisor_envelope,
        "payload": &supervisor_payload,
        "before": &supervisor_before,
        "after": &supervisor_after,
        "supervisor_should_wrap": supervisor_should_wrap(),
    });
    require(
        supervisor_envelope["isError"] == Value::Bool(true)
            && supervisor_payload["code"] == "CBM_INDEX_WORKER_BINARY_PATH_UNBOUND"
            && supervisor_payload["outcome"] == "spawn_refused"
            && supervisor_payload["message"]
                .as_str()
                .is_some_and(|message| !message.trim().is_empty())
            && supervisor_payload["remediation"]
                .as_str()
                .is_some_and(|remediation| !remediation.trim().is_empty())
            && binding_project_artifacts_absent(&supervisor_after)
            && supervisor_before["cache_top_level"] == json!([])
            && supervisor_before["worker_binary_binding"].is_null()
            && supervisor_after["worker_binary_binding"].is_null()
            && binding_terminal_cache_inventory_valid(&supervisor_after, &project)
            && supervisor_should_wrap(),
        "ISSUE_1146_UNBOUND_SUPERVISOR_REFUSAL_MISMATCH",
        supervisor_diagnostic,
    )?;
    let (integrity, rows) = config_rows(&cache, &project)?;
    require(
        integrity == "ok" && rows.len() == 1,
        "ISSUE_1146_TERMINAL_TRANSITION_SET_INVALID",
        rows.len(),
    )?;
    let (transition_key, transition_raw) = rows
        .first_key_value()
        .ok_or("ISSUE_1146_TERMINAL_TRANSITION_MISSING")?;
    let transition: Value = serde_json::from_str(transition_raw)?;
    let canonical_repo = repo.canonicalize()?;
    let canonical_db = observed_cache.join(format!("{project}.db"));
    let (response_sha256, raw_response_sha256) = validate_unbound_transition(
        transition_key,
        &transition,
        &project,
        &canonical_repo,
        &canonical_db,
        &supervisor_raw,
        &supervisor_envelope,
    )?;
    let supervisor_raw_bytes = supervisor_raw.len();
    let logs = cache.join("logs");
    let worker_workspaces = if logs.try_exists()? {
        fs::read_dir(&logs)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".worker-"))
            .count()
    } else {
        0
    };
    require(
        worker_workspaces == 0,
        "ISSUE_1146_UNBOUND_WORKSPACE_CREATED",
        worker_workspaces,
    )?;
    let fixture_after = fixture_source_state(&repo)?;
    require(
        fixture_after == fixture["source"],
        "ISSUE_1146_EDGE_FIXTURE_SOURCE_MUTATED",
        &fixture_after,
    )?;
    let final_state = binding_edge_state(&cache, &project)?;
    let receipt = json!({
        "schema": "astrolabe.issue-1146.binding-edges.v1",
        "tree_sha": canonical_head()?,
        "source_generation_schema": worker_source_generation::SOURCE_GENERATION_SCHEMA,
        "source_generation_sha256": source_generation,
        "driver_artifact": current_driver_artifact_state()?,
        "project": project,
        "cache": cache,
        "observed_cache": observed_cache,
        "repo": repo,
        "fixture": fixture,
        "fixture_after": fixture_after,
        "missing": {"before":missing_before,"after":missing_after,"input_before":missing_input_before,"input_after":missing_input_after,"supervisor_should_wrap_before":missing_wrap_before,"supervisor_should_wrap_after":missing_wrap_after,"error":missing_error.into_envelope()},
        "directory": {"before":directory_before,"after":directory_after,"input_before":directory_input_before,"input_after":directory_input_after,"supervisor_should_wrap_before":directory_wrap_before,"supervisor_should_wrap_after":directory_wrap_after,"error":directory_error.into_envelope()},
        "supervisor_unbound": {
            "before": supervisor_before,
            "after": supervisor_after,
            "raw": {
                "text": supervisor_raw,
                "bytes": supervisor_raw_bytes,
                "sha256": raw_response_sha256,
            },
            "response_envelope": supervisor_envelope,
            "response": supervisor_payload,
            "response_sha256": response_sha256,
            "transition_key": transition_key,
            "transition_raw": transition_raw,
            "transition_sha256": sha256(transition_raw.as_bytes()),
            "worker_workspace_count": worker_workspaces,
            "supervisor_should_wrap": supervisor_should_wrap(),
        },
        "final_state": final_state,
    });
    let persisted = write_new_readback(
        &root.join("binding-edges.json"),
        &serde_json::to_vec_pretty(&receipt)?,
    )?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"event":"ISSUE_1146_BINDING_EDGES_COMPLETE","receipt":persisted})
        )?
    );
    Ok(())
}

fn binding_readback(root: PathBuf) -> AnyResult<()> {
    let receipt_bytes = fs::read(root.join("binding-edges.json"))?;
    let receipt: Value = serde_json::from_slice(&receipt_bytes)?;
    require(
        receipt["schema"] == "astrolabe.issue-1146.binding-edges.v1",
        "ISSUE_1146_RECEIPT_SCHEMA_INVALID",
        &receipt["schema"],
    )?;
    let current_tree_sha = canonical_head()?;
    let source_generation = current_source_generation_sha256()?;
    let driver_artifact = current_driver_artifact_state()?;
    require(
        receipt["tree_sha"].as_str() == Some(current_tree_sha.as_str())
            && receipt["source_generation_schema"]
                == worker_source_generation::SOURCE_GENERATION_SCHEMA
            && receipt["source_generation_sha256"] == Value::String(source_generation.clone())
            && source_generation == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256
            && receipt["driver_artifact"] == driver_artifact
            && !supervisor_should_wrap()
            && configured_cbm_host_binary_path()?.is_none(),
        "ISSUE_1146_READBACK_PROCESS_IDENTITY_MISMATCH",
        json!({
            "tree_sha": current_tree_sha,
            "source_generation_sha256": source_generation,
            "driver_artifact": driver_artifact,
            "supervisor_should_wrap": supervisor_should_wrap(),
            "worker_binary_binding": configured_cbm_host_binary_path()?,
        }),
    )?;
    let cache = PathBuf::from(
        receipt["cache"]
            .as_str()
            .ok_or("ISSUE_1146_RECEIPT_CACHE_MISSING")?,
    );
    let project = receipt["project"]
        .as_str()
        .ok_or("ISSUE_1146_RECEIPT_PROJECT_MISSING")?;
    let fixture_repo = PathBuf::from(
        receipt["repo"]
            .as_str()
            .ok_or("ISSUE_1146_RECEIPT_REPO_MISSING")?,
    );
    let observed_cache = PathBuf::from(
        receipt["observed_cache"]
            .as_str()
            .ok_or("ISSUE_1146_RECEIPT_OBSERVED_CACHE_MISSING")?,
    );
    require(
        cache == root.join("cache")
            && observed_cache == cache
            && fixture_repo == root.join("real-rust-repo"),
        "ISSUE_1146_RECEIPT_ROOT_BINDING_MISMATCH",
        json!({"root": root, "cache": cache, "repo": fixture_repo}),
    )?;
    let (integrity, rows) = config_rows(&cache, project)?;
    let transition_key = receipt["supervisor_unbound"]["transition_key"]
        .as_str()
        .ok_or("ISSUE_1146_RECEIPT_TRANSITION_KEY_MISSING")?;
    let transition_raw = receipt["supervisor_unbound"]["transition_raw"]
        .as_str()
        .ok_or("ISSUE_1146_RECEIPT_TRANSITION_RAW_MISSING")?;
    let transition_sha256 = sha256(transition_raw.as_bytes());
    let transition: Value = serde_json::from_str(transition_raw)?;
    let response_raw = receipt["supervisor_unbound"]["raw"]["text"]
        .as_str()
        .ok_or("ISSUE_1146_RECEIPT_RAW_RESPONSE_MISSING")?;
    let reparsed_response_envelope: Value = serde_json::from_str(response_raw)?;
    let response_envelope = &receipt["supervisor_unbound"]["response_envelope"];
    let response_sha256 = sha256(&serde_json::to_vec(&reparsed_response_envelope)?);
    let raw_response_sha256 = sha256(response_raw.as_bytes());
    require(
        integrity == "ok"
            && rows.len() == 1
            && rows.get(transition_key).map(String::as_str) == Some(transition_raw)
            && receipt["supervisor_unbound"]["transition_sha256"].as_str()
                == Some(transition_sha256.as_str())
            && receipt["supervisor_unbound"]["response_sha256"].as_str()
                == Some(response_sha256.as_str())
            && receipt["supervisor_unbound"]["raw"]["bytes"].as_u64()
                == u64::try_from(response_raw.len()).ok()
            && receipt["supervisor_unbound"]["raw"]["sha256"].as_str()
                == Some(raw_response_sha256.as_str())
            && &reparsed_response_envelope == response_envelope
            && transition["evidence"]["response_hash_basis"]
                == "astrolabe.persisted-json-compact.v1"
            && transition["evidence"]["response_sha256"] == Value::String(response_sha256.clone())
            && transition["evidence"]["raw_response_sha256"]
                == Value::String(raw_response_sha256.clone()),
        "ISSUE_1146_TRANSITION_PHYSICAL_READBACK_MISMATCH",
        transition_key,
    )?;
    let (validated_response_sha256, validated_raw_response_sha256) = validate_unbound_transition(
        transition_key,
        &transition,
        project,
        &fixture_repo.canonicalize()?,
        &observed_cache.join(format!("{project}.db")),
        response_raw,
        response_envelope,
    )?;
    require(
        validated_response_sha256 == response_sha256
            && validated_raw_response_sha256 == raw_response_sha256,
        "ISSUE_1146_RESPONSE_HASH_RECOMPUTATION_MISMATCH",
        json!({
            "response_sha256": &response_sha256,
            "validated_response_sha256": &validated_response_sha256,
            "raw_response_sha256": &raw_response_sha256,
            "validated_raw_response_sha256": &validated_raw_response_sha256,
        }),
    )?;
    let state = binding_edge_state(&cache, project)?;
    require(
        state == receipt["final_state"] && binding_project_artifacts_absent(&state),
        "ISSUE_1146_FINAL_PHYSICAL_STATE_MISMATCH",
        &state,
    )?;
    require(
        state["worker_binary_binding"].is_null()
            && binding_terminal_cache_inventory_valid(&state, project),
        "ISSUE_1146_FINAL_CACHE_INVENTORY_INVALID",
        &state["cache_top_level"],
    )?;
    let fixture_source = fixture_source_state(&fixture_repo)?;
    require(
        fixture_source == receipt["fixture"]["source"]
            && fixture_source == receipt["fixture_after"],
        "ISSUE_1146_FIXTURE_SOURCE_READBACK_MISMATCH",
        &fixture_source,
    )?;
    let missing_input = optional_file_state(&root.join("missing-astrolabe.exe"))?;
    let directory_input = cache_top_level_inventory(&root.join("ordinary-directory"))?;
    require(
        missing_input == receipt["missing"]["input_after"]
            && receipt["directory"]["input_after"].as_array() == Some(&directory_input)
            && missing_input["exists"] == Value::Bool(false)
            && directory_input.is_empty(),
        "ISSUE_1146_INVALID_INPUT_SEPARATE_READBACK_MISMATCH",
        json!({"missing": missing_input, "directory": directory_input}),
    )?;
    let logs = cache.join("logs");
    let worker_workspaces = if logs.try_exists()? {
        fs::read_dir(&logs)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".worker-"))
            .count()
    } else {
        0
    };
    require(
        worker_workspaces == 0,
        "ISSUE_1146_READBACK_WORKER_WORKSPACE_PRESENT",
        worker_workspaces,
    )?;
    let readback = json!({
        "schema": "astrolabe.issue-1146.binding-readback.v1",
        "receipt_sha256": sha256(&receipt_bytes),
        "tree_sha": current_tree_sha,
        "source_generation_schema": worker_source_generation::SOURCE_GENERATION_SCHEMA,
        "source_generation_sha256": source_generation,
        "driver_artifact": driver_artifact,
        "config_integrity": integrity,
        "config_row_count": rows.len(),
        "transition_key": transition_key,
        "transition_sha256": transition_sha256,
        "response_sha256": response_sha256,
        "raw_response_sha256": raw_response_sha256,
        "raw_response_bytes": response_raw.len(),
        "raw_response_reparsed": true,
        "worker_workspace_count": worker_workspaces,
        "fixture_source": fixture_source,
        "missing_input": missing_input,
        "directory_input": directory_input,
        "final_state": state,
        "project_artifacts_absent": true,
        "separate_process_readback": true,
    });
    let persisted = write_new_readback(
        &root.join("binding-readback.json"),
        &serde_json::to_vec_pretty(&readback)?,
    )?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"event":"ISSUE_1146_BINDING_READBACK_COMPLETE","receipt":persisted,"state":readback})
        )?
    );
    Ok(())
}

fn staged_abort_project_root(cache: &Path, project: &str) -> PathBuf {
    let project_digest = sha256(project.as_bytes());
    cache
        .join(".astrolabe-shadow-publication")
        .join(&project_digest[..32])
}

fn staged_abort_preserved_root(cache: &Path, project: &str) -> PathBuf {
    let project_digest = sha256(project.as_bytes());
    cache
        .join(".astrolabe-shadow-preserved-stage")
        .join(&project_digest[..32])
}

fn staged_abort_vault_path(stage_cache: &Path, project: &str) -> PathBuf {
    stage_cache.join(format!("{project}.astrolabe-vault"))
}

fn staged_abort_vector_state(vector: &SlotVector) -> Value {
    match vector {
        SlotVector::Dense { dim, data } => json!({
            "kind": "dense",
            "dim": dim,
            "bits": data.iter().map(|value| value.to_bits()).collect::<Vec<_>>(),
        }),
        SlotVector::Sparse { dim, entries } => json!({
            "kind": "sparse",
            "dim": dim,
            "entries": entries
                .iter()
                .map(|entry| json!({"idx":entry.idx,"bits":entry.val.to_bits()}))
                .collect::<Vec<_>>(),
        }),
        SlotVector::Multi { token_dim, tokens } => json!({
            "kind": "multi",
            "token_dim": token_dim,
            "bits": tokens
                .iter()
                .map(|token| token.iter().map(|value| value.to_bits()).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
        }),
        SlotVector::Absent { reason } => json!({
            "kind": "absent",
            "reason": reason,
        }),
    }
}

fn immutable_sqlite(path: &Path) -> AnyResult<Connection> {
    let uri = astrolabe_domain::winpath::sqlite_immutable_uri(path)?;
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE,
    )?;
    connection.pragma_update(None, "query_only", true)?;
    Ok(connection)
}

fn staged_abort_symbol_count(db_path: &Path, project: &str) -> AnyResult<u64> {
    let connection = immutable_sqlite(db_path)?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM nodes WHERE project = ?1 AND name = 'staged_abort_only_delta'",
        [project],
        |row| row.get(0),
    )?;
    require(
        count >= 0,
        "ISSUE_1147_STAGED_ABORT_SYMBOL_COUNT_INVALID",
        count,
    )?;
    Ok(u64::try_from(count)?)
}

fn staged_abort_live_generation_state(cache: &Path, project: &str) -> AnyResult<Value> {
    let source_db = cache.join(format!("{project}.db"));
    let lowered_db = cache.join(format!("{project}.astrolabe-lowered.db"));
    let vault = cache.join(format!("{project}.astrolabe-vault"));
    let search_manifest = cache.join(format!("{project}.astrolabe-search-index.v2.json"));
    let source_connection = immutable_sqlite(&source_db)?;
    let integrity: String =
        source_connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let node_count: i64 =
        source_connection.query_row("SELECT COUNT(*) FROM nodes", [], |row| row.get(0))?;
    let edge_count: i64 =
        source_connection.query_row("SELECT COUNT(*) FROM edges", [], |row| row.get(0))?;
    let delta_count: i64 = source_connection.query_row(
        "SELECT COUNT(*) FROM nodes WHERE project = ?1 AND name = 'staged_abort_only_delta'",
        [project],
        |row| row.get(0),
    )?;
    let semantic_project = read_moderate_semantic_project_state(&source_connection, project)?;
    drop(source_connection);
    require(
        integrity == "ok" && node_count > 0 && edge_count >= 0 && delta_count >= 0,
        "ISSUE_1147_STAGED_ABORT_LIVE_SQLITE_INVALID",
        json!({
            "integrity": integrity,
            "nodes": node_count,
            "edges": edge_count,
            "delta_count": delta_count,
        }),
    )?;
    let (config_integrity, mut config) = config_rows(cache, project)?;
    let transition_key = format!("astrolabe.calyx.{project}.project_transition_json");
    let transition_present = config.remove(&transition_key).is_some();
    require(
        config_integrity == "ok" && transition_present,
        "ISSUE_1147_STAGED_ABORT_LIVE_CONFIG_INVALID",
        json!({"integrity":config_integrity,"transition_present":transition_present}),
    )?;
    let state = json!({
        "source_family": transition_family_evidence(&source_db)?,
        "lowered_family": transition_family_evidence(&lowered_db)?,
        "vault_tree": tree_state(&vault)?,
        "search_manifest": optional_file_state(&search_manifest)?,
        "config_rows_excluding_transition": ordered_config_rows(&config),
        "sqlite": {
            "integrity": integrity,
            "nodes": u64::try_from(node_count)?,
            "edges": u64::try_from(edge_count)?,
            "staged_abort_only_delta": u64::try_from(delta_count)?,
            "node_vectors": semantic_project.node_vector_count,
            "token_vectors": semantic_project.token_vector_count,
            "project": semantic_project_state_json(&semantic_project),
        },
    });
    Ok(json!({
        "sha256": sha256(&serde_json::to_vec(&state)?),
        "state": state,
    }))
}

fn commit_staged_abort_delta(repo: &Path) -> AnyResult<Value> {
    let source_path = repo.join("src").join("lib.rs");
    let before = fixture_source_state(repo)?;
    let delta = br#"

pub fn staged_abort_only_delta(value: i64) -> i64 {
    normalize(value) + 7
}
"#;
    let mut source = OpenOptions::new().append(true).open(&source_path)?;
    source.write_all(delta)?;
    source.sync_all()?;
    drop(source);
    let observed = fs::read(&source_path)?;
    require(
        observed.ends_with(delta),
        "ISSUE_1147_STAGED_ABORT_DELTA_READBACK_MISMATCH",
        source_path.display(),
    )?;
    let run = |args: &[&str]| -> AnyResult<()> {
        let output = Command::new("git.exe")
            .args(args)
            .current_dir(repo)
            .output()?;
        require(
            output.status.success(),
            "ISSUE_1147_STAGED_ABORT_GIT_FAILED",
            format!(
                "args={args:?} exit={:?} stdout={} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ),
        )
    };
    run(&["add", "src/lib.rs"])?;
    run(&[
        "-c",
        "user.name=Astrolabe FSV",
        "-c",
        "user.email=astrolabe-fsv@invalid.local",
        "-c",
        "commit.gpgSign=false",
        "commit",
        "-m",
        "staged abort generation delta",
    ])?;
    let head = Command::new("git.exe")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()?;
    require(
        head.status.success(),
        "ISSUE_1147_STAGED_ABORT_HEAD_FAILED",
        String::from_utf8_lossy(&head.stderr),
    )?;
    let after = fixture_source_state(repo)?;
    require(
        before != after,
        "ISSUE_1147_STAGED_ABORT_DELTA_DID_NOT_CHANGE_SOURCE",
        &after,
    )?;
    Ok(json!({
        "schema": "astrolabe.issue-1147.staged-source-delta.v1",
        "source_path": source_path,
        "delta_bytes": delta.len(),
        "delta_sha256": sha256(delta),
        "head": String::from_utf8(head.stdout)?.trim(),
        "before": before,
        "after": after,
    }))
}

struct StagedAbortTransaction {
    generation: String,
    generation_dir: PathBuf,
    stage_cache: PathBuf,
    journal: Value,
    journal_bytes: Vec<u8>,
}

struct StagedAbortBarrierReady {
    root: PathBuf,
    arm: Value,
    arm_bytes: Vec<u8>,
    ready: Value,
    ready_bytes: Vec<u8>,
    ready_sha256: String,
    target_binding: Value,
}

fn staged_abort_read_transaction(
    cache: &Path,
    project: &str,
) -> AnyResult<Option<StagedAbortTransaction>> {
    let project_root = staged_abort_project_root(cache, project);
    if !project_root.try_exists()? {
        return Ok(None);
    }
    let root_metadata = fs::symlink_metadata(&project_root)?;
    require(
        root_metadata.is_dir() && root_metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1147_STAGED_ABORT_TRANSACTION_ROOT_INVALID",
        project_root.display(),
    )?;
    let mut entries = fs::read_dir(&project_root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    if entries.is_empty() {
        return Ok(None);
    }
    require(
        entries.len() == 1,
        "ISSUE_1147_STAGED_ABORT_TRANSACTION_AMBIGUOUS",
        json!({
            "root": project_root,
            "entries": entries
                .iter()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
        }),
    )?;
    let generation_dir = entries.remove(0).path();
    let generation_metadata = fs::symlink_metadata(&generation_dir)?;
    require(
        generation_metadata.is_dir()
            && generation_metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1147_STAGED_ABORT_GENERATION_INVALID",
        generation_dir.display(),
    )?;
    let generation = generation_dir
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or("ISSUE_1147_STAGED_ABORT_GENERATION_NAME_INVALID")?
        .to_string();
    let journal_path = generation_dir.join("transaction.json");
    let journal_bytes = match fs::read(&journal_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let journal: Value = serde_json::from_slice(&journal_bytes).map_err(|error| -> Box<dyn Error + Send + Sync> {
        format!(
            "ISSUE_1147_STAGED_ABORT_JOURNAL_INVALID: path={} bytes={} sha256={} parse_error={error}; remediation: preserve the transaction and inspect the exact journal producer",
            journal_path.display(),
            journal_bytes.len(),
            sha256(&journal_bytes),
        )
        .into()
    })?;
    let stage_cache = generation_dir.join("stage");
    require(
        journal["schema"] == "astrolabe.shadow-publication.v3"
            && journal["project"] == Value::String(project.to_string())
            && journal["generation"] == Value::String(generation.clone())
            && journal["live_cache"] == json!(cache)
            && journal["stage_cache"] == json!(stage_cache)
            && journal["owner"]["pid"].as_u64().is_some_and(|pid| pid > 0)
            && journal["owner"]["process_start_utc_ticks"]
                .as_u64()
                .is_some_and(|ticks| ticks > 0),
        "ISSUE_1147_STAGED_ABORT_JOURNAL_IDENTITY_MISMATCH",
        &journal,
    )?;
    Ok(Some(StagedAbortTransaction {
        generation,
        generation_dir,
        stage_cache,
        journal,
        journal_bytes,
    }))
}

fn staged_abort_arm_barrier(
    root: &Path,
    payload: &Path,
    project: &str,
    source_delta: &Value,
) -> AnyResult<Value> {
    require(
        root.is_absolute() && root.try_exists()?,
        "ISSUE_1147_STAGED_ABORT_BARRIER_ROOT_INVALID",
        root.display(),
    )?;
    let metadata = fs::symlink_metadata(root)?;
    require(
        metadata.is_dir() && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1147_STAGED_ABORT_BARRIER_ROOT_INVALID",
        root.display(),
    )?;
    let entries = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    require(
        entries.is_empty(),
        "ISSUE_1147_STAGED_ABORT_BARRIER_ROOT_NOT_EMPTY",
        entries
            .iter()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(","),
    )?;
    let source_delta_sha256 = sha256(&serde_json::to_vec(source_delta)?);
    let barrier_id = sha256(&serde_json::to_vec(&json!({
        "schema": STAGED_ABORT_BARRIER_ARM_SCHEMA,
        "payload": payload,
        "project": project,
        "source_delta_sha256": source_delta_sha256,
        "target_slot": STAGED_ABORT_SLOT,
    }))?);
    let arm = json!({
        "schema": STAGED_ABORT_BARRIER_ARM_SCHEMA,
        "project": project,
        "barrier_root": root,
        "payload_root": payload,
        "barrier_id": barrier_id,
        "target_slot": STAGED_ABORT_SLOT,
        "source_delta_sha256": source_delta_sha256,
        "wait_timeout_ms": STAGED_ABORT_BARRIER_WAIT_MS,
    });
    let bytes = serde_json::to_vec(&arm)?;
    let physical = write_new_atomic_readback(&root.join("arm.json"), &bytes)?;
    Ok(json!({
        "value": arm,
        "physical": physical,
    }))
}

fn staged_abort_wait_for_ready(
    barrier_root: &Path,
    cache: &Path,
    project: &str,
    call_done: &AtomicBool,
) -> AnyResult<(StagedAbortTransaction, StagedAbortBarrierReady)> {
    let arm_path = barrier_root.join("arm.json");
    let arm_bytes = fs::read(&arm_path)?;
    let arm: Value = serde_json::from_slice(&arm_bytes)?;
    require(
        arm.as_object().is_some_and(|object| object.len() == 8)
            && arm["schema"] == STAGED_ABORT_BARRIER_ARM_SCHEMA
            && arm["project"] == Value::String(project.to_string())
            && arm["barrier_root"] == json!(barrier_root)
            && arm["payload_root"]
                .as_str()
                .map(Path::new)
                .is_some_and(|payload| barrier_root.starts_with(payload))
            && arm["barrier_id"].as_str().is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            && arm["target_slot"] == STAGED_ABORT_SLOT
            && arm["source_delta_sha256"].as_str().is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            && arm["wait_timeout_ms"] == STAGED_ABORT_BARRIER_WAIT_MS,
        "ISSUE_1147_STAGED_ABORT_BARRIER_ARM_MISMATCH",
        &arm,
    )?;
    let started = Instant::now();
    let timeout = Duration::from_millis(STAGED_ABORT_BARRIER_WAIT_MS);
    let ready_path = barrier_root.join("ready.json");
    loop {
        if call_done.load(Ordering::Acquire) {
            return Err(
                "ISSUE_1147_STAGED_ABORT_BARRIER_MISSED: index_repository completed before the durable post-binding ready receipt was observed; no mutation is authorized and no retry/fallback is performed"
                    .into(),
            );
        }
        if started.elapsed() > timeout {
            return Err(format!(
                "ISSUE_1147_STAGED_ABORT_BARRIER_TIMEOUT: no durable ready receipt was observed within {} ms; no mutation was attempted",
                STAGED_ABORT_BARRIER_WAIT_MS,
            )
            .into());
        }
        let ready_bytes = match fs::read(&ready_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(STAGED_ABORT_BARRIER_POLL_MS));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let ready_metadata = fs::symlink_metadata(&ready_path)?;
        require(
            ready_metadata.is_file()
                && ready_metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
            "ISSUE_1147_STAGED_ABORT_BARRIER_READY_FILE_INVALID",
            ready_path.display(),
        )?;
        let ready: Value = serde_json::from_slice(&ready_bytes).map_err(
            |error| -> Box<dyn Error + Send + Sync> {
                format!(
                    "ISSUE_1147_STAGED_ABORT_BARRIER_READY_INVALID: bytes={} sha256={} parse_error={error}; remediation: preserve the barrier and staged generation",
                    ready_bytes.len(),
                    sha256(&ready_bytes),
                )
                .into()
            },
        )?;
        if ready_path.try_exists()? {
            let transaction = staged_abort_read_transaction(cache, project)?
                .ok_or("ISSUE_1147_STAGED_ABORT_TRANSACTION_MISSING_AT_BARRIER")?;
            let vault_path = staged_abort_vault_path(&transaction.stage_cache, project);
            let slot_bindings = ready["slot_bindings"]
                .as_array()
                .filter(|bindings| !bindings.is_empty())
                .ok_or("ISSUE_1147_STAGED_ABORT_BARRIER_BINDINGS_MISSING")?;
            let binding_snapshot_seq = ready["source_binding_snapshot_seq"]
                .as_u64()
                .filter(|seq| *seq > 0)
                .ok_or("ISSUE_1147_STAGED_ABORT_BARRIER_BINDING_SEQ_INVALID")?;
            let source_compression_generation = ready["source_compression_generation"]
                .as_u64()
                .ok_or("ISSUE_1147_STAGED_ABORT_BARRIER_COMPRESSION_GENERATION_INVALID")?;
            let lowercase_sha = |value: &str| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            };
            let mut binding_slots = BTreeSet::new();
            let mut target_binding = None;
            for binding in slot_bindings {
                let slot = u16::try_from(
                    binding["slot"]
                        .as_u64()
                        .ok_or("ISSUE_1147_STAGED_ABORT_BARRIER_SLOT_INVALID")?,
                )?;
                let slot_generation = binding["slot_cf_generation"]
                    .as_u64()
                    .ok_or("ISSUE_1147_STAGED_ABORT_BARRIER_SLOT_GENERATION_INVALID")?;
                let compression_generation = binding["compression_cf_generation"]
                    .as_u64()
                    .ok_or("ISSUE_1147_STAGED_ABORT_BARRIER_COMPRESSION_GENERATION_INVALID")?;
                let identity: Option<CompressedGenerationIdentity> =
                    serde_json::from_value(binding["compressed_generation_identity"].clone())?;
                let identity_valid = identity.as_ref().is_none_or(|identity| {
                    identity.slot_id == slot
                        && identity.raw_dim > 0
                        && identity.stored_dim > 0
                        && lowercase_sha(&identity.codec_context_sha256)
                        && lowercase_sha(&identity.generation_sha256)
                        && lowercase_sha(&identity.raw_generation_sha256)
                        && lowercase_sha(&identity.membership_sha256)
                        && identity
                            .assay_attestation_sha256
                            .as_deref()
                            .is_none_or(lowercase_sha)
                });
                require(
                    binding.as_object().is_some_and(|object| object.len() == 4)
                        && binding_slots.insert(slot)
                        && slot_generation <= binding_snapshot_seq
                        && compression_generation == source_compression_generation
                        && compression_generation <= binding_snapshot_seq
                        && identity_valid,
                    "ISSUE_1147_STAGED_ABORT_BARRIER_BINDING_INVALID",
                    binding,
                )?;
                if slot == STAGED_ABORT_SLOT {
                    target_binding = Some(binding.clone());
                }
            }
            require(
                ready.as_object().is_some_and(|object| object.len() == 17)
                    && ready["schema"] == STAGED_ABORT_BARRIER_READY_SCHEMA
                    && ready["barrier_id"] == arm["barrier_id"]
                    && ready["project"] == Value::String(project.to_string())
                    && ready["target_slot"] == STAGED_ABORT_SLOT
                    && ready["arm_sha256"] == Value::String(sha256(&arm_bytes))
                    && ready["worker_pid"] == ready["publication_owner"]["pid"]
                    && ready["worker_pid"] == transaction.journal["owner"]["pid"]
                    && ready["publication_generation"]
                        == Value::String(transaction.generation.clone())
                    && ready["transaction_journal_sha256"]
                        == Value::String(sha256(&transaction.journal_bytes))
                    && ready["publication_owner"] == transaction.journal["owner"]
                    && ready["stage_cache"] == json!(transaction.stage_cache)
                    && ready["vault_path"] == json!(vault_path)
                    && ready["source_binding_snapshot_seq"]
                        .as_u64()
                        .is_some_and(|seq| seq > 0)
                    && ready["compact_graph_snapshot_seq"] == ready["source_binding_snapshot_seq"]
                    && ready["vault_latest_seq"] == ready["source_binding_snapshot_seq"]
                    && ready["source_compression_generation"].as_u64().is_some()
                    && ready["phase"]
                        == "all_source_bindings_complete_lease_dropped_before_first_bound_slot_materialization"
                    && target_binding.is_some()
                    && transaction.journal["phase"] == "cbm_complete",
                "ISSUE_1147_STAGED_ABORT_BARRIER_READY_MISMATCH",
                json!({
                    "ready": ready,
                    "journal": transaction.journal,
                    "vault_path": vault_path,
                }),
            )?;
            return Ok((
                transaction,
                StagedAbortBarrierReady {
                    root: barrier_root.to_path_buf(),
                    arm,
                    arm_bytes,
                    ready_sha256: sha256(&ready_bytes),
                    ready,
                    ready_bytes,
                    target_binding: target_binding
                        .ok_or("ISSUE_1147_STAGED_ABORT_TARGET_BINDING_MISSING")?,
                },
            ));
        }
    }
}

struct StagedAbortBarrierAckRequest<'a> {
    barrier: &'a StagedAbortBarrierReady,
    transaction: &'a StagedAbortTransaction,
    vault_path: &'a Path,
    project: &'a str,
    commit_seq: u64,
    ledger_ref: &'a LedgerRef,
    mutation_payload_sha256: &'a str,
    mutation_receipt: &'a Value,
    data_key: &'a [u8],
    data_value: &'a [u8],
    data_row_blake3: &'a str,
}

fn staged_abort_write_barrier_ack(request: StagedAbortBarrierAckRequest<'_>) -> AnyResult<Value> {
    let StagedAbortBarrierAckRequest {
        barrier,
        transaction,
        vault_path,
        project,
        commit_seq,
        ledger_ref,
        mutation_payload_sha256,
        mutation_receipt,
        data_key,
        data_value,
        data_row_blake3,
    } = request;
    let mutation_receipt_bytes = mutation_receipt["bytes"]
        .as_u64()
        .ok_or("ISSUE_1147_STAGED_ABORT_MUTATION_RECEIPT_BYTES_MISSING")?;
    let mutation_receipt_sha256 = mutation_receipt["sha256"]
        .as_str()
        .ok_or("ISSUE_1147_STAGED_ABORT_MUTATION_RECEIPT_SHA_MISSING")?;
    let ack = json!({
        "schema": STAGED_ABORT_BARRIER_ACK_SCHEMA,
        "barrier_id": barrier.arm["barrier_id"],
        "project": project,
        "ready_sha256": barrier.ready_sha256,
        "status": "source_mutation_committed_and_handle_closed",
        "publication_generation": transaction.generation,
        "stage_cache": transaction.stage_cache,
        "vault_path": vault_path,
        "slot": STAGED_ABORT_SLOT,
        "commit_seq": commit_seq,
        "ledger_ref": ledger_ref,
        "mutation_payload_sha256": mutation_payload_sha256,
        "mutation_receipt_bytes": mutation_receipt_bytes,
        "mutation_receipt_sha256": mutation_receipt_sha256,
        "data_key_hex": hex_lower(data_key),
        "data_value_sha256": sha256(data_value),
        "data_row_blake3": data_row_blake3,
        "error_sha256": Value::Null,
    });
    require(
        ack.as_object().is_some_and(|object| object.len() == 18),
        "ISSUE_1147_STAGED_ABORT_BARRIER_ACK_SHAPE_INVALID",
        &ack,
    )?;
    let bytes = serde_json::to_vec(&ack)?;
    let physical = write_new_atomic_readback(&barrier.root.join("ack.json"), &bytes)?;
    Ok(json!({
        "value": ack,
        "physical": physical,
    }))
}

fn staged_abort_write_barrier_failure_ack(
    barrier: &StagedAbortBarrierReady,
    transaction: &StagedAbortTransaction,
    project: &str,
    error: &str,
) -> AnyResult<Value> {
    let ack = json!({
        "schema": STAGED_ABORT_BARRIER_ACK_SCHEMA,
        "barrier_id": barrier.arm["barrier_id"],
        "project": project,
        "ready_sha256": barrier.ready_sha256,
        "status": "source_mutation_failed",
        "publication_generation": transaction.generation,
        "stage_cache": transaction.stage_cache,
        "vault_path": staged_abort_vault_path(&transaction.stage_cache, project),
        "slot": Value::Null,
        "commit_seq": Value::Null,
        "ledger_ref": Value::Null,
        "mutation_payload_sha256": Value::Null,
        "mutation_receipt_bytes": Value::Null,
        "mutation_receipt_sha256": Value::Null,
        "data_key_hex": Value::Null,
        "data_value_sha256": Value::Null,
        "data_row_blake3": Value::Null,
        "error_sha256": sha256(error.as_bytes()),
    });
    require(
        ack.as_object().is_some_and(|object| object.len() == 18),
        "ISSUE_1147_STAGED_ABORT_BARRIER_FAILURE_ACK_SHAPE_INVALID",
        &ack,
    )?;
    let bytes = serde_json::to_vec(&ack)?;
    let physical = write_new_atomic_readback(&barrier.root.join("ack.json"), &bytes)?;
    Ok(json!({
        "value": ack,
        "physical": physical,
    }))
}

fn staged_abort_physical_ledger<C>(
    vault: &AsterVault<C>,
    reference: &LedgerRef,
    expected_subject: &SubjectId,
    expected_payload: &[u8],
) -> AnyResult<(Vec<u8>, Value)>
where
    C: Clock,
{
    let wanted = BTreeSet::from([reference.seq]);
    let (rows, trace) = vault.read_physical_ledger_seqs(&wanted)?;
    let resolved = trace.tiers.iter().map(|tier| tier.resolved).sum::<usize>();
    let complete_scan_wanted = trace
        .tiers
        .iter()
        .filter(|tier| tier.tier == "complete_scan")
        .map(|tier| tier.wanted)
        .sum::<usize>();
    let row = rows
        .get(&reference.seq)
        .ok_or("ISSUE_1147_STAGED_ABORT_PHYSICAL_LEDGER_ROW_MISSING")?;
    let entry = calyx_ledger::decode(&row.bytes)?;
    require(
        rows.len() == 1
            && resolved == 1
            && complete_scan_wanted == 0
            && row.seq == reference.seq
            && entry.seq == reference.seq
            && entry.entry_hash == reference.hash
            && entry.verify()
            && entry.kind == EntryKind::Admin
            && entry.subject == *expected_subject
            && entry.actor == ActorId::Service(STAGED_ABORT_ACTOR.to_string())
            && entry.payload == expected_payload,
        "ISSUE_1147_STAGED_ABORT_PHYSICAL_LEDGER_MISMATCH",
        json!({
            "reference": reference,
            "row_seq": row.seq,
            "entry": entry,
            "trace": trace,
            "resolved": resolved,
            "complete_scan_wanted": complete_scan_wanted,
        }),
    )?;
    Ok((
        row.bytes.clone(),
        json!({
            "reference": reference,
            "physical_row_bytes": row.bytes.len(),
            "physical_row_sha256": sha256(&row.bytes),
            "entry": entry,
            "payload_bytes": expected_payload.len(),
            "payload_sha256": sha256(expected_payload),
            "point_read_trace": trace,
            "complete_scan_wanted": complete_scan_wanted,
        }),
    ))
}

fn staged_abort_wal_commit_inventory<C>(
    vault: &AsterVault<C>,
    commit_seq: u64,
    data_cf: ColumnFamily,
    data_key: &[u8],
    data_value: &[u8],
    ledger_ref: &LedgerRef,
    ledger_bytes: &[u8],
) -> AnyResult<Value>
where
    C: Clock,
{
    let expected_cfs = [data_cf, ColumnFamily::Ledger, ColumnFamily::TimeIndex];
    let inventory = vault.physical_wal_commit_inventory(commit_seq, &expected_cfs)?;
    let data_rows = inventory
        .rows
        .iter()
        .filter(|row| row.cf == data_cf)
        .collect::<Vec<_>>();
    let ledger_rows = inventory
        .rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::Ledger)
        .collect::<Vec<_>>();
    let time_index_rows = inventory
        .rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::TimeIndex)
        .collect::<Vec<_>>();
    let expected_ledger_key = ledger_key(ledger_ref.seq);
    let expected_ledger_bytes = u64::try_from(ledger_bytes.len())?;
    let mut expected_time_index_key = Vec::with_capacity(16);
    expected_time_index_key.extend_from_slice(&GENERATION_OBSERVED_AT_MS.to_be_bytes());
    expected_time_index_key.extend_from_slice(&commit_seq.to_be_bytes());
    let expected_time_index_value = [0_u8];
    require(
        inventory.seq == commit_seq
            && vault.latest_seq() == commit_seq
            && inventory.wal_replay_floor_seq < commit_seq
            && inventory.column_families == expected_cfs
            && inventory.rows.len() == 3
            && inventory.wal_record.length > 0
            && data_rows.len() == 1
            && data_rows[0].key == data_key
            && data_rows[0].value_length == u64::try_from(data_value.len())?
            && data_rows[0].value_sha256_hex() == sha256(data_value)
            && !data_rows[0].tombstoned
            && ledger_rows.len() == 1
            && ledger_rows[0].key == expected_ledger_key
            && ledger_rows[0].value_length == expected_ledger_bytes
            && ledger_rows[0].value_sha256_hex() == sha256(ledger_bytes)
            && !ledger_rows[0].tombstoned
            && time_index_rows.len() == 1
            && time_index_rows[0].key == expected_time_index_key
            && time_index_rows[0].value_length == 1
            && time_index_rows[0].value_sha256_hex() == sha256(&expected_time_index_value)
            && !time_index_rows[0].tombstoned,
        "ISSUE_1147_STAGED_ABORT_WAL_INVENTORY_MISMATCH",
        format!("{inventory:#?}"),
    )?;
    Ok(json!({
        "commit_seq": commit_seq,
        "wal_replay_floor_seq": inventory.wal_replay_floor_seq,
        "uncheckpointed_wal_tail": true,
        "column_families": inventory
            .column_families
            .iter()
            .map(|cf| cf.name())
            .collect::<Vec<_>>(),
        "rows": inventory.rows.iter().map(|row| json!({
            "ordinal": row.ordinal,
            "cf": row.cf.name(),
            "key_hex": hex_lower(&row.key),
            "key_sha256": row.key_sha256_hex(),
            "value_length": row.value_length,
            "value_sha256": row.value_sha256_hex(),
            "tombstoned": row.tombstoned,
        })).collect::<Vec<_>>(),
        "wal_record": {
            "role": format!("{:?}", inventory.wal_record.role),
            "identity": inventory.wal_record.canonical_identity(),
            "offset": inventory.wal_record.offset,
            "length": inventory.wal_record.length,
            "sha256": inventory.wal_record.sha256_hex(),
        },
        "data_row_verified": true,
        "ledger_row_verified": true,
        "time_index_row_verified": true,
    }))
}

fn staged_abort_mutate_source_after_ready(
    transaction: &StagedAbortTransaction,
    barrier: &StagedAbortBarrierReady,
    project: &str,
    call_done: &AtomicBool,
) -> AnyResult<Value> {
    let vault_path = staged_abort_vault_path(&transaction.stage_cache, project);
    require(
        vault_path.starts_with(&transaction.stage_cache) && vault_path.try_exists()?,
        "ISSUE_1147_STAGED_ABORT_VAULT_PATH_INVALID",
        vault_path.display(),
    )?;
    let vault_id = STAGED_ABORT_SHADOW_VAULT_ID.parse::<VaultId>()?;
    let vault_salt = format!("astrolabe-shadow-v1:{project}").into_bytes();
    let vault = AsterVault::open_with_clock(
        &vault_path,
        vault_id,
        vault_salt,
        VaultOptions {
            read_only: false,
            restore_ledger_hook: true,
            restore_mvcc_rows: false,
            selected_cfs: None,
            ..VaultOptions::default()
        },
        FixedClock::new(GENERATION_OBSERVED_AT_MS),
    )?;
    let slot = SlotId::new(STAGED_ABORT_SLOT);
    let slot_cf = ColumnFamily::slot(slot);
    let before_seq = vault.latest_seq();
    let rows = vault.scan_cf_range_page_at(
        before_seq,
        slot_cf,
        &KeyRange {
            start: Vec::new(),
            end: None,
        },
        None,
        1,
    )?;
    require(
        rows.len() == 1 && rows[0].0.len() == 16,
        "ISSUE_1147_STAGED_ABORT_SLOT_PAGE_INVALID",
        json!({
            "slot": STAGED_ABORT_SLOT,
            "rows": rows.len(),
            "key_bytes": rows.first().map(|row| row.0.len()),
        }),
    )?;
    let (row_key, row_bytes) = rows
        .into_iter()
        .next()
        .ok_or("ISSUE_1147_STAGED_ABORT_SLOT_ROW_MISSING")?;
    let cx_id = CxId::from_bytes(<[u8; 16]>::try_from(row_key.as_slice())?);
    let decoded = decode_strict_raw_slot_value(slot, cx_id, &row_bytes)?;
    let compression_key = compression_manifest_key(slot);
    let compression_manifest_before =
        vault.read_cf_at(before_seq, ColumnFamily::Compression, &compression_key)?;
    let slot_generation_before = vault.cf_content_generation(slot_cf)?;
    let compression_generation_before = vault.cf_content_generation(ColumnFamily::Compression)?;
    let storage_before = vault.latest_only_readback_status();
    let production_slot_generation = barrier.target_binding["slot_cf_generation"]
        .as_u64()
        .ok_or("ISSUE_1147_STAGED_ABORT_READY_SLOT_GENERATION_MISSING")?;
    let production_compression_generation = barrier.target_binding["compression_cf_generation"]
        .as_u64()
        .ok_or("ISSUE_1147_STAGED_ABORT_READY_COMPRESSION_GENERATION_MISSING")?;
    require(
        before_seq == barrier.ready["source_binding_snapshot_seq"]
            && compression_manifest_before.is_none()
            && slot_generation_before > 0
            && barrier.target_binding["slot"] == STAGED_ABORT_SLOT
            && barrier.target_binding["compressed_generation_identity"].is_null()
            && storage_before.latest_only
            && storage_before.overlay_keys == 0
            && storage_before.overlay_versions == 0
            && storage_before.overlay_bytes == 0,
        "ISSUE_1147_STAGED_ABORT_SOURCE_PRESTATE_INVALID",
        json!({
            "compression_manifest_present": compression_manifest_before.is_some(),
            "slot_generation": slot_generation_before,
            "compression_generation": compression_generation_before,
            "storage": storage_before,
        }),
    )?;
    let barrier_state = json!({
        "root": barrier.root,
        "arm": barrier.arm,
        "arm_bytes": barrier.arm_bytes.len(),
        "arm_sha256": sha256(&barrier.arm_bytes),
        "ready": barrier.ready,
        "ready_bytes": barrier.ready_bytes.len(),
        "ready_sha256": barrier.ready_sha256,
        "worker_waits_for_ack": true,
        "source_order": "shadow_import.rs: complete Slot/Compression binding -> drop source lease -> durable ready -> wait for ack -> first bound Slot materialization",
        "target_binding": barrier.target_binding,
    });
    let before = json!({
        "snapshot_seq": before_seq,
        "slot": STAGED_ABORT_SLOT,
        "slot_cf": slot_cf.name(),
        "slot_cf_generation": slot_generation_before,
        "compression_cf_generation": compression_generation_before,
        "compression_manifest_present": false,
        "generation_semantics": "reopened latest-only conservative floor; not the production operation binding",
        "production_binding": {
            "slot_cf_generation": production_slot_generation,
            "compression_cf_generation": production_compression_generation,
        },
        "row": {
            "cx_id": cx_id.to_string(),
            "key_hex": hex_lower(&row_key),
            "bytes": row_bytes.len(),
            "sha256": sha256(&row_bytes),
            "decoded": staged_abort_vector_state(&decoded),
        },
        "storage": storage_before,
        "barrier": barrier_state,
    });
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"staged_slot_generation_mutation",
            "phase":"before",
            "state":before,
        }))?
    );
    require(
        !call_done.load(Ordering::Acquire),
        "ISSUE_1147_STAGED_ABORT_MUTATION_WINDOW_MISSED",
        "index_repository completed while its durable post-binding barrier was still awaiting ack; no late mutation is authorized and no retry is performed",
    )?;
    let mutation_payload = serde_json::to_vec(&json!({
        "schema": "astrolabe.issue-1147.staged-slot-generation-mutation.v1",
        "project": project,
        "generation": transaction.generation,
        "generation_observed_at_ms": GENERATION_OBSERVED_AT_MS,
        "slot": STAGED_ABORT_SLOT,
        "cx_id": cx_id.to_string(),
        "barrier_ready_sha256": barrier.ready_sha256,
        "journal_sha256": sha256(&transaction.journal_bytes),
        "before_snapshot_seq": before_seq,
        "before_slot_cf_generation": slot_generation_before,
        "before_compression_cf_generation": compression_generation_before,
        "production_binding_slot_cf_generation": production_slot_generation,
        "production_binding_compression_cf_generation": production_compression_generation,
        "row_bytes": row_bytes.len(),
        "row_sha256": sha256(&row_bytes),
        "byte_identical_rewrite": true,
        "purpose": "mutate the first real cold-loaded Slot CF generation after Weave captured every operation binding and before any source read or derived write",
    }))?;
    let subject = SubjectId::Cx(cx_id);
    let commit = vault.write_cf_batch_with_ledger_entry_with_row_digests(
        [(slot_cf, row_key.clone(), row_bytes.clone())],
        EntryKind::Admin,
        subject.clone(),
        mutation_payload.clone(),
        ActorId::Service(STAGED_ABORT_ACTOR.to_string()),
    )?;
    require(
        commit.data_row_digests.len() == 1
            && commit.data_row_digests[0].cf == slot_cf
            && commit.data_row_digests[0].key == row_key
            && commit.data_row_digests[0].value_blake3 == *blake3::hash(&row_bytes).as_bytes()
            && !commit.data_row_digests[0].tombstoned,
        "ISSUE_1147_STAGED_ABORT_COMMIT_RECEIPT_INVALID",
        format!("{commit:#?}"),
    )?;
    let after_seq = vault.latest_seq();
    let row_after = vault
        .read_cf_at(after_seq, slot_cf, &row_key)?
        .ok_or("ISSUE_1147_STAGED_ABORT_SLOT_ROW_MISSING_AFTER")?;
    let decoded_after = decode_strict_raw_slot_value(slot, cx_id, &row_after)?;
    let slot_generation_after = vault.cf_content_generation(slot_cf)?;
    let compression_generation_after = vault.cf_content_generation(ColumnFamily::Compression)?;
    let compression_manifest_after =
        vault.read_cf_at(after_seq, ColumnFamily::Compression, &compression_key)?;
    let storage_after = vault.latest_only_readback_status();
    let (ledger_bytes, ledger) =
        staged_abort_physical_ledger(&vault, &commit.ledger_ref, &subject, &mutation_payload)?;
    let wal_commit_inventory = staged_abort_wal_commit_inventory(
        &vault,
        commit.seq,
        slot_cf,
        &row_key,
        &row_bytes,
        &commit.ledger_ref,
        &ledger_bytes,
    )?;
    let ledger_head = calyx_aster::ledger_head::read_head_anchor(&vault_path)?
        .ok_or("ISSUE_1147_STAGED_ABORT_LEDGER_HEAD_MISSING")?;
    require(
        commit.seq
            == before_seq
                .checked_add(1)
                .ok_or("ISSUE_1147_STAGED_ABORT_MUTATION_SEQUENCE_OVERFLOW")?
            && after_seq == commit.seq
            && slot_generation_after == commit.seq
            && slot_generation_after > slot_generation_before
            && compression_generation_after == compression_generation_before
            && compression_manifest_after.is_none()
            && row_after == row_bytes
            && decoded_after == decoded
            && ledger_head.height >= commit.ledger_ref.seq
            && storage_after.latest_only
            && storage_after.overlay_keys == 0
            && storage_after.overlay_versions == 0
            && storage_after.overlay_bytes == 0,
        "ISSUE_1147_STAGED_ABORT_SOURCE_POSTSTATE_INVALID",
        json!({
            "before": before,
            "commit_seq": commit.seq,
            "after_seq": after_seq,
            "slot_generation_after": slot_generation_after,
            "compression_generation_after": compression_generation_after,
            "compression_manifest_present": compression_manifest_after.is_some(),
            "row_after_sha256": sha256(&row_after),
            "decoded_after": staged_abort_vector_state(&decoded_after),
            "ledger_head": ledger_head,
            "storage_after": storage_after,
        }),
    )?;
    let after = json!({
        "snapshot_seq": after_seq,
        "mutation_commit_seq": commit.seq,
        "slot": STAGED_ABORT_SLOT,
        "slot_cf": slot_cf.name(),
        "slot_cf_generation": slot_generation_after,
        "compression_cf_generation": compression_generation_after,
        "compression_manifest_present": false,
        "row": {
            "cx_id": cx_id.to_string(),
            "key_hex": hex_lower(&row_key),
            "bytes": row_after.len(),
            "sha256": sha256(&row_after),
            "decoded": staged_abort_vector_state(&decoded_after),
            "byte_identical_to_before": row_after == row_bytes,
        },
        "storage": storage_after,
        "ledger": ledger,
        "ledger_head": ledger_head,
        "physical_wal_commit_inventory": wal_commit_inventory,
    });
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"staged_slot_generation_mutation",
            "phase":"after",
            "state":after,
        }))?
    );
    let mutation_payload_sha256 = sha256(&mutation_payload);
    let data_row_blake3 = hex_lower(&commit.data_row_digests[0].value_blake3);
    let mut receipt = json!({
        "schema": "astrolabe.issue-1147.staged-slot-generation-mutation-receipt.v1",
        "generation": transaction.generation,
        "generation_dir": transaction.generation_dir,
        "stage_cache": transaction.stage_cache,
        "vault_path": vault_path,
        "journal": transaction.journal,
        "journal_bytes": transaction.journal_bytes.len(),
        "journal_sha256": sha256(&transaction.journal_bytes),
        "barrier": {
            "ready": barrier_state,
        },
        "before": before,
        "after": after,
        "payload": serde_json::from_slice::<Value>(&mutation_payload)?,
        "payload_bytes": mutation_payload.len(),
        "payload_sha256": mutation_payload_sha256,
        "ledger_ref": commit.ledger_ref,
        "commit_seq": commit.seq,
        "data_row_blake3": data_row_blake3,
        "byte_identical_write_generation_advanced": true,
    });
    let persisted_receipt_bytes = serde_json::to_vec(&receipt)?;
    drop(vault);
    let persisted_receipt = write_new_atomic_readback(
        &barrier.root.join("mutation-receipt.json"),
        &persisted_receipt_bytes,
    )?;
    let barrier_ack = staged_abort_write_barrier_ack(StagedAbortBarrierAckRequest {
        barrier,
        transaction,
        vault_path: &vault_path,
        project,
        commit_seq: commit.seq,
        ledger_ref: &commit.ledger_ref,
        mutation_payload_sha256: &mutation_payload_sha256,
        mutation_receipt: &persisted_receipt,
        data_key: &row_key,
        data_value: &row_bytes,
        data_row_blake3: &data_row_blake3,
    })?;
    receipt["barrier"]["mutation_receipt"] = persisted_receipt;
    receipt["barrier"]["ack"] = barrier_ack;
    Ok(receipt)
}

fn staged_abort_mutate_source(
    barrier_root: &Path,
    cache: &Path,
    project: &str,
    call_done: &AtomicBool,
) -> AnyResult<Value> {
    let (transaction, barrier) =
        staged_abort_wait_for_ready(barrier_root, cache, project, call_done)?;
    match staged_abort_mutate_source_after_ready(&transaction, &barrier, project, call_done) {
        Ok(receipt) => Ok(receipt),
        Err(error) => {
            let primary = error.to_string();
            let failure_ack =
                staged_abort_write_barrier_failure_ack(&barrier, &transaction, project, &primary);
            match failure_ack {
                Ok(ack) => Err(format!(
                    "{primary}; failure_ack_bytes={} failure_ack_sha256={}",
                    ack["physical"]["bytes"], ack["physical"]["sha256"],
                )
                .into()),
                Err(ack_error) => Err(format!(
                    "{primary}; ISSUE_1147_STAGED_ABORT_FAILURE_ACK_FAILED: {ack_error}"
                )
                .into()),
            }
        }
    }
}

fn staged_abort_barrier_readback(
    root: &Path,
    project: &str,
    arm_receipt: &Value,
    mutation: &Value,
) -> AnyResult<Value> {
    let root_metadata = fs::symlink_metadata(root)?;
    require(
        root.is_absolute()
            && root_metadata.is_dir()
            && root_metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1147_STAGED_ABORT_BARRIER_ROOT_INVALID",
        root.display(),
    )?;
    let mut names = fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    let expected_names = vec![
        "ack.json".to_string(),
        "arm.json".to_string(),
        "mutation-receipt.json".to_string(),
        "ready.json".to_string(),
    ];
    require(
        names == expected_names,
        "ISSUE_1147_STAGED_ABORT_BARRIER_INVENTORY_MISMATCH",
        json!({"root":root,"names":names}),
    )?;
    let read = |name: &str| -> AnyResult<(Vec<u8>, Value)> {
        let path = root.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        require(
            metadata.is_file()
                && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0
                && !PathBuf::from(format!("{}.pending", path.display())).try_exists()?,
            "ISSUE_1147_STAGED_ABORT_BARRIER_FILE_INVALID",
            path.display(),
        )?;
        let bytes = fs::read(&path)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        require(
            value.is_object(),
            "ISSUE_1147_STAGED_ABORT_BARRIER_FILE_NOT_OBJECT",
            path.display(),
        )?;
        Ok((bytes, value))
    };
    let (arm_bytes, arm) = read("arm.json")?;
    let (ready_bytes, ready) = read("ready.json")?;
    let (mutation_bytes, mutation_file) = read("mutation-receipt.json")?;
    let (ack_bytes, ack) = read("ack.json")?;
    let mut expected_mutation_file = mutation.clone();
    let expected_barrier = expected_mutation_file["barrier"]
        .as_object_mut()
        .ok_or("ISSUE_1147_STAGED_ABORT_MUTATION_BARRIER_MISSING")?;
    expected_barrier.remove("mutation_receipt");
    expected_barrier.remove("ack");
    require(
        arm == arm_receipt["value"]
            && arm_receipt["physical"]["bytes"].as_u64() == u64::try_from(arm_bytes.len()).ok()
            && arm_receipt["physical"]["sha256"] == Value::String(sha256(&arm_bytes))
            && arm["schema"] == STAGED_ABORT_BARRIER_ARM_SCHEMA
            && arm["project"] == Value::String(project.to_string())
            && arm["barrier_root"] == json!(root)
            && ready == mutation["barrier"]["ready"]["ready"]
            && ready["schema"] == STAGED_ABORT_BARRIER_READY_SCHEMA
            && ready["barrier_id"] == arm["barrier_id"]
            && ready["project"] == arm["project"]
            && ready["arm_sha256"] == Value::String(sha256(&arm_bytes))
            && mutation["barrier"]["ready"]["ready_bytes"].as_u64()
                == u64::try_from(ready_bytes.len()).ok()
            && mutation["barrier"]["ready"]["ready_sha256"] == Value::String(sha256(&ready_bytes))
            && mutation_file == expected_mutation_file
            && mutation["barrier"]["mutation_receipt"]["bytes"].as_u64()
                == u64::try_from(mutation_bytes.len()).ok()
            && mutation["barrier"]["mutation_receipt"]["sha256"]
                == Value::String(sha256(&mutation_bytes))
            && ack == mutation["barrier"]["ack"]["value"]
            && mutation["barrier"]["ack"]["physical"]["bytes"].as_u64()
                == u64::try_from(ack_bytes.len()).ok()
            && mutation["barrier"]["ack"]["physical"]["sha256"]
                == Value::String(sha256(&ack_bytes))
            && ack["schema"] == STAGED_ABORT_BARRIER_ACK_SCHEMA
            && ack["barrier_id"] == arm["barrier_id"]
            && ack["project"] == arm["project"]
            && ack["ready_sha256"] == Value::String(sha256(&ready_bytes))
            && ack["status"] == "source_mutation_committed_and_handle_closed"
            && ack["publication_generation"] == ready["publication_generation"]
            && ack["stage_cache"] == ready["stage_cache"]
            && ack["vault_path"] == ready["vault_path"]
            && ack["slot"].as_u64() == Some(u64::from(STAGED_ABORT_SLOT))
            && ack["commit_seq"] == mutation_file["commit_seq"]
            && ack["ledger_ref"] == mutation_file["ledger_ref"]
            && ack["mutation_payload_sha256"] == mutation_file["payload_sha256"]
            && ack["mutation_receipt_bytes"].as_u64() == u64::try_from(mutation_bytes.len()).ok()
            && ack["mutation_receipt_sha256"] == Value::String(sha256(&mutation_bytes))
            && ack["data_key_hex"] == mutation_file["before"]["row"]["key_hex"]
            && ack["data_value_sha256"] == mutation_file["before"]["row"]["sha256"]
            && ack["data_row_blake3"] == mutation_file["data_row_blake3"]
            && ack["error_sha256"].is_null(),
        "ISSUE_1147_STAGED_ABORT_BARRIER_CROSS_LINK_MISMATCH",
        json!({
            "arm":arm,
            "ready":ready,
            "mutation_file":mutation_file,
            "ack":ack,
        }),
    )?;
    Ok(json!({
        "root": root,
        "inventory": names,
        "arm": {"bytes":arm_bytes.len(),"sha256":sha256(&arm_bytes),"value":arm},
        "ready": {"bytes":ready_bytes.len(),"sha256":sha256(&ready_bytes),"value":ready},
        "mutation_receipt": {"bytes":mutation_bytes.len(),"sha256":sha256(&mutation_bytes),"value":mutation_file},
        "ack": {"bytes":ack_bytes.len(),"sha256":sha256(&ack_bytes),"value":ack},
        "pending_files_absent": true,
        "all_cross_links_verified": true,
    }))
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedAbortFingerprint {
    schema: String,
    project: String,
    admission_identity_sha256: String,
    producer_executable_sha256: String,
    canonical_repo_path: String,
    git_history_state: astrolabe_anchors::archaeology::GitHistoryState,
    git_source_fingerprint: String,
    symbol_canonical_schema: String,
    panel_version: u32,
    publication_schema: String,
    generation_clock_contract: String,
    generation_observed_at_ms: u64,
}

fn staged_abort_collect_inventory(
    root: &Path,
    current: &Path,
    files: &mut Vec<Value>,
) -> AnyResult<()> {
    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        require(
            metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
            "ISSUE_1147_PRESERVED_INVENTORY_REPARSE_REFUSED",
            path.display(),
        )?;
        if metadata.is_dir() {
            staged_abort_collect_inventory(root, &path, files)?;
            continue;
        }
        require(
            metadata.is_file(),
            "ISSUE_1147_PRESERVED_INVENTORY_ENTRY_INVALID",
            path.display(),
        )?;
        let relative_path = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        if relative_path == "preserved-stage.json" {
            continue;
        }
        let (bytes, digest) = file_sha256(&path)?;
        files.push(json!({
            "relative_path": relative_path,
            "bytes": bytes,
            "sha256": digest,
        }));
    }
    Ok(())
}

fn staged_abort_preserved_inventory(root: &Path) -> AnyResult<Value> {
    let metadata = fs::symlink_metadata(root)?;
    require(
        metadata.is_dir() && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
        "ISSUE_1147_PRESERVED_ROOT_INVALID",
        root.display(),
    )?;
    let mut files = Vec::new();
    staged_abort_collect_inventory(root, root, &mut files)?;
    files.sort_by(|left, right| {
        left["relative_path"]
            .as_str()
            .cmp(&right["relative_path"].as_str())
    });
    let mut bytes = 0_u64;
    for entry in &files {
        bytes = bytes
            .checked_add(
                entry["bytes"]
                    .as_u64()
                    .ok_or("ISSUE_1147_PRESERVED_INVENTORY_BYTES_MISSING")?,
            )
            .ok_or("ISSUE_1147_PRESERVED_INVENTORY_BYTES_OVERFLOW")?;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"astrolabe.shadow-preserved-stage.inventory.v1\0");
    for entry in &files {
        let relative_path = entry["relative_path"]
            .as_str()
            .ok_or("ISSUE_1147_PRESERVED_INVENTORY_PATH_MISSING")?
            .as_bytes();
        let entry_bytes = entry["bytes"]
            .as_u64()
            .ok_or("ISSUE_1147_PRESERVED_INVENTORY_BYTES_MISSING")?;
        let digest = entry["sha256"]
            .as_str()
            .ok_or("ISSUE_1147_PRESERVED_INVENTORY_SHA_MISSING")?
            .as_bytes();
        hasher.update((relative_path.len() as u64).to_be_bytes());
        hasher.update(relative_path);
        hasher.update(entry_bytes.to_be_bytes());
        hasher.update((digest.len() as u64).to_be_bytes());
        hasher.update(digest);
    }
    Ok(json!({
        "schema": STAGED_ABORT_PRESERVED_INVENTORY_SCHEMA,
        "files": files,
        "file_count": files.len(),
        "bytes": bytes,
        "sha256": hex_lower(&hasher.finalize()),
    }))
}

fn staged_abort_sqlite_source_state(path: &Path, project: &str) -> AnyResult<Value> {
    let family = transition_family_evidence(path)?;
    let journal = optional_file_state(&sqlite_family_member_path(path, "-journal"))?;
    require(
        family["db"]["present"] == Value::Bool(true)
            && family["wal"]["present"] == Value::Bool(false)
            && family["shm"]["present"] == Value::Bool(false)
            && journal["exists"] == Value::Bool(false),
        "ISSUE_1147_PRESERVED_SQLITE_FAMILY_NOT_QUIESCENT",
        json!({"family":family,"journal":journal}),
    )?;
    let connection = immutable_sqlite(path)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let nodes: i64 = connection.query_row("SELECT COUNT(*) FROM nodes", [], |row| row.get(0))?;
    let edges: i64 = connection.query_row("SELECT COUNT(*) FROM edges", [], |row| row.get(0))?;
    let delta_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM nodes WHERE project = ?1 AND name = 'staged_abort_only_delta'",
        [project],
        |row| row.get(0),
    )?;
    drop(connection);
    require(
        integrity == "ok" && nodes > 0 && edges >= 0 && delta_count == 1,
        "ISSUE_1147_PRESERVED_SQLITE_CONTENT_MISMATCH",
        json!({
            "integrity": integrity,
            "nodes": nodes,
            "edges": edges,
            "staged_abort_only_delta": delta_count,
        }),
    )?;
    Ok(json!({
        "family": family,
        "journal": journal,
        "immutable_query_only": true,
        "integrity": integrity,
        "nodes": u64::try_from(nodes)?,
        "edges": u64::try_from(edges)?,
        "staged_abort_only_delta": u64::try_from(delta_count)?,
    }))
}

fn staged_abort_validate_preserved_manifest(
    root: &Path,
    repo: &Path,
    project: &str,
    fault: &Value,
    mutation: &Value,
) -> AnyResult<Value> {
    let manifest_path = root.join("preserved-stage.json");
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(
        |error| -> Box<dyn Error + Send + Sync> {
            format!(
                "ISSUE_1147_PRESERVED_MANIFEST_INVALID: path={} bytes={} sha256={} parse_error={error}; remediation: preserve the slot and inspect its exact producer",
                manifest_path.display(),
                manifest_bytes.len(),
                sha256(&manifest_bytes),
            )
            .into()
        },
    )?;
    let inventory = staged_abort_preserved_inventory(root)?;
    let evidence = &fault["stage_preservation"]["evidence"];
    let fingerprint: StagedAbortFingerprint =
        serde_json::from_value(manifest["fingerprint"].clone())?;
    let fingerprint_bytes = serde_json::to_vec(&fingerprint)?;
    let mut fingerprint_hasher = Sha256::new();
    fingerprint_hasher.update(b"astrolabe.shadow-preserved-stage.fingerprint.v3\0");
    fingerprint_hasher.update((fingerprint_bytes.len() as u64).to_be_bytes());
    fingerprint_hasher.update(&fingerprint_bytes);
    let fingerprint_sha256 = hex_lower(&fingerprint_hasher.finalize());
    let source_file = manifest["source_file"]
        .as_str()
        .ok_or("ISSUE_1147_PRESERVED_SOURCE_FILE_MISSING")?;
    let source_path = root.join(source_file);
    let (source_bytes, source_sha256) = file_sha256(&source_path)?;
    let index_tool_result = manifest["index_tool_result"]
        .as_str()
        .ok_or("ISSUE_1147_PRESERVED_INDEX_RESULT_MISSING")?;
    let canonical_repo = repo.canonicalize()?;
    require(
        manifest["schema"] == STAGED_ABORT_PRESERVED_SCHEMA
            && manifest["project"] == Value::String(project.to_string())
            && manifest["generation"] == mutation["generation"]
            && manifest["preserved_at_unix_nanos"]
                .as_u64()
                .is_some_and(|value| value > 0)
            && manifest["owner_pid"] == mutation["journal"]["owner"]["pid"]
            && manifest["owner_process_start_utc_ticks"]
                == mutation["journal"]["owner"]["process_start_utc_ticks"]
            && manifest["abort_phase"] == "staged build"
            && manifest["abort_error"] == fault["underlying_error"]
            && fingerprint.schema == "astrolabe.shadow-preserved-stage.fingerprint.v3"
            && fingerprint.project == project
            && Path::new(&fingerprint.canonical_repo_path) == canonical_repo
            && fingerprint.generation_clock_contract == "astrolabe.generation-clock.utc-seconds.v1"
            && fingerprint.generation_observed_at_ms == GENERATION_OBSERVED_AT_MS
            && fingerprint_sha256 == manifest["fingerprint_sha256"]
            && source_file == format!("{project}.db")
            && manifest["source_bytes"].as_u64() == Some(source_bytes)
            && manifest["source_sha256"] == Value::String(source_sha256.clone())
            && manifest["stage_inventory"] == inventory
            && manifest["index_tool_result_sha256"]
                == Value::String(sha256(index_tool_result.as_bytes()))
            && manifest["superseded_generation"].is_null()
            && manifest["retention"] == 1
            && fault["stage_preservation"]["status"] == "preserved"
            && evidence["schema"] == "astrolabe.shadow-preserved-stage-evidence.v2"
            && evidence["preserved_stage_dir"] == json!(root)
            && evidence["source_path"] == json!(source_path)
            && evidence["source_bytes"].as_u64() == Some(source_bytes)
            && evidence["source_sha256"] == Value::String(source_sha256.clone())
            && evidence["stage_file_count"] == inventory["file_count"]
            && evidence["stage_bytes"] == inventory["bytes"]
            && evidence["stage_sha256"] == inventory["sha256"]
            && evidence["manifest_path"] == json!(manifest_path)
            && evidence["manifest_bytes"].as_u64() == u64::try_from(manifest_bytes.len()).ok()
            && evidence["manifest_sha256"] == Value::String(sha256(&manifest_bytes))
            && evidence["config_path"] == json!(root.join("_config.db"))
            && evidence["config_present"] == Value::Bool(true)
            && evidence["signal_card_ledger_present"] == Value::Bool(true)
            && evidence["resume_token"] == Value::String(fingerprint_sha256.clone())
            && evidence["generation"] == mutation["generation"]
            && evidence["superseded_generation"].is_null()
            && evidence["abort_phase"] == "staged build"
            && evidence["retention"] == 1,
        "ISSUE_1147_PRESERVED_MANIFEST_MISMATCH",
        json!({
            "manifest": manifest,
            "inventory": inventory,
            "evidence": evidence,
            "fingerprint_sha256": fingerprint_sha256,
            "canonical_repo": canonical_repo,
            "source_bytes": source_bytes,
            "source_sha256": source_sha256,
        }),
    )?;
    let sqlite = staged_abort_sqlite_source_state(&source_path, project)?;
    Ok(json!({
        "root": root,
        "manifest_path": manifest_path,
        "manifest_bytes": manifest_bytes.len(),
        "manifest_sha256": sha256(&manifest_bytes),
        "manifest": manifest,
        "inventory": inventory,
        "fingerprint_bytes": fingerprint_bytes.len(),
        "fingerprint_sha256": fingerprint_sha256,
        "source_path": source_path,
        "source_bytes": source_bytes,
        "source_sha256": source_sha256,
        "sqlite": sqlite,
        "evidence_matches_physical_state": true,
    }))
}

fn staged_abort_preserved_vault_readback(
    preserved_root: &Path,
    project: &str,
    mutation: &Value,
) -> AnyResult<Value> {
    let vault_path = staged_abort_vault_path(preserved_root, project);
    let vault_id = STAGED_ABORT_SHADOW_VAULT_ID.parse::<VaultId>()?;
    let vault = AsterVault::open_with_clock(
        &vault_path,
        vault_id,
        format!("astrolabe-shadow-v1:{project}").into_bytes(),
        VaultOptions {
            read_only: true,
            restore_ledger_hook: false,
            restore_mvcc_rows: false,
            selected_cfs: Some(vec![
                ColumnFamily::slot(SlotId::new(STAGED_ABORT_SLOT)),
                ColumnFamily::Compression,
                ColumnFamily::Ledger,
                ColumnFamily::TimeIndex,
            ]),
            ..VaultOptions::default()
        },
        FixedClock::new(GENERATION_OBSERVED_AT_MS),
    )?;
    let slot = SlotId::new(STAGED_ABORT_SLOT);
    let slot_cf = ColumnFamily::slot(slot);
    let snapshot = vault.latest_seq();
    let rows = vault.scan_cf_range_page_at(
        snapshot,
        slot_cf,
        &KeyRange {
            start: Vec::new(),
            end: None,
        },
        None,
        1,
    )?;
    require(
        rows.len() == 1 && rows[0].0.len() == 16,
        "ISSUE_1147_PRESERVED_SLOT_PAGE_INVALID",
        rows.len(),
    )?;
    let expected_key = decode_hex(
        mutation["before"]["row"]["key_hex"]
            .as_str()
            .ok_or("ISSUE_1147_MUTATION_KEY_MISSING")?,
    )?;
    let expected_row_sha256 = mutation["before"]["row"]["sha256"]
        .as_str()
        .ok_or("ISSUE_1147_MUTATION_ROW_SHA_MISSING")?;
    let (row_key, row_bytes) = &rows[0];
    let cx_id = CxId::from_bytes(<[u8; 16]>::try_from(row_key.as_slice())?);
    let decoded = decode_strict_raw_slot_value(slot, cx_id, row_bytes)?;
    let compression_key = compression_manifest_key(slot);
    let compression_manifest =
        vault.read_cf_at(snapshot, ColumnFamily::Compression, &compression_key)?;
    let slot_generation = vault.cf_content_generation(slot_cf)?;
    let compression_generation = vault.cf_content_generation(ColumnFamily::Compression)?;
    let expected_slot_generation = mutation["after"]["slot_cf_generation"]
        .as_u64()
        .ok_or("ISSUE_1147_MUTATION_AFTER_SLOT_GENERATION_MISSING")?;
    let expected_compression_generation = mutation["before"]["compression_cf_generation"]
        .as_u64()
        .ok_or("ISSUE_1147_MUTATION_BEFORE_COMPRESSION_GENERATION_MISSING")?;
    let storage = vault.latest_only_readback_status();
    let ledger_ref: LedgerRef = serde_json::from_value(mutation["ledger_ref"].clone())?;
    let mutation_commit_seq = mutation["commit_seq"]
        .as_u64()
        .ok_or("ISSUE_1147_MUTATION_COMMIT_SEQ_MISSING")?;
    let mut time_index_key = Vec::with_capacity(16);
    time_index_key.extend_from_slice(&GENERATION_OBSERVED_AT_MS.to_be_bytes());
    time_index_key.extend_from_slice(&mutation_commit_seq.to_be_bytes());
    let time_index_value = vault
        .read_cf_at(snapshot, ColumnFamily::TimeIndex, &time_index_key)?
        .ok_or("ISSUE_1147_PRESERVED_TIME_INDEX_ROW_MISSING")?;
    let mutation_payload = serde_json::to_vec(&mutation["payload"])?;
    require(
        mutation["payload_bytes"].as_u64() == u64::try_from(mutation_payload.len()).ok()
            && mutation["payload_sha256"] == Value::String(sha256(&mutation_payload)),
        "ISSUE_1147_MUTATION_PAYLOAD_RECEIPT_MISMATCH",
        &mutation["payload"],
    )?;
    let subject = SubjectId::Cx(cx_id);
    let (ledger_bytes, physical_ledger) =
        staged_abort_physical_ledger(&vault, &ledger_ref, &subject, &mutation_payload)?;
    let wal_commit_inventory = staged_abort_wal_commit_inventory(
        &vault,
        mutation_commit_seq,
        slot_cf,
        row_key,
        row_bytes,
        &ledger_ref,
        &ledger_bytes,
    )?;
    let (chain, head) = astrolabe_ingest::verify_chain_and_head(&vault)?;
    let head = head.ok_or("ISSUE_1147_PRESERVED_LEDGER_HEAD_MISSING")?;
    require(
        snapshot == mutation_commit_seq
            && row_key == &expected_key
            && sha256(row_bytes) == expected_row_sha256
            && staged_abort_vector_state(&decoded) == mutation["before"]["row"]["decoded"]
            && compression_manifest.is_none()
            && time_index_value == [0_u8]
            && slot_generation >= expected_slot_generation
            && slot_generation <= snapshot
            && mutation_commit_seq == expected_slot_generation
            && mutation["after"]["compression_cf_generation"].as_u64()
                == Some(expected_compression_generation)
            && compression_generation >= expected_compression_generation
            && compression_generation <= snapshot
            && storage.latest_only
            && storage.overlay_keys == 0
            && storage.overlay_versions == 0
            && storage.overlay_bytes == 0
            && chain.is_intact()
            && chain.count > 0
            && chain.checked_range_start <= ledger_ref.seq
            && chain.checked_range_end > ledger_ref.seq
            && head.height >= ledger_ref.seq,
        "ISSUE_1147_PRESERVED_VAULT_STATE_MISMATCH",
        json!({
            "snapshot": snapshot,
            "row_key_hex": hex_lower(row_key),
            "row_sha256": sha256(row_bytes),
            "decoded": staged_abort_vector_state(&decoded),
            "compression_manifest_present": compression_manifest.is_some(),
            "time_index_key_hex": hex_lower(&time_index_key),
            "time_index_value_hex": hex_lower(&time_index_value),
            "slot_generation": slot_generation,
            "expected_slot_generation": expected_slot_generation,
            "mutation_commit_seq": mutation["commit_seq"],
            "slot_generation_is_conservative_reopen_floor": true,
            "compression_generation": compression_generation,
            "expected_compression_generation": expected_compression_generation,
            "compression_generation_is_conservative_reopen_floor": true,
            "storage": storage,
            "ledger_ref": ledger_ref,
            "chain": chain,
            "head": head,
            "wal_commit_inventory": wal_commit_inventory,
        }),
    )?;
    require(
        wal_commit_inventory == mutation["after"]["physical_wal_commit_inventory"],
        "ISSUE_1147_PRESERVED_WAL_INVENTORY_MISMATCH",
        json!({
            "reopened": wal_commit_inventory,
            "execute": mutation["after"]["physical_wal_commit_inventory"],
        }),
    )?;
    drop(vault);
    Ok(json!({
        "vault_path": vault_path,
        "selected_cfs": [slot_cf.name(), ColumnFamily::Compression.name(), ColumnFamily::Ledger.name(), ColumnFamily::TimeIndex.name()],
        "snapshot_seq": snapshot,
        "slot": STAGED_ABORT_SLOT,
        "slot_cf_generation": slot_generation,
        "slot_generation_semantics": {
            "same_handle_before": mutation["before"]["slot_cf_generation"],
            "same_handle_after": mutation["after"]["slot_cf_generation"],
            "mutation_commit_seq": mutation["commit_seq"],
            "reopened_conservative_floor": slot_generation,
            "exact_row_hash_reopened": sha256(row_bytes),
            "physical_mutation_ledger_reopened": true,
        },
        "compression_cf_generation": compression_generation,
        "compression_generation_semantics": {
            "same_handle_before": mutation["before"]["compression_cf_generation"],
            "same_handle_after": mutation["after"]["compression_cf_generation"],
            "reopened_conservative_floor": compression_generation,
            "manifest_absent_before": mutation["before"]["compression_manifest_present"] == Value::Bool(false),
            "manifest_absent_after": mutation["after"]["compression_manifest_present"] == Value::Bool(false),
            "manifest_absent_reopened": true,
        },
        "compression_manifest_present": false,
        "row": {
            "cx_id": cx_id.to_string(),
            "key_hex": hex_lower(row_key),
            "bytes": row_bytes.len(),
            "sha256": sha256(row_bytes),
            "decoded": staged_abort_vector_state(&decoded),
        },
        "storage": storage,
        "physical_ledger": physical_ledger,
        "physical_wal_commit_inventory": wal_commit_inventory,
        "physical_time_index": {
            "key_hex": hex_lower(&time_index_key),
            "value_bytes": time_index_value.len(),
            "value_sha256": sha256(&time_index_value),
            "exact_zero_sentinel": true,
        },
        "chain": chain,
        "head": head,
        "mutation_ref_in_verified_chain": true,
    }))
}

struct StagedAbortBindingFault {
    expected_seq: u64,
    observed_seq: u64,
    expected_slot_generation: u64,
    observed_slot_generation: u64,
    expected_compression_generation: u64,
    observed_compression_generation: u64,
}

fn staged_abort_binding_fault(message: &str) -> AnyResult<StagedAbortBindingFault> {
    let prefix = format!("S{STAGED_ABORT_SLOT} binding changed before read: ");
    let fields = message
        .strip_prefix(&prefix)
        .ok_or("ISSUE_1147_BINDING_FAULT_PREFIX_MISMATCH")?
        .split(", ")
        .collect::<Vec<_>>();
    require(
        fields.len() == 6,
        "ISSUE_1147_BINDING_FAULT_FIELD_COUNT_MISMATCH",
        message,
    )?;
    let field = |index: usize, name: &str| -> AnyResult<u64> {
        Ok(fields[index]
            .strip_prefix(&format!("{name}="))
            .ok_or("ISSUE_1147_BINDING_FAULT_FIELD_NAME_MISMATCH")?
            .parse::<u64>()?)
    };
    Ok(StagedAbortBindingFault {
        expected_seq: field(0, "expected_seq")?,
        observed_seq: field(1, "observed_seq")?,
        expected_slot_generation: field(2, "expected_slot_generation")?,
        observed_slot_generation: field(3, "observed_slot_generation")?,
        expected_compression_generation: field(4, "expected_compression_generation")?,
        observed_compression_generation: field(5, "observed_compression_generation")?,
    })
}

fn staged_abort_validate_fault(
    envelope: &Value,
    fault: &Value,
    project: &str,
    mutation: &Value,
) -> AnyResult<Value> {
    let underlying_message = fault["underlying_fault"]["message"]
        .as_str()
        .ok_or("ISSUE_1147_BINDING_FAULT_MESSAGE_MISSING")?;
    let binding_fault = staged_abort_binding_fault(underlying_message)?;
    let ready_binding = &mutation["barrier"]["ready"]["target_binding"];
    let expected_slot_generation = ready_binding["slot_cf_generation"]
        .as_u64()
        .ok_or("ISSUE_1147_READY_SLOT_GENERATION_MISSING")?;
    let expected_compression_generation = ready_binding["compression_cf_generation"]
        .as_u64()
        .ok_or("ISSUE_1147_READY_COMPRESSION_GENERATION_MISSING")?;
    let mutation_commit_seq = mutation["commit_seq"]
        .as_u64()
        .ok_or("ISSUE_1147_MUTATION_COMMIT_SEQ_MISSING")?;
    let underlying_error = format!("ASTRO_WEAVE_SLOT_BINDING_CHANGED: {underlying_message}");
    let expected_outer_message = format!(
        "shadow publication for project {project:?} failed during staged build: {underlying_error}; the prior live generation was not committed"
    );
    let outer_remediation = "fix the named underlying error, inspect the preserved-stage evidence, and rerun index_repository with calyx=\"shadow\"; never publish or substitute a partial generation";
    let inner_remediation = "preserve the staged generation and identify the exact Slot or Compression writer; recapture the complete source generation before any derived write instead of retrying a historical sequence or changing representation";
    require(
        envelope["isError"] == Value::Bool(true)
            && envelope["content"][0]["type"] == "text"
            && envelope["content"][0]["text"] == serde_json::to_string(fault)?
            && envelope["structuredContent"] == *fault
            && fault["schema"] == STAGED_ABORT_TOOL_FAULT_SCHEMA
            && fault["status"] == "error"
            && fault["code"] == "ASTRO_SHADOW_PUBLICATION_ABORTED"
            && fault["message"] == Value::String(expected_outer_message.clone())
            && fault["remediation"] == outer_remediation
            && fault["project"] == Value::String(project.to_string())
            && fault["failed_phase"] == "staged build"
            && fault["underlying_error"] == Value::String(underlying_error.clone())
            && fault["underlying_code"] == "ASTRO_WEAVE_SLOT_BINDING_CHANGED"
            && fault["underlying_fault"]["schema"] == STAGED_ABORT_TOOL_FAULT_SCHEMA
            && fault["underlying_fault"]["status"] == "error"
            && fault["underlying_fault"]["code"] == "ASTRO_WEAVE_SLOT_BINDING_CHANGED"
            && fault["underlying_fault"]["remediation"] == inner_remediation
            && ready_binding["slot"].as_u64() == Some(u64::from(STAGED_ABORT_SLOT))
            && binding_fault.expected_seq == mutation_commit_seq
            && binding_fault.observed_seq == mutation_commit_seq
            && binding_fault.expected_slot_generation == expected_slot_generation
            && binding_fault.observed_slot_generation == mutation_commit_seq
            && binding_fault.expected_compression_generation == expected_compression_generation
            && binding_fault.observed_compression_generation == expected_compression_generation,
        "ISSUE_1147_STRUCTURED_ABORT_FAULT_MISMATCH",
        json!({
            "envelope": envelope,
            "fault": fault,
            "expected_outer_message": expected_outer_message,
            "expected_underlying_error": underlying_error,
            "underlying_message": underlying_message,
            "ready_binding": ready_binding,
            "mutation_commit_seq": mutation_commit_seq,
        }),
    )?;
    Ok(json!({
        "outer_code": "ASTRO_SHADOW_PUBLICATION_ABORTED",
        "outer_message": expected_outer_message,
        "outer_remediation": outer_remediation,
        "failed_phase": "staged build",
        "underlying_code": "ASTRO_WEAVE_SLOT_BINDING_CHANGED",
        "underlying_error": underlying_error,
        "underlying_message": underlying_message,
        "binding_observation": {
            "expected_seq": binding_fault.expected_seq,
            "observed_seq": binding_fault.observed_seq,
            "expected_slot_generation": binding_fault.expected_slot_generation,
            "observed_slot_generation": binding_fault.observed_slot_generation,
            "expected_compression_generation": binding_fault.expected_compression_generation,
            "observed_compression_generation": binding_fault.observed_compression_generation,
        },
        "underlying_remediation": inner_remediation,
        "text_structured_exact_mirror": true,
        "text_bytes": envelope["content"][0]["text"].as_str().map(str::len),
        "text_sha256": envelope["content"][0]["text"].as_str().map(|text| sha256(text.as_bytes())),
    }))
}

struct StagedAbortFailedTransitionRequest<'a> {
    cache: &'a Path,
    project: &'a str,
    canonical_repo: &'a Path,
    canonical_db: &'a Path,
    envelope: &'a Value,
    response_raw: &'a str,
    binding: &'a CbmVerifiedWorkerBinding,
    expected_family: &'a Value,
}

fn staged_abort_failed_transition(
    request: StagedAbortFailedTransitionRequest<'_>,
) -> AnyResult<Value> {
    let StagedAbortFailedTransitionRequest {
        cache,
        project,
        canonical_repo,
        canonical_db,
        envelope,
        response_raw,
        binding,
        expected_family,
    } = request;
    let (integrity, rows) = config_rows(cache, project)?;
    let key = format!("astrolabe.calyx.{project}.project_transition_json");
    let raw = rows
        .get(&key)
        .ok_or("ISSUE_1147_FAILED_TRANSITION_MISSING")?
        .clone();
    let transition: Value = serde_json::from_str(&raw)?;
    let response_sha256 = sha256(&serde_json::to_vec(envelope)?);
    let raw_response_sha256 = transition["evidence"]["raw_response_sha256"]
        .as_str()
        .ok_or("ISSUE_1147_FAILED_TRANSITION_RAW_RESPONSE_SHA_MISSING")?;
    let expected_raw_response_sha256 = sha256(response_raw.as_bytes());
    let (owner_pid, owner_process_start_utc_ticks) = capability_owner_identity(binding)?;
    let generation = transition["generation"]
        .as_str()
        .ok_or("ISSUE_1147_FAILED_TRANSITION_GENERATION_MISSING")?;
    let generation_valid = generation.len() == 64
        && generation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let current_family = transition_family_evidence(canonical_db)?;
    require(
        integrity == "ok"
            && generation_valid
            && transition["schema"] == "astrolabe-project-transition-v1"
            && transition["phase"] == "terminal"
            && transition["project"] == Value::String(project.to_string())
            && transition["canonical_root"] == json!(canonical_repo)
            && transition["canonical_db_path"] == json!(canonical_db)
            && transition["owner"]["pid"].as_u64() == Some(u64::from(owner_pid))
            && transition["owner"]["process_start_utc_ticks"].as_u64()
                == Some(owner_process_start_utc_ticks)
            && transition["quiescence"]["holder_inventory_stable"] == Value::Bool(true)
            && transition["quiescence"]["holder_count"] == 0
            && transition["normalization"]["status"] == "normalized"
            && transition["normalization"]["after"] == *expected_family
            && transition["normalization"]["post_close_quiescence"]["holder_inventory_stable"]
                == Value::Bool(true)
            && transition["normalization"]["post_close_quiescence"]["holder_count"] == 0
            && transition["evidence"]["status"] == "failed"
            && transition["evidence"]["response_hash_basis"]
                == "astrolabe.persisted-json-compact.v1"
            && transition["evidence"]["response_sha256"] == Value::String(response_sha256.clone())
            && raw_response_sha256 == expected_raw_response_sha256
            && transition["evidence"]["sqlite_publication_started"].is_null()
            && transition["evidence"]["family_before"] == *expected_family
            && transition["evidence"]["family_after"] == *expected_family
            && current_family == *expected_family,
        "ISSUE_1147_FAILED_TRANSITION_MISMATCH",
        json!({
            "transition": transition,
            "expected_family": expected_family,
            "current_family": current_family,
            "response_sha256": response_sha256,
            "raw_response_sha256": raw_response_sha256,
            "expected_raw_response_sha256": expected_raw_response_sha256,
        }),
    )?;
    Ok(json!({
        "key": key,
        "raw": raw,
        "sha256": sha256(raw.as_bytes()),
        "transition": transition,
        "config_integrity": integrity,
        "config_row_count": rows.len(),
        "response_sha256": response_sha256,
        "raw_response_sha256": raw_response_sha256,
        "raw_response_bytes": response_raw.len(),
        "family_readback": current_family,
        "terminal_failed_generation_preserved": true,
    }))
}

fn staged_abort_complete_state(cache: &Path, repo: &Path, project: &str) -> AnyResult<Value> {
    let (integrity, rows) = config_rows(cache, project)?;
    let state = json!({
        "live_generation": staged_abort_live_generation_state(cache, project)?,
        "config_integrity": integrity,
        "config_rows": ordered_config_rows(&rows),
        "publication_root": tree_state(&staged_abort_project_root(cache, project))?,
        "preserved_root": tree_state(&staged_abort_preserved_root(cache, project))?,
        "fixture_source": fixture_source_state(repo)?,
        "cache_tree": tree_state(cache)?,
    });
    Ok(json!({
        "sha256": sha256(&serde_json::to_vec(&state)?),
        "state": state,
    }))
}

fn staged_abort_legacy_parser_edge(
    envelope: &Value,
    cache: &Path,
    repo: &Path,
    project: &str,
) -> AnyResult<Value> {
    let before = staged_abort_complete_state(cache, repo, project)?;
    let legacy_text = "ASTRO_SHADOW_PUBLICATION_ABORTED: legacy unstructured inner tool prose";
    let mut malformed_envelope = envelope.clone();
    malformed_envelope["content"][0]["text"] = Value::String(legacy_text.to_string());
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"legacy_inner_tool_prose",
            "phase":"before",
            "state":before,
            "input":malformed_envelope,
        }))?
    );
    let diagnostic = match parse_tool_text("index_repository", true, legacy_text) {
        Err(error) => error.to_string(),
        Ok(value) => {
            return Err(format!("ISSUE_1147_LEGACY_PROSE_UNEXPECTEDLY_PARSED: {value}").into());
        }
    };
    let prefix = legacy_text.chars().take(160).collect::<String>();
    require(
        diagnostic.contains("ISSUE_1116_1119_INNER_PAYLOAD_INVALID")
            && diagnostic.contains("tool=\"index_repository\"")
            && diagnostic.contains("isError=true")
            && diagnostic.contains(&format!("text_bytes={}", legacy_text.len()))
            && diagnostic.contains(&format!("text_sha256={}", sha256(legacy_text.as_bytes())))
            && diagnostic.contains(&format!("text_prefix={prefix:?}"))
            && diagnostic.contains("parse_error=")
            && diagnostic.contains("never treat malformed or legacy prose as success"),
        "ISSUE_1147_LEGACY_PROSE_DIAGNOSTIC_INCOMPLETE",
        &diagnostic,
    )?;
    let after = staged_abort_complete_state(cache, repo, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"legacy_inner_tool_prose",
            "phase":"after",
            "state":after,
            "diagnostic":diagnostic,
        }))?
    );
    require(
        before == after,
        "ISSUE_1147_LEGACY_PROSE_MUTATED_STATE",
        json!({"before":before,"after":after}),
    )?;
    Ok(json!({
        "input_envelope": malformed_envelope,
        "legacy_text": legacy_text,
        "legacy_text_bytes": legacy_text.len(),
        "legacy_text_sha256": sha256(legacy_text.as_bytes()),
        "diagnostic": diagnostic,
        "before": before,
        "after": after,
        "state_unchanged": true,
    }))
}

fn staged_abort(payload: PathBuf) -> AnyResult<()> {
    require(
        payload.is_absolute() && !payload.try_exists()?,
        "ISSUE_1147_STAGED_ABORT_PAYLOAD_PREEXISTS",
        payload.display(),
    )?;
    fs::create_dir_all(&payload)?;
    let barrier_root = payload.join("weave-binding-barrier");
    fs::create_dir(&barrier_root)?;
    // SAFETY: staged-abort sets its process-local manual-FSV control root before
    // any bridge/server initialization or thread creation. It is never changed
    // again; baseline remains deliberately unarmed until arm.json is published.
    unsafe {
        std::env::set_var(STAGED_ABORT_BARRIER_ENV, &barrier_root);
    }
    require(
        std::env::var_os(STAGED_ABORT_BARRIER_ENV).as_deref() == Some(barrier_root.as_os_str()),
        "ISSUE_1147_STAGED_ABORT_BARRIER_ENV_MISMATCH",
        barrier_root.display(),
    )?;
    let tree_sha = canonical_head()?;
    let driver_artifact = current_driver_artifact_state()?;
    let source_generation = current_source_generation_sha256()?;
    require(
        source_generation == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256,
        "ISSUE_1147_STAGED_ABORT_SOURCE_GENERATION_DRIFT",
        &source_generation,
    )?;
    let repo = payload.join("real-rust-repo");
    let cache = payload.join("real-cache");
    let fixture = write_fixture(&repo)?;
    fs::create_dir(&cache)?;
    let observed_cache = set_cbm_cache_dir(&cache)?;
    require(
        observed_cache == cache,
        "ISSUE_1147_STAGED_ABORT_CACHE_BINDING_MISMATCH",
        observed_cache.display(),
    )?;
    let (shipping_host, shipping_host_state) = shipping_astrolabe_executable()?;
    require(
        configured_cbm_host_binary_path()?.is_none() && !supervisor_should_wrap(),
        "ISSUE_1147_STAGED_ABORT_PROCESS_PRESTATE_INVALID",
        "a fresh staged-abort process already had a binary binding or supervisor role",
    )?;
    let shipping_sha256 = shipping_host_state["sha256"]
        .as_str()
        .ok_or("ISSUE_1147_STAGED_ABORT_SHIPPING_SHA_MISSING")?;
    let verified_worker = initialize_cbm_host_process_with_verified_worker(
        &shipping_host,
        shipping_sha256,
        &source_generation,
    )?;
    let worker_identity = validate_verified_worker_binding(&verified_worker, &shipping_host)?;
    require(
        configured_cbm_host_binary_path()?.as_deref() == Some(shipping_host.as_path())
            && supervisor_should_wrap(),
        "ISSUE_1147_STAGED_ABORT_SHIPPING_BINDING_MISMATCH",
        shipping_host.display(),
    )?;
    let transition_binding = verified_worker.clone();
    let worker_binding = json!({
        "configured": shipping_host_state,
        "verified_worker": verified_worker,
        "verified_worker_identity": worker_identity,
        "supervisor_should_wrap": supervisor_should_wrap(),
        "readback": configured_cbm_host_binary_path()?,
    });
    let runner = CbmToolRunner::new_default()?;
    let project = cbm_project_name_from_path(
        repo.to_str()
            .ok_or("ISSUE_1147_STAGED_ABORT_REPO_PATH_NOT_UTF8")?,
    )?;
    let publication_root = staged_abort_project_root(&cache, &project);
    let preserved_root = staged_abort_preserved_root(&cache, &project);
    let before = json!({
        "publication_root": tree_state(&publication_root)?,
        "preserved_root": tree_state(&preserved_root)?,
        "cache": tree_state(&cache)?,
        "barrier": tree_state(&barrier_root)?,
        "fixture_source": fixture_source_state(&repo)?,
    });
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"staged_abort_real_index",
            "phase":"before",
            "state":before,
        }))?
    );
    require(
        before["publication_root"]["exists"] == Value::Bool(false)
            && before["preserved_root"]["exists"] == Value::Bool(false)
            && before["barrier"]["file_count"] == 0,
        "ISSUE_1147_STAGED_ABORT_PRESTATE_NOT_PRISTINE",
        &before,
    )?;

    let (baseline_raw, baseline_envelope, baseline_response) =
        call_tool_with_raw(&runner, "index_repository", &index_request(&repo))?;
    require(
        baseline_envelope["isError"] != Value::Bool(true)
            && baseline_response["project"] == Value::String(project.clone()),
        "ISSUE_1147_STAGED_ABORT_BASELINE_INDEX_FAILED",
        &baseline_response,
    )?;
    let canonical_repo = repo.canonicalize()?;
    let canonical_db = cache.join(format!("{project}.db"));
    let baseline_transition_observation_path = payload.join("baseline-transition-observation.json");
    let baseline_transition = read_completed_transition(ReadCompletedTransitionRequest {
        cache: &cache,
        project: &project,
        canonical_root: &canonical_repo,
        canonical_db: &canonical_db,
        response_raw: &baseline_raw,
        response_envelope: &baseline_envelope,
        response_payload: &baseline_response,
        binding: &transition_binding,
        observation_path: Some(&baseline_transition_observation_path),
    })?;
    let (baseline_config_integrity, baseline_config) = config_rows(&cache, &project)?;
    let baseline_weave = verify_weave_generation_receipt(&baseline_config, &project)?;
    let baseline_live = staged_abort_live_generation_state(&cache, &project)?;
    require(
        baseline_config_integrity == "ok"
            && moderate_semantic_response_matches_sqlite(
                &baseline_response,
                &baseline_live["state"]["sqlite"],
            )
            && baseline_live["state"]["sqlite"]["staged_abort_only_delta"] == 0
            && staged_abort_symbol_count(&canonical_db, &project)? == 0
            && tree_state(&publication_root)?["exists"] == Value::Bool(false)
            && tree_state(&preserved_root)?["exists"] == Value::Bool(false),
        "ISSUE_1147_STAGED_ABORT_BASELINE_STATE_INVALID",
        json!({
            "config_integrity": baseline_config_integrity,
            "response_semantic": {
                "index_mode": baseline_response["index_mode"],
                "semantic_search": baseline_response["semantic_search"],
                "semantic_vector_readback": baseline_response["semantic_vector_readback"],
            },
            "baseline_live": baseline_live,
        }),
    )?;

    let source_delta = commit_staged_abort_delta(&repo)?;
    require(
        fixture_source_state(&repo)? == source_delta["after"],
        "ISSUE_1147_STAGED_ABORT_SOURCE_DELTA_NOT_PHYSICAL",
        &source_delta,
    )?;
    let barrier_arm = staged_abort_arm_barrier(&barrier_root, &payload, &project, &source_delta)?;
    let call_done = Arc::new(AtomicBool::new(false));
    let mutation_barrier = barrier_root.clone();
    let mutation_cache = cache.clone();
    let mutation_project = project.clone();
    let mutation_done = Arc::clone(&call_done);
    let (abort_call, mutation_join) = std::thread::scope(|scope| {
        let mutator = scope.spawn(move || {
            staged_abort_mutate_source(
                &mutation_barrier,
                &mutation_cache,
                &mutation_project,
                mutation_done.as_ref(),
            )
        });
        let call = call_tool_with_raw(&runner, "index_repository", &index_request(&repo));
        call_done.store(true, Ordering::Release);
        (call, mutator.join())
    });
    let mutation_result = mutation_join.map_err(|_| -> Box<dyn Error + Send + Sync> {
        "ISSUE_1147_STAGED_ABORT_MUTATOR_PANICKED: external marker-bound mutator panicked; remediation: preserve the payload and inspect the exact thread boundary"
            .into()
    })?;
    let mutation = mutation_result?;
    let (abort_raw, abort_envelope, abort_fault) = abort_call?;
    require(
        abort_envelope["isError"] == Value::Bool(true)
            && abort_fault["code"] == "ASTRO_SHADOW_PUBLICATION_ABORTED"
            && abort_fault["underlying_code"] == "ASTRO_WEAVE_SLOT_BINDING_CHANGED",
        "ISSUE_1147_STAGED_ABORT_UNEXPECTED_TOOL_OUTCOME",
        json!({"envelope":abort_envelope,"fault":abort_fault}),
    )?;
    let barrier_readback =
        staged_abort_barrier_readback(&barrier_root, &project, &barrier_arm, &mutation)?;
    let baseline_binding_slots = baseline_weave["slot_cf_generations"]
        .as_object()
        .ok_or("ISSUE_1147_BASELINE_BINDING_ROSTER_MISSING")?
        .keys()
        .map(|slot| -> AnyResult<u16> { Ok(slot.parse::<u16>()?) })
        .collect::<AnyResult<BTreeSet<_>>>()?;
    let ready_binding_slots = barrier_readback["ready"]["value"]["slot_bindings"]
        .as_array()
        .ok_or("ISSUE_1147_READY_BINDING_ROSTER_MISSING")?
        .iter()
        .map(|binding| -> AnyResult<u16> {
            let slot = binding["slot"]
                .as_u64()
                .ok_or("ISSUE_1147_READY_BINDING_SLOT_MISSING")?;
            Ok(u16::try_from(slot)?)
        })
        .collect::<AnyResult<BTreeSet<_>>>()?;
    require(
        !baseline_binding_slots.is_empty()
            && ready_binding_slots == baseline_binding_slots
            && ready_binding_slots.len()
                == barrier_readback["ready"]["value"]["slot_bindings"]
                    .as_array()
                    .map(Vec::len)
                    .unwrap_or(0),
        "ISSUE_1147_STAGED_ABORT_READY_ROSTER_MISMATCH",
        json!({
            "baseline": baseline_binding_slots,
            "ready": ready_binding_slots,
        }),
    )?;

    let live_after = staged_abort_live_generation_state(&cache, &project)?;
    let publication_after = tree_state(&publication_root)?;
    let preserved_before_reopen = tree_state(&preserved_root)?;
    require(
        live_after == baseline_live
            && live_after["state"]["sqlite"]["staged_abort_only_delta"] == 0
            && staged_abort_symbol_count(&canonical_db, &project)? == 0
            && publication_after["exists"] == Value::Bool(false)
            && preserved_before_reopen["exists"] == Value::Bool(true)
            && fixture_source_state(&repo)? == source_delta["after"],
        "ISSUE_1147_STAGED_ABORT_LIVE_GENERATION_CHANGED",
        json!({
            "baseline_live": baseline_live,
            "live_after": live_after,
            "publication_after": publication_after,
            "preserved_before_reopen": preserved_before_reopen,
        }),
    )?;
    let preserved_manifest = staged_abort_validate_preserved_manifest(
        &preserved_root,
        &repo,
        &project,
        &abort_fault,
        &mutation,
    )?;
    let preserved_vault =
        staged_abort_preserved_vault_readback(&preserved_root, &project, &mutation)?;
    let preserved_after_reopen = tree_state(&preserved_root)?;
    require(
        preserved_before_reopen == preserved_after_reopen,
        "ISSUE_1147_STAGED_ABORT_REOPEN_MUTATED_PRESERVED_STAGE",
        json!({
            "before": preserved_before_reopen,
            "after": preserved_after_reopen,
        }),
    )?;
    let structured_fault =
        staged_abort_validate_fault(&abort_envelope, &abort_fault, &project, &mutation)?;
    require(
        preserved_manifest["manifest"]["abort_error"] == structured_fault["underlying_error"],
        "ISSUE_1147_PRESERVED_ABORT_ERROR_NOT_STRUCTURED_FAULT",
        json!({
            "manifest_abort_error": preserved_manifest["manifest"]["abort_error"],
            "fault_underlying_error": structured_fault["underlying_error"],
        }),
    )?;
    let terminal_transition = staged_abort_failed_transition(StagedAbortFailedTransitionRequest {
        cache: &cache,
        project: &project,
        canonical_repo: &canonical_repo,
        canonical_db: &canonical_db,
        envelope: &abort_envelope,
        response_raw: &abort_raw,
        binding: &transition_binding,
        expected_family: &live_after["state"]["source_family"],
    })?;
    let legacy_parser_edge =
        staged_abort_legacy_parser_edge(&abort_envelope, &cache, &repo, &project)?;
    let final_state = staged_abort_complete_state(&cache, &repo, &project)?;
    let receipt = json!({
        "schema": "astrolabe.issue-1147.staged-abort.v1",
        "tree_sha": tree_sha,
        "source_generation_schema": worker_source_generation::SOURCE_GENERATION_SCHEMA,
        "source_generation_sha256": source_generation,
        "driver_artifact": driver_artifact,
        "source_of_truth": "the canonical live SQLite/lowered/vault/search/config generation; the terminal project-transition row; the v4 preserved-stage manifest and complete file inventory; immutable preserved SQLite rows; selected physical S1/Compression/Ledger/TimeIndex state, exact framed WAL commit, and verified ledger chain",
        "payload": payload,
        "repo": repo,
        "cache": cache,
        "project": project,
        "fixture": fixture,
        "worker_binding": worker_binding,
        "baseline": {
            "raw": {
                "text": baseline_raw,
                "bytes": baseline_raw.len(),
                "sha256": sha256(baseline_raw.as_bytes()),
            },
            "envelope": baseline_envelope,
            "response": baseline_response,
            "transition": baseline_transition,
            "weave_generation": baseline_weave,
        },
        "source_delta": source_delta,
        "barrier_arm": barrier_arm,
        "barrier": barrier_readback,
        "baseline_live": baseline_live,
        "mutation": mutation,
        "abort": {
            "raw": {
                "text": abort_raw,
                "bytes": abort_raw.len(),
                "sha256": sha256(abort_raw.as_bytes()),
            },
            "envelope": abort_envelope,
            "fault": abort_fault,
            "structured_fault": structured_fault,
        },
        "publication_after": publication_after,
        "live_after": live_after,
        "preserved": {
            "before_reopen": preserved_before_reopen,
            "manifest": preserved_manifest,
            "vault": preserved_vault,
            "after_reopen": preserved_after_reopen,
        },
        "terminal_transition": terminal_transition,
        "legacy_parser_edge": legacy_parser_edge,
        "final_state": final_state,
        "expected_refusal_observed": true,
        "prior_live_generation_preserved": true,
        "preserved_stage_physically_reopened": true,
    });
    let persisted = write_new_readback(
        &payload.join("staged-abort.json"),
        &serde_json::to_vec_pretty(&receipt)?,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event":"ISSUE_1147_STAGED_ABORT_COMPLETE",
            "receipt":persisted,
            "project":receipt["project"],
            "outer_code":receipt["abort"]["fault"]["code"],
            "underlying_code":receipt["abort"]["fault"]["underlying_code"],
            "mutation_commit_seq":receipt["mutation"]["commit_seq"],
            "preserved_stage_sha256":receipt["preserved"]["manifest"]["inventory"]["sha256"],
            "live_generation_sha256":receipt["live_after"]["sha256"],
            "transition_sha256":receipt["terminal_transition"]["sha256"],
            "legacy_parser_state_unchanged":receipt["legacy_parser_edge"]["state_unchanged"],
        }))?
    );
    Ok(())
}

fn staged_abort_readback(payload: PathBuf) -> AnyResult<()> {
    require(
        payload.try_exists()?,
        "ISSUE_1147_STAGED_ABORT_READBACK_PAYLOAD_MISSING",
        payload.display(),
    )?;
    let readback_path = payload.join("staged-abort-readback.json");
    require(
        !readback_path.try_exists()?,
        "ISSUE_1147_STAGED_ABORT_READBACK_PREEXISTS",
        readback_path.display(),
    )?;
    let execution_path = payload.join("staged-abort.json");
    let execution_bytes = fs::read(&execution_path)?;
    let execution: Value = serde_json::from_slice(&execution_bytes)?;
    let tree_sha = canonical_head()?;
    let source_generation = current_source_generation_sha256()?;
    let driver_artifact = current_driver_artifact_state()?;
    require(
        execution["schema"] == "astrolabe.issue-1147.staged-abort.v1"
            && execution["payload"] == json!(payload)
            && execution["tree_sha"] == Value::String(tree_sha.clone())
            && execution["source_generation_sha256"] == Value::String(source_generation.clone())
            && source_generation == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256
            && execution["driver_artifact"] == driver_artifact,
        "ISSUE_1147_STAGED_ABORT_EXECUTION_RECEIPT_MISMATCH",
        json!({
            "execution_schema": execution["schema"],
            "payload": payload,
            "tree_sha": tree_sha,
            "source_generation": source_generation,
            "driver_artifact": driver_artifact,
        }),
    )?;
    let repo = PathBuf::from(
        execution["repo"]
            .as_str()
            .ok_or("ISSUE_1147_STAGED_ABORT_RECEIPT_REPO_MISSING")?,
    );
    let cache = PathBuf::from(
        execution["cache"]
            .as_str()
            .ok_or("ISSUE_1147_STAGED_ABORT_RECEIPT_CACHE_MISSING")?,
    );
    let project = execution["project"]
        .as_str()
        .ok_or("ISSUE_1147_STAGED_ABORT_RECEIPT_PROJECT_MISSING")?;
    let observed_cache = set_cbm_cache_dir(&cache)?;
    require(
        observed_cache == cache
            && cbm_project_name_from_path(
                repo.to_str()
                    .ok_or("ISSUE_1147_STAGED_ABORT_READBACK_REPO_NOT_UTF8")?,
            )? == project
            && fixture_source_state(&repo)? == execution["source_delta"]["after"],
        "ISSUE_1147_STAGED_ABORT_READBACK_INPUT_MISMATCH",
        json!({"repo":repo,"cache":cache,"project":project}),
    )?;
    let canonical_repo = repo.canonicalize()?;
    let canonical_db = cache.join(format!("{project}.db"));
    let baseline_observation_path = payload.join("baseline-transition-observation.json");
    let baseline_observation_bytes = fs::read(&baseline_observation_path)?;
    let baseline_observation: Value = serde_json::from_slice(&baseline_observation_bytes)?;
    let baseline_observation_physical = json!({
        "path": baseline_observation_path,
        "bytes": baseline_observation_bytes.len(),
        "sha256": sha256(&baseline_observation_bytes),
    });
    let baseline_binding: CbmVerifiedWorkerBinding =
        serde_json::from_value(execution["worker_binding"]["verified_worker"].clone())?;
    let (baseline_owner_pid, _) = capability_owner_identity(&baseline_binding)?;
    let baseline_response_raw = execution["baseline"]["raw"]["text"]
        .as_str()
        .ok_or("ISSUE_1147_STAGED_ABORT_BASELINE_RAW_MISSING")?;
    let parsed_baseline_response_envelope: Value = serde_json::from_str(baseline_response_raw)?;
    let baseline_transition_raw = execution["baseline"]["transition"]["raw"]
        .as_str()
        .ok_or("ISSUE_1147_STAGED_ABORT_BASELINE_TRANSITION_RAW_MISSING")?;
    let baseline_transition_value: Value = serde_json::from_str(baseline_transition_raw)?;
    let baseline_family = transition_family_evidence(&canonical_db)?;
    let baseline_key = format!("astrolabe.calyx.{project}.project_transition_json");
    let baseline_recomputed = validate_completed_transition(CompletedTransitionRequest {
        transition_key: &baseline_key,
        transition: &baseline_transition_value,
        project,
        canonical_root: &canonical_repo,
        canonical_db: &canonical_db,
        response_raw: baseline_response_raw,
        response_envelope: &execution["baseline"]["envelope"],
        response_payload: &execution["baseline"]["response"],
        family_after: &baseline_family,
        binding: &baseline_binding,
        expected_process_pid: baseline_owner_pid,
        observation_path: None,
    })?;
    let comparable_recomputed_observation = baseline_recomputed.observation;
    let mut comparable_persisted_observation = baseline_observation.clone();
    comparable_persisted_observation["binding"]["observer_process_pid"] =
        comparable_recomputed_observation["binding"]["observer_process_pid"].clone();
    let observed_check_names = baseline_observation["checks"]
        .as_array()
        .ok_or("ISSUE_1147_STAGED_ABORT_BASELINE_CHECKS_MISSING")?
        .iter()
        .map(|check| {
            check["name"]
                .as_str()
                .ok_or("ISSUE_1147_STAGED_ABORT_BASELINE_CHECK_NAME_MISSING")
        })
        .collect::<Result<Vec<_>, _>>()?;
    require(
        execution["baseline"]["transition"]["validation_observation"]["physical"]["path"]
            == baseline_observation_physical["path"]
            && execution["baseline"]["transition"]["validation_observation"]["physical"]["bytes"]
                == baseline_observation_physical["bytes"]
            && execution["baseline"]["transition"]["validation_observation"]["physical"]["sha256"]
                == baseline_observation_physical["sha256"]
            && execution["baseline"]["transition"]["validation_observation"]["value"]
                == baseline_observation
            && execution["baseline"]["raw"]["bytes"].as_u64()
                == u64::try_from(baseline_response_raw.len()).ok()
            && execution["baseline"]["raw"]["sha256"]
                == Value::String(sha256(baseline_response_raw.as_bytes()))
            && parsed_baseline_response_envelope == execution["baseline"]["envelope"]
            && execution["baseline"]["transition"]["sha256"]
                == Value::String(sha256(baseline_transition_raw.as_bytes()))
            && execution["baseline"]["transition"]["raw"]
                == Value::String(baseline_transition_raw.to_string())
            && execution["baseline"]["transition"]["validation_observation"]["value"]["binding"]["challenge"]
                == execution["worker_binding"]["verified_worker"]["capability"]["challenge"]
            && baseline_observation["binding"]["expected_process_pid"]
                == Value::from(baseline_owner_pid)
            && baseline_observation["binding"]["observer_process_pid"]
                == Value::from(baseline_owner_pid)
            && baseline_observation["binding"]["parse_error"].is_null()
            && baseline_observation["schema"]
                == "astrolabe.issue-1116-1119.completed-transition-observation.v1"
            && baseline_observation["failed_checks"] == json!([])
            && observed_check_names == COMPLETED_TRANSITION_CHECK_NAMES
            && baseline_observation["checks"]
                .as_array()
                .is_some_and(|checks| {
                    checks
                        .iter()
                        .all(|check| check["passed"] == Value::Bool(true))
                })
            && baseline_recomputed.persisted_observation.is_none()
            && execution["baseline"]["transition"]["response_sha256"].as_str()
                == Some(baseline_recomputed.response_sha256.as_str())
            && comparable_persisted_observation == comparable_recomputed_observation,
        "ISSUE_1147_STAGED_ABORT_BASELINE_OBSERVATION_MISMATCH",
        json!({
            "physical": baseline_observation_physical,
            "value": baseline_observation,
            "execution": execution["baseline"]["transition"]["validation_observation"],
            "recomputed": comparable_recomputed_observation,
        }),
    )?;
    let publication_root = staged_abort_project_root(&cache, project);
    let preserved_root = staged_abort_preserved_root(&cache, project);
    let live = staged_abort_live_generation_state(&cache, project)?;
    let publication = tree_state(&publication_root)?;
    let preserved_before = tree_state(&preserved_root)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"separate_process_preserved_stage_reopen",
            "phase":"before",
            "state":{
                "live":live,
                "publication":publication,
                "preserved":preserved_before,
            },
        }))?
    );
    require(
        live == execution["baseline_live"]
            && live == execution["live_after"]
            && live["state"]["sqlite"]["staged_abort_only_delta"] == 0
            && staged_abort_symbol_count(&canonical_db, project)? == 0
            && publication["exists"] == Value::Bool(false)
            && preserved_before["exists"] == Value::Bool(true),
        "ISSUE_1147_STAGED_ABORT_READBACK_LIVE_MISMATCH",
        json!({
            "live": live,
            "baseline": execution["baseline_live"],
            "execute_after": execution["live_after"],
            "publication": publication,
            "preserved": preserved_before,
        }),
    )?;
    let envelope = &execution["abort"]["envelope"];
    let fault = &execution["abort"]["fault"];
    let abort_raw = execution["abort"]["raw"]["text"]
        .as_str()
        .ok_or("ISSUE_1147_STAGED_ABORT_READBACK_RAW_RESPONSE_MISSING")?;
    let reparsed_abort_envelope: Value = serde_json::from_str(abort_raw)?;
    require(
        execution["abort"]["raw"]["bytes"].as_u64() == u64::try_from(abort_raw.len()).ok()
            && execution["abort"]["raw"]["sha256"] == Value::String(sha256(abort_raw.as_bytes()))
            && reparsed_abort_envelope == *envelope
            && envelope["isError"] == Value::Bool(true)
            && envelope["content"][0]["text"] == serde_json::to_string(fault)?
            && envelope["structuredContent"] == *fault,
        "ISSUE_1147_STAGED_ABORT_READBACK_STRUCTURED_MIRROR_MISMATCH",
        envelope,
    )?;
    let mutation = &execution["mutation"];
    let barrier_root = PathBuf::from(
        execution["barrier"]["root"]
            .as_str()
            .ok_or("ISSUE_1147_STAGED_ABORT_READBACK_BARRIER_ROOT_MISSING")?,
    );
    let barrier =
        staged_abort_barrier_readback(&barrier_root, project, &execution["barrier_arm"], mutation)?;
    require(
        barrier == execution["barrier"],
        "ISSUE_1147_STAGED_ABORT_READBACK_BARRIER_MISMATCH",
        &barrier,
    )?;
    let manifest =
        staged_abort_validate_preserved_manifest(&preserved_root, &repo, project, fault, mutation)?;
    let vault = staged_abort_preserved_vault_readback(&preserved_root, project, mutation)?;
    let structured_fault = staged_abort_validate_fault(envelope, fault, project, mutation)?;
    require(
        structured_fault == execution["abort"]["structured_fault"]
            && manifest["inventory"] == execution["preserved"]["manifest"]["inventory"]
            && manifest["manifest_sha256"] == execution["preserved"]["manifest"]["manifest_sha256"]
            && vault["slot_cf_generation"] == execution["preserved"]["vault"]["slot_cf_generation"]
            && vault["compression_cf_generation"]
                == execution["preserved"]["vault"]["compression_cf_generation"]
            && vault["physical_ledger"]["physical_row_sha256"]
                == execution["preserved"]["vault"]["physical_ledger"]["physical_row_sha256"],
        "ISSUE_1147_STAGED_ABORT_READBACK_PRESERVED_MISMATCH",
        json!({
            "structured_fault": structured_fault,
            "manifest": manifest,
            "vault": vault,
        }),
    )?;
    let (config_integrity, config) = config_rows(&cache, project)?;
    let weave_generation = verify_weave_generation_receipt(&config, project)?;
    require(
        weave_generation == execution["baseline"]["weave_generation"],
        "ISSUE_1147_STAGED_ABORT_READBACK_WEAVE_RECEIPT_MISMATCH",
        json!({
            "execution": execution["baseline"]["weave_generation"],
            "readback": weave_generation,
        }),
    )?;
    let transition_key = format!("astrolabe.calyx.{project}.project_transition_json");
    let transition_raw = config
        .get(&transition_key)
        .ok_or("ISSUE_1147_READBACK_TRANSITION_MISSING")?
        .clone();
    let transition: Value = serde_json::from_str(&transition_raw)?;
    let family = transition_family_evidence(&canonical_db)?;
    let response_sha256 = sha256(&serde_json::to_vec(envelope)?);
    let raw_response_sha256 = sha256(abort_raw.as_bytes());
    require(
        config_integrity == "ok"
            && transition_raw == execution["terminal_transition"]["raw"]
            && transition["schema"] == "astrolabe-project-transition-v1"
            && transition["phase"] == "terminal"
            && transition["project"] == Value::String(project.to_string())
            && transition["canonical_root"] == json!(canonical_repo)
            && transition["canonical_db_path"] == json!(canonical_db)
            && transition["evidence"]["status"] == "failed"
            && transition["evidence"]["response_hash_basis"]
                == "astrolabe.persisted-json-compact.v1"
            && transition["evidence"]["response_sha256"] == Value::String(response_sha256.clone())
            && transition["evidence"]["raw_response_sha256"]
                == Value::String(raw_response_sha256.clone())
            && transition["evidence"]["sqlite_publication_started"].is_null()
            && transition["evidence"]["family_before"] == family
            && transition["evidence"]["family_after"] == family
            && transition["normalization"]["after"] == family,
        "ISSUE_1147_STAGED_ABORT_READBACK_TRANSITION_MISMATCH",
        json!({
            "transition": transition,
            "family": family,
            "response_sha256": response_sha256,
            "raw_response_sha256": raw_response_sha256,
        }),
    )?;
    let legacy_parser_edge = staged_abort_legacy_parser_edge(envelope, &cache, &repo, project)?;
    require(
        legacy_parser_edge["diagnostic"] == execution["legacy_parser_edge"]["diagnostic"]
            && legacy_parser_edge["state_unchanged"] == Value::Bool(true),
        "ISSUE_1147_STAGED_ABORT_READBACK_LEGACY_EDGE_MISMATCH",
        &legacy_parser_edge,
    )?;
    let preserved_after = tree_state(&preserved_root)?;
    let live_after = staged_abort_live_generation_state(&cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"separate_process_preserved_stage_reopen",
            "phase":"after",
            "state":{
                "live":live_after,
                "publication":tree_state(&publication_root)?,
                "preserved":preserved_after,
                "manifest_inventory":manifest["inventory"],
                "selected_vault":vault,
                "terminal_transition":transition,
            },
        }))?
    );
    require(
        preserved_before == preserved_after
            && live == live_after
            && tree_state(&publication_root)? == publication,
        "ISSUE_1147_STAGED_ABORT_READBACK_REOPEN_MUTATED_STATE",
        json!({
            "preserved_before": preserved_before,
            "preserved_after": preserved_after,
            "live_before": live,
            "live_after": live_after,
        }),
    )?;
    let report = json!({
        "schema": "astrolabe.issue-1147.staged-abort-readback.v1",
        "tree_sha": tree_sha,
        "source_generation_schema": worker_source_generation::SOURCE_GENERATION_SCHEMA,
        "source_generation_sha256": source_generation,
        "driver_artifact": driver_artifact,
        "source_of_truth": "a fresh process reopened the prior live SQLite generation and the preserved v4 stage; recomputed every staged file digest and aggregate; opened immutable source SQLite and selected physical S1/Compression/Ledger/TimeIndex; reread the exact framed WAL commit, point-read the mutation ledger entry, and verified the complete chain/head; reread the terminal transition",
        "execution": {
            "path": execution_path,
            "bytes": execution_bytes.len(),
            "sha256": sha256(&execution_bytes),
        },
        "project": project,
        "fixture_source": fixture_source_state(&repo)?,
        "live": live_after,
        "publication": publication,
        "preserved": {
            "before": preserved_before,
            "manifest": manifest,
            "vault": vault,
            "after": preserved_after,
        },
        "structured_fault": structured_fault,
        "barrier": barrier,
        "weave_generation": weave_generation,
        "baseline_transition_observation": {
            "physical": baseline_observation_physical,
            "value": baseline_observation,
        },
        "terminal_transition": {
            "key": transition_key,
            "raw": transition_raw,
            "sha256": sha256(transition_raw.as_bytes()),
            "value": transition,
            "family": family,
        "response_sha256": response_sha256,
        "raw_response_sha256": raw_response_sha256,
        },
        "legacy_parser_edge": legacy_parser_edge,
        "prior_live_generation_preserved": true,
        "preserved_stage_inventory_v4_recomputed": true,
        "preserved_sqlite_physically_reopened": true,
        "preserved_s1_compression_ledger_time_index_wal_physically_reopened": true,
        "mutation_ledger_ref_in_verified_chain": true,
        "zero_overlay_rows_bytes": true,
        "separate_process_readback": true,
    });
    let persisted = write_new_readback(&readback_path, &serde_json::to_vec_pretty(&report)?)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event":"ISSUE_1147_STAGED_ABORT_READBACK_COMPLETE",
            "receipt":persisted,
            "project":project,
            "live_generation_sha256":report["live"]["sha256"],
            "preserved_stage_sha256":report["preserved"]["manifest"]["inventory"]["sha256"],
            "mutation_commit_seq":execution["mutation"]["commit_seq"],
            "ledger_head":report["preserved"]["vault"]["head"],
            "terminal_transition_sha256":report["terminal_transition"]["sha256"],
            "legacy_parser_state_unchanged":report["legacy_parser_edge"]["state_unchanged"],
        }))?
    );
    Ok(())
}

fn required_fsv_env(name: &str) -> AnyResult<String> {
    let value =
        std::env::var(name).map_err(|error| format!("ISSUE_1150_{name}_REQUIRED: {error}"))?;
    require(
        !value.trim().is_empty(),
        &format!("ISSUE_1150_{name}_EMPTY"),
        "the association FSV external-evaluator identity must be explicit",
    )?;
    Ok(value)
}

fn discovery_fsv_budgets() -> AnyResult<Value> {
    let raw = required_fsv_env("ASTRO_ASSOCIATION_FSV_BUDGETS_JSON")?;
    let budgets: Value = serde_json::from_str(&raw)?;
    let object = budgets
        .as_object()
        .ok_or("ISSUE_1150_DISCOVERY_BUDGETS_NOT_OBJECT")?;
    let expected = BTreeSet::from([
        "max_evaluation_bindings",
        "max_request_bytes_per_binding",
        "max_request_bytes_total",
        "max_response_bytes_per_binding",
        "max_response_bytes_total",
        "max_generation_rows",
        "max_generation_bytes",
    ]);
    let observed = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let positive = expected.iter().all(|field| {
        object
            .get(*field)
            .and_then(Value::as_u64)
            .is_some_and(|value| value > 0)
    });
    require(
        observed == expected
            && positive
            && budgets["max_request_bytes_total"].as_u64()
                >= budgets["max_request_bytes_per_binding"].as_u64()
            && budgets["max_response_bytes_total"].as_u64()
                >= budgets["max_response_bytes_per_binding"].as_u64(),
        "ISSUE_1150_DISCOVERY_BUDGETS_INVALID",
        json!({"observed_fields": observed, "expected_fields": expected, "budgets": budgets}),
    )?;
    Ok(budgets)
}

fn discovery_prepare_request(
    project: &str,
    generation_ordinal: u64,
    budgets: &Value,
    evaluator_id: &str,
    model_id: &str,
) -> Value {
    json!({
        "project": project,
        "mode": "prepare",
        "workers": 1,
        "cross_validation_folds": 32,
        "top_k": 5,
        "min_shared_intermediaries": 1,
        "budgets": budgets,
        "evaluator_declarations": [
            {
                "evaluator_id": evaluator_id,
                "model_id": model_id,
                "prompt_id": format!("manual-fsv-grounded-review-a-generation-{generation_ordinal}"),
                "temperature_x100": 0,
                "prompt_utf8": format!("Generation {generation_ordinal}: evaluate only the exact grounded association evidence in this request and return the strict response schema.")
            },
            {
                "evaluator_id": evaluator_id,
                "model_id": model_id,
                "prompt_id": format!("manual-fsv-grounded-review-b-generation-{generation_ordinal}"),
                "temperature_x100": 20,
                "prompt_utf8": format!("Generation {generation_ordinal}: independently seek falsification using only the exact grounded association evidence and return the strict response schema.")
            }
        ],
    })
}

fn discovery_capture_path(payload: &Path, prepared_hash: &str) -> PathBuf {
    payload.join(format!("association-external-capture-{prepared_hash}.json"))
}

fn persist_discovery_external_requests(
    payload: &Path,
    request: &Value,
    prepared: &Value,
) -> AnyResult<Value> {
    let prepared_hash = prepared["prepared_artifact_sha256"]
        .as_str()
        .ok_or("ISSUE_1150_PREPARED_HASH_MISSING")?;
    let roster = prepared["evaluation_roster"]
        .as_object()
        .ok_or("ISSUE_1150_EVALUATION_ROSTER_MISSING")?;
    let bundle = json!({
        "schema": DISCOVERY_FSV_REQUEST_SCHEMA,
        "prepared_artifact_sha256": prepared_hash,
        "source_generation_sha256": prepared["source_generation_sha256"],
        "evaluator_id": request["evaluator_declarations"][0]["evaluator_id"],
        "model_id": request["evaluator_declarations"][0]["model_id"],
        "budgets": request["budgets"],
        "evaluation_roster": roster,
        "capture_contract": {
            "capture_schema": DISCOVERY_CAPTURE_SCHEMA_V1,
            "receipt_schema": DISCOVERY_RECEIPT_SCHEMA_V2,
            "response_schema": DISCOVERY_RESPONSE_SCHEMA_V1,
            "capture_file": discovery_capture_path(payload, prepared_hash),
            "instruction": "Invoke every exact binding through the declared genuine external evaluator. Persist the provider-returned response bytes and provider response identity; do not synthesize, repair, or substitute a response."
        }
    });
    write_new_readback(
        &payload.join(format!(
            "association-external-requests-{prepared_hash}.json"
        )),
        &serde_json::to_vec_pretty(&bundle)?,
    )
}

fn exact_object_fields(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == expected.iter().copied().collect::<BTreeSet<_>>()
    })
}

fn load_genuine_discovery_capture(
    payload: &Path,
    request: &Value,
    prepared: &Value,
) -> AnyResult<(Value, Value)> {
    let prepared_hash = prepared["prepared_artifact_sha256"]
        .as_str()
        .ok_or("ISSUE_1150_PREPARED_HASH_MISSING")?;
    let path = discovery_capture_path(payload, prepared_hash);
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "ISSUE_1150_GENUINE_EXTERNAL_CAPTURE_REQUIRED: {}: {error}; invoke every exact request in association-external-requests-{prepared_hash}.json through the declared real evaluator and persist the exact provider receipts at {}",
            path.display(),
            path.display(),
        )
    })?;
    let capture: Value = serde_json::from_slice(&bytes)?;
    require(
        exact_object_fields(
            &capture,
            &[
                "schema",
                "prepared_artifact_sha256",
                "source_generation_sha256",
                "receipts",
            ],
        ) && capture["schema"] == DISCOVERY_FSV_CAPTURE_SCHEMA
            && capture["prepared_artifact_sha256"] == prepared["prepared_artifact_sha256"]
            && capture["source_generation_sha256"] == prepared["source_generation_sha256"],
        "ISSUE_1150_EXTERNAL_CAPTURE_HEADER_INVALID",
        &capture,
    )?;
    let receipts = capture["receipts"]
        .as_array()
        .ok_or("ISSUE_1150_EXTERNAL_CAPTURE_RECEIPTS_NOT_ARRAY")?;
    let bindings = prepared["evaluation_roster"]["bindings"]
        .as_array()
        .ok_or("ISSUE_1150_PREPARED_BINDINGS_MISSING")?;
    let budgets = request["budgets"]
        .as_object()
        .ok_or("ISSUE_1150_PREPARED_BUDGETS_MISSING")?;
    let required_receipt_fields = [
        "schema",
        "invocation_id",
        "external_invocation_id",
        "provider_response_id",
        "capture_schema",
        "capture_provenance",
        "prepared_artifact_sha256",
        "source_generation_sha256",
        "hypothesis_id",
        "hypothesis_content_sha256",
        "evaluator_id",
        "model_id",
        "prompt_id",
        "temperature_x100",
        "prompt_utf8",
        "prompt_sha256",
        "request_utf8",
        "request_sha256",
        "response_utf8",
        "response_sha256",
        "parse_result",
    ];
    let required_parse_fields = [
        "schema",
        "plausible_score",
        "novelty_score",
        "testability_score",
        "falsifiability_score",
        "justification",
        "falsification_test",
        "cited_evidence_ids",
    ];
    require(
        receipts.len() == bindings.len()
            && receipts.len()
                <= usize::try_from(
                    budgets["max_evaluation_bindings"]
                        .as_u64()
                        .ok_or("ISSUE_1150_CAPTURE_BINDING_BUDGET_MISSING")?,
                )?,
        "ISSUE_1150_EXTERNAL_CAPTURE_ROSTER_CARDINALITY_MISMATCH",
        json!({"receipts": receipts.len(), "bindings": bindings.len(), "budgets": budgets}),
    )?;
    let mut by_invocation = BTreeMap::<&str, &Value>::new();
    let mut external_ids = BTreeSet::<&str>::new();
    let mut provider_ids = BTreeSet::<&str>::new();
    let mut request_bytes_total = 0_u64;
    let mut response_bytes_total = 0_u64;
    for receipt in receipts {
        let invocation_id = receipt["invocation_id"]
            .as_str()
            .ok_or("ISSUE_1150_CAPTURE_INVOCATION_ID_MISSING")?;
        let external_id = receipt["external_invocation_id"]
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or("ISSUE_1150_CAPTURE_EXTERNAL_INVOCATION_ID_MISSING")?;
        let provider_id = receipt["provider_response_id"]
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .ok_or("ISSUE_1150_CAPTURE_PROVIDER_RESPONSE_ID_MISSING")?;
        let request_utf8 = receipt["request_utf8"]
            .as_str()
            .ok_or("ISSUE_1150_CAPTURE_REQUEST_MISSING")?;
        let response_utf8 = receipt["response_utf8"]
            .as_str()
            .ok_or("ISSUE_1150_CAPTURE_RESPONSE_MISSING")?;
        let reparsed: Value = serde_json::from_str(response_utf8)?;
        let provenance = receipt["capture_provenance"]
            .as_array()
            .filter(|items| {
                !items.is_empty()
                    && items
                        .iter()
                        .all(|item| item.as_str().is_some_and(|text| !text.trim().is_empty()))
            })
            .ok_or("ISSUE_1150_CAPTURE_PROVENANCE_INVALID")?;
        require(
            exact_object_fields(receipt, &required_receipt_fields)
                && exact_object_fields(&receipt["parse_result"], &required_parse_fields)
                && receipt["schema"] == DISCOVERY_RECEIPT_SCHEMA_V2
                && receipt["capture_schema"] == DISCOVERY_CAPTURE_SCHEMA_V1
                && receipt["prepared_artifact_sha256"] == prepared["prepared_artifact_sha256"]
                && receipt["source_generation_sha256"] == prepared["source_generation_sha256"]
                && receipt["request_sha256"] == Value::String(sha256(request_utf8.as_bytes()))
                && receipt["response_sha256"] == Value::String(sha256(response_utf8.as_bytes()))
                && receipt["parse_result"] == reparsed
                && receipt["parse_result"]["schema"] == DISCOVERY_RESPONSE_SCHEMA_V1
                && !provenance.is_empty()
                && by_invocation.insert(invocation_id, receipt).is_none()
                && external_ids.insert(external_id)
                && provider_ids.insert(provider_id),
            "ISSUE_1150_EXTERNAL_CAPTURE_RECEIPT_INVALID",
            receipt,
        )?;
        let request_bytes = u64::try_from(request_utf8.len())?;
        let response_bytes = u64::try_from(response_utf8.len())?;
        require(
            request_bytes
                <= budgets["max_request_bytes_per_binding"]
                    .as_u64()
                    .ok_or("ISSUE_1150_REQUEST_BYTE_BUDGET_MISSING")?
                && response_bytes
                    <= budgets["max_response_bytes_per_binding"]
                        .as_u64()
                        .ok_or("ISSUE_1150_RESPONSE_BYTE_BUDGET_MISSING")?,
            "ISSUE_1150_EXTERNAL_CAPTURE_PER_BINDING_BUDGET_EXCEEDED",
            json!({"invocation_id": invocation_id, "request_bytes": request_bytes, "response_bytes": response_bytes}),
        )?;
        request_bytes_total = request_bytes_total
            .checked_add(request_bytes)
            .ok_or("ISSUE_1150_CAPTURE_REQUEST_TOTAL_OVERFLOW")?;
        response_bytes_total = response_bytes_total
            .checked_add(response_bytes)
            .ok_or("ISSUE_1150_CAPTURE_RESPONSE_TOTAL_OVERFLOW")?;
    }
    for binding in bindings {
        let invocation_id = binding["invocation_id"]
            .as_str()
            .ok_or("ISSUE_1150_BINDING_INVOCATION_ID_MISSING")?;
        let receipt = by_invocation
            .get(invocation_id)
            .ok_or("ISSUE_1150_EXTERNAL_CAPTURE_BINDING_MISSING")?;
        for field in [
            "invocation_id",
            "source_generation_sha256",
            "hypothesis_id",
            "hypothesis_content_sha256",
            "evaluator_id",
            "model_id",
            "prompt_id",
            "temperature_x100",
            "prompt_utf8",
            "prompt_sha256",
            "request_utf8",
            "request_sha256",
        ] {
            require(
                receipt[field] == binding[field],
                "ISSUE_1150_EXTERNAL_CAPTURE_BINDING_MISMATCH",
                json!({"invocation_id": invocation_id, "field": field, "binding": binding[field], "receipt": receipt[field]}),
            )?;
        }
    }
    require(
        request_bytes_total
            <= budgets["max_request_bytes_total"]
                .as_u64()
                .ok_or("ISSUE_1150_REQUEST_TOTAL_BUDGET_MISSING")?
            && response_bytes_total
                <= budgets["max_response_bytes_total"]
                    .as_u64()
                    .ok_or("ISSUE_1150_RESPONSE_TOTAL_BUDGET_MISSING")?,
        "ISSUE_1150_EXTERNAL_CAPTURE_TOTAL_BUDGET_EXCEEDED",
        json!({"request_bytes": request_bytes_total, "response_bytes": response_bytes_total}),
    )?;
    Ok((
        Value::Array(receipts.clone()),
        json!({
            "path": path,
            "bytes": bytes.len(),
            "sha256": sha256(&bytes),
            "receipt_count": receipts.len(),
            "unique_external_invocation_ids": external_ids.len(),
            "unique_provider_response_ids": provider_ids.len(),
            "request_bytes_total": request_bytes_total,
            "response_bytes_total": response_bytes_total,
            "strict_request_response_reparse_verified": true,
        }),
    ))
}

fn execute(payload: PathBuf) -> AnyResult<()> {
    require(
        !payload.try_exists()?,
        "ISSUE_1116_1119_PAYLOAD_PREEXISTS",
        payload.display(),
    )?;
    fs::create_dir_all(&payload)?;
    let tree_sha = canonical_head()?;
    let driver_artifact = current_driver_artifact_state()?;
    let source_generation = current_source_generation_sha256()?;
    require(
        source_generation == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256,
        "ISSUE_1146_COMPILED_SOURCE_GENERATION_DRIFT",
        &source_generation,
    )?;
    let repo = payload.join("real-rust-repo");
    let cache = payload.join("real-cache");
    let fixture = write_fixture(&repo)?;
    fs::create_dir(&cache)?;
    let observed_cache = set_cbm_cache_dir(&cache)?;
    require(
        observed_cache == cache,
        "ISSUE_1116_1119_CACHE_BINDING_MISMATCH",
        observed_cache.display(),
    )?;
    let (shipping_host, shipping_host_state) = shipping_astrolabe_executable()?;
    require(
        configured_cbm_host_binary_path()?.is_none() && !supervisor_should_wrap(),
        "ISSUE_1116_1119_EXECUTE_PROCESS_PRESTATE_INVALID",
        "a fresh execute process already had a binary binding or supervisor role",
    )?;
    let shipping_sha256 = shipping_host_state["sha256"]
        .as_str()
        .ok_or("ISSUE_1116_1119_SHIPPING_SHA256_MISSING")?;
    let verified_worker = initialize_cbm_host_process_with_verified_worker(
        &shipping_host,
        shipping_sha256,
        &source_generation,
    )?;
    let verified_worker_identity =
        validate_verified_worker_binding(&verified_worker, &shipping_host)?;
    require(
        configured_cbm_host_binary_path()?.as_deref() == Some(shipping_host.as_path())
            && supervisor_should_wrap(),
        "ISSUE_1116_1119_SHIPPING_HOST_BINDING_MISMATCH",
        shipping_host.display(),
    )?;
    let current = std::env::current_exe()?;
    let conflict_input_before = optional_file_state(&current)?;
    let conflict_before = json!({
        "worker_binary_binding": configured_cbm_host_binary_path()?,
        "cache_tree": tree_state(&cache)?,
    });
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"non_cli_worker_capability",
            "phase":"before",
            "state":conflict_before,
            "input":conflict_input_before,
        }))?
    );
    let (_, current_sha256) = file_sha256(&current)?;
    let conflict_result = initialize_cbm_host_process_with_verified_worker(
        &current,
        &current_sha256,
        &source_generation,
    );
    let conflict_input_after = optional_file_state(&current)?;
    let conflict_after = json!({
        "worker_binary_binding": configured_cbm_host_binary_path()?,
        "cache_tree": tree_state(&cache)?,
    });
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"non_cli_worker_capability",
            "phase":"after",
            "state":conflict_after,
            "input":conflict_input_after,
        }))?
    );
    let conflict = match conflict_result {
        Err(error) => error,
        Ok(binding) => {
            return Err(format!(
                "ISSUE_1116_1119_CONFLICTING_WORKER_UNEXPECTEDLY_SUCCEEDED: {binding:?}"
            )
            .into());
        }
    };
    require(
        conflict.envelope().code == "ASTRO_CBM_WORKER_CAPABILITY_REFUSED"
            && !conflict.envelope().message.trim().is_empty()
            && !conflict.envelope().remediation.trim().is_empty()
            && conflict_before == conflict_after
            && conflict_input_before == conflict_input_after
            && configured_cbm_host_binary_path()?.as_deref() == Some(shipping_host.as_path()),
        "ISSUE_1116_1119_SHIPPING_HOST_CONFLICT_NOT_REFUSED",
        &conflict,
    )?;

    let alternate = payload.join("alternate-astrolabe.exe");
    let mut shipping_reader = File::open(&shipping_host)?;
    let mut alternate_writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&alternate)?;
    let copied = std::io::copy(&mut shipping_reader, &mut alternate_writer)?;
    alternate_writer.sync_all()?;
    drop(alternate_writer);
    drop(shipping_reader);
    let alternate_input_before = optional_file_state(&alternate)?;
    let alternate_identity_before = capture_windows_file_identity(&alternate)?;
    require(
        alternate_input_before["sha256"] == Value::String(shipping_sha256.to_string())
            && alternate_input_before["bytes"].as_u64() == Some(copied)
            && (alternate_identity_before.volume_serial != verified_worker_identity.volume_serial
                || alternate_identity_before.file_id_128 != verified_worker_identity.file_id_128),
        "ISSUE_1146_ALTERNATE_WORKER_COPY_INVALID",
        json!({
            "copy": alternate_input_before,
            "copy_identity": alternate_identity_before,
            "bound_identity": verified_worker_identity,
        }),
    )?;
    let native_conflict_before = json!({
        "worker_binary_binding": configured_cbm_host_binary_path()?,
        "supervisor_should_wrap": supervisor_should_wrap(),
        "cache_tree": tree_state(&cache)?,
        "original_identity": capture_windows_file_identity(&shipping_host)?,
    });
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"distinct_file_identity_conflict",
            "phase":"before",
            "state":native_conflict_before,
            "input":alternate_input_before,
        }))?
    );
    let native_conflict_result = initialize_cbm_host_process_with_verified_worker(
        &alternate,
        shipping_sha256,
        &source_generation,
    );
    let alternate_input_after = optional_file_state(&alternate)?;
    let alternate_identity_after = capture_windows_file_identity(&alternate)?;
    let native_conflict_after = json!({
        "worker_binary_binding": configured_cbm_host_binary_path()?,
        "supervisor_should_wrap": supervisor_should_wrap(),
        "cache_tree": tree_state(&cache)?,
        "original_identity": capture_windows_file_identity(&shipping_host)?,
    });
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"distinct_file_identity_conflict",
            "phase":"after",
            "state":native_conflict_after,
            "input":alternate_input_after,
        }))?
    );
    let native_conflict = match native_conflict_result {
        Err(error) => error,
        Ok(binding) => {
            return Err(format!(
                "ISSUE_1146_DISTINCT_IDENTITY_UNEXPECTEDLY_SUCCEEDED: {binding:?}"
            )
            .into());
        }
    };
    require(
        native_conflict.envelope().code == "CBM_WORKER_BINARY_CONFLICT"
            && !native_conflict.envelope().message.trim().is_empty()
            && !native_conflict.envelope().remediation.trim().is_empty()
            && native_conflict_before == native_conflict_after
            && alternate_input_before == alternate_input_after
            && alternate_identity_before == alternate_identity_after
            && configured_cbm_host_binary_path()?.as_deref() == Some(shipping_host.as_path())
            && validate_verified_worker_binding(&verified_worker, &shipping_host)?
                == verified_worker_identity,
        "ISSUE_1146_DISTINCT_IDENTITY_CONFLICT_NOT_REFUSED",
        &native_conflict,
    )?;
    let transition_binding = verified_worker.clone();
    let worker_binding = json!({
        "configured": shipping_host_state,
        "verified_worker": verified_worker,
        "verified_worker_identity": verified_worker_identity,
        "supervisor_should_wrap": supervisor_should_wrap(),
        "readback": configured_cbm_host_binary_path()?,
        "conflicting_path": current,
        "conflict": conflict.into_envelope(),
        "conflict_before": conflict_before,
        "conflict_after": conflict_after,
        "conflict_input_before": conflict_input_before,
        "conflict_input_after": conflict_input_after,
        "distinct_identity_conflict": {
            "path": alternate,
            "before": native_conflict_before,
            "after": native_conflict_after,
            "input_before": alternate_input_before,
            "input_after": alternate_input_after,
            "identity_before": alternate_identity_before,
            "identity_after": alternate_identity_after,
            "error": native_conflict.into_envelope(),
        },
        "original_binding_preserved": true,
    });
    let runner = CbmToolRunner::new_default()?;
    let project = cbm_project_name_from_path(repo.to_str().ok_or("repo path is not UTF-8")?)?;

    let absent_before = binding_edge_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case": "index_happy", "phase": "before", "state": absent_before})
        )?
    );
    require(
        absent_before["config"]["exists"] == Value::Bool(false)
            && binding_project_artifacts_absent(&absent_before),
        "ISSUE_1116_1119_INDEX_PRESTATE_NOT_PRISTINE",
        &absent_before,
    )?;
    let (index_raw, index_envelope, index) =
        call_tool_with_raw(&runner, "index_repository", &index_request(&repo))?;
    require(
        index_envelope["isError"] != Value::Bool(true)
            && index["project"] == Value::String(project.clone()),
        "ISSUE_1116_1119_INDEX_FAILED",
        &index,
    )?;
    let canonical_repo = repo.canonicalize()?;
    let canonical_db = observed_cache.join(format!("{project}.db"));
    let index_transition = read_completed_transition(ReadCompletedTransitionRequest {
        cache: &cache,
        project: &project,
        canonical_root: &canonical_repo,
        canonical_db: &canonical_db,
        response_raw: &index_raw,
        response_envelope: &index_envelope,
        response_payload: &index,
        binding: &transition_binding,
        observation_path: None,
    })?;
    let index_after = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case": "index_happy", "phase": "after", "state": index_after})
        )?
    );
    require(
        moderate_semantic_response_matches_sqlite(&index, &index_after["state"]["sqlite"])
            && index_after["state"]["sqlite"]["nodes"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && index_after["state"]["sqlite"]["edges"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && index_after["state"]["sqlite"]["node_vectors"]
                .as_u64()
                .is_some_and(|count| count > 0),
        "ISSUE_1116_1119_INDEX_PHYSICAL_STATE_EMPTY",
        json!({
            "request": index_request(&repo),
            "response_semantic": {
                "index_mode": index["index_mode"],
                "semantic_search": index["semantic_search"],
                "semantic_vector_readback": index["semantic_vector_readback"],
            },
            "before": absent_before,
            "after": index_after,
        }),
    )?;

    let changed_symbol = fixture_changed_symbol(&cache, &project)?;
    let oracle_generation = oracle_generation_state(&cache, &project)?;
    let oracle_refusal_code = oracle_generation["gate"]["refusal_code"]
        .as_str()
        .ok_or("ISSUE_1116_1119_ORACLE_REFUSAL_CODE_MISSING")?;
    let oracle_backtest = run_predict_backtest(
        &runner,
        &cache,
        &project,
        &oracle_generation,
        "oracle_automatic_backtest_attestation",
    )?;
    let fixture_base_head = fixture["base_head"]
        .as_str()
        .ok_or("ISSUE_1116_1119_FIXTURE_BASE_HEAD_MISSING")?;
    let fixture_head = fixture["head"]
        .as_str()
        .ok_or("ISSUE_1116_1119_FIXTURE_HEAD_MISSING")?;
    let native_changed_detect = run_native_changed_detect(
        &runner,
        &cache,
        &project,
        fixture_base_head,
        fixture_head,
        &changed_symbol,
        "native_changed_symbol_generation",
    )?;
    let failed_gate_predict = run_failed_gate_predict(
        &runner,
        &cache,
        &project,
        &changed_symbol,
        oracle_refusal_code,
        "oracle_changed_symbol_failed_gate_refusal",
    )?;
    let changed_detect_gate_refusal = run_changed_detect_gate_refusal(
        &runner,
        &cache,
        &project,
        fixture_base_head,
        oracle_refusal_code,
        "detect_changes_changed_symbol_failed_gate_refusal",
    )?;

    let sim_terminal_attestation =
        exercise_sim_terminal_attestation_contract(&cache, &project, &payload)?;

    let repeat_before = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case": "index_repeat", "phase": "before", "state": repeat_before})
        )?
    );
    let (repeat_config_integrity_before, repeat_config_before) = config_rows(&cache, &project)?;
    let repeat_config_rows_before = ordered_config_rows(&repeat_config_before);
    let repeat_config_sha256_before = sha256(&serde_json::to_vec(&repeat_config_rows_before)?);
    let weave_generation = verify_weave_generation_receipt(&repeat_config_before, &project)?;
    let persisted_kernel_generation =
        persisted_kernel_generation_receipt(&repeat_config_before, &project)?;
    let transition_key = index_transition["key"]
        .as_str()
        .ok_or("ISSUE_1116_1119_TRANSITION_KEY_EVIDENCE_MISSING")?
        .to_string();
    let transition_raw = index_transition["raw"]
        .as_str()
        .ok_or("ISSUE_1116_1119_TRANSITION_RAW_EVIDENCE_MISSING")?
        .to_string();
    let publication_generation_key =
        format!("astrolabe.calyx.{project}.shadow_publication_generation");
    let publication_generation = repeat_config_before
        .get(&publication_generation_key)
        .ok_or("ISSUE_1116_1119_PUBLICATION_GENERATION_MISSING")?
        .clone();
    require(
        repeat_config_integrity_before == "ok"
            && repeat_config_before
                .get(&transition_key)
                .map(String::as_str)
                == Some(transition_raw.as_str()),
        "ISSUE_1116_1119_INDEX_REPEAT_CONFIG_PRESTATE_INVALID",
        json!({
            "integrity": repeat_config_integrity_before,
            "transition_key": transition_key,
            "transition_sha256": sha256(transition_raw.as_bytes()),
        }),
    )?;
    let (repeat_envelope, index_repeat) =
        call_tool(&runner, "index_repository", &index_request(&repo))?;
    require(
        repeat_envelope["isError"] != Value::Bool(true)
            && index_repeat["status"] == "unchanged"
            && index_repeat["index_admission"]["status"] == "cache_hit"
            && index_repeat["index_admission"]["writes_skipped"] == Value::Bool(true)
            && index_repeat["grounding_summary"]["status"] == "unchanged"
            && index_repeat["grounding_summary"]["writes_skipped"] == Value::Bool(true)
            && index_repeat["grounding_summary"]["noop_readback"]["config_rows"].as_u64()
                == u64::try_from(repeat_config_rows_before.len()).ok()
            && index_repeat["grounding_summary"]["noop_readback"]["config_rows_sha256"]
                == Value::String(repeat_config_sha256_before.clone())
            && index_repeat["grounding_summary"]["noop_readback"]["publication_generation"]
                == Value::String(publication_generation.clone()),
        "ISSUE_1116_1119_INDEX_REPEAT_FAILED",
        &index_repeat,
    )?;
    let (repeat_config_integrity_after, repeat_config_after) = config_rows(&cache, &project)?;
    let repeat_config_rows_after = ordered_config_rows(&repeat_config_after);
    let repeat_config_sha256_after = sha256(&serde_json::to_vec(&repeat_config_rows_after)?);
    let publication_generation_after = repeat_config_after
        .get(&publication_generation_key)
        .ok_or("ISSUE_1116_1119_PUBLICATION_GENERATION_AFTER_MISSING")?
        .clone();
    let weave_generation_after = verify_weave_generation_receipt(&repeat_config_after, &project)?;
    require(
        repeat_config_integrity_after == "ok"
            && repeat_config_after == repeat_config_before
            && repeat_config_rows_after == repeat_config_rows_before
            && repeat_config_sha256_after == repeat_config_sha256_before
            && publication_generation_after == publication_generation
            && weave_generation_after == weave_generation
            && repeat_config_after.get(&transition_key).map(String::as_str)
                == Some(transition_raw.as_str()),
        "ISSUE_1116_1119_INDEX_REPEAT_CONFIG_MUTATED",
        json!({
            "integrity_before": repeat_config_integrity_before,
            "integrity_after": repeat_config_integrity_after,
            "row_count_before": repeat_config_rows_before.len(),
            "row_count_after": repeat_config_rows_after.len(),
            "sha256_before": repeat_config_sha256_before,
            "sha256_after": repeat_config_sha256_after,
            "transition_key": transition_key,
        }),
    )?;
    let repeat_after = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case": "index_repeat", "phase": "after", "state": repeat_after})
        )?
    );
    require(
        repeat_before["sha256"] == repeat_after["sha256"],
        "ISSUE_1116_1119_INDEX_REPEAT_MUTATED_STATE",
        json!({
            "request": index_request(&repo),
            "response": index_repeat,
            "before": repeat_before,
            "after": repeat_after,
        }),
    )?;

    let architecture_clusters = exercise_architecture_clusters(&runner, &cache, &project)?;

    let search_request = json!({
        "project": project,
        "query": "normalize doubled reading bridge",
        "fusion": true,
        "k": 5,
        "ef": 32,
        "timeout_ms": 10_000,
    });
    let search_before = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"fused_search_first","phase":"before","state":search_before})
        )?
    );
    let (search_one_envelope, search_one) = call_tool(&runner, "search_graph", &search_request)?;
    require(
        search_one_envelope["isError"] != Value::Bool(true)
            && search_one["mode"] == Value::String("fused".to_string())
            && search_one["result_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && search_one["results"].as_array().is_some_and(|results| {
                results.iter().any(|result| {
                    result["qualified_name"]
                        .as_str()
                        .is_some_and(|name| name.contains("normalize") || name.contains("bridge"))
                        && result["contributions"]
                            .as_array()
                            .is_some_and(|contributions| {
                                contributions.iter().any(|contribution| {
                                    contribution["slot"] == 18 || contribution["slot"] == 20
                                })
                            })
                })
            })
            && search_one["servable_slots"]
                .as_array()
                .is_some_and(|slots| slots.iter().any(|slot| slot == 18 || slot == 20)),
        "ISSUE_1116_1119_FUSED_SEARCH_FAILED",
        &search_one,
    )?;
    let search_middle = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"fused_search_first","phase":"after","state":search_middle})
        )?
    );
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"fused_search_repeat","phase":"before","state":search_middle})
        )?
    );
    let (search_two_envelope, search_two) = call_tool(&runner, "search_graph", &search_request)?;
    require(
        search_two_envelope["isError"] != Value::Bool(true)
            && search_two["results"] == search_one["results"]
            && search_two["manifest"]["content_hash"] == search_one["manifest"]["content_hash"],
        "ISSUE_1116_1119_FUSED_SEARCH_REPEAT_MISMATCH",
        &search_two,
    )?;
    let search_after = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"fused_search_repeat","phase":"after","state":search_after})
        )?
    );
    require(
        search_middle["sha256"] == search_after["sha256"],
        "ISSUE_1116_1119_FUSED_SEARCH_REPEAT_MUTATED_STATE",
        &search_after,
    )?;

    let latent_request = json!({
        "project": project,
        "mode": "sweep",
        "relation": "undirected",
        "min_shared_intermediaries": 1,
        "top_k": 10,
    });
    let latent_before = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"latent_write","phase":"before","state":latent_before})
        )?
    );
    let (latent_one_envelope, latent_one) =
        call_tool(&runner, "discover_latent_links", &latent_request)?;
    require(
        latent_one_envelope["isError"] != Value::Bool(true)
            && latent_one["pair_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && latent_one["persistence"]["state"] == Value::String("written".to_string())
            && latent_one["persistence"]["rows_read_back_verified"] == 2,
        "ISSUE_1116_1119_LATENT_WRITE_FAILED",
        &latent_one,
    )?;
    let latent_middle = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"latent_write","phase":"after","state":latent_middle})
        )?
    );
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"latent_repeat","phase":"before","state":latent_middle})
        )?
    );
    let (latent_two_envelope, latent_two) =
        call_tool(&runner, "discover_latent_links", &latent_request)?;
    require(
        latent_two_envelope["isError"] != Value::Bool(true)
            && latent_two["persistence"]["state"] == Value::String("unchanged".to_string())
            && latent_two["persistence"]["request_sha256"]
                == latent_one["persistence"]["request_sha256"]
            && latent_two["persistence"]["ledger_ref"] == latent_one["persistence"]["ledger_ref"],
        "ISSUE_1116_1119_LATENT_REPEAT_MISMATCH",
        &latent_two,
    )?;
    let latent_after = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"latent_repeat","phase":"after","state":latent_after})
        )?
    );
    require(
        latent_middle["sha256"] == latent_after["sha256"],
        "ISSUE_1116_1119_LATENT_REPEAT_MUTATED_STATE",
        &latent_after,
    )?;

    let discovery_budgets = discovery_fsv_budgets()?;
    let discovery_evaluator_id = required_fsv_env("ASTRO_ASSOCIATION_FSV_EVALUATOR_ID")?;
    let discovery_model_id = required_fsv_env("ASTRO_ASSOCIATION_FSV_MODEL_ID")?;
    let discovery_request_one = discovery_prepare_request(
        &project,
        1,
        &discovery_budgets,
        &discovery_evaluator_id,
        &discovery_model_id,
    );
    let discovery_request_two = discovery_prepare_request(
        &project,
        2,
        &discovery_budgets,
        &discovery_evaluator_id,
        &discovery_model_id,
    );
    let discovery_prepublication_edges = vec![
        expect_refusal(
            &runner,
            &cache,
            &project,
            "discovery_prepare_without_budgets",
            "discover_associations",
            &json!({
                "project": project,
                "mode": "prepare",
                "workers": 1,
                "cross_validation_folds": 32,
                "top_k": 5,
                "min_shared_intermediaries": 1,
                "evaluator_declarations": discovery_request_one["evaluator_declarations"],
            }),
            "ASTRO_DISCOVERY_BUDGETS_REQUIRED",
        )?,
        expect_refusal(
            &runner,
            &cache,
            &project,
            "discovery_prepare_with_receipts",
            "discover_associations",
            &json!({
                "project": project,
                "mode": "prepare",
                "workers": 1,
                "cross_validation_folds": 32,
                "top_k": 5,
                "min_shared_intermediaries": 1,
                "budgets": discovery_budgets,
                "evaluator_declarations": discovery_request_one["evaluator_declarations"],
                "evaluator_receipts": [],
            }),
            "ASTRO_DISCOVERY_ARGUMENT_UNEXPECTED",
        )?,
    ];
    let discovery_before = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"association_prepare","phase":"before","state":discovery_before})
        )?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"association_prepare",
            "phase":"action",
            "tool":"discover_associations",
            "request":discovery_request_one,
        }))?
    );
    let (discovery_one_envelope, discovery_one) =
        call_tool(&runner, "discover_associations", &discovery_request_one)?;
    require(
        discovery_one_envelope["isError"] != Value::Bool(true)
            && discovery_one["status"] == Value::String("prepared".to_string())
            && discovery_one["candidate_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && discovery_one["performance"]["prepared_cache_hit"] == Value::Bool(false)
            && discovery_one["performance"]["graph_compiles_this_call"] == 1
            && discovery_one["persistence"]["state"] == Value::String("written".to_string()),
        "ISSUE_1116_1119_DISCOVERY_PREPARE_FAILED",
        &discovery_one,
    )?;
    let discovery_one_export =
        persist_discovery_external_requests(&payload, &discovery_request_one, &discovery_one)?;
    let discovery_middle = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"association_prepare","phase":"after","state":discovery_middle})
        )?
    );
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"association_prepare_second","phase":"before","state":discovery_middle})
        )?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"association_prepare_second",
            "phase":"action",
            "tool":"discover_associations",
            "request":discovery_request_two,
        }))?
    );
    let (discovery_two_envelope, discovery_two) =
        call_tool(&runner, "discover_associations", &discovery_request_two)?;
    require(
        discovery_two_envelope["isError"] != Value::Bool(true)
            && discovery_two["status"] == "prepared"
            && discovery_two["prepared_artifact_sha256"]
                != discovery_one["prepared_artifact_sha256"]
            && discovery_two["source_generation_sha256"]
                == discovery_one["source_generation_sha256"]
            && discovery_two["performance"]["prepared_cache_hit"] == Value::Bool(false)
            && discovery_two["performance"]["graph_compiles_this_call"] == 1
            && discovery_two["persistence"]["state"] == Value::String("written".to_string()),
        "ISSUE_1116_1119_DISCOVERY_SECOND_PREPARE_MISMATCH",
        &discovery_two,
    )?;
    let discovery_two_export =
        persist_discovery_external_requests(&payload, &discovery_request_two, &discovery_two)?;
    let discovery_second = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"association_prepare_second","phase":"after","state":discovery_second})
        )?
    );
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"association_repeat","phase":"before","state":discovery_second})
        )?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"association_repeat",
            "phase":"action",
            "tool":"discover_associations",
            "request":discovery_request_two,
        }))?
    );
    let (discovery_repeat_envelope, discovery_repeat) =
        call_tool(&runner, "discover_associations", &discovery_request_two)?;
    require(
        discovery_repeat_envelope["isError"] != Value::Bool(true)
            && discovery_repeat["prepared_artifact_sha256"]
                == discovery_two["prepared_artifact_sha256"]
            && discovery_repeat["performance"]["prepared_cache_hit"] == Value::Bool(true)
            && discovery_repeat["performance"]["graph_compiles_this_call"] == 0
            && discovery_repeat["persistence"]["state"] == Value::String("unchanged".to_string()),
        "ISSUE_1116_1119_DISCOVERY_REPEAT_MISMATCH",
        &discovery_repeat,
    )?;
    let discovery_after = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"association_repeat","phase":"after","state":discovery_after})
        )?
    );
    require(
        discovery_second["sha256"] == discovery_after["sha256"],
        "ISSUE_1116_1119_DISCOVERY_REPEAT_MUTATED_STATE",
        &discovery_after,
    )?;

    let mut edges = discovery_prepublication_edges;
    edges.extend([
        expect_refusal(
            &runner,
            &cache,
            &project,
            "latent_missing_seed",
            "discover_latent_links",
            &json!({"project": project, "mode": "open", "relation": "undirected"}),
            "ASTRO_LATENT_SEED_REQUIRED",
        )?,
        expect_refusal(
            &runner,
            &cache,
            &project,
            "latent_unresolved_seed",
            "discover_latent_links",
            &json!({
                "project": project,
                "mode": "open",
                "relation": "undirected",
                "seed": "fixture::definitely_absent",
            }),
            "ASTRO_LATENT_SYMBOL_UNRESOLVED",
        )?,
        expect_refusal(
            &runner,
            &cache,
            &project,
            "discovery_publish_without_hash",
            "discover_associations",
            &json!({"project": project, "mode": "publish"}),
            "ASTRO_DISCOVERY_PREPARED_HASH_REQUIRED",
        )?,
        expect_refusal(
            &runner,
            &cache,
            &project,
            "discovery_read_without_final",
            "discover_associations",
            &json!({"project": project, "mode": "read"}),
            "ASTRO_DISCOVERY_CURRENT_MISSING",
        )?,
        expect_refusal(
            &runner,
            &cache,
            &project,
            "fused_search_non_shadow_project",
            "search_graph",
            &json!({"project": "fixture-project-absent", "query": "reading", "fusion": true}),
            "ASTRO_SEARCH_FUSION_SHADOW",
        )?,
        expect_refusal(
            &runner,
            &cache,
            &project,
            "kernel_build_non_fleet_scope",
            "get_kernel",
            &json!({
                "project": project,
                "mode": "build",
                "scope": format!("repo:{project}:manual-subgraph"),
                "kernel_admission": kernel_admission(),
            }),
            "ASTRO_KERNEL_BUILD_SCOPE_UNSUPPORTED",
        )?,
    ]);
    let malformed_lowering = exercise_malformed_lowering(&runner, &cache, &project)?;

    let kernel_generation = verify_complete_kernel_generation(
        &cache,
        &project,
        &kernel_admission(),
        &persisted_kernel_generation,
    )?;
    let final_state = physical_state(&cache, &project)?;
    let fixture_after = fixture_source_state(&repo)?;
    require(
        fixture_after == fixture["source"],
        "ISSUE_1116_1119_FIXTURE_SOURCE_MUTATED",
        &fixture_after,
    )?;
    let repeat_response_sha256 = sha256(&serde_json::to_vec(&repeat_envelope)?);
    let execution = json!({
        "schema": "astrolabe.issues-1116-1119.execute.v1",
        "tree_sha": tree_sha,
        "source_generation_schema": worker_source_generation::SOURCE_GENERATION_SCHEMA,
        "source_generation_sha256": source_generation,
        "driver_artifact": driver_artifact,
        "project": project,
        "repo": repo,
        "cache": cache,
        "shipping_host": worker_binding,
        "fixture": fixture,
        "fixture_after": fixture_after,
        "source_of_truth": "fresh config including the exact successful project-transition row, persisted complete-kernel publication receipt, and SQLite-family evidence; CBM/lowered SQLite including the complete nodes plus CALLS/IMPORTS clustering projection; independently rebuilt clustering label/source/projection/result hashes and complete member roster; physical Aster Graph/XTerm/Kernel/Assay/Ledger/Anchors/Kv/Compression/S20 rows; exact SIM family raw bytes, terminal markers, point-read Ledger rows, and composite-CSR family refs plus isolated byte-identical-clone no-delta/bootstrap/malformed/stale/CAS transactions; the composite current pointer, manifest, eight generation rows and aliases, checksum-validated member HNSW, independently re-encoded real-query corpus and exact graph-routed report rebuild; real persisted KernelGraph bytes with fail-closed delta/region probes and an exact structural full-rebuild artifact/FVS/source byte comparison; the search manifest; and two exact prepared-v4 association generations whose externally invocable request rosters are persisted without fabricated responses",
        "absent_before": absent_before,
        "index": {
            "raw": {
                "text": index_raw,
                "bytes": index_raw.len(),
                "sha256": sha256(index_raw.as_bytes()),
            },
            "envelope": index_envelope,
            "response": index,
            "transition": index_transition,
            "after": index_after,
            "weave_generation": weave_generation,
            "kernel_generation": kernel_generation,
        },
        "oracle": {
            "generation": oracle_generation,
            "changed_symbol": changed_symbol,
            "backtest": oracle_backtest,
            "native_changed_detect": native_changed_detect,
            "failed_gate_predict": failed_gate_predict,
            "changed_detect_gate_refusal": changed_detect_gate_refusal,
            "genuine_ci_anchor_available": false,
            "grounded_success_claimed": false,
        },
        "index_repeat": {
            "envelope": repeat_envelope,
            "response": index_repeat,
            "response_sha256": repeat_response_sha256,
            "config_before": {
                "integrity": repeat_config_integrity_before,
                "row_count": repeat_config_rows_before.len(),
                "sha256": repeat_config_sha256_before,
                "publication_generation": publication_generation,
                "transition_sha256": sha256(transition_raw.as_bytes()),
            },
            "config_after": {
                "integrity": repeat_config_integrity_after,
                "row_count": repeat_config_rows_after.len(),
                "sha256": repeat_config_sha256_after,
                "publication_generation": publication_generation_after,
                "transition_sha256": sha256(transition_raw.as_bytes()),
            },
            "before": repeat_before,
            "after": repeat_after,
        },
        "sim_terminal_attestation": sim_terminal_attestation,
        "architecture_clusters": architecture_clusters,
        "search": {
            "request": search_request,
            "first": search_one,
            "second": search_two,
            "before": search_before,
            "middle": search_middle,
            "after": search_after,
        },
        "latent": {
            "request": latent_request,
            "first": latent_one,
            "second": latent_two,
            "before": latent_before,
            "middle": latent_middle,
            "after": latent_after,
        },
        "discovery": {
            "budgets": discovery_budgets,
            "evaluator_id": discovery_evaluator_id,
            "model_id": discovery_model_id,
            "requests": [discovery_request_one, discovery_request_two],
            "prepared": [discovery_one, discovery_two],
            "repeat": discovery_repeat,
            "request_exports": [discovery_one_export, discovery_two_export],
            "before": discovery_before,
            "middle": discovery_middle,
            "second": discovery_second,
            "after": discovery_after,
        },
        "edges": edges,
        "malformed_lowering": malformed_lowering,
        "final_state": final_state,
    });
    let execution_bytes = serde_json::to_vec_pretty(&execution)?;
    let execution_receipt = write_new_readback(&payload.join("execution.json"), &execution_bytes)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event": "ISSUE_1116_1119_EXECUTE_COMPLETE",
            "execution": execution_receipt,
            "project": execution["project"],
            "association_capture_required": true,
            "association_prepared_hashes": [
                execution["discovery"]["prepared"][0]["prepared_artifact_sha256"],
                execution["discovery"]["prepared"][1]["prepared_artifact_sha256"],
            ],
            "kernel_generation_id": execution["index"]["kernel_generation"]["generation_id"],
            "kernel_members": execution["index"]["kernel_generation"]["artifact"]["member_count"],
            "kernel_graph_nodes": execution["index"]["kernel_generation"]["s20_complete_graph_roster"]["graph_node_count"],
            "kernel_s20_vectors": execution["index"]["kernel_generation"]["s20_complete_graph_roster"]["physical_vector_count"],
            "kernel_real_queries": execution["index"]["kernel_generation"]["query_corpus"]["queries"].as_array().map_or(0, Vec::len),
            "kernel_recall_permille": execution["index"]["kernel_generation"]["graph_routed_report"]["recall_permille"],
            "cluster_sqlite_nodes": execution["architecture_clusters"]["source"]["node_count"],
            "cluster_sqlite_calls": execution["architecture_clusters"]["source"]["calls_edge_count"],
            "cluster_sqlite_imports": execution["architecture_clusters"]["source"]["imports_edge_count"],
            "cluster_communities": execution["architecture_clusters"]["exact"]["proof"]["community_count"],
            "cluster_source_sha256": execution["architecture_clusters"]["exact"]["proof"]["source_sha256"],
            "cluster_projection_sha256": execution["architecture_clusters"]["exact"]["proof"]["projection_sha256"],
            "cluster_result_sha256": execution["architecture_clusters"]["exact"]["proof"]["result_sha256"],
            "pre_capture_state_sha256": execution["final_state"]["sha256"],
        }))?
    );
    Ok(())
}

fn publish_genuine_discovery_generation(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    prepared: &Value,
    receipts: Value,
) -> AnyResult<(Value, Value, Value)> {
    let prepared_hash = prepared["prepared_artifact_sha256"]
        .as_str()
        .ok_or("ISSUE_1150_PREPARED_HASH_MISSING")?;
    let request = json!({
        "project": project,
        "mode": "publish",
        "prepared_artifact_sha256": prepared_hash,
        "evaluator_receipts": receipts,
    });
    let before = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": format!("association_publish_{prepared_hash}"),
            "phase": "before",
            "state": before,
        }))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": format!("association_publish_{prepared_hash}"),
            "phase": "action",
            "tool": "discover_associations",
            "request": request,
        }))?
    );
    let (envelope, response) = call_tool(runner, "discover_associations", &request)?;
    require(
        envelope["isError"] != Value::Bool(true)
            && response["schema"] == "astrolabe.discover_associations.v4"
            && response["status"] == "published"
            && response["project"] == project
            && response["prepared_artifact_sha256"] == prepared_hash
            && response["source_generation_sha256"] == prepared["source_generation_sha256"]
            && response["artifact_sha256"]
                .as_str()
                .is_some_and(|value| value.len() == 64)
            && response["persistence"]["schema"] == DISCOVERY_PERSISTED_SCHEMA_V3
            && matches!(
                response["persistence"]["state"].as_str(),
                Some("written" | "unchanged")
            )
            && response["persistence"]["ledger_paired"] == Value::Bool(true),
        "ISSUE_1150_GENUINE_DISCOVERY_PUBLICATION_FAILED",
        &response,
    )?;
    let after = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": format!("association_publish_{prepared_hash}"),
            "phase": "after",
            "state": after,
        }))?
    );
    require(
        (response["persistence"]["state"] == "written" && before["sha256"] != after["sha256"])
            || (response["persistence"]["state"] == "unchanged" && before == after),
        "ISSUE_1150_DISCOVERY_PUBLICATION_STATE_TRANSITION_MISMATCH",
        json!({"before": before, "after": after}),
    )?;
    Ok((request, response, after))
}

fn initialize_association_fsv_worker(execution: &Value) -> AnyResult<(CbmToolRunner, Value)> {
    let cache = PathBuf::from(
        execution["cache"]
            .as_str()
            .ok_or("ISSUE_1150_EXECUTION_CACHE_MISSING")?,
    );
    set_cbm_cache_dir(&cache)?;
    require(
        configured_cbm_host_binary_path()?.is_none() && !supervisor_should_wrap(),
        "ISSUE_1150_ASSOCIATION_PROCESS_PRESTATE_INVALID",
        "a fresh association-publish process already had a binary binding or supervisor role",
    )?;
    let source_generation = current_source_generation_sha256()?;
    let (shipping_host, shipping_state) = shipping_astrolabe_executable()?;
    let shipping_sha256 = shipping_state["sha256"]
        .as_str()
        .ok_or("ISSUE_1150_SHIPPING_SHA256_MISSING")?;
    let worker = initialize_cbm_host_process_with_verified_worker(
        &shipping_host,
        shipping_sha256,
        &source_generation,
    )?;
    let identity = validate_verified_worker_binding(&worker, &shipping_host)?;
    require(
        execution["tree_sha"] == Value::String(canonical_head()?)
            && execution["driver_artifact"] == current_driver_artifact_state()?
            && execution["source_generation_sha256"] == source_generation
            && source_generation == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256
            && execution["shipping_host"]["configured"] == shipping_state,
        "ISSUE_1150_ASSOCIATION_EXECUTION_BINDING_MISMATCH",
        json!({"shipping_host": shipping_host, "source_generation": source_generation}),
    )?;
    Ok((
        CbmToolRunner::new_default()?,
        json!({
            "binding": worker,
            "physical_identity": identity,
            "artifact": shipping_state,
        }),
    ))
}

fn association_publish(payload: PathBuf) -> AnyResult<()> {
    let execution_path = payload.join("execution.json");
    let execution_bytes = fs::read(&execution_path)?;
    let execution: Value = serde_json::from_slice(&execution_bytes)?;
    require(
        execution["schema"] == "astrolabe.issues-1116-1119.execute.v1"
            && PathBuf::from(
                execution["repo"]
                    .as_str()
                    .ok_or("ISSUE_1150_EXECUTION_REPO_MISSING")?,
            ) == payload.join("real-rust-repo")
            && PathBuf::from(
                execution["cache"]
                    .as_str()
                    .ok_or("ISSUE_1150_EXECUTION_CACHE_MISSING")?,
            ) == payload.join("real-cache"),
        "ISSUE_1150_ASSOCIATION_EXECUTION_INVALID",
        &execution,
    )?;
    let cache = PathBuf::from(
        execution["cache"]
            .as_str()
            .ok_or("ISSUE_1150_EXECUTION_CACHE_MISSING")?,
    );
    let project = execution["project"]
        .as_str()
        .ok_or("ISSUE_1150_EXECUTION_PROJECT_MISSING")?;
    let wave_one_path = payload.join("association-publish-wave-1.json");
    let wave_two_path = payload.join("association-publish-wave-2.json");
    require(
        !wave_two_path.exists(),
        "ISSUE_1150_ASSOCIATION_PUBLICATION_ALREADY_COMPLETE",
        "the three genuine generations are already published and physically read back",
    )?;
    let (runner, worker) = initialize_association_fsv_worker(&execution)?;
    if !wave_one_path.exists() {
        let prepared = execution["discovery"]["prepared"]
            .as_array()
            .filter(|values| values.len() == 2)
            .ok_or("ISSUE_1150_INITIAL_PREPARED_ROSTER_INVALID")?;
        let requests = execution["discovery"]["requests"]
            .as_array()
            .filter(|values| values.len() == 2)
            .ok_or("ISSUE_1150_INITIAL_REQUEST_ROSTER_INVALID")?;
        let capture_preflight_before = physical_state(&cache, project)?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "case":"association_external_capture_preflight_one",
                "phase":"before",
                "state":capture_preflight_before,
            }))?
        );
        println!(
            "{}",
            serde_json::to_string(&json!({
                "case":"association_external_capture_preflight_one",
                "phase":"action",
                "operation":"read_and_strictly_reparse_all_genuine_external_capture_files_before_any_publication",
                "prepared_artifact_sha256":[prepared[0]["prepared_artifact_sha256"],prepared[1]["prepared_artifact_sha256"]],
            }))?
        );
        let captures_and_receipts_result = requests
            .iter()
            .zip(prepared)
            .map(|(request, generation)| {
                load_genuine_discovery_capture(&payload, request, generation)
            })
            .collect::<AnyResult<Vec<_>>>();
        let capture_preflight_after = physical_state(&cache, project)?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "case":"association_external_capture_preflight_one",
                "phase":"after",
                "state":capture_preflight_after,
            }))?
        );
        require(
            capture_preflight_before == capture_preflight_after,
            "ISSUE_1150_EXTERNAL_CAPTURE_PREFLIGHT_MUTATED_STATE",
            json!({"before":capture_preflight_before,"after":capture_preflight_after}),
        )?;
        let captures_and_receipts = captures_and_receipts_result?;
        let receipt_rosters = captures_and_receipts
            .iter()
            .map(|(receipts, _)| receipts.clone())
            .collect::<Vec<_>>();
        let mut captures = Vec::new();
        let mut publications = Vec::new();
        for ((_, generation), (receipts, capture)) in
            requests.iter().zip(prepared).zip(captures_and_receipts)
        {
            let (publish_request, response, after) = publish_genuine_discovery_generation(
                &runner, &cache, project, generation, receipts,
            )?;
            captures.push(capture);
            publications.push(json!({
                "request": publish_request,
                "response": response,
                "after": after,
            }));
        }
        let retained_before = discovery_retention_state(&cache, project, &[])?;
        require(
            retained_before["prepared"]["pointer"]["retained_generation_count"] == 2
                && retained_before["final"]["pointer"]["retained_generation_count"] == 2
                && retained_before["prepared"]["current"]["target"]["artifact_sha256"]
                    == prepared[1]["prepared_artifact_sha256"]
                && retained_before["prepared"]["previous"]["target"]["artifact_sha256"]
                    == prepared[0]["prepared_artifact_sha256"]
                && retained_before["final"]["current"]["target"]["artifact_sha256"]
                    == publications[1]["response"]["artifact_sha256"]
                && retained_before["final"]["previous"]["target"]["artifact_sha256"]
                    == publications[0]["response"]["artifact_sha256"]
                && retained_before["final"]["current"]["evaluator_receipts"] == receipt_rosters[1]
                && retained_before["final"]["previous"]["evaluator_receipts"] == receipt_rosters[0],
            "ISSUE_1150_INITIAL_CURRENT_PREVIOUS_RETENTION_MISMATCH",
            &retained_before,
        )?;
        let third_request = discovery_prepare_request(
            project,
            3,
            &execution["discovery"]["budgets"],
            execution["discovery"]["evaluator_id"]
                .as_str()
                .ok_or("ISSUE_1150_EXECUTION_EVALUATOR_ID_MISSING")?,
            execution["discovery"]["model_id"]
                .as_str()
                .ok_or("ISSUE_1150_EXECUTION_MODEL_ID_MISSING")?,
        );
        let before_third_prepare = physical_state(&cache, project)?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "case": "association_prepare_third_retention",
                "phase": "before",
                "state": before_third_prepare,
            }))?
        );
        println!(
            "{}",
            serde_json::to_string(&json!({
                "case": "association_prepare_third_retention",
                "phase": "action",
                "tool": "discover_associations",
                "request": third_request,
            }))?
        );
        let (third_envelope, third_prepared) =
            call_tool(&runner, "discover_associations", &third_request)?;
        require(
            third_envelope["isError"] != Value::Bool(true)
                && third_prepared["schema"] == "astrolabe.discover_associations.v4"
                && third_prepared["status"] == "prepared"
                && third_prepared["persistence"]["schema"] == DISCOVERY_PERSISTED_SCHEMA_V3
                && third_prepared["persistence"]["state"] == "written"
                && prepared.iter().all(|prior| {
                    prior["prepared_artifact_sha256"] != third_prepared["prepared_artifact_sha256"]
                }),
            "ISSUE_1150_THIRD_PREPARE_FAILED",
            &third_prepared,
        )?;
        let third_export =
            persist_discovery_external_requests(&payload, &third_request, &third_prepared)?;
        let after_third_prepare = physical_state(&cache, project)?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "case": "association_prepare_third_retention",
                "phase": "after",
                "state": after_third_prepare,
            }))?
        );
        let retired = vec![
            json!({"kind":"prepared", "artifact_sha256":prepared[0]["prepared_artifact_sha256"], "persistence":prepared[0]["persistence"]}),
            json!({"kind":"final", "artifact_sha256":publications[0]["response"]["artifact_sha256"], "persistence":publications[0]["response"]["persistence"]}),
        ];
        let retained_after = discovery_retention_state(&cache, project, &retired)?;
        require(
            retained_after["prepared"]["pointer"]["retained_generation_count"] == 2
                && retained_after["prepared"]["current"]["target"]["artifact_sha256"]
                    == third_prepared["prepared_artifact_sha256"]
                && retained_after["prepared"]["previous"]["target"]["artifact_sha256"]
                    == prepared[1]["prepared_artifact_sha256"]
                && retained_after["final"]["pointer"]["retained_generation_count"] == 1
                && retained_after["final"]["current"]["target"]["artifact_sha256"]
                    == publications[1]["response"]["artifact_sha256"]
                && retained_after["final"]["previous"].is_null()
                && retained_after["retired"]
                    .as_array()
                    .is_some_and(|rows| rows.len() == 2)
                && retained_after["retired_exact_tombstones_verified"] == Value::Bool(true),
            "ISSUE_1150_CROSS_KIND_RETENTION_MISMATCH",
            &retained_after,
        )?;
        let wave = json!({
            "schema": DISCOVERY_FSV_WAVE_SCHEMA,
            "wave": 1,
            "tree_sha": execution["tree_sha"],
            "execution": {"path": execution_path, "bytes": execution_bytes.len(), "sha256": sha256(&execution_bytes)},
            "worker": worker,
            "captures": captures,
            "publications": publications,
            "retention_before_third_prepare": retained_before,
            "third": {"request":third_request, "prepared":third_prepared, "request_export":third_export},
            "retired": retired,
            "retention_after_third_prepare": retained_after,
            "before_third_prepare": before_third_prepare,
            "after_third_prepare": after_third_prepare,
            "next_capture_required": true,
        });
        let persisted = write_new_readback(&wave_one_path, &serde_json::to_vec_pretty(&wave)?)?;
        println!(
            "{}",
            serde_json::to_string(&json!({
                "event":"ISSUE_1150_ASSOCIATION_PUBLISH_WAVE_ONE_COMPLETE",
                "receipt":persisted,
                "next_prepared_artifact_sha256":wave["third"]["prepared"]["prepared_artifact_sha256"],
                "genuine_external_capture_required":true,
            }))?
        );
        return Ok(());
    }

    let wave_one_bytes = fs::read(&wave_one_path)?;
    let wave_one: Value = serde_json::from_slice(&wave_one_bytes)?;
    require(
        wave_one["schema"] == DISCOVERY_FSV_WAVE_SCHEMA
            && wave_one["wave"] == 1
            && wave_one["tree_sha"] == execution["tree_sha"]
            && wave_one["execution"]["sha256"] == Value::String(sha256(&execution_bytes)),
        "ISSUE_1150_ASSOCIATION_WAVE_ONE_INVALID",
        &wave_one,
    )?;
    let third_request = &wave_one["third"]["request"];
    let third_prepared = &wave_one["third"]["prepared"];
    let capture_preflight_before = physical_state(&cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"association_external_capture_preflight_two",
            "phase":"before",
            "state":capture_preflight_before,
        }))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"association_external_capture_preflight_two",
            "phase":"action",
            "operation":"read_and_strictly_reparse_the_final_genuine_external_capture_file_before_publication",
            "prepared_artifact_sha256":third_prepared["prepared_artifact_sha256"],
        }))?
    );
    let third_capture_result =
        load_genuine_discovery_capture(&payload, third_request, third_prepared);
    let capture_preflight_after = physical_state(&cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"association_external_capture_preflight_two",
            "phase":"after",
            "state":capture_preflight_after,
        }))?
    );
    require(
        capture_preflight_before == capture_preflight_after,
        "ISSUE_1150_EXTERNAL_CAPTURE_PREFLIGHT_MUTATED_STATE",
        json!({"before":capture_preflight_before,"after":capture_preflight_after}),
    )?;
    let (third_receipts, third_capture) = third_capture_result?;
    let (third_publish_request, third_published, third_after) =
        publish_genuine_discovery_generation(
            &runner,
            &cache,
            project,
            third_prepared,
            third_receipts.clone(),
        )?;
    let retired = wave_one["retired"]
        .as_array()
        .ok_or("ISSUE_1150_RETIRED_ROSTER_MISSING")?;
    let final_retention = discovery_retention_state(&cache, project, retired)?;
    let read_request = json!({
        "project": project,
        "mode": "read",
        "prepared_artifact_sha256": third_published["artifact_sha256"],
        "section": "all",
    });
    let read_before = physical_state(&cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"association_final_read",
            "phase":"before",
            "state":read_before,
        }))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"association_final_read",
            "phase":"action",
            "tool":"discover_associations",
            "request":read_request,
        }))?
    );
    let (read_envelope, read_response) =
        call_tool(&runner, "discover_associations", &read_request)?;
    let read_after = physical_state(&cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"association_final_read",
            "phase":"after",
            "state":read_after,
        }))?
    );
    require(
        read_envelope["isError"] != Value::Bool(true)
            && read_response["schema"] == "astrolabe.discover_associations.v4"
            && read_response["status"] == "read"
            && read_response["artifact_sha256"] == third_published["artifact_sha256"]
            && read_response["physical_readback_sha256"] == third_published["artifact_sha256"]
            && read_response["value"]["artifact"]["schema"] == DISCOVERY_FINAL_SCHEMA_V4
            && read_response["value"]["artifact"]["evaluator_receipts"] == third_receipts
            && read_before == read_after,
        "ISSUE_1150_FINAL_DISCOVERY_READBACK_FAILED",
        json!({"response":read_response,"before":read_before,"after":read_after}),
    )?;
    let first_final_hash = wave_one["publications"][0]["response"]["artifact_sha256"]
        .as_str()
        .ok_or("ISSUE_1150_FIRST_FINAL_HASH_MISSING")?;
    let mut invalid_receipts = third_receipts.clone();
    invalid_receipts[0]
        .as_object_mut()
        .ok_or("ISSUE_1150_CAPTURE_RECEIPT_NOT_OBJECT")?
        .remove("provider_response_id");
    let mut extra_receipts = third_receipts.clone();
    extra_receipts
        .as_array_mut()
        .ok_or("ISSUE_1150_CAPTURE_RECEIPTS_NOT_ARRAY")?
        .push(third_receipts[0].clone());
    let mut response_hash_mismatch = third_receipts.clone();
    response_hash_mismatch[0]["response_sha256"] = Value::String(ZERO_SHA256.to_string());
    let mut postpublication_edges = vec![
        expect_refusal(
            &runner,
            &cache,
            project,
            "discovery_publish_without_receipts",
            "discover_associations",
            &json!({"project":project,"mode":"publish","prepared_artifact_sha256":third_prepared["prepared_artifact_sha256"]}),
            "ASTRO_DISCOVERY_EVALUATOR_REQUIRED",
        )?,
        expect_refusal(
            &runner,
            &cache,
            project,
            "discovery_publish_empty_receipt_roster",
            "discover_associations",
            &json!({"project":project,"mode":"publish","prepared_artifact_sha256":third_prepared["prepared_artifact_sha256"],"evaluator_receipts":[]}),
            "ASTRO_DISCOVERY_EVALUATOR_RECEIPT_BUDGET_EXCEEDED",
        )?,
        expect_refusal(
            &runner,
            &cache,
            project,
            "discovery_publish_extra_receipt",
            "discover_associations",
            &json!({"project":project,"mode":"publish","prepared_artifact_sha256":third_prepared["prepared_artifact_sha256"],"evaluator_receipts":extra_receipts}),
            "ASTRO_DISCOVERY_EVALUATOR_RECEIPT_BUDGET_EXCEEDED",
        )?,
        expect_refusal(
            &runner,
            &cache,
            project,
            "discovery_publish_missing_provider_identity",
            "discover_associations",
            &json!({"project":project,"mode":"publish","prepared_artifact_sha256":third_prepared["prepared_artifact_sha256"],"evaluator_receipts":invalid_receipts}),
            "ASTRO_DISCOVERY_EVALUATOR_RECEIPTS_INVALID",
        )?,
        expect_refusal(
            &runner,
            &cache,
            project,
            "discovery_publish_response_hash_mismatch",
            "discover_associations",
            &json!({"project":project,"mode":"publish","prepared_artifact_sha256":third_prepared["prepared_artifact_sha256"],"evaluator_receipts":response_hash_mismatch}),
            "ASTRO_DISCOVERY_EVALUATOR_INVALID",
        )?,
        expect_refusal(
            &runner,
            &cache,
            project,
            "discovery_read_retired_final",
            "discover_associations",
            &json!({"project":project,"mode":"read","prepared_artifact_sha256":first_final_hash,"section":"all"}),
            "ASTRO_DISCOVERY_FINAL_NOT_RETAINED",
        )?,
        expect_refusal(
            &runner,
            &cache,
            project,
            "discovery_read_unknown_section",
            "discover_associations",
            &json!({"project":project,"mode":"read","prepared_artifact_sha256":third_published["artifact_sha256"],"section":"not-a-section"}),
            "ASTRO_DISCOVERY_SECTION_UNSUPPORTED",
        )?,
    ];
    if third_receipts
        .as_array()
        .is_some_and(|values| values.len() > 1)
    {
        let mut duplicate_invocation = third_receipts.clone();
        let replayed_external_invocation_id =
            duplicate_invocation[0]["external_invocation_id"].clone();
        duplicate_invocation[1]["external_invocation_id"] = replayed_external_invocation_id;
        postpublication_edges.push(expect_refusal(
            &runner,
            &cache,
            project,
            "discovery_publish_replayed_external_invocation",
            "discover_associations",
            &json!({"project":project,"mode":"publish","prepared_artifact_sha256":third_prepared["prepared_artifact_sha256"],"evaluator_receipts":duplicate_invocation}),
            "ASTRO_DISCOVERY_EVALUATOR_INVALID",
        )?);
    }
    let final_state = physical_state(&cache, project)?;
    let wave = json!({
        "schema": DISCOVERY_FSV_WAVE_SCHEMA,
        "wave": 2,
        "tree_sha": execution["tree_sha"],
        "execution": {"path":execution_path,"bytes":execution_bytes.len(),"sha256":sha256(&execution_bytes)},
        "wave_one": {"path":wave_one_path,"bytes":wave_one_bytes.len(),"sha256":sha256(&wave_one_bytes)},
        "worker":worker,
        "capture":third_capture,
        "publication":{"request":third_publish_request,"response":third_published,"after":third_after},
        "read_request":read_request,
        "read":read_response,
        "read_before":read_before,
        "read_after":read_after,
        "retention":final_retention,
        "edges":postpublication_edges,
        "final_state":final_state,
        "complete":true,
    });
    let persisted = write_new_readback(&wave_two_path, &serde_json::to_vec_pretty(&wave)?)?;
    let transcript = expected_transport_requests(&execution, &wave["read_request"])
        .into_iter()
        .map(|value| serde_json::to_string(&value))
        .collect::<Result<Vec<_>, _>>()?
        .join("\n")
        + "\n";
    let transcript_receipt =
        write_new_readback(&payload.join("transport.ndjson"), transcript.as_bytes())?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event":"ISSUE_1150_ASSOCIATION_PUBLISH_COMPLETE",
            "receipt":persisted,
            "transcript":transcript_receipt,
            "current_final_artifact_sha256":wave["publication"]["response"]["artifact_sha256"],
            "current_and_previous_retained":true,
            "retired_generation_tombstones_verified":true,
            "final_state_sha256":wave["final_state"]["sha256"],
        }))?
    );
    Ok(())
}

fn detect_changes_fsv_request(project: &str, result_max_bytes: u64) -> Value {
    json!({
        "project": project,
        "scope": "symbols",
        "depth": DETECT_CHANGES_FSV_DEPTH,
        "changed_file_max": DETECT_CHANGES_FSV_CHANGED_FILE_MAX,
        "impact_max_symbols": DETECT_CHANGES_FSV_IMPACT_MAX_SYMBOLS,
        "reach_max_nodes_per_symbol": DETECT_CHANGES_FSV_REACH_MAX_NODES_PER_SYMBOL,
        "result_max_bytes": result_max_bytes,
        "base_branch": "main",
    })
}

fn detect_changes_changed_fsv_request(project: &str, since: &str, result_max_bytes: u64) -> Value {
    json!({
        "project": project,
        "scope": "symbols",
        "depth": DETECT_CHANGES_FSV_DEPTH,
        "changed_file_max": DETECT_CHANGES_FSV_CHANGED_FILE_MAX,
        "impact_max_symbols": DETECT_CHANGES_FSV_IMPACT_MAX_SYMBOLS,
        "reach_max_nodes_per_symbol": DETECT_CHANGES_FSV_REACH_MAX_NODES_PER_SYMBOL,
        "result_max_bytes": result_max_bytes,
        "since": since,
    })
}

fn predict_backtest_request(project: &str) -> Value {
    json!({"project":project,"mode":"backtest","seeds":[]})
}

fn predict_changed_symbol_request(project: &str, qualified_name: &str) -> Value {
    json!({"project":project,"mode":"predict","seeds":[qualified_name]})
}

fn expected_transport_requests(execution: &Value, discovery_request: &Value) -> Vec<Value> {
    let project = execution["project"].as_str().unwrap_or_default();
    let base_head = execution["fixture"]["base_head"]
        .as_str()
        .unwrap_or_default();
    let changed_symbol = execution["oracle"]["changed_symbol"]["qualified_name"]
        .as_str()
        .unwrap_or_default();
    vec![
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_projects","arguments":{}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_graph","arguments":execution["search"]["request"]}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"discover_latent_links","arguments":execution["latent"]["request"]}}),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"discover_associations","arguments":discovery_request}}),
        json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"detect_changes","arguments":detect_changes_fsv_request(project, DETECT_CHANGES_FSV_RESULT_MAX_BYTES)}}),
        json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_architecture","arguments":execution["architecture_clusters"]["exact"]["request"]}}),
        json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"predict_impact","arguments":predict_backtest_request(project)}}),
        json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"predict_impact","arguments":predict_changed_symbol_request(project, changed_symbol)}}),
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"detect_changes","arguments":detect_changes_changed_fsv_request(project, base_head, DETECT_CHANGES_FSV_RESULT_MAX_BYTES)}}),
    ]
}

fn exact_fields_equal(left: &Value, right: &Value, fields: &[&str]) -> bool {
    fields
        .iter()
        .all(|field| matches!((left.get(*field), right.get(*field)), (Some(left), Some(right)) if left == right))
}

fn jsonrpc_tool_payload(response: &Value, tool: &str) -> AnyResult<Value> {
    let content = response["result"]["content"]
        .as_array()
        .filter(|content| content.len() == 1)
        .ok_or("JSON-RPC tool response does not have exactly one content item")?;
    let text = content
        .first()
        .and_then(|item| item["text"].as_str())
        .ok_or("JSON-RPC tool response has no text payload")?;
    let payload = parse_tool_text(
        &format!("JSON-RPC tool {tool}"),
        response["result"]["isError"] == Value::Bool(true),
        text,
    )?;
    require(
        response["result"].get("structuredContent") == Some(&payload) && payload.is_object(),
        "ISSUE_1116_1119_TRANSPORT_STRUCTURED_CONTENT_MISMATCH",
        json!({"tool":tool,"isError":response["result"]["isError"],"result":response["result"],"payload":payload}),
    )?;
    Ok(payload)
}

fn verify_get_architecture_tools_list_schema(tools: &[Value]) -> AnyResult<Value> {
    let matches = tools
        .iter()
        .filter(|tool| tool["name"] == "get_architecture")
        .collect::<Vec<_>>();
    require(
        matches.len() == 1,
        "ISSUE_1149_ARCHITECTURE_TOOL_DEFINITION_CARDINALITY_INVALID",
        json!({"tool_count": tools.len(), "matching_definitions": matches.len()}),
    )?;
    let tool = matches[0];
    let expected_aspects = json!([
        "all",
        "overview",
        "structure",
        "dependencies",
        "routes",
        "languages",
        "packages",
        "entry_points",
        "hotspots",
        "boundaries",
        "layers",
        "file_tree",
        "clusters",
        "skill_tree",
        "bridges",
        "search_scale",
        "weave",
        "kernel",
        "kernel_context",
        "anomalies",
        "provenance",
        "agreement_graph",
        "redundancy",
        "n_eff",
        "layout_map",
        "grounding_gaps",
        "signal_ranking",
    ]);
    let expected_schema = json!({
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "path": {
                "type": "string",
                "description": "Optional directory prefix to scope architecture (e.g. apps/hoa)",
            },
            "resolution": {
                "type": "number",
                "exclusiveMinimum": 0,
                "description": "Required with clusters/all; finite modularity resolution (no default)",
            },
            "cluster_max_nodes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2_147_483_647_u64,
                "description": "Required with clusters/all; caller-owned preallocation node bound",
            },
            "cluster_max_edges": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2_147_483_647_u64,
                "description": "Required with clusters/all; caller-owned induced-edge bound",
            },
            "cluster_max_move_visits": {
                "type": "integer",
                "minimum": 1,
                "maximum": u64::MAX,
                "description": "Required with clusters/all; global deterministic move-work bound",
            },
            "cluster_max_result_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": u64::MAX,
                "description": "Required with clusters/all; bounds the complete compact UTF-8 C architecture object copied to content[0].text and structuredContent after all native fields are constructed; excludes the outer MCP envelope and canonical hash preimage; a Rust host must re-enforce after augmentation",
            },
            "aspects": {
                "type": "array",
                "items": {"type": "string", "enum": expected_aspects},
                "minItems": 1,
                "maxItems": 26,
                "uniqueItems": true,
                "description": "Aspects to include. Omit for the narrow overview only; file_tree and clusters are never implicit. Selecting clusters or all requires explicit resolution, cluster_max_nodes, cluster_max_edges, cluster_max_move_visits, and cluster_max_result_bytes with no defaults. cluster_max_result_bytes bounds the final logical architecture payload bytes mirrored in content[0].text and structuredContent after every Astrolabe augmentation; generic MCP envelope framing is excluded. all must be the sole selector and includes every legacy and Astrolabe aspect. Astrolabe selectors read only their named persisted project surface. search_scale serves the exact Calyx backend/admission plan; weave serves the exact Weave/Loom family, cross-term, association, Sextant quantization, and Forge commissioning receipts. signal_ranking reads the exact committed Assay transaction and returns a structured tool error for a validated preserved failed publication even when the live shadow dial is absent. kernel is an alias for kernel_context and n_eff is an alias for redundancy. Astrolabe aspects are project-scoped and refuse a non-empty path rather than returning an unscoped answer.",
            },
        },
        "required": ["project"],
        "additionalProperties": false,
    });
    let tool_keys = tool
        .as_object()
        .ok_or("ISSUE_1149_ARCHITECTURE_TOOL_DEFINITION_NOT_OBJECT")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_tool_keys = BTreeSet::from([
        "name",
        "title",
        "description",
        "inputSchema",
        "outputSchema",
    ]);
    require(
        usize::BITS == 64
            && tool_keys == expected_tool_keys
            && tool["title"] == "Get architecture"
            && tool["description"]
                == "Get high-level architecture overview — packages, services, dependencies, and project structure at a glance. Includes 'clusters': a deterministic, versioned Leiden variant over the call/import graph's complete stable-atom projection, surfacing every de-facto module (each with a label, member count, cohesion score, a complete canonical member_atom_ids identity roster, up to five degree-ranked top_nodes representative display names, and the packages/edge_types that bind it) — use these to grasp the real architectural seams, which often cut across the folder layout. The cluster_receipt binds exact source/projection/result hashes, counts, convergence, work, and connectivity. Optional path scopes analysis to nodes under that literal directory prefix (file_path). Clustering is never implicit: request clusters or all and provide resolution plus every cluster_* work bound."
            && tool["inputSchema"] == expected_schema
            && tool["outputSchema"] == json!({"type":"object","additionalProperties":true}),
        "ISSUE_1149_ARCHITECTURE_TOOLS_LIST_SCHEMA_MISMATCH",
        json!({
            "expected_tool_keys": expected_tool_keys,
            "observed_tool_keys": tool_keys,
            "expected_input_schema": expected_schema,
            "observed_tool": tool,
        }),
    )?;
    let input_schema_bytes = serde_json::to_vec(&tool["inputSchema"])?;
    let output_schema_bytes = serde_json::to_vec(&tool["outputSchema"])?;
    Ok(json!({
        "tool": tool,
        "input_schema_bytes": input_schema_bytes.len(),
        "input_schema_sha256": sha256(&input_schema_bytes),
        "output_schema_bytes": output_schema_bytes.len(),
        "output_schema_sha256": sha256(&output_schema_bytes),
        "exact_input_schema_equal": true,
        "exact_output_schema_equal": true,
        "exact_tool_object_keys_equal": true,
        "unique_definition": true,
    }))
}

fn verify_detect_changes_tools_list_schema(tools: &[Value]) -> AnyResult<Value> {
    let matches = tools
        .iter()
        .filter(|tool| tool["name"] == "detect_changes")
        .collect::<Vec<_>>();
    require(
        matches.len() == 1,
        "ISSUE_1116_1119_DETECT_CHANGES_TOOL_DEFINITION_CARDINALITY_INVALID",
        json!({"tool_count": tools.len(), "matching_definitions": matches.len()}),
    )?;
    let tool = matches[0];
    let expected_schema = json!({
        "type": "object",
        "properties": {
            "project": {"type": "string"},
            "scope": {
                "type": "string",
                "enum": ["files", "symbols"],
                "default": "symbols",
            },
            "depth": {
                "type": "integer",
                "minimum": 1,
                "maximum": 16,
                "default": 2,
                "description": "Exact change-reach hop budget; Astrolabe's declared kernel reach registry admits 1..16.",
            },
            "changed_file_max": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2_147_483_647_u64,
                "description": "Required caller bound for the complete canonical changed-file roster.",
            },
            "impact_max_symbols": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2_147_483_647_u64,
                "description": "Required caller work bound for the complete impacted constellation roster.",
            },
            "reach_max_nodes_per_symbol": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2_147_483_647_u64,
                "description": "Required caller output bound per impacted symbol; full reach counts and digest remain returned.",
            },
            "result_max_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": u64::MAX,
                "description": "Required caller bound for the complete final public MCP result in UTF-8 bytes; no default or truncation.",
            },
            "base_branch": {
                "type": "string",
                "minLength": 1,
                "default": "main",
            },
            "since": {
                "type": "string",
                "minLength": 1,
                "description": "Git ref or tag to compare from (e.g. HEAD~5, v0.5.0). Diffs <ref>...HEAD.",
            },
        },
        "required": [
            "project",
            "changed_file_max",
            "impact_max_symbols",
            "reach_max_nodes_per_symbol",
            "result_max_bytes"
        ],
        "additionalProperties": false,
    });
    let tool_keys = tool
        .as_object()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_TOOL_DEFINITION_NOT_OBJECT")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_tool_keys = BTreeSet::from([
        "name",
        "title",
        "description",
        "inputSchema",
        "outputSchema",
    ]);
    require(
        tool_keys == expected_tool_keys
            && tool["title"] == "Detect changes"
            && tool["description"]
                == "Detect the exact canonical Git changed-file roster and, for scope=symbols, every measured indexed constellation mapped to those files. Every Git source must succeed; unmapped-file coverage is explicit. The Astrolabe host requires a current hash-bound Oracle/kernel generation for symbol grounding and refuses when it is unavailable."
            && tool["inputSchema"] == expected_schema
            && tool["outputSchema"] == json!({"type":"object","additionalProperties":true}),
        "ISSUE_1116_1119_DETECT_CHANGES_TOOLS_LIST_SCHEMA_MISMATCH",
        json!({
            "expected_tool_keys": expected_tool_keys,
            "observed_tool_keys": tool_keys,
            "expected_input_schema": expected_schema,
            "observed_tool": tool,
        }),
    )?;
    let input_schema_bytes = serde_json::to_vec(&tool["inputSchema"])?;
    let output_schema_bytes = serde_json::to_vec(&tool["outputSchema"])?;
    Ok(json!({
        "tool": tool,
        "input_schema_bytes": input_schema_bytes.len(),
        "input_schema_sha256": sha256(&input_schema_bytes),
        "output_schema_bytes": output_schema_bytes.len(),
        "output_schema_sha256": sha256(&output_schema_bytes),
        "closed_arguments": true,
        "required_positive_int_max_bounds": [
            "changed_file_max",
            "impact_max_symbols",
            "reach_max_nodes_per_symbol"
        ],
        "required_positive_size_max_result_bound": "result_max_bytes",
        "runtime_usize_bits": usize::BITS,
        "advertised_result_max_equals_win64_size_max": true,
        "scope_enum_and_fixed_positive_depth_range_1_through_16": true,
        "exact_input_schema_equal": true,
        "exact_output_schema_equal": true,
        "exact_tool_object_keys_equal": true,
        "unique_definition": true,
    }))
}

fn verify_discover_associations_tools_list_schema(tools: &[Value]) -> AnyResult<Value> {
    let matches = tools
        .iter()
        .filter(|tool| tool["name"] == "discover_associations")
        .collect::<Vec<_>>();
    require(
        matches.len() == 1,
        "ISSUE_1150_DISCOVERY_TOOL_DEFINITION_CARDINALITY_INVALID",
        matches.len(),
    )?;
    let tool = matches[0];
    let input = &tool["inputSchema"];
    let property_names = input["properties"]
        .as_object()
        .ok_or("ISSUE_1150_DISCOVERY_TOOL_PROPERTIES_MISSING")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_properties = BTreeSet::from([
        "project",
        "mode",
        "prepared_artifact_sha256",
        "section",
        "workers",
        "cross_validation_folds",
        "top_k",
        "max_intermediary_degree",
        "min_shared_intermediaries",
        "budgets",
        "evaluator_declarations",
        "evaluator_receipts",
    ]);
    let budget_properties = input["properties"]["budgets"]["properties"]
        .as_object()
        .ok_or("ISSUE_1150_DISCOVERY_TOOL_BUDGET_PROPERTIES_MISSING")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_budgets = BTreeSet::from([
        "max_evaluation_bindings",
        "max_request_bytes_per_binding",
        "max_request_bytes_total",
        "max_response_bytes_per_binding",
        "max_response_bytes_total",
        "max_generation_rows",
        "max_generation_bytes",
    ]);
    let declaration_properties =
        input["properties"]["evaluator_declarations"]["items"]["properties"]
            .as_object()
            .ok_or("ISSUE_1150_DISCOVERY_TOOL_DECLARATION_PROPERTIES_MISSING")?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
    let expected_declarations = BTreeSet::from([
        "evaluator_id",
        "model_id",
        "prompt_id",
        "temperature_x100",
        "prompt_utf8",
    ]);
    let receipt_properties = input["properties"]["evaluator_receipts"]["items"]["properties"]
        .as_object()
        .ok_or("ISSUE_1150_DISCOVERY_TOOL_RECEIPT_PROPERTIES_MISSING")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_receipts = BTreeSet::from([
        "schema",
        "invocation_id",
        "external_invocation_id",
        "provider_response_id",
        "capture_schema",
        "capture_provenance",
        "prepared_artifact_sha256",
        "source_generation_sha256",
        "hypothesis_id",
        "hypothesis_content_sha256",
        "evaluator_id",
        "model_id",
        "prompt_id",
        "temperature_x100",
        "prompt_utf8",
        "prompt_sha256",
        "request_utf8",
        "request_sha256",
        "response_utf8",
        "response_sha256",
        "parse_result",
    ]);
    let parse_properties = input["properties"]["evaluator_receipts"]["items"]["properties"]
        ["parse_result"]["properties"]
        .as_object()
        .ok_or("ISSUE_1150_DISCOVERY_TOOL_PARSE_PROPERTIES_MISSING")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_parse = BTreeSet::from([
        "schema",
        "plausible_score",
        "novelty_score",
        "testability_score",
        "falsifiability_score",
        "justification",
        "falsification_test",
        "cited_evidence_ids",
    ]);
    require(
        input["type"] == "object"
            && input["additionalProperties"] == Value::Bool(false)
            && input["required"] == json!(["project", "mode"])
            && input["properties"]["mode"]["enum"] == json!(["prepare", "publish", "read"])
            && input["properties"]["section"]["enum"]
                == json!([
                    "all",
                    "manifest",
                    "source",
                    "roster",
                    "receipts",
                    "evaluator",
                    "ranked",
                    "kernel"
                ])
            && property_names == expected_properties
            && budget_properties == expected_budgets
            && input["properties"]["budgets"]["required"]
                == json!([
                    "max_evaluation_bindings",
                    "max_request_bytes_per_binding",
                    "max_request_bytes_total",
                    "max_response_bytes_per_binding",
                    "max_response_bytes_total",
                    "max_generation_rows",
                    "max_generation_bytes"
                ])
            && input["properties"]["budgets"]["additionalProperties"] == Value::Bool(false)
            && declaration_properties == expected_declarations
            && input["properties"]["evaluator_declarations"]["minItems"] == 1
            && input["properties"]["evaluator_declarations"]["items"]["required"]
                == json!([
                    "evaluator_id",
                    "model_id",
                    "prompt_id",
                    "temperature_x100",
                    "prompt_utf8"
                ])
            && input["properties"]["evaluator_declarations"]["items"]["additionalProperties"]
                == Value::Bool(false)
            && receipt_properties == expected_receipts
            && input["properties"]["evaluator_receipts"]["minItems"] == 1
            && input["properties"]["evaluator_receipts"]["items"]["properties"]["schema"]["const"]
                == DISCOVERY_RECEIPT_SCHEMA_V2
            && input["properties"]["evaluator_receipts"]["items"]["properties"]["capture_schema"]["const"]
                == DISCOVERY_CAPTURE_SCHEMA_V1
            && input["properties"]["evaluator_receipts"]["items"]["additionalProperties"]
                == Value::Bool(false)
            && input["properties"]["evaluator_receipts"]["items"]["required"]
                == json!([
                    "schema",
                    "invocation_id",
                    "external_invocation_id",
                    "provider_response_id",
                    "capture_schema",
                    "capture_provenance",
                    "prepared_artifact_sha256",
                    "source_generation_sha256",
                    "hypothesis_id",
                    "hypothesis_content_sha256",
                    "evaluator_id",
                    "model_id",
                    "prompt_id",
                    "temperature_x100",
                    "prompt_utf8",
                    "prompt_sha256",
                    "request_utf8",
                    "request_sha256",
                    "response_utf8",
                    "response_sha256",
                    "parse_result"
                ])
            && parse_properties == expected_parse
            && input["properties"]["evaluator_receipts"]["items"]["properties"]["parse_result"]["properties"]
                ["schema"]["const"]
                == DISCOVERY_RESPONSE_SCHEMA_V1
            && input["properties"]["evaluator_receipts"]["items"]["properties"]["parse_result"]["required"]
                == json!([
                    "schema",
                    "plausible_score",
                    "novelty_score",
                    "testability_score",
                    "falsifiability_score",
                    "justification",
                    "falsification_test",
                    "cited_evidence_ids"
                ])
            && input["properties"]["evaluator_receipts"]["items"]["properties"]["parse_result"]["additionalProperties"]
                == Value::Bool(false),
        "ISSUE_1150_DISCOVERY_TOOLS_LIST_SCHEMA_MISMATCH",
        tool,
    )?;
    let bytes = serde_json::to_vec(input)?;
    Ok(json!({
        "tool":tool,
        "input_schema_bytes":bytes.len(),
        "input_schema_sha256":sha256(&bytes),
        "exact_budget_declaration_receipt_and_parse_schema_verified":true,
    }))
}

fn is_canonical_git_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_native_changed_detect_payload(
    payload: &Value,
    request: &Value,
    project: &str,
    base_head: &str,
    head: &str,
    changed_symbol: &Value,
) -> AnyResult<Value> {
    let request_fields = request
        .as_object()
        .ok_or("ISSUE_1116_1119_CHANGED_REQUEST_NOT_OBJECT")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let payload_fields = payload
        .as_object()
        .ok_or("ISSUE_1116_1119_CHANGED_PAYLOAD_NOT_OBJECT")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_payload_fields = BTreeSet::from([
        "schema",
        "project",
        "resolved_base_ref",
        "resolved_base_oid",
        "resolved_head_oid",
        "git_observation_passes",
        "changed_file_max",
        "changed_files",
        "changed_count",
        "impacted_symbols",
        "changed_file_mappings",
        "depth",
        "impact_max_symbols",
        "reach_max_nodes_per_symbol",
        "result_max_bytes",
        "scope",
    ]);
    let impacted = payload["impacted_symbols"]
        .as_array()
        .ok_or("ISSUE_1116_1119_CHANGED_IMPACTED_MISSING")?;
    let mut node_ids = BTreeSet::new();
    let mut atom_ids = BTreeSet::new();
    let mut qualified_names = BTreeSet::new();
    for symbol in impacted {
        let fields = symbol
            .as_object()
            .ok_or("ISSUE_1116_1119_CHANGED_SYMBOL_NOT_OBJECT")?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let node_id = symbol["node_id"]
            .as_i64()
            .filter(|value| *value > 0)
            .ok_or("ISSUE_1116_1119_CHANGED_NODE_ID_INVALID")?;
        let atom_id = symbol["atom_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("ISSUE_1116_1119_CHANGED_ATOM_ID_INVALID")?;
        let qualified_name = symbol["qualified_name"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("ISSUE_1116_1119_CHANGED_QUALIFIED_NAME_INVALID")?;
        require(
            fields
                == BTreeSet::from([
                    "node_id",
                    "atom_id",
                    "name",
                    "qualified_name",
                    "label",
                    "file",
                ])
                && symbol["file"] == "src/lib.rs"
                && symbol["name"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
                && symbol["label"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
                && node_ids.insert(node_id)
                && atom_ids.insert(atom_id.to_string())
                && qualified_names.insert(qualified_name.to_string()),
            "ISSUE_1116_1119_CHANGED_SYMBOL_INVALID",
            symbol,
        )?;
    }
    let mapping = payload["changed_file_mappings"]
        .as_array()
        .and_then(|values| values.first().filter(|_| values.len() == 1))
        .ok_or("ISSUE_1116_1119_CHANGED_MAPPING_CARDINALITY")?;
    require(
        request_fields
            == BTreeSet::from([
                "project",
                "scope",
                "depth",
                "changed_file_max",
                "impact_max_symbols",
                "reach_max_nodes_per_symbol",
                "result_max_bytes",
                "since",
            ])
            && request
                == &detect_changes_changed_fsv_request(
                    project,
                    base_head,
                    request["result_max_bytes"]
                        .as_u64()
                        .ok_or("ISSUE_1116_1119_CHANGED_RESULT_BOUND_MISSING")?,
                )
            && payload_fields == expected_payload_fields
            && payload["schema"] == "cbm.detect_changes.v2"
            && payload["project"] == project
            && payload["resolved_base_ref"] == base_head
            && payload["resolved_base_oid"] == base_head
            && payload["resolved_head_oid"] == head
            && is_canonical_git_oid(base_head)
            && is_canonical_git_oid(head)
            && base_head != head
            && payload["git_observation_passes"] == 2
            && payload["scope"] == request["scope"]
            && payload["depth"] == request["depth"]
            && payload["changed_file_max"] == request["changed_file_max"]
            && payload["impact_max_symbols"] == request["impact_max_symbols"]
            && payload["reach_max_nodes_per_symbol"] == request["reach_max_nodes_per_symbol"]
            && payload["result_max_bytes"] == request["result_max_bytes"]
            && payload["changed_count"] == 1
            && payload["changed_files"] == json!(["src/lib.rs"])
            && mapping["file"] == "src/lib.rs"
            && mapping["symbols_requested"] == Value::Bool(true)
            && mapping["node_count"].as_u64() == u64::try_from(impacted.len()).ok()
            && !impacted.is_empty()
            && impacted.len() <= usize::try_from(DETECT_CHANGES_FSV_IMPACT_MAX_SYMBOLS)?
            && qualified_names.contains(
                changed_symbol["qualified_name"]
                    .as_str()
                    .ok_or("ISSUE_1116_1119_CHANGED_SYMBOL_QN_MISSING")?,
            )
            && impacted.iter().any(|symbol| {
                symbol["node_id"] == changed_symbol["node_id"]
                    && symbol["atom_id"] == changed_symbol["atom_id"]
                    && symbol["name"] == changed_symbol["name"]
                    && symbol["qualified_name"] == changed_symbol["qualified_name"]
                    && symbol["label"] == changed_symbol["label"]
                    && symbol["file"] == changed_symbol["file"]
            }),
        "ISSUE_1116_1119_NATIVE_CHANGED_DETECT_MISMATCH",
        json!({
            "request":request,
            "payload":payload,
            "base_head":base_head,
            "head":head,
            "changed_symbol":changed_symbol,
        }),
    )?;
    Ok(json!({
        "schema":"astrolabe.issue-1116-1119.native-changed-detect.v1",
        "request":request,
        "payload":payload,
        "changed_file":"src/lib.rs",
        "changed_symbol":changed_symbol,
        "impacted_symbol_count":impacted.len(),
        "exact_git_base_head_and_symbol_identity_verified":true,
        "no_oracle_augmentation_or_fabricated_evidence":true,
    }))
}

fn run_native_changed_detect(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    base_head: &str,
    head: &str,
    changed_symbol: &Value,
    case: &str,
) -> AnyResult<Value> {
    let request =
        detect_changes_changed_fsv_request(project, base_head, DETECT_CHANGES_FSV_RESULT_MAX_BYTES);
    let before = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"before","state":before}))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":case,
            "phase":"action",
            "tool":"native_cbm.detect_changes",
            "request":request,
        }))?
    );
    let raw = runner.handle_tool_raw("detect_changes", &serde_json::to_string(&request)?)?;
    let envelope: Value = serde_json::from_str(&raw)?;
    let text = envelope["content"]
        .as_array()
        .filter(|items| items.len() == 1)
        .and_then(|items| items.first())
        .and_then(|item| item["text"].as_str())
        .ok_or("ISSUE_1116_1119_NATIVE_CHANGED_TEXT_MISSING")?;
    let payload = parse_tool_text(
        "native_cbm.detect_changes",
        envelope["isError"] == Value::Bool(true),
        text,
    )?;
    require(
        envelope["isError"] != Value::Bool(true)
            && envelope["content"][0]["type"] == "text"
            && envelope["structuredContent"] == payload
            && text == serde_json::to_string(&payload)?,
        "ISSUE_1116_1119_NATIVE_CHANGED_ENVELOPE_INVALID",
        &envelope,
    )?;
    let contract = verify_native_changed_detect_payload(
        &payload,
        &request,
        project,
        base_head,
        head,
        changed_symbol,
    )?;
    let after = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"after","state":after}))?
    );
    require(
        before["sha256"] == after["sha256"],
        "ISSUE_1116_1119_NATIVE_CHANGED_DETECT_MUTATED_STATE",
        json!({"before":before,"after":after}),
    )?;
    Ok(json!({
        "case":case,
        "raw_bytes":raw.len(),
        "raw_sha256":sha256(raw.as_bytes()),
        "contract":contract,
        "before":before,
        "after":after,
        "state_unchanged":true,
    }))
}

fn run_predict_backtest(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    oracle: &Value,
    case: &str,
) -> AnyResult<Value> {
    let request = predict_backtest_request(project);
    let before = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"before","state":before}))?
    );
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":case,"phase":"action","tool":"predict_impact","request":request})
        )?
    );
    let (raw, envelope, response) = call_tool_with_raw(runner, "predict_impact", &request)?;
    require(
        envelope["isError"] != Value::Bool(true)
            && response["schema"] == "astrolabe.predict_impact.v1"
            && response["project"] == project
            && response["status"] == "backtest_attested"
            && response["advertise_grounded"] == Value::Bool(false)
            && response["gate"]["attestation_id"]
                == oracle["gate"]["attestation"]["attestation_id"]
            && response["gate"]["admitted"] == Value::Bool(false)
            && response["gate"]["refusal_code"] == oracle["gate"]["refusal_code"]
            && response["gate"]["backtest"] == oracle["gate"]["attestation"]["body"]["backtest"]
            && response["gate"]["kernel_generation_id"]
                == oracle["post_label_kernel"]["generation_id"]
            && response["trust"] == "provisional"
            && response["freshness"] == "fresh",
        "ISSUE_1116_1119_ORACLE_BACKTEST_TOOL_MISMATCH",
        json!({"oracle":oracle,"response":response}),
    )?;
    let after = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"after","state":after}))?
    );
    require(
        before["sha256"] == after["sha256"],
        "ISSUE_1116_1119_ORACLE_BACKTEST_MUTATED_STATE",
        json!({"before":before,"after":after}),
    )?;
    Ok(json!({
        "case":case,
        "request":request,
        "response":response,
        "raw_bytes":raw.len(),
        "raw_sha256":sha256(raw.as_bytes()),
        "before":before,
        "after":after,
        "state_unchanged":true,
    }))
}

fn run_failed_gate_predict(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    changed_symbol: &Value,
    refusal_code: &str,
    case: &str,
) -> AnyResult<Value> {
    let qualified_name = changed_symbol["qualified_name"]
        .as_str()
        .ok_or("ISSUE_1116_1119_ORACLE_CHANGED_QN_MISSING")?;
    expect_refusal(
        runner,
        cache,
        project,
        case,
        "predict_impact",
        &predict_changed_symbol_request(project, qualified_name),
        refusal_code,
    )
}

fn run_changed_detect_gate_refusal(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    base_head: &str,
    persisted_refusal_code: &str,
    case: &str,
) -> AnyResult<Value> {
    let request =
        detect_changes_changed_fsv_request(project, base_head, DETECT_CHANGES_FSV_RESULT_MAX_BYTES);
    let before = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"before","state":before}))?
    );
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":case,"phase":"action","tool":"detect_changes","request":request})
        )?
    );
    let (raw, envelope, response) = call_tool_with_raw(runner, "detect_changes", &request)?;
    require(
        envelope["isError"] == Value::Bool(true)
            && response["schema"] == "astrolabe.tool_fault/v1"
            && response["status"] == "error"
            && response["code"] == ORACLE_DETECT_GROUNDING_DEFICIT
            && response["failed_stage"] == "oracle_gate_attestation"
            && response["tool"] == "detect_changes"
            && response["message"]
                .as_str()
                .is_some_and(|message| message.contains(persisted_refusal_code))
            && response["remediation"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()),
        "ISSUE_1116_1119_CHANGED_DETECT_GATE_REFUSAL_MISMATCH",
        json!({"request":request,"response":response}),
    )?;
    let after = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"after","state":after}))?
    );
    require(
        before["sha256"] == after["sha256"],
        "ISSUE_1116_1119_CHANGED_DETECT_GATE_REFUSAL_MUTATED_STATE",
        json!({"before":before,"after":after}),
    )?;
    Ok(json!({
        "case":case,
        "request":request,
        "response":response,
        "raw_bytes":raw.len(),
        "raw_sha256":sha256(raw.as_bytes()),
        "persisted_refusal_code":persisted_refusal_code,
        "before":before,
        "after":after,
        "state_unchanged":true,
    }))
}

fn verify_detect_changes_v2_payload(
    payload: &Value,
    request: &Value,
    expected_project: &str,
    expected_head_oid: &str,
) -> AnyResult<Value> {
    let request_object = request
        .as_object()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_REQUEST_NOT_OBJECT")?;
    let request_fields = request_object
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_request_fields = BTreeSet::from([
        "project",
        "scope",
        "depth",
        "changed_file_max",
        "impact_max_symbols",
        "reach_max_nodes_per_symbol",
        "result_max_bytes",
        "base_branch",
    ]);
    let requested_result_max_bytes = request["result_max_bytes"]
        .as_u64()
        .filter(|bound| *bound > 0)
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_RESULT_MAX_BYTES_INVALID")?;
    require(
        request_fields == expected_request_fields
            && request == &detect_changes_fsv_request(expected_project, requested_result_max_bytes),
        "ISSUE_1116_1119_DETECT_CHANGES_REQUEST_CONTRACT_MISMATCH",
        json!({
            "expected": detect_changes_fsv_request(expected_project, requested_result_max_bytes),
            "observed": request,
            "observed_fields": request_fields,
        }),
    )?;
    let object = payload
        .as_object()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_PAYLOAD_NOT_OBJECT")?;
    let payload_fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_payload_fields = BTreeSet::from([
        "schema",
        "project",
        "resolved_base_ref",
        "resolved_base_oid",
        "resolved_head_oid",
        "git_observation_passes",
        "changed_file_max",
        "changed_files",
        "changed_count",
        "impacted_symbols",
        "changed_file_mappings",
        "depth",
        "impact_max_symbols",
        "reach_max_nodes_per_symbol",
        "result_max_bytes",
        "scope",
        "grounded_risk",
    ]);
    let base_oid = payload["resolved_base_oid"]
        .as_str()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_BASE_OID_MISSING")?;
    let head_oid = payload["resolved_head_oid"]
        .as_str()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_HEAD_OID_MISSING")?;
    let changed_files = payload["changed_files"]
        .as_array()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_CHANGED_FILES_MISSING")?;
    let changed_file_names = changed_files
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|path| !path.is_empty())
                .map(str::to_string)
                .ok_or_else(|| "ISSUE_1116_1119_DETECT_CHANGES_CHANGED_FILE_INVALID".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    require(
        changed_file_names
            .windows(2)
            .all(|window| window[0].as_bytes() < window[1].as_bytes()),
        "ISSUE_1116_1119_DETECT_CHANGES_CHANGED_FILES_NONCANONICAL",
        &payload["changed_files"],
    )?;
    let mappings = payload["changed_file_mappings"]
        .as_array()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_MAPPINGS_MISSING")?;
    let impacted = payload["impacted_symbols"]
        .as_array()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_IMPACTED_MISSING")?;
    let mut mapping_counts = BTreeMap::<String, u64>::new();
    for (expected_file, mapping) in changed_file_names.iter().zip(mappings) {
        let mapping_object = mapping
            .as_object()
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_MAPPING_NOT_OBJECT")?;
        let fields = mapping_object
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        require(
            fields == BTreeSet::from(["file", "node_count", "symbols_requested"])
                && mapping["file"] == expected_file.as_str()
                && mapping["symbols_requested"] == Value::Bool(true),
            "ISSUE_1116_1119_DETECT_CHANGES_MAPPING_IDENTITY_MISMATCH",
            mapping,
        )?;
        let count = mapping["node_count"]
            .as_u64()
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_MAPPING_COUNT_INVALID")?;
        require(
            count > 0
                && mapping_counts
                    .insert(expected_file.clone(), count)
                    .is_none(),
            "ISSUE_1116_1119_DETECT_CHANGES_MAPPING_COVERAGE_INVALID",
            mapping,
        )?;
    }
    let mut observed_counts = BTreeMap::<String, u64>::new();
    let mut node_ids = BTreeSet::new();
    let mut atom_ids = BTreeSet::new();
    for symbol in impacted {
        let symbol_object = symbol
            .as_object()
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_SYMBOL_NOT_OBJECT")?;
        let fields = symbol_object
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let node_id = symbol["node_id"]
            .as_i64()
            .filter(|node_id| *node_id > 0)
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_NODE_ID_INVALID")?;
        let atom_id = symbol["atom_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_ATOM_ID_INVALID")?;
        let file = symbol["file"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_SYMBOL_FILE_INVALID")?;
        require(
            fields
                == BTreeSet::from([
                    "node_id",
                    "atom_id",
                    "name",
                    "qualified_name",
                    "label",
                    "file",
                ])
                && ["name", "qualified_name", "label"]
                    .into_iter()
                    .all(|field| {
                        symbol[field]
                            .as_str()
                            .is_some_and(|value| !value.is_empty())
                    })
                && mapping_counts.contains_key(file)
                && node_ids.insert(node_id)
                && atom_ids.insert(atom_id.to_string()),
            "ISSUE_1116_1119_DETECT_CHANGES_SYMBOL_IDENTITY_INVALID",
            symbol,
        )?;
        *observed_counts.entry(file.to_string()).or_default() += 1;
    }
    let mapped_total = mapping_counts.values().try_fold(0_u64, |total, count| {
        total
            .checked_add(*count)
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_MAPPING_TOTAL_OVERFLOW")
    })?;
    let grounded = &payload["grounded_risk"];
    let grounded_fields = grounded
        .as_object()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_GROUNDED_BLOCK_MISSING")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    require(
        payload_fields == expected_payload_fields
            && payload["schema"] == "cbm.detect_changes.v2"
            && payload["project"] == expected_project
            && payload["resolved_base_ref"] == request["base_branch"]
            && is_canonical_git_oid(base_oid)
            && is_canonical_git_oid(head_oid)
            && base_oid == head_oid
            && head_oid == expected_head_oid
            && payload["git_observation_passes"] == 2
            && payload["scope"] == request["scope"]
            && payload["depth"] == request["depth"]
            && payload["changed_file_max"] == request["changed_file_max"]
            && payload["impact_max_symbols"] == request["impact_max_symbols"]
            && payload["reach_max_nodes_per_symbol"] == request["reach_max_nodes_per_symbol"]
            && payload["result_max_bytes"] == request["result_max_bytes"]
            && payload["changed_count"].as_u64() == u64::try_from(changed_file_names.len()).ok()
            && changed_file_names.len() <= usize::try_from(DETECT_CHANGES_FSV_CHANGED_FILE_MAX)?
            && impacted.len() <= usize::try_from(DETECT_CHANGES_FSV_IMPACT_MAX_SYMBOLS)?
            && mappings.len() == changed_file_names.len()
            && mapped_total == u64::try_from(impacted.len())?
            && mapping_counts == observed_counts
            && changed_file_names.is_empty()
            && impacted.is_empty()
            && mappings.is_empty()
            && grounded_fields
                == BTreeSet::from([
                    "schema",
                    "status",
                    "grounded_symbol_count",
                    "symbol_count",
                    "symbols",
                    "trust",
                    "freshness",
                    "provenance",
                ])
            && grounded["schema"] == "astrolabe.detect_changes_grounded_risk.v2"
            && grounded["status"] == "no_changes"
            && grounded["grounded_symbol_count"] == 0
            && grounded["symbol_count"] == 0
            && grounded["symbols"] == json!([])
            && grounded["trust"] == "not_applicable"
            && grounded["freshness"] == "fresh"
            && grounded["provenance"]
                .as_array()
                .is_some_and(|provenance| provenance.len() == 2),
        "ISSUE_1116_1119_DETECT_CHANGES_V2_PAYLOAD_MISMATCH",
        json!({
            "request": request,
            "payload": payload,
            "expected_project": expected_project,
            "expected_head_oid": expected_head_oid,
            "mapping_counts": mapping_counts,
            "observed_counts": observed_counts,
        }),
    )?;
    Ok(json!({
        "request": request,
        "payload": payload,
        "schema_v2": true,
        "closed_request_arguments": true,
        "project_and_base_ref_echo_equal": true,
        "canonical_base_and_head_oids_equal_clean_fixture_head": true,
        "git_observation_passes": 2,
        "scope_depth_and_all_four_positive_bounds_echo_equal": true,
        "result_max_bytes_echo_equal": true,
        "changed_file_mapping_coverage_exact": true,
        "clean_real_fixture_no_changes": true,
        "oracle_grounded_numeric_success_claimed": false,
        "grounded_status": "no_changes",
    }))
}

fn run_detect_changes_success(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    expected_head_oid: &str,
    case: &str,
    request: &Value,
) -> AnyResult<Value> {
    let before = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"before","state":before}))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": case,
            "phase": "action",
            "tool": "detect_changes",
            "request": request,
        }))?
    );
    let (raw, envelope, payload) = call_tool_with_raw(runner, "detect_changes", request)?;
    let payload_text = envelope["content"][0]["text"]
        .as_str()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_PAYLOAD_TEXT_MISSING")?;
    let compact_payload = serde_json::to_string(&payload)?;
    let compact_envelope = serde_json::to_string(&envelope)?;
    let result_max_bytes = request["result_max_bytes"]
        .as_u64()
        .filter(|bound| *bound > 0)
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_RESULT_BOUND_MISSING")?;
    let final_result_bytes = u64::try_from(raw.len())?;
    require(
        envelope["isError"] != Value::Bool(true)
            && payload_text == compact_payload
            && raw == compact_envelope
            && final_result_bytes <= result_max_bytes,
        "ISSUE_1116_1119_DETECT_CHANGES_PUBLIC_RESULT_INVALID",
        json!({
            "case": case,
            "request": request,
            "raw_bytes": raw.len(),
            "raw_sha256": sha256(raw.as_bytes()),
            "compact_envelope_bytes": compact_envelope.len(),
            "compact_envelope_sha256": sha256(compact_envelope.as_bytes()),
            "payload_text_bytes": payload_text.len(),
            "payload_text_sha256": sha256(payload_text.as_bytes()),
            "result": envelope,
        }),
    )?;
    let contract = verify_detect_changes_v2_payload(&payload, request, project, expected_head_oid)?;
    let after = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"after","state":after}))?
    );
    require(
        before["sha256"] == after["sha256"],
        "ISSUE_1116_1119_DETECT_CHANGES_READ_MUTATED_STATE",
        json!({"case": case, "before": before, "after": after}),
    )?;
    Ok(json!({
        "case": case,
        "request": request,
        "response": payload,
        "contract": contract,
        "final_public_mcp_result_bytes": final_result_bytes,
        "final_public_mcp_result_sha256": sha256(raw.as_bytes()),
        "payload_text_bytes": payload_text.len(),
        "payload_text_sha256": sha256(payload_text.as_bytes()),
        "result_max_bytes_echo": payload["result_max_bytes"],
        "exact_compact_text_and_public_result_serialization": true,
        "before": before,
        "after": after,
        "state_unchanged": true,
    }))
}

fn settle_detect_changes_result_byte_bound(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    expected_head_oid: &str,
    case_prefix: &str,
) -> AnyResult<Value> {
    let mut candidate = DETECT_CHANGES_FSV_RESULT_MAX_BYTES;
    let mut rounds = Vec::new();
    for round in 1_u64..=20 {
        let request = detect_changes_fsv_request(project, candidate);
        let run = run_detect_changes_success(
            runner,
            cache,
            project,
            expected_head_oid,
            &format!("{case_prefix}_calibration_{round}"),
            &request,
        )?;
        let measured = run["final_public_mcp_result_bytes"]
            .as_u64()
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_CALIBRATION_BYTES_MISSING")?;
        require(
            measured <= candidate,
            "ISSUE_1116_1119_DETECT_CHANGES_EXACT_BOUND_CALIBRATION_GREW",
            json!({
                "case_prefix": case_prefix,
                "round": round,
                "candidate": candidate,
                "measured": measured,
                "run": run,
            }),
        )?;
        let settled = measured == candidate;
        rounds.push(json!({
            "round": round,
            "requested_bound": candidate,
            "measured_final_public_mcp_result_bytes": measured,
            "run": run,
        }));
        if settled {
            return Ok(json!({
                "schema": "astrolabe.issue-1116-1119.detect-changes-exact-result-byte-bound.v1",
                "bound": candidate,
                "round_count": rounds.len(),
                "rounds": rounds,
                "exact_byte_success": true,
            }));
        }
        candidate = measured;
    }
    Err(format!(
        "ISSUE_1116_1119_DETECT_CHANGES_EXACT_BOUND_DID_NOT_SETTLE: case={case_prefix:?}; final_candidate={candidate}; remediation: preserve every result and repair deterministic final-public-result byte accounting"
    )
    .into())
}

fn expect_detect_changes_result_bound_refusal(
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    case: &str,
    request: &Value,
) -> AnyResult<Value> {
    let before = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"before","state":before}))?
    );
    let jsonrpc_request = json!({
        "jsonrpc": "2.0",
        "id": case,
        "method": "tools/call",
        "params": {
            "name": "detect_changes",
            "arguments": request,
        },
    });
    let mut request_bytes = serde_json::to_vec(&jsonrpc_request)?;
    request_bytes.push(b'\n');
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": case,
            "phase": "action",
            "tool": "detect_changes",
            "request": request,
            "transport": "public JSON-RPC tools/call",
        }))?
    );
    let mut output = Vec::new();
    astrolabe_server::serve_jsonrpc(
        runner,
        BufReader::new(request_bytes.as_slice()),
        &mut output,
    )?;
    let responses = std::str::from_utf8(&output)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let response = responses
        .first()
        .filter(|_| responses.len() == 1)
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_BOUND_REFUSAL_RESPONSE_CARDINALITY")?;
    let payload = jsonrpc_tool_payload(response, "detect_changes result-bound refusal")?;
    let payload_fields = payload
        .as_object()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_BOUND_REFUSAL_NOT_OBJECT")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let result_max_bytes = request["result_max_bytes"]
        .as_u64()
        .filter(|bound| *bound > 0)
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_BOUND_REFUSAL_REQUEST_INVALID")?;
    require(
        request == &detect_changes_fsv_request(project, result_max_bytes)
            && response["jsonrpc"] == "2.0"
            && response["id"] == case
            && response.get("error").is_none()
            && response["result"]["isError"] == Value::Bool(true)
            && payload_fields
                == BTreeSet::from([
                    "schema",
                    "status",
                    "code",
                    "message",
                    "remediation",
                    "failed_stage",
                    "tool",
                ])
            && payload["schema"] == "astrolabe.tool_fault/v1"
            && payload["status"] == "error"
            && payload["code"] == "ASTRO_DETECT_CHANGES_RESULT_BOUND_EXCEEDED"
            && payload["failed_stage"] == "final_public_mcp_result_bytes"
            && payload["tool"] == "detect_changes"
            && payload["remediation"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()),
        "ISSUE_1116_1119_DETECT_CHANGES_BOUND_REFUSAL_MISMATCH",
        json!({"request": request, "response": response, "payload": payload}),
    )?;
    let after = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":case,"phase":"after","state":after}))?
    );
    require(
        before["sha256"] == after["sha256"],
        "ISSUE_1116_1119_DETECT_CHANGES_BOUND_REFUSAL_MUTATED_STATE",
        json!({"case": case, "before": before, "after": after}),
    )?;
    Ok(json!({
        "case": case,
        "tool": "detect_changes",
        "request": request,
        "jsonrpc_request": jsonrpc_request,
        "jsonrpc_request_bytes": request_bytes.len(),
        "jsonrpc_request_sha256": sha256(&request_bytes),
        "jsonrpc_response_bytes": output.len(),
        "jsonrpc_response_sha256": sha256(&output),
        "response": payload,
        "expected_code": "ASTRO_DETECT_CHANGES_RESULT_BOUND_EXCEEDED",
        "expected_failed_stage": "final_public_mcp_result_bytes",
        "before": before,
        "after": after,
        "state_unchanged": true,
    }))
}

fn transport(payload: PathBuf) -> AnyResult<()> {
    let execution: Value = serde_json::from_slice(&fs::read(payload.join("execution.json"))?)?;
    let association_wave_two: Value =
        serde_json::from_slice(&fs::read(payload.join("association-publish-wave-2.json"))?)?;
    let cache = PathBuf::from(
        execution["cache"]
            .as_str()
            .ok_or("execution cache missing")?,
    );
    let project = execution["project"]
        .as_str()
        .ok_or("execution project missing")?;
    let repo = PathBuf::from(execution["repo"].as_str().ok_or("execution repo missing")?);
    let source_generation = current_source_generation_sha256()?;
    require(
        execution["schema"] == "astrolabe.issues-1116-1119.execute.v1"
            && repo == payload.join("real-rust-repo")
            && cache == payload.join("real-cache")
            && execution["tree_sha"] == Value::String(canonical_head()?)
            && execution["driver_artifact"] == current_driver_artifact_state()?
            && execution["source_generation_schema"]
                == worker_source_generation::SOURCE_GENERATION_SCHEMA
            && execution["source_generation_sha256"] == Value::String(source_generation.clone())
            && source_generation == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256
            && association_wave_two["schema"] == DISCOVERY_FSV_WAVE_SCHEMA
            && association_wave_two["wave"] == 2
            && association_wave_two["complete"] == Value::Bool(true)
            && association_wave_two["tree_sha"] == execution["tree_sha"],
        "ISSUE_1116_1119_EXECUTION_RECEIPT_BINDING_MISMATCH",
        json!({"payload": payload, "repo": repo, "cache": cache}),
    )?;
    let fixture_source = fixture_source_state(&repo)?;
    require(
        fixture_source == execution["fixture"]["source"]
            && fixture_source == execution["fixture_after"],
        "ISSUE_1116_1119_FIXTURE_SOURCE_READBACK_MISMATCH",
        &fixture_source,
    )?;
    set_cbm_cache_dir(&cache)?;
    require(
        configured_cbm_host_binary_path()?.is_none() && !supervisor_should_wrap(),
        "ISSUE_1116_1119_TRANSPORT_PROCESS_PRESTATE_INVALID",
        "a fresh transport process already had a binary binding or supervisor role",
    )?;
    let (shipping_host, shipping_host_state) = shipping_astrolabe_executable()?;
    require(
        execution["shipping_host"]["configured"] == shipping_host_state,
        "ISSUE_1116_1119_SHIPPING_HOST_DRIFT",
        &shipping_host_state,
    )?;
    let shipping_sha256 = shipping_host_state["sha256"]
        .as_str()
        .ok_or("ISSUE_1116_1119_SHIPPING_SHA256_MISSING")?;
    let verified_worker = initialize_cbm_host_process_with_verified_worker(
        &shipping_host,
        shipping_sha256,
        &source_generation,
    )?;
    let verified_worker_identity =
        validate_verified_worker_binding(&verified_worker, &shipping_host)?;
    let execute_verified_worker: CbmVerifiedWorkerBinding =
        serde_json::from_value(execution["shipping_host"]["verified_worker"].clone())?;
    require(
        configured_cbm_host_binary_path()?.as_deref() == Some(shipping_host.as_path())
            && supervisor_should_wrap()
            && verified_worker_stable_fields_equal(&execute_verified_worker, &verified_worker)
            && execute_verified_worker.capability.challenge != verified_worker.capability.challenge
            && execution["shipping_host"]["verified_worker_identity"]
                == json!(verified_worker_identity),
        "ISSUE_1116_1119_TRANSPORT_HOST_BINDING_MISMATCH",
        shipping_host.display(),
    )?;
    let before = physical_state(&cache, project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"jsonrpc_transport","phase":"before","state":before})
        )?
    );
    let transcript_path = payload.join("transport.ndjson");
    let transcript_bytes = fs::read(&transcript_path)?;
    let transcript_requests = std::str::from_utf8(&transcript_bytes)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let expected_requests =
        expected_transport_requests(&execution, &association_wave_two["read_request"]);
    require(
        transcript_requests == expected_requests,
        "ISSUE_1116_1119_TRANSPORT_TRIGGER_MISMATCH",
        json!({"observed": transcript_requests, "expected": expected_requests}),
    )?;
    let output_path = payload.join("transport-output.ndjson");
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": "jsonrpc_transport",
            "phase": "action",
            "operation": "serve_jsonrpc_ndjson",
            "transcript_path": transcript_path,
            "transcript_bytes": transcript_bytes.len(),
            "transcript_sha256": sha256(&transcript_bytes),
            "request_count": transcript_requests.len(),
            "output_path": output_path,
        }))?
    );
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)?;
    let runner = CbmToolRunner::new_default()?;
    let mut writer = BufWriter::new(output);
    astrolabe_server::serve_jsonrpc(
        &runner,
        BufReader::new(transcript_bytes.as_slice()),
        &mut writer,
    )?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    let output_bytes = fs::read(&output_path)?;
    let responses = std::str::from_utf8(&output_bytes)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    require(
        responses.len() == 7
            && responses.iter().enumerate().all(|(index, response)| {
                response["jsonrpc"] == "2.0"
                    && response["id"] == json!(index + 1)
                    && response.get("error").is_none()
            }),
        "ISSUE_1116_1119_TRANSPORT_RESPONSE_SET_INVALID",
        responses.len(),
    )?;
    let tools = responses[0]["result"]["tools"]
        .as_array()
        .ok_or("tools/list has no tools")?;
    let architecture_tool_schema = verify_get_architecture_tools_list_schema(tools)?;
    let detect_changes_tool_schema = verify_detect_changes_tools_list_schema(tools)?;
    let discovery_tool_schema = verify_discover_associations_tools_list_schema(tools)?;
    require(
        tools
            .iter()
            .any(|tool| tool["name"] == Value::String("discover_associations".to_string()))
            && tools
                .iter()
                .any(|tool| tool["name"] == Value::String("discover_latent_links".to_string()))
            && tools
                .iter()
                .any(|tool| tool["name"] == Value::String("detect_changes".to_string())),
        "ISSUE_1116_1119_TRANSPORT_TOOL_ROSTER_MISSING",
        tools.len(),
    )?;
    let projects = jsonrpc_tool_payload(&responses[1], "list_projects")?;
    let search = jsonrpc_tool_payload(&responses[2], "search_graph")?;
    let latent = jsonrpc_tool_payload(&responses[3], "discover_latent_links")?;
    let discovery = jsonrpc_tool_payload(&responses[4], "discover_associations")?;
    let detect_changes = jsonrpc_tool_payload(&responses[5], "detect_changes")?;
    let detect_changes_head_oid = fixture_source["head"]
        .as_str()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_FIXTURE_HEAD_MISSING")?;
    let detect_changes_contract = verify_detect_changes_v2_payload(
        &detect_changes,
        &transcript_requests[5]["params"]["arguments"],
        project,
        detect_changes_head_oid,
    )?;
    let detect_changes_exact_result_byte_bound = settle_detect_changes_result_byte_bound(
        &runner,
        &cache,
        project,
        detect_changes_head_oid,
        "detect_changes_exact_final_public_result_byte_bound",
    )?;
    let detect_changes_exact_bound = detect_changes_exact_result_byte_bound["bound"]
        .as_u64()
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_EXACT_RESULT_BOUND_MISSING")?;
    let detect_changes_exact_run = detect_changes_exact_result_byte_bound["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .and_then(|round| round.get("run"))
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_EXACT_RESULT_RUN_MISSING")?;
    require(
        detect_changes_exact_bound > 1
            && detect_changes_exact_run["final_public_mcp_result_bytes"]
                == detect_changes_exact_bound
            && detect_changes_exact_run["request"]["result_max_bytes"]
                == detect_changes_exact_bound
            && detect_changes_exact_run["response"]["result_max_bytes"]
                == detect_changes_exact_bound,
        "ISSUE_1116_1119_DETECT_CHANGES_EXACT_RESULT_BOUND_NOT_EXACT",
        &detect_changes_exact_result_byte_bound,
    )?;
    let detect_changes_below_request =
        detect_changes_fsv_request(project, detect_changes_exact_bound - 1);
    let detect_changes_one_byte_below = expect_detect_changes_result_bound_refusal(
        &runner,
        &cache,
        project,
        "detect_changes_final_public_result_one_byte_below",
        &detect_changes_below_request,
    )?;
    require(
        detect_changes_one_byte_below["request"]["result_max_bytes"]
            == detect_changes_exact_bound - 1
            && detect_changes_one_byte_below["response"]["code"]
                == "ASTRO_DETECT_CHANGES_RESULT_BOUND_EXCEEDED"
            && detect_changes_one_byte_below["response"]["failed_stage"]
                == "final_public_mcp_result_bytes",
        "ISSUE_1116_1119_DETECT_CHANGES_ONE_BYTE_BELOW_INVALID",
        &detect_changes_one_byte_below,
    )?;
    let architecture = jsonrpc_tool_payload(&responses[6], "get_architecture")?;
    let architecture_result_bytes = serde_json::to_vec(&responses[6]["result"])?;
    let architecture_payload_text = responses[6]["result"]["content"][0]["text"]
        .as_str()
        .ok_or("ISSUE_1149_TRANSPORT_ARCHITECTURE_TEXT_MISSING")?;
    let admitted_projects = projects["projects"]
        .as_array()
        .ok_or("list_projects projects array is missing")?;
    require(
        projects["cache_enumeration_complete"] == Value::Bool(true)
            && projects["discovery_complete"] == Value::Bool(true)
            && projects["candidate_store_count"]
                .as_u64()
                .is_some_and(|count| count >= 6)
            && projects["admitted_store_count"]
                .as_u64()
                .is_some_and(|count| count >= 6)
            && projects["excluded_store_count"] == 0
            && admitted_projects
                .iter()
                .any(|candidate| candidate["name"] == Value::String(project.to_string()))
            && responses[1]["result"]["isError"] != Value::Bool(true)
            && responses[2]["result"]["isError"] != Value::Bool(true)
            && responses[3]["result"]["isError"] != Value::Bool(true)
            && responses[4]["result"]["isError"] != Value::Bool(true)
            && responses[5]["result"]["isError"] != Value::Bool(true)
            && responses[6]["result"]["isError"] != Value::Bool(true)
            && architecture == execution["architecture_clusters"]["exact"]["response"]
            && exact_fields_equal(
                &search,
                &execution["search"]["first"],
                &[
                    "mode",
                    "project",
                    "query",
                    "result_count",
                    "results",
                    "servable_slots",
                    "manifest",
                    "trust",
                    "freshness",
                    "provenance",
                ],
            )
            && exact_fields_equal(
                &latent,
                &execution["latent"]["first"],
                &[
                    "schema",
                    "envelope_schema",
                    "project",
                    "mode",
                    "relation",
                    "config",
                    "node_count",
                    "pair_count",
                    "pairs",
                    "artifact_sha256",
                    "artifact_bytes",
                    "trust",
                    "freshness",
                    "provenance",
                ],
            )
            && latent["persistence"]["state"] == Value::String("unchanged".to_string())
            && latent["persistence"]["ledger_ref"]
                == execution["latent"]["first"]["persistence"]["ledger_ref"]
            && discovery == association_wave_two["read"],
        "ISSUE_1116_1119_TRANSPORT_PAYLOAD_MISMATCH",
        json!({"projects":projects,"search":search,"latent":latent,"discovery":discovery,"detect_changes":detect_changes,"architecture":architecture}),
    )?;
    let after = physical_state(&cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case":"jsonrpc_transport","phase":"after","state":after}))?
    );
    require(
        before["sha256"] == after["sha256"],
        "ISSUE_1116_1119_TRANSPORT_MUTATED_STATE",
        &after,
    )?;
    let receipt = json!({
        "schema": "astrolabe.issues-1116-1119.transport.v1",
        "tree_sha": canonical_head()?,
        "source_generation_schema": worker_source_generation::SOURCE_GENERATION_SCHEMA,
        "source_generation_sha256": source_generation,
        "driver_artifact": current_driver_artifact_state()?,
        "verified_worker": verified_worker,
        "verified_worker_identity": verified_worker_identity,
        "supervisor_should_wrap": supervisor_should_wrap(),
        "transcript": {
            "path": transcript_path,
            "bytes": transcript_bytes.len(),
            "sha256": sha256(&transcript_bytes),
            "request_count": transcript_requests.len(),
        },
        "output": {
            "path": output_path,
            "bytes": output_bytes.len(),
            "sha256": sha256(&output_bytes),
        },
        "response_count": responses.len(),
        "tool_count": tools.len(),
        "get_architecture_tool_schema": architecture_tool_schema,
        "detect_changes_tool_schema": detect_changes_tool_schema,
        "discover_associations_tool_schema": discovery_tool_schema,
        "association_publication": {
            "wave": association_wave_two["wave"],
            "artifact_sha256": association_wave_two["publication"]["response"]["artifact_sha256"],
            "read_request": association_wave_two["read_request"],
        },
        "projects": projects,
        "search": search,
        "latent": latent,
        "discovery": discovery,
        "detect_changes": detect_changes_contract,
        "detect_changes_result_byte_bound": {
            "runtime_mode": "transport process after the seven-call real NDJSON exchange",
            "runtime_order": [
                "request id 6: successful detect_changes with the explicit wide result bound",
                "request id 7: ordinary get_architecture completes the persisted transcript",
                "deterministically settle an exact complete post-augmentation public-result byte bound",
                "send that exact bound successfully",
                "send exact bound minus one through public JSON-RPC and require the Rust final-envelope refusal"
            ],
            "exact": detect_changes_exact_result_byte_bound,
            "one_byte_below": detect_changes_one_byte_below,
            "measured_surface": "complete final public MCP result String after grounded augmentation",
            "cost_boundary": {
                "operation": "manual Full State Verification only",
                "fixture": "one real clean committed repository with explicit changed-file, impact, reach, and final-result bounds",
                "production_n": 192873,
                "production_e": 328899,
                "fixture_is_not_cost_evidence": true,
                "defect_classes": ["PC-16", "PC-24", "PC-37", "PC-38", "PC-41"],
                "invariant": "canonical clean Git head/base identity, closed request fields, fixed explicit caller bounds, deterministic compact serialization"
            },
            "exact_and_one_byte_below_exercised": true,
        },
        "architecture": architecture,
        "architecture_exchange": {
            "request": transcript_requests[6],
            "result_bytes": architecture_result_bytes.len(),
            "result_sha256": sha256(&architecture_result_bytes),
            "payload_text_bytes": architecture_payload_text.len(),
            "payload_text_sha256": sha256(architecture_payload_text.as_bytes()),
            "exact_execution_response_equal": true,
        },
        "before": before,
        "after": after,
        "state_unchanged": true,
    });
    let receipt_bytes = serde_json::to_vec_pretty(&receipt)?;
    let persisted = write_new_readback(&payload.join("transport-receipt.json"), &receipt_bytes)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event": "ISSUE_1116_1119_TRANSPORT_COMPLETE",
            "receipt": persisted,
            "state_sha256": after["sha256"],
        }))?
    );
    Ok(())
}

fn cf_from_name(name: &str) -> AnyResult<ColumnFamily> {
    match name {
        "Kernel" => Ok(ColumnFamily::Kernel),
        "Assay" => Ok(ColumnFamily::Assay),
        "Graph" => Ok(ColumnFamily::Graph),
        other => Err(format!("unsupported physical stage CF {other}").into()),
    }
}

fn read_cf_state(
    vault: &AsterVault,
    snapshot: u64,
    cf: ColumnFamily,
    key: &[u8],
) -> AnyResult<Value> {
    let bytes = vault
        .read_cf_at(snapshot, cf, key)?
        .ok_or_else(|| format!("physical row absent cf={cf:?} key={}", hex_lower(key)))?;
    Ok(json!({
        "cf": format!("{cf:?}"),
        "key_hex": hex_lower(key),
        "bytes": bytes.len(),
        "sha256": sha256(&bytes),
        "json": serde_json::from_slice::<Value>(&bytes).ok(),
    }))
}

fn verify_ledger(
    vault: &AsterVault,
    snapshot: u64,
    reference: &Value,
    expected_actor: &str,
    expected_subject: &[u8],
    expected_payload: &[u8],
) -> AnyResult<Value> {
    let seq = reference["seq"].as_u64().ok_or("ledger ref seq missing")?;
    let expected_hash = reference["hash"]
        .as_str()
        .ok_or("ledger ref hash missing")?;
    let bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Ledger, &ledger_key(seq))?
        .ok_or("ledger row absent")?;
    let entry = calyx_ledger::decode(&bytes)?;
    require(
        entry.verify()
            && entry.seq == seq
            && hex_lower(&entry.entry_hash) == expected_hash
            && matches!(&entry.actor, ActorId::Service(actor) if actor == expected_actor)
            && matches!(&entry.subject, SubjectId::Kernel(subject) if subject == expected_subject)
            && entry.payload == expected_payload,
        "ISSUE_1116_1119_LEDGER_REF_MISMATCH",
        seq,
    )?;
    Ok(json!({
        "seq": seq,
        "bytes": bytes.len(),
        "sha256": sha256(&bytes),
        "entry_hash": hex_lower(&entry.entry_hash),
        "payload_bytes": entry.payload.len(),
        "payload_sha256": sha256(&entry.payload),
        "actor": expected_actor,
        "subject_hex": hex_lower(expected_subject),
        "payload_bound_to_manifest": true,
        "verified": true,
    }))
}

fn discovery_pointer_key(kind: &str, project: &str) -> Vec<u8> {
    format!(
        "{DISCOVERY_PREFIX_V3}pointer:{kind}:{}",
        sha256(project.as_bytes())
    )
    .into_bytes()
}

fn verify_discovery_ledger_manifest(
    vault: &AsterVault,
    snapshot: u64,
    manifest: &Value,
) -> AnyResult<Value> {
    let reference = &manifest["ledger_ref"];
    let seq = reference["seq"]
        .as_u64()
        .ok_or("ISSUE_1150_DISCOVERY_LEDGER_SEQ_MISSING")?;
    let expected_hash = reference["hash"]
        .as_str()
        .ok_or("ISSUE_1150_DISCOVERY_LEDGER_HASH_MISSING")?;
    let bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Ledger, &ledger_key(seq))?
        .ok_or("ISSUE_1150_DISCOVERY_LEDGER_ROW_ABSENT")?;
    let entry = calyx_ledger::decode(&bytes)?;
    let payload: Value = serde_json::from_slice(&entry.payload)?;
    let artifact_hash = manifest["artifact_sha256"]
        .as_str()
        .ok_or("ISSUE_1150_DISCOVERY_ARTIFACT_HASH_MISSING")?;
    require(
        entry.verify()
            && entry.seq == seq
            && hex_lower(&entry.entry_hash) == expected_hash
            && matches!(&entry.actor, ActorId::Service(actor) if actor == "astrolabe-association-discovery")
            && matches!(&entry.subject, SubjectId::Kernel(subject) if subject == artifact_hash.as_bytes())
            && manifest["ledger_payload_sha256"] == Value::String(sha256(&entry.payload))
            && exact_object_fields(
                &payload,
                &[
                    "schema",
                    "kind",
                    "project",
                    "source_generation_sha256",
                    "prepared_artifact_sha256",
                    "artifact_sha256",
                    "request_identity_sha256",
                    "stages",
                    "previous_artifact_sha256",
                    "retired_artifact_sha256",
                    "cross_kind_retired_artifact_sha256",
                ],
            )
            && payload["schema"] == "astrolabe.association_discovery.ledger_payload.v1"
            && payload["kind"] == manifest["kind"]
            && payload["project"] == manifest["project"]
            && payload["source_generation_sha256"] == manifest["source_generation_sha256"]
            && payload["prepared_artifact_sha256"] == manifest["prepared_artifact_sha256"]
            && payload["artifact_sha256"] == manifest["artifact_sha256"]
            && payload["request_identity_sha256"] == manifest["request_identity_sha256"]
            && payload["stages"] == manifest["stages"]
            && payload["previous_artifact_sha256"] == manifest["previous_artifact_sha256"]
            && payload["retired_artifact_sha256"] == manifest["retired_artifact_sha256"],
        "ISSUE_1150_DISCOVERY_LEDGER_PAYLOAD_MISMATCH",
        json!({"manifest":manifest,"payload":payload,"seq":seq}),
    )?;
    Ok(json!({
        "seq":seq,
        "bytes":bytes.len(),
        "sha256":sha256(&bytes),
        "entry_hash":hex_lower(&entry.entry_hash),
        "payload":payload,
        "payload_bytes":entry.payload.len(),
        "payload_sha256":sha256(&entry.payload),
        "verified":true,
    }))
}

fn read_discovery_logical_stage(
    vault: &AsterVault,
    snapshot: u64,
    cf: ColumnFamily,
    base: &str,
    name: &str,
) -> AnyResult<(Vec<u8>, Value)> {
    let key = format!("{base}{name}").into_bytes();
    let bytes = vault
        .read_cf_at(snapshot, cf, &key)?
        .ok_or("ISSUE_1150_DISCOVERY_LOGICAL_STAGE_ABSENT")?;
    let value: Value = serde_json::from_slice(&bytes)?;
    if value["schema"] != "astrolabe.association_discovery.chunk_descriptor.v1" {
        return Ok((bytes, value));
    }
    let chunks = value["chunks"]
        .as_array()
        .ok_or("ISSUE_1150_DISCOVERY_CHUNK_ROSTER_MISSING")?;
    let mut logical = Vec::with_capacity(usize::try_from(
        value["logical_bytes"]
            .as_u64()
            .ok_or("ISSUE_1150_DISCOVERY_LOGICAL_BYTE_COUNT_MISSING")?,
    )?);
    for (ordinal, chunk) in chunks.iter().enumerate() {
        let chunk_key = decode_hex(
            chunk["key_hex"]
                .as_str()
                .ok_or("ISSUE_1150_DISCOVERY_CHUNK_KEY_MISSING")?,
        )?;
        let chunk_bytes = vault
            .read_cf_at(snapshot, cf, &chunk_key)?
            .ok_or("ISSUE_1150_DISCOVERY_CHUNK_ABSENT")?;
        require(
            chunk["ordinal"].as_u64() == u64::try_from(ordinal).ok()
                && chunk["bytes"].as_u64() == u64::try_from(chunk_bytes.len()).ok()
                && chunk["sha256"] == Value::String(sha256(&chunk_bytes)),
            "ISSUE_1150_DISCOVERY_CHUNK_MISMATCH",
            json!({"descriptor":value,"chunk":chunk,"ordinal":ordinal}),
        )?;
        logical.extend_from_slice(&chunk_bytes);
    }
    require(
        value["logical_name"] == name
            && value["logical_bytes"].as_u64() == u64::try_from(logical.len()).ok()
            && value["logical_sha256"] == Value::String(sha256(&logical)),
        "ISSUE_1150_DISCOVERY_LOGICAL_STAGE_MISMATCH",
        &value,
    )?;
    let decoded: Value = serde_json::from_slice(&logical)?;
    Ok((logical, decoded))
}

fn discovery_retained_generation_state(
    vault: &AsterVault,
    snapshot: u64,
    kind: &str,
    project: &str,
    target: &Value,
) -> AnyResult<Value> {
    let artifact_hash = target["artifact_sha256"]
        .as_str()
        .ok_or("ISSUE_1150_DISCOVERY_TARGET_HASH_MISSING")?;
    let manifest_key = decode_hex(
        target["manifest_key_hex"]
            .as_str()
            .ok_or("ISSUE_1150_DISCOVERY_MANIFEST_KEY_MISSING")?,
    )?;
    let expected_manifest_key =
        format!("{DISCOVERY_PREFIX_V3}{kind}:{artifact_hash}:manifest").into_bytes();
    let manifest_bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &manifest_key)?
        .ok_or("ISSUE_1150_DISCOVERY_MANIFEST_ABSENT")?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    require(
        manifest_key == expected_manifest_key
            && target["manifest_sha256"] == Value::String(sha256(&manifest_bytes))
            && target["commit_seq"].as_u64().is_some_and(|seq| seq > 0)
            && target["commit_seq"]
                .as_u64()
                .is_some_and(|seq| seq <= snapshot)
            && target["ledger_ref"] == manifest["ledger_ref"]
            && exact_object_fields(
                &manifest,
                &[
                    "schema",
                    "kind",
                    "project",
                    "source_generation_sha256",
                    "prepared_artifact_sha256",
                    "artifact_sha256",
                    "request_identity_sha256",
                    "stages",
                    "ledger_ref",
                    "ledger_payload_sha256",
                    "previous_artifact_sha256",
                    "retired_artifact_sha256",
                    "retention",
                ],
            )
            && manifest["schema"] == DISCOVERY_PERSISTED_SCHEMA_V3
            && manifest["kind"] == kind
            && manifest["project"] == project
            && manifest["artifact_sha256"] == artifact_hash
            && manifest["retention"]
                == "bounded_current_plus_previous; retired immutable rows are tombstoned in the same pointer/manifest/Ledger transaction",
        "ISSUE_1150_DISCOVERY_MANIFEST_INVALID",
        json!({"target":target,"manifest":manifest}),
    )?;
    let stages = manifest["stages"]
        .as_array()
        .ok_or("ISSUE_1150_DISCOVERY_MANIFEST_STAGES_MISSING")?;
    let mut physical_stages = Vec::with_capacity(stages.len());
    let mut names = BTreeSet::new();
    for stage in stages {
        let cf = cf_from_name(
            stage["cf"]
                .as_str()
                .ok_or("ISSUE_1150_DISCOVERY_STAGE_CF_MISSING")?,
        )?;
        let name = stage["name"]
            .as_str()
            .ok_or("ISSUE_1150_DISCOVERY_STAGE_NAME_MISSING")?;
        let key = decode_hex(
            stage["key_hex"]
                .as_str()
                .ok_or("ISSUE_1150_DISCOVERY_STAGE_KEY_MISSING")?,
        )?;
        let expected_key = format!("{DISCOVERY_PREFIX_V3}{kind}:{artifact_hash}:{name}");
        let row = read_cf_state(vault, snapshot, cf, &key)?;
        require(
            key == expected_key.as_bytes()
                && row["bytes"] == stage["bytes"]
                && row["sha256"] == stage["sha256"]
                && names.insert(name),
            "ISSUE_1150_DISCOVERY_STAGE_PHYSICAL_MISMATCH",
            json!({"stage":stage,"row":row,"expected_key":expected_key}),
        )?;
        physical_stages.push(row);
    }
    let expected_core_names = if kind == "prepared" {
        BTreeSet::from([
            "artifact",
            "source_manifest",
            "concept_map",
            "typed_edges",
            "latent",
            "spectral",
            "walks",
            "candidates",
            "evaluation_roster",
            "validation",
        ])
    } else {
        BTreeSet::from([
            "artifact",
            "source_manifest",
            "evaluation_roster",
            "evaluator_receipts",
            "evaluator",
            "ranked",
            "reasoning_kernel",
        ])
    };
    require(
        expected_core_names.iter().all(|name| names.contains(name)),
        "ISSUE_1150_DISCOVERY_LOGICAL_STAGE_ROSTER_INCOMPLETE",
        json!({"kind":kind,"expected":expected_core_names,"observed":names}),
    )?;
    let base = format!("{DISCOVERY_PREFIX_V3}{kind}:{artifact_hash}:");
    let (_, header) =
        read_discovery_logical_stage(vault, snapshot, ColumnFamily::Kernel, &base, "artifact")?;
    let artifact_schema = if kind == "prepared" {
        DISCOVERY_PREPARED_SCHEMA_V4
    } else {
        DISCOVERY_FINAL_SCHEMA_V4
    };
    require(
        header["schema"] == "astrolabe.association_discovery.compact_header.v1"
            && header["artifact_sha256"] == artifact_hash
            && header["artifact_fields"]["schema"] == artifact_schema,
        "ISSUE_1150_DISCOVERY_COMPACT_HEADER_INVALID",
        &header,
    )?;
    let (_, source_manifest) = read_discovery_logical_stage(
        vault,
        snapshot,
        ColumnFamily::Kernel,
        &base,
        "source_manifest",
    )?;
    let (_, evaluation_roster) = read_discovery_logical_stage(
        vault,
        snapshot,
        ColumnFamily::Assay,
        &base,
        "evaluation_roster",
    )?;
    require(
        source_manifest["schema"] == "astrolabe.association_discovery.source_manifest.v3"
            && source_manifest["project"] == project
            && evaluation_roster["schema"]
                == "astrolabe.association_discovery.evaluation_roster.v2"
            && evaluation_roster["binding_count"].as_u64().is_some()
            && evaluation_roster["bindings"]
                .as_array()
                .is_some_and(|bindings| {
                    u64::try_from(bindings.len()).ok()
                        == evaluation_roster["binding_count"].as_u64()
                }),
        "ISSUE_1150_DISCOVERY_SOURCE_OR_ROSTER_SCHEMA_INVALID",
        json!({"source_manifest":source_manifest,"evaluation_roster":evaluation_roster}),
    )?;
    let evaluator_receipts = if kind == "final" {
        let (_, evaluator_receipts_value) = read_discovery_logical_stage(
            vault,
            snapshot,
            ColumnFamily::Assay,
            &base,
            "evaluator_receipts",
        )?;
        let evaluator_receipts = evaluator_receipts_value
            .as_array()
            .ok_or("ISSUE_1150_DISCOVERY_FINAL_RECEIPT_ROW_INVALID")?;
        require(
            !evaluator_receipts.is_empty()
                && evaluator_receipts.iter().all(|receipt| {
                    receipt["schema"] == DISCOVERY_RECEIPT_SCHEMA_V2
                        && receipt["capture_schema"] == DISCOVERY_CAPTURE_SCHEMA_V1
                        && receipt["provider_response_id"]
                            .as_str()
                            .is_some_and(|value| !value.trim().is_empty())
                }),
            "ISSUE_1150_DISCOVERY_FINAL_RECEIPT_SCHEMA_INVALID",
            evaluator_receipts.len(),
        )?;
        evaluator_receipts_value
    } else {
        Value::Null
    };
    let validation = if kind == "prepared" {
        let (_, value) = read_discovery_logical_stage(
            vault,
            snapshot,
            ColumnFamily::Assay,
            &base,
            "validation",
        )?;
        value
    } else {
        Value::Null
    };
    let ledger = verify_discovery_ledger_manifest(vault, snapshot, &manifest)?;
    Ok(json!({
        "target":target,
        "manifest_key_hex":hex_lower(&manifest_key),
        "manifest_bytes":manifest_bytes.len(),
        "manifest_sha256":sha256(&manifest_bytes),
        "manifest":manifest,
        "physical_stages":physical_stages,
        "compact_header":header,
        "source_manifest":source_manifest,
        "evaluation_roster":evaluation_roster,
        "evaluator_receipts":evaluator_receipts,
        "validation":validation,
        "ledger":ledger,
    }))
}

fn discovery_kind_retention_state(
    vault: &AsterVault,
    snapshot: u64,
    kind: &str,
    project: &str,
) -> AnyResult<Value> {
    let key = discovery_pointer_key(kind, project);
    let pointer_bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &key)?
        .ok_or_else(|| format!("ISSUE_1150_DISCOVERY_{kind}_POINTER_ABSENT"))?;
    let pointer: Value = serde_json::from_slice(&pointer_bytes)?;
    require(
        exact_object_fields(
            &pointer,
            &[
                "schema",
                "kind",
                "project",
                "pointer_commit_seq",
                "current",
                "previous",
                "retained_generation_count",
            ],
        ) && pointer["schema"] == "astrolabe.association_discovery.pointer.v1"
            && pointer["kind"] == kind
            && pointer["project"] == project
            && pointer["pointer_commit_seq"] == pointer["current"]["commit_seq"]
            && pointer["pointer_commit_seq"]
                .as_u64()
                .is_some_and(|seq| seq > 0 && seq <= snapshot)
            && exact_object_fields(
                &pointer["current"],
                &[
                    "artifact_sha256",
                    "manifest_key_hex",
                    "manifest_sha256",
                    "commit_seq",
                    "ledger_ref",
                ],
            )
            && (pointer["previous"].is_null()
                || exact_object_fields(
                    &pointer["previous"],
                    &[
                        "artifact_sha256",
                        "manifest_key_hex",
                        "manifest_sha256",
                        "commit_seq",
                        "ledger_ref",
                    ],
                ))
            && pointer["retained_generation_count"].as_u64()
                == Some(1 + u64::from(!pointer["previous"].is_null())),
        "ISSUE_1150_DISCOVERY_POINTER_INVALID",
        &pointer,
    )?;
    let current =
        discovery_retained_generation_state(vault, snapshot, kind, project, &pointer["current"])?;
    let previous = if pointer["previous"].is_null() {
        Value::Null
    } else {
        discovery_retained_generation_state(vault, snapshot, kind, project, &pointer["previous"])?
    };
    Ok(json!({
        "pointer_key_hex":hex_lower(&key),
        "pointer_bytes":pointer_bytes.len(),
        "pointer_sha256":sha256(&pointer_bytes),
        "pointer":pointer,
        "current":current,
        "previous":previous,
    }))
}

fn discovery_retention_state(cache: &Path, project: &str, retired: &[Value]) -> AnyResult<Value> {
    let (vault, _) = open_vault_selected(
        cache,
        project,
        vec![
            ColumnFamily::Kernel,
            ColumnFamily::Assay,
            ColumnFamily::Ledger,
            ColumnFamily::TimeIndex,
        ],
    )?;
    let snapshot = vault.latest_seq();
    let prepared = discovery_kind_retention_state(&vault, snapshot, "prepared", project)?;
    let final_state = discovery_kind_retention_state(&vault, snapshot, "final", project)?;
    let retirement_inventory = if retired.is_empty() {
        None
    } else {
        let retirement_seq = prepared["current"]["target"]["commit_seq"]
            .as_u64()
            .ok_or("ISSUE_1150_RETIREMENT_COMMIT_SEQ_MISSING")?;
        Some(vault.physical_wal_commit_inventory(
            retirement_seq,
            &[
                ColumnFamily::Kernel,
                ColumnFamily::Assay,
                ColumnFamily::Ledger,
                ColumnFamily::TimeIndex,
            ],
        )?)
    };
    let mut physical_retirement_rows = BTreeMap::new();
    if let Some(inventory) = &retirement_inventory {
        for row in &inventory.rows {
            physical_retirement_rows
                .entry(row.cf)
                .or_insert_with(BTreeMap::new)
                .entry(row.key.clone())
                .and_modify(|entry| *entry = None)
                .or_insert(Some(row));
        }
    }
    let tombstone = tombstone_value();
    let mut retired_rows = Vec::new();
    for generation in retired {
        let kind = generation["kind"]
            .as_str()
            .ok_or("ISSUE_1150_RETIRED_KIND_MISSING")?;
        let persistence = &generation["persistence"];
        let stages = persistence["stages"]
            .as_array()
            .filter(|stages| !stages.is_empty())
            .ok_or("ISSUE_1150_RETIRED_STAGES_MISSING")?;
        require(
            persistence["schema"] == DISCOVERY_PERSISTED_SCHEMA_V3
                && persistence["rows_read_back_verified"].as_u64()
                    == u64::try_from(stages.len()).ok()
                && persistence["ledger_paired"] == Value::Bool(true),
            "ISSUE_1150_RETIRED_PERSISTENCE_RECEIPT_INVALID",
            persistence,
        )?;
        let artifact_hash = generation["artifact_sha256"]
            .as_str()
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or("ISSUE_1150_RETIRED_ARTIFACT_IDENTITY_MISSING")?;
        let mut keys = stages
            .iter()
            .map(|stage| {
                Ok((
                    cf_from_name(
                        stage["cf"]
                            .as_str()
                            .ok_or("ISSUE_1150_RETIRED_STAGE_CF_MISSING")?,
                    )?,
                    decode_hex(
                        stage["key_hex"]
                            .as_str()
                            .ok_or("ISSUE_1150_RETIRED_STAGE_KEY_MISSING")?,
                    )?,
                ))
            })
            .collect::<AnyResult<Vec<_>>>()?;
        keys.push((
            ColumnFamily::Kernel,
            format!("{DISCOVERY_PREFIX_V3}{kind}:{artifact_hash}:manifest").into_bytes(),
        ));
        let mut rows = Vec::with_capacity(keys.len());
        for (cf, key) in keys {
            let inventory = retirement_inventory
                .as_ref()
                .ok_or("ISSUE_1150_RETIREMENT_INVENTORY_MISSING")?;
            let physical = physical_retirement_rows
                .get(&cf)
                .and_then(|rows| rows.get(key.as_slice()))
                .and_then(|row| *row)
                .ok_or("ISSUE_1150_RETIRED_PHYSICAL_WAL_ROW_ABSENT_OR_DUPLICATED")?;
            let logical = vault.read_cf_at(snapshot, cf, &key)?;
            require(
                logical.is_none()
                    && physical.key_sha256_hex() == sha256(&key)
                    && physical.tombstoned
                    && physical.value_length == u64::try_from(tombstone.len())?
                    && physical.value_sha256_hex() == sha256(&tombstone),
                "ISSUE_1150_RETIRED_ROW_NOT_TOMBSTONE",
                json!({"kind":kind,"artifact_sha256":artifact_hash,"cf":format!("{cf:?}"),"key_hex":hex_lower(&key),"logical":logical,"physical_tombstoned":physical.tombstoned,"physical_value_bytes":physical.value_length,"physical_value_sha256":physical.value_sha256_hex()}),
            )?;
            rows.push(json!({
                "cf":format!("{cf:?}"),
                "key_hex":hex_lower(&key),
                "physical_commit_seq":inventory.seq,
                "physical_row_ordinal":physical.ordinal,
                "value_bytes":physical.value_length,
                "value_sha256":physical.value_sha256_hex(),
                "logical_absent":logical.is_none(),
                "exact_tombstone":true,
            }));
        }
        let ledger_seq = persistence["ledger_ref"]["seq"]
            .as_u64()
            .ok_or("ISSUE_1150_RETIRED_LEDGER_SEQ_MISSING")?;
        let ledger_bytes = vault
            .read_cf_at(snapshot, ColumnFamily::Ledger, &ledger_key(ledger_seq))?
            .ok_or("ISSUE_1150_RETIRED_LEDGER_ROW_ABSENT")?;
        let ledger = calyx_ledger::decode(&ledger_bytes)?;
        let ledger_payload: Value = serde_json::from_slice(&ledger.payload)?;
        require(
            ledger.verify()
                && ledger.seq == ledger_seq
                && persistence["ledger_ref"]["hash"] == hex_lower(&ledger.entry_hash)
                && ledger_payload["schema"] == "astrolabe.association_discovery.ledger_payload.v1"
                && ledger_payload["kind"] == kind
                && ledger_payload["artifact_sha256"] == artifact_hash
                && ledger_payload["stages"] == persistence["stages"],
            "ISSUE_1150_RETIRED_LEDGER_INVALID",
            json!({"seq":ledger_seq,"payload":ledger_payload}),
        )?;
        retired_rows.push(json!({
            "kind":kind,
            "artifact_sha256":artifact_hash,
            "rows":rows,
            "ledger":{"seq":ledger_seq,"bytes":ledger_bytes.len(),"sha256":sha256(&ledger_bytes),"entry_hash":hex_lower(&ledger.entry_hash),"payload":ledger_payload,"verified":true},
        }));
    }
    let physical_retirement = retirement_inventory.as_ref().map(|inventory| {
        json!({
            "seq":inventory.seq,
            "wal_replay_floor_seq":inventory.wal_replay_floor_seq,
            "column_families":inventory.column_families.iter().map(|cf| format!("{cf:?}")).collect::<Vec<_>>(),
            "row_count":inventory.rows.len(),
            "wal_record":{
                "container":inventory.wal_record.container.name(),
                "relative_path":inventory.wal_record.relative_path,
                "offset":inventory.wal_record.offset,
                "length":inventory.wal_record.length,
                "sha256":inventory.wal_record.sha256_hex(),
            },
            "exact_framed_wal_commit_redecoded":true,
        })
    });
    Ok(json!({
        "snapshot_seq":snapshot,
        "prepared":prepared,
        "final":final_state,
        "retired":retired_rows,
        "physical_retirement_commit":physical_retirement,
        "physical_current_previous_and_ledger_verified":true,
        "retired_exact_tombstones_verified":!retired.is_empty(),
    }))
}

fn verify_latent_rows(vault: &AsterVault, snapshot: u64, execution: &Value) -> AnyResult<Value> {
    let first = &execution["latent"]["first"]["persistence"];
    let second = &execution["latent"]["second"]["persistence"];
    let request_hex = first["request_sha256"]
        .as_str()
        .ok_or("latent request hash missing")?;
    let request_bytes = decode_hex(request_hex)?;
    require(
        request_bytes.len() == 32,
        "ISSUE_1116_1119_LATENT_REQUEST_HASH_INVALID",
        request_hex,
    )?;
    let artifact_key = decode_hex(
        first["artifact_key_hex"]
            .as_str()
            .ok_or("artifact key missing")?,
    )?;
    let manifest_key = decode_hex(
        first["manifest_key_hex"]
            .as_str()
            .ok_or("manifest key missing")?,
    )?;
    let expected_artifact_key = format!("astrolabe:latent:v1:{request_hex}:artifact").into_bytes();
    let expected_manifest_key = format!("astrolabe:latent:v1:{request_hex}:manifest").into_bytes();
    require(
        artifact_key == expected_artifact_key && manifest_key == expected_manifest_key,
        "ISSUE_1116_1119_LATENT_KEY_DERIVATION_MISMATCH",
        request_hex,
    )?;
    let artifact_bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &artifact_key)?
        .ok_or("latent artifact row absent")?;
    let manifest_bytes = vault
        .read_cf_at(snapshot, ColumnFamily::Kernel, &manifest_key)?
        .ok_or("latent manifest row absent")?;
    let artifact = read_cf_state(vault, snapshot, ColumnFamily::Kernel, &artifact_key)?;
    let manifest = read_cf_state(vault, snapshot, ColumnFamily::Kernel, &manifest_key)?;
    let manifest_json: Value = serde_json::from_slice(&manifest_bytes)?;
    let project = execution["project"]
        .as_str()
        .ok_or("execution project missing")?;
    require(
        artifact["bytes"] == first["artifact_bytes"]
            && artifact["sha256"] == first["artifact_sha256"]
            && manifest["bytes"] == first["manifest_bytes"]
            && manifest["sha256"] == first["manifest_sha256"]
            && first["request_sha256"] == second["request_sha256"]
            && first["artifact_sha256"] == second["artifact_sha256"]
            && first["manifest_sha256"] == second["manifest_sha256"]
            && first["ledger_ref"] == second["ledger_ref"]
            && manifest_json["schema"] == "astrolabe.latent_persisted.v1"
            && manifest_json["project"] == project
            && manifest_json["request_sha256"] == request_hex
            && manifest_json["artifact_sha256"] == sha256(&artifact_bytes)
            && manifest_json["artifact_bytes"] == artifact_bytes.len() as u64
            && manifest_json["mode"] == execution["latent"]["request"]["mode"]
            && manifest_json["relation"] == execution["latent"]["request"]["relation"],
        "ISSUE_1116_1119_LATENT_PHYSICAL_MISMATCH",
        first,
    )?;
    let ledger = verify_ledger(
        vault,
        snapshot,
        &first["ledger_ref"],
        "astrolabe-latent-discovery",
        &request_bytes,
        &manifest_bytes,
    )?;
    Ok(json!({
        "artifact": artifact,
        "manifest": manifest,
        "manifest_contract": manifest_json,
        "ledger": ledger,
        "repeat_identity": true,
    }))
}

fn close(actual: f64, expected: f64, label: &str) -> AnyResult<()> {
    require(
        (actual - expected).abs() <= 1.0e-12,
        "ISSUE_1116_1119_VALIDATION_ARITHMETIC_MISMATCH",
        format!("{label}: actual={actual} expected={expected}"),
    )
}

fn verify_stability(
    name: &str,
    actual: Option<&astrolabe_kernel::ValidationMetricStability>,
    values: &[f64],
) -> AnyResult<()> {
    if values.is_empty() {
        return require(
            actual.is_none(),
            "ISSUE_1116_1119_EMPTY_STABILITY_FABRICATED",
            name,
        );
    }
    let actual = actual.ok_or_else(|| format!("{name} stability absent"))?;
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| {
            let delta = *value - mean;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;
    let minimum = values.iter().copied().fold(f64::INFINITY, f64::min);
    let maximum = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    require(
        actual.sample_count == values.len(),
        "ISSUE_1116_1119_STABILITY_DENOMINATOR_MISMATCH",
        name,
    )?;
    close(actual.mean, mean, &format!("{name}.mean"))?;
    close(
        actual.population_stddev,
        variance.sqrt(),
        &format!("{name}.population_stddev"),
    )?;
    close(actual.minimum, minimum, &format!("{name}.minimum"))?;
    close(actual.maximum, maximum, &format!("{name}.maximum"))
}

fn verify_mean(name: &str, actual: f64, values: &[f64]) -> AnyResult<()> {
    require(
        !values.is_empty(),
        "ISSUE_1116_1119_MEAN_DENOMINATOR_EMPTY",
        name,
    )?;
    close(
        actual,
        values.iter().sum::<f64>() / values.len() as f64,
        name,
    )
}

fn verify_optional_mean(name: &str, actual: Option<f64>, values: &[f64]) -> AnyResult<()> {
    if values.is_empty() {
        return require(
            actual.is_none(),
            "ISSUE_1116_1119_EMPTY_MEAN_FABRICATED",
            name,
        );
    }
    verify_mean(
        name,
        actual.ok_or_else(|| format!("{name} mean absent"))?,
        values,
    )
}

fn verify_validation(report: &CrossValidationReport, top_k: usize) -> AnyResult<Value> {
    let usable = report
        .folds
        .iter()
        .filter(|fold| fold.usable)
        .collect::<Vec<_>>();
    let unusable_count = report.folds.len().saturating_sub(usable.len());
    require(
        usable.len() == report.usable_fold_count
            && !usable.is_empty()
            && unusable_count > 0
            && usable.iter().any(|fold| fold.evaluation_pair_count > 0),
        "ISSUE_1116_1119_USABLE_FOLD_COUNT_MISMATCH",
        format!("usable={} unusable={unusable_count}", usable.len()),
    )?;
    for fold in &report.folds {
        require(
            fold.rank_score_semantics
                == "resource_allocation_rank_score_not_a_calibrated_probability",
            "ISSUE_1116_1119_RA_SEMANTICS_MISMATCH",
            fold.fold,
        )?;
        if !fold.usable {
            require(
                fold.binary_brier_at_k.is_none()
                    && fold.no_skill_binary_brier.is_none()
                    && fold.binary_brier_skill_at_k.is_none(),
                "ISSUE_1116_1119_UNUSABLE_FOLD_FABRICATED",
                fold.fold,
            )?;
            continue;
        }
        let k = top_k.min(fold.predicted_pair_count);
        let fp = k.saturating_sub(fold.hits_at_k);
        let fn_count = fold.held_out_pair_count.saturating_sub(fold.hits_at_k);
        let union = fold.predicted_pair_count.saturating_add(
            fold.held_out_pair_count
                .saturating_sub(fold.held_out_candidate_count),
        );
        require(
            fold.top_k_evaluated_count == k
                && fold.false_positives_at_k == fp
                && fold.false_negatives_at_k == fn_count
                && fold.evaluation_pair_count == union,
            "ISSUE_1116_1119_VALIDATION_COUNTS_MISMATCH",
            fold.fold,
        )?;
        let brier = (fp + fn_count) as f64 / union.max(1) as f64;
        let prevalence = fold.held_out_pair_count as f64 / union.max(1) as f64;
        let no_skill = prevalence * (1.0 - prevalence);
        close(
            fold.precision_at_k,
            fold.hits_at_k as f64 / k.max(1) as f64,
            "precision_at_k",
        )?;
        close(
            fold.recall_at_k,
            fold.hits_at_k as f64 / fold.held_out_pair_count as f64,
            "recall_at_k",
        )?;
        close(
            fold.binary_brier_at_k.ok_or("usable fold Brier missing")?,
            brier,
            "binary_brier_at_k",
        )?;
        close(
            fold.no_skill_binary_brier
                .ok_or("usable fold no-skill Brier missing")?,
            no_skill,
            "no_skill_binary_brier",
        )?;
        if no_skill > f64::EPSILON {
            close(
                fold.binary_brier_skill_at_k
                    .ok_or("usable fold Brier skill missing")?,
                1.0 - brier / no_skill,
                "binary_brier_skill_at_k",
            )?;
        } else {
            require(
                fold.binary_brier_skill_at_k.is_none(),
                "ISSUE_1116_1119_ZERO_BASELINE_SKILL_FABRICATED",
                fold.fold,
            )?;
        }
        close(
            fold.candidate_coverage_at_k,
            k as f64 / fold.predicted_pair_count.max(1) as f64,
            "candidate_coverage_at_k",
        )?;
        close(
            fold.held_out_candidate_coverage,
            fold.held_out_candidate_count as f64 / fold.held_out_pair_count.max(1) as f64,
            "held_out_candidate_coverage",
        )?;
    }
    let precision = usable
        .iter()
        .map(|fold| fold.precision_at_k)
        .collect::<Vec<_>>();
    let recall = usable
        .iter()
        .map(|fold| fold.recall_at_k)
        .collect::<Vec<_>>();
    let reciprocal_rank = usable
        .iter()
        .map(|fold| fold.reciprocal_rank)
        .collect::<Vec<_>>();
    let candidate_coverage = usable
        .iter()
        .map(|fold| fold.candidate_coverage_at_k)
        .collect::<Vec<_>>();
    let held_out_coverage = usable
        .iter()
        .map(|fold| fold.held_out_candidate_coverage)
        .collect::<Vec<_>>();
    let brier = usable
        .iter()
        .filter_map(|fold| fold.binary_brier_at_k)
        .collect::<Vec<_>>();
    let no_skill = usable
        .iter()
        .filter_map(|fold| fold.no_skill_binary_brier)
        .collect::<Vec<_>>();
    let brier_skill = usable
        .iter()
        .filter_map(|fold| fold.binary_brier_skill_at_k)
        .collect::<Vec<_>>();
    let null_hits = usable
        .iter()
        .map(|fold| fold.null_hits_at_k as f64)
        .collect::<Vec<_>>();
    verify_stability(
        "precision_at_k",
        report.stability.precision_at_k.as_ref(),
        &precision,
    )?;
    verify_stability(
        "recall_at_k",
        report.stability.recall_at_k.as_ref(),
        &recall,
    )?;
    verify_stability(
        "reciprocal_rank",
        report.stability.reciprocal_rank.as_ref(),
        &reciprocal_rank,
    )?;
    verify_stability(
        "candidate_coverage_at_k",
        report.stability.candidate_coverage_at_k.as_ref(),
        &candidate_coverage,
    )?;
    verify_stability(
        "held_out_candidate_coverage",
        report.stability.held_out_candidate_coverage.as_ref(),
        &held_out_coverage,
    )?;
    verify_stability(
        "binary_brier_at_k",
        report.stability.binary_brier_at_k.as_ref(),
        &brier,
    )?;
    verify_stability(
        "no_skill_binary_brier",
        report.stability.no_skill_binary_brier.as_ref(),
        &no_skill,
    )?;
    verify_stability(
        "binary_brier_skill_at_k",
        report.stability.binary_brier_skill_at_k.as_ref(),
        &brier_skill,
    )?;
    verify_stability(
        "null_hits_at_k",
        report.stability.null_hits_at_k.as_ref(),
        &null_hits,
    )?;
    verify_mean(
        "mean_precision_at_k",
        report.mean_precision_at_k,
        &precision,
    )?;
    verify_mean("mean_recall_at_k", report.mean_recall_at_k, &recall)?;
    verify_mean(
        "mean_reciprocal_rank",
        report.mean_reciprocal_rank,
        &reciprocal_rank,
    )?;
    verify_mean(
        "mean_candidate_coverage_at_k",
        report.mean_candidate_coverage_at_k,
        &candidate_coverage,
    )?;
    verify_mean(
        "mean_held_out_candidate_coverage",
        report.mean_held_out_candidate_coverage,
        &held_out_coverage,
    )?;
    verify_optional_mean(
        "mean_binary_brier_at_k",
        report.mean_binary_brier_at_k,
        &brier,
    )?;
    verify_optional_mean(
        "mean_no_skill_binary_brier",
        report.mean_no_skill_binary_brier,
        &no_skill,
    )?;
    verify_optional_mean(
        "mean_binary_brier_skill_at_k",
        report.mean_binary_brier_skill_at_k,
        &brier_skill,
    )?;
    verify_mean(
        "mean_null_hits_at_k",
        report.mean_null_hits_at_k,
        &null_hits,
    )?;
    Ok(json!({
        "fold_count": report.folds.len(),
        "usable_fold_count": report.usable_fold_count,
        "unusable_fold_count": unusable_count,
        "all_count_derived_binary_and_coverage_metrics_recomputed": true,
        "ranking_and_null_stability_reduced_from_persisted_fold_values": true,
        "all_stability_and_mean_fields_recomputed": true,
    }))
}

fn verify_discovery_rows(
    vault: &AsterVault,
    snapshot: u64,
    payload: &Path,
    execution: &Value,
    wave_one: &Value,
    wave_two: &Value,
) -> AnyResult<Value> {
    let cache = PathBuf::from(
        execution["cache"]
            .as_str()
            .ok_or("ISSUE_1150_DISCOVERY_EXECUTION_CACHE_MISSING")?,
    );
    let project = execution["project"]
        .as_str()
        .ok_or("ISSUE_1150_DISCOVERY_EXECUTION_PROJECT_MISSING")?;
    let prepared = discovery_kind_retention_state(vault, snapshot, "prepared", project)?;
    let final_state = discovery_kind_retention_state(vault, snapshot, "final", project)?;
    let third_prepared = &wave_one["third"]["prepared"];
    let second_prepared = &execution["discovery"]["prepared"][1];
    let third_published = &wave_two["publication"]["response"];
    let second_published = &wave_one["publications"][1]["response"];
    let first_prepared = &execution["discovery"]["prepared"][0];
    let first_published = &wave_one["publications"][0]["response"];
    require(
        prepared["pointer"]["retained_generation_count"] == 2
            && final_state["pointer"]["retained_generation_count"] == 2
            && prepared["current"]["target"]["artifact_sha256"]
                == third_prepared["prepared_artifact_sha256"]
            && prepared["previous"]["target"]["artifact_sha256"]
                == second_prepared["prepared_artifact_sha256"]
            && final_state["current"]["target"]["artifact_sha256"]
                == third_published["artifact_sha256"]
            && final_state["previous"]["target"]["artifact_sha256"]
                == second_published["artifact_sha256"]
            && final_state["current"]["manifest"]["prepared_artifact_sha256"]
                == third_prepared["prepared_artifact_sha256"]
            && final_state["previous"]["manifest"]["prepared_artifact_sha256"]
                == second_prepared["prepared_artifact_sha256"]
            && prepared["current"]["manifest"]["previous_artifact_sha256"]
                == second_prepared["prepared_artifact_sha256"]
            && prepared["current"]["manifest"]["retired_artifact_sha256"]
                == first_prepared["prepared_artifact_sha256"]
            && prepared["current"]["ledger"]["payload"]["cross_kind_retired_artifact_sha256"]
                == first_published["artifact_sha256"]
            && final_state["current"]["manifest"]["previous_artifact_sha256"]
                == second_published["artifact_sha256"]
            && final_state["current"]["manifest"]["retired_artifact_sha256"].is_null(),
        "ISSUE_1150_DISCOVERY_CURRENT_PREVIOUS_IDENTITY_MISMATCH",
        json!({"prepared":prepared,"final":final_state}),
    )?;
    let validation_value = prepared["current"]["validation"].clone();
    let validation: CrossValidationReport = serde_json::from_value(validation_value)?;
    let validation_audit = verify_validation(&validation, 5)?;
    let request_generations = [
        (
            &execution["discovery"]["requests"][0],
            &execution["discovery"]["prepared"][0],
            &execution["discovery"]["request_exports"][0],
        ),
        (
            &execution["discovery"]["requests"][1],
            &execution["discovery"]["prepared"][1],
            &execution["discovery"]["request_exports"][1],
        ),
        (
            &wave_one["third"]["request"],
            &wave_one["third"]["prepared"],
            &wave_one["third"]["request_export"],
        ),
    ];
    let mut request_exports = Vec::with_capacity(request_generations.len());
    for &(request, prepared_generation, receipt) in &request_generations {
        let prepared_hash = prepared_generation["prepared_artifact_sha256"]
            .as_str()
            .ok_or("ISSUE_1150_REQUEST_EXPORT_PREPARED_HASH_MISSING")?;
        let path = payload.join(format!(
            "association-external-requests-{prepared_hash}.json"
        ));
        let bytes = fs::read(&path)?;
        let bundle: Value = serde_json::from_slice(&bytes)?;
        require(
            receipt["path"] == Value::String(path.to_string_lossy().into_owned())
                && receipt["bytes"].as_u64() == u64::try_from(bytes.len()).ok()
                && receipt["sha256"] == Value::String(sha256(&bytes))
                && bundle["schema"] == DISCOVERY_FSV_REQUEST_SCHEMA
                && bundle["prepared_artifact_sha256"]
                    == prepared_generation["prepared_artifact_sha256"]
                && bundle["source_generation_sha256"]
                    == prepared_generation["source_generation_sha256"]
                && bundle["evaluation_roster"] == prepared_generation["evaluation_roster"]
                && bundle["budgets"] == request["budgets"]
                && bundle["capture_contract"]["capture_schema"] == DISCOVERY_CAPTURE_SCHEMA_V1
                && bundle["capture_contract"]["receipt_schema"] == DISCOVERY_RECEIPT_SCHEMA_V2
                && bundle["capture_contract"]["response_schema"] == DISCOVERY_RESPONSE_SCHEMA_V1,
            "ISSUE_1150_EXTERNAL_REQUEST_EXPORT_READBACK_MISMATCH",
            json!({"receipt":receipt,"bundle":bundle}),
        )?;
        request_exports.push(json!({
            "path":path,
            "bytes":bytes.len(),
            "sha256":sha256(&bytes),
            "prepared_artifact_sha256":prepared_hash,
            "binding_count":bundle["evaluation_roster"]["binding_count"],
            "exact_physical_readback":true,
        }));
    }
    let mut capture_readbacks = Vec::with_capacity(request_generations.len());
    for (ordinal, &(request, prepared_generation, _)) in request_generations.iter().enumerate() {
        let (receipts, capture) =
            load_genuine_discovery_capture(payload, request, prepared_generation)?;
        let expected_capture = if ordinal < 2 {
            &wave_one["captures"][ordinal]
        } else {
            &wave_two["capture"]
        };
        let persisted_receipts = match ordinal {
            0 => {
                &wave_one["retention_before_third_prepare"]["final"]["previous"]["evaluator_receipts"]
            }
            1 => {
                &wave_one["retention_before_third_prepare"]["final"]["current"]["evaluator_receipts"]
            }
            _ => &final_state["current"]["evaluator_receipts"],
        };
        require(
            &capture == expected_capture && &receipts == persisted_receipts,
            "ISSUE_1150_EXTERNAL_CAPTURE_SEPARATE_READBACK_MISMATCH",
            json!({"ordinal":ordinal,"observed":capture,"expected":expected_capture,"receipts":receipts,"persisted_receipts":persisted_receipts}),
        )?;
        capture_readbacks.push(capture);
    }
    let (third_receipts, third_capture) =
        load_genuine_discovery_capture(payload, &wave_one["third"]["request"], third_prepared)?;
    require(
        wave_two["read"]["schema"] == "astrolabe.discover_associations.v4"
            && wave_two["read"]["status"] == "read"
            && wave_two["read"]["artifact_sha256"] == third_published["artifact_sha256"]
            && wave_two["read"]["physical_readback_sha256"] == third_published["artifact_sha256"]
            && wave_two["read"]["value"]["artifact"]["schema"] == DISCOVERY_FINAL_SCHEMA_V4
            && wave_two["read"]["value"]["artifact"]["evaluator_receipts"] == third_receipts
            && wave_two["read"]["ledger_ref"] == final_state["current"]["manifest"]["ledger_ref"],
        "ISSUE_1150_DISCOVERY_FINAL_VALUE_MISMATCH",
        &wave_two["read"],
    )?;
    let retired = wave_one["retired"]
        .as_array()
        .ok_or("ISSUE_1150_DISCOVERY_RETIRED_ROSTER_MISSING")?;
    let retention = discovery_retention_state(&cache, project, retired)?;
    require(
        retention["prepared"]["pointer"] == prepared["pointer"]
            && retention["final"]["pointer"] == final_state["pointer"]
            && retention["retired_exact_tombstones_verified"] == Value::Bool(true)
            && retention["retired"]
                .as_array()
                .is_some_and(|rows| rows.len() == 2),
        "ISSUE_1150_DISCOVERY_RETENTION_READBACK_MISMATCH",
        &retention,
    )?;
    let mut retired_ledgers = Vec::new();
    for kind in ["prepared", "final"] {
        let retired_generation = &wave_one["retention_before_third_prepare"][kind]["previous"];
        let ledger =
            verify_discovery_ledger_manifest(vault, snapshot, &retired_generation["manifest"])?;
        require(
            ledger == retired_generation["ledger"],
            "ISSUE_1150_RETIRED_LEDGER_SEPARATE_READBACK_MISMATCH",
            json!({"kind":kind,"observed":ledger,"recorded":retired_generation["ledger"]}),
        )?;
        retired_ledgers.push(json!({"kind":kind,"ledger":ledger}));
    }
    Ok(json!({
        "prepared":prepared,
        "final":final_state,
        "retention":retention,
        "validation":validation_audit,
        "external_request_exports":request_exports,
        "external_capture_readbacks":capture_readbacks,
        "third_external_capture":third_capture,
        "retired_ledgers":retired_ledgers,
        "final_read":wave_two["read"],
        "prepublication_edges":execution["edges"],
        "postpublication_edges":wave_two["edges"],
        "all_six_generation_ledgers_physically_point_read":true,
        "current_and_previous_prepared_and_final_physically_read":true,
        "retired_prepared_and_final_rows_are_exact_tombstones":true,
        "real_external_receipts_reparsed_from_capture_file":true,
    }))
}

fn verify_search_manifest(cache: &Path, project: &str, execution: &Value) -> AnyResult<Value> {
    let path = cache.join(format!("{project}.astrolabe-search-index.v2.json"));
    let bytes = fs::read(&path)?;
    let manifest = SlotIndexManifest::from_bytes(&bytes)?;
    require(
        manifest.to_canonical_bytes()? == bytes,
        "ISSUE_1116_1119_SEARCH_MANIFEST_NONCANONICAL",
        path.display(),
    )?;
    let content_hash = hex_lower(&manifest.content_hash()?);
    let expected_content_hash = execution["search"]["first"]["manifest"]["content_hash"]
        .as_str()
        .ok_or("served search manifest content hash missing")?;
    let expected_document_count = execution["search"]["first"]["manifest"]["document_count"]
        .as_u64()
        .ok_or("served search manifest document count missing")?
        as usize;
    require(
        content_hash == expected_content_hash
            && manifest.documents.len() == expected_document_count,
        "ISSUE_1116_1119_SEARCH_MANIFEST_IDENTITY_MISMATCH",
        &content_hash,
    )?;
    let vector_slots = manifest
        .slots
        .iter()
        .filter(|spec| {
            matches!(
                spec.kind,
                astrolabe_weave::search_index::SlotIndexKind::Vector { .. }
            )
        })
        .count();
    let vector_rows = manifest
        .documents
        .iter()
        .flat_map(|document| document.slots.values())
        .filter(|content| {
            matches!(
                content,
                astrolabe_weave::search_index::StoredContent::VectorBits(bits) if !bits.is_empty()
            )
        })
        .count();
    require(
        vector_slots > 0 && vector_rows > 0,
        "ISSUE_1116_1119_SEARCH_VECTOR_STATE_EMPTY",
        format!("slots={vector_slots} rows={vector_rows}"),
    )?;
    Ok(json!({
        "path": path,
        "bytes": bytes.len(),
        "sha256": sha256(&bytes),
        "content_hash": content_hash,
        "base_seq": manifest.base_seq,
        "document_count": manifest.documents.len(),
        "vector_slot_count": vector_slots,
        "vector_row_count": vector_rows,
        "canonical": true,
    }))
}

fn is_lower_hex_64(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn semantic_witness_u64(value: &Value, field: &str) -> AnyResult<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("semantic coverage field {field:?} is not u64").into())
}

fn exact_json_object_fields(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|field| object.contains_key(*field))
}

fn append_semantic_manifest_frame(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn semantic_atom_manifest_from_counts(
    panel_version: u32,
    family_constellations: &BTreeMap<astrolabe_panel::semantic::SemanticFamily, u64>,
    rule_present: &BTreeMap<u16, u64>,
) -> String {
    use astrolabe_panel::semantic::{SEMANTIC_RULES, SemanticFamily};

    let mut canonical = Vec::with_capacity(SEMANTIC_RULES.len() * 64);
    append_semantic_manifest_frame(
        &mut canonical,
        b"astrolabe.cbm.semantic-source-atom-manifest.v1",
    );
    append_semantic_manifest_frame(&mut canonical, &panel_version.to_be_bytes());
    for family in SemanticFamily::ALL {
        append_semantic_manifest_frame(&mut canonical, family.as_str().as_bytes());
        append_semantic_manifest_frame(
            &mut canonical,
            &family_constellations
                .get(&family)
                .copied()
                .unwrap_or(0)
                .to_be_bytes(),
        );
    }
    for rule in SEMANTIC_RULES {
        append_semantic_manifest_frame(&mut canonical, &rule.value_slot.to_be_bytes());
        append_semantic_manifest_frame(&mut canonical, rule.family.as_str().as_bytes());
        append_semantic_manifest_frame(&mut canonical, rule.path.as_bytes());
        append_semantic_manifest_frame(&mut canonical, rule.source_type.as_str().as_bytes());
        append_semantic_manifest_frame(&mut canonical, rule.kind.as_str().as_bytes());
        append_semantic_manifest_frame(
            &mut canonical,
            &rule_present
                .get(&rule.value_slot)
                .copied()
                .unwrap_or(0)
                .to_be_bytes(),
        );
    }
    sha256(&canonical)
}

#[derive(Debug)]
struct SqliteProjectSemanticState {
    name: String,
    indexed_at: String,
    root_path: String,
    index_mode: String,
    semantic_state: String,
    semantic_vector_dimension: i64,
    semantic_eligible_node_count: Option<i64>,
    node_vector_count: i64,
    token_vector_count: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemanticProjectExpectation {
    ModerateAvailable,
    ModerateUnavailableCorpus,
    FastUnavailableMode,
}

fn read_semantic_project_state(
    connection: &Connection,
    project: &str,
) -> AnyResult<SqliteProjectSemanticState> {
    Ok(connection.query_row(
        "SELECT name, indexed_at, root_path, index_mode, semantic_state, \
                semantic_vector_dimension, semantic_eligible_node_count, node_vector_count, \
                token_vector_count FROM projects WHERE name = ?1",
        [project],
        |row| {
            Ok(SqliteProjectSemanticState {
                name: row.get(0)?,
                indexed_at: row.get(1)?,
                root_path: row.get(2)?,
                index_mode: row.get(3)?,
                semantic_state: row.get(4)?,
                semantic_vector_dimension: row.get(5)?,
                semantic_eligible_node_count: row.get(6)?,
                node_vector_count: row.get(7)?,
                token_vector_count: row.get(8)?,
            })
        },
    )?)
}

fn physical_semantic_vector_counts(
    connection: &Connection,
    project: &str,
) -> AnyResult<(i64, i64)> {
    let node_vectors = connection.query_row(
        "SELECT COUNT(*) FROM node_vectors WHERE project = ?1",
        [project],
        |row| row.get(0),
    )?;
    let token_vectors = connection.query_row(
        "SELECT COUNT(*) FROM token_vectors WHERE project = ?1",
        [project],
        |row| row.get(0),
    )?;
    Ok((node_vectors, token_vectors))
}

fn read_moderate_semantic_project_state(
    connection: &Connection,
    project: &str,
) -> AnyResult<SqliteProjectSemanticState> {
    let state = read_semantic_project_state(connection, project)?;
    let (physical_node_vectors, physical_token_vectors) =
        physical_semantic_vector_counts(connection, project)?;
    require(
        state.name == project
            && !state.indexed_at.is_empty()
            && !state.root_path.is_empty()
            && state.index_mode == "moderate"
            && state.semantic_state == "available"
            && state.semantic_vector_dimension == 768
            && state.semantic_eligible_node_count.is_some_and(|eligible| {
                eligible >= 2
                    && eligible == state.node_vector_count
                    && eligible == physical_node_vectors
            })
            && state.node_vector_count > 0
            && state.token_vector_count > 0
            && state.token_vector_count == physical_token_vectors,
        "ISSUE_1116_1119_MODERATE_SEMANTIC_PROJECT_STATE_INVALID",
        json!({
            "project_row": format!("{state:?}"),
            "physical_node_vectors": physical_node_vectors,
            "physical_token_vectors": physical_token_vectors,
            "expected": {
                "index_mode": "moderate",
                "semantic_state": "available",
                "semantic_vector_dimension": 768,
                "semantic_eligible_node_count_minimum": 2,
                "node_vector_count": "semantic_eligible_node_count and physical node_vectors",
                "token_vector_count": "positive and equal to physical token_vectors",
            },
        }),
    )?;
    Ok(state)
}

fn read_fast_unavailable_semantic_project_state(
    connection: &Connection,
    project: &str,
) -> AnyResult<SqliteProjectSemanticState> {
    let state = read_semantic_project_state(connection, project)?;
    let (physical_node_vectors, physical_token_vectors) =
        physical_semantic_vector_counts(connection, project)?;
    require(
        state.name == project
            && !state.indexed_at.is_empty()
            && !state.root_path.is_empty()
            && state.index_mode == "fast"
            && state.semantic_state == "unavailable_mode"
            && state.semantic_vector_dimension == 768
            && state.semantic_eligible_node_count.is_none()
            && state.node_vector_count == 0
            && state.token_vector_count == 0
            && physical_node_vectors == 0
            && physical_token_vectors == 0,
        "ISSUE_980_FAST_UNAVAILABLE_PROJECT_STATE_INVALID",
        json!({
            "project_row": format!("{state:?}"),
            "physical_node_vectors": physical_node_vectors,
            "physical_token_vectors": physical_token_vectors,
            "expected": {
                "index_mode": "fast",
                "semantic_state": "unavailable_mode",
                "semantic_vector_dimension": 768,
                "semantic_eligible_node_count": null,
                "node_vector_count": 0,
                "token_vector_count": 0,
            },
        }),
    )?;
    Ok(state)
}

fn read_moderate_unavailable_corpus_project_state(
    connection: &Connection,
    project: &str,
) -> AnyResult<SqliteProjectSemanticState> {
    let state = read_semantic_project_state(connection, project)?;
    let (physical_node_vectors, physical_token_vectors) =
        physical_semantic_vector_counts(connection, project)?;
    require(
        state.name == project
            && !state.indexed_at.is_empty()
            && !state.root_path.is_empty()
            && state.index_mode == "moderate"
            && state.semantic_state == "unavailable_corpus"
            && state.semantic_vector_dimension == 768
            && state.semantic_eligible_node_count == Some(1)
            && state.node_vector_count == 0
            && state.token_vector_count == 0
            && physical_node_vectors == 0
            && physical_token_vectors == 0,
        "ISSUE_980_UNAVAILABLE_CORPUS_PROJECT_STATE_INVALID",
        json!({
            "project_row": format!("{state:?}"),
            "physical_node_vectors": physical_node_vectors,
            "physical_token_vectors": physical_token_vectors,
            "expected": {
                "index_mode": "moderate",
                "semantic_state": "unavailable_corpus",
                "semantic_vector_dimension": 768,
                "semantic_eligible_node_count": 1,
                "node_vector_count": 0,
                "token_vector_count": 0,
            },
        }),
    )?;
    Ok(state)
}

fn semantic_project_state_json(state: &SqliteProjectSemanticState) -> Value {
    json!({
        "name": state.name,
        "indexed_at": state.indexed_at,
        "root_path": state.root_path,
        "index_mode": state.index_mode,
        "semantic_state": state.semantic_state,
        "semantic_vector_dimension": state.semantic_vector_dimension,
        "semantic_eligible_node_count": state.semantic_eligible_node_count,
        "node_vector_count": state.node_vector_count,
        "token_vector_count": state.token_vector_count,
    })
}

fn sqlite_semantic_source_state(
    cache: &Path,
    project: &str,
    expectation: SemanticProjectExpectation,
) -> AnyResult<Value> {
    use astrolabe_panel::semantic::SemanticFamily;

    let path = cache.join(format!("{project}.db"));
    let connection = readonly_sqlite(&path)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let foreign_key_errors: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    let project_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM projects WHERE name = ?1",
        [project],
        |row| row.get(0),
    )?;
    require(
        integrity == "ok" && foreign_key_errors == 0 && project_rows == 1,
        "ISSUE_1116_1119_SEMANTIC_SQLITE_INVALID",
        json!({
            "path": path,
            "integrity": integrity,
            "foreign_key_errors": foreign_key_errors,
            "project_rows": project_rows,
        }),
    )?;
    let state = match expectation {
        SemanticProjectExpectation::ModerateAvailable => {
            read_moderate_semantic_project_state(&connection, project)?
        }
        SemanticProjectExpectation::ModerateUnavailableCorpus => {
            read_moderate_unavailable_corpus_project_state(&connection, project)?
        }
        SemanticProjectExpectation::FastUnavailableMode => {
            read_fast_unavailable_semantic_project_state(&connection, project)?
        }
    };

    let count = |sql: &str| -> AnyResult<u64> {
        let count: i64 = connection.query_row(sql, [project], |row| row.get(0))?;
        require(
            count >= 0,
            "ISSUE_1116_1119_SEMANTIC_SQLITE_COUNT_INVALID",
            format!("sql={sql:?}; count={count}"),
        )?;
        Ok(u64::try_from(count)?)
    };
    let family_counts = BTreeMap::from([
        (SemanticFamily::Project, u64::try_from(project_rows)?),
        (
            SemanticFamily::FileHash,
            count("SELECT COUNT(*) FROM file_hashes WHERE project = ?1")?,
        ),
        (
            SemanticFamily::Node,
            count("SELECT COUNT(*) FROM nodes WHERE project = ?1")?,
        ),
        (
            SemanticFamily::Edge,
            count("SELECT COUNT(*) FROM edges WHERE project = ?1")?,
        ),
        (
            SemanticFamily::ProjectSummary,
            count("SELECT COUNT(*) FROM project_summaries WHERE project = ?1")?,
        ),
        (
            SemanticFamily::NodeVector,
            count("SELECT COUNT(*) FROM node_vectors WHERE project = ?1")?,
        ),
        (
            SemanticFamily::TokenVector,
            count("SELECT COUNT(*) FROM token_vectors WHERE project = ?1")?,
        ),
    ]);
    Ok(json!({
        "path": path,
        "bytes": fs::metadata(&path)?.len(),
        "sha256": astrolabe_ingest::fingerprint_sqlite_hex(&path)?,
        "source_schema_sha256":
            astrolabe_ingest::semantic_sqlite_source_schema_sha256_hex(&path)?,
        "integrity": integrity,
        "foreign_key_errors": foreign_key_errors,
        "family_constellations": family_counts
            .iter()
            .map(|(family, count)| (family.as_str().to_string(), *count))
            .collect::<BTreeMap<_, _>>(),
        "project": semantic_project_state_json(&state),
    }))
}

fn verify_project_semantic_slot_values(
    cache: &Path,
    project: &str,
    state: &SqliteProjectSemanticState,
) -> AnyResult<Value> {
    use astrolabe_panel::semantic::{
        SemanticValue, encode_structured_value, semantic_rule_by_slot,
    };

    let (_, vault_dir, _, _) = vault_identity(cache, project)?;
    let optional_slot = SlotId::new(208);
    let optional_dir = vault_dir.join("cf").join("slot_208");
    let optional_dir_state = match fs::symlink_metadata(&optional_dir) {
        Ok(metadata) => {
            require(
                metadata.is_dir() && metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE == 0,
                "ISSUE_980_SEMANTIC_OPTIONAL_SLOT_DIRECTORY_INVALID",
                optional_dir.display(),
            )?;
            json!({"exists": true, "reparse": false})
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            json!({"exists": false, "reparse": false})
        }
        Err(error) => return Err(error.into()),
    };
    require(
        optional_dir_state["exists"] == Value::Bool(state.semantic_eligible_node_count.is_some()),
        "ISSUE_980_SEMANTIC_OPTIONAL_SLOT_DIRECTORY_STATE_MISMATCH",
        json!({
            "sqlite_semantic_eligible_node_count": state.semantic_eligible_node_count,
            "slot_directory": optional_dir_state,
        }),
    )?;

    let mut selected_cfs = vec![ColumnFamily::Base, ColumnFamily::Graph];
    for slot in [205_u16, 206, 207, 209, 210] {
        selected_cfs.push(ColumnFamily::slot(SlotId::new(slot)));
    }
    if state.semantic_eligible_node_count.is_some() {
        selected_cfs.push(ColumnFamily::slot(optional_slot));
    }
    let (point_vault, _) = open_vault_selected(cache, project, selected_cfs)?;
    let snapshot = point_vault.latest_seq();
    let mut project_rows = Vec::new();
    for (key, bytes) in point_vault.scan_cf_at(snapshot, ColumnFamily::Graph)? {
        if !key.starts_with(b"astrolabe:semantic-constellation:v1:") {
            continue;
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        if value["schema"] == "astrolabe.semantic-constellation.v1"
            && value["project"] == project
            && value["family"] == "project"
            && value["source_key"] == project
        {
            project_rows.push(json!({
                "key_hex": hex_lower(&key),
                "bytes": bytes.len(),
                "sha256": sha256(&bytes),
                "value": value,
            }));
        }
    }
    require(
        project_rows.len() == 1,
        "ISSUE_980_SEMANTIC_PROJECT_GRAPH_ROSTER_INVALID",
        json!({"project": project, "rows": project_rows}),
    )?;
    let graph_row = &project_rows[0];
    let cx_id: CxId = serde_json::from_value(graph_row["value"]["cx_id"].clone())?;
    let graph_slots = graph_row["value"]["slot_ids"]
        .as_array()
        .ok_or("ISSUE_980_SEMANTIC_PROJECT_GRAPH_SLOTS_MISSING")?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|slot| u16::try_from(slot).ok())
                .ok_or_else(|| "ISSUE_980_SEMANTIC_PROJECT_GRAPH_SLOT_INVALID".into())
        })
        .collect::<AnyResult<BTreeSet<_>>>()?;
    let values = BTreeMap::from([
        (205_u16, SemanticValue::Text(state.index_mode.clone())),
        (206, SemanticValue::Text(state.semantic_state.clone())),
        (207, SemanticValue::Integer(state.semantic_vector_dimension)),
        (209, SemanticValue::Integer(state.node_vector_count)),
        (210, SemanticValue::Integer(state.token_vector_count)),
    ]);
    let mut point_reads = BTreeMap::<String, Value>::new();
    for (slot, value) in values {
        let slot_id = SlotId::new(slot);
        require(
            graph_slots.contains(&slot),
            "ISSUE_980_SEMANTIC_PROJECT_SLOT_ABSENT_FROM_GRAPH",
            slot,
        )?;
        let rule =
            semantic_rule_by_slot(slot_id).ok_or("ISSUE_980_SEMANTIC_PROJECT_RULE_MISSING")?;
        let sqlite_value = match &value {
            SemanticValue::Text(value) => Value::String(value.clone()),
            SemanticValue::Integer(value) => json!(value),
            _ => {
                return Err(format!(
                    "ISSUE_980_SEMANTIC_PROJECT_VALUE_KIND_INVALID: slot=S{slot}; value={value:?}"
                )
                .into());
            }
        };
        let independently_encoded = encode_structured_value(rule, &value)?;
        let row_bytes = point_vault
            .read_cf_at(snapshot, ColumnFamily::slot(slot_id), &slot_key(cx_id))?
            .ok_or("ISSUE_980_SEMANTIC_PROJECT_SLOT_ROW_MISSING")?;
        let decoded = decode_strict_raw_slot_value(slot_id, cx_id, &row_bytes)?;
        require(
            decoded == independently_encoded,
            "ISSUE_980_SEMANTIC_PROJECT_SLOT_VECTOR_MISMATCH",
            json!({
                "slot": slot,
                "sqlite_value": &sqlite_value,
                "expected": staged_abort_vector_state(&independently_encoded),
                "actual": staged_abort_vector_state(&decoded),
            }),
        )?;
        point_reads.insert(
            format!("S{slot}"),
            json!({
                "source_path": rule.path,
                "source_type": rule.source_type.as_str(),
                "sqlite_value": &sqlite_value,
                "row_bytes": row_bytes.len(),
                "row_sha256": sha256(&row_bytes),
                "decoded_bits": staged_abort_vector_state(&decoded),
                "independent_encoder_bits": staged_abort_vector_state(&independently_encoded),
                "exact_bits_equal": true,
            }),
        );
    }
    let optional_readback = if let Some(value) = state.semantic_eligible_node_count {
        require(
            graph_slots.contains(&208),
            "ISSUE_980_SEMANTIC_OPTIONAL_SLOT_GRAPH_ROW_MISSING",
            &graph_slots,
        )?;
        let rule = semantic_rule_by_slot(optional_slot)
            .ok_or("ISSUE_980_SEMANTIC_OPTIONAL_RULE_MISSING")?;
        let source_value = SemanticValue::Integer(value);
        let independently_encoded = encode_structured_value(rule, &source_value)?;
        let row_bytes = point_vault
            .read_cf_at(
                snapshot,
                ColumnFamily::slot(optional_slot),
                &slot_key(cx_id),
            )?
            .ok_or("ISSUE_980_SEMANTIC_OPTIONAL_SLOT_ROW_MISSING")?;
        let decoded = decode_strict_raw_slot_value(optional_slot, cx_id, &row_bytes)?;
        require(
            decoded == independently_encoded,
            "ISSUE_980_SEMANTIC_OPTIONAL_SLOT_VECTOR_MISMATCH",
            staged_abort_vector_state(&decoded),
        )?;
        json!({
            "status": "present",
            "source_path": rule.path,
            "sqlite_value": value,
            "row_bytes": row_bytes.len(),
            "row_sha256": sha256(&row_bytes),
            "decoded_bits": staged_abort_vector_state(&decoded),
            "independent_encoder_bits": staged_abort_vector_state(&independently_encoded),
            "exact_bits_equal": true,
            "cf_selected": true,
        })
    } else {
        require(
            !graph_slots.contains(&208) && optional_dir_state["exists"] == Value::Bool(false),
            "ISSUE_980_SEMANTIC_OPTIONAL_SLOT_ABSENCE_INVALID",
            json!({"graph_slots": graph_slots, "directory": optional_dir_state}),
        )?;
        json!({
            "status": "absent",
            "sqlite_value": null,
            "graph_roster_slot_absent": true,
            "physical_cf_directory_absent": true,
            "physical_row_absent": true,
            "cf_selected": false,
        })
    };
    Ok(json!({
        "schema": "astrolabe.issue-980.project-semantic-point-read.v1",
        "project_cx_id": cx_id,
        "project_graph_roster": graph_row,
        "project_graph_slot_ids": graph_slots,
        "sqlite_project": semantic_project_state_json(state),
        "required_point_reads": point_reads,
        "S208": optional_readback,
        "snapshot": snapshot,
        "derived_from_physical_graph_roster": true,
        "all_persisted_vectors_equal_independent_panel_encoder_bits": true,
    }))
}

fn verify_semantic_coverage(
    vault: &AsterVault,
    snapshot: u64,
    cache: &Path,
    project: &str,
    expectation: SemanticProjectExpectation,
) -> AnyResult<Value> {
    use astrolabe_panel::semantic::{SEMANTIC_RULES, SemanticFamily, SemanticKind};

    let mut key = SEMANTIC_COVERAGE_PREFIX.to_vec();
    key.extend_from_slice(&Sha256::digest(project.as_bytes()));
    let row = read_cf_state(vault, snapshot, ColumnFamily::Graph, &key)?;
    let witness = row["json"].clone();
    let panel_version = witness["panel_version"]
        .as_u64()
        .and_then(|version| u32::try_from(version).ok())
        .ok_or("semantic coverage panel_version is missing or out of range")?;
    let sqlite_source = sqlite_semantic_source_state(cache, project, expectation)?;
    let semantic_connection = readonly_sqlite(&cache.join(format!("{project}.db")))?;
    let physical_project = read_semantic_project_state(&semantic_connection, project)?;
    drop(semantic_connection);
    let project_slot_point_reads =
        verify_project_semantic_slot_values(cache, project, &physical_project)?;
    require(
        exact_json_object_fields(
            &witness,
            &[
                "schema",
                "project",
                "panel_version",
                "registry_sha256",
                "source_schema_sha256",
                "sqlite_fingerprint_sha256",
                "slot_manifest_sha256",
                "source_atom_manifest_schema",
                "source_atom_manifest_sha256",
                "emitted_atom_manifest_sha256",
                "constellations",
                "present",
                "encoded",
                "embedded",
                "imported_vector",
                "uncovered",
                "families",
                "rules",
            ],
        ) && witness["schema"] == Value::String("astrolabe.semantic-coverage.v2".to_string())
            && witness["project"] == Value::String(project.to_string())
            && panel_version == astrolabe_panel::CURRENT_SEMANTIC_PANEL_VERSION
            && witness["registry_sha256"]
                == Value::String(hex_lower(
                    &astrolabe_panel::semantic::semantic_registry_sha256(),
                ))
            && witness["slot_manifest_sha256"]
                == Value::String(hex_lower(&astrolabe_panel::panel_slot_manifest_sha256(
                    panel_version,
                )?))
            && is_lower_hex_64(&witness["source_schema_sha256"])
            && witness["source_schema_sha256"] == sqlite_source["source_schema_sha256"]
            && is_lower_hex_64(&witness["sqlite_fingerprint_sha256"])
            && witness["sqlite_fingerprint_sha256"] == sqlite_source["sha256"]
            && witness["source_atom_manifest_schema"]
                == "astrolabe.cbm.semantic-source-atom-manifest.v1"
            && is_lower_hex_64(&witness["source_atom_manifest_sha256"])
            && witness["source_atom_manifest_sha256"] == witness["emitted_atom_manifest_sha256"]
            && witness["uncovered"] == 0,
        "ISSUE_1116_1119_SEMANTIC_COVERAGE_INVALID",
        &witness,
    )?;

    let families = witness["families"]
        .as_array()
        .ok_or("semantic coverage families is not an array")?;
    let rules = witness["rules"]
        .as_array()
        .ok_or("semantic coverage rules is not an array")?;
    let mut family_rows = BTreeMap::new();
    for family_row in families {
        let family_name = family_row["family"]
            .as_str()
            .ok_or("semantic coverage family name is missing")?;
        let family = SemanticFamily::from_manifest_str(family_name)
            .ok_or_else(|| format!("unknown semantic coverage family {family_name:?}"))?;
        require(
            exact_json_object_fields(
                family_row,
                &[
                    "family",
                    "constellations",
                    "present",
                    "encoded",
                    "embedded",
                    "imported_vector",
                ],
            ) && family_rows.insert(family, family_row).is_none(),
            "ISSUE_1116_1119_SEMANTIC_FAMILY_ROSTER_INVALID",
            family_row,
        )?;
    }
    require(
        family_rows.len() == SemanticFamily::ALL.len()
            && SemanticFamily::ALL
                .iter()
                .all(|family| family_rows.contains_key(family)),
        "ISSUE_1116_1119_SEMANTIC_FAMILY_ROSTER_INCOMPLETE",
        families.len(),
    )?;

    let mut rule_present = BTreeMap::new();
    for rule_row in rules {
        let slot = rule_row["slot_id"]
            .as_u64()
            .and_then(|slot| u16::try_from(slot).ok())
            .ok_or("semantic coverage rule slot_id is missing or out of range")?;
        let canonical = astrolabe_panel::semantic::semantic_rule_by_slot(SlotId::new(slot))
            .ok_or_else(|| format!("semantic coverage contains unknown rule S{slot}"))?;
        require(
            exact_json_object_fields(
                rule_row,
                &[
                    "family",
                    "path",
                    "source_type",
                    "kind",
                    "slot_id",
                    "present",
                ],
            ) && rule_row["family"] == canonical.family.as_str()
                && rule_row["path"] == canonical.path
                && rule_row["source_type"] == canonical.source_type.as_str()
                && rule_row["kind"] == canonical.kind.as_str()
                && rule_present
                    .insert(slot, semantic_witness_u64(rule_row, "present")?)
                    .is_none(),
            "ISSUE_1116_1119_SEMANTIC_RULE_ROSTER_INVALID",
            rule_row,
        )?;
    }
    require(
        rule_present.len() == SEMANTIC_RULES.len()
            && SEMANTIC_RULES
                .iter()
                .all(|rule| rule_present.contains_key(&rule.value_slot)),
        "ISSUE_1116_1119_SEMANTIC_RULE_ROSTER_INCOMPLETE",
        json!({"expected":SEMANTIC_RULES.len(),"observed":rule_present.len()}),
    )?;

    let sqlite_family_counts = sqlite_source["family_constellations"]
        .as_object()
        .ok_or("semantic SQLite family counts are missing")?;
    let mut family_constellations = BTreeMap::new();
    let mut derived_constellations = 0_u64;
    let mut derived_present = 0_u64;
    let mut derived_encoded = 0_u64;
    let mut derived_embedded = 0_u64;
    let mut derived_imported = 0_u64;
    for family in SemanticFamily::ALL {
        let family_row = family_rows
            .get(&family)
            .ok_or("semantic family disappeared after roster validation")?;
        let constellations = semantic_witness_u64(family_row, "constellations")?;
        require(
            sqlite_family_counts
                .get(family.as_str())
                .and_then(Value::as_u64)
                == Some(constellations),
            "ISSUE_1116_1119_SEMANTIC_SQLITE_FAMILY_MISMATCH",
            json!({
                "family": family.as_str(),
                "sqlite": sqlite_family_counts.get(family.as_str()),
                "witness": constellations,
            }),
        )?;
        family_constellations.insert(family, constellations);
        let mut present = 0_u64;
        let mut encoded = 0_u64;
        let mut embedded = 0_u64;
        let mut imported = 0_u64;
        for rule in SEMANTIC_RULES.iter().filter(|rule| rule.family == family) {
            let count = rule_present.get(&rule.value_slot).copied().unwrap_or(0);
            present = present
                .checked_add(count)
                .ok_or("semantic present overflow")?;
            let class = match rule.kind {
                SemanticKind::LatentCode | SemanticKind::LatentProse => &mut embedded,
                SemanticKind::ImportedVector => &mut imported,
                _ => &mut encoded,
            };
            *class = class
                .checked_add(count)
                .ok_or("semantic class count overflow")?;
        }
        require(
            semantic_witness_u64(family_row, "present")? == present
                && semantic_witness_u64(family_row, "encoded")? == encoded
                && semantic_witness_u64(family_row, "embedded")? == embedded
                && semantic_witness_u64(family_row, "imported_vector")? == imported,
            "ISSUE_1116_1119_SEMANTIC_FAMILY_TOTAL_MISMATCH",
            family_row,
        )?;
        derived_constellations = derived_constellations
            .checked_add(constellations)
            .ok_or("semantic constellation total overflow")?;
        derived_present = derived_present
            .checked_add(present)
            .ok_or("semantic present total overflow")?;
        derived_encoded = derived_encoded
            .checked_add(encoded)
            .ok_or("semantic encoded total overflow")?;
        derived_embedded = derived_embedded
            .checked_add(embedded)
            .ok_or("semantic embedded total overflow")?;
        derived_imported = derived_imported
            .checked_add(imported)
            .ok_or("semantic imported total overflow")?;
    }
    require(
        semantic_witness_u64(&witness, "constellations")? == derived_constellations
            && semantic_witness_u64(&witness, "present")? == derived_present
            && semantic_witness_u64(&witness, "encoded")? == derived_encoded
            && semantic_witness_u64(&witness, "embedded")? == derived_embedded
            && semantic_witness_u64(&witness, "imported_vector")? == derived_imported
            && derived_present
                == derived_encoded
                    .checked_add(derived_embedded)
                    .and_then(|value| value.checked_add(derived_imported))
                    .ok_or("semantic classified total overflow")?
            && witness["source_atom_manifest_sha256"]
                == Value::String(semantic_atom_manifest_from_counts(
                    panel_version,
                    &family_constellations,
                    &rule_present,
                )),
        "ISSUE_1116_1119_SEMANTIC_TOP_LEVEL_TOTAL_MISMATCH",
        &witness,
    )?;

    let project_rule_expectations = BTreeMap::from([
        (31_u16, 1_u64),
        (32, 1),
        (33, 1),
        (205, 1),
        (206, 1),
        (207, 1),
        (
            208,
            u64::from(sqlite_source["project"]["semantic_eligible_node_count"] != Value::Null),
        ),
        (209, 1),
        (210, 1),
    ]);
    require(
        SEMANTIC_RULES
            .iter()
            .filter(|rule| rule.family == SemanticFamily::Project)
            .all(|rule| {
                project_rule_expectations.get(&rule.value_slot)
                    == rule_present.get(&rule.value_slot)
            }),
        "ISSUE_1116_1119_SEMANTIC_PROJECT_RULE_MISMATCH",
        json!({
            "sqlite_project": sqlite_source["project"],
            "expected": project_rule_expectations,
            "observed": rule_present
                .iter()
                .filter(|(slot, _)| project_rule_expectations.contains_key(slot))
                .collect::<BTreeMap<_, _>>(),
        }),
    )?;

    let mut ledger_matches = Vec::new();
    for (ledger_key_bytes, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Ledger)? {
        let entry = calyx_ledger::decode(&bytes)?;
        if !entry.verify() {
            continue;
        }
        let Ok(payload) = serde_json::from_slice::<Value>(&entry.payload) else {
            continue;
        };
        if payload["semantic_coverage"] == witness {
            ledger_matches.push(json!({
                "key_hex": hex_lower(&ledger_key_bytes),
                "seq": entry.seq,
                "entry_hash": hex_lower(&entry.entry_hash),
                "payload_sha256": sha256(&entry.payload),
                "verified": true,
            }));
        }
    }
    require(
        !ledger_matches.is_empty(),
        "ISSUE_1116_1119_SEMANTIC_COVERAGE_LEDGER_MISSING",
        project,
    )?;

    let (_, vault_dir, vault_id, vault_salt) = vault_identity(cache, project)?;
    let deep =
        astrolabe_ingest::verify_deep_vault_path(&vault_dir, &vault_id.to_string(), &vault_salt)?;
    require(
        deep.sqlite_semantic_coverage_witness_rows == 1
            && deep.sqlite_semantic_coverage_present == derived_present
            && deep.sqlite_semantic_coverage_encoded == derived_encoded
            && deep.sqlite_semantic_coverage_embedded == derived_embedded
            && deep.sqlite_semantic_coverage_imported_vectors == derived_imported
            && deep.sqlite_semantic_coverage_uncovered == 0
            && deep.sqlite_semantic_constellation_rows == usize::try_from(derived_constellations)?
            && deep.sqlite_semantic_slot_rows >= usize::try_from(derived_present)?,
        "ISSUE_1116_1119_SEMANTIC_DEEP_PHYSICAL_MISMATCH",
        serde_json::to_value(&deep)?,
    )?;
    Ok(json!({
        "graph_row": row,
        "sqlite_source": sqlite_source,
        "ledger_matches": ledger_matches,
        "deep_physical_readback": deep,
        "project_slot_point_reads": project_slot_point_reads,
        "exact_registry_rule_count": SEMANTIC_RULES.len(),
        "source_and_emitted_atom_manifests_equal": true,
        "all_sqlite_families_physically_recounted": true,
        "all_base_slot_rows_and_ledger_physically_reopened": true,
    }))
}

fn verify_semantic_registry() -> AnyResult<Value> {
    use astrolabe_panel::semantic::{
        SEMANTIC_RULES, SEMANTIC_VALUE_SLOT_START, SemanticFamily, SemanticSourceType,
        semantic_rule, semantic_rule_by_slot, semantic_rule_count_for_family,
    };

    let mut keys = std::collections::BTreeSet::new();
    let mut slots = std::collections::BTreeSet::new();
    for rule in SEMANTIC_RULES {
        require(
            keys.insert((rule.family, rule.source_type, rule.path))
                && slots.insert(rule.value_slot)
                && semantic_rule(rule.family, rule.path, rule.source_type) == Some(rule)
                && semantic_rule_by_slot(SlotId::new(rule.value_slot)) == Some(rule),
            "ISSUE_1116_1119_SEMANTIC_RULE_ROUNDTRIP_FAILED",
            rule.path,
        )?;
        let wrong_type = if rule.source_type == SemanticSourceType::Boolean {
            SemanticSourceType::Text
        } else {
            SemanticSourceType::Boolean
        };
        require(
            semantic_rule(rule.family, rule.path, wrong_type).is_none()
                && semantic_rule(rule.family, "__astrolabe_absent_path__", rule.source_type)
                    .is_none(),
            "ISSUE_1116_1119_SEMANTIC_RULE_DRIFT_ACCEPTED",
            rule.path,
        )?;
    }
    let family_counts = SemanticFamily::ALL
        .into_iter()
        .map(|family| {
            let recounted = SEMANTIC_RULES
                .iter()
                .filter(|rule| rule.family == family)
                .count();
            require(
                semantic_rule_count_for_family(family) == recounted,
                "ISSUE_1116_1119_SEMANTIC_FAMILY_COUNT_MISMATCH",
                family.as_str(),
            )?;
            Ok((family.as_str().to_string(), recounted))
        })
        .collect::<AnyResult<BTreeMap<_, _>>>()?;
    require(
        semantic_rule_by_slot(SlotId::new(SEMANTIC_VALUE_SLOT_START - 1)).is_none()
            && semantic_rule_by_slot(SlotId::new(u16::MAX)).is_none(),
        "ISSUE_1116_1119_SEMANTIC_SLOT_RANGE_ACCEPTED",
        "below-range or u16::MAX slot resolved",
    )?;
    let canonical = serde_json::to_vec(SEMANTIC_RULES)?;
    Ok(json!({
        "rule_count": SEMANTIC_RULES.len(),
        "family_counts": family_counts,
        "unique_keys": keys.len(),
        "unique_slots": slots.len(),
        "registry_sha256": sha256(&canonical),
        "exact_lookup_and_slot_roundtrip": true,
        "wrong_path_type_and_slot_refusal": true,
    }))
}

fn readback(payload: PathBuf) -> AnyResult<()> {
    require(
        configured_cbm_host_binary_path()?.is_none() && !supervisor_should_wrap(),
        "ISSUE_1116_1119_READBACK_PROCESS_PRESTATE_INVALID",
        "a fresh readback process already had a binary binding or supervisor role",
    )?;
    let tree_sha = canonical_head()?;
    let driver_artifact = current_driver_artifact_state()?;
    let source_generation = current_source_generation_sha256()?;
    let execution_bytes = fs::read(payload.join("execution.json"))?;
    let execution: Value = serde_json::from_slice(&execution_bytes)?;
    let association_wave_one_bytes = fs::read(payload.join("association-publish-wave-1.json"))?;
    let association_wave_one: Value = serde_json::from_slice(&association_wave_one_bytes)?;
    let association_wave_two_bytes = fs::read(payload.join("association-publish-wave-2.json"))?;
    let association_wave_two: Value = serde_json::from_slice(&association_wave_two_bytes)?;
    let transport_bytes = fs::read(payload.join("transport-receipt.json"))?;
    let transport: Value = serde_json::from_slice(&transport_bytes)?;
    require(
        execution["schema"] == "astrolabe.issues-1116-1119.execute.v1"
            && transport["schema"] == "astrolabe.issues-1116-1119.transport.v1"
            && transport["state_unchanged"] == Value::Bool(true)
            && execution["tree_sha"] == Value::String(tree_sha.clone())
            && transport["tree_sha"] == Value::String(tree_sha.clone())
            && execution["driver_artifact"] == driver_artifact
            && transport["driver_artifact"] == driver_artifact
            && execution["source_generation_schema"]
                == worker_source_generation::SOURCE_GENERATION_SCHEMA
            && transport["source_generation_schema"]
                == worker_source_generation::SOURCE_GENERATION_SCHEMA
            && execution["source_generation_sha256"] == Value::String(source_generation.clone())
            && transport["source_generation_sha256"] == Value::String(source_generation.clone())
            && source_generation == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256
            && association_wave_one["schema"] == DISCOVERY_FSV_WAVE_SCHEMA
            && association_wave_one["wave"] == 1
            && association_wave_two["schema"] == DISCOVERY_FSV_WAVE_SCHEMA
            && association_wave_two["wave"] == 2
            && association_wave_two["complete"] == Value::Bool(true)
            && association_wave_one["tree_sha"] == execution["tree_sha"]
            && association_wave_two["tree_sha"] == execution["tree_sha"]
            && association_wave_two["wave_one"]["sha256"]
                == Value::String(sha256(&association_wave_one_bytes)),
        "ISSUE_1116_1119_RECEIPT_SCHEMA_INVALID",
        json!({"execution":execution["schema"],"transport":transport["schema"]}),
    )?;
    let transcript_path = payload.join("transport.ndjson");
    let transcript_bytes = fs::read(&transcript_path)?;
    let transcript_requests = std::str::from_utf8(&transcript_bytes)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    require(
        transcript_requests
            == expected_transport_requests(&execution, &association_wave_two["read_request"])
            && transport["transcript"]["path"]
                == Value::String(transcript_path.to_string_lossy().into_owned())
            && transport["transcript"]["bytes"].as_u64()
                == u64::try_from(transcript_bytes.len()).ok()
            && transport["transcript"]["sha256"] == Value::String(sha256(&transcript_bytes))
            && transport["transcript"]["request_count"].as_u64()
                == u64::try_from(transcript_requests.len()).ok(),
        "ISSUE_1116_1119_TRANSPORT_TRIGGER_READBACK_MISMATCH",
        json!({
            "path": transcript_path,
            "bytes": transcript_bytes.len(),
            "sha256": sha256(&transcript_bytes),
            "requests": transcript_requests,
        }),
    )?;
    let transport_output_path = payload.join("transport-output.ndjson");
    let transport_output_bytes = fs::read(&transport_output_path)?;
    let transport_responses = std::str::from_utf8(&transport_output_bytes)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    require(
        transport["output"]["path"]
            == Value::String(transport_output_path.to_string_lossy().into_owned())
            && transport["output"]["bytes"].as_u64()
                == u64::try_from(transport_output_bytes.len()).ok()
            && transport["output"]["sha256"] == Value::String(sha256(&transport_output_bytes))
            && transport_responses.len() == 7
            && transport_responses
                .iter()
                .enumerate()
                .all(|(index, response)| {
                    response["jsonrpc"] == "2.0"
                        && response["id"] == json!(index + 1)
                        && response.get("error").is_none()
                }),
        "ISSUE_1116_1119_TRANSPORT_OUTPUT_READBACK_MISMATCH",
        json!({
            "path": transport_output_path,
            "bytes": transport_output_bytes.len(),
            "sha256": sha256(&transport_output_bytes),
            "response_count": transport_responses.len(),
        }),
    )?;
    let physical_tools = transport_responses[0]["result"]["tools"]
        .as_array()
        .ok_or("physical tools/list response has no tools")?;
    let physical_architecture_tool_schema =
        verify_get_architecture_tools_list_schema(physical_tools)?;
    let physical_detect_changes_tool_schema =
        verify_detect_changes_tools_list_schema(physical_tools)?;
    let physical_discovery_tool_schema =
        verify_discover_associations_tools_list_schema(physical_tools)?;
    let physical_projects = jsonrpc_tool_payload(&transport_responses[1], "list_projects")?;
    let physical_search = jsonrpc_tool_payload(&transport_responses[2], "search_graph")?;
    let physical_latent = jsonrpc_tool_payload(&transport_responses[3], "discover_latent_links")?;
    let physical_discovery =
        jsonrpc_tool_payload(&transport_responses[4], "discover_associations")?;
    let physical_detect_changes = jsonrpc_tool_payload(&transport_responses[5], "detect_changes")?;
    let physical_detect_changes_contract = verify_detect_changes_v2_payload(
        &physical_detect_changes,
        &transcript_requests[5]["params"]["arguments"],
        execution["project"]
            .as_str()
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_PROJECT_MISSING")?,
        execution["fixture"]["source"]["head"]
            .as_str()
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_EXECUTION_HEAD_MISSING")?,
    )?;
    let physical_architecture = jsonrpc_tool_payload(&transport_responses[6], "get_architecture")?;
    let physical_architecture_result_bytes = serde_json::to_vec(&transport_responses[6]["result"])?;
    let physical_architecture_text = transport_responses[6]["result"]["content"][0]["text"]
        .as_str()
        .ok_or("ISSUE_1149_TRANSPORT_READBACK_ARCHITECTURE_TEXT_MISSING")?;
    require(
        transport["response_count"].as_u64() == u64::try_from(transport_responses.len()).ok()
            && transport["tool_count"].as_u64() == u64::try_from(physical_tools.len()).ok()
            && physical_architecture_tool_schema == transport["get_architecture_tool_schema"]
            && physical_detect_changes_tool_schema == transport["detect_changes_tool_schema"]
            && physical_discovery_tool_schema == transport["discover_associations_tool_schema"]
            && physical_projects == transport["projects"]
            && physical_search == transport["search"]
            && physical_latent == transport["latent"]
            && physical_discovery == transport["discovery"]
            && physical_discovery == association_wave_two["read"]
            && physical_detect_changes_contract == transport["detect_changes"]
            && transport["association_publication"]["wave"] == 2
            && transport["association_publication"]["artifact_sha256"]
                == association_wave_two["publication"]["response"]["artifact_sha256"]
            && transport["association_publication"]["read_request"]
                == association_wave_two["read_request"]
            && physical_architecture == transport["architecture"]
            && physical_architecture == execution["architecture_clusters"]["exact"]["response"]
            && transport["architecture_exchange"]["request"] == transcript_requests[6]
            && transport["architecture_exchange"]["result_bytes"].as_u64()
                == u64::try_from(physical_architecture_result_bytes.len()).ok()
            && transport["architecture_exchange"]["result_sha256"]
                == Value::String(sha256(&physical_architecture_result_bytes))
            && transport["architecture_exchange"]["payload_text_bytes"].as_u64()
                == u64::try_from(physical_architecture_text.len()).ok()
            && transport["architecture_exchange"]["payload_text_sha256"]
                == Value::String(sha256(physical_architecture_text.as_bytes()))
            && transport["before"]["sha256"] == transport["after"]["sha256"],
        "ISSUE_1116_1119_TRANSPORT_PAYLOAD_READBACK_MISMATCH",
        json!({
            "tools": physical_tools.len(),
            "get_architecture_tool_schema": physical_architecture_tool_schema,
            "detect_changes_tool_schema": physical_detect_changes_tool_schema,
            "discover_associations_tool_schema": physical_discovery_tool_schema,
            "projects": physical_projects,
            "search": physical_search,
            "latent": physical_latent,
            "discovery": physical_discovery,
            "detect_changes": physical_detect_changes_contract,
            "architecture": physical_architecture,
            "before": transport["before"]["sha256"],
            "after": transport["after"]["sha256"],
        }),
    )?;
    let cache = PathBuf::from(
        execution["cache"]
            .as_str()
            .ok_or("execution cache missing")?,
    );
    let project = execution["project"]
        .as_str()
        .ok_or("execution project missing")?;
    let repo = PathBuf::from(execution["repo"].as_str().ok_or("execution repo missing")?);
    require(
        repo == payload.join("real-rust-repo") && cache == payload.join("real-cache"),
        "ISSUE_1116_1119_READBACK_RECEIPT_BINDING_MISMATCH",
        json!({"payload": payload, "repo": repo, "cache": cache}),
    )?;
    let fixture_source = fixture_source_state(&repo)?;
    require(
        fixture_source == execution["fixture"]["source"]
            && fixture_source == execution["fixture_after"],
        "ISSUE_1116_1119_FIXTURE_SOURCE_READBACK_MISMATCH",
        &fixture_source,
    )?;
    let (shipping_host, shipping_host_state) = shipping_astrolabe_executable()?;
    let execute_verified_worker: CbmVerifiedWorkerBinding =
        serde_json::from_value(execution["shipping_host"]["verified_worker"].clone())?;
    let transport_verified_worker: CbmVerifiedWorkerBinding =
        serde_json::from_value(transport["verified_worker"].clone())?;
    let execute_worker_identity =
        validate_verified_worker_binding(&execute_verified_worker, &shipping_host)?;
    let transport_worker_identity =
        validate_verified_worker_binding(&transport_verified_worker, &shipping_host)?;
    require(
        execution["shipping_host"]["configured"] == shipping_host_state,
        "ISSUE_1116_1119_READBACK_SHIPPING_HOST_DRIFT",
        &shipping_host_state,
    )?;
    require(
        verified_worker_stable_fields_equal(&execute_verified_worker, &transport_verified_worker)
            && execute_verified_worker.capability.challenge
                != transport_verified_worker.capability.challenge
            && execute_worker_identity == transport_worker_identity
            && execution["shipping_host"]["verified_worker_identity"]
                == json!(execute_worker_identity)
            && transport["verified_worker_identity"] == json!(transport_worker_identity)
            && execution["shipping_host"]["supervisor_should_wrap"] == Value::Bool(true)
            && transport["supervisor_should_wrap"] == Value::Bool(true),
        "ISSUE_1146_WORKER_CAPABILITY_SEPARATE_READBACK_MISMATCH",
        json!({
            "execute": execute_verified_worker,
            "transport": transport_verified_worker,
            "physical_identity": execute_worker_identity,
        }),
    )?;
    set_cbm_cache_dir(&cache)?;
    let shipping_sha256 = shipping_host_state["sha256"]
        .as_str()
        .ok_or("ISSUE_1116_1119_SHIPPING_SHA256_MISSING")?;
    let readback_verified_worker = initialize_cbm_host_process_with_verified_worker(
        &shipping_host,
        shipping_sha256,
        &source_generation,
    )?;
    let readback_worker_identity =
        validate_verified_worker_binding(&readback_verified_worker, &shipping_host)?;
    require(
        configured_cbm_host_binary_path()?.as_deref() == Some(shipping_host.as_path())
            && supervisor_should_wrap()
            && verified_worker_stable_fields_equal(
                &execute_verified_worker,
                &readback_verified_worker,
            )
            && readback_verified_worker.capability.challenge
                != execute_verified_worker.capability.challenge
            && readback_verified_worker.capability.challenge
                != transport_verified_worker.capability.challenge
            && readback_worker_identity == execute_worker_identity,
        "ISSUE_1149_CLUSTER_READBACK_WORKER_BINDING_MISMATCH",
        json!({
            "execute": execute_verified_worker,
            "transport": transport_verified_worker,
            "readback": readback_verified_worker,
            "physical_identity": readback_worker_identity,
        }),
    )?;
    let (config, vault_dir, _, _) = vault_identity(&cache, project)?;
    let weave_generation_readback = verify_weave_generation_receipt(&config, project)?;
    require(
        weave_generation_readback == execution["index"]["weave_generation"],
        "ISSUE_1147_WEAVE_SEPARATE_READBACK_MISMATCH",
        json!({
            "execute": execution["index"]["weave_generation"],
            "readback": weave_generation_readback,
        }),
    )?;
    let sim_terminal_attestation_readback =
        readback_sim_terminal_attestation_contract(&cache, project, &payload, &execution)?;
    let persisted_kernel_generation = persisted_kernel_generation_receipt(&config, project)?;
    let kernel_generation_readback = verify_complete_kernel_generation(
        &cache,
        project,
        &kernel_admission(),
        &persisted_kernel_generation,
    )?;
    require(
        kernel_generation_readback == execution["index"]["kernel_generation"],
        "ISSUE_1148_KERNEL_SEPARATE_PROCESS_READBACK_MISMATCH",
        json!({
            "execution": execution["index"]["kernel_generation"],
            "readback": kernel_generation_readback,
        }),
    )?;
    let architecture_cluster_source = sqlite_cluster_source_state(&cache, project)?;
    let architecture_cluster_request =
        architecture_cluster_request(project, &architecture_cluster_source, false)?;
    require(
        architecture_cluster_source == execution["architecture_clusters"]["source"]
            && architecture_cluster_source == execution["architecture_clusters"]["source_after"]
            && architecture_cluster_request
                == execution["architecture_clusters"]["exact"]["request"],
        "ISSUE_1149_CLUSTER_SEPARATE_SQLITE_READBACK_MISMATCH",
        json!({
            "source": architecture_cluster_source,
            "execution_source": execution["architecture_clusters"]["source"],
            "request": architecture_cluster_request,
            "execution_request": execution["architecture_clusters"]["exact"]["request"],
        }),
    )?;
    let architecture_runner = CbmToolRunner::new_default()?;
    let detect_changes_exact_bound =
        transport["detect_changes_result_byte_bound"]["exact"]["bound"]
            .as_u64()
            .filter(|bound| *bound > 1)
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_READBACK_EXACT_BOUND_MISSING")?;
    let execution_detect_changes_exact_run = transport["detect_changes_result_byte_bound"]["exact"]
        ["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .and_then(|round| round.get("run"))
        .ok_or("ISSUE_1116_1119_DETECT_CHANGES_READBACK_EXACT_RUN_MISSING")?;
    let detect_changes_exact_request =
        detect_changes_fsv_request(project, detect_changes_exact_bound);
    let detect_changes_exact_readback = run_detect_changes_success(
        &architecture_runner,
        &cache,
        project,
        fixture_source["head"]
            .as_str()
            .ok_or("ISSUE_1116_1119_DETECT_CHANGES_READBACK_HEAD_MISSING")?,
        "detect_changes_exact_final_public_result_separate_process_readback",
        &detect_changes_exact_request,
    )?;
    require(
        detect_changes_exact_readback["request"] == execution_detect_changes_exact_run["request"]
            && detect_changes_exact_readback["response"]
                == execution_detect_changes_exact_run["response"]
            && detect_changes_exact_readback["contract"]
                == execution_detect_changes_exact_run["contract"]
            && detect_changes_exact_readback["final_public_mcp_result_bytes"]
                == detect_changes_exact_bound
            && detect_changes_exact_readback["final_public_mcp_result_sha256"]
                == execution_detect_changes_exact_run["final_public_mcp_result_sha256"],
        "ISSUE_1116_1119_DETECT_CHANGES_EXACT_RESULT_SEPARATE_READBACK_MISMATCH",
        json!({
            "execution": execution_detect_changes_exact_run,
            "readback": detect_changes_exact_readback,
        }),
    )?;
    let detect_changes_below_request =
        detect_changes_fsv_request(project, detect_changes_exact_bound - 1);
    let detect_changes_below_readback = expect_detect_changes_result_bound_refusal(
        &architecture_runner,
        &cache,
        project,
        "detect_changes_final_public_result_one_byte_below_separate_process_readback",
        &detect_changes_below_request,
    )?;
    require(
        detect_changes_below_readback["request"]
            == transport["detect_changes_result_byte_bound"]["one_byte_below"]["request"]
            && detect_changes_below_readback["response"]
                == transport["detect_changes_result_byte_bound"]["one_byte_below"]["response"]
            && detect_changes_below_readback["request"]["result_max_bytes"]
                == detect_changes_exact_bound - 1,
        "ISSUE_1116_1119_DETECT_CHANGES_ONE_BYTE_BELOW_SEPARATE_READBACK_MISMATCH",
        json!({
            "execution": transport["detect_changes_result_byte_bound"]["one_byte_below"],
            "readback": detect_changes_below_readback,
        }),
    )?;
    let detect_changes_result_byte_bound_readback = json!({
        "exact": detect_changes_exact_readback,
        "one_byte_below": detect_changes_below_readback,
        "exact_bound": detect_changes_exact_bound,
        "measured_surface": "complete final public MCP result String after grounded augmentation",
        "separate_process_exact_and_one_byte_below_equal": true,
    });
    let architecture_cluster_exact = run_architecture_cluster_success(
        &architecture_runner,
        &cache,
        project,
        "architecture_clusters_separate_process_readback",
        &architecture_cluster_request,
        &architecture_cluster_source,
        false,
    )?;
    require(
        architecture_cluster_exact["response"]
            == execution["architecture_clusters"]["exact"]["response"]
            && architecture_cluster_exact["proof"]
                == execution["architecture_clusters"]["exact"]["proof"],
        "ISSUE_1149_CLUSTER_SEPARATE_RECEIPT_READBACK_MISMATCH",
        json!({
            "execution": execution["architecture_clusters"]["exact"],
            "readback": architecture_cluster_exact,
        }),
    )?;
    let c_exact_bound = execution["architecture_clusters"]["c_exact_byte_bound"]["bound"]
        .as_u64()
        .ok_or("ISSUE_1149_CLUSTER_READBACK_C_EXACT_BOUND_MISSING")?;
    let execution_c_exact_run = execution["architecture_clusters"]["c_exact_byte_bound"]["rounds"]
        .as_array()
        .and_then(|rounds| rounds.last())
        .and_then(|round| round.get("run"))
        .ok_or("ISSUE_1149_CLUSTER_READBACK_C_EXACT_RUN_MISSING")?;
    let mut c_exact_request = architecture_cluster_request.clone();
    c_exact_request["cluster_max_result_bytes"] = json!(c_exact_bound);
    let c_exact_readback = run_architecture_cluster_success(
        &architecture_runner,
        &cache,
        project,
        "architecture_clusters_c_exact_byte_separate_process_readback",
        &c_exact_request,
        &architecture_cluster_source,
        false,
    )?;
    require(
        c_exact_readback["response"] == execution_c_exact_run["response"]
            && c_exact_readback["proof"] == execution_c_exact_run["proof"],
        "ISSUE_1149_CLUSTER_C_EXACT_BYTE_READBACK_MISMATCH",
        json!({"execution": execution_c_exact_run, "readback": c_exact_readback}),
    )?;
    let mut c_below_request = architecture_cluster_request.clone();
    c_below_request["cluster_max_result_bytes"] = json!(c_exact_bound - 1);
    let c_below_readback = expect_refusal(
        &architecture_runner,
        &cache,
        project,
        "architecture_clusters_c_one_byte_below_separate_process_readback",
        "get_architecture",
        &c_below_request,
        "CBM_ARCH_CLUSTER_SERIALIZED_RESULT_BOUND_EXCEEDED",
    )?;
    require(
        c_below_readback["response"]
            == execution["architecture_clusters"]["c_below_byte_bound"]["response"],
        "ISSUE_1149_CLUSTER_C_ONE_BYTE_BELOW_READBACK_MISMATCH",
        json!({
            "execution": execution["architecture_clusters"]["c_below_byte_bound"],
            "readback": c_below_readback,
        }),
    )?;

    let augmented_exact_bound =
        execution["architecture_clusters"]["augmented_exact_byte_bound"]["bound"]
            .as_u64()
            .ok_or("ISSUE_1149_CLUSTER_READBACK_AUGMENTED_EXACT_BOUND_MISSING")?;
    let execution_augmented_exact_run =
        execution["architecture_clusters"]["augmented_exact_byte_bound"]["rounds"]
            .as_array()
            .and_then(|rounds| rounds.last())
            .and_then(|round| round.get("run"))
            .ok_or("ISSUE_1149_CLUSTER_READBACK_AUGMENTED_EXACT_RUN_MISSING")?;
    let mut augmented_exact_request = architecture_cluster_request.clone();
    augmented_exact_request["aspects"] = json!(["clusters", "kernel_context"]);
    augmented_exact_request["cluster_max_result_bytes"] = json!(augmented_exact_bound);
    let augmented_exact_readback = run_architecture_cluster_success(
        &architecture_runner,
        &cache,
        project,
        "architecture_clusters_augmented_exact_byte_separate_process_readback",
        &augmented_exact_request,
        &architecture_cluster_source,
        true,
    )?;
    require(
        augmented_exact_readback["response"] == execution_augmented_exact_run["response"]
            && augmented_exact_readback["proof"] == execution_augmented_exact_run["proof"],
        "ISSUE_1149_CLUSTER_AUGMENTED_EXACT_BYTE_READBACK_MISMATCH",
        json!({
            "execution": execution_augmented_exact_run,
            "readback": augmented_exact_readback,
        }),
    )?;
    let mut augmented_below_request = architecture_cluster_request.clone();
    augmented_below_request["aspects"] = json!(["clusters", "kernel_context"]);
    augmented_below_request["cluster_max_result_bytes"] = json!(augmented_exact_bound - 1);
    let augmented_below_readback = expect_refusal(
        &architecture_runner,
        &cache,
        project,
        "architecture_clusters_augmented_one_byte_below_separate_process_readback",
        "get_architecture",
        &augmented_below_request,
        "ASTRO_ARCHITECTURE_SERIALIZED_RESULT_BOUND_EXCEEDED",
    )?;
    require(
        augmented_below_readback["response"]
            == execution["architecture_clusters"]["augmented_below_byte_bound"]["response"],
        "ISSUE_1149_CLUSTER_AUGMENTED_ONE_BYTE_BELOW_READBACK_MISMATCH",
        json!({
            "execution": execution["architecture_clusters"]["augmented_below_byte_bound"],
            "readback": augmented_below_readback,
        }),
    )?;
    let physical_edge_fixture_readback = readback_cluster_fixture_edges(
        &architecture_runner,
        &cache,
        &execution["architecture_clusters"]["physical_edge_fixtures"],
    )?;
    let mut raw_refusal_readback = serde_json::Map::new();
    for field in [
        "duplicate_key",
        "embedded_nul_project",
        "embedded_nul_path",
        "too_many_aspects",
    ] {
        let expected = &execution["architecture_clusters"]["raw_refusals"][field];
        let raw_arguments = expected["raw_arguments"]["text"]
            .as_str()
            .ok_or("ISSUE_1149_RAW_REFUSAL_READBACK_ARGUMENTS_MISSING")?;
        let expected_code = expected["expected_code"]
            .as_str()
            .ok_or("ISSUE_1149_RAW_REFUSAL_READBACK_CODE_MISSING")?;
        let observed = expect_raw_architecture_refusal(
            &architecture_runner,
            &cache,
            &format!("architecture_clusters_{field}_separate_process_readback"),
            raw_arguments,
            expected_code,
        )?;
        require(
            observed["handler"]["sha256"] == expected["handler"]["sha256"]
                && observed["handler"]["response"] == expected["handler"]["response"]
                && observed["jsonrpc"]["response_sha256"] == expected["jsonrpc"]["response_sha256"]
                && observed["jsonrpc"]["response"] == expected["jsonrpc"]["response"],
            "ISSUE_1149_RAW_REFUSAL_SEPARATE_READBACK_MISMATCH",
            json!({"field": field, "expected": expected, "observed": observed}),
        )?;
        raw_refusal_readback.insert(field.to_string(), observed);
    }
    let edge_count = architecture_cluster_source["cluster_edge_count"]
        .as_u64()
        .ok_or("ISSUE_1149_READBACK_EDGE_COUNT_MISSING")?;
    let mut below_edge_request = architecture_cluster_request.clone();
    below_edge_request["cluster_max_edges"] = json!(edge_count - 1);
    let below_edge_readback = expect_refusal(
        &architecture_runner,
        &cache,
        project,
        "architecture_clusters_below_edge_bound_separate_process_readback",
        "get_architecture",
        &below_edge_request,
        "CBM_ARCH_CLUSTER_EDGE_BOUND_EXCEEDED",
    )?;
    require(
        below_edge_readback["response"]
            == execution["architecture_clusters"]["below_edge_bound"]["response"],
        "ISSUE_1149_BELOW_EDGE_BOUND_SEPARATE_READBACK_MISMATCH",
        &below_edge_readback,
    )?;
    let mut move_cap_request = architecture_cluster_request.clone();
    move_cap_request["cluster_max_move_visits"] = json!(1_u64);
    let move_cap_readback = expect_refusal(
        &architecture_runner,
        &cache,
        project,
        "architecture_clusters_move_cap_separate_process_readback",
        "get_architecture",
        &move_cap_request,
        "CBM_LEIDEN_MOVE_CAP_EXHAUSTED",
    )?;
    require(
        move_cap_readback["request"]
            == execution["architecture_clusters"]["move_cap_refusal"]["request"]
            && move_cap_readback["response"]
                == execution["architecture_clusters"]["move_cap_refusal"]["response"]
            && move_cap_readback["response"]["cluster_receipt"]["move_visit_cap"] == 1
            && move_cap_readback["response"]["cluster_receipt"]["move_visit_count"] == 1
            && move_cap_readback["response"]["cluster_receipt"]["move_phase_status"] == "refused",
        "ISSUE_1149_MOVE_CAP_SEPARATE_READBACK_MISMATCH",
        &move_cap_readback,
    )?;
    let architecture_clusters = json!({
        "source": architecture_cluster_source,
        "exact": architecture_cluster_exact,
        "c_exact_byte_bound": c_exact_readback,
        "c_below_byte_bound": c_below_readback,
        "augmented_exact_byte_bound": augmented_exact_readback,
        "augmented_below_byte_bound": augmented_below_readback,
        "execution_invalid_resolution": execution["architecture_clusters"]["invalid_resolution"],
        "execution_below_node_bound": execution["architecture_clusters"]["below_node_bound"],
        "below_edge_bound": below_edge_readback,
        "move_cap_refusal": move_cap_readback,
        "raw_refusals": raw_refusal_readback,
        "physical_edge_fixtures": physical_edge_fixture_readback,
        "execution_above": execution["architecture_clusters"]["above"],
        "separate_shipping_handler_readback": true,
        "source_and_complete_receipt_equal": true,
        "exact_and_one_byte_below_bounds_reexecuted": true,
    });
    let transition_key = execution["index"]["transition"]["key"]
        .as_str()
        .ok_or("ISSUE_1116_1119_READBACK_TRANSITION_KEY_MISSING")?
        .to_string();
    let persisted_transition_raw = execution["index"]["transition"]["raw"]
        .as_str()
        .ok_or("ISSUE_1116_1119_READBACK_TRANSITION_RAW_MISSING")?
        .to_string();
    let config_connection = readonly_sqlite(&cache.join("_config.db"))?;
    let config_integrity =
        config_connection.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?;
    let exact_transition_row_count = config_connection.query_row(
        "SELECT COUNT(*) FROM config WHERE key = ?1",
        [&transition_key],
        |row| row.get::<_, i64>(0),
    )?;
    let current_transition_raw = config_connection.query_row(
        "SELECT value FROM config WHERE key = ?1",
        [&transition_key],
        |row| row.get::<_, String>(0),
    )?;
    drop(config_connection);
    let current_transition: Value = serde_json::from_str(&current_transition_raw)?;
    let canonical_repo = repo.canonicalize()?;
    let canonical_db = cache.join(format!("{project}.db"));
    let current_transition_family = transition_family_evidence(&canonical_db)?;
    let index_raw = execution["index"]["raw"]["text"]
        .as_str()
        .ok_or("ISSUE_1116_1119_INDEX_RAW_RESPONSE_MISSING")?;
    let reparsed_index_envelope: Value = serde_json::from_str(index_raw)?;
    require(
        execution["index"]["raw"]["bytes"].as_u64() == u64::try_from(index_raw.len()).ok()
            && execution["index"]["raw"]["sha256"] == Value::String(sha256(index_raw.as_bytes()))
            && reparsed_index_envelope == execution["index"]["envelope"],
        "ISSUE_1116_1119_INDEX_RAW_RESPONSE_MISMATCH",
        &execution["index"]["raw"],
    )?;
    let current_validation = validate_completed_transition(CompletedTransitionRequest {
        transition_key: &transition_key,
        transition: &current_transition,
        project,
        canonical_root: &canonical_repo,
        canonical_db: &canonical_db,
        response_raw: index_raw,
        response_envelope: &execution["index"]["envelope"],
        response_payload: &execution["index"]["response"],
        family_after: &current_transition_family,
        binding: &execute_verified_worker,
        expected_process_pid: capability_owner_identity(&execute_verified_worker)?.0,
        observation_path: None,
    })?;
    require(
        current_validation.persisted_observation.is_none(),
        "ISSUE_1116_1119_READBACK_UNEXPECTED_TRANSITION_OBSERVATION",
        &current_validation.persisted_observation,
    )?;
    let current_response_sha256 = current_validation.response_sha256;
    let current_transition_sha256 = sha256(current_transition_raw.as_bytes());
    let repeat_response_sha256 =
        sha256(&serde_json::to_vec(&execution["index_repeat"]["envelope"])?);
    let noop_readback =
        &execution["index_repeat"]["response"]["grounding_summary"]["noop_readback"];
    require(
        exact_transition_row_count == 1
            && config.get(&transition_key).map(String::as_str)
                == Some(current_transition_raw.as_str())
            && current_transition_raw == persisted_transition_raw
            && execution["index"]["transition"]["sha256"]
                == Value::String(current_transition_sha256.clone())
            && execution["index"]["transition"]["response_sha256"]
                == Value::String(current_response_sha256.clone())
            && execution["index"]["transition"]["raw_response_sha256"]
                == Value::String(sha256(index_raw.as_bytes()))
            && execution["index"]["transition"]["family_readback"] == current_transition_family
            && execution["index_repeat"]["response_sha256"]
                == Value::String(repeat_response_sha256.clone())
            && execution["index_repeat"]["response"]["status"] == "unchanged"
            && execution["index_repeat"]["response"]["index_admission"]["status"] == "cache_hit"
            && execution["index_repeat"]["response"]["index_admission"]["writes_skipped"]
                == Value::Bool(true)
            && execution["index_repeat"]["response"]["grounding_summary"]["status"] == "unchanged"
            && execution["index_repeat"]["response"]["grounding_summary"]["writes_skipped"]
                == Value::Bool(true)
            && execution["index_repeat"]["config_before"]["integrity"] == "ok"
            && execution["index_repeat"]["config_after"]["integrity"] == "ok"
            && execution["index_repeat"]["config_before"]["row_count"]
                == noop_readback["config_rows"]
            && execution["index_repeat"]["config_before"]["sha256"]
                == noop_readback["config_rows_sha256"]
            && execution["index_repeat"]["config_before"]["publication_generation"]
                == noop_readback["publication_generation"]
            && execution["index_repeat"]["config_before"]["row_count"]
                == execution["index_repeat"]["config_after"]["row_count"]
            && execution["index_repeat"]["config_before"]["sha256"]
                == execution["index_repeat"]["config_after"]["sha256"]
            && execution["index_repeat"]["config_before"]["publication_generation"]
                == execution["index_repeat"]["config_after"]["publication_generation"]
            && execution["index_repeat"]["config_before"]["transition_sha256"]
                == Value::String(current_transition_sha256.clone())
            && execution["index_repeat"]["config_after"]["transition_sha256"]
                == Value::String(current_transition_sha256.clone()),
        "ISSUE_1116_1119_PROJECT_TRANSITION_READBACK_MISMATCH",
        json!({
            "key": transition_key,
            "exact_row_count": exact_transition_row_count,
            "transition_sha256": current_transition_sha256,
            "response_sha256": current_response_sha256,
            "repeat_response_sha256": repeat_response_sha256,
            "family": current_transition_family,
        }),
    )?;
    let project_transition_readback = json!({
        "key": transition_key,
        "exact_row_count": exact_transition_row_count,
        "raw_bytes": current_transition_raw.len(),
        "raw_sha256": current_transition_sha256,
        "response_sha256": current_response_sha256,
        "raw_response_sha256": sha256(index_raw.as_bytes()),
        "family_readback": current_transition_family,
        "config_integrity": config_integrity,
        "separate_exact_row_readback": true,
        "noop": {
            "response_sha256": repeat_response_sha256,
            "status": execution["index_repeat"]["response"]["status"],
            "admission_status": execution["index_repeat"]["response"]["index_admission"]["status"],
            "writes_skipped": execution["index_repeat"]["response"]["index_admission"]["writes_skipped"],
            "config_rows": noop_readback["config_rows"],
            "config_rows_sha256": noop_readback["config_rows_sha256"],
            "publication_generation": noop_readback["publication_generation"],
            "config_map_and_transition_unchanged": true,
        },
    });
    let sqlite = sqlite_counts(&cache, project)?;
    require(
        config_integrity == "ok"
            && sqlite["integrity"] == Value::String("ok".to_string())
            && sqlite["nodes"].as_u64().is_some_and(|count| count > 0)
            && sqlite["edges"].as_u64().is_some_and(|count| count > 0)
            && sqlite["node_vectors"]
                .as_u64()
                .is_some_and(|count| count > 0),
        "ISSUE_1116_1119_SQLITE_READBACK_FAILED",
        &sqlite,
    )?;
    let fixture_sqlite = verify_fixture_sqlite_rows(&cache, project, &repo)?;
    let lowered_key = format!("astrolabe.calyx.{project}.lowered_sqlite_path");
    let lowered_path = PathBuf::from(
        config
            .get(&lowered_key)
            .ok_or("persisted lowered_sqlite_path is missing")?,
    );
    let (lowering_vault, _) = open_lowering_vault(&cache, project)?;
    let lowered_verification =
        astrolabe_lower::verify_lowered_artifact(&lowering_vault, &lowered_path, project)?;
    drop(lowering_vault);
    let (_, lowered_file_sha256) = file_sha256(&lowered_path)?;
    require(
        lowered_verification.project == project
            && lowered_verification.artifact_path == lowered_path
            && lowered_verification.artifact_sha256 == lowered_file_sha256
            && config
                .get(&format!(
                    "astrolabe.calyx.{project}.lowered_artifact_sha256"
                ))
                .map(String::as_str)
                == Some(lowered_file_sha256.as_str())
            && config
                .get(&format!(
                    "astrolabe.calyx.{project}.lowered_vault_fingerprint_sha256"
                ))
                .map(String::as_str)
                == Some(lowered_verification.vault_fingerprint_sha256.as_str())
            && config
                .get(&format!("astrolabe.calyx.{project}.lowered_manifest_seq"))
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|seq| seq > 0),
        "ISSUE_1116_1119_LOWERED_ARTIFACT_READBACK_MISMATCH",
        json!({
            "configured_path": &lowered_path,
            "file_sha256": &lowered_file_sha256,
            "verification": &lowered_verification,
        }),
    )?;
    let malformed = &execution["malformed_lowering"];
    for (key_field, raw_field) in [
        ("source_key", "source_raw"),
        ("observation_key", "observation_raw"),
        ("fault_key", "fault_raw"),
    ] {
        let key = malformed[key_field]
            .as_str()
            .ok_or_else(|| format!("malformed receipt {key_field} missing"))?;
        let raw = malformed[raw_field]
            .as_str()
            .ok_or_else(|| format!("malformed receipt {raw_field} missing"))?;
        require(
            config.get(key).map(String::as_str) == Some(raw),
            "ISSUE_1116_1119_MALFORMED_SEPARATE_READBACK_MISMATCH",
            key,
        )?;
    }
    let semantic_available_before = physical_state(&cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"semantic_project_moderate_available",
            "phase":"before",
            "state":semantic_available_before,
        }))?
    );
    let (vault, _) = open_vault(&cache, project)?;
    let snapshot = vault.latest_seq();
    let complete = read_complete_association_state_at(&vault, snapshot)?;
    require(
        complete.constellation_count > 0
            && complete.completion_row_count > 0
            && complete.physical_block_count > 0
            && !complete.witness_state_hash.is_empty()
            && !complete.pair_key_stream_hash.is_empty()
            && !complete.pair_value_stream_hash.is_empty(),
        "ISSUE_1116_1119_COMPLETE_XTERM_EMPTY",
        serde_json::to_string(&complete)?,
    )?;
    let semantic_coverage = verify_semantic_coverage(
        &vault,
        snapshot,
        &cache,
        project,
        SemanticProjectExpectation::ModerateAvailable,
    )?;
    let semantic_registry = verify_semantic_registry()?;
    let latent = verify_latent_rows(&vault, snapshot, &execution)?;
    let discovery = verify_discovery_rows(
        &vault,
        snapshot,
        &payload,
        &execution,
        &association_wave_one,
        &association_wave_two,
    )?;
    let search = verify_search_manifest(&cache, project, &execution)?;
    drop(vault);
    let semantic_available_after = physical_state(&cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"semantic_project_moderate_available",
            "phase":"after",
            "state":semantic_available_after,
        }))?
    );
    require(
        semantic_available_before["sha256"] == semantic_available_after["sha256"],
        "ISSUE_980_SEMANTIC_AVAILABLE_READBACK_MUTATED_STATE",
        json!({
            "before": semantic_available_before,
            "after": semantic_available_after,
        }),
    )?;
    let ledger_chain = astrolabe_ingest::verify_chain_vault_path(&vault_dir)?;
    require(
        ledger_chain.is_intact() && ledger_chain.count > 0,
        "ISSUE_1116_1119_LEDGER_CHAIN_NOT_INTACT",
        &ledger_chain.status,
    )?;
    let final_state = physical_state(&cache, project)?;
    require(
        final_state["sha256"] == association_wave_two["final_state"]["sha256"]
            && final_state["sha256"] == transport["after"]["sha256"],
        "ISSUE_1116_1119_FINAL_STATE_MISMATCH",
        json!({
            "readback": final_state["sha256"],
            "association_publish": association_wave_two["final_state"]["sha256"],
            "transport": transport["after"]["sha256"],
        }),
    )?;
    let report = json!({
        "schema": "astrolabe.issues-1116-1119.readback.v1",
        "tree_sha": tree_sha,
        "source_generation_schema": worker_source_generation::SOURCE_GENERATION_SCHEMA,
        "source_generation_sha256": source_generation,
        "driver_artifact": driver_artifact,
        "project": project,
        "fixture_source": fixture_source,
        "source_of_truth": "separate-process exact project-transition and complete-kernel publication config rows plus authoritative SQLite bytes/typed Project-column/family recounts; exact physical SQLite nodes and CALLS/IMPORTS cluster projection rows with independently rebuilt label/source/projection/result hashes and a fresh shipping get_architecture read; exact native detect_changes v2 tools/list plus a closed, explicitly bounded clean-fixture request/result proving base/head OIDs, double Git observation, empty mapping coverage and labeled no_changes without an Oracle-grounded numeric claim, with exact final-public-MCP-result byte success and one-byte-below Rust refusal reexecuted in the separate process; fresh narrow read-only reopens of the primary and five isolated SIM vault generations proving exact raw family hashes, marker/Ledger point rows, composite-CSR refs, true no-delta reuse, bootstrap invalidation, corrupt/stale refusal and sequence CAS; a fresh narrow read-only Aster reopen of the composite Kernel current pointer, manifest, eight generation rows and aliases, checksum-validated member HNSW, physical Ledger row, complete KernelGraph S20 roster, independently re-encoded external query corpus and exact graph-routed report; real persisted KernelGraph bytes with fail-closed delta/region probes and an exact structural full-rebuild artifact/FVS/source byte comparison; fresh all-CF Graph/Base/Slot semantic reconstruction with exact source/emitted manifests and Ledger payload; XTerm/Assay point reads and ledger verification; canonical search manifest; strict external association capture files reparsed against exact prepared bindings; physical prepared/final current+previous pointers, manifests, stages and all six Ledger rows; exact tombstone bytes for both retired generation row sets; complete directory-and-file tree digests",
        "execution": {"bytes": execution_bytes.len(), "sha256": sha256(&execution_bytes)},
        "transport": {
            "receipt_bytes": transport_bytes.len(),
            "receipt_sha256": sha256(&transport_bytes),
            "output_path": transport_output_path,
            "output_bytes": transport_output_bytes.len(),
            "output_sha256": sha256(&transport_output_bytes),
            "response_count": transport_responses.len(),
            "get_architecture_tool_schema": physical_architecture_tool_schema,
            "detect_changes_tool_schema": physical_detect_changes_tool_schema,
            "discover_associations_tool_schema": physical_discovery_tool_schema,
            "detect_changes": physical_detect_changes_contract,
            "state_unchanged": transport["state_unchanged"],
            "separate_physical_output_readback": true,
            "transcript_path": transcript_path,
            "transcript_bytes": transcript_bytes.len(),
            "transcript_sha256": sha256(&transcript_bytes),
            "trigger_request_count": transcript_requests.len(),
            "separate_physical_trigger_readback": true,
        },
        "config": {
            "integrity": config_integrity,
            "selected_row_count": config.len(),
            "dial": config.get(&format!("astrolabe.calyx.{project}")),
            "vault_dir": vault_dir,
        },
        "project_transition": project_transition_readback,
        "weave_generation": weave_generation_readback,
        "sim_terminal_attestation": sim_terminal_attestation_readback,
        "kernel_generation": kernel_generation_readback,
        "detect_changes_result_byte_bound": detect_changes_result_byte_bound_readback,
        "architecture_clusters": architecture_clusters,
        "sqlite": sqlite,
        "fixture_sqlite": fixture_sqlite,
        "lowered_verification": lowered_verification,
        "semantic_coverage": semantic_coverage,
        "semantic_available_before": semantic_available_before,
        "semantic_available_after": semantic_available_after,
        "semantic_registry": semantic_registry,
        "complete_xterm": complete,
        "search": search,
        "latent": latent,
        "discovery": discovery,
        "association_publication": {
            "wave_one": {"bytes":association_wave_one_bytes.len(),"sha256":sha256(&association_wave_one_bytes)},
            "wave_two": {"bytes":association_wave_two_bytes.len(),"sha256":sha256(&association_wave_two_bytes)},
            "current_final_artifact_sha256":association_wave_two["publication"]["response"]["artifact_sha256"],
            "genuine_external_capture_files_reparsed":true,
            "current_previous_and_retired_physical_state_verified":true,
        },
        "ledger_chain": ledger_chain,
        "edges": execution["edges"],
        "malformed_lowering": {
            "source_key": malformed["source_key"],
            "source_sha256": malformed["source_sha256"],
            "observation_key": malformed["observation_key"],
            "observation_sha256": sha256(malformed["observation_raw"].as_str().ok_or("observation raw missing")?.as_bytes()),
            "fault_key": malformed["fault_key"],
            "fault_sha256": sha256(malformed["fault_raw"].as_str().ok_or("fault raw missing")?.as_bytes()),
            "separate_exact_row_readback": true,
            "cached_state_unchanged": malformed["cached_state_unchanged"],
        },
        "shipping_host": {
            "execute_binding": execution["shipping_host"],
            "transport_binding": transport["verified_worker"],
            "readback_binding": readback_verified_worker,
            "independent_artifact_readback": shipping_host_state,
            "independent_file_identity": readback_worker_identity,
        },
        "final_state": final_state,
    });
    let bytes = serde_json::to_vec_pretty(&report)?;
    let persisted = write_new_readback(&payload.join("readback.json"), &bytes)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event": "ISSUE_1116_1119_READBACK_COMPLETE",
            "report": persisted,
            "project": project,
            "sqlite_nodes": report["sqlite"]["nodes"],
            "sqlite_edges": report["sqlite"]["edges"],
            "node_vectors": report["sqlite"]["node_vectors"],
            "xterm_rows": report["complete_xterm"]["completion_row_count"],
            "search_documents": report["search"]["document_count"],
            "latent_ledger_seq": report["latent"]["ledger"]["seq"],
            "discovery_current_ledger_seq": report["discovery"]["final"]["current"]["ledger"]["seq"],
            "discovery_previous_ledger_seq": report["discovery"]["final"]["previous"]["ledger"]["seq"],
            "discovery_retired_generation_count": report["discovery"]["retention"]["retired"].as_array().map_or(0, Vec::len),
            "discovery_external_capture_reparsed": report["discovery"]["real_external_receipts_reparsed_from_capture_file"],
            "usable_folds": report["discovery"]["validation"]["usable_fold_count"],
            "unusable_folds": report["discovery"]["validation"]["unusable_fold_count"],
            "kernel_generation_id": report["kernel_generation"]["generation_id"],
            "kernel_members": report["kernel_generation"]["artifact"]["member_count"],
            "kernel_graph_nodes": report["kernel_generation"]["s20_complete_graph_roster"]["graph_node_count"],
            "kernel_s20_vectors": report["kernel_generation"]["s20_complete_graph_roster"]["physical_vector_count"],
            "kernel_real_queries": report["kernel_generation"]["query_corpus"]["queries"].as_array().map_or(0, Vec::len),
            "kernel_recall_permille": report["kernel_generation"]["graph_routed_report"]["recall_permille"],
            "cluster_sqlite_nodes": report["architecture_clusters"]["source"]["node_count"],
            "cluster_sqlite_calls": report["architecture_clusters"]["source"]["calls_edge_count"],
            "cluster_sqlite_imports": report["architecture_clusters"]["source"]["imports_edge_count"],
            "cluster_communities": report["architecture_clusters"]["exact"]["proof"]["community_count"],
            "cluster_source_sha256": report["architecture_clusters"]["exact"]["proof"]["source_sha256"],
            "cluster_projection_sha256": report["architecture_clusters"]["exact"]["proof"]["projection_sha256"],
            "cluster_result_sha256": report["architecture_clusters"]["exact"]["proof"]["result_sha256"],
            "final_state_sha256": report["final_state"]["sha256"],
        }))?
    );
    Ok(())
}

fn fast_semantic_edge(payload: PathBuf) -> AnyResult<()> {
    require(
        !payload.try_exists()?,
        "ISSUE_980_FAST_PAYLOAD_PREEXISTS",
        payload.display(),
    )?;
    fs::create_dir_all(&payload)?;
    let tree_sha = canonical_head()?;
    let driver_artifact = current_driver_artifact_state()?;
    let source_generation = current_source_generation_sha256()?;
    require(
        source_generation == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256,
        "ISSUE_980_FAST_COMPILED_SOURCE_GENERATION_DRIFT",
        &source_generation,
    )?;
    let repo = payload.join("real-fast-rust-repo");
    let cache = payload.join("real-fast-cache");
    let fixture = write_fixture(&repo)?;
    fs::create_dir(&cache)?;
    require(
        set_cbm_cache_dir(&cache)? == cache,
        "ISSUE_980_FAST_CACHE_BINDING_MISMATCH",
        cache.display(),
    )?;
    let (shipping_host, shipping_host_state) = shipping_astrolabe_executable()?;
    require(
        configured_cbm_host_binary_path()?.is_none() && !supervisor_should_wrap(),
        "ISSUE_980_FAST_PROCESS_PRESTATE_INVALID",
        "a fresh fast-semantic-edge process already had a worker binding",
    )?;
    let shipping_sha256 = shipping_host_state["sha256"]
        .as_str()
        .ok_or("ISSUE_980_FAST_SHIPPING_SHA256_MISSING")?;
    let verified_worker = initialize_cbm_host_process_with_verified_worker(
        &shipping_host,
        shipping_sha256,
        &source_generation,
    )?;
    let verified_worker_identity =
        validate_verified_worker_binding(&verified_worker, &shipping_host)?;
    let runner = CbmToolRunner::new_default()?;
    let project = cbm_project_name_from_path(repo.to_str().ok_or("repo path is not UTF-8")?)?;
    let before = binding_edge_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case":"fast_unavailable_project","phase":"before","state":before})
        )?
    );
    require(
        before["config"]["exists"] == Value::Bool(false)
            && binding_project_artifacts_absent(&before),
        "ISSUE_980_FAST_PRESTATE_NOT_PRISTINE",
        &before,
    )?;

    let request = fast_index_request(&repo);
    let (response_raw, response_envelope, response) =
        call_tool_with_raw(&runner, "index_repository", &request)?;
    require(
        response_envelope["isError"] != Value::Bool(true)
            && response["project"] == Value::String(project.clone()),
        "ISSUE_980_FAST_INDEX_FAILED",
        &response,
    )?;
    let canonical_repo = repo.canonicalize()?;
    let canonical_db = cache.join(format!("{project}.db"));
    let transition = read_completed_transition(ReadCompletedTransitionRequest {
        cache: &cache,
        project: &project,
        canonical_root: &canonical_repo,
        canonical_db: &canonical_db,
        response_raw: &response_raw,
        response_envelope: &response_envelope,
        response_payload: &response,
        binding: &verified_worker,
        observation_path: None,
    })?;
    let after_index = edge_semantic_physical_state(
        &cache,
        &project,
        SemanticProjectExpectation::FastUnavailableMode,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"fast_unavailable_project",
            "phase":"after",
            "state":after_index,
        }))?
    );
    require(
        fast_unavailable_semantic_response_matches_sqlite(
            &response,
            &after_index["state"]["sqlite"],
        ) && after_index["state"]["sqlite"]["family_constellations"]["node"]
            .as_u64()
            .is_some_and(|count| count > 0)
            && after_index["state"]["sqlite"]["family_constellations"]["edge"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && after_index["state"]["base"]["row_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && after_index["state"]["graph"]["row_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && after_index["state"]["slot_s20_name_semantic"]["row_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && after_index["state"]["slot_s208_semantic_eligible_node_count"]["row_count"] == 0
            && after_index["state"]["ledger"]["row_count"]
                .as_u64()
                .is_some_and(|count| count > 0),
        "ISSUE_980_FAST_PHYSICAL_STATE_INVALID",
        json!({"request":request,"response":response,"state":after_index}),
    )?;

    let (config_integrity, config) = config_rows(&cache, &project)?;
    let weave_generation = verify_weave_generation_receipt(&config, &project)?;
    let persisted_kernel_generation = persisted_kernel_generation_receipt(&config, &project)?;
    let verification_before = edge_semantic_physical_state(
        &cache,
        &project,
        SemanticProjectExpectation::FastUnavailableMode,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"fast_unavailable_read_only_verification",
            "phase":"before",
            "state":verification_before,
        }))?
    );
    let kernel_generation = verify_complete_kernel_generation(
        &cache,
        &project,
        &kernel_admission(),
        &persisted_kernel_generation,
    )?;
    let (vault, _) = open_vault(&cache, &project)?;
    let snapshot = vault.latest_seq();
    let semantic_coverage = verify_semantic_coverage(
        &vault,
        snapshot,
        &cache,
        &project,
        SemanticProjectExpectation::FastUnavailableMode,
    )?;
    drop(vault);
    let verification_after = edge_semantic_physical_state(
        &cache,
        &project,
        SemanticProjectExpectation::FastUnavailableMode,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"fast_unavailable_read_only_verification",
            "phase":"after",
            "state":verification_after,
        }))?
    );
    require(
        config_integrity == "ok"
            && verification_before == verification_after
            && semantic_coverage["graph_row"]["json"]["imported_vector"] == 0
            && kernel_generation["artifact"]["member_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && kernel_generation["s20_complete_graph_roster"]["graph_node_count"]
                == kernel_generation["s20_complete_graph_roster"]["physical_vector_count"]
            && kernel_generation["s20_complete_graph_roster"]["physical_vector_count"]
                .as_u64()
                .is_some_and(|count| count > 0),
        "ISSUE_980_FAST_UNAVAILABLE_KERNEL_OR_SEMANTIC_PROOF_INVALID",
        json!({
            "before":verification_before,
            "after":verification_after,
            "semantic_coverage":semantic_coverage,
            "kernel_generation":kernel_generation,
        }),
    )?;
    let fixture_after = fixture_source_state(&repo)?;
    require(
        fixture_after == fixture["source"],
        "ISSUE_980_FAST_FIXTURE_SOURCE_MUTATED",
        &fixture_after,
    )?;
    let execution = json!({
        "schema":"astrolabe.issue-980.fast-unavailable.execute.v1",
        "tree_sha":tree_sha,
        "driver_artifact":driver_artifact,
        "source_generation_sha256":source_generation,
        "project":project,
        "repo":repo,
        "cache":cache,
        "shipping_host":{
            "configured":shipping_host_state,
            "verified_worker":verified_worker,
            "verified_worker_identity":verified_worker_identity,
        },
        "source_of_truth":"real fast-mode CBM SQLite Project row and empty node_vectors/token_vectors tables; independently reopened Aster Graph/Base/S20/S208/Ledger rows; semantic-coverage witness and deep physical readback; composite Kernel current pointer/manifest/generation rows, universal panel-derived S20 roster, external query corpus, graph-routed report, and physical Ledger pairing",
        "fixture":fixture,
        "fixture_after":fixture_after,
        "before":before,
        "request":request,
        "response_raw":{
            "bytes":response_raw.len(),
            "sha256":sha256(response_raw.as_bytes()),
            "text":response_raw,
        },
        "response_envelope":response_envelope,
        "response":response,
        "transition":transition,
        "after_index":after_index,
        "weave_generation":weave_generation,
        "kernel_generation":kernel_generation,
        "semantic_coverage":semantic_coverage,
        "verification_before":verification_before,
        "verification_after":verification_after,
    });
    let persisted = write_new_readback(
        &payload.join("fast-semantic-execution.json"),
        &serde_json::to_vec_pretty(&execution)?,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event":"ISSUE_980_FAST_UNAVAILABLE_EXECUTE_COMPLETE",
            "receipt":persisted,
            "project":execution["project"],
            "semantic_state":execution["after_index"]["state"]["sqlite"]["project"]["semantic_state"],
            "semantic_eligible_node_count":execution["after_index"]["state"]["sqlite"]["project"]["semantic_eligible_node_count"],
            "cbm_node_vectors":execution["after_index"]["state"]["sqlite"]["family_constellations"]["node_vector"],
            "universal_s20_vectors":execution["kernel_generation"]["s20_complete_graph_roster"]["physical_vector_count"],
            "kernel_generation_id":execution["kernel_generation"]["generation_id"],
            "state_sha256":execution["verification_after"]["sha256"],
        }))?
    );
    Ok(())
}

fn fast_semantic_readback(payload: PathBuf) -> AnyResult<()> {
    let execution_path = payload.join("fast-semantic-execution.json");
    let execution_bytes = fs::read(&execution_path)?;
    let execution: Value = serde_json::from_slice(&execution_bytes)?;
    require(
        execution["schema"] == "astrolabe.issue-980.fast-unavailable.execute.v1",
        "ISSUE_980_FAST_EXECUTION_SCHEMA_INVALID",
        &execution["schema"],
    )?;
    let repo = PathBuf::from(
        execution["repo"]
            .as_str()
            .ok_or("ISSUE_980_FAST_REPO_MISSING")?,
    );
    let cache = PathBuf::from(
        execution["cache"]
            .as_str()
            .ok_or("ISSUE_980_FAST_CACHE_MISSING")?,
    );
    let project = execution["project"]
        .as_str()
        .ok_or("ISSUE_980_FAST_PROJECT_MISSING")?;
    require(
        repo == payload.join("real-fast-rust-repo")
            && cache == payload.join("real-fast-cache")
            && fixture_source_state(&repo)? == execution["fixture"]["source"],
        "ISSUE_980_FAST_READBACK_BINDING_MISMATCH",
        json!({"payload":payload,"repo":repo,"cache":cache}),
    )?;
    require(
        set_cbm_cache_dir(&cache)? == cache,
        "ISSUE_980_FAST_READBACK_CACHE_BINDING_MISMATCH",
        cache.display(),
    )?;
    let source_generation = current_source_generation_sha256()?;
    let (shipping_host, shipping_host_state) = shipping_astrolabe_executable()?;
    let shipping_sha256 = shipping_host_state["sha256"]
        .as_str()
        .ok_or("ISSUE_980_FAST_READBACK_SHIPPING_SHA256_MISSING")?;
    let readback_worker = initialize_cbm_host_process_with_verified_worker(
        &shipping_host,
        shipping_sha256,
        &source_generation,
    )?;
    let readback_worker_identity =
        validate_verified_worker_binding(&readback_worker, &shipping_host)?;
    let execute_worker: CbmVerifiedWorkerBinding =
        serde_json::from_value(execution["shipping_host"]["verified_worker"].clone())?;
    require(
        shipping_host_state == execution["shipping_host"]["configured"]
            && verified_worker_stable_fields_equal(&execute_worker, &readback_worker)
            && execute_worker.capability.challenge != readback_worker.capability.challenge
            && readback_worker_identity
                == validate_verified_worker_binding(&execute_worker, &shipping_host)?,
        "ISSUE_980_FAST_READBACK_WORKER_BINDING_MISMATCH",
        json!({"execute":execute_worker,"readback":readback_worker}),
    )?;

    let before = edge_semantic_physical_state(
        &cache,
        project,
        SemanticProjectExpectation::FastUnavailableMode,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"fast_unavailable_separate_process_readback",
            "phase":"before",
            "state":before,
        }))?
    );
    let (config_integrity, config) = config_rows(&cache, project)?;
    let transition_key = execution["transition"]["key"]
        .as_str()
        .ok_or("ISSUE_980_FAST_TRANSITION_KEY_MISSING")?;
    let transition_raw = execution["transition"]["raw"]
        .as_str()
        .ok_or("ISSUE_980_FAST_TRANSITION_RAW_MISSING")?;
    let persisted_kernel_generation = persisted_kernel_generation_receipt(&config, project)?;
    let kernel_generation = verify_complete_kernel_generation(
        &cache,
        project,
        &kernel_admission(),
        &persisted_kernel_generation,
    )?;
    let weave_generation = verify_weave_generation_receipt(&config, project)?;
    let (vault, _) = open_vault(&cache, project)?;
    let semantic_coverage = verify_semantic_coverage(
        &vault,
        vault.latest_seq(),
        &cache,
        project,
        SemanticProjectExpectation::FastUnavailableMode,
    )?;
    drop(vault);
    let after = edge_semantic_physical_state(
        &cache,
        project,
        SemanticProjectExpectation::FastUnavailableMode,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"fast_unavailable_separate_process_readback",
            "phase":"after",
            "state":after,
        }))?
    );
    require(
        config_integrity == "ok"
            && config.get(transition_key).map(String::as_str) == Some(transition_raw)
            && before == after
            && before == execution["verification_after"]
            && kernel_generation == execution["kernel_generation"]
            && weave_generation == execution["weave_generation"]
            && semantic_coverage == execution["semantic_coverage"]
            && fast_unavailable_semantic_response_matches_sqlite(
                &execution["response"],
                &before["state"]["sqlite"],
            ),
        "ISSUE_980_FAST_SEPARATE_READBACK_MISMATCH",
        json!({
            "before":before,
            "after":after,
            "kernel_generation":kernel_generation,
            "semantic_coverage":semantic_coverage,
        }),
    )?;
    let report = json!({
        "schema":"astrolabe.issue-980.fast-unavailable.readback.v1",
        "execution_file":{
            "path":execution_path,
            "bytes":execution_bytes.len(),
            "sha256":sha256(&execution_bytes),
        },
        "project":project,
        "source_of_truth":execution["source_of_truth"],
        "worker":{
            "binding":readback_worker,
            "physical_identity":readback_worker_identity,
            "artifact":shipping_host_state,
        },
        "before":before,
        "after":after,
        "weave_generation":weave_generation,
        "kernel_generation":kernel_generation,
        "semantic_coverage":semantic_coverage,
        "separate_process_physical_readback":true,
        "no_state_change":true,
    });
    let persisted = write_new_readback(
        &payload.join("fast-semantic-readback.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event":"ISSUE_980_FAST_UNAVAILABLE_READBACK_COMPLETE",
            "receipt":persisted,
            "project":project,
            "semantic_state":report["after"]["state"]["sqlite"]["project"]["semantic_state"],
            "semantic_eligible_node_count":report["after"]["state"]["sqlite"]["project"]["semantic_eligible_node_count"],
            "cbm_node_vectors":report["after"]["state"]["sqlite"]["family_constellations"]["node_vector"],
            "universal_s20_vectors":report["kernel_generation"]["s20_complete_graph_roster"]["physical_vector_count"],
            "state_sha256":report["after"]["sha256"],
        }))?
    );
    Ok(())
}

fn unavailable_corpus_edge(payload: PathBuf) -> AnyResult<()> {
    require(
        !payload.try_exists()?,
        "ISSUE_980_UNAVAILABLE_CORPUS_PAYLOAD_PREEXISTS",
        payload.display(),
    )?;
    fs::create_dir_all(&payload)?;
    let tree_sha = canonical_head()?;
    let driver_artifact = current_driver_artifact_state()?;
    let source_generation = current_source_generation_sha256()?;
    require(
        source_generation == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256,
        "ISSUE_980_UNAVAILABLE_CORPUS_COMPILED_SOURCE_GENERATION_DRIFT",
        &source_generation,
    )?;
    let repo = payload.join("real-unavailable-corpus-rust-repo");
    let cache = payload.join("real-unavailable-corpus-cache");
    let fixture = write_unavailable_corpus_fixture(&repo)?;
    fs::create_dir(&cache)?;
    require(
        set_cbm_cache_dir(&cache)? == cache,
        "ISSUE_980_UNAVAILABLE_CORPUS_CACHE_BINDING_MISMATCH",
        cache.display(),
    )?;
    let (shipping_host, shipping_host_state) = shipping_astrolabe_executable()?;
    require(
        configured_cbm_host_binary_path()?.is_none() && !supervisor_should_wrap(),
        "ISSUE_980_UNAVAILABLE_CORPUS_PROCESS_PRESTATE_INVALID",
        "a fresh unavailable-corpus-edge process already had a worker binding",
    )?;
    let shipping_sha256 = shipping_host_state["sha256"]
        .as_str()
        .ok_or("ISSUE_980_UNAVAILABLE_CORPUS_SHIPPING_SHA256_MISSING")?;
    let verified_worker = initialize_cbm_host_process_with_verified_worker(
        &shipping_host,
        shipping_sha256,
        &source_generation,
    )?;
    let verified_worker_identity =
        validate_verified_worker_binding(&verified_worker, &shipping_host)?;
    let runner = CbmToolRunner::new_default()?;
    let project = cbm_project_name_from_path(repo.to_str().ok_or("repo path is not UTF-8")?)?;
    let before = binding_edge_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"moderate_unavailable_corpus",
            "phase":"before",
            "state":before,
        }))?
    );
    require(
        before["config"]["exists"] == Value::Bool(false)
            && binding_project_artifacts_absent(&before),
        "ISSUE_980_UNAVAILABLE_CORPUS_PRESTATE_NOT_PRISTINE",
        &before,
    )?;

    let request = unavailable_corpus_index_request(&repo);
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"moderate_unavailable_corpus",
            "phase":"action",
            "tool":"index_repository",
            "request":request,
        }))?
    );
    let (response_raw, response_envelope, response) =
        call_tool_with_raw(&runner, "index_repository", &request)?;
    require(
        response_envelope["isError"] != Value::Bool(true)
            && response["project"] == Value::String(project.clone()),
        "ISSUE_980_UNAVAILABLE_CORPUS_INDEX_FAILED",
        &response,
    )?;
    let canonical_repo = repo.canonicalize()?;
    let canonical_db = cache.join(format!("{project}.db"));
    let transition = read_completed_transition(ReadCompletedTransitionRequest {
        cache: &cache,
        project: &project,
        canonical_root: &canonical_repo,
        canonical_db: &canonical_db,
        response_raw: &response_raw,
        response_envelope: &response_envelope,
        response_payload: &response,
        binding: &verified_worker,
        observation_path: None,
    })?;
    let after_index = edge_semantic_physical_state(
        &cache,
        &project,
        SemanticProjectExpectation::ModerateUnavailableCorpus,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"moderate_unavailable_corpus",
            "phase":"after",
            "state":after_index,
        }))?
    );
    require(
        unavailable_corpus_semantic_response_matches_sqlite(
            &response,
            &after_index["state"]["sqlite"],
        ) && after_index["state"]["sqlite"]["family_constellations"]["node"]
            .as_u64()
            .is_some_and(|count| count > 0)
            && after_index["state"]["sqlite"]["family_constellations"]["edge"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && after_index["state"]["base"]["row_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && after_index["state"]["graph"]["row_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && after_index["state"]["kernel"]["row_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && after_index["state"]["slot_s20_name_semantic"]["row_count"]
                .as_u64()
                .is_some_and(|count| count > 0)
            && after_index["state"]["slot_s208_semantic_eligible_node_count"]["row_count"] == 1
            && after_index["state"]["ledger"]["row_count"]
                .as_u64()
                .is_some_and(|count| count > 0),
        "ISSUE_980_UNAVAILABLE_CORPUS_PHYSICAL_STATE_INVALID",
        json!({"request":request,"response":response,"state":after_index}),
    )?;

    let (config_integrity, config) = config_rows(&cache, &project)?;
    let weave_generation = verify_weave_generation_receipt(&config, &project)?;
    let persisted_kernel_generation = persisted_kernel_generation_receipt(&config, &project)?;
    let verification_before = edge_semantic_physical_state(
        &cache,
        &project,
        SemanticProjectExpectation::ModerateUnavailableCorpus,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"moderate_unavailable_corpus_read_only_verification",
            "phase":"before",
            "state":verification_before,
        }))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"moderate_unavailable_corpus_read_only_verification",
            "phase":"action",
            "operation":"reopen SQLite, Aster semantic coverage, S208, current Kernel generation, and Ledger",
            "project":project,
        }))?
    );
    let kernel_generation =
        verify_edge_kernel_generation(&cache, &project, &persisted_kernel_generation)?;
    let (vault, _) = open_vault(&cache, &project)?;
    let snapshot = vault.latest_seq();
    let semantic_coverage = verify_semantic_coverage(
        &vault,
        snapshot,
        &cache,
        &project,
        SemanticProjectExpectation::ModerateUnavailableCorpus,
    )?;
    drop(vault);
    let verification_after = edge_semantic_physical_state(
        &cache,
        &project,
        SemanticProjectExpectation::ModerateUnavailableCorpus,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"moderate_unavailable_corpus_read_only_verification",
            "phase":"after",
            "state":verification_after,
        }))?
    );
    require(
        config_integrity == "ok"
            && verification_before == verification_after
            && semantic_coverage["graph_row"]["json"]["imported_vector"] == 0
            && semantic_coverage["project_slot_point_reads"]["S208"]["status"] == "present"
            && semantic_coverage["project_slot_point_reads"]["S208"]["sqlite_value"] == 1
            && kernel_generation["query_corpus"]["params"]
                == unavailable_corpus_kernel_admission()["params"]
            && kernel_generation["query_corpus"]["queries"]
                .as_array()
                .is_some_and(|queries| queries.len() == 2),
        "ISSUE_980_UNAVAILABLE_CORPUS_READBACK_PROOF_INVALID",
        json!({
            "before":verification_before,
            "after":verification_after,
            "semantic_coverage":semantic_coverage,
            "kernel_generation":kernel_generation,
        }),
    )?;
    let fixture_after = fixture_source_state(&repo)?;
    require(
        fixture_after == fixture["source"],
        "ISSUE_980_UNAVAILABLE_CORPUS_FIXTURE_SOURCE_MUTATED",
        &fixture_after,
    )?;
    let execution = json!({
        "schema":"astrolabe.issue-980.unavailable-corpus.execute.v1",
        "tree_sha":tree_sha,
        "driver_artifact":driver_artifact,
        "source_generation_sha256":source_generation,
        "project":project,
        "repo":repo,
        "cache":cache,
        "shipping_host":{
            "configured":shipping_host_state,
            "verified_worker":verified_worker,
            "verified_worker_identity":verified_worker_identity,
        },
        "source_of_truth":"real moderate-mode CBM SQLite Project row with semantic_state=unavailable_corpus and eligible_node_count=1; physically empty node_vectors/token_vectors; independently reopened Aster Graph/Base/Kernel/S20/S208/Ledger rows; exact S208 panel encoding and semantic-coverage witness; physical current Kernel manifest/pointer/Ledger generation",
        "fixture":fixture,
        "fixture_after":fixture_after,
        "before":before,
        "request":request,
        "response_raw":{
            "bytes":response_raw.len(),
            "sha256":sha256(response_raw.as_bytes()),
            "text":response_raw,
        },
        "response_envelope":response_envelope,
        "response":response,
        "transition":transition,
        "after_index":after_index,
        "weave_generation":weave_generation,
        "persisted_kernel_generation":persisted_kernel_generation,
        "kernel_generation":kernel_generation,
        "semantic_coverage":semantic_coverage,
        "verification_before":verification_before,
        "verification_after":verification_after,
    });
    let persisted = write_new_readback(
        &payload.join("unavailable-corpus-execution.json"),
        &serde_json::to_vec_pretty(&execution)?,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event":"ISSUE_980_UNAVAILABLE_CORPUS_EXECUTE_COMPLETE",
            "receipt":persisted,
            "project":execution["project"],
            "semantic_state":execution["after_index"]["state"]["sqlite"]["project"]["semantic_state"],
            "semantic_eligible_node_count":execution["after_index"]["state"]["sqlite"]["project"]["semantic_eligible_node_count"],
            "cbm_node_vectors":execution["after_index"]["state"]["sqlite"]["family_constellations"]["node_vector"],
            "s208_rows":execution["after_index"]["state"]["slot_s208_semantic_eligible_node_count"]["row_count"],
            "kernel_generation_id":execution["kernel_generation"]["generation_id"],
            "state_sha256":execution["verification_after"]["sha256"],
        }))?
    );
    Ok(())
}

fn unavailable_corpus_readback(payload: PathBuf) -> AnyResult<()> {
    let execution_path = payload.join("unavailable-corpus-execution.json");
    let execution_bytes = fs::read(&execution_path)?;
    let execution: Value = serde_json::from_slice(&execution_bytes)?;
    require(
        execution["schema"] == "astrolabe.issue-980.unavailable-corpus.execute.v1",
        "ISSUE_980_UNAVAILABLE_CORPUS_EXECUTION_SCHEMA_INVALID",
        &execution["schema"],
    )?;
    let repo = PathBuf::from(
        execution["repo"]
            .as_str()
            .ok_or("ISSUE_980_UNAVAILABLE_CORPUS_REPO_MISSING")?,
    );
    let cache = PathBuf::from(
        execution["cache"]
            .as_str()
            .ok_or("ISSUE_980_UNAVAILABLE_CORPUS_CACHE_MISSING")?,
    );
    let project = execution["project"]
        .as_str()
        .ok_or("ISSUE_980_UNAVAILABLE_CORPUS_PROJECT_MISSING")?;
    require(
        repo == payload.join("real-unavailable-corpus-rust-repo")
            && cache == payload.join("real-unavailable-corpus-cache")
            && fixture_source_state(&repo)? == execution["fixture"]["source"],
        "ISSUE_980_UNAVAILABLE_CORPUS_READBACK_BINDING_MISMATCH",
        json!({"payload":payload,"repo":repo,"cache":cache}),
    )?;
    require(
        set_cbm_cache_dir(&cache)? == cache,
        "ISSUE_980_UNAVAILABLE_CORPUS_READBACK_CACHE_BINDING_MISMATCH",
        cache.display(),
    )?;
    require(
        configured_cbm_host_binary_path()?.is_none() && !supervisor_should_wrap(),
        "ISSUE_980_UNAVAILABLE_CORPUS_READBACK_PROCESS_PRESTATE_INVALID",
        "a fresh unavailable-corpus-readback process already had a worker binding",
    )?;
    let source_generation = current_source_generation_sha256()?;
    let tree_sha = canonical_head()?;
    let driver_artifact = current_driver_artifact_state()?;
    require(
        execution["tree_sha"] == Value::String(tree_sha)
            && execution["driver_artifact"] == driver_artifact
            && execution["source_generation_sha256"] == Value::String(source_generation.clone())
            && source_generation == astrolabe_server::ASTRO_WORKER_SOURCE_GENERATION_SHA256,
        "ISSUE_980_UNAVAILABLE_CORPUS_READBACK_SOURCE_BINDING_MISMATCH",
        json!({
            "execution_tree": execution["tree_sha"],
            "execution_source_generation": execution["source_generation_sha256"],
            "readback_source_generation": source_generation,
        }),
    )?;
    let (shipping_host, shipping_host_state) = shipping_astrolabe_executable()?;
    let shipping_sha256 = shipping_host_state["sha256"]
        .as_str()
        .ok_or("ISSUE_980_UNAVAILABLE_CORPUS_READBACK_SHIPPING_SHA256_MISSING")?;
    let readback_worker = initialize_cbm_host_process_with_verified_worker(
        &shipping_host,
        shipping_sha256,
        &source_generation,
    )?;
    let readback_worker_identity =
        validate_verified_worker_binding(&readback_worker, &shipping_host)?;
    let execute_worker: CbmVerifiedWorkerBinding =
        serde_json::from_value(execution["shipping_host"]["verified_worker"].clone())?;
    require(
        shipping_host_state == execution["shipping_host"]["configured"]
            && verified_worker_stable_fields_equal(&execute_worker, &readback_worker)
            && execute_worker.capability.challenge != readback_worker.capability.challenge
            && readback_worker_identity
                == validate_verified_worker_binding(&execute_worker, &shipping_host)?,
        "ISSUE_980_UNAVAILABLE_CORPUS_READBACK_WORKER_BINDING_MISMATCH",
        json!({"execute":execute_worker,"readback":readback_worker}),
    )?;

    let before = edge_semantic_physical_state(
        &cache,
        project,
        SemanticProjectExpectation::ModerateUnavailableCorpus,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"moderate_unavailable_corpus_separate_process_readback",
            "phase":"before",
            "state":before,
        }))?
    );
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"moderate_unavailable_corpus_separate_process_readback",
            "phase":"action",
            "operation":"separately reopen persisted SQLite, Aster semantic coverage, S208, current Kernel generation, and Ledger",
            "execution_path":execution_path,
            "execution_bytes":execution_bytes.len(),
            "execution_sha256":sha256(&execution_bytes),
        }))?
    );
    let (config_integrity, config) = config_rows(&cache, project)?;
    let transition_key = execution["transition"]["key"]
        .as_str()
        .ok_or("ISSUE_980_UNAVAILABLE_CORPUS_TRANSITION_KEY_MISSING")?;
    let transition_raw = execution["transition"]["raw"]
        .as_str()
        .ok_or("ISSUE_980_UNAVAILABLE_CORPUS_TRANSITION_RAW_MISSING")?;
    let persisted_kernel_generation = persisted_kernel_generation_receipt(&config, project)?;
    let kernel_generation =
        verify_edge_kernel_generation(&cache, project, &persisted_kernel_generation)?;
    let weave_generation = verify_weave_generation_receipt(&config, project)?;
    let (vault, _) = open_vault(&cache, project)?;
    let semantic_coverage = verify_semantic_coverage(
        &vault,
        vault.latest_seq(),
        &cache,
        project,
        SemanticProjectExpectation::ModerateUnavailableCorpus,
    )?;
    drop(vault);
    let after = edge_semantic_physical_state(
        &cache,
        project,
        SemanticProjectExpectation::ModerateUnavailableCorpus,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case":"moderate_unavailable_corpus_separate_process_readback",
            "phase":"after",
            "state":after,
        }))?
    );
    require(
        config_integrity == "ok"
            && config.get(transition_key).map(String::as_str) == Some(transition_raw)
            && before == after
            && before == execution["verification_after"]
            && persisted_kernel_generation == execution["persisted_kernel_generation"]
            && kernel_generation == execution["kernel_generation"]
            && weave_generation == execution["weave_generation"]
            && semantic_coverage == execution["semantic_coverage"]
            && unavailable_corpus_semantic_response_matches_sqlite(
                &execution["response"],
                &before["state"]["sqlite"],
            )
            && before["state"]["slot_s208_semantic_eligible_node_count"]["row_count"] == 1,
        "ISSUE_980_UNAVAILABLE_CORPUS_SEPARATE_READBACK_MISMATCH",
        json!({
            "before":before,
            "after":after,
            "kernel_generation":kernel_generation,
            "semantic_coverage":semantic_coverage,
        }),
    )?;
    let report = json!({
        "schema":"astrolabe.issue-980.unavailable-corpus.readback.v1",
        "execution_file":{
            "path":execution_path,
            "bytes":execution_bytes.len(),
            "sha256":sha256(&execution_bytes),
        },
        "project":project,
        "source_of_truth":execution["source_of_truth"],
        "worker":{
            "binding":readback_worker,
            "physical_identity":readback_worker_identity,
            "artifact":shipping_host_state,
        },
        "before":before,
        "after":after,
        "weave_generation":weave_generation,
        "persisted_kernel_generation":persisted_kernel_generation,
        "kernel_generation":kernel_generation,
        "semantic_coverage":semantic_coverage,
        "separate_process_physical_readback":true,
        "no_state_change":true,
    });
    let persisted = write_new_readback(
        &payload.join("unavailable-corpus-readback.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "event":"ISSUE_980_UNAVAILABLE_CORPUS_READBACK_COMPLETE",
            "receipt":persisted,
            "project":project,
            "semantic_state":report["after"]["state"]["sqlite"]["project"]["semantic_state"],
            "semantic_eligible_node_count":report["after"]["state"]["sqlite"]["project"]["semantic_eligible_node_count"],
            "cbm_node_vectors":report["after"]["state"]["sqlite"]["family_constellations"]["node_vector"],
            "s208_rows":report["after"]["state"]["slot_s208_semantic_eligible_node_count"]["row_count"],
            "kernel_generation_id":report["kernel_generation"]["generation_id"],
            "state_sha256":report["after"]["sha256"],
        }))?
    );
    Ok(())
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let mode = args
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| {
            fail(
                "ISSUE_1116_1119_MODE_REQUIRED",
                "mode is required",
                "pass binding-edges, binding-readback, staged-abort, staged-abort-readback, execute, association-publish, transport, readback, fast-semantic-edge, fast-semantic-readback, unavailable-corpus-edge, or unavailable-corpus-readback followed by one payload path",
            )
        });
    let payload = args.next().map(PathBuf::from).unwrap_or_else(|| {
        fail(
            "ISSUE_1116_1119_PAYLOAD_REQUIRED",
            "payload path is required",
            "pass one absent binding-edges/execute/staged-abort/fast-semantic-edge/unavailable-corpus-edge path or the exact prior payload for binding-readback/association-publish/transport/readback/staged-abort-readback/fast-semantic-readback/unavailable-corpus-readback",
        )
    });
    if args.next().is_some() {
        fail(
            "ISSUE_1116_1119_ARGUMENT_UNKNOWN",
            "unexpected extra argument",
            "pass exactly one mode and one payload path",
        );
    }
    let result = match mode.as_str() {
        "binding-edges" => binding_edges(payload),
        "binding-readback" => binding_readback(payload),
        "staged-abort" => staged_abort(payload),
        "staged-abort-readback" => staged_abort_readback(payload),
        "execute" => execute(payload),
        "association-publish" => association_publish(payload),
        "transport" => transport(payload),
        "readback" => readback(payload),
        "fast-semantic-edge" => fast_semantic_edge(payload),
        "fast-semantic-readback" => fast_semantic_readback(payload),
        "unavailable-corpus-edge" => unavailable_corpus_edge(payload),
        "unavailable-corpus-readback" => unavailable_corpus_readback(payload),
        other => Err(format!("unsupported mode {other:?}").into()),
    };
    if let Err(error) = result {
        fail(
            "ISSUE_1116_1119_FSV_FAILED",
            error,
            "preserve the payload and inspect the first failed physical invariant; do not substitute another corpus or weaken the assertion",
        );
    }
}
