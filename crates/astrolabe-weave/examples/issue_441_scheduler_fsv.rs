//! Manual Full State Verification for #441/#1103.
//!
//! This is an executable reality probe, not a test. `run` resolves the real
//! runtime knobs before creating any state, plans and persists SIM_PROFILE rows
//! through the production Weave/Aster path, drops the writer, then reopens only
//! the Graph and Ledger column families read-only. `inspect` is a separate
//! physical read of the already-persisted vault.

use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use astrolabe_weave::{
    SimilarityFamily, SimilarityNode, SimilarityPlannerConfig, persist_similarity_family_run,
    plan_similarity_family_run, read_similarity_edge_rows, scan_similarity_physical_state,
};
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{FixedClock, SlotVector, VaultId, VaultStore};
use calyx_ledger::decode as decode_ledger;
use serde_json::{Value, json};

const DIM: u32 = 24;
const THRESHOLD: f32 = 0.99;
const MAX_PAIR_COUNT: usize = 4_096;
const FIXED_TIME_MS: u64 = 1_700_000_000_000;
const VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const VAULT_SALT: &[u8] = b"issue-441-1103-scheduler-fsv-v1";
const ACTION_FILE: &str = "action.json";

type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

fn bytes_blake3(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn hex_lower(bytes: &[u8]) -> AnyResult<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let capacity = bytes
        .len()
        .checked_mul(2)
        .ok_or("hex output capacity exceeded usize")?;
    let mut out = String::new();
    out.try_reserve_exact(capacity)?;
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(out)
}

fn update_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn write_synced(path: &Path, bytes: &[u8]) -> AnyResult<()> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn symbol_id(index: usize) -> String {
    format!("issue-441-symbol-{index:05}")
}

fn qualified_name(index: usize) -> String {
    format!("issue_441::symbol_{index:05}")
}

fn vector_for_pair(pair: usize, pair_count: usize) -> Vec<f32> {
    let significant_bits = usize::BITS as usize - (pair_count - 1).leading_zeros() as usize;
    let significant_bits = significant_bits.max(1);
    (0..DIM as usize)
        .map(|coordinate| {
            if (pair >> (coordinate % significant_bits)) & 1 == 0 {
                -1.0
            } else {
                1.0
            }
        })
        .collect()
}

fn synthetic_nodes(pair_count: usize) -> AnyResult<Vec<SimilarityNode>> {
    if pair_count == 0 || pair_count > MAX_PAIR_COUNT {
        return Err(
            format!("pair_count must be in [1..={MAX_PAIR_COUNT}], observed {pair_count}").into(),
        );
    }
    let node_count = pair_count
        .checked_mul(2)
        .ok_or("synthetic node-count overflow")?;
    let mut nodes = Vec::new();
    nodes.try_reserve_exact(node_count)?;
    for pair in 0..pair_count {
        let vector = vector_for_pair(pair, pair_count);
        for member in 0..2 {
            let index = pair * 2 + member;
            nodes.push(
                SimilarityNode::new(symbol_id(index), qualified_name(index)).with_slot(
                    SimilarityFamily::Profile.slot(),
                    SlotVector::Dense {
                        dim: DIM,
                        data: vector.clone(),
                    },
                ),
            );
        }
    }
    Ok(nodes)
}

fn parse_pair_count(value: Option<&Value>) -> AnyResult<usize> {
    let raw = value
        .and_then(Value::as_u64)
        .ok_or("action receipt has no integer pair_count")?;
    let pair_count = usize::try_from(raw)?;
    if pair_count == 0 || pair_count > MAX_PAIR_COUNT {
        return Err(format!(
            "action receipt pair_count must be in [1..={MAX_PAIR_COUNT}], observed {pair_count}"
        )
        .into());
    }
    Ok(pair_count)
}

fn validate_expected_rows(
    rows: &[astrolabe_weave::PersistedSimilarityEdgeRow],
    pair_count: usize,
) -> AnyResult<()> {
    if rows.len() != pair_count {
        return Err(format!(
            "expected {pair_count} physical SIM_PROFILE rows, observed {}",
            rows.len()
        )
        .into());
    }
    for (pair, persisted) in rows.iter().enumerate() {
        let source_index = pair * 2;
        let target_index = source_index + 1;
        let row = &persisted.row;
        if row.family != SimilarityFamily::Profile.wire_name()
            || row.source_id != symbol_id(source_index)
            || row.target_id != symbol_id(target_index)
            || row.source_qn != qualified_name(source_index)
            || row.target_qn != qualified_name(target_index)
            || row.slot != SimilarityFamily::Profile.slot().get()
            || row.threshold_bits != THRESHOLD.to_bits()
            || !(THRESHOLD..=1.000_001).contains(&row.weight())
        {
            return Err(format!(
                "physical row {pair} differs from its known paired-vector outcome: {:?}",
                row
            )
            .into());
        }
    }
    Ok(())
}

fn row_sample(
    rows: &[astrolabe_weave::PersistedSimilarityEdgeRow],
    take_from_start: bool,
) -> Vec<Value> {
    let selected = if take_from_start {
        &rows[..rows.len().min(3)]
    } else {
        &rows[rows.len() - rows.len().min(3)..]
    };
    selected
        .iter()
        .map(|persisted| {
            json!({
                "key_blake3": bytes_blake3(&persisted.key),
                "source_id": persisted.row.source_id,
                "target_id": persisted.row.target_id,
                "weight_bits": format!("{:08x}", persisted.row.weight_bits),
                "threshold_bits": format!("{:08x}", persisted.row.threshold_bits),
            })
        })
        .collect()
}

fn read_physical_state(payload: &Path, pair_count: usize) -> AnyResult<Value> {
    let vault_dir = payload.join("vault");
    let vault_id = VAULT_ID.parse::<VaultId>()?;
    let options = VaultOptions {
        restore_mvcc_rows: false,
        restore_ledger_hook: false,
        read_only: true,
        selected_cfs: Some(vec![ColumnFamily::Graph, ColumnFamily::Ledger]),
        ..VaultOptions::default()
    };
    let vault = AsterVault::open_with_clock(
        &vault_dir,
        vault_id,
        VAULT_SALT.to_vec(),
        options,
        FixedClock::new(FIXED_TIME_MS),
    )?;

    let rows = read_similarity_edge_rows(&vault)?;
    validate_expected_rows(&rows, pair_count)?;
    let physical = scan_similarity_physical_state(&vault)?;
    if physical.rows_scanned != pair_count {
        return Err(format!(
            "bounded physical scan expected {pair_count} rows, observed {}",
            physical.rows_scanned
        )
        .into());
    }

    let chain = astrolabe_ingest::verify_chain(&vault)?;
    if !chain.is_intact() || chain.ledger_rows == 0 {
        return Err(
            format!("physical Ledger chain is not a non-empty intact chain: {chain:?}").into(),
        );
    }

    let snapshot = vault.snapshot();
    let ledger_rows = vault.scan_cf_at(snapshot, ColumnFamily::Ledger)?;
    let mut ledger_hasher = blake3::Hasher::new();
    let mut ledger_payloads = Vec::new();
    for (key, value) in &ledger_rows {
        update_len_prefixed(&mut ledger_hasher, key);
        update_len_prefixed(&mut ledger_hasher, value);
        let entry = decode_ledger(value)?;
        let payload_value: Value = serde_json::from_slice(&entry.payload)?;
        ledger_payloads.push(json!({
            "seq": entry.seq,
            "entry_hash": hex_lower(&entry.entry_hash)?,
            "payload": payload_value,
        }));
    }
    if !ledger_payloads.iter().any(|entry| {
        entry.pointer("/payload/schema").and_then(Value::as_str)
            == Some(astrolabe_weave::SIM_EDGE_LEDGER_SCHEMA)
    }) {
        return Err("physical Ledger CF has no SIM edge persistence payload".into());
    }

    Ok(json!({
        "source_of_truth": {
            "vault": vault_dir,
            "column_families": ["graph", "ledger"],
            "open_mode": "read_only_selected_cfs_no_mvcc_restore",
        },
        "snapshot_seq": snapshot,
        "graph": physical,
        "all_expected_rows_validated": rows.len(),
        "first_rows": row_sample(&rows, true),
        "last_rows": row_sample(&rows, false),
        "ledger": {
            "chain": chain,
            "physical_rows": ledger_rows.len(),
            "physical_rows_blake3": ledger_hasher.finalize().to_hex().to_string(),
            "decoded_payloads": ledger_payloads,
        },
    }))
}

fn run_mode(payload: &Path, pair_count: usize) -> AnyResult<Value> {
    let before = json!({
        "phase": "before",
        "payload": payload,
        "payload_exists": payload.exists(),
    });
    println!("{}", serde_json::to_string(&before)?);
    std::io::stdout().flush()?;
    if payload.exists() {
        return Err(format!("payload path already exists: {}", payload.display()).into());
    }

    let mut config = match SimilarityPlannerConfig::resolve_runtime() {
        Ok(config) => config,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::to_string(&json!({
                    "phase": "configuration_refusal",
                    "error": error,
                    "state_after": {
                        "payload": payload,
                        "payload_exists": payload.exists(),
                    },
                }))?
            );
            return Err("runtime configuration refused before state creation".into());
        }
    };
    if config.runtime.dense_ann_strategy()
        != astrolabe_weave::knobs::WEAVE_DENSE_ANN_STRATEGY_EXACT_KNN
    {
        return Err(format!(
            "manual scheduler FSV requires exact strategy ordinal {}, observed {}",
            astrolabe_weave::knobs::WEAVE_DENSE_ANN_STRATEGY_EXACT_KNN,
            config.runtime.dense_ann_strategy()
        )
        .into());
    }
    config.per_node_cap = 4;
    config.thresholds.sim_profile_min_score = THRESHOLD;

    let nodes = synthetic_nodes(pair_count)?;
    fs::create_dir_all(payload)?;
    let vault_dir = payload.join("vault");
    let run_dir = payload.join("run");
    let vault_id = VAULT_ID.parse::<VaultId>()?;
    let vault = AsterVault::new_durable_with_clock(
        &vault_dir,
        vault_id,
        VAULT_SALT.to_vec(),
        VaultOptions::default(),
        FixedClock::new(FIXED_TIME_MS),
    )?;
    let plan = plan_similarity_family_run(
        &vault,
        &run_dir,
        format!("issue=441;pair_count={pair_count};known_identical_pairs=true"),
        &nodes,
        SimilarityFamily::Profile,
        &config,
    )?;
    if plan.edge_count() != pair_count || !plan.stream_report().skips.vector_skips.is_empty() {
        return Err(format!(
            "known paired-vector plan expected {pair_count} edges and zero vector skips, observed edges={} skips={}",
            plan.edge_count(),
            plan.stream_report().skips.vector_skips.len()
        )
        .into());
    }
    let scheduler_telemetry = plan.stream_report().scheduler_telemetry.clone();
    let stream_workers = plan.stream_report().workers_requested;
    let mut global_dump_hasher = blake3::Hasher::new();
    let persisted = persist_similarity_family_run(
        &vault,
        plan,
        &mut global_dump_hasher,
        "issue-441-scheduler-fsv",
    )?;
    if persisted.edge_count != pair_count
        || persisted.rows_written != pair_count
        || persisted.rows_tombstoned != 0
        || persisted.edge_dump_hash != global_dump_hasher.finalize().to_hex().to_string()
    {
        return Err(format!("unexpected persistence receipt: {persisted:?}").into());
    }
    vault.flush()?;

    let action = json!({
        "schema": "astrolabe.issue_441_1103.scheduler_fsv.v1",
        "pair_count": pair_count,
        "node_count": nodes.len(),
        "known_outcome": {
            "edge_count": pair_count,
            "edge_shape": "each even source ordinal is connected only to its identical odd partner",
            "profile_dim": DIM,
            "threshold_bits": format!("{:08x}", THRESHOLD.to_bits()),
        },
        "resolved_config": config.runtime,
        "stream_workers": stream_workers,
        "scheduler_telemetry": scheduler_telemetry,
        "persist": {
            "edge_count": persisted.edge_count,
            "rows_written": persisted.rows_written,
            "rows_unchanged": persisted.rows_unchanged,
            "rows_tombstoned": persisted.rows_tombstoned,
            "edge_dump_hash": persisted.edge_dump_hash,
            "ledger_refs": persisted.ledger_refs.len(),
            "fsv_witnesses": persisted.fsv.len(),
            "run": persisted.run,
        },
    });
    let action_bytes = serde_json::to_vec_pretty(&action)?;
    write_synced(&payload.join(ACTION_FILE), &action_bytes)?;
    drop(vault);

    let readback = read_physical_state(payload, pair_count)?;
    let action_readback = fs::read(payload.join(ACTION_FILE))?;
    if action_readback != action_bytes {
        return Err("action receipt changed on immediate independent readback".into());
    }
    if readback
        .pointer("/graph/edge_dump_hash")
        .and_then(Value::as_str)
        != action
            .pointer("/persist/edge_dump_hash")
            .and_then(Value::as_str)
    {
        return Err("physical Graph edge digest differs from the persistence receipt".into());
    }

    Ok(json!({
        "phase": "after_independent_reopen",
        "action_file": {
            "path": payload.join(ACTION_FILE),
            "bytes": action_readback.len(),
            "blake3": bytes_blake3(&action_readback),
            "byte_identical_to_written_receipt": true,
        },
        "action": action,
        "physical_readback": readback,
    }))
}

fn inspect_mode(payload: &Path) -> AnyResult<Value> {
    let action_path = payload.join(ACTION_FILE);
    let action_bytes = fs::read(&action_path)?;
    let action: Value = serde_json::from_slice(&action_bytes)?;
    if action.get("schema").and_then(Value::as_str)
        != Some("astrolabe.issue_441_1103.scheduler_fsv.v1")
    {
        return Err("action receipt schema is absent or unsupported".into());
    }
    let pair_count = parse_pair_count(action.get("pair_count"))?;
    let readback = read_physical_state(payload, pair_count)?;
    if readback
        .pointer("/graph/edge_dump_hash")
        .and_then(Value::as_str)
        != action
            .pointer("/persist/edge_dump_hash")
            .and_then(Value::as_str)
    {
        return Err("separate inspect found a Graph digest different from action.json".into());
    }
    Ok(json!({
        "phase": "separate_process_inspect",
        "action_file": {
            "path": action_path,
            "bytes": action_bytes.len(),
            "blake3": bytes_blake3(&action_bytes),
        },
        "physical_readback": readback,
    }))
}

/// The matrix is single-threaded at every environment mutation boundary: each
/// real vault run joins its scoped scheduler workers and drops the vault before
/// the next override is installed. Rust 2024 marks process-environment mutation
/// unsafe because concurrent readers would make it unsound; this executable has
/// no concurrent threads at those exact boundaries.
fn set_worker_override(value: Option<&str>) {
    unsafe {
        match value {
            Some(value) => {
                std::env::set_var(astrolabe_weave::knobs::WEAVE_SIMILARITY_WORKERS_ENV, value)
            }
            None => std::env::remove_var(astrolabe_weave::knobs::WEAVE_SIMILARITY_WORKERS_ENV),
        }
    }
}

fn set_exact_strategy_override() {
    unsafe {
        std::env::set_var(
            astrolabe_weave::knobs::WEAVE_DENSE_ANN_STRATEGY_ENV,
            astrolabe_weave::knobs::WEAVE_DENSE_ANN_STRATEGY_EXACT_KNN.to_string(),
        );
    }
}

fn config_refusal_case(root: &Path, name: &str, raw: &str) -> AnyResult<Value> {
    let payload = root.join(format!("invalid-{name}"));
    let before = json!({
        "phase": "before",
        "case": name,
        "raw_override": raw,
        "payload": payload,
        "payload_exists": payload.exists(),
    });
    println!("{}", serde_json::to_string(&before)?);
    std::io::stdout().flush()?;
    if payload.exists() {
        return Err(format!(
            "invalid-case payload unexpectedly exists: {}",
            payload.display()
        )
        .into());
    }
    set_worker_override(Some(raw));
    let error = match SimilarityPlannerConfig::resolve_runtime() {
        Ok(_) => {
            return Err(format!(
                "invalid override case {name:?} was accepted before state creation"
            )
            .into());
        }
        Err(error) => error,
    };
    let error_value = serde_json::to_value(&error)?;
    let code = error_value
        .get("code")
        .and_then(Value::as_str)
        .ok_or("invalid runtime override did not expose a structured error code")?;
    if !matches!(
        (name, code),
        ("empty", "ASTRO_WEAVE_KNOB_EMPTY")
            | ("nonnumeric", "ASTRO_WEAVE_KNOB_NOT_INTEGER")
            | ("out_of_range", "ASTRO_WEAVE_KNOB_OUT_OF_RANGE")
            | ("whitespace", "ASTRO_WEAVE_KNOB_WHITESPACE")
    ) {
        return Err(format!(
            "invalid override case {name:?} returned unexpected code {code:?}: {error_value}"
        )
        .into());
    }
    let after = json!({
        "phase": "after",
        "case": name,
        "raw_override": raw,
        "structured_refusal": error_value,
        "payload": payload,
        "payload_exists": payload.exists(),
    });
    println!("{}", serde_json::to_string(&after)?);
    std::io::stdout().flush()?;
    Ok(json!({ "before": before, "after": after }))
}

fn edge_dump_digest(value: &Value, label: &str) -> AnyResult<String> {
    value
        .pointer("/physical_readback/graph/edge_dump_hash")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{label} Graph digest missing").into())
}

fn matrix_mode(root: &Path, pair_count: usize) -> AnyResult<Value> {
    if root.exists() {
        return Err(format!("matrix root already exists: {}", root.display()).into());
    }
    fs::create_dir_all(root)?;
    set_exact_strategy_override();

    set_worker_override(Some("1"));
    let worker_1 = run_mode(&root.join("worker-1"), pair_count)?;
    set_worker_override(Some("32"));
    let worker_32 = run_mode(&root.join("worker-32"), pair_count)?;
    set_worker_override(Some("32"));
    let worker_32_repeat = run_mode(&root.join("worker-32-repeat"), pair_count)?;

    let digest_1 = edge_dump_digest(&worker_1, "worker-1")?;
    let digest_32 = edge_dump_digest(&worker_32, "worker-32")?;
    let digest_32_repeat = edge_dump_digest(&worker_32_repeat, "worker-32 repeat")?;
    if digest_1 != digest_32 || digest_1 != digest_32_repeat {
        return Err(format!(
            "Graph edge bytes diverged across 1/32/repeat: {digest_1}, {digest_32}, {digest_32_repeat}"
        )
        .into());
    }
    let requested_workers = |value: &Value| {
        value
            .pointer("/action/resolved_config/similarity_workers_requested")
            .and_then(Value::as_u64)
    };
    if requested_workers(&worker_1) != Some(1)
        || requested_workers(&worker_32) != Some(32)
        || requested_workers(&worker_32_repeat) != Some(32)
    {
        return Err("persisted scheduler receipts do not bind the requested 1/32/32 matrix".into());
    }

    let invalid = [
        config_refusal_case(root, "empty", "")?,
        config_refusal_case(root, "nonnumeric", "thirty-two")?,
        config_refusal_case(root, "out_of_range", "4097")?,
        config_refusal_case(root, "whitespace", " 32")?,
    ];
    set_worker_override(None);

    Ok(json!({
        "schema": "astrolabe.issue_441_1103.scheduler_matrix_fsv.v1",
        "phase": "matrix_after_independent_reopens",
        "source_of_truth": "three independent Aster Graph+Ledger vaults and four absent invalid-case payloads",
        "pair_count": pair_count,
        "node_count": pair_count.checked_mul(2).ok_or("matrix node count overflow")?,
        "edge_dump_byte_parity": true,
        "edge_dump_hash": digest_1,
        "worker_1": worker_1,
        "worker_32": worker_32,
        "worker_32_repeat": worker_32_repeat,
        "invalid_boundaries": invalid,
    }))
}

fn main() -> AnyResult<()> {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next().ok_or(
        "usage: issue_441_scheduler_fsv <run|inspect|matrix> <payload-directory> [pair-count]",
    )?;
    let payload = args.next().map(PathBuf::from).ok_or(
        "usage: issue_441_scheduler_fsv <run|inspect|matrix> <payload-directory> [pair-count]",
    )?;
    let output = match mode.to_str() {
        Some("run") => {
            let pair_count = match args.next() {
                Some(raw) => raw
                    .to_str()
                    .ok_or("pair-count is not Unicode")?
                    .parse::<usize>()?,
                None => 2_048,
            };
            if args.next().is_some() {
                return Err("run accepts at most one pair-count argument".into());
            }
            run_mode(&payload, pair_count)?
        }
        Some("inspect") => {
            if args.next().is_some() {
                return Err("inspect accepts no pair-count argument".into());
            }
            inspect_mode(&payload)?
        }
        Some("matrix") => {
            let pair_count = match args.next() {
                Some(raw) => raw
                    .to_str()
                    .ok_or("pair-count is not Unicode")?
                    .parse::<usize>()?,
                None => 256,
            };
            if args.next().is_some() {
                return Err("matrix accepts at most one pair-count argument".into());
            }
            matrix_mode(&payload, pair_count)?
        }
        _ => {
            return Err(
                "usage: issue_441_scheduler_fsv <run|inspect|matrix> <payload-directory> [pair-count]".into(),
            );
        }
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
