//! Manual Full State Verification for #1134's signed causal utility and
//! finite-input numeric-overflow refusals.
//!
//! This executable indexes a real source fixture through the production shadow
//! pipeline, calls the production MCP dispatcher, and independently point-reads
//! the resulting Assay, Kernel, and Ledger rows from the durable Aster vault.
//! It prints physical before/after state for the happy path and three refusal
//! edges. It is a manual reality probe, not a test or alternate implementation.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use astrolabe_bridge::{
    CbmToolRunner, cbm_project_name_from_path, initialize_cbm_host_process, set_cbm_cache_dir,
};
use calyx_aster::cf::{ColumnFamily, ledger_key};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::VaultId;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const SHADOW_VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const CAUSAL_PREFIX: &[u8] = b"astrolabe:causal:v1:";
const GENERATION_OBSERVED_AT_MS: u64 = 1_787_000_134_000;

type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

fn fail(code: &str, message: impl std::fmt::Display, remediation: &str) -> ! {
    eprintln!("code={code} message={message} remediation={remediation}");
    std::process::exit(1);
}

fn require(condition: bool, code: &str, message: impl std::fmt::Display) {
    if !condition {
        fail(
            code,
            message,
            "preserve the staged session and inspect the first mismatched physical readback",
        );
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_exact(path: &Path, bytes: &[u8]) -> AnyResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    let observed = fs::read(path)?;
    if observed != bytes {
        return Err(format!("write/read mismatch at {}", path.display()).into());
    }
    Ok(())
}

fn file_state(path: &Path) -> AnyResult<Value> {
    match fs::read(path) {
        Ok(bytes) => Ok(json!({
            "exists": true,
            "bytes": bytes.len(),
            "sha256": sha256(&bytes),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({
            "exists": false,
            "bytes": 0,
            "sha256": null,
        })),
        Err(error) => Err(error.into()),
    }
}

fn collect_tree_files(root: &Path, current: &Path, rows: &mut Vec<Value>) -> AnyResult<()> {
    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "unexpected symlink in physical vault tree: {}",
                path.display()
            )
            .into());
        }
        if metadata.is_dir() {
            collect_tree_files(root, &path, rows)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&path)?;
            rows.push(json!({
                "path": path.strip_prefix(root)?.to_string_lossy().replace('\\', "/"),
                "bytes": bytes.len(),
                "sha256": sha256(&bytes),
            }));
        } else {
            return Err(format!("unexpected non-file vault entry: {}", path.display()).into());
        }
    }
    Ok(())
}

fn tree_state(root: &Path) -> AnyResult<Value> {
    if !root.is_dir() {
        return Ok(json!({"exists": false, "files": [], "tree_sha256": null}));
    }
    let mut files = Vec::new();
    collect_tree_files(root, root, &mut files)?;
    let encoded = serde_json::to_vec(&files)?;
    Ok(json!({
        "exists": true,
        "file_count": files.len(),
        "tree_sha256": sha256(&encoded),
        "files": files,
    }))
}

fn write_fixture(repo: &Path) -> AnyResult<()> {
    require(
        !repo.exists(),
        "ISSUE_1134_FSV_REPO_PREEXISTS",
        repo.display(),
    );
    fs::create_dir_all(repo)?;
    write_exact(
        &repo.join("provider.py"),
        b"def remote(value):\n    return value * 2\n",
    )?;
    write_exact(
        &repo.join("consumer.py"),
        b"from provider import remote\n\ndef consume():\n    return remote(21)\n",
    )?;
    write_exact(
        &repo.join("Helper.java"),
        b"final class Helper {\n    static int twice(int value) { return value * 2; }\n}\n",
    )?;
    write_exact(
        &repo.join("Caller.java"),
        b"final class Caller {\n    int local(int value) { return value + 1; }\n    int invoke() { return local(1) + Helper.twice(2); }\n}\n",
    )?;
    Ok(())
}

fn config_rows(cache: &Path) -> AnyResult<(String, BTreeMap<String, String>)> {
    let connection =
        Connection::open_with_flags(cache.join("_config.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let mut statement = connection.prepare("SELECT key, value FROM config ORDER BY key")?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<BTreeMap<String, String>, _>>()?;
    Ok((integrity, rows))
}

fn generation_key(kind: &str, artifact_sha256: &str) -> Vec<u8> {
    let mut key = CAUSAL_PREFIX.to_vec();
    key.extend_from_slice(kind.as_bytes());
    key.push(b':');
    key.extend_from_slice(artifact_sha256.as_bytes());
    key
}

fn current_pointer_key(project: &str) -> Vec<u8> {
    let mut key = CAUSAL_PREFIX.to_vec();
    key.extend_from_slice(b"current:");
    key.extend_from_slice(sha256(project.as_bytes()).as_bytes());
    key
}

fn row_state(vault: &AsterVault, snapshot: u64, cf: ColumnFamily, key: &[u8]) -> AnyResult<Value> {
    match vault.read_cf_at(snapshot, cf, key)? {
        Some(bytes) => Ok(json!({
            "present": true,
            "cf": format!("{cf:?}"),
            "key_hex": hex_lower(key),
            "bytes": bytes.len(),
            "sha256": sha256(&bytes),
            "json": serde_json::from_slice::<Value>(&bytes).ok(),
        })),
        None => Ok(json!({
            "present": false,
            "cf": format!("{cf:?}"),
            "key_hex": hex_lower(key),
            "bytes": 0,
            "sha256": null,
            "json": null,
        })),
    }
}

fn physical_state(cache: &Path, project: &str) -> AnyResult<Value> {
    let (integrity, rows) = config_rows(cache)?;
    let prefix = format!("astrolabe.calyx.{project}");
    let vault_dir = rows
        .get(&format!("{prefix}.vault_dir"))
        .map(PathBuf::from)
        .unwrap_or_else(|| cache.join(format!("{project}.astrolabe-vault")));
    let vault_id = rows
        .get(&format!("{prefix}.vault_id"))
        .map(String::as_str)
        .unwrap_or(SHADOW_VAULT_ID)
        .parse::<VaultId>()?;
    let vault_salt = rows
        .get(&format!("{prefix}.vault_salt"))
        .cloned()
        .unwrap_or_else(|| format!("astrolabe-shadow-v1:{project}"));
    let vault = AsterVault::open(
        &vault_dir,
        vault_id,
        vault_salt.into_bytes(),
        VaultOptions {
            restore_mvcc_rows: false,
            read_only: true,
            restore_ledger_hook: false,
            selected_cfs: Some(vec![
                ColumnFamily::Assay,
                ColumnFamily::Kernel,
                ColumnFamily::Ledger,
            ]),
            ..VaultOptions::default()
        },
    )?;
    let snapshot = vault.latest_seq();
    let current_key = current_pointer_key(project);
    let current = vault.read_cf_at(snapshot, ColumnFamily::Kernel, &current_key)?;
    let causal = if let Some(current) = current {
        let artifact_sha256 = String::from_utf8(current)?;
        let artifact = row_state(
            &vault,
            snapshot,
            ColumnFamily::Assay,
            &generation_key("assay", &artifact_sha256),
        )?;
        let kernel = row_state(
            &vault,
            snapshot,
            ColumnFamily::Kernel,
            &generation_key("kernel", &artifact_sha256),
        )?;
        let manifest = row_state(
            &vault,
            snapshot,
            ColumnFamily::Kernel,
            &generation_key("manifest", &artifact_sha256),
        )?;
        let ledger_seq = manifest["json"]["ledger_seq"]
            .as_u64()
            .ok_or("causal manifest has no ledger_seq")?;
        let ledger = row_state(
            &vault,
            snapshot,
            ColumnFamily::Ledger,
            &ledger_key(ledger_seq),
        )?;
        let ledger_bytes = vault
            .read_cf_at(snapshot, ColumnFamily::Ledger, &ledger_key(ledger_seq))?
            .ok_or("causal ledger row disappeared during point-read")?;
        let decoded = calyx_ledger::decode(&ledger_bytes)?;
        require(
            decoded.verify(),
            "ISSUE_1134_FSV_LEDGER_VERIFY_FAILED",
            format!("ledger seq {ledger_seq}"),
        );
        json!({
            "present": true,
            "artifact_sha256": artifact_sha256,
            "current_pointer": row_state(&vault, snapshot, ColumnFamily::Kernel, &current_key)?,
            "assay_artifact": artifact,
            "kernel": kernel,
            "manifest": manifest,
            "ledger": ledger,
            "ledger_decoded": {
                "seq": decoded.seq,
                "entry_hash": hex_lower(&decoded.entry_hash),
                "verified": true,
            },
        })
    } else {
        json!({
            "present": false,
            "current_pointer": row_state(&vault, snapshot, ColumnFamily::Kernel, &current_key)?,
        })
    };
    drop(vault);

    let current_manifest = file_state(&vault_dir.join("CURRENT"))?;
    let pointed_manifest = if current_manifest["exists"] == Value::Bool(true) {
        let name = fs::read_to_string(vault_dir.join("CURRENT"))?;
        file_state(&vault_dir.join(name.trim()))?
    } else {
        json!({"exists": false, "bytes": 0, "sha256": null})
    };
    let state = json!({
        "config_integrity": integrity,
        "config_rows": rows,
        "config_db": file_state(&cache.join("_config.db"))?,
        "graph_db": file_state(&cache.join(format!("{project}.db")))?,
        "vault_dir": vault_dir,
        "snapshot_seq": snapshot,
        "causal": causal,
        "ledger_head_current": file_state(&vault_dir.join("ledger_head").join("current.json"))?,
        "current_manifest_pointer": current_manifest,
        "pointed_manifest": pointed_manifest,
        "vault_tree": tree_state(&vault_dir)?,
    });
    let fingerprint = sha256(&serde_json::to_vec(&state)?);
    Ok(json!({"fingerprint": fingerprint, "state": state}))
}

fn call_tool(runner: &CbmToolRunner, tool: &str, arguments: &Value) -> AnyResult<(Value, Value)> {
    let raw = astrolabe_server::migration::handle_tool_raw(
        runner,
        tool,
        &serde_json::to_string(arguments)?,
    )?;
    let envelope: Value = serde_json::from_str(&raw)?;
    let content = envelope["content"]
        .as_array()
        .filter(|content| content.len() == 1)
        .and_then(|content| content.first())
        .and_then(|content| content["text"].as_str())
        .ok_or("MCP envelope does not contain exactly one text payload")?;
    let payload: Value = serde_json::from_str(content)?;
    if envelope["isError"] != Value::Bool(true) {
        require(
            envelope.get("structuredContent") == Some(&payload),
            "ISSUE_1134_FSV_STRUCTURED_CONTENT_MISMATCH",
            tool,
        );
    }
    Ok((envelope, payload))
}

fn tools_state(runner: &CbmToolRunner) -> AnyResult<Value> {
    let request = json!({"jsonrpc": "2.0", "id": 1134, "method": "tools/list", "params": {}});
    let raw =
        astrolabe_server::migration::handle_jsonrpc_raw(runner, &serde_json::to_string(&request)?)?
            .ok_or("tools/list returned no response")?;
    let response: Value = serde_json::from_str(&raw)?;
    let tools = response["result"]["tools"]
        .as_array()
        .ok_or("tools/list result has no tools array")?;
    let mut names = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    let count = names.len();
    names.sort_unstable();
    names.dedup();
    require(
        count == names.len() && count <= 40,
        "ISSUE_1134_FSV_TOOL_ROSTER_INVALID",
        format!("count={count} unique={}", names.len()),
    );
    let causal = tools
        .iter()
        .filter(|tool| tool["name"] == Value::String("causal_analysis".to_string()))
        .collect::<Vec<_>>();
    let expected = tools
        .iter()
        .filter(|tool| tool["name"] == Value::String("expected_gain".to_string()))
        .collect::<Vec<_>>();
    require(
        causal.len() == 1 && expected.len() == 1,
        "ISSUE_1134_FSV_CAUSAL_TOOLS_MISSING",
        format!("causal={} expected_gain={}", causal.len(), expected.len()),
    );
    let outcome_value = &causal[0]["inputSchema"]["properties"]["decisions"]["items"]["properties"]
        ["outcome_value"];
    require(
        outcome_value["type"] == Value::String("number".to_string())
            && outcome_value["not"]["const"].as_f64() == Some(0.0)
            && outcome_value["description"]
                .as_str()
                .is_some_and(|description| description.contains("negative")),
        "ISSUE_1134_FSV_SIGNED_SCHEMA_INVALID",
        outcome_value,
    );
    Ok(json!({
        "count": count,
        "unique_count": names.len(),
        "names": names,
        "causal_analysis": causal[0],
        "expected_gain": expected[0],
        "raw_sha256": sha256(raw.as_bytes()),
    }))
}

fn happy_request(project: &str) -> Value {
    json!({
        "project": project,
        "mode": "prepare",
        "observations": [
            {"row_id":"c1","values":{"treatment":0.0,"latency":10.0,"throughput":10.0},"strata":{"cohort":"all"}},
            {"row_id":"c2","values":{"treatment":0.0,"latency":12.0,"throughput":12.0},"strata":{"cohort":"all"}},
            {"row_id":"t1","values":{"treatment":1.0,"latency":6.0,"throughput":12.0},"strata":{"cohort":"all"}},
            {"row_id":"t2","values":{"treatment":1.0,"latency":8.0,"throughput":14.0},"strata":{"cohort":"all"}}
        ],
        "treatments": ["treatment"],
        "outcomes": ["latency", "throughput"],
        "pairs": [
            {"treatment":"treatment","outcome":"latency","adjustment_set":["cohort"]},
            {"treatment":"treatment","outcome":"throughput","adjustment_set":["cohort"]}
        ],
        "assumptions": ["consistency","conditional_exchangeability","positivity","no_interference"],
        "minimum_propensity": 0.25,
        "minimum_arm_count": 2,
        "confidence_level": 0.95,
        "decisions": [
            {"treatment":"treatment","outcome":"latency","outcome_value":-10.0,"action_cost":5.0,"unit":"credits"},
            {"treatment":"treatment","outcome":"throughput","outcome_value":10.0,"action_cost":1.0,"unit":"credits"}
        ]
    })
}

fn effect<'a>(payload: &'a Value, outcome: &str) -> &'a Value {
    payload["artifact"]["causal"]["effects"]
        .as_array()
        .and_then(|effects| effects.iter().find(|effect| effect["outcome"] == outcome))
        .unwrap_or_else(|| {
            fail(
                "ISSUE_1134_FSV_EFFECT_MISSING",
                outcome,
                "inspect the complete causal effect roster",
            )
        })
}

fn gain<'a>(payload: &'a Value, outcome: &str) -> &'a Value {
    payload["artifact"]["expected_gains"]
        .as_array()
        .and_then(|gains| gains.iter().find(|gain| gain["outcome"] == outcome))
        .unwrap_or_else(|| {
            fail(
                "ISSUE_1134_FSV_GAIN_MISSING",
                outcome,
                "inspect the complete expected-gain roster",
            )
        })
}

fn approximate(observed: f64, expected: f64, tolerance: f64) -> bool {
    (observed - expected).abs() <= tolerance
}

fn verify_happy(payload: &Value, physical: &Value) -> AnyResult<Value> {
    let latency = effect(payload, "latency");
    let throughput = effect(payload, "throughput");
    let latency_gain = gain(payload, "latency");
    let throughput_gain = gain(payload, "throughput");
    let expected_se = (4.0_f64 / 3.0).sqrt();
    for (name, observed, expected) in [
        (
            "latency association",
            latency["unadjusted_association"]
                .as_f64()
                .unwrap_or(f64::NAN),
            -4.0,
        ),
        (
            "latency ATE",
            latency["average_treatment_effect"]
                .as_f64()
                .unwrap_or(f64::NAN),
            -4.0,
        ),
        (
            "latency SE",
            latency["standard_error"].as_f64().unwrap_or(f64::NAN),
            expected_se,
        ),
        (
            "throughput association",
            throughput["unadjusted_association"]
                .as_f64()
                .unwrap_or(f64::NAN),
            2.0,
        ),
        (
            "throughput ATE",
            throughput["average_treatment_effect"]
                .as_f64()
                .unwrap_or(f64::NAN),
            2.0,
        ),
        (
            "throughput SE",
            throughput["standard_error"].as_f64().unwrap_or(f64::NAN),
            expected_se,
        ),
        (
            "latency gross",
            latency_gain["expected_gross_gain"]
                .as_f64()
                .unwrap_or(f64::NAN),
            40.0,
        ),
        (
            "latency net",
            latency_gain["expected_net_gain"]
                .as_f64()
                .unwrap_or(f64::NAN),
            35.0,
        ),
        (
            "latency break-even",
            latency_gain["break_even_effect"]
                .as_f64()
                .unwrap_or(f64::NAN),
            -0.5,
        ),
        (
            "throughput gross",
            throughput_gain["expected_gross_gain"]
                .as_f64()
                .unwrap_or(f64::NAN),
            20.0,
        ),
        (
            "throughput net",
            throughput_gain["expected_net_gain"]
                .as_f64()
                .unwrap_or(f64::NAN),
            19.0,
        ),
        (
            "throughput break-even",
            throughput_gain["break_even_effect"]
                .as_f64()
                .unwrap_or(f64::NAN),
            0.1,
        ),
    ] {
        require(
            approximate(observed, expected, 1e-12),
            "ISSUE_1134_FSV_MATH_MISMATCH",
            format!("{name}: expected={expected} observed={observed}"),
        );
    }
    for (effect, gain) in [(latency, latency_gain), (throughput, throughput_gain)] {
        let value = gain["outcome_value"]
            .as_f64()
            .ok_or("gain has no outcome_value")?;
        let cost = gain["action_cost"]
            .as_f64()
            .ok_or("gain has no action_cost")?;
        let point = gain["expected_net_gain"]
            .as_f64()
            .ok_or("gain has no point")?;
        let first = effect["confidence_lower"]
            .as_f64()
            .ok_or("effect has no lower")?
            * value
            - cost;
        let second = effect["confidence_upper"]
            .as_f64()
            .ok_or("effect has no upper")?
            * value
            - cost;
        let lower = gain["expected_net_gain_lower"]
            .as_f64()
            .ok_or("gain has no lower")?;
        let upper = gain["expected_net_gain_upper"]
            .as_f64()
            .ok_or("gain has no upper")?;
        require(
            approximate(lower, first.min(second), 1e-12)
                && approximate(upper, first.max(second), 1e-12)
                && lower <= point
                && point <= upper,
            "ISSUE_1134_FSV_BOUND_NORMALIZATION_MISMATCH",
            gain,
        );
    }
    require(
        latency_gain["rank_within_unit"].as_u64() == Some(1)
            && throughput_gain["rank_within_unit"].as_u64() == Some(2),
        "ISSUE_1134_FSV_SIGNED_RANK_MISMATCH",
        payload["artifact"]["expected_gains"].clone(),
    );
    let persisted_causal = &physical["state"]["causal"]["assay_artifact"]["json"]["causal"];
    let persisted_gains = &physical["state"]["causal"]["kernel"]["json"]["expected_gains"];
    require(
        persisted_causal == &payload["artifact"]["causal"]
            && persisted_gains == &payload["artifact"]["expected_gains"],
        "ISSUE_1134_FSV_PHYSICAL_PAYLOAD_MISMATCH",
        "Assay causal artifact or Kernel expected gains differ from MCP readback",
    );
    Ok(json!({
        "formula": "expected_net_gain = effect * signed_outcome_value - action_cost",
        "influence_values": {
            "latency": [-2.0, -6.0, -6.0, -2.0],
            "throughput": [4.0, 0.0, 0.0, 4.0]
        },
        "sample_variance": 16.0 / 3.0,
        "standard_error": expected_se,
        "latency": {"ate": -4.0, "value": -10.0, "cost": 5.0, "gross": 40.0, "net": 35.0, "break_even": -0.5, "rank": 1},
        "throughput": {"ate": 2.0, "value": 10.0, "cost": 1.0, "gross": 20.0, "net": 19.0, "break_even": 0.1, "rank": 2},
    }))
}

fn expect_error(
    case: &str,
    runner: &CbmToolRunner,
    cache: &Path,
    project: &str,
    request: &Value,
    expected_code: &str,
    expected_message_parts: &[&str],
) -> AnyResult<Value> {
    let before = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "before", "physical": before}))?
    );
    let (envelope, payload) = call_tool(runner, "causal_analysis", request)?;
    require(
        envelope["isError"] == Value::Bool(true)
            && payload["status"] == Value::String("error".to_string())
            && payload["code"] == Value::String(expected_code.to_string())
            && payload["remediation"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()),
        "ISSUE_1134_FSV_ERROR_CONTRACT_MISMATCH",
        payload.clone(),
    );
    let message = payload["message"].as_str().unwrap_or_default();
    for part in expected_message_parts {
        require(
            message.contains(part),
            "ISSUE_1134_FSV_ERROR_DETAIL_MISSING",
            format!("case={case} missing={part:?} message={message:?}"),
        );
    }
    let after = physical_state(cache, project)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "after", "physical": after}))?
    );
    require(
        before["fingerprint"] == after["fingerprint"],
        "ISSUE_1134_FSV_REFUSAL_MUTATED_STATE",
        format!(
            "case={case} before={} after={}",
            before["fingerprint"], after["fingerprint"]
        ),
    );
    Ok(json!({
        "case": case,
        "expected_code": expected_code,
        "response": payload,
        "before": before,
        "after": after,
        "state_unchanged": true,
    }))
}

fn run(payload_dir: PathBuf) -> AnyResult<()> {
    require(
        !payload_dir.exists(),
        "ISSUE_1134_FSV_PAYLOAD_PREEXISTS",
        payload_dir.display(),
    );
    fs::create_dir_all(&payload_dir)?;
    let repo = payload_dir.join("real-source");
    let cache = payload_dir.join("real-cache");
    write_fixture(&repo)?;
    fs::create_dir(&cache)?;
    let cache_readback = set_cbm_cache_dir(&cache)?;
    require(
        cache_readback == cache,
        "ISSUE_1134_FSV_CACHE_READBACK_MISMATCH",
        format!(
            "requested={} observed={}",
            cache.display(),
            cache_readback.display()
        ),
    );
    initialize_cbm_host_process()?;
    let runner = CbmToolRunner::new_default()?;
    let project = cbm_project_name_from_path(repo.to_str().ok_or("repo path is not UTF-8")?)?;
    let tools = tools_state(&runner)?;
    write_exact(
        &payload_dir.join("tools.json"),
        &serde_json::to_vec_pretty(&tools)?,
    )?;

    let index_args = json!({
        "repo_path": repo,
        "mode": "fast",
        "calyx": "shadow",
        "generation_observed_at_ms": GENERATION_OBSERVED_AT_MS,
    });
    let (index_envelope, index_payload) = call_tool(&runner, "index_repository", &index_args)?;
    require(
        index_envelope["isError"] != Value::Bool(true)
            && index_payload["project"] == Value::String(project.clone()),
        "ISSUE_1134_FSV_SHADOW_INDEX_FAILED",
        index_payload.clone(),
    );
    write_exact(
        &payload_dir.join("index.json"),
        &serde_json::to_vec_pretty(&index_payload)?,
    )?;

    let pre_success = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case": "signed_happy", "phase": "before", "physical": pre_success})
        )?
    );
    require(
        pre_success["state"]["causal"]["present"] == Value::Bool(false),
        "ISSUE_1134_FSV_CAUSAL_PRESTATE_NOT_EMPTY",
        pre_success.clone(),
    );
    let happy = happy_request(&project);
    let (happy_envelope, happy_payload) = call_tool(&runner, "causal_analysis", &happy)?;
    require(
        happy_envelope["isError"] != Value::Bool(true)
            && happy_payload["status"] == Value::String("success".to_string()),
        "ISSUE_1134_FSV_HAPPY_CALL_FAILED",
        happy_payload.clone(),
    );
    let post_success = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case": "signed_happy", "phase": "after", "physical": post_success})
        )?
    );
    require(
        pre_success["fingerprint"] != post_success["fingerprint"]
            && post_success["state"]["causal"]["present"] == Value::Bool(true),
        "ISSUE_1134_FSV_HAPPY_STATE_NOT_PUBLISHED",
        post_success.clone(),
    );
    let manual_math = verify_happy(&happy_payload, &post_success)?;

    let mut loom_overflow = happy.clone();
    loom_overflow["decisions"][0]["outcome_value"] = json!(f64::MAX);
    let loom_edge = expect_error(
        "loom_product_overflow",
        &runner,
        &cache,
        &project,
        &loom_overflow,
        "CALYX_LOOM_EXPECTED_GAIN_NUMERIC_INVALID",
        &["treatment=>latency", "effect * outcome_value"],
    )?;

    let mut assay_overflow = happy.clone();
    for observation in assay_overflow["observations"]
        .as_array_mut()
        .ok_or("observations is not an array")?
    {
        observation["values"]["latency"] = json!(f64::MAX);
    }
    let assay_edge = expect_error(
        "assay_stratum_overflow",
        &runner,
        &cache,
        &project,
        &assay_overflow,
        "ASTRO_ASSAY_CAUSAL_NUMERIC_INVALID",
        &[
            "treatment=>latency",
            "stratum control outcome accumulation",
            "row \"c2\"",
            "cohort=all",
        ],
    )?;

    let mut zero_value = happy.clone();
    zero_value["decisions"][0]["outcome_value"] = json!(0.0);
    let zero_edge = expect_error(
        "zero_marginal_value",
        &runner,
        &cache,
        &project,
        &zero_value,
        "ASTRO_MCP_ARGUMENT_CONST_FORBIDDEN",
        &["arguments.decisions[0].outcome_value", "forbidden constant"],
    )?;

    let idempotent_before = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case": "idempotent_repeat", "phase": "before", "physical": idempotent_before})
        )?
    );
    let (repeat_envelope, repeat_payload) = call_tool(&runner, "causal_analysis", &happy)?;
    require(
        repeat_envelope["isError"] != Value::Bool(true)
            && repeat_payload["artifact_sha256"] == happy_payload["artifact_sha256"],
        "ISSUE_1134_FSV_IDEMPOTENT_RESPONSE_MISMATCH",
        repeat_payload.clone(),
    );
    let idempotent_after = physical_state(&cache, &project)?;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"case": "idempotent_repeat", "phase": "after", "physical": idempotent_after})
        )?
    );
    require(
        idempotent_before["fingerprint"] == idempotent_after["fingerprint"],
        "ISSUE_1134_FSV_IDEMPOTENT_STATE_MUTATED",
        format!(
            "before={} after={}",
            idempotent_before["fingerprint"], idempotent_after["fingerprint"]
        ),
    );

    let read_before = physical_state(&cache, &project)?;
    let (_, causal_read) = call_tool(
        &runner,
        "causal_analysis",
        &json!({"project": project, "mode": "read"}),
    )?;
    let (_, gain_read) = call_tool(&runner, "expected_gain", &json!({"project": project}))?;
    let read_after = physical_state(&cache, &project)?;
    require(
        read_before["fingerprint"] == read_after["fingerprint"]
            && causal_read["artifact_sha256"] == happy_payload["artifact_sha256"]
            && gain_read["expected_gains"] == happy_payload["artifact"]["expected_gains"],
        "ISSUE_1134_FSV_READBACK_MISMATCH",
        "read surfaces mutated or disagreed with the physical generation",
    );

    let report = json!({
        "schema": "astrolabe.issue-1134.causal-numeric-fsv.v1",
        "project": project,
        "source_of_truth": "physical Calyx Assay, Kernel, and Ledger rows plus ledger_head/current.json, CURRENT, pointed MANIFEST, config SQLite, and complete vault file tree",
        "tools": tools,
        "index": index_payload,
        "happy": {
            "request": happy,
            "response": happy_payload,
            "manual_math": manual_math,
            "before": pre_success,
            "after": post_success,
        },
        "edges": [loom_edge, assay_edge, zero_edge],
        "idempotent": {
            "response": repeat_payload,
            "before": idempotent_before,
            "after": idempotent_after,
            "state_unchanged": true,
        },
        "independent_reads": {
            "causal_analysis": causal_read,
            "expected_gain": gain_read,
            "before": read_before,
            "after": read_after,
            "state_unchanged": true,
        },
    });
    let report_bytes = serde_json::to_vec_pretty(&report)?;
    let report_path = payload_dir.join("report.json");
    write_exact(&report_path, &report_bytes)?;
    println!(
        "ISSUE_1134_FSV_SOURCE_OF_TRUTH path={} bytes={} sha256={} report={}",
        report_path.display(),
        report_bytes.len(),
        sha256(&report_bytes),
        serde_json::to_string(&report)?
    );
    Ok(())
}

fn main() {
    let process_args = std::env::args_os().collect::<Vec<_>>();
    if process_args
        .get(1)
        .is_some_and(|argument| argument == "cli")
    {
        std::process::exit(astrolabe_server::run_from_env_on_sized_host_thread());
    }
    let mut args = process_args.into_iter().skip(1);
    let payload = args.next().map(PathBuf::from).unwrap_or_else(|| {
        fail(
            "ISSUE_1134_FSV_PAYLOAD_REQUIRED",
            "payload directory is required",
            "run the committed example through native-fsv-run",
        )
    });
    if args.next().is_some() {
        fail(
            "ISSUE_1134_FSV_ARGUMENT_UNKNOWN",
            "unexpected extra argument",
            "pass exactly one absent payload directory",
        );
    }
    if let Err(error) = run(payload) {
        fail(
            "ISSUE_1134_FSV_FAILED",
            error,
            "preserve the staged session and inspect the exact failure plus physical state",
        );
    }
}
