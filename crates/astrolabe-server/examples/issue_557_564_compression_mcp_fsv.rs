//! Manual Full State Verification for #557/#564's production MCP compression
//! commission, status, and deterministic selector-replay surfaces.
//!
//! The Registry FSV driver first creates a real raw two-candidate vault and the
//! exact `_config.db` rows consumed by the shipping server. This executable then
//! drives the public JSON-RPC transport and independently hashes Config, CURRENT,
//! its immutable MANIFEST, Compression/Ledger rows, candidate columns, and every
//! vault file before and after each action. It is a manual reality probe, not a
//! test or an alternate implementation.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use astrolabe_bridge::{CbmToolRunner, initialize_cbm_host_process, set_cbm_cache_dir};
use calyx_aster::cf::{ColumnFamily, compression_manifest_key};
use calyx_aster::dedup::DedupPolicy;
use calyx_aster::manifest::ManifestStore;
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{SlotId, VaultId};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ROOT_ENV: &str = "ASTROLABE_COMPRESSION_FSV_ROOT";
const PROJECT: &str = "issues-557-564-compression-admission-fsv";
const INPUT_FILE: &str = "mcp-input.json";
const OUTPUT_FILE: &str = "mcp-dispatch-result.json";
const SHADOW_LEDGER_CHECKPOINT_KEY: &str = "shadow_ledger_checkpoint_json";
const OPERATION_PREFLIGHT_STAGE: &str =
    "pure operation-shape preflight before vault/manifest/Ledger open";
const SLOT_COUNT_PREFLIGHT_STAGE: &str =
    "candidate slot count validation before slot Vec allocation";
const SLOT_PARSE_PREFLIGHT_STAGE: &str = "candidate slot parse before vault/manifest/Ledger open";
const RECEIPT_PARSE_PREFLIGHT_STAGE: &str =
    "candidate receipt parse before vault/manifest/Ledger open";

type AnyResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;

struct PreparedInput {
    bytes: Vec<u8>,
    raw: Value,
    project: String,
    cache_dir: PathBuf,
    slot_ids: Vec<u16>,
    candidate_request: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateLayout {
    RawUnmanifested,
    CompressedWithRawSidecar,
}

impl CandidateLayout {
    const fn label(self) -> &'static str {
        match self {
            Self::RawUnmanifested => "raw_primary_without_sidecar",
            Self::CompressedWithRawSidecar => "compressed_primary_with_raw_sidecar",
        }
    }

    const fn requires_raw_sidecar(self) -> bool {
        matches!(self, Self::CompressedWithRawSidecar)
    }
}

struct JsonRpcExchange {
    request_raw: String,
    transport_output_raw: String,
    response_raw: String,
    response: Value,
}

impl JsonRpcExchange {
    fn evidence(&self) -> Value {
        json!({
            "request_raw": self.request_raw,
            "transport_output_raw": self.transport_output_raw,
            "response_raw": self.response_raw,
            "response": self.response,
        })
    }

    fn tool_result(&self) -> AnyResult<(&Value, bool)> {
        let result = self
            .response
            .get("result")
            .and_then(Value::as_object)
            .ok_or("JSON-RPC tools/call response has no result object")?;
        let content = result
            .get("content")
            .and_then(Value::as_array)
            .filter(|content| content.len() == 1)
            .and_then(|content| content.first())
            .and_then(|content| content.get("text"))
            .and_then(Value::as_str)
            .ok_or("JSON-RPC tools/call response has no exact single text payload")?;
        let payload = serde_json::from_str::<Value>(content)?;
        let structured = result
            .get("structuredContent")
            .ok_or("JSON-RPC tools/call response omitted structuredContent")?;
        require(
            structured == &payload,
            "ISSUE_557_564_FSV_STRUCTURED_CONTENT_MISMATCH",
            "text and structuredContent payloads differ",
        )?;
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .ok_or("JSON-RPC tools/call response omitted boolean isError")?;
        Ok((structured, is_error))
    }
}

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

fn write_exact(path: &Path, bytes: &[u8]) -> AnyResult<()> {
    require(
        !path.exists(),
        "ISSUE_557_564_FSV_OUTPUT_PREEXISTS",
        path.display(),
    )?;
    fs::write(path, bytes)?;
    let observed = fs::read(path)?;
    require(
        observed == bytes,
        "ISSUE_557_564_FSV_OUTPUT_READBACK_MISMATCH",
        path.display(),
    )
}

fn required_file_state(path: &Path) -> AnyResult<Value> {
    let bytes = fs::read(path)?;
    Ok(json!({
        "path": path,
        "bytes": bytes.len(),
        "sha256": sha256(&bytes),
    }))
}

fn collect_tree_files(root: &Path, current: &Path, rows: &mut Vec<Value>) -> AnyResult<()> {
    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        require(
            !metadata.file_type().is_symlink(),
            "ISSUE_557_564_FSV_TREE_SYMLINK",
            path.display(),
        )?;
        if metadata.is_dir() {
            collect_tree_files(root, &path, rows)?;
        } else {
            require(
                metadata.is_file(),
                "ISSUE_557_564_FSV_TREE_NON_FILE",
                path.display(),
            )?;
            let bytes = fs::read(&path)?;
            rows.push(json!({
                "path": path.strip_prefix(root)?.to_string_lossy().replace('\\', "/"),
                "bytes": bytes.len(),
                "sha256": sha256(&bytes),
            }));
        }
    }
    Ok(())
}

fn tree_state(root: &Path) -> AnyResult<Value> {
    require(
        root.is_dir(),
        "ISSUE_557_564_FSV_TREE_MISSING",
        root.display(),
    )?;
    let mut files = Vec::new();
    collect_tree_files(root, root, &mut files)?;
    let encoded = serde_json::to_vec(&files)?;
    Ok(json!({
        "file_count": files.len(),
        "tree_sha256": sha256(&encoded),
        "files": files,
    }))
}

fn config_state(cache_dir: &Path) -> AnyResult<Value> {
    let config_path = cache_dir.join("_config.db");
    let connection = Connection::open_with_flags(
        &config_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.pragma_update(None, "query_only", true)?;
    let query_only: i64 = connection.pragma_query_value(None, "query_only", |row| row.get(0))?;
    let integrity: String =
        connection.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
    require(
        query_only == 1 && integrity == "ok",
        "ISSUE_557_564_FSV_CONFIG_INVALID",
        format!("query_only={query_only} integrity={integrity:?}"),
    )?;
    let mut statement = connection.prepare("SELECT key, value FROM config ORDER BY key ASC")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    drop(statement);
    connection.close().map_err(|(_, error)| error)?;
    let rows_sha256 = sha256(&serde_json::to_vec(&rows)?);
    Ok(json!({
        "query_only": true,
        "integrity": integrity,
        "rows": rows,
        "rows_sha256": rows_sha256,
        "database": required_file_state(&config_path)?,
        "cache_tree": tree_state(cache_dir)?,
    }))
}

fn hash_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"issues-557-564-cf-rows-v1");
    for (key, value) in rows {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key);
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    format!("{:x}", hasher.finalize())
}

fn column_state(
    vault: &AsterVault,
    snapshot: u64,
    column_family: ColumnFamily,
) -> AnyResult<Value> {
    let rows = vault.scan_cf_at(snapshot, column_family)?;
    let key_bytes = rows.iter().map(|(key, _)| key.len() as u64).sum::<u64>();
    let value_bytes = rows
        .iter()
        .map(|(_, value)| value.len() as u64)
        .sum::<u64>();
    Ok(json!({
        "column_family": column_family.name(),
        "physical_namespace": "present",
        "rows": rows.len(),
        "key_bytes": key_bytes,
        "value_bytes": value_bytes,
        "rows_sha256": hash_rows(&rows),
    }))
}

fn absent_column_state(column_family: ColumnFamily) -> Value {
    json!({
        "column_family": column_family.name(),
        "physical_namespace": "absent",
    })
}

fn require_raw_sidecar_absent(vault_dir: &Path, slot_id: SlotId) -> AnyResult<()> {
    let raw_cf = ColumnFamily::slot_raw(slot_id);
    let path = vault_dir.join("cf").join(raw_cf.name());
    match fs::symlink_metadata(&path) {
        Ok(_) => Err(format!(
            "ISSUE_557_564_FSV_RAW_SIDECAR_NAMESPACE_PRESENT: raw/unmanifested slot {} has a physical namespace at {}",
            slot_id.get(),
            path.display()
        )
        .into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "ISSUE_557_564_FSV_RAW_SIDECAR_NAMESPACE_INSPECTION_FAILED: inspect {}: {error}",
            path.display()
        )
        .into()),
    }
}

/// #1064 PC-02/03/04/05/09/29/41/43: every snapshot opens only Compression,
/// Ledger, the declared primaries, and the raw sidecars required by `layout`.
/// The first snapshot proves two sidecar namespaces absent; the remaining 14
/// require both sidecars and read their rows. Project/config identity,
/// candidate SlotIds, and immutable Panel/Registry refs stay invariant. The
/// eight-row fixture is correctness evidence only, not a production-N cost
/// measurement.
fn physical_state(
    cache_dir: &Path,
    project: &str,
    slot_ids: &[u16],
    layout: CandidateLayout,
) -> AnyResult<Value> {
    let config = config_state(cache_dir)?;
    let prefix = format!("astrolabe.calyx.{project}");
    let rows = config["rows"]
        .as_object()
        .ok_or("config state rows are not an object")?;
    require(
        rows.get(&prefix).and_then(Value::as_str) == Some("shadow"),
        "ISSUE_557_564_FSV_CONFIG_DIAL_MISMATCH",
        &prefix,
    )?;
    let vault_dir = PathBuf::from(
        rows.get(&format!("{prefix}.vault_dir"))
            .and_then(Value::as_str)
            .ok_or("config has no exact vault_dir")?,
    );
    let vault_id = VaultId::from_str(
        rows.get(&format!("{prefix}.vault_id"))
            .and_then(Value::as_str)
            .ok_or("config has no exact vault_id")?,
    )?;
    let vault_salt = rows
        .get(&format!("{prefix}.vault_salt"))
        .and_then(Value::as_str)
        .ok_or("config has no exact vault_salt")?
        .as_bytes()
        .to_vec();

    let mut selected_cfs = vec![ColumnFamily::Compression, ColumnFamily::Ledger];
    for slot_id in slot_ids {
        let slot_id = SlotId::new(*slot_id);
        selected_cfs.push(ColumnFamily::slot(slot_id));
        if layout.requires_raw_sidecar() {
            selected_cfs.push(ColumnFamily::slot_raw(slot_id));
        } else {
            require_raw_sidecar_absent(&vault_dir, slot_id)?;
        }
    }
    let vault = AsterVault::open(
        &vault_dir,
        vault_id,
        vault_salt,
        VaultOptions {
            dedup_policy: Some(DedupPolicy::Off),
            restore_mvcc_rows: false,
            read_only: true,
            restore_ledger_hook: false,
            selected_cfs: Some(selected_cfs),
            ..VaultOptions::default()
        },
    )?;
    let snapshot = vault.latest_seq();
    let compression = column_state(&vault, snapshot, ColumnFamily::Compression)?;
    let ledger = column_state(&vault, snapshot, ColumnFamily::Ledger)?;
    let mut slots = Vec::with_capacity(slot_ids.len());
    for slot_id in slot_ids {
        let slot_id = SlotId::new(*slot_id);
        let manifest_present = vault
            .read_cf_at(
                snapshot,
                ColumnFamily::Compression,
                &compression_manifest_key(slot_id),
            )?
            .is_some();
        require(
            manifest_present == layout.requires_raw_sidecar(),
            "ISSUE_557_564_FSV_CANDIDATE_LAYOUT_MISMATCH",
            format!(
                "slot={} expected_layout={} manifest_present={manifest_present}",
                slot_id.get(),
                layout.label()
            ),
        )?;
        let raw_cf = ColumnFamily::slot_raw(slot_id);
        let raw = if layout.requires_raw_sidecar() {
            column_state(&vault, snapshot, raw_cf)?
        } else {
            absent_column_state(raw_cf)
        };
        slots.push(json!({
            "slot_id": slot_id.get(),
            "primary": column_state(&vault, snapshot, ColumnFamily::slot(slot_id))?,
            "raw": raw,
        }));
    }
    drop(vault);

    let chain = astrolabe_ingest::verify_chain_vault_path(&vault_dir)?;
    require(
        chain.status == "intact",
        "ISSUE_557_564_FSV_LEDGER_NOT_INTACT",
        &chain.status,
    )?;
    let manifest_store = ManifestStore::open(&vault_dir);
    let current_pointer = manifest_store.current_pointer()?;
    let current_bytes = fs::read(vault_dir.join("CURRENT"))?;
    let manifest_path = vault_dir.join(&current_pointer);
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest = manifest_store.load_current()?;
    let manifest_json = serde_json::to_value(&manifest)?;
    let vault_tree = tree_state(&vault_dir)?;
    let state = json!({
        "config": config,
        "vault_dir": vault_dir,
        "snapshot_seq": snapshot,
        "candidate_layout": layout.label(),
        "manifest": {
            "current_pointer": current_pointer,
            "current_bytes": current_bytes.len(),
            "current_sha256": sha256(&current_bytes),
            "pointed_manifest_bytes": manifest_bytes.len(),
            "pointed_manifest_sha256": sha256(&manifest_bytes),
            "decoded": manifest_json,
        },
        "compression": compression,
        "ledger": {
            "column": ledger,
            "chain": chain,
        },
        "slots": slots,
        "vault_tree": vault_tree,
    });
    let fingerprint = sha256(&serde_json::to_vec(&state)?);
    Ok(json!({"fingerprint": fingerprint, "state": state}))
}

fn load_prepared_input(root: &Path) -> AnyResult<PreparedInput> {
    let input_path = root.join(INPUT_FILE);
    let bytes = fs::read(&input_path)?;
    let raw = serde_json::from_slice::<Value>(&bytes)?;
    let object = raw.as_object().ok_or("mcp-input.json is not an object")?;
    require(
        object.len() == 4
            && object.contains_key("project")
            && object.contains_key("cache_dir")
            && object.contains_key("candidate_slot_ids")
            && object.contains_key("candidate_request"),
        "ISSUE_557_564_FSV_INPUT_CONTRACT_MISMATCH",
        "mcp-input.json must contain exactly project/cache_dir/candidate_slot_ids/candidate_request",
    )?;
    let project = object
        .get("project")
        .and_then(Value::as_str)
        .ok_or("prepared project is not a string")?
        .to_string();
    require(
        project == PROJECT,
        "ISSUE_557_564_FSV_PROJECT_MISMATCH",
        &project,
    )?;
    let cache_dir = PathBuf::from(
        object
            .get("cache_dir")
            .and_then(Value::as_str)
            .ok_or("prepared cache_dir is not a string")?,
    );
    require(
        cache_dir == root.join("cache") && cache_dir.is_dir(),
        "ISSUE_557_564_FSV_CACHE_MISMATCH",
        cache_dir.display(),
    )?;
    let raw_slots = object
        .get("candidate_slot_ids")
        .and_then(Value::as_array)
        .ok_or("prepared candidate_slot_ids is not an array")?;
    let slot_ids = raw_slots
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| "prepared candidate slot is not u16".into())
        })
        .collect::<AnyResult<Vec<_>>>()?;
    require(
        slot_ids.len() == 2 && slot_ids[0] != slot_ids[1],
        "ISSUE_557_564_FSV_CANDIDATE_SET_INVALID",
        format!("slot_ids={slot_ids:?}"),
    )?;
    let candidate_request = object
        .get("candidate_request")
        .cloned()
        .ok_or("prepared candidate_request is absent")?;
    Ok(PreparedInput {
        bytes,
        raw,
        project,
        cache_dir,
        slot_ids,
        candidate_request,
    })
}

fn dispatch_jsonrpc(
    runner: &CbmToolRunner,
    id: u64,
    method: &str,
    params: Value,
) -> AnyResult<JsonRpcExchange> {
    let request = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });
    let request_raw = serde_json::to_string(&request)?;
    let input = format!("{request_raw}\n").into_bytes();
    let mut output = Vec::new();
    astrolabe_server::serve_jsonrpc(runner, Cursor::new(input), &mut output)?;
    let transport_output_raw = String::from_utf8(output)?;
    let response_raw = transport_output_raw
        .trim_end_matches(['\r', '\n'])
        .to_string();
    require(
        !response_raw.is_empty() && !response_raw.contains('\n'),
        "ISSUE_557_564_FSV_JSONRPC_RESPONSE_COUNT_INVALID",
        &transport_output_raw,
    )?;
    let response = serde_json::from_str::<Value>(&response_raw)?;
    require(
        response.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
            && response.get("id").and_then(Value::as_u64) == Some(id),
        "ISSUE_557_564_FSV_JSONRPC_ID_MISMATCH",
        &response_raw,
    )?;
    Ok(JsonRpcExchange {
        request_raw,
        transport_output_raw,
        response_raw,
        response,
    })
}

fn call_optimizer(
    runner: &CbmToolRunner,
    id: u64,
    arguments: &Value,
) -> AnyResult<JsonRpcExchange> {
    dispatch_jsonrpc(
        runner,
        id,
        "tools/call",
        json!({"name": "optimizer_status", "arguments": arguments}),
    )
}

fn tools_list(runner: &CbmToolRunner) -> AnyResult<Value> {
    let exchange = dispatch_jsonrpc(runner, 55_756_400, "tools/list", json!({}))?;
    let tools = exchange.response["result"]["tools"]
        .as_array()
        .ok_or("tools/list response has no tools array")?;
    let optimizer = tools
        .iter()
        .filter(|tool| tool.get("name").and_then(Value::as_str) == Some("optimizer_status"))
        .collect::<Vec<_>>();
    require(
        optimizer.len() == 1,
        "ISSUE_557_564_FSV_OPTIMIZER_TOOL_COUNT_INVALID",
        optimizer.len(),
    )?;
    let schema = &optimizer[0]["inputSchema"];
    let modes = schema["properties"]["mode"]["enum"]
        .as_array()
        .ok_or("optimizer mode enum is absent")?;
    for expected in [
        "status",
        "commission_compression_candidates",
        "select_compression_candidates",
    ] {
        require(
            modes.iter().any(|mode| mode.as_str() == Some(expected)),
            "ISSUE_557_564_FSV_OPTIMIZER_MODE_MISSING",
            expected,
        )?;
    }
    for required_property in [
        "candidate_slot_ids",
        "candidate_request",
        "candidate_receipts",
    ] {
        require(
            schema["properties"].get(required_property).is_some(),
            "ISSUE_557_564_FSV_OPTIMIZER_SCHEMA_FIELD_MISSING",
            required_property,
        )?;
    }
    require(
        schema["properties"]["candidate_slot_ids"]["minItems"] == 2
            && schema["properties"]["candidate_slot_ids"]["maxItems"] == 65_536
            && schema["properties"]["candidate_slot_ids"]["uniqueItems"] == Value::Bool(true)
            && schema["properties"]["candidate_receipts"]["minItems"] == 2
            && schema["properties"]["candidate_receipts"]["maxItems"] == 65_536,
        "ISSUE_557_564_FSV_OPTIMIZER_CANDIDATE_ROSTER_BOUNDS_MISSING",
        schema,
    )?;
    let work_limits = &schema["properties"]["candidate_request"]["properties"]["work_limits"];
    let required_work_limits = work_limits["required"]
        .as_array()
        .ok_or("optimizer work-limit required list is absent")?;
    require(
        work_limits["properties"]
            .as_object()
            .map(|fields| fields.len())
            == Some(11)
            && required_work_limits.len() == 11,
        "ISSUE_557_564_FSV_OPTIMIZER_WORK_LIMIT_SCHEMA_CARDINALITY",
        work_limits,
    )?;
    for required_limit in [
        "maximum_corpus_rows",
        "maximum_held_out_queries",
        "maximum_total_packed_searches",
        "maximum_pairwise_score_evaluations",
        "maximum_coefficient_evaluations",
        "maximum_candidate_slots",
        "maximum_peak_codec_geometry_bytes",
        "maximum_aggregate_codec_retained_entry_and_sample_bound",
        "maximum_aggregate_codec_transform_coefficient_visits",
        "maximum_aggregate_pairwise_score_evaluations",
        "maximum_total_accounted_work_units",
    ] {
        require(
            work_limits["properties"].get(required_limit).is_some()
                && required_work_limits
                    .iter()
                    .any(|field| field.as_str() == Some(required_limit)),
            "ISSUE_557_564_FSV_OPTIMIZER_WORK_LIMIT_MISSING",
            required_limit,
        )?;
    }
    require(
        work_limits["additionalProperties"] == Value::Bool(false),
        "ISSUE_557_564_FSV_OPTIMIZER_WORK_LIMIT_SCHEMA_OPEN",
        work_limits,
    )?;
    require(
        optimizer[0]["description"]
            .as_str()
            .is_some_and(|description| {
                description.contains("Registry compression core only")
                    && description.contains("commission and selection-replay orchestration")
                    && description.contains("Theta(M)")
                    && description.contains("Theta(P log P)")
                    && description.contains("production M/P/open counts are currently unknown")
                    && description.contains("#1137")
                    && description.contains("PC-05/PC-40/PC-43")
                    && description.contains("MXFP4 multi-candidate commission is preflight-refused")
                    && description.contains("exact-key bounded lookup")
                    && description.contains("#1136")
                    && description.contains("PC-03/PC-43")
            }),
        "ISSUE_557_564_FSV_OPTIMIZER_END_TO_END_COST_SCOPE_AMBIGUOUS",
        optimizer[0],
    )?;
    require(
        schema["properties"]["candidate_slot_ids"]["description"]
            .as_str()
            .is_some_and(|description| {
                description.contains("MXFP4 commission is currently preflight-refused")
                    && description.contains("before candidate scan/write")
                    && description.contains("exact-key bounded lookup")
                    && description.contains("#1136")
                    && description.contains("single-candidate diagnostics remain available")
            }),
        "ISSUE_557_564_FSV_OPTIMIZER_MXFP4_COMMISSION_SCOPE_AMBIGUOUS",
        &schema["properties"]["candidate_slot_ids"],
    )?;
    require(
        work_limits["properties"]["maximum_total_packed_searches"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("build-recall"))
            && work_limits["properties"]["maximum_aggregate_codec_retained_entry_and_sample_bound"]
                ["description"]
                .as_str()
                .is_some_and(|description| description.contains("not measured or complete"))
            && work_limits["properties"]["maximum_total_accounted_work_units"]["description"]
                .as_str()
                .is_some_and(|description| {
                    description.contains("other Registry-core validation/source passes")
                        && description.contains("not end-to-end MCP work")
                }),
        "ISSUE_557_564_FSV_OPTIMIZER_WORK_LIMIT_SEMANTICS_AMBIGUOUS",
        work_limits,
    )?;
    let gates = &schema["properties"]["candidate_request"]["properties"]["gates"];
    require(
        gates["properties"]["maximum_working_set_bytes"]["description"]
            .as_str()
            .is_some_and(|description| description.contains("not the transient process peak")),
        "ISSUE_557_564_FSV_OPTIMIZER_RSS_GATE_SEMANTICS_AMBIGUOUS",
        gates,
    )?;
    Ok(json!({
        "exchange": exchange.evidence(),
        "optimizer_definition": optimizer[0],
        "advertised_modes": modes,
    }))
}

fn commission_arguments(input: &PreparedInput) -> Value {
    json!({
        "project": input.project,
        "mode": "commission_compression_candidates",
        "candidate_slot_ids": input.slot_ids,
        "candidate_request": input.candidate_request,
    })
}

fn extract_replay_arguments(
    project: &str,
    commission: &Value,
    expected_slots: &[u16],
) -> AnyResult<(Value, String)> {
    let selected_receipt = commission["selected_configuration"]["receipt_sha256"]
        .as_str()
        .filter(|receipt| receipt.len() == 64)
        .ok_or("commission response has no selected receipt SHA-256")?
        .to_string();
    let candidates =
        commission["selected_configuration"]["measurement"]["candidate_selection"]["candidates"]
            .as_array()
            .filter(|candidates| candidates.len() == expected_slots.len())
            .ok_or("selected receipt has no exact candidate set")?;
    let mut receipts = Vec::with_capacity(candidates.len());
    let mut observed_slots = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let slot_id = candidate["slot_id"]
            .as_u64()
            .and_then(|slot_id| u16::try_from(slot_id).ok())
            .ok_or("selection candidate has no u16 slot_id")?;
        let receipt_sha256 = candidate["receipt_sha256"]
            .as_str()
            .filter(|receipt| receipt.len() == 64)
            .ok_or("selection candidate has no receipt SHA-256")?;
        observed_slots.push(slot_id);
        receipts.push(json!({
            "slot_id": slot_id,
            "receipt_sha256": receipt_sha256,
        }));
    }
    observed_slots.sort_unstable();
    let mut expected = expected_slots.to_vec();
    expected.sort_unstable();
    require(
        observed_slots == expected,
        "ISSUE_557_564_FSV_SELECTION_SET_MISMATCH",
        format!("expected={expected:?} observed={observed_slots:?}"),
    )?;
    receipts.sort_by_key(|receipt| receipt["slot_id"].as_u64());
    Ok((
        json!({
            "project": project,
            "mode": "select_compression_candidates",
            "candidate_receipts": receipts,
        }),
        selected_receipt,
    ))
}

fn verify_commission_payload(payload: &Value, selected_receipt: &str) -> AnyResult<()> {
    let selected = &payload["selected_configuration"];
    require(
        payload["status"] == "commissioned_and_selected"
            && payload["publication_action"] == "selection_receipt_and_current_pointer_published"
            && selected["receipt_sha256"] == selected_receipt
            && selected["measurement"]["build"]["elapsed_ns"]
                .as_u64()
                .is_some_and(|elapsed| elapsed > 0)
            && selected["measurement"]["placement"]["requested_backend"] == "cpu"
            && selected["measurement"]["placement"]["observed_backend"] == "cpu"
            && selected["measurement"]["physical_components"]
                .as_array()
                .is_some_and(|components| !components.is_empty())
            && selected["measurement"]["candidate_selection"]["candidates"]
                .as_array()
                .is_some_and(|candidates| candidates.len() == 2),
        "ISSUE_557_564_FSV_COMMISSION_PAYLOAD_INVALID",
        payload,
    )?;
    let compact_candidates = payload["candidate_evaluations"]
        .as_array()
        .filter(|candidates| candidates.len() == 2)
        .ok_or("commission response has no exact compact candidate roster")?;
    let selected_candidates = selected["measurement"]["candidate_selection"]["candidates"]
        .as_array()
        .ok_or("selected receipt has no candidate roster")?;
    for candidate in compact_candidates {
        let slot_id = candidate["generation"]["slot_id"]
            .as_u64()
            .ok_or("compact commission candidate has no generation slot id")?;
        let receipt_sha256 = candidate["receipt_sha256"]
            .as_str()
            .filter(|digest| digest.len() == 64)
            .ok_or("compact commission candidate has no receipt SHA-256")?;
        let matches_selection = selected_candidates.iter().any(|selected_candidate| {
            selected_candidate["slot_id"].as_u64() == Some(slot_id)
                && selected_candidate["receipt_sha256"].as_str() == Some(receipt_sha256)
        });
        let encoded = serde_json::to_string(candidate)?;
        require(
            matches_selection
                && candidate.get("evaluation").is_none()
                && candidate.get("receipt").is_none()
                && candidate["generation"].get("rows").is_none()
                && candidate["generation"].get("ledger").is_none()
                && !encoded.contains("\"held_out_queries\"")
                && !encoded.contains("\"queries\"")
                && !encoded.contains("\"reconstruction\"")
                && !encoded.contains("\"physical_components\"")
                && !encoded.contains("\"membership_proofs\""),
            "ISSUE_557_564_FSV_COMMISSION_CANDIDATE_PAYLOAD_NOT_COMPACT",
            candidate,
        )?;
    }
    require(
        payload["cost_scope"]["mode"] == "commission_compression_candidates"
            && payload["cost_scope"]["work_limits"] == "candidate_request.work_limits"
            && payload["cost_scope"]["end_to_end_mcp_bounded"] == Value::Bool(false)
            && payload["known_cost_gap"]["mcp_ledger_verification"]["issue"] == 1137
            && payload["known_cost_gap"]["mcp_ledger_verification"]["defect_classes"]
                == json!(["PC-40", "PC-43"])
            && payload["known_cost_gap"]["mcp_ledger_verification"]["operation"]
                .as_str()
                .is_some_and(|operation| operation.contains("pre/post full Ledger-chain"))
            && payload["known_cost_gap"]["mcp_ledger_verification"]["asymptotic_cost"]
                .as_str()
                .is_some_and(|cost| cost.contains("Theta(M)"))
            && payload["known_cost_gap"]["mcp_ledger_verification"]["production_ledger_entries_m"]
                == "unknown"
            && payload["known_cost_gap"]["mcp_ledger_verification"]["production_store_open_count"]
                == "unknown"
            && payload["known_cost_gap"]["mcp_ledger_verification"]["bounded_by_candidate_request_work_limits"]
                == Value::Bool(false)
            && payload["known_cost_gap"]["mcp_panel_roster_resolution"]["issue"] == 1137
            && payload["known_cost_gap"]["mcp_panel_roster_resolution"]["defect_classes"]
                == json!(["PC-05", "PC-43"])
            && payload["known_cost_gap"]["mcp_panel_roster_resolution"]["asymptotic_cost"]
                .as_str()
                .is_some_and(|cost| cost.contains("Theta(P log P + C log P)"))
            && payload["known_cost_gap"]["mcp_panel_roster_resolution"]["production_panel_slots_p"]
                == "unknown"
            && payload["known_cost_gap"]["mcp_panel_roster_resolution"]["bounded_by_candidate_request_work_limits"]
                == Value::Bool(false),
        "ISSUE_557_564_FSV_COMMISSION_END_TO_END_COST_GAP_MISSING",
        payload,
    )?;
    require(
        payload["known_cost_gap"]["mxfp4_commission_evidence"]["issue"] == 1136
            && payload["known_cost_gap"]["mxfp4_commission_evidence"]["defect_classes"]
                == json!(["PC-03", "PC-43"])
            && payload["known_cost_gap"]["mxfp4_commission_evidence"]["current_behavior"]
                .as_str()
                .is_some_and(|behavior| {
                    behavior.contains("preflight-refuses MXFP4 before candidate scan/write")
                })
            && payload["known_cost_gap"]["mxfp4_commission_evidence"]["required_bounded_primitive"]
                == "exact-key bounded initial Assay evidence lookup"
            && payload["known_cost_gap"]["mxfp4_commission_evidence"]["single_candidate_diagnostic_behavior"]
                == "unchanged",
        "ISSUE_557_564_FSV_COMMISSION_MXFP4_LIMITATION_MISSING",
        payload,
    )?;
    require(
        payload["source_state"]["preflight"]
            .as_str()
            .is_some_and(|preflight| {
                preflight.contains("allocation-free slot/lens descriptors")
                    && preflight.contains("raw/Base identity bindings")
                    && preflight.contains("absent fresh compressed manifest")
                    && preflight.contains("canonical corpus equality")
                    && preflight.contains("work/limits")
                    && preflight.contains("query disjointness")
                    && preflight.contains("CPU backend")
                    && preflight.contains("Codec-context creation begins during build")
            }),
        "ISSUE_557_564_FSV_COMMISSION_PREFLIGHT_SCOPE_INACCURATE",
        payload,
    )
}

fn verify_selection_replay_cost_payload(payload: &Value) -> AnyResult<()> {
    require(
        payload["cost_scope"]["mode"] == "select_compression_candidates"
            && payload["cost_scope"]["bounded_path"]
                .as_str()
                .is_some_and(|path| path.contains("exact-receipt streaming"))
            && payload["cost_scope"]["work_limits"]
                == "canonical work/limits persisted in the exact source receipts"
            && payload["cost_scope"]["end_to_end_mcp_bounded"] == Value::Bool(false)
            && payload["known_cost_gap"]["mcp_ledger_verification"]["issue"] == 1137
            && payload["known_cost_gap"]["mcp_ledger_verification"]["defect_classes"]
                == json!(["PC-40", "PC-43"])
            && payload["known_cost_gap"]["mcp_ledger_verification"]["operation"]
                .as_str()
                .is_some_and(|operation| {
                    operation.contains("commission/selection-replay pre/post full Ledger-chain")
                })
            && payload["known_cost_gap"]["mcp_ledger_verification"]["asymptotic_cost"]
                .as_str()
                .is_some_and(|cost| cost.contains("Theta(M)"))
            && payload["known_cost_gap"]["mcp_ledger_verification"]["production_ledger_entries_m"]
                == "unknown"
            && payload["known_cost_gap"]["mcp_ledger_verification"]["production_store_open_count"]
                == "unknown"
            && payload["known_cost_gap"]["mcp_ledger_verification"]["bounded_by_candidate_request_work_limits"]
                == Value::Bool(false)
            && payload["known_cost_gap"]["mcp_panel_roster_resolution"]["issue"] == 1137
            && payload["known_cost_gap"]["mcp_panel_roster_resolution"]["defect_classes"]
                == json!(["PC-05", "PC-43"])
            && payload["known_cost_gap"]["mcp_panel_roster_resolution"]["asymptotic_cost"]
                .as_str()
                .is_some_and(|cost| cost.contains("Theta(P log P + C log P)"))
            && payload["known_cost_gap"]["mcp_panel_roster_resolution"]["production_panel_slots_p"]
                == "unknown"
            && payload["known_cost_gap"]["mcp_panel_roster_resolution"]["bounded_by_candidate_request_work_limits"]
                == Value::Bool(false),
        "ISSUE_557_564_FSV_SELECTION_REPLAY_COST_GAP_MISSING",
        payload,
    )
}

fn verify_status_payload(
    payload: &Value,
    slot_ids: &[u16],
    selected_receipt: &str,
    expected_shadow_ledger_checkpoint: &Value,
) -> AnyResult<Value> {
    let admission = &payload["compression_admission"];
    let slots = admission["slots"]
        .as_array()
        .ok_or("optimizer status has no compression slots")?;
    let mut relevant = Vec::new();
    let mut latest_states = Vec::new();
    let mut current_receipts = Vec::new();
    for slot_id in slot_ids {
        let matches = slots
            .iter()
            .filter(|slot| slot["slot_id"].as_u64() == Some(u64::from(*slot_id)))
            .collect::<Vec<_>>();
        require(
            matches.len() == 1,
            "ISSUE_557_564_FSV_STATUS_SLOT_COUNT_INVALID",
            format!("slot_id={slot_id} matches={}", matches.len()),
        )?;
        let slot = matches[0];
        latest_states.push(
            slot["state"]["latest_evaluation"]
                .as_str()
                .ok_or("status latest state is not a string")?
                .to_string(),
        );
        if let Some(receipt) = slot["current_admission"]["receipt_sha256"].as_str() {
            current_receipts.push(receipt.to_string());
        }
        relevant.push((*slot).clone());
    }
    latest_states.sort();
    require(
        latest_states.len() == 2
            && latest_states[0] == "admitted"
            && latest_states[1] == "candidate_evaluated"
            && current_receipts.len() == 1
            && current_receipts[0] == selected_receipt,
        "ISSUE_557_564_FSV_STATUS_STATE_MISMATCH",
        format!("latest={latest_states:?} current={current_receipts:?}"),
    )?;
    require(
        payload["source_state"]["shadow_ledger_checkpoint"] == *expected_shadow_ledger_checkpoint,
        "ISSUE_557_564_FSV_STATUS_LEDGER_CHECKPOINT_MISMATCH",
        &payload["source_state"]["shadow_ledger_checkpoint"],
    )?;
    Ok(json!({
        "relevant_slots": relevant,
        "latest_states": latest_states,
        "current_receipts": current_receipts,
        "state_counts": admission["state_counts"],
    }))
}

struct RefusalRequest<'a> {
    runner: &'a CbmToolRunner,
    id: u64,
    case: &'a str,
    arguments: &'a Value,
    expected_code: &'a str,
    expected_preflight_stage: Option<&'a str>,
    cache_dir: &'a Path,
    project: &'a str,
    slot_ids: &'a [u16],
    layout: CandidateLayout,
}

fn expect_refusal(request: RefusalRequest<'_>) -> AnyResult<Value> {
    let RefusalRequest {
        runner,
        id,
        case,
        arguments,
        expected_code,
        expected_preflight_stage,
        cache_dir,
        project,
        slot_ids,
        layout,
    } = request;
    let before = physical_state(cache_dir, project, slot_ids, layout)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "before", "physical": before}))?
    );
    let exchange = call_optimizer(runner, id, arguments)?;
    let (payload, is_error) = exchange.tool_result()?;
    require(
        is_error
            && payload["status"] == "error"
            && payload["code"] == expected_code
            && payload["remediation"]
                .as_str()
                .is_some_and(|remediation| !remediation.trim().is_empty()),
        "ISSUE_557_564_FSV_REFUSAL_CONTRACT_MISMATCH",
        format!("case={case} payload={payload}"),
    )?;
    if let Some(expected_stage) = expected_preflight_stage {
        require(
            payload["stage"] == expected_stage
                && payload["vault_or_manifest_opened"] == Value::Bool(false)
                && payload["ledger_chain_scanned"] == Value::Bool(false),
            "ISSUE_557_564_FSV_REFUSAL_PAID_STATE_IO_BEFORE_PREFLIGHT",
            format!("case={case} payload={payload}"),
        )?;
    }
    let after = physical_state(cache_dir, project, slot_ids, layout)?;
    println!(
        "{}",
        serde_json::to_string(&json!({"case": case, "phase": "after", "physical": after}))?
    );
    require(
        before["fingerprint"] == after["fingerprint"],
        "ISSUE_557_564_FSV_REFUSAL_MUTATED_STATE",
        format!(
            "case={case} before={} after={}",
            before["fingerprint"], after["fingerprint"]
        ),
    )?;
    Ok(json!({
        "case": case,
        "expected_code": expected_code,
        "exchange": exchange.evidence(),
        "payload": payload,
        "before": before,
        "after": after,
        "byte_stable": true,
        "preflight_before_vault_manifest_or_ledger_io": expected_preflight_stage,
    }))
}

fn run(root: PathBuf) -> AnyResult<()> {
    require(
        root.is_dir(),
        "ISSUE_557_564_FSV_ROOT_MISSING",
        root.display(),
    )?;
    let output_path = root.join(OUTPUT_FILE);
    require(
        !output_path.exists(),
        "ISSUE_557_564_FSV_OUTPUT_PREEXISTS",
        output_path.display(),
    )?;
    let input = load_prepared_input(&root)?;
    let cache_readback = set_cbm_cache_dir(&input.cache_dir)?;
    require(
        cache_readback == input.cache_dir,
        "ISSUE_557_564_FSV_CACHE_READBACK_MISMATCH",
        format!(
            "requested={} observed={}",
            input.cache_dir.display(),
            cache_readback.display()
        ),
    )?;
    initialize_cbm_host_process()?;
    let runner = CbmToolRunner::new_default()?;
    let tools = tools_list(&runner)?;

    let commission_args = commission_arguments(&input);
    let commission_before = physical_state(
        &input.cache_dir,
        &input.project,
        &input.slot_ids,
        CandidateLayout::RawUnmanifested,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": "commission_happy",
            "phase": "before",
            "physical": commission_before,
        }))?
    );
    let commission_exchange = call_optimizer(&runner, 55_756_401, &commission_args)?;
    let (commission_payload, commission_error) = commission_exchange.tool_result()?;
    require(
        !commission_error,
        "ISSUE_557_564_FSV_COMMISSION_FAILED",
        commission_payload,
    )?;
    let (replay_args, selected_receipt) =
        extract_replay_arguments(&input.project, commission_payload, &input.slot_ids)?;
    verify_commission_payload(commission_payload, &selected_receipt)?;
    let commission_after = physical_state(
        &input.cache_dir,
        &input.project,
        &input.slot_ids,
        CandidateLayout::CompressedWithRawSidecar,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "case": "commission_happy",
            "phase": "after",
            "physical": commission_after,
        }))?
    );
    require(
        commission_before["fingerprint"] != commission_after["fingerprint"]
            && commission_before["state"]["config"] == commission_after["state"]["config"]
            && commission_before["state"]["manifest"]["decoded"]["panel_ref"]
                == commission_after["state"]["manifest"]["decoded"]["panel_ref"]
            && commission_before["state"]["manifest"]["decoded"]["registry_ref"]
                == commission_after["state"]["manifest"]["decoded"]["registry_ref"]
            && commission_before["state"]["ledger"]["column"]["rows"]
                .as_u64()
                .zip(commission_after["state"]["ledger"]["column"]["rows"].as_u64())
                .is_some_and(|(before, after)| after > before),
        "ISSUE_557_564_FSV_COMMISSION_PHYSICAL_STATE_INVALID",
        "commission did not change durable admission state while preserving Config and immutable Panel/Registry refs",
    )?;

    let status_args = json!({"project": input.project, "mode": "status"});
    let status_before = physical_state(
        &input.cache_dir,
        &input.project,
        &input.slot_ids,
        CandidateLayout::CompressedWithRawSidecar,
    )?;
    let checkpoint_key = format!(
        "astrolabe.calyx.{}.{SHADOW_LEDGER_CHECKPOINT_KEY}",
        input.project
    );
    let expected_shadow_ledger_checkpoint = serde_json::from_str::<Value>(
        status_before["state"]["config"]["rows"]
            .get(&checkpoint_key)
            .and_then(Value::as_str)
            .ok_or("prepared MCP config has no shadow Ledger checkpoint row")?,
    )?;
    let status_exchange = call_optimizer(&runner, 55_756_402, &status_args)?;
    let (status_payload, status_error) = status_exchange.tool_result()?;
    require(
        !status_error,
        "ISSUE_557_564_FSV_STATUS_FAILED",
        status_payload,
    )?;
    let status_evidence = verify_status_payload(
        status_payload,
        &input.slot_ids,
        &selected_receipt,
        &expected_shadow_ledger_checkpoint,
    )?;
    let status_after = physical_state(
        &input.cache_dir,
        &input.project,
        &input.slot_ids,
        CandidateLayout::CompressedWithRawSidecar,
    )?;
    require(
        status_before["fingerprint"] == status_after["fingerprint"],
        "ISSUE_557_564_FSV_STATUS_MUTATED_STATE",
        "optimizer status changed physical state",
    )?;

    let replay_before = physical_state(
        &input.cache_dir,
        &input.project,
        &input.slot_ids,
        CandidateLayout::CompressedWithRawSidecar,
    )?;
    let replay_exchange = call_optimizer(&runner, 55_756_403, &replay_args)?;
    let (replay_payload, replay_error) = replay_exchange.tool_result()?;
    require(
        !replay_error
            && replay_payload["publication_action"] == "idempotent_current_readback"
            && replay_payload["selected_configuration"]["receipt_sha256"] == selected_receipt
            && replay_payload["before_vault_seq"] == replay_payload["after_vault_seq"],
        "ISSUE_557_564_FSV_REPLAY_INVALID",
        replay_payload,
    )?;
    verify_selection_replay_cost_payload(replay_payload)?;
    let replay_after = physical_state(
        &input.cache_dir,
        &input.project,
        &input.slot_ids,
        CandidateLayout::CompressedWithRawSidecar,
    )?;
    require(
        replay_before["fingerprint"] == replay_after["fingerprint"],
        "ISSUE_557_564_FSV_REPLAY_MUTATED_STATE",
        "exact selector replay changed physical state",
    )?;

    let repeat_before = physical_state(
        &input.cache_dir,
        &input.project,
        &input.slot_ids,
        CandidateLayout::CompressedWithRawSidecar,
    )?;
    let repeat_exchange = call_optimizer(&runner, 55_756_404, &replay_args)?;
    let (repeat_payload, repeat_error) = repeat_exchange.tool_result()?;
    require(
        !repeat_error
            && repeat_payload["publication_action"] == "idempotent_current_readback"
            && repeat_payload["selected_configuration"]["receipt_sha256"] == selected_receipt
            && repeat_payload["before_vault_seq"] == repeat_payload["after_vault_seq"],
        "ISSUE_557_564_FSV_IDEMPOTENT_REPEAT_INVALID",
        repeat_payload,
    )?;
    verify_selection_replay_cost_payload(repeat_payload)?;
    let repeat_after = physical_state(
        &input.cache_dir,
        &input.project,
        &input.slot_ids,
        CandidateLayout::CompressedWithRawSidecar,
    )?;
    require(
        repeat_before["fingerprint"] == repeat_after["fingerprint"],
        "ISSUE_557_564_FSV_IDEMPOTENT_REPEAT_MUTATED_STATE",
        "idempotent selector repeat changed physical state",
    )?;

    let mut duplicate_replay = replay_args.clone();
    let replay_receipts = duplicate_replay["candidate_receipts"]
        .as_array_mut()
        .ok_or("selection replay candidate_receipts are not an array")?;
    require(
        replay_receipts.len() >= 2,
        "ISSUE_557_564_FSV_REPLAY_FIXTURE_TOO_SMALL",
        replay_receipts.len(),
    )?;
    replay_receipts[1]["slot_id"] = replay_receipts[0]["slot_id"].clone();
    let duplicate_replay_edge = expect_refusal(RefusalRequest {
        runner: &runner,
        id: 55_756_405,
        case: "duplicate_selection_replay_slot",
        arguments: &duplicate_replay,
        expected_code: "ASTRO_OPTIMIZER_COMPRESSION_RECEIPT_DUPLICATE_SLOT",
        expected_preflight_stage: Some(RECEIPT_PARSE_PREFLIGHT_STAGE),
        cache_dir: &input.cache_dir,
        project: &input.project,
        slot_ids: &input.slot_ids,
        layout: CandidateLayout::CompressedWithRawSidecar,
    })?;

    let mut duplicate_query = commission_args.clone();
    let queries = duplicate_query["candidate_request"]["queries"]
        .as_array_mut()
        .ok_or("candidate queries are not an array")?;
    require(
        queries.len() >= 2,
        "ISSUE_557_564_FSV_QUERY_FIXTURE_TOO_SMALL",
        queries.len(),
    )?;
    queries[1]["cx_id"] = queries[0]["cx_id"].clone();
    let duplicate_query_edge = expect_refusal(RefusalRequest {
        runner: &runner,
        id: 55_756_410,
        case: "duplicate_query_cx_id",
        arguments: &duplicate_query,
        expected_code: "CALYX_COMPRESSION_ADMISSION_REFUSED",
        expected_preflight_stage: Some(OPERATION_PREFLIGHT_STAGE),
        cache_dir: &input.cache_dir,
        project: &input.project,
        slot_ids: &input.slot_ids,
        layout: CandidateLayout::CompressedWithRawSidecar,
    })?;

    let mut duplicate_slot = commission_args.clone();
    duplicate_slot["candidate_slot_ids"] = json!([input.slot_ids[0], input.slot_ids[0]]);
    let duplicate_slot_edge = expect_refusal(RefusalRequest {
        runner: &runner,
        id: 55_756_411,
        case: "duplicate_candidate_slot",
        arguments: &duplicate_slot,
        expected_code: "ASTRO_OPTIMIZER_COMPRESSION_SLOT_DUPLICATE",
        expected_preflight_stage: Some(SLOT_PARSE_PREFLIGHT_STAGE),
        cache_dir: &input.cache_dir,
        project: &input.project,
        slot_ids: &input.slot_ids,
        layout: CandidateLayout::CompressedWithRawSidecar,
    })?;

    let mut single_candidate = commission_args.clone();
    single_candidate["candidate_slot_ids"] = json!([input.slot_ids[0]]);
    let single_candidate_edge = expect_refusal(RefusalRequest {
        runner: &runner,
        id: 55_756_412,
        case: "single_candidate_commission",
        arguments: &single_candidate,
        expected_code: "ASTRO_OPTIMIZER_COMPRESSION_SLOT_COUNT_INVALID",
        expected_preflight_stage: Some(SLOT_COUNT_PREFLIGHT_STAGE),
        cache_dir: &input.cache_dir,
        project: &input.project,
        slot_ids: &input.slot_ids,
        layout: CandidateLayout::CompressedWithRawSidecar,
    })?;

    let mut query_limit = commission_args.clone();
    let query_count = query_limit["candidate_request"]["queries"]
        .as_array()
        .map(Vec::len)
        .ok_or("candidate queries are not an array")?;
    require(
        query_count > 1,
        "ISSUE_557_564_FSV_QUERY_FIXTURE_TOO_SMALL",
        query_count,
    )?;
    query_limit["candidate_request"]["work_limits"]["maximum_held_out_queries"] =
        json!(query_count - 1);
    let query_limit_edge = expect_refusal(RefusalRequest {
        runner: &runner,
        id: 55_756_413,
        case: "held_out_query_exact_minus_one_limit",
        arguments: &query_limit,
        expected_code: "CALYX_COMPRESSION_ADMISSION_REFUSED",
        expected_preflight_stage: Some(OPERATION_PREFLIGHT_STAGE),
        cache_dir: &input.cache_dir,
        project: &input.project,
        slot_ids: &input.slot_ids,
        layout: CandidateLayout::CompressedWithRawSidecar,
    })?;

    let mut lifecycle_limit = commission_args.clone();
    let lifecycle_searches =
        lifecycle_limit["candidate_request"]["work_limits"]["maximum_total_packed_searches"]
            .as_u64()
            .filter(|value| *value > 1)
            .ok_or("lifecycle packed-search fixture limit is not positive")?;
    lifecycle_limit["candidate_request"]["work_limits"]["maximum_total_packed_searches"] =
        json!(lifecycle_searches - 1);
    let lifecycle_limit_edge = expect_refusal(RefusalRequest {
        runner: &runner,
        id: 55_756_414,
        case: "lifecycle_packed_search_exact_minus_one_limit",
        arguments: &lifecycle_limit,
        expected_code: "CALYX_COMPRESSION_ADMISSION_REFUSED",
        expected_preflight_stage: Some(OPERATION_PREFLIGHT_STAGE),
        cache_dir: &input.cache_dir,
        project: &input.project,
        slot_ids: &input.slot_ids,
        layout: CandidateLayout::CompressedWithRawSidecar,
    })?;

    let mut invalid_runs = commission_args.clone();
    invalid_runs["candidate_request"]["measured_runs"] = json!(2);
    let invalid_runs_edge = expect_refusal(RefusalRequest {
        runner: &runner,
        id: 55_756_415,
        case: "measured_runs_below_schema_minimum",
        arguments: &invalid_runs,
        expected_code: "ASTRO_MCP_ARGUMENT_BOUND_INVALID",
        expected_preflight_stage: None,
        cache_dir: &input.cache_dir,
        project: &input.project,
        slot_ids: &input.slot_ids,
        layout: CandidateLayout::CompressedWithRawSidecar,
    })?;

    let mut invalid_backend = commission_args.clone();
    invalid_backend["candidate_request"]["requested_backend"] = json!("cuda");
    let invalid_backend_edge = expect_refusal(RefusalRequest {
        runner: &runner,
        id: 55_756_416,
        case: "unsupported_cuda_backend",
        arguments: &invalid_backend,
        expected_code: "CALYX_COMPRESSION_ADMISSION_REFUSED",
        expected_preflight_stage: Some(OPERATION_PREFLIGHT_STAGE),
        cache_dir: &input.cache_dir,
        project: &input.project,
        slot_ids: &input.slot_ids,
        layout: CandidateLayout::CompressedWithRawSidecar,
    })?;

    let mut invalid_gates = commission_args.clone();
    invalid_gates["candidate_request"]["gates"]["maximum_mean_cosine_error"] = json!(0.75);
    invalid_gates["candidate_request"]["gates"]["maximum_cosine_error"] = json!(0.5);
    let invalid_gates_edge = expect_refusal(RefusalRequest {
        runner: &runner,
        id: 55_756_417,
        case: "incoherent_cosine_error_gates",
        arguments: &invalid_gates,
        expected_code: "CALYX_COMPRESSION_ADMISSION_REFUSED",
        expected_preflight_stage: Some(OPERATION_PREFLIGHT_STAGE),
        cache_dir: &input.cache_dir,
        project: &input.project,
        slot_ids: &input.slot_ids,
        layout: CandidateLayout::CompressedWithRawSidecar,
    })?;

    let final_state = physical_state(
        &input.cache_dir,
        &input.project,
        &input.slot_ids,
        CandidateLayout::CompressedWithRawSidecar,
    )?;
    require(
        final_state["fingerprint"] == commission_after["fingerprint"],
        "ISSUE_557_564_FSV_FINAL_STATE_DRIFT",
        "status/replay/refusal probes changed the commissioned source of truth",
    )?;
    let report = json!({
        "schema": "astrolabe.issue-557-564.compression-mcp-fsv.v1",
        "project": input.project,
        "source_of_truth": "driver-prepared query_only _config.db; CURRENT and its immutable MANIFEST; physical raw-sidecar namespace absence before commission; independently scanned candidate primary and representation-required raw, Compression, and Ledger column families after commission; intact physical Ledger chain; complete vault-file hashes",
        "input": {
            "path": root.join(INPUT_FILE),
            "bytes": input.bytes.len(),
            "sha256": sha256(&input.bytes),
            "json": input.raw,
        },
        "tools_list": tools,
        "commission": {
            "arguments": commission_args,
            "exchange": commission_exchange.evidence(),
            "payload": commission_payload,
            "before": commission_before,
            "after": commission_after,
        },
        "independent_status": {
            "exchange": status_exchange.evidence(),
            "payload": status_payload,
            "verified_slots": status_evidence,
            "before": status_before,
            "after": status_after,
            "byte_stable": true,
        },
        "selector_replay": {
            "arguments": replay_args,
            "exchange": replay_exchange.evidence(),
            "payload": replay_payload,
            "before": replay_before,
            "after": replay_after,
            "byte_stable": true,
        },
        "idempotent_repeat": {
            "exchange": repeat_exchange.evidence(),
            "payload": repeat_payload,
            "before": repeat_before,
            "after": repeat_after,
            "byte_stable": true,
        },
        "malformed_calls": [
            duplicate_query_edge,
            duplicate_slot_edge,
            duplicate_replay_edge,
            single_candidate_edge,
            query_limit_edge,
            lifecycle_limit_edge,
            invalid_runs_edge,
            invalid_backend_edge,
            invalid_gates_edge,
        ],
        "selected_current_receipt_sha256": selected_receipt,
        "final_state": final_state,
    });
    let report_bytes = serde_json::to_vec_pretty(&report)?;
    write_exact(&output_path, &report_bytes)?;
    println!(
        "ISSUE_557_564_COMPRESSION_MCP_FSV_SOURCE_OF_TRUTH path={} bytes={} sha256={} report={}",
        output_path.display(),
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
    if process_args.len() != 1 {
        fail(
            "ISSUE_557_564_FSV_ARGUMENT_UNKNOWN",
            "this executable accepts no arguments",
            "set ASTROLABE_COMPRESSION_FSV_ROOT to the driver-prepared root",
        );
    }
    let root = std::env::var_os(ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            fail(
                "ISSUE_557_564_FSV_ROOT_REQUIRED",
                format!("{ROOT_ENV} is unset"),
                "run compression_admission_fsv prepare_mcp, then set its exact root",
            )
        });
    if let Err(error) = run(root) {
        fail(
            "ISSUE_557_564_COMPRESSION_MCP_FSV_FAILED",
            error,
            "preserve the driver root and inspect the first physical or JSON-RPC mismatch",
        );
    }
}
