use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use astrolabe_bridge::CbmToolRunner;
use astrolabe_ingest::{SqliteImportOptions, import_sqlite_to_vault, verify_chain};
use astrolabe_panel::{DEFAULT_PANEL_VERSION, PanelInput, PanelResult, PanelSlotSpec, SlotRuntime};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{AbsentReason, SlotVector, VaultId};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};

use crate::DynError;

const CONFIG_KEY_PREFIX: &str = "astrolabe.calyx.";
const SHADOW_VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const VAULT_SUFFIX: &str = ".astrolabe-vault";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MigrationDial {
    Off,
    Shadow,
}

impl MigrationDial {
    fn parse(value: &Value) -> Result<Self, String> {
        match value.as_str() {
            Some("off") => Ok(Self::Off),
            Some("shadow") => Ok(Self::Shadow),
            Some(other) => Err(format!(
                "invalid calyx dial {other:?}; expected \"off\" or \"shadow\""
            )),
            None => Err("invalid calyx dial; expected string \"off\" or \"shadow\"".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
        }
    }
}

#[derive(Debug, Clone)]
struct ShadowImportOutcome {
    vault_dir: PathBuf,
    vault_id: String,
    vault_salt: String,
    sqlite_path: PathBuf,
    sqlite_fingerprint_sha256: String,
    sqlite_nodes: usize,
    sqlite_edges: usize,
    constellation_inputs: usize,
    ledger_seq: u64,
    ledger_rows_after: usize,
    verify_chain_status: String,
}

#[derive(Debug)]
struct ShadowSlotRuntime;

impl SlotRuntime for ShadowSlotRuntime {
    fn measure_slot(&self, _slot: &PanelSlotSpec, _input: &PanelInput) -> PanelResult<SlotVector> {
        Ok(SlotVector::Absent {
            reason: AbsentReason::LensUnavailable,
        })
    }
}

pub fn handle_tool_raw(
    runner: &CbmToolRunner,
    tool_name: &str,
    args_json: &str,
) -> Result<String, DynError> {
    match tool_name {
        "index_repository" => handle_index_repository(runner, args_json),
        "index_status" => handle_index_status(runner, args_json),
        _ => Ok(runner.handle_tool_raw(tool_name, args_json)?),
    }
}

pub fn handle_jsonrpc_raw(
    runner: &CbmToolRunner,
    request_json: &str,
) -> Result<Option<String>, DynError> {
    let Ok(request) = serde_json::from_str::<Value>(request_json) else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    let Some(request_obj) = request.as_object() else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    if request_obj
        .get("method")
        .and_then(Value::as_str)
        .is_none_or(|method| method != "tools/call")
    {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    }

    let Some(id) = request_obj
        .get("id")
        .filter(|id| id.is_string() || id.is_number())
    else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    let Some(params) = request_obj.get("params").and_then(Value::as_object) else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    let Some(tool_name) = params.get("name").and_then(Value::as_str) else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    if tool_name != "index_repository" && tool_name != "index_status" {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    }

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let Some(args_obj) = arguments.as_object() else {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    };
    if !should_wrap_tool(tool_name, args_obj)? {
        return Ok(runner.handle_jsonrpc_raw(request_json)?);
    }

    let args_json = serde_json::to_string(&arguments)?;
    let result_raw = handle_tool_raw(runner, tool_name, &args_json)?;
    Ok(Some(jsonrpc_result_response(id.clone(), &result_raw)?))
}

fn should_wrap_tool(tool_name: &str, args: &Map<String, Value>) -> Result<bool, DynError> {
    match tool_name {
        "index_repository" => {
            if args.contains_key("calyx") {
                return Ok(true);
            }
            let Some(project) = index_project_from_args(args)? else {
                return Ok(false);
            };
            Ok(read_dial(&project)? == MigrationDial::Shadow)
        }
        "index_status" => {
            let Some(project) = status_project_from_args(args)? else {
                return Ok(false);
            };
            Ok(read_dial(&project)? == MigrationDial::Shadow)
        }
        _ => Ok(false),
    }
}

fn handle_index_repository(runner: &CbmToolRunner, args_json: &str) -> Result<String, DynError> {
    let Ok(args) = serde_json::from_str::<Value>(args_json) else {
        return Ok(runner.handle_tool_raw("index_repository", args_json)?);
    };
    let Some(args_obj) = args.as_object() else {
        return Ok(runner.handle_tool_raw("index_repository", args_json)?);
    };

    let project = index_project_from_args(args_obj)?;
    let explicit_dial = args_obj.get("calyx");
    let dial = match explicit_dial {
        Some(value) => match MigrationDial::parse(value) {
            Ok(dial) => dial,
            Err(message) => return tool_error_result(message),
        },
        None => project
            .as_ref()
            .map(|project| read_dial(project))
            .transpose()?
            .unwrap_or(MigrationDial::Off),
    };

    if explicit_dial.is_none() && dial == MigrationDial::Off {
        return Ok(runner.handle_tool_raw("index_repository", args_json)?);
    }

    let sanitized_args = strip_calyx_arg(args_obj)?;
    let result = runner.handle_tool_raw("index_repository", &sanitized_args)?;
    if tool_result_is_error(&result)? {
        return Ok(result);
    }

    let project = project
        .or_else(|| project_from_tool_result(&result))
        .ok_or("index_repository succeeded without a project name")?;
    persist_dial(&project, dial)?;
    if dial == MigrationDial::Off {
        return Ok(result);
    }

    let outcome = match import_shadow_vault(&project) {
        Ok(outcome) => outcome,
        Err(error) => return tool_error_result(format!("shadow import failed: {error}")),
    };
    persist_shadow_outcome(&project, &outcome)?;
    augment_tool_result(
        &result,
        json!({
            "calyx": "shadow",
            "vault_fingerprint": outcome.sqlite_fingerprint_sha256,
            "grounding_summary": grounding_summary(&outcome),
        }),
    )
}

fn handle_index_status(runner: &CbmToolRunner, args_json: &str) -> Result<String, DynError> {
    let Ok(args) = serde_json::from_str::<Value>(args_json) else {
        return Ok(runner.handle_tool_raw("index_status", args_json)?);
    };
    let Some(args_obj) = args.as_object() else {
        return Ok(runner.handle_tool_raw("index_status", args_json)?);
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return Ok(runner.handle_tool_raw("index_status", args_json)?);
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return Ok(runner.handle_tool_raw("index_status", args_json)?);
    }

    let result = runner.handle_tool_raw("index_status", args_json)?;
    if tool_result_is_error(&result)? {
        return Ok(result);
    }
    if let Err(error) = ensure_shadow_import_current(&project) {
        return tool_error_result(format!("shadow import recovery failed: {error}"));
    }
    augment_tool_result(&result, shadow_status_summary(&project)?)
}

fn ensure_shadow_import_current(project: &str) -> Result<(), DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    if !sqlite_path(&cache_dir, project).exists() {
        return Ok(());
    }

    let fingerprint = read_config_value(&cache_dir, &metadata_key(project, "vault_fingerprint"))?;
    let configured_vault_dir = read_config_value(&cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(&cache_dir, project));
    let verify_intact = configured_vault_dir.exists()
        && astrolabe_ingest::verify_chain_vault_path(&configured_vault_dir)
            .map(|report| report.is_intact())
            .unwrap_or(false);
    if fingerprint.is_some() && verify_intact {
        return Ok(());
    }

    let outcome = import_shadow_vault(project)?;
    persist_shadow_outcome(project, &outcome)
}

fn import_shadow_vault(project: &str) -> Result<ShadowImportOutcome, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    fs::create_dir_all(&cache_dir)?;
    let sqlite_path = sqlite_path(&cache_dir, project);
    if !sqlite_path.exists() {
        return Err(format!(
            "CBM SQLite store is missing after index_repository: {}",
            sqlite_path.display()
        )
        .into());
    }

    let vault_dir = vault_dir(&cache_dir, project);
    fs::create_dir_all(&vault_dir)?;
    let vault_id = VaultId::from_str(SHADOW_VAULT_ID)?;
    let vault_salt = vault_salt(project);
    let vault = AsterVault::new_durable(
        &vault_dir,
        vault_id,
        vault_salt.as_bytes().to_vec(),
        VaultOptions::default(),
    )?;
    let options = SqliteImportOptions::new(
        project,
        format!("shadow-import-v1:{project}"),
        DEFAULT_PANEL_VERSION,
    )
    .with_available_slots(std::iter::empty());
    let report = import_sqlite_to_vault(&sqlite_path, &vault, &ShadowSlotRuntime, &options)?;
    let verify = verify_chain(&vault)?;
    if !verify.is_intact() {
        return Err(format!(
            "shadow vault ledger verification failed after import: {}",
            verify.status
        )
        .into());
    }

    Ok(ShadowImportOutcome {
        vault_dir,
        vault_id: SHADOW_VAULT_ID.to_string(),
        vault_salt,
        sqlite_path,
        sqlite_fingerprint_sha256: hex_lower(&report.sqlite_fingerprint_sha256),
        sqlite_nodes: report.sqlite_nodes,
        sqlite_edges: report.sqlite_edges,
        constellation_inputs: report.constellation_inputs,
        ledger_seq: report.ledger_seq,
        ledger_rows_after: report.ledger_rows_after,
        verify_chain_status: verify.status,
    })
}

fn grounding_summary(outcome: &ShadowImportOutcome) -> Value {
    json!({
        "status": "imported",
        "sqlite_nodes": outcome.sqlite_nodes,
        "sqlite_edges": outcome.sqlite_edges,
        "constellation_inputs": outcome.constellation_inputs,
        "sqlite_path": outcome.sqlite_path,
        "vault_dir": outcome.vault_dir,
        "vault_id": outcome.vault_id,
        "vault_salt": outcome.vault_salt,
        "ledger_seq": outcome.ledger_seq,
        "ledger_rows_after": outcome.ledger_rows_after,
        "verify_chain": outcome.verify_chain_status,
        "panel_version": DEFAULT_PANEL_VERSION,
        "panel_runtime": "lens_unavailable",
        "stores": stores_summary(&outcome.sqlite_path, &outcome.vault_dir),
    })
}

fn shadow_status_summary(project: &str) -> Result<Value, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let sqlite_path = sqlite_path(&cache_dir, project);
    let configured_vault_dir = read_config_value(&cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(&cache_dir, project));
    let fingerprint = read_config_value(&cache_dir, &metadata_key(project, "vault_fingerprint"))?;
    let ledger_seq = read_config_value(&cache_dir, &metadata_key(project, "ledger_seq"))?
        .and_then(|value| value.parse::<u64>().ok());
    let panel_version = read_config_value(&cache_dir, &metadata_key(project, "panel_version"))?
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(DEFAULT_PANEL_VERSION);
    let verify_status = if configured_vault_dir.exists() {
        match astrolabe_ingest::verify_chain_vault_path(&configured_vault_dir) {
            Ok(report) => report.status,
            Err(error) => format!("error:{error}"),
        }
    } else {
        "missing".to_string()
    };

    Ok(json!({
        "calyx": "shadow",
        "vault_fingerprint": fingerprint,
        "vault_ledger_head": ledger_seq,
        "panel_version": panel_version,
        "stores": stores_summary(&sqlite_path, &configured_vault_dir),
        "vault": {
            "dir": configured_vault_dir,
            "id": read_config_value(&cache_dir, &metadata_key(project, "vault_id"))?
                .unwrap_or_else(|| SHADOW_VAULT_ID.to_string()),
            "salt": read_config_value(&cache_dir, &metadata_key(project, "vault_salt"))?
                .unwrap_or_else(|| vault_salt(project)),
            "ledger_head": ledger_seq,
            "verify_chain": verify_status,
        },
    }))
}

fn stores_summary(sqlite_path: &Path, vault_dir: &Path) -> Value {
    json!({
        "sqlite": {
            "writer": "codebase-memory-mcp",
            "path": sqlite_path,
            "serves_legacy_tools": true,
        },
        "vault": {
            "writer": "astrolabe",
            "path": vault_dir,
            "serves_legacy_tools": false,
        },
    })
}

fn augment_tool_result(result: &str, additions: Value) -> Result<String, DynError> {
    let additions = additions
        .as_object()
        .ok_or("tool result additions must be a JSON object")?;
    let mut value: Value = serde_json::from_str(result)?;
    if let Some(structured) = value
        .get_mut("structuredContent")
        .and_then(Value::as_object_mut)
    {
        merge_object(structured, additions);
    }

    if let Some(text) = value
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(|item| item.get_mut("text"))
        && let Some(raw_text) = text.as_str()
        && let Ok(mut text_value) = serde_json::from_str::<Value>(raw_text)
        && let Some(text_obj) = text_value.as_object_mut()
    {
        merge_object(text_obj, additions);
        *text = Value::String(serde_json::to_string(&text_value)?);
    }

    Ok(serde_json::to_string(&value)?)
}

fn merge_object(target: &mut Map<String, Value>, additions: &Map<String, Value>) {
    for (key, value) in additions {
        target.insert(key.clone(), value.clone());
    }
}

fn strip_calyx_arg(args: &Map<String, Value>) -> Result<String, DynError> {
    let mut sanitized = args.clone();
    sanitized.remove("calyx");
    Ok(serde_json::to_string(&Value::Object(sanitized))?)
}

fn index_project_from_args(args: &Map<String, Value>) -> Result<Option<String>, DynError> {
    if let Some(name) = string_arg(args, "name") {
        return Ok(Some(astrolabe_bridge::cbm_project_name_from_path(name)?));
    }
    Ok(string_arg(args, "repo_path")
        .map(astrolabe_bridge::cbm_project_name_from_path)
        .transpose()?)
}

fn status_project_from_args(args: &Map<String, Value>) -> Result<Option<String>, DynError> {
    for key in ["project", "project_name", "project_id", "projectName"] {
        if let Some(project) = string_arg(args, key) {
            if project.contains('/') || project.contains('\\') {
                return Ok(Some(astrolabe_bridge::cbm_project_name_from_path(project)?));
            }
            return Ok(Some(project.to_string()));
        }
    }
    Ok(None)
}

fn string_arg<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn project_from_tool_result(result: &str) -> Option<String> {
    let value: Value = serde_json::from_str(result).ok()?;
    value
        .get("structuredContent")
        .and_then(|content| content.get("project"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn tool_result_is_error(result: &str) -> Result<bool, DynError> {
    let value: Value = serde_json::from_str(result)?;
    Ok(value
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

fn tool_error_result(message: impl Into<String>) -> Result<String, DynError> {
    Ok(serde_json::to_string(&json!({
        "content": [{"type": "text", "text": message.into()}],
        "isError": true,
    }))?)
}

fn jsonrpc_result_response(id: Value, result_raw: &str) -> Result<String, DynError> {
    let result: Value = serde_json::from_str(result_raw)?;
    Ok(serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    }))?)
}

fn persist_dial(project: &str, dial: MigrationDial) -> Result<(), DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    persist_dial_at(&cache_dir, project, dial)
}

fn read_dial(project: &str) -> Result<MigrationDial, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    read_dial_at(&cache_dir, project)
}

fn persist_dial_at(cache_dir: &Path, project: &str, dial: MigrationDial) -> Result<(), DynError> {
    write_config_value(cache_dir, &dial_key(project), dial.as_str())
}

fn read_dial_at(cache_dir: &Path, project: &str) -> Result<MigrationDial, DynError> {
    let Some(value) = read_config_value(cache_dir, &dial_key(project))? else {
        return Ok(MigrationDial::Off);
    };
    Ok(match value.as_str() {
        "shadow" => MigrationDial::Shadow,
        "off" => MigrationDial::Off,
        _ => MigrationDial::Off,
    })
}

fn persist_shadow_outcome(project: &str, outcome: &ShadowImportOutcome) -> Result<(), DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let conn = open_config(&cache_dir)?;
    for (key, value) in [
        ("vault_dir", outcome.vault_dir.display().to_string()),
        ("vault_id", outcome.vault_id.clone()),
        ("vault_salt", outcome.vault_salt.clone()),
        ("sqlite_path", outcome.sqlite_path.display().to_string()),
        (
            "vault_fingerprint",
            outcome.sqlite_fingerprint_sha256.clone(),
        ),
        ("ledger_seq", outcome.ledger_seq.to_string()),
        ("ledger_rows", outcome.ledger_rows_after.to_string()),
        ("panel_version", DEFAULT_PANEL_VERSION.to_string()),
    ] {
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            params![metadata_key(project, key), value],
        )?;
    }
    Ok(())
}

fn read_config_value(cache_dir: &Path, key: &str) -> Result<Option<String>, DynError> {
    let conn = open_config(cache_dir)?;
    Ok(conn
        .query_row(
            "SELECT value FROM config WHERE key = ?",
            params![key],
            |row| row.get(0),
        )
        .optional()?)
}

fn write_config_value(cache_dir: &Path, key: &str, value: &str) -> Result<(), DynError> {
    let conn = open_config(cache_dir)?;
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        params![key, value],
    )?;
    Ok(())
}

fn open_config(cache_dir: &Path) -> Result<Connection, DynError> {
    fs::create_dir_all(cache_dir)?;
    let conn = Connection::open(cache_dir.join("_config.db"))?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)",
        [],
    )?;
    Ok(conn)
}

fn dial_key(project: &str) -> String {
    format!("{CONFIG_KEY_PREFIX}{project}")
}

fn metadata_key(project: &str, key: &str) -> String {
    format!("{CONFIG_KEY_PREFIX}{project}.{key}")
}

fn sqlite_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}.db"))
}

fn vault_dir(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{VAULT_SUFFIX}"))
}

fn vault_salt(project: &str) -> String {
    format!("astrolabe-shadow-v1:{project}")
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

    #[test]
    fn calyx_arg_is_stripped_before_legacy_caller() {
        let args = serde_json::json!({
            "repo_path": "/tmp/demo",
            "mode": "fast",
            "calyx": "shadow",
        });
        let sanitized = strip_calyx_arg(args.as_object().unwrap()).unwrap();
        let value: Value = serde_json::from_str(&sanitized).unwrap();
        assert!(value.get("calyx").is_none());
        assert_eq!(value["mode"], "fast");
    }

    #[test]
    fn dial_persists_in_cbm_config_schema() {
        let dir = temp_dir("dial");
        persist_dial_at(&dir, "demo", MigrationDial::Shadow).unwrap();

        let conn = Connection::open(dir.join("_config.db")).unwrap();
        let value: String = conn
            .query_row(
                "SELECT value FROM config WHERE key = ?",
                params![dial_key("demo")],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(value, "shadow");
        assert_eq!(read_dial_at(&dir, "demo").unwrap(), MigrationDial::Shadow);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shadow_augmentation_updates_structured_content_and_text() {
        let result = serde_json::json!({
            "content": [{"type": "text", "text": "{\"project\":\"demo\",\"status\":\"indexed\"}"}],
            "structuredContent": {"project": "demo", "status": "indexed"},
            "isError": false,
        });
        let augmented = augment_tool_result(
            &serde_json::to_string(&result).unwrap(),
            serde_json::json!({
                "calyx": "shadow",
                "vault_fingerprint": "abc123",
            }),
        )
        .unwrap();
        let value: Value = serde_json::from_str(&augmented).unwrap();
        assert_eq!(value["structuredContent"]["calyx"], "shadow");
        assert_eq!(value["structuredContent"]["vault_fingerprint"], "abc123");
        let text = value["content"][0]["text"].as_str().unwrap();
        let text_value: Value = serde_json::from_str(text).unwrap();
        assert_eq!(text_value["calyx"], "shadow");
        assert_eq!(text_value["vault_fingerprint"], "abc123");
    }

    #[test]
    fn invalid_calyx_dial_is_a_tool_error() {
        let err = MigrationDial::parse(&serde_json::json!("maybe")).unwrap_err();
        let raw = tool_error_result(err).unwrap();
        let value: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["isError"], true);
        assert!(
            value["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("invalid calyx dial")
        );
    }

    fn temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "astrolabe-server-migration-{name}-{}",
            std::process::id()
        ));
        fs::remove_dir_all(&dir).ok();
        dir
    }
}
