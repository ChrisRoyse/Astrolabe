use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use astrolabe_bridge::CbmToolRunner;
use astrolabe_ingest::{SqliteImportOptions, import_sqlite_to_vault, verify_chain};
use astrolabe_lower::{LowerSqliteOptions, lower_cbm_sqlite};
use astrolabe_panel::{DEFAULT_PANEL_VERSION, PanelInput, PanelResult, PanelSlotSpec, SlotRuntime};
use calyx_aster::vault::{AsterVault, VaultOptions};
use calyx_core::{AbsentReason, Clock, SlotVector, VaultId};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::DynError;

const CONFIG_KEY_PREFIX: &str = "astrolabe.calyx.";
const SHADOW_VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const VAULT_SUFFIX: &str = ".astrolabe-vault";
const LOWERED_SQLITE_SUFFIX: &str = ".astrolabe-lowered.db";
const SHADOW_IMPORT_LOCK_SUFFIX: &str = ".astrolabe-shadow-import.lock";
const LOWERED_SQLITE_LOCK_SUFFIX: &str = ".astrolabe-lowered.lock";
const LOWERED_SQLITE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const LOWERED_SQLITE_LOCK_STALE_AFTER: Duration = Duration::from_secs(300);
const LOWERED_SQLITE_LOCK_POLL: Duration = Duration::from_millis(25);

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
    lowered_sqlite_path: PathBuf,
    lowered_artifact_sha256: String,
    lowered_vault_fingerprint_sha256: String,
    lowered_manifest_seq: u64,
    lowered_nodes: usize,
    lowered_edges: usize,
    lowered_skipped_edges: usize,
    sqlite_nodes: usize,
    sqlite_edges: usize,
    constellation_inputs: usize,
    structural_only: usize,
    new_cx_ids: usize,
    reused_cx_ids: usize,
    graph_rows_written: usize,
    edge_rows_written: usize,
    cx_id_set_sha256: String,
    ledger_seq: u64,
    ledger_rows_after: u64,
    verify_chain_status: String,
}

#[derive(Debug)]
struct ShadowSlotRuntime;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ShadowRefreshStatus {
    Current,
    Refreshed,
    Busy,
}

#[derive(Debug)]
struct ShadowImportLock {
    _file: fs::File,
    path: PathBuf,
}

impl Drop for ShadowImportLock {
    fn drop(&mut self) {
        let _ = self._file.unlock();
        let _ = fs::remove_file(&self.path);
    }
}

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

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let Some(_shadow_import_lock) = try_shadow_import_lock(&cache_dir, &project)? else {
        return augment_tool_result(&result, shadow_import_busy_summary_at(&cache_dir, &project));
    };
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
    let refresh_status = match ensure_shadow_import_current(&project) {
        Ok(status) => status,
        Err(error) => {
            return tool_error_result(format!("shadow import recovery failed: {error}"));
        }
    };
    let mut summary = shadow_status_summary(&project)?;
    if refresh_status == ShadowRefreshStatus::Busy
        && let Some(summary_obj) = summary.as_object_mut()
    {
        let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
        merge_object(
            summary_obj,
            shadow_import_busy_summary_at(&cache_dir, &project)
                .as_object()
                .expect("busy summary object"),
        );
    }
    augment_tool_result(&result, summary)
}

fn ensure_shadow_import_current(project: &str) -> Result<ShadowRefreshStatus, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    if !sqlite_path(&cache_dir, project).exists() {
        return Ok(ShadowRefreshStatus::Current);
    }

    let fingerprint = read_config_value(&cache_dir, &metadata_key(project, "vault_fingerprint"))?;
    let configured_vault_dir = read_config_value(&cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(&cache_dir, project));
    let configured_lowered_path =
        read_config_value(&cache_dir, &metadata_key(project, "lowered_sqlite_path"))?
            .map(PathBuf::from)
            .unwrap_or_else(|| lowered_sqlite_path(&cache_dir, project));
    let verify_intact = configured_vault_dir.exists()
        && astrolabe_ingest::verify_chain_vault_path(&configured_vault_dir)
            .map(|report| report.is_intact())
            .unwrap_or(false);
    if fingerprint.is_some() && verify_intact && configured_lowered_path.exists() {
        return Ok(ShadowRefreshStatus::Current);
    }

    let Some(_shadow_import_lock) = try_shadow_import_lock(&cache_dir, project)? else {
        return Ok(ShadowRefreshStatus::Busy);
    };
    let outcome = import_shadow_vault(project)?;
    persist_shadow_outcome(project, &outcome)?;
    Ok(ShadowRefreshStatus::Refreshed)
}

fn try_shadow_import_lock(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<ShadowImportLock>, DynError> {
    fs::create_dir_all(cache_dir)?;
    let lock_path = shadow_import_lock_path(cache_dir, project);
    let mut lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    match lock.try_lock() {
        Ok(()) => {
            lock.set_len(0)?;
            writeln!(lock, "pid={}", std::process::id())?;
            lock.sync_all()?;
            Ok(Some(ShadowImportLock {
                _file: lock,
                path: lock_path,
            }))
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn shadow_import_busy_summary_at(cache_dir: &Path, project: &str) -> Value {
    json!({
        "calyx": "shadow",
        "shadow_import": {
            "status": "busy",
            "freshness": "stale_ok",
            "trust": "provisional",
            "owner": "another-process",
            "lock_path": shadow_import_lock_path(cache_dir, project),
            "remediation": "retry after the active Astrolabe shadow import completes; legacy SQLite results remain served by codebase-memory-mcp",
        }
    })
}

fn shadow_import_current_summary(verify_status: &str, lowered_exists: bool) -> Value {
    let current = verify_status == "intact" && lowered_exists;
    json!({
        "status": if current { "current" } else { "unverified" },
        "freshness": if current { "fresh" } else { "stale_or_missing" },
        "trust": if current { "verified" } else { "provisional" },
        "remediation": if current {
            Value::Null
        } else {
            Value::String("run index_repository with calyx shadow or retry index_status after shadow import completes".to_string())
        },
    })
}

fn remove_stale_lowered_sqlite_lock(lock_path: &Path) -> Result<bool, DynError> {
    remove_stale_sidecar_lock(lock_path, LOWERED_SQLITE_LOCK_STALE_AFTER)
}

fn remove_stale_sidecar_lock(lock_path: &Path, stale_after: Duration) -> Result<bool, DynError> {
    let Ok(metadata) = fs::metadata(lock_path) else {
        return Ok(false);
    };
    let Ok(modified) = metadata.modified() else {
        return Ok(false);
    };
    let Ok(age) = modified.elapsed() else {
        return Ok(false);
    };
    if age < stale_after {
        return Ok(false);
    }
    match fs::remove_file(lock_path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn shadow_import_lock_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{SHADOW_IMPORT_LOCK_SUFFIX}"))
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
    let lowered_sqlite_path = lowered_sqlite_path(&cache_dir, project);
    let lower_report = lower_shadow_sqlite(&cache_dir, project, &vault)?;
    let verify = verify_chain(&vault)?;
    if !verify.is_intact() {
        return Err(format!(
            "shadow vault ledger verification failed after import/lower: {}",
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
        lowered_sqlite_path,
        lowered_artifact_sha256: lower_report.artifact_sha256,
        lowered_vault_fingerprint_sha256: lower_report.vault_fingerprint_sha256,
        lowered_manifest_seq: lower_report.manifest_seq,
        lowered_nodes: lower_report.node_count,
        lowered_edges: lower_report.edge_count,
        lowered_skipped_edges: lower_report.skipped_edges,
        sqlite_nodes: report.sqlite_nodes,
        sqlite_edges: report.sqlite_edges,
        constellation_inputs: report.constellation_inputs,
        structural_only: report.structural_only,
        new_cx_ids: report.new_cx_ids,
        reused_cx_ids: report.reused_cx_ids,
        graph_rows_written: report.graph_rows_written,
        edge_rows_written: report.edge_rows_written,
        cx_id_set_sha256: cx_id_set_sha256(&report.cx_ids),
        ledger_seq: lower_report.manifest_seq,
        ledger_rows_after: verify.ledger_rows,
        verify_chain_status: verify.status,
    })
}

fn lower_shadow_sqlite<C>(
    cache_dir: &Path,
    project: &str,
    vault: &AsterVault<C>,
) -> Result<astrolabe_lower::LoweredSqliteReport, DynError>
where
    C: Clock,
{
    with_lowered_sqlite_lock(cache_dir, project, || {
        lower_cbm_sqlite(
            vault,
            lowered_sqlite_path(cache_dir, project),
            &LowerSqliteOptions::new(project),
        )
        .map_err(Into::into)
    })
}

fn with_lowered_sqlite_lock<T>(
    cache_dir: &Path,
    project: &str,
    work: impl FnOnce() -> Result<T, DynError>,
) -> Result<T, DynError> {
    let lock_path = lowered_sqlite_lock_path(cache_dir, project);
    let started = Instant::now();
    let mut work = Some(work);
    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(lock) => {
                drop(lock);
                let result = work.take().expect("lowered sqlite lock work runs once")();
                let cleanup = fs::remove_file(&lock_path);
                if let Err(error) = cleanup
                    && result.is_ok()
                {
                    return Err(error.into());
                }
                return result;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if remove_stale_lowered_sqlite_lock(&lock_path)? {
                    continue;
                }
                if started.elapsed() >= LOWERED_SQLITE_LOCK_TIMEOUT {
                    return Err(format!(
                        "timed out waiting for lowered SQLite lock: {}",
                        lock_path.display()
                    )
                    .into());
                }
                thread::sleep(LOWERED_SQLITE_LOCK_POLL);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn grounding_summary(outcome: &ShadowImportOutcome) -> Value {
    json!({
        "status": "imported",
        "sqlite_nodes": outcome.sqlite_nodes,
        "sqlite_edges": outcome.sqlite_edges,
        "constellation_inputs": outcome.constellation_inputs,
        "structural_only": outcome.structural_only,
        "idempotency": {
            "new_cx_ids": outcome.new_cx_ids,
            "reused_cx_ids": outcome.reused_cx_ids,
            "graph_rows_written": outcome.graph_rows_written,
            "edge_rows_written": outcome.edge_rows_written,
            "cx_id_set_sha256": outcome.cx_id_set_sha256,
        },
        "sqlite_path": outcome.sqlite_path,
        "lowered_sqlite": lowered_summary(
            &outcome.lowered_sqlite_path,
            Some(&outcome.lowered_artifact_sha256),
            Some(&outcome.lowered_vault_fingerprint_sha256),
            Some(outcome.lowered_manifest_seq),
            Some(outcome.lowered_nodes),
            Some(outcome.lowered_edges),
            Some(outcome.lowered_skipped_edges),
        ),
        "vault_dir": outcome.vault_dir,
        "vault_id": outcome.vault_id,
        "vault_salt": outcome.vault_salt,
        "ledger_seq": outcome.ledger_seq,
        "ledger_rows_after": outcome.ledger_rows_after,
        "verify_chain": outcome.verify_chain_status,
        "panel_version": DEFAULT_PANEL_VERSION,
        "panel_runtime": "lens_unavailable",
        "stores": stores_summary(
            &outcome.sqlite_path,
            &outcome.vault_dir,
            Some(&outcome.lowered_sqlite_path),
        ),
    })
}

fn shadow_status_summary(project: &str) -> Result<Value, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let sqlite_path = sqlite_path(&cache_dir, project);
    let configured_vault_dir = read_config_value(&cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(&cache_dir, project));
    let lowered_path =
        read_config_value(&cache_dir, &metadata_key(project, "lowered_sqlite_path"))?
            .map(PathBuf::from)
            .unwrap_or_else(|| lowered_sqlite_path(&cache_dir, project));
    let fingerprint = read_config_value(&cache_dir, &metadata_key(project, "vault_fingerprint"))?;
    let ledger_seq = read_config_value(&cache_dir, &metadata_key(project, "ledger_seq"))?
        .and_then(|value| value.parse::<u64>().ok());
    let new_cx_ids = read_config_value(&cache_dir, &metadata_key(project, "new_cx_ids"))?
        .and_then(|value| value.parse::<usize>().ok());
    let reused_cx_ids = read_config_value(&cache_dir, &metadata_key(project, "reused_cx_ids"))?
        .and_then(|value| value.parse::<usize>().ok());
    let graph_rows_written =
        read_config_value(&cache_dir, &metadata_key(project, "graph_rows_written"))?
            .and_then(|value| value.parse::<usize>().ok());
    let edge_rows_written =
        read_config_value(&cache_dir, &metadata_key(project, "edge_rows_written"))?
            .and_then(|value| value.parse::<usize>().ok());
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
        "shadow_import": shadow_import_current_summary(&verify_status, lowered_path.exists()),
        "idempotency": {
            "new_cx_ids": new_cx_ids,
            "reused_cx_ids": reused_cx_ids,
            "graph_rows_written": graph_rows_written,
            "edge_rows_written": edge_rows_written,
            "cx_id_set_sha256": read_config_value(&cache_dir, &metadata_key(project, "cx_id_set_sha256"))?,
        },
        "lowered_sqlite": lowered_summary(
            &lowered_path,
            read_config_value(&cache_dir, &metadata_key(project, "lowered_artifact_sha256"))?.as_ref(),
            read_config_value(&cache_dir, &metadata_key(project, "lowered_vault_fingerprint_sha256"))?.as_ref(),
            read_config_value(&cache_dir, &metadata_key(project, "lowered_manifest_seq"))?
                .and_then(|value| value.parse::<u64>().ok()),
            read_config_value(&cache_dir, &metadata_key(project, "lowered_nodes"))?
                .and_then(|value| value.parse::<usize>().ok()),
            read_config_value(&cache_dir, &metadata_key(project, "lowered_edges"))?
                .and_then(|value| value.parse::<usize>().ok()),
            read_config_value(&cache_dir, &metadata_key(project, "lowered_skipped_edges"))?
                .and_then(|value| value.parse::<usize>().ok()),
        ),
        "stores": stores_summary(&sqlite_path, &configured_vault_dir, Some(&lowered_path)),
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

fn lowered_summary(
    path: &Path,
    artifact_sha256: Option<&String>,
    vault_fingerprint_sha256: Option<&String>,
    manifest_seq: Option<u64>,
    nodes: Option<usize>,
    edges: Option<usize>,
    skipped_edges: Option<usize>,
) -> Value {
    json!({
        "writer": "astrolabe",
        "path": path,
        "exists": path.exists(),
        "artifact_sha256": artifact_sha256,
        "vault_fingerprint_sha256": vault_fingerprint_sha256,
        "manifest_seq": manifest_seq,
        "nodes": nodes,
        "edges": edges,
        "skipped_edges": skipped_edges,
        "serves_legacy_tools": false,
    })
}

fn stores_summary(
    sqlite_path: &Path,
    vault_dir: &Path,
    lowered_sqlite_path: Option<&Path>,
) -> Value {
    let mut stores = Map::new();
    stores.insert(
        "sqlite".to_string(),
        json!({
            "writer": "codebase-memory-mcp",
            "path": sqlite_path,
            "serves_legacy_tools": true,
        }),
    );
    stores.insert(
        "vault".to_string(),
        json!({
            "writer": "astrolabe",
            "path": vault_dir,
            "serves_legacy_tools": false,
        }),
    );
    if let Some(path) = lowered_sqlite_path {
        stores.insert(
            "lowered_sqlite".to_string(),
            json!({
                "writer": "astrolabe",
                "path": path,
                "serves_legacy_tools": false,
            }),
        );
    }
    Value::Object(stores)
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
            "lowered_sqlite_path",
            outcome.lowered_sqlite_path.display().to_string(),
        ),
        (
            "lowered_artifact_sha256",
            outcome.lowered_artifact_sha256.clone(),
        ),
        (
            "lowered_vault_fingerprint_sha256",
            outcome.lowered_vault_fingerprint_sha256.clone(),
        ),
        (
            "lowered_manifest_seq",
            outcome.lowered_manifest_seq.to_string(),
        ),
        ("lowered_nodes", outcome.lowered_nodes.to_string()),
        ("lowered_edges", outcome.lowered_edges.to_string()),
        (
            "lowered_skipped_edges",
            outcome.lowered_skipped_edges.to_string(),
        ),
        (
            "vault_fingerprint",
            outcome.sqlite_fingerprint_sha256.clone(),
        ),
        ("ledger_seq", outcome.ledger_seq.to_string()),
        ("ledger_rows", outcome.ledger_rows_after.to_string()),
        ("panel_version", DEFAULT_PANEL_VERSION.to_string()),
        ("structural_only", outcome.structural_only.to_string()),
        ("new_cx_ids", outcome.new_cx_ids.to_string()),
        ("reused_cx_ids", outcome.reused_cx_ids.to_string()),
        ("graph_rows_written", outcome.graph_rows_written.to_string()),
        ("edge_rows_written", outcome.edge_rows_written.to_string()),
        ("cx_id_set_sha256", outcome.cx_id_set_sha256.clone()),
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

fn lowered_sqlite_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{LOWERED_SQLITE_SUFFIX}"))
}

fn lowered_sqlite_lock_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{LOWERED_SQLITE_LOCK_SUFFIX}"))
}

fn vault_dir(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{VAULT_SUFFIX}"))
}

fn vault_salt(project: &str) -> String {
    format!("astrolabe-shadow-v1:{project}")
}

fn cx_id_set_sha256(ids: &[calyx_core::CxId]) -> String {
    let mut sorted = ids.to_vec();
    sorted.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"astrolabe-shadow-cx-id-set-v1");
    for id in sorted {
        hasher.update(id.as_bytes());
    }
    hex_lower(&hasher.finalize())
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
    fn stores_summary_labels_lowered_sqlite_as_astrolabe_sidecar() {
        let stores = stores_summary(
            Path::new("/cache/demo.db"),
            Path::new("/cache/demo.astrolabe-vault"),
            Some(Path::new("/cache/demo.astrolabe-lowered.db")),
        );
        assert_eq!(stores["sqlite"]["writer"], "codebase-memory-mcp");
        assert_eq!(stores["sqlite"]["serves_legacy_tools"], true);
        assert_eq!(stores["lowered_sqlite"]["writer"], "astrolabe");
        assert_eq!(stores["lowered_sqlite"]["serves_legacy_tools"], false);
    }

    #[test]
    fn shadow_import_lock_reports_busy_until_owner_drops() {
        let dir = temp_dir("shadow-import-lock");
        fs::create_dir_all(&dir).unwrap();
        let first = try_shadow_import_lock(&dir, "demo")
            .unwrap()
            .expect("first process owns shadow import");
        let lock_path = shadow_import_lock_path(&dir, "demo");
        assert!(lock_path.exists());
        assert!(fs::read_to_string(&lock_path).unwrap().contains("pid="));
        assert!(
            try_shadow_import_lock(&dir, "demo").unwrap().is_none(),
            "second process must see an honest busy state"
        );

        let busy = shadow_import_busy_summary_at(&dir, "demo");
        assert_eq!(busy["shadow_import"]["status"], "busy");
        assert_eq!(busy["shadow_import"]["freshness"], "stale_ok");
        assert_eq!(busy["shadow_import"]["trust"], "provisional");
        assert_eq!(
            busy["shadow_import"]["lock_path"],
            lock_path.display().to_string()
        );

        drop(first);
        assert!(!lock_path.exists());
        let second = try_shadow_import_lock(&dir, "demo")
            .unwrap()
            .expect("lock releases on owner drop");
        drop(second);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn shadow_import_lock_releases_after_owner_process_kill() {
        let dir = temp_dir("shadow-import-kill");
        fs::create_dir_all(&dir).unwrap();
        let ready = dir.join("owner.ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--ignored")
            .arg("--exact")
            .arg("migration::tests::shadow_import_lock_child_process")
            .arg("--nocapture")
            .env("ASTROLABE_SHADOW_LOCK_CHILD", "1")
            .env("ASTROLABE_SHADOW_LOCK_CACHE", &dir)
            .env("ASTROLABE_SHADOW_LOCK_PROJECT", "demo")
            .env("ASTROLABE_SHADOW_LOCK_READY", &ready)
            .spawn()
            .expect("spawn shadow import lock child");

        wait_for_file_or_child_exit(&ready, &mut child);
        assert!(
            try_shadow_import_lock(&dir, "demo").unwrap().is_none(),
            "parent must observe the live child owner as busy"
        );

        child.kill().expect("kill shadow import lock child");
        let status = child.wait().expect("wait for shadow import lock child");
        assert!(
            !status.success(),
            "child should be killed while holding lock"
        );

        let recovered = wait_for_shadow_import_lock(&dir, "demo");
        drop(recovered);
        assert!(
            !shadow_import_lock_path(&dir, "demo").exists(),
            "new owner drop removes the crash-left lock marker"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[ignore = "child process helper for shadow_import_lock_releases_after_owner_process_kill"]
    fn shadow_import_lock_child_process() {
        if std::env::var_os("ASTROLABE_SHADOW_LOCK_CHILD").is_none() {
            return;
        }
        let cache_dir = PathBuf::from(
            std::env::var_os("ASTROLABE_SHADOW_LOCK_CACHE").expect("ASTROLABE_SHADOW_LOCK_CACHE"),
        );
        let project =
            std::env::var("ASTROLABE_SHADOW_LOCK_PROJECT").expect("ASTROLABE_SHADOW_LOCK_PROJECT");
        let ready = PathBuf::from(
            std::env::var_os("ASTROLABE_SHADOW_LOCK_READY").expect("ASTROLABE_SHADOW_LOCK_READY"),
        );
        let _lock = try_shadow_import_lock(&cache_dir, &project)
            .unwrap()
            .expect("child owns shadow import lock");
        fs::write(&ready, b"ready").expect("write child ready marker");
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    #[test]
    fn shadow_import_status_labels_unverified_state() {
        let current = shadow_import_current_summary("intact", true);
        assert_eq!(current["status"], "current");
        assert_eq!(current["trust"], "verified");
        assert!(current["remediation"].is_null());

        let unverified = shadow_import_current_summary("missing", false);
        assert_eq!(unverified["status"], "unverified");
        assert_eq!(unverified["freshness"], "stale_or_missing");
        assert_eq!(unverified["trust"], "provisional");
        assert!(
            unverified["remediation"]
                .as_str()
                .unwrap()
                .contains("retry index_status")
        );
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

    fn wait_for_file_or_child_exit(path: &Path, child: &mut std::process::Child) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if path.exists() {
                return;
            }
            if let Some(status) = child.try_wait().expect("poll child") {
                panic!("child exited before ready marker: {status}");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        child.kill().ok();
        panic!("timed out waiting for {}", path.display());
    }

    fn wait_for_shadow_import_lock(cache_dir: &Path, project: &str) -> ShadowImportLock {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Some(lock) = try_shadow_import_lock(cache_dir, project).unwrap() {
                return lock;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "timed out waiting to reacquire shadow import lock {}",
            shadow_import_lock_path(cache_dir, project).display()
        );
    }
}
