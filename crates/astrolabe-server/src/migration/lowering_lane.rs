use super::*;

use std::sync::Arc;

use astrolabe_domain::LoweringTrigger;
use astrolabe_lower::{LowerDebouncer, RunOutcome};
use calyx_core::SystemClock;

pub(crate) const LOWERING_DEBOUNCE_STATUS_KEY: &str = "lowering_debounce_json";
pub(crate) const LOWERING_PENDING_KEY: &str = "lowering_pending";
pub(crate) const LOWERING_MALFORMED_OBSERVATION_KEY: &str = "lowering_malformed_observation_json";
pub(crate) const LOWERING_MALFORMED_FAULT_KEY: &str = "lowering_malformed_fault_json";

const LOWERING_MALFORMED_OBSERVATION_SCHEMA: &str = "astrolabe-lowering-malformed-observation-v1";
const LOWERING_MALFORMED_FAULT_SCHEMA: &str = "astrolabe-lowering-malformed-fault-v1";

static LOWERING_DEBOUNCERS: OnceLock<Mutex<BTreeMap<String, Arc<LowerDebouncer<SystemClock>>>>> =
    OnceLock::new();
static LOWERING_TERMINAL_CACHE: OnceLock<Mutex<BTreeMap<String, LoweringTerminalCacheEntry>>> =
    OnceLock::new();

#[derive(Clone)]
struct LoweringTerminalCacheEntry {
    source_raw: String,
    observation_raw: String,
    fault_raw: String,
    fault: Value,
}

enum LoweringStatusRecord {
    Valid { raw: String, status: Value },
    Terminal { fault: Value },
}

fn debouncers() -> &'static Mutex<BTreeMap<String, Arc<LowerDebouncer<SystemClock>>>> {
    LOWERING_DEBOUNCERS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn terminal_cache() -> &'static Mutex<BTreeMap<String, LoweringTerminalCacheEntry>> {
    LOWERING_TERMINAL_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn lowering_registry_key(cache_dir: &Path, project: &str) -> String {
    format!("{}\0{project}", cache_dir.display())
}

fn project_debouncer(
    cache_dir: &Path,
    project: &str,
) -> Result<Arc<LowerDebouncer<SystemClock>>, DynError> {
    let mut map = debouncers()
        .lock()
        .map_err(|_| "lowering debouncer registry mutex poisoned")?;
    let registry_key = lowering_registry_key(cache_dir, project);
    if let Some(existing) = map.get(&registry_key) {
        return Ok(Arc::clone(existing));
    }
    let debouncer = Arc::new(LowerDebouncer::with_default_window(SystemClock));
    if read_config_value(cache_dir, &metadata_key(project, LOWERING_PENDING_KEY))?.as_deref()
        == Some("true")
    {
        debouncer.request_regeneration();
    }
    map.insert(registry_key, Arc::clone(&debouncer));
    Ok(debouncer)
}

pub(crate) fn drive_project_lowering(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    let (current_raw, current_status) = match read_lowering_status_record(cache_dir, project)? {
        Some(LoweringStatusRecord::Valid { raw, status }) => (Some(raw), Some(status)),
        Some(LoweringStatusRecord::Terminal { fault }) => return Ok(fault),
        None => (None, None),
    };
    let debouncer = project_debouncer(cache_dir, project)?;
    let status = match debouncer.run_due(|| regenerate_lowered_under_lock(cache_dir, project)) {
        Ok(RunOutcome::Idle) => current_status.unwrap_or_else(|| {
            json!({
                "schema": "astrolabe-lowering-debounce-v1",
                "status": "idle",
                "pending": false,
                "window_ms": debouncer.window_ms(),
                "freshness": "current_or_uninitialized",
                "trust": "verified",
            })
        }),
        Ok(RunOutcome::Waiting) => json!({
            "schema": "astrolabe-lowering-debounce-v1",
            "status": "waiting",
            "pending": true,
            "window_ms": debouncer.window_ms(),
            "freshness": "stale",
            "trust": "verified",
        }),
        Ok(RunOutcome::Regenerated(report)) => {
            persist_regenerated_lowering(cache_dir, project, &report)?;
            json!({
                "schema": "astrolabe-lowering-debounce-v1",
                "status": "regenerated",
                "pending": false,
                "window_ms": debouncer.window_ms(),
                "freshness": "fresh",
                "trust": "verified",
                "artifact_sha256": report.artifact_sha256,
                "vault_fingerprint_sha256": report.vault_fingerprint_sha256,
                "manifest_seq": report.manifest_seq,
                "node_count": report.node_count,
                "edge_count": report.edge_count,
                "skipped_edges": report.skipped_edges,
            })
        }
        Err(error) => json!({
            "schema": "astrolabe-lowering-debounce-v1",
            "status": "error",
            "pending": true,
            "window_ms": debouncer.window_ms(),
            "freshness": "stale",
            "trust": "provisional",
            "code": "ASTRO_DEBOUNCED_LOWERING_FAILED",
            "message": error.to_string(),
            "remediation": "repair the writable vault or lowered-artifact path; the persisted debounce debt will retry on a later watcher or index_status tick",
        }),
    };
    persist_lowering_status_if_changed(cache_dir, project, current_raw.as_deref(), &status)?;
    Ok(status)
}

pub(crate) fn lowering_status_snapshot(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    if let Some(status) = read_lowering_status(cache_dir, project)? {
        return Ok(status);
    }
    let pending = read_config_value(cache_dir, &metadata_key(project, LOWERING_PENDING_KEY))?
        .as_deref()
        == Some("true");
    let window_ms = LowerDebouncer::with_default_window(SystemClock).window_ms();
    Ok(if pending {
        json!({
            "schema": "astrolabe-lowering-debounce-v1",
            "status": "waiting",
            "pending": true,
            "window_ms": window_ms,
            "freshness": "stale",
            "trust": "verified",
        })
    } else {
        json!({
            "schema": "astrolabe-lowering-debounce-v1",
            "status": "idle",
            "pending": false,
            "window_ms": window_ms,
            "freshness": "current_or_uninitialized",
            "trust": "verified",
        })
    })
}

pub(crate) fn read_lowering_status(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<Value>, DynError> {
    Ok(
        read_lowering_status_record(cache_dir, project)?.map(|record| match record {
            LoweringStatusRecord::Valid { status, .. } => status,
            LoweringStatusRecord::Terminal { fault } => fault,
        }),
    )
}

fn read_lowering_status_record(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<LoweringStatusRecord>, DynError> {
    let key = metadata_key(project, LOWERING_DEBOUNCE_STATUS_KEY);
    let observation_key = metadata_key(project, LOWERING_MALFORMED_OBSERVATION_KEY);
    let fault_key = metadata_key(project, LOWERING_MALFORMED_FAULT_KEY);
    let values = read_config_values(
        cache_dir,
        &[key.clone(), observation_key.clone(), fault_key.clone()],
    )?;
    let [raw, observation_raw, fault_raw]: [Option<String>; 3] = values
        .try_into()
        .map_err(|_| "lowering status exact-key read returned the wrong cardinality")?;
    let Some(raw) = raw else {
        clear_malformed_terminal_state(
            cache_dir,
            project,
            &key,
            None,
            observation_raw.as_deref(),
            fault_raw.as_deref(),
        )?;
        return Ok(None);
    };
    if let (Some(observation_raw), Some(fault_raw)) =
        (observation_raw.as_deref(), fault_raw.as_deref())
        && let Some(fault) =
            cached_terminal_fault_exact(cache_dir, project, &raw, observation_raw, fault_raw)?
    {
        return Ok(Some(LoweringStatusRecord::Terminal { fault }));
    }
    let source_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
    if let (Some(observation_raw), Some(fault_raw)) =
        (observation_raw.as_deref(), fault_raw.as_deref())
        && let Some(fault) = cached_terminal_fault(CachedTerminalFaultRequest {
            cache_dir,
            project,
            key: &key,
            source_raw: &raw,
            observation_raw,
            fault_raw,
            source_bytes: raw.len(),
            source_sha256: &source_sha256,
        })?
    {
        return Ok(Some(LoweringStatusRecord::Terminal { fault }));
    }
    match serde_json::from_str::<Value>(&raw) {
        Ok(status) => {
            clear_malformed_terminal_state(
                cache_dir,
                project,
                &key,
                Some(&raw),
                observation_raw.as_deref(),
                fault_raw.as_deref(),
            )?;
            Ok(Some(LoweringStatusRecord::Valid { raw, status }))
        }
        Err(_) => observe_malformed_lowering_status(
            cache_dir,
            project,
            &key,
            &raw,
            observation_raw.as_deref(),
            fault_raw.as_deref(),
        )
        .map(Some),
    }
}

fn malformed_observation_json(project: &str, key: &str, raw: &str, fault_sha256: &str) -> Value {
    json!({
        "schema": LOWERING_MALFORMED_OBSERVATION_SCHEMA,
        "project": project,
        "key": key,
        "source_present": true,
        "source_bytes": raw.len(),
        "source_sha256": format!("{:x}", Sha256::digest(raw.as_bytes())),
        "fault_sha256": fault_sha256,
    })
}

fn malformed_observation_matches_source(
    observation: &Value,
    project: &str,
    key: &str,
    source_bytes: usize,
    source_sha256: &str,
    fault_raw: &str,
) -> bool {
    observation.get("schema").and_then(Value::as_str) == Some(LOWERING_MALFORMED_OBSERVATION_SCHEMA)
        && observation.get("project").and_then(Value::as_str) == Some(project)
        && observation.get("key").and_then(Value::as_str) == Some(key)
        && observation.get("source_present").and_then(Value::as_bool) == Some(true)
        && observation.get("source_bytes").and_then(Value::as_u64) == Some(source_bytes as u64)
        && observation.get("source_sha256").and_then(Value::as_str) == Some(source_sha256)
        && observation.get("fault_sha256").and_then(Value::as_str)
            == Some(format!("{:x}", Sha256::digest(fault_raw.as_bytes())).as_str())
}

fn terminal_fault_matches_source(
    fault: &Value,
    project: &str,
    key: &str,
    source_bytes: usize,
    source_sha256: &str,
) -> bool {
    fault.get("schema").and_then(Value::as_str) == Some(LOWERING_MALFORMED_FAULT_SCHEMA)
        && fault.get("status").and_then(Value::as_str) == Some("error")
        && fault.get("terminal").and_then(Value::as_bool) == Some(true)
        && fault.get("code").and_then(Value::as_str) == Some("ASTRO_LOWERING_STATUS_MALFORMED")
        && fault.get("project").and_then(Value::as_str) == Some(project)
        && fault.get("key").and_then(Value::as_str) == Some(key)
        && fault.get("source_present").and_then(Value::as_bool) == Some(true)
        && fault.get("source_bytes").and_then(Value::as_u64) == Some(source_bytes as u64)
        && fault.get("source_sha256").and_then(Value::as_str) == Some(source_sha256)
        && fault.get("message").and_then(Value::as_str).is_some()
        && fault.get("remediation").and_then(Value::as_str).is_some()
}

struct CachedTerminalFaultRequest<'a> {
    cache_dir: &'a Path,
    project: &'a str,
    key: &'a str,
    source_raw: &'a str,
    observation_raw: &'a str,
    fault_raw: &'a str,
    source_bytes: usize,
    source_sha256: &'a str,
}

fn cached_terminal_fault(
    request: CachedTerminalFaultRequest<'_>,
) -> Result<Option<Value>, DynError> {
    let CachedTerminalFaultRequest {
        cache_dir,
        project,
        key,
        source_raw,
        observation_raw,
        fault_raw,
        source_bytes,
        source_sha256,
    } = request;
    let registry_key = lowering_registry_key(cache_dir, project);
    {
        let cache = terminal_cache()
            .lock()
            .map_err(|_| "lowering terminal cache mutex poisoned")?;
        if let Some(entry) = cache.get(&registry_key)
            && entry.source_raw == source_raw
            && entry.observation_raw == observation_raw
            && entry.fault_raw == fault_raw
        {
            return Ok(Some(entry.fault.clone()));
        }
    }
    let Ok(observation) = serde_json::from_str::<Value>(observation_raw) else {
        return Ok(None);
    };
    if !malformed_observation_matches_source(
        &observation,
        project,
        key,
        source_bytes,
        source_sha256,
        fault_raw,
    ) {
        return Ok(None);
    }
    let Ok(fault) = serde_json::from_str::<Value>(fault_raw) else {
        return Ok(None);
    };
    if !terminal_fault_matches_source(&fault, project, key, source_bytes, source_sha256) {
        return Ok(None);
    }
    terminal_cache()
        .lock()
        .map_err(|_| "lowering terminal cache mutex poisoned")?
        .insert(
            registry_key,
            LoweringTerminalCacheEntry {
                source_raw: source_raw.to_string(),
                observation_raw: observation_raw.to_string(),
                fault_raw: fault_raw.to_string(),
                fault: fault.clone(),
            },
        );
    Ok(Some(fault))
}

fn cached_terminal_fault_exact(
    cache_dir: &Path,
    project: &str,
    source_raw: &str,
    observation_raw: &str,
    fault_raw: &str,
) -> Result<Option<Value>, DynError> {
    let cache = terminal_cache()
        .lock()
        .map_err(|_| "lowering terminal cache mutex poisoned")?;
    Ok(cache
        .get(&lowering_registry_key(cache_dir, project))
        .filter(|entry| {
            entry.source_raw == source_raw
                && entry.observation_raw == observation_raw
                && entry.fault_raw == fault_raw
        })
        .map(|entry| entry.fault.clone()))
}

fn observe_malformed_lowering_status(
    cache_dir: &Path,
    project: &str,
    key: &str,
    raw: &str,
    observation_raw: Option<&str>,
    fault_raw: Option<&str>,
) -> Result<LoweringStatusRecord, DynError> {
    let observation_key = metadata_key(project, LOWERING_MALFORMED_OBSERVATION_KEY);
    let fault_key = metadata_key(project, LOWERING_MALFORMED_FAULT_KEY);
    let source_bytes = raw.len();
    let source_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));

    if let (Some(observation_raw), Some(fault_raw)) = (observation_raw, fault_raw)
        && let Some(fault) = cached_terminal_fault(CachedTerminalFaultRequest {
            cache_dir,
            project,
            key,
            source_raw: raw,
            observation_raw,
            fault_raw,
            source_bytes,
            source_sha256: &source_sha256,
        })?
    {
        return Ok(LoweringStatusRecord::Terminal { fault });
    }

    let mut conn = open_config(cache_dir)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let transaction_raw = tx
        .query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if transaction_raw.as_deref() != Some(raw) {
        return Err(format!(
            "ASTRO_LOWERING_STATUS_OBSERVATION_CHANGED: durable lowering status row {key:?} for project {project:?} changed between the read-only observation and the serialized classification transaction; expected_source_sha256={source_sha256}, expected_source_bytes={source_bytes}; remediation: preserve the config store and retry only by observing the new exact durable value"
        )
        .into());
    }
    let transaction_observation = tx
        .query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![&observation_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let transaction_fault = tx
        .query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![&fault_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let (Some(transaction_observation_raw), Some(transaction_fault_raw)) = (
        transaction_observation.as_deref(),
        transaction_fault.as_deref(),
    ) && let Some(fault) = cached_terminal_fault(CachedTerminalFaultRequest {
        cache_dir,
        project,
        key,
        source_raw: raw,
        observation_raw: transaction_observation_raw,
        fault_raw: transaction_fault_raw,
        source_bytes,
        source_sha256: &source_sha256,
    })? {
        tx.commit()?;
        return Ok(LoweringStatusRecord::Terminal { fault });
    }

    let parse_error = serde_json::from_str::<Value>(raw)
        .expect_err("malformed lowering status was rechecked under the write transaction");
    let fault = json!({
        "schema": LOWERING_MALFORMED_FAULT_SCHEMA,
        "status": "error",
        "terminal": true,
        "pending": Value::Null,
        "freshness": "stale",
        "trust": "verified-terminal-refusal",
        "code": "ASTRO_LOWERING_STATUS_MALFORMED",
        "message": format!("durable lowering status row {key:?} for project {project:?} is not valid JSON: {parse_error}"),
        "remediation": "preserve the invalid lowering_debounce_json row and replace it only with one valid lowering status generation after inspecting the exact source identity",
        "project": project,
        "key": key,
        "source_present": true,
        "source_bytes": source_bytes,
        "source_sha256": source_sha256,
        "prior_observation_bytes": transaction_observation.as_ref().map(String::len),
        "prior_observation_sha256": transaction_observation.as_ref().map(|value| format!("{:x}", Sha256::digest(value.as_bytes()))),
        "prior_fault_bytes": transaction_fault.as_ref().map(String::len),
        "prior_fault_sha256": transaction_fault.as_ref().map(|value| format!("{:x}", Sha256::digest(value.as_bytes()))),
    });
    let serialized_fault = serde_json::to_string(&fault)?;
    let fault_sha256 = format!("{:x}", Sha256::digest(serialized_fault.as_bytes()));
    let expected_observation_raw = serde_json::to_string(&malformed_observation_json(
        project,
        key,
        raw,
        &fault_sha256,
    ))?;
    for (derived_key, value) in [
        (&observation_key, &expected_observation_raw),
        (&fault_key, &serialized_fault),
    ] {
        tx.execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value \
             WHERE config.value <> excluded.value",
            params![derived_key, value],
        )?;
    }
    tx.commit()?;

    let readback = read_config_values(cache_dir, &[key.to_string(), observation_key, fault_key])?;
    let expected = [
        Some(raw.to_string()),
        Some(expected_observation_raw.clone()),
        Some(serialized_fault.clone()),
    ];
    if readback.as_slice() != expected {
        return Err(format!(
            "ASTRO_LOWERING_TERMINAL_STATE_READBACK_MISMATCH: project {project:?} committed a terminal malformed-status classification, but independent exact-key readback differed; expected={expected:?}, actual={readback:?}; remediation: preserve the config database family and inspect the competing writer before retrying"
        )
        .into());
    }
    terminal_cache()
        .lock()
        .map_err(|_| "lowering terminal cache mutex poisoned")?
        .insert(
            lowering_registry_key(cache_dir, project),
            LoweringTerminalCacheEntry {
                source_raw: raw.to_string(),
                observation_raw: expected_observation_raw,
                fault_raw: serialized_fault,
                fault: fault.clone(),
            },
        );
    Err(format!(
        "ASTRO_LOWERING_STATUS_MALFORMED: durable lowering status row {key:?} for project {project:?} is not valid JSON; source_sha256={source_sha256}, source_bytes={source_bytes}; terminal diagnostic was persisted and independently read back; remediation: preserve the invalid row and inspect the durable malformed fault before replacing the source with one valid status generation"
    )
    .into())
}

fn clear_malformed_terminal_state(
    cache_dir: &Path,
    project: &str,
    key: &str,
    expected_raw: Option<&str>,
    observation_raw: Option<&str>,
    fault_raw: Option<&str>,
) -> Result<(), DynError> {
    if observation_raw.is_none() && fault_raw.is_none() {
        terminal_cache()
            .lock()
            .map_err(|_| "lowering terminal cache mutex poisoned")?
            .remove(&lowering_registry_key(cache_dir, project));
        return Ok(());
    }
    let observation_key = metadata_key(project, LOWERING_MALFORMED_OBSERVATION_KEY);
    let fault_key = metadata_key(project, LOWERING_MALFORMED_FAULT_KEY);
    let mut conn = open_config(cache_dir)?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let transaction_raw = tx
        .query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if transaction_raw.as_deref() != expected_raw {
        return Err(format!(
            "ASTRO_LOWERING_STATUS_REARM_SOURCE_CHANGED: durable lowering status row {key:?} for project {project:?} changed while clearing the prior malformed observation; expected={expected_raw:?}, actual={transaction_raw:?}; remediation: preserve the config store and classify the new exact source generation"
        )
        .into());
    }
    tx.execute(
        "DELETE FROM config WHERE key IN (?1, ?2)",
        params![&observation_key, &fault_key],
    )?;
    tx.commit()?;
    let readback = read_config_values(cache_dir, &[key.to_string(), observation_key, fault_key])?;
    let expected = [expected_raw.map(ToOwned::to_owned), None, None];
    if readback.as_slice() != expected {
        return Err(format!(
            "ASTRO_LOWERING_STATUS_REARM_READBACK_MISMATCH: project {project:?} cleared a stale malformed-status classification, but independent exact-key readback differed; expected={expected:?}, actual={readback:?}; remediation: preserve the config database family and inspect the competing writer before retrying"
        )
        .into());
    }
    terminal_cache()
        .lock()
        .map_err(|_| "lowering terminal cache mutex poisoned")?
        .remove(&lowering_registry_key(cache_dir, project));
    Ok(())
}

fn persist_lowering_status_if_changed(
    cache_dir: &Path,
    project: &str,
    current_raw: Option<&str>,
    status: &Value,
) -> Result<(), DynError> {
    let key = metadata_key(project, LOWERING_DEBOUNCE_STATUS_KEY);
    let serialized = serde_json::to_string(status)?;
    if current_raw == Some(serialized.as_str()) {
        return Ok(());
    }

    write_config_value(cache_dir, &key, &serialized).map_err(|error| -> DynError {
        format!(
            "ASTRO_LOWERING_STATUS_WRITE_FAILED: failed to persist durable lowering status row {key:?} for project {project:?}: {error}; remediation: preserve the config store and inspect its writable SQLite state"
        )
        .into()
    })?;
    let readback = read_config_value(cache_dir, &key).map_err(|error| -> DynError {
        format!(
            "ASTRO_LOWERING_STATUS_READBACK_FAILED: persisted durable lowering status row {key:?} for project {project:?}, but its independent read failed: {error}; remediation: preserve the config store and inspect the exact SQLite transaction"
        )
        .into()
    })?;
    if readback.as_deref() != Some(serialized.as_str()) {
        return Err(format!(
            "ASTRO_LOWERING_STATUS_READBACK_MISMATCH: durable lowering status row {key:?} for project {project:?} did not equal its exact write; expected={serialized:?}, actual={readback:?}; remediation: preserve the config store and inspect the exact SQLite transaction"
        )
        .into());
    }
    Ok(())
}

pub(crate) fn persist_regenerated_lowering(
    cache_dir: &Path,
    project: &str,
    report: &astrolabe_lower::LoweredSqliteReport,
) -> Result<(), DynError> {
    let conn = open_config(cache_dir)?;
    let tx = conn.unchecked_transaction()?;
    for (name, value) in [
        (LOWERING_PENDING_KEY, "false".to_string()),
        (
            "lowered_sqlite_path",
            report.output_path.display().to_string(),
        ),
        ("lowered_artifact_sha256", report.artifact_sha256.clone()),
        (
            "lowered_vault_fingerprint_sha256",
            report.vault_fingerprint_sha256.clone(),
        ),
        ("lowered_manifest_seq", report.manifest_seq.to_string()),
        ("lowered_nodes", report.node_count.to_string()),
        ("lowered_edges", report.edge_count.to_string()),
        ("lowered_skipped_edges", report.skipped_edges.to_string()),
    ] {
        tx.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            params![metadata_key(project, name), value],
        )?;
    }
    tx.commit()?;
    Ok(())
}
