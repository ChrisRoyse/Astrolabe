use super::*;

use std::sync::Arc;

use astrolabe_domain::LoweringTrigger;
use astrolabe_lower::{LowerDebouncer, RunOutcome};
use calyx_core::SystemClock;

pub(crate) const LOWERING_DEBOUNCE_STATUS_KEY: &str = "lowering_debounce_json";
const LOWERING_PENDING_KEY: &str = "lowering_pending";

static LOWERING_DEBOUNCERS: OnceLock<Mutex<BTreeMap<String, Arc<LowerDebouncer<SystemClock>>>>> =
    OnceLock::new();

fn debouncers() -> &'static Mutex<BTreeMap<String, Arc<LowerDebouncer<SystemClock>>>> {
    LOWERING_DEBOUNCERS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn project_debouncer(
    cache_dir: &Path,
    project: &str,
) -> Result<Arc<LowerDebouncer<SystemClock>>, DynError> {
    let mut map = debouncers()
        .lock()
        .map_err(|_| "lowering debouncer registry mutex poisoned")?;
    let registry_key = format!("{}\0{project}", cache_dir.display());
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

pub(crate) fn schedule_project_lowering(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let debouncer = project_debouncer(cache_dir, project)?;
    debouncer.request_regeneration();
    write_config_value(
        cache_dir,
        &metadata_key(project, LOWERING_PENDING_KEY),
        "true",
    )?;
    let status = json!({
        "schema": "astrolabe-lowering-debounce-v1",
        "status": "waiting",
        "pending": true,
        "window_ms": debouncer.window_ms(),
        "freshness": "stale",
        "trust": "verified",
        "provenance": "production weave mutation scheduled trailing-edge regeneration",
    });
    write_config_value(
        cache_dir,
        &metadata_key(project, LOWERING_DEBOUNCE_STATUS_KEY),
        &serde_json::to_string(&status)?,
    )?;
    Ok(status)
}

pub(crate) fn schedule_lowering_after_convergence(
    cache_dir: &Path,
    project: &str,
    import_changed: bool,
    weave: &Value,
) -> Result<Option<Value>, DynError> {
    if import_changed || weave_mutated_lower_inputs(weave) {
        Ok(Some(schedule_project_lowering(cache_dir, project)?))
    } else {
        Ok(None)
    }
}

fn weave_mutated_lower_inputs(weave: &Value) -> bool {
    ["similarity", "eager_cross_terms"].into_iter().any(|name| {
        weave[name]["rows_written"].as_u64().unwrap_or(0) > 0
            || weave[name]["rows_tombstoned"].as_u64().unwrap_or(0) > 0
    })
}

pub(crate) fn drive_project_lowering(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    let debouncer = project_debouncer(cache_dir, project)?;
    let status = match debouncer.run_due(|| regenerate_lowered_under_lock(cache_dir, project)) {
        Ok(RunOutcome::Idle) => read_lowering_status(cache_dir, project)?.unwrap_or_else(|| {
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
    write_config_value(
        cache_dir,
        &metadata_key(project, LOWERING_DEBOUNCE_STATUS_KEY),
        &serde_json::to_string(&status)?,
    )?;
    Ok(status)
}

pub(crate) fn read_lowering_status(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<Value>, DynError> {
    read_config_value(
        cache_dir,
        &metadata_key(project, LOWERING_DEBOUNCE_STATUS_KEY),
    )?
    .map(|raw| serde_json::from_str(&raw).map_err(Into::into))
    .transpose()
}

fn persist_regenerated_lowering(
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
        ("ledger_seq", report.manifest_seq.to_string()),
    ] {
        tx.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            params![metadata_key(project, name), value],
        )?;
    }
    tx.commit()?;
    Ok(())
}
