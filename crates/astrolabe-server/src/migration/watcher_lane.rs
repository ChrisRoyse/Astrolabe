use super::*;

use std::io::Read;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use astrolabe_bridge::{BridgeError, CbmWatcher, ErrorEnvelope};
use astrolabe_domain::knobs::WATCHER_DEFAULT_POLL_INTERVAL_MS;

use super::dispatch::handle_index_repository;

pub(crate) const WATCHER_TICK_STATUS_KEY: &str = "watcher_tick_json";
pub(crate) const WATCHER_FAULT_STATUS_KEY: &str = "watcher_fault_json";

#[derive(Debug, Clone, Eq, PartialEq)]
struct WatchRegistration {
    project: String,
    root: String,
}

pub(crate) fn run_incremental_watcher_loop(shutdown: Arc<AtomicBool>) -> Result<(), DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let runner = Rc::new(CbmToolRunner::new_default()?);
    let callback_runner = Rc::clone(&runner);
    let callback_cache = cache_dir.clone();
    let mut watcher = CbmWatcher::new_for_polling(move |project, root| {
        run_watcher_index_tick(&callback_runner, &callback_cache, project, root)
            .map_err(watcher_bridge_error)
    })?;
    let mut registered = BTreeMap::<String, String>::new();
    let mut prior_policy_observation = None::<String>;

    while !shutdown.load(Ordering::Relaxed) {
        let policy = read_auto_watch_policy_at(&cache_dir);
        let observation = match &policy {
            Ok(true) => "enabled".to_string(),
            Ok(false) => "disabled".to_string(),
            Err(error) => format!("error:{error}"),
        };
        if prior_policy_observation.as_deref() != Some(observation.as_str()) {
            match &policy {
                Ok(true) => tracing::info!(
                    key = AUTO_WATCH_CONFIG_KEY,
                    "incremental_watcher.policy_enabled"
                ),
                Ok(false) => tracing::info!(
                    key = AUTO_WATCH_CONFIG_KEY,
                    "incremental_watcher.policy_disabled"
                ),
                Err(error) => tracing::warn!(
                    code = error.code,
                    key = AUTO_WATCH_CONFIG_KEY,
                    error = %error,
                    "incremental_watcher.policy_refused"
                ),
            }
            prior_policy_observation = Some(observation);
        }
        if !matches!(policy, Ok(true)) {
            unwatch_all(&mut watcher, &mut registered)?;
            sleep_watcher_slice(&shutdown);
            continue;
        }

        let discovered = discover_watch_registrations(&cache_dir)?;
        let desired = discovered
            .iter()
            .map(|registration| (registration.project.clone(), registration.root.clone()))
            .collect::<BTreeMap<_, _>>();
        for stale in registered
            .keys()
            .filter(|project| !desired.contains_key(*project))
            .cloned()
            .collect::<Vec<_>>()
        {
            watcher.unwatch(&stale)?;
            registered.remove(&stale);
        }
        for registration in discovered {
            if registered.get(&registration.project) == Some(&registration.root) {
                continue;
            }
            if registered.contains_key(&registration.project) {
                watcher.unwatch(&registration.project)?;
            }
            watcher.watch(&registration.project, &registration.root)?;
            registered.insert(registration.project, registration.root);
        }

        rearm_changed_faults(&cache_dir, &registered, &mut watcher)?;

        if let Err(error) = watcher.poll_once() {
            tracing::warn!(
                code = %error.envelope().code,
                message = %error.envelope().message,
                "incremental_watcher.poll_failed"
            );
        }
        for project in registered.keys() {
            if let Err(error) = drive_project_lowering(&cache_dir, project) {
                tracing::warn!(
                    project,
                    error = %error,
                    "incremental_watcher.lowering_tick_failed"
                );
            }
        }
        sleep_watcher_slice(&shutdown);
    }
    Ok(())
}

fn discover_watch_registrations(cache_dir: &Path) -> Result<Vec<WatchRegistration>, DynError> {
    let mut registrations = Vec::new();
    let index_args_suffix = format!(".{SHADOW_INDEX_ARGS_KEY}");
    for (key, args_json) in scan_config_prefix(cache_dir, CONFIG_KEY_PREFIX)? {
        if !key.ends_with(&index_args_suffix) {
            continue;
        }
        let Some(project) = project_from_metadata_key(&key, SHADOW_INDEX_ARGS_KEY) else {
            continue;
        };
        let args: Value = match serde_json::from_str(&args_json) {
            Ok(args) => args,
            Err(error) => {
                persist_registration_error(
                    cache_dir,
                    &project,
                    &format!("persisted index args are invalid JSON: {error}"),
                )?;
                continue;
            }
        };
        let Some(args) = args.as_object() else {
            persist_registration_error(
                cache_dir,
                &project,
                "persisted index args are not an object",
            )?;
            continue;
        };
        let Some(root) = string_arg(args, "repo_path").or_else(|| string_arg(args, "name")) else {
            persist_registration_error(
                cache_dir,
                &project,
                "persisted index args have neither repo_path nor name",
            )?;
            continue;
        };
        let ownership = match background_lane_status_at(cache_dir, &project) {
            Ok(ownership) => ownership,
            Err(error) => {
                persist_registration_error(
                    cache_dir,
                    &project,
                    &format!("background-lane ownership probe failed: {error}"),
                )?;
                continue;
            }
        };
        if ownership.get("single_owner").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        registrations.push(WatchRegistration {
            project,
            root: root.to_string(),
        });
    }
    Ok(registrations)
}

fn unwatch_all(
    watcher: &mut CbmWatcher,
    registered: &mut BTreeMap<String, String>,
) -> Result<(), BridgeError> {
    for project in registered.keys().cloned().collect::<Vec<_>>() {
        watcher.unwatch(&project)?;
        registered.remove(&project);
    }
    Ok(())
}

fn persist_registration_error(
    cache_dir: &Path,
    project: &str,
    message: &str,
) -> Result<(), DynError> {
    let status = json!({
        "schema": "astrolabe-watcher-tick-v1",
        "status": "error",
        "project": project,
        "elapsed_ms": 0,
        "freshness": "stale",
        "trust": "provisional",
        "code": "ASTRO_WATCHER_REGISTRATION_INVALID",
        "message": message,
        "remediation": "repair the persisted index_repository arguments and retry registration",
    });
    write_config_value(
        cache_dir,
        &metadata_key(project, WATCHER_TICK_STATUS_KEY),
        &serde_json::to_string(&status)?,
    )?;
    Ok(())
}

fn run_watcher_index_tick(
    runner: &CbmToolRunner,
    cache_dir: &Path,
    project: &str,
    root: &str,
) -> Result<(), DynError> {
    let Some(raw_args) =
        read_config_value(cache_dir, &metadata_key(project, SHADOW_INDEX_ARGS_KEY))?
    else {
        return Err(format!("watcher project {project:?} has no persisted index args").into());
    };
    let mut args: Value = serde_json::from_str(&raw_args)?;
    let Some(object) = args.as_object_mut() else {
        return Err(format!("watcher project {project:?} index args are not an object").into());
    };
    object.insert("repo_path".to_string(), Value::String(root.to_string()));
    object.insert("calyx".to_string(), Value::String("shadow".to_string()));
    let normalized_args = serde_json::to_string(&args)?;
    let fault_key = metadata_key(project, WATCHER_FAULT_STATUS_KEY);
    let prior_fault = read_config_value(cache_dir, &fault_key)?
        .map(|raw| serde_json::from_str::<Value>(&raw))
        .transpose()?;
    let observation = watcher_observation(
        cache_dir,
        project,
        root,
        &normalized_args,
        prior_fault
            .as_ref()
            .and_then(|fault| fault.get("observation")),
    )?;
    let observation_sha256 = value_sha256(&observation)?;
    if prior_fault
        .as_ref()
        .and_then(|fault| fault.get("observation_sha256"))
        .and_then(Value::as_str)
        == Some(observation_sha256.as_str())
    {
        let status = json!({
            "schema": "astrolabe-watcher-tick-v2",
            "status": "suppressed_terminal_fault",
            "project": project,
            "fault_code": prior_fault.as_ref().and_then(|fault| fault.get("fault_code")),
            "observation_sha256": observation_sha256,
            "freshness": "stale",
            "trust": "verified",
            "worker_started": false,
            "remediation": "change the exact source/store/config state named by watcher_fault_json, or install a corrected binary generation",
        });
        persist_watcher_status(cache_dir, project, &status)?;
        return Ok(());
    }
    if prior_fault.is_some() {
        delete_watcher_fault(cache_dir, &fault_key)?;
    }
    let started = Instant::now();
    let response = handle_index_repository(runner, &normalized_args)?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    if tool_result_is_error(&response)? {
        if let Some(fault_code) = terminal_watcher_fault_code(&response) {
            let fault = json!({
                "schema": "astrolabe-watcher-fault-v1",
                "status": "terminal_fault",
                "project": project,
                "fault_code": fault_code,
                "observation": observation,
                "observation_sha256": observation_sha256,
                "rearm_signature": watcher_rearm_signature(cache_dir, project, &normalized_args)?,
                "response_sha256": hex_lower(&Sha256::digest(response.as_bytes())),
                "worker_started": true,
                "retry_suppressed_until_observation_changes": true,
                "remediation": "repair or replace the exact source/store/config state; unchanged periodic retries are suppressed",
            });
            write_config_value(cache_dir, &fault_key, &serde_json::to_string(&fault)?)?;
            let readback = read_config_value(cache_dir, &fault_key)?;
            if readback.as_deref() != Some(serde_json::to_string(&fault)?.as_str()) {
                return Err(format!(
                    "ASTRO_WATCHER_FAULT_READBACK_MISMATCH: persisted fault for {project:?} did not match its exact write"
                )
                .into());
            }
            let status = json!({
                "schema": "astrolabe-watcher-tick-v2",
                "status": "terminal_fault_recorded",
                "project": project,
                "fault_code": fault_code,
                "elapsed_ms": elapsed_ms,
                "observation_sha256": fault.get("observation_sha256"),
                "response_sha256": fault.get("response_sha256"),
                "freshness": "stale",
                "trust": "verified",
                "worker_started": true,
                "retry_suppressed_until_observation_changes": true,
            });
            persist_watcher_status(cache_dir, project, &status)?;
            // The indexing operation failed, but change-detection coordination
            // converged: advancing the C baseline is what prevents a second
            // identical worker. The durable fault remains the serving truth.
            return Ok(());
        }
        let status = json!({
            "schema": "astrolabe-watcher-tick-v2",
            "status": "transient_error",
            "project": project,
            "elapsed_ms": elapsed_ms,
            "freshness": "stale",
            "trust": "provisional",
            "response_hash": hex_lower(&Sha256::digest(response.as_bytes())),
            "remediation": "inspect the index_repository error and retry the watcher tick",
        });
        persist_watcher_status(cache_dir, project, &status)?;
        return Err(format!("watcher index tick failed for {project:?}").into());
    }
    delete_watcher_fault(cache_dir, &fault_key)?;
    // P7.4 (#368): after the delta converges, auto-extract this project's newest
    // commit diff into a pending commit-OOD request (changed symbols + enclosing
    // exemplars, derived from the indexed graph). The producer advances its own
    // per-commit baseline and never crashes the tick — a git/vault fault is a
    // labeled degradation.
    let commit_ood_producer = match produce_commit_ood_request(cache_dir, project, root) {
        Ok(summary) => summary,
        Err(error) => {
            tracing::warn!(
                project,
                error = %error,
                "incremental_watcher.commit_ood_producer_failed"
            );
            json!({"status": "degraded", "reason": error.to_string()})
        }
    };

    // P7.4 (#48 DoD 3, #355): after the delta converges, score any pending
    // commit-OOD request for this project through the shared panel instrument
    // (#341 per-snippet reparse) and surface OOD verdicts on the review surface.
    // This is measurement inside the live watcher tick — a bad request is labeled
    // (never a silent swallow) and never crashes the tick.
    let commit_ood = match score_pending_commit_ood(cache_dir, project) {
        Ok(triggers) => json!({"status": "scored", "ood_triggers": triggers}),
        Err(error) => {
            tracing::warn!(
                project,
                error = %error,
                "incremental_watcher.commit_ood_tick_failed"
            );
            json!({"status": "degraded", "reason": error.to_string()})
        }
    };

    let status = json!({
        "schema": "astrolabe-watcher-tick-v2",
        "status": "converged",
        "project": project,
        "elapsed_ms": elapsed_ms,
        "freshness": "fresh",
        "trust": "verified",
        "response_hash": hex_lower(&Sha256::digest(response.as_bytes())),
        "commit_ood_producer": commit_ood_producer,
        "commit_ood": commit_ood,
    });
    persist_watcher_status(cache_dir, project, &status)?;
    Ok(())
}

fn rearm_changed_faults(
    cache_dir: &Path,
    registered: &BTreeMap<String, String>,
    watcher: &mut CbmWatcher,
) -> Result<(), DynError> {
    for (project, root) in registered {
        let fault_key = metadata_key(project, WATCHER_FAULT_STATUS_KEY);
        let Some(raw_fault) = read_config_value(cache_dir, &fault_key)? else {
            continue;
        };
        let fault: Value = serde_json::from_str(&raw_fault)?;
        let raw_args = read_config_value(cache_dir, &metadata_key(project, SHADOW_INDEX_ARGS_KEY))?
            .ok_or_else(|| -> DynError {
                format!("watcher project {project:?} lost persisted index args while a terminal fault was active").into()
            })?;
        let mut args: Value = serde_json::from_str(&raw_args)?;
        let args = args.as_object_mut().ok_or_else(|| -> DynError {
            format!("watcher project {project:?} persisted index args are not an object").into()
        })?;
        args.insert("repo_path".to_string(), Value::String(root.clone()));
        args.insert("calyx".to_string(), Value::String("shadow".to_string()));
        let normalized_args = serde_json::to_string(&args)?;
        let current = watcher_rearm_signature(cache_dir, project, &normalized_args)?;
        if fault.get("rearm_signature") == Some(&current) {
            continue;
        }
        watcher.invalidate(project)?;
        let status = json!({
            "schema": "astrolabe-watcher-tick-v2",
            "status": "rearmed",
            "project": project,
            "root": root,
            "prior_observation_sha256": fault.get("observation_sha256"),
            "prior_rearm_signature": fault.get("rearm_signature"),
            "current_rearm_signature": current,
            "freshness": "stale",
            "trust": "verified",
            "worker_started": false,
        });
        persist_watcher_status(cache_dir, project, &status)?;
    }
    Ok(())
}

fn watcher_observation(
    cache_dir: &Path,
    project: &str,
    root: &str,
    args_json: &str,
    prior: Option<&Value>,
) -> Result<Value, DynError> {
    let source_fingerprint =
        astrolabe_anchors::archaeology::git_source_fingerprint(Path::new(root))?;
    let mut members = Vec::new();
    for path in store_family_paths(cache_dir, project) {
        let metadata = file_metadata_observation(&path)?;
        let prior_member = prior
            .and_then(|value| value.get("store_family"))
            .and_then(Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item.get("path") == Some(&json!(path)))
            });
        let sha256 = if prior_member.and_then(|item| item.get("metadata")) == Some(&metadata) {
            prior_member
                .and_then(|item| item.get("sha256"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| "absent".to_string())
        } else if metadata.get("present").and_then(Value::as_bool) == Some(true) {
            sha256_file(&path)?
        } else {
            "absent".to_string()
        };
        members.push(json!({"path": path, "metadata": metadata, "sha256": sha256}));
    }
    Ok(json!({
        "schema": "astrolabe-watcher-observation-v1",
        "project": project,
        "canonical_root": fs::canonicalize(root)?,
        "source_fingerprint": source_fingerprint,
        "index_args_sha256": hex_lower(&Sha256::digest(args_json.as_bytes())),
        "store_family": members,
        "executable": executable_observation()?,
    }))
}

fn watcher_rearm_signature(
    cache_dir: &Path,
    project: &str,
    args_json: &str,
) -> Result<Value, DynError> {
    let store_family = store_family_paths(cache_dir, project)
        .into_iter()
        .map(|path| Ok(json!({"path": path, "metadata": file_metadata_observation(&path)?})))
        .collect::<Result<Vec<_>, DynError>>()?;
    Ok(json!({
        "schema": "astrolabe-watcher-rearm-v1",
        "index_args_sha256": hex_lower(&Sha256::digest(args_json.as_bytes())),
        "store_family": store_family,
        "executable": executable_observation()?,
    }))
}

fn store_family_paths(cache_dir: &Path, project: &str) -> [PathBuf; 3] {
    let db = sqlite_path(cache_dir, project);
    [
        db.clone(),
        PathBuf::from(format!("{}-wal", db.display())),
        PathBuf::from(format!("{}-shm", db.display())),
    ]
}

fn executable_observation() -> Result<Value, DynError> {
    static OBSERVATION: OnceLock<Result<Value, String>> = OnceLock::new();
    OBSERVATION
        .get_or_init(|| {
            let path = std::env::current_exe().map_err(|error| error.to_string())?;
            let metadata = file_metadata_observation(&path).map_err(|error| error.to_string())?;
            let sha256 = sha256_file(&path).map_err(|error| error.to_string())?;
            Ok(json!({"path": path, "metadata": metadata, "sha256": sha256}))
        })
        .clone()
        .map_err(Into::into)
}

fn file_metadata_observation(path: &Path) -> Result<Value, DynError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(json!({
            "present": true,
            "bytes": metadata.len(),
            "modified_unix_ns": metadata.modified()?.duration_since(UNIX_EPOCH)?.as_nanos(),
            "created_unix_ns": metadata.created()?.duration_since(UNIX_EPOCH)?.as_nanos(),
            "readonly": metadata.permissions().readonly(),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(json!({"present": false}))
        }
        Err(error) => Err(format!(
            "ASTRO_WATCHER_OBSERVATION_FAILED: metadata read for {} failed: {error}; remediation: restore readable source/store state before watcher retry",
            path.display()
        )
        .into()),
    }
}

fn sha256_file(path: &Path) -> Result<String, DynError> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn value_sha256(value: &Value) -> Result<String, DynError> {
    Ok(hex_lower(&Sha256::digest(serde_json::to_vec(value)?)))
}

fn terminal_watcher_fault_code(response: &str) -> Option<&'static str> {
    const TERMINAL_CODES: &[&str] = &[
        "CBM_SCHEMA_VERSION_UNSTAMPED",
        "CBM_SCHEMA_VERSION_UNSUPPORTED",
        "CBM_SCHEMA_FRESHNESS_UNREADABLE",
        "CBM_PIPELINE_EMPTY_SOURCE_CORPUS",
        "CBM_STORE_INTEGRITY_FAILED",
        "CBM_STORE_PROVENANCE_FAILED",
        "ASTRO_SHADOW_PROJECT_MISMATCH",
    ];
    TERMINAL_CODES
        .iter()
        .copied()
        .find(|code| response.contains(code))
}

fn persist_watcher_status(cache_dir: &Path, project: &str, status: &Value) -> Result<(), DynError> {
    let key = metadata_key(project, WATCHER_TICK_STATUS_KEY);
    let serialized = serde_json::to_string(status)?;
    write_config_value(cache_dir, &key, &serialized)?;
    if read_config_value(cache_dir, &key)?.as_deref() != Some(serialized.as_str()) {
        return Err(format!(
            "ASTRO_WATCHER_STATUS_READBACK_MISMATCH: durable status row for {project:?} did not equal its exact write"
        )
        .into());
    }
    Ok(())
}

fn delete_watcher_fault(cache_dir: &Path, key: &str) -> Result<(), DynError> {
    delete_config_value(cache_dir, key)?;
    if read_config_value(cache_dir, key)?.is_some() {
        return Err(format!(
            "ASTRO_WATCHER_FAULT_DELETE_READBACK_MISMATCH: durable fault row {key:?} remained after deletion"
        )
        .into());
    }
    Ok(())
}

fn watcher_bridge_error(error: DynError) -> BridgeError {
    BridgeError::new(
        ErrorEnvelope::new(
            "ASTRO_WATCHER_DELTA_FAILED",
            error.to_string(),
            "inspect the persisted watcher tick status, repair the project, and retry",
        )
        .with_stderr(error.to_string()),
    )
}

fn sleep_watcher_slice(shutdown: &AtomicBool) {
    let slice = Duration::from_millis(WATCHER_DEFAULT_POLL_INTERVAL_MS);
    let mut elapsed = Duration::ZERO;
    let interval = Duration::from_millis(WATCHER_DEFAULT_POLL_INTERVAL_MS);
    while elapsed < interval && !shutdown.load(Ordering::Relaxed) {
        thread::sleep(slice.min(interval.saturating_sub(elapsed)));
        elapsed += slice;
    }
}
