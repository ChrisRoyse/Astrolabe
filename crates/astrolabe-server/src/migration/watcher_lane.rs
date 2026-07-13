use super::*;

use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use astrolabe_bridge::{BridgeError, CbmWatcher, ErrorEnvelope};
use astrolabe_domain::knobs::WATCHER_DEFAULT_POLL_INTERVAL_MS;

use super::dispatch::handle_index_repository;

pub(crate) const WATCHER_TICK_STATUS_KEY: &str = "watcher_tick_json";

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

    while !shutdown.load(Ordering::Relaxed) {
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

        // The C watcher retains its own per-project baseline and worktree
        // fingerprint. The server owns the shipping convergence budget, so it
        // resets adaptive backoff at the registry-declared product cadence.
        for project in registered.keys() {
            watcher.touch(project)?;
        }

        if let Err(error) = watcher.poll_once() {
            tracing::warn!(
                code = %error.envelope().code,
                message = %error.envelope().message,
                "incremental_watcher.poll_failed"
            );
        }
        sleep_watcher_slice(&shutdown);
    }
    Ok(())
}

fn discover_watch_registrations(cache_dir: &Path) -> Result<Vec<WatchRegistration>, DynError> {
    let conn = open_config(cache_dir)?;
    let pattern = format!("{CONFIG_KEY_PREFIX}%.{SHADOW_INDEX_ARGS_KEY}");
    let mut statement =
        conn.prepare("SELECT key, value FROM config WHERE key LIKE ? ORDER BY key")?;
    let rows = statement.query_map(params![pattern], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut registrations = Vec::new();
    for row in rows {
        let (key, args_json) = row?;
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
    let started = Instant::now();
    let response = handle_index_repository(runner, &serde_json::to_string(&args)?)?;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    if tool_result_is_error(&response)? {
        let status = json!({
            "schema": "astrolabe-watcher-tick-v1",
            "status": "error",
            "project": project,
            "elapsed_ms": elapsed_ms,
            "freshness": "stale",
            "trust": "provisional",
            "response_hash": hex_lower(&Sha256::digest(response.as_bytes())),
            "remediation": "inspect the index_repository error and retry the watcher tick",
        });
        write_config_value(
            cache_dir,
            &metadata_key(project, WATCHER_TICK_STATUS_KEY),
            &serde_json::to_string(&status)?,
        )?;
        return Err(format!("watcher index tick failed for {project:?}").into());
    }
    let status = json!({
        "schema": "astrolabe-watcher-tick-v1",
        "status": "converged",
        "project": project,
        "elapsed_ms": elapsed_ms,
        "freshness": "fresh",
        "trust": "verified",
        "response_hash": hex_lower(&Sha256::digest(response.as_bytes())),
    });
    write_config_value(
        cache_dir,
        &metadata_key(project, WATCHER_TICK_STATUS_KEY),
        &serde_json::to_string(&status)?,
    )?;
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
