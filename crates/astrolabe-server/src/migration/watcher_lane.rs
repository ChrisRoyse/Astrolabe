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
pub(crate) const WATCHER_REGISTRATION_FAULT_STATUS_KEY: &str = "watcher_registration_fault_json";

#[derive(Debug, Clone, Eq, PartialEq)]
struct WatchRegistration {
    project: String,
    root: String,
}

struct RegistrationRecoveryRefresh<'a> {
    fault_code: &'a str,
    prior_fault: &'a Value,
    prior_observation: &'a Value,
    current_sentinel: Value,
    recompute_reason: &'a str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct InvalidRegistrationRecoveryObservation {
    raw_sha256: String,
    raw_bytes: usize,
}

#[derive(Debug)]
struct RegistrationRecoveryRefusal {
    code: String,
    message: String,
    observation: InvalidRegistrationRecoveryObservation,
}

#[derive(Debug)]
enum RegistrationRecoveryDisposition {
    Proceed,
    Suppress,
    Refuse(RegistrationRecoveryRefusal),
}

#[derive(Debug)]
enum RegistrationCatchUpDisposition {
    PublicationInFlight,
    Ready(Option<Value>),
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
    let mut invalid_registration_recovery_observations =
        BTreeMap::<String, InvalidRegistrationRecoveryObservation>::new();
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
            invalid_registration_recovery_observations.clear();
            sleep_watcher_slice(&shutdown);
            continue;
        }

        let discovered = discover_watch_registrations(&cache_dir)?;
        let desired = discovered
            .iter()
            .map(|registration| (registration.project.clone(), registration.root.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut catch_up_registrations = Vec::new();
        for stale in registered
            .keys()
            .filter(|project| !desired.contains_key(*project))
            .cloned()
            .collect::<Vec<_>>()
        {
            watcher.unwatch(&stale)?;
            registered.remove(&stale);
            invalid_registration_recovery_observations.remove(&stale);
        }
        for registration in discovered {
            if registered.get(&registration.project) == Some(&registration.root) {
                continue;
            }
            match registration_recovery_disposition(
                &cache_dir,
                &registration,
                &mut invalid_registration_recovery_observations,
            ) {
                Ok(RegistrationRecoveryDisposition::Suppress) => continue,
                Ok(RegistrationRecoveryDisposition::Proceed) => {}
                Ok(RegistrationRecoveryDisposition::Refuse(refusal)) => {
                    let status_changed = persist_registration_recovery_validation_refusal(
                        &cache_dir,
                        &registration,
                        &refusal,
                    )?;
                    invalid_registration_recovery_observations
                        .insert(registration.project.clone(), refusal.observation.clone());
                    if status_changed {
                        tracing::warn!(
                            project = %registration.project,
                            root = %registration.root,
                            code = %refusal.code,
                            observation_sha256 = %refusal.observation.raw_sha256,
                            observation_bytes = refusal.observation.raw_bytes,
                            error = %refusal.message,
                            "incremental_watcher.registration_recovery_fault_validation_refused"
                        );
                    }
                    continue;
                }
                Err(error) => {
                    let message =
                        format!("durable registration recovery fault validation failed: {error}");
                    if persist_registration_error(&cache_dir, &registration.project, &message)? {
                        tracing::warn!(
                            project = %registration.project,
                            root = %registration.root,
                            error = %error,
                            "incremental_watcher.registration_recovery_fault_validation_refused"
                        );
                    }
                    continue;
                }
            }
            if registered.contains_key(&registration.project) {
                watcher.unwatch(&registration.project)?;
                registered.remove(&registration.project);
            }
            let catch_up = match registration_catch_up_status(&cache_dir, &registration) {
                Ok(RegistrationCatchUpDisposition::PublicationInFlight) => continue,
                Ok(RegistrationCatchUpDisposition::Ready(status)) => status,
                Err(error) => {
                    record_registration_reconciliation_refusal(&cache_dir, &registration, error)?;
                    continue;
                }
            };
            invalid_registration_recovery_observations.remove(&registration.project);
            if let Some(status) = &catch_up {
                persist_watcher_status(&cache_dir, &registration.project, status)?;
                tracing::info!(
                    project = %registration.project,
                    root = %registration.root,
                    verification = status.get("verification").and_then(|value| value.as_str()),
                    "incremental_watcher.catch_up_scheduled"
                );
            }
            watcher.watch(&registration.project, &registration.root)?;
            if catch_up.is_none() {
                clear_resolved_registration_error(&cache_dir, &registration.project)?;
            }
            if catch_up.is_some() {
                catch_up_registrations.push(registration.clone());
            }
            registered.insert(registration.project, registration.root);
        }

        // A newly watched C registration has no baseline. Its first poll must
        // initialize that local observation before invalidation; otherwise
        // `init_baseline` overwrites the invalidation sentinel and silently
        // accepts changes made while disabled or while this process was down
        // (#828). Durable source truth above decides which newly initialized
        // registrations must be invalidated, never the in-memory baseline.
        poll_incremental_watcher(&mut watcher);
        rearm_changed_faults(&cache_dir, &registered, &mut watcher)?;
        for registration in &catch_up_registrations {
            watcher.invalidate(&registration.project)?;
        }
        if !catch_up_registrations.is_empty() {
            poll_incremental_watcher(&mut watcher);
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

fn registration_catch_up_status(
    cache_dir: &Path,
    registration: &WatchRegistration,
) -> Result<RegistrationCatchUpDisposition, DynError> {
    match reconcile_shadow_publications_for_project(cache_dir, &registration.project)? {
        ShadowPublicationReconciliation::Absent => {}
        ShadowPublicationReconciliation::Reconciled => {
            tracing::info!(
                project = %registration.project,
                root = %registration.root,
                "incremental_watcher.publication_recovered"
            );
        }
        ShadowPublicationReconciliation::Active { .. } => {
            return Ok(RegistrationCatchUpDisposition::PublicationInFlight);
        }
    }
    let fingerprint_key = metadata_key(&registration.project, GIT_SOURCE_FINGERPRINT_KEY);
    let root_key = metadata_key(&registration.project, GIT_SOURCE_REPO_PATH_KEY);
    let persisted_fingerprint =
        read_config_value(cache_dir, &fingerprint_key)?.filter(|value| !value.trim().is_empty());
    let persisted_root =
        read_config_value(cache_dir, &root_key)?.filter(|value| !value.trim().is_empty());

    // Non-Git corpora have no Git source checkpoint and the native watcher has
    // no Git strategy for them. Preserve that explicit no-watch behavior. A
    // Git corpus with a missing checkpoint must be indexed once to mint it.
    if persisted_fingerprint.is_none()
        && !astrolabe_anchors::archaeology::is_git_work_tree(Path::new(&registration.root))
    {
        return Ok(RegistrationCatchUpDisposition::Ready(None));
    }

    let canonical_root = fs::canonicalize(&registration.root).map_err(|error| {
        format!(
            "ASTRO_WATCHER_CATCH_UP_ROOT_UNREADABLE: could not canonicalize current root {:?} for project {:?}: {error}. Remediation: restore the persisted source root before automatic indexing can resume",
            registration.root, registration.project
        )
    })?;
    let (persisted_canonical_root, persisted_root_error) = match persisted_root.as_deref() {
        Some(root) => match fs::canonicalize(root) {
            Ok(root) => (Some(root), None),
            Err(error) => (None, Some(error.to_string())),
        },
        None => (None, None),
    };
    let root_matches = persisted_canonical_root.as_ref() == Some(&canonical_root);
    let live_fingerprint =
        astrolabe_anchors::archaeology::git_source_fingerprint(Path::new(&registration.root))?;
    if root_matches && persisted_fingerprint.as_deref() == Some(live_fingerprint.as_str()) {
        return Ok(RegistrationCatchUpDisposition::Ready(None));
    }

    let verification = if persisted_fingerprint.is_none() {
        "source_checkpoint_missing"
    } else if !root_matches {
        "source_checkpoint_root_mismatch"
    } else {
        "source_fingerprint_mismatch"
    };
    Ok(RegistrationCatchUpDisposition::Ready(Some(json!({
        "schema": "astrolabe-watcher-tick-v2",
        "status": "catch_up_scheduled",
        "project": registration.project,
        "root": registration.root,
        "verification": verification,
        "expected_source_fingerprint": persisted_fingerprint,
        "actual_source_fingerprint": live_fingerprint,
        "persisted_source_root": persisted_root,
        "persisted_canonical_root": persisted_canonical_root,
        "current_canonical_root": canonical_root,
        "persisted_root_canonicalization_error": persisted_root_error,
        "root_matches": root_matches,
        "freshness": "stale",
        "trust": "verified",
        "worker_started": false,
        "remediation": "allow the enabled resident lane to complete its scheduled failure-atomic index generation; inspect watcher_fault_json if it refuses",
    }))))
}

fn registration_recovery_disposition(
    cache_dir: &Path,
    registration: &WatchRegistration,
    invalid_observations: &mut BTreeMap<String, InvalidRegistrationRecoveryObservation>,
) -> Result<RegistrationRecoveryDisposition, DynError> {
    let Some(raw_fault) = read_registration_recovery_fault_raw(cache_dir, &registration.project)?
    else {
        invalid_observations.remove(&registration.project);
        return Ok(RegistrationRecoveryDisposition::Proceed);
    };
    let invalid_observation = InvalidRegistrationRecoveryObservation {
        raw_sha256: hex_lower(&Sha256::digest(raw_fault.as_bytes())),
        raw_bytes: raw_fault.len(),
    };
    if invalid_observations.get(&registration.project) == Some(&invalid_observation) {
        return Ok(RegistrationRecoveryDisposition::Suppress);
    }
    let prior_fault = match parse_registration_recovery_fault(&raw_fault, &registration.project) {
        Ok(fault) => fault,
        Err(error) => {
            return registration_recovery_refusal(invalid_observation, error);
        }
    };
    let prior_observation =
        match validated_registration_recovery_observation(&prior_fault, registration) {
            Ok(observation) => observation,
            Err(error) => {
                return registration_recovery_refusal(invalid_observation, error);
            }
        };
    let Some(fault_code) = prior_observation.get("fault_code").and_then(Value::as_str) else {
        return registration_recovery_refusal(
            invalid_observation,
            format!(
                "ASTRO_WATCHER_REGISTRATION_FAULT_CODE_MISSING: durable registration fault for {:?} has no structured fault_code; remediation: preserve the config store and inspect watcher_registration_fault_json",
                registration.project
            )
            .into(),
        );
    };
    invalid_observations.remove(&registration.project);
    let current_sentinel = match registration_recovery_sentinel(cache_dir, registration, fault_code)
    {
        Ok(Some(sentinel)) => sentinel,
        Ok(None) => {
            delete_registration_recovery_fault(cache_dir, &registration.project)?;
            return Ok(RegistrationRecoveryDisposition::Proceed);
        }
        Err(error) => {
            let sentinel_error = error.to_string();
            return recompute_after_current_sentinel_error(
                cache_dir,
                registration,
                fault_code,
                &prior_observation,
                &sentinel_error,
            );
        }
    };
    match validated_registration_recovery_sentinel(&prior_fault, registration, fault_code) {
        Ok(prior_sentinel) if prior_sentinel == current_sentinel => {
            Ok(RegistrationRecoveryDisposition::Suppress)
        }
        Ok(_) => refresh_or_clear_registration_recovery_fault(
            cache_dir,
            registration,
            RegistrationRecoveryRefresh {
                fault_code,
                prior_fault: &prior_fault,
                prior_observation: &prior_observation,
                current_sentinel,
                recompute_reason: "sentinel_changed",
            },
        ),
        Err(error) => {
            let reason = error.to_string();
            refresh_or_clear_registration_recovery_fault(
                cache_dir,
                registration,
                RegistrationRecoveryRefresh {
                    fault_code,
                    prior_fault: &prior_fault,
                    prior_observation: &prior_observation,
                    current_sentinel,
                    recompute_reason: &reason,
                },
            )
        }
    }
}

fn refresh_or_clear_registration_recovery_fault(
    cache_dir: &Path,
    registration: &WatchRegistration,
    refresh: RegistrationRecoveryRefresh<'_>,
) -> Result<RegistrationRecoveryDisposition, DynError> {
    let RegistrationRecoveryRefresh {
        fault_code,
        prior_fault,
        prior_observation,
        current_sentinel,
        recompute_reason,
    } = refresh;
    let fault_class = recovery_fault_log_class(fault_code);
    tracing::info!(
        project = %registration.project,
        root = %registration.root,
        terminal_fault_class = %fault_class,
        recompute_reason = recompute_reason,
        "incremental_watcher.registration_fault_full_observation_recompute"
    );
    let current_observation =
        match registration_recovery_observation(cache_dir, registration, fault_code)? {
            Some(observation) => observation,
            None => {
                delete_registration_recovery_fault(cache_dir, &registration.project)?;
                return Ok(RegistrationRecoveryDisposition::Proceed);
            }
        };
    if current_observation != *prior_observation {
        delete_registration_recovery_fault(cache_dir, &registration.project)?;
        return Ok(RegistrationRecoveryDisposition::Proceed);
    }
    let message = prior_fault
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("durable registration recovery fault remains unchanged");
    let refreshed = registration_recovery_fault_record(
        registration,
        fault_code,
        current_observation,
        current_sentinel,
        message,
        Some(recompute_reason),
    )?;
    persist_registration_recovery_fault(cache_dir, &registration.project, &refreshed)?;
    let observation_sha256 = refreshed
        .get("observation_sha256")
        .and_then(|value| value.as_str())
        .unwrap_or("missing");
    let sentinel_sha256 = refreshed
        .get("sentinel_sha256")
        .and_then(|value| value.as_str())
        .unwrap_or("missing");
    tracing::warn!(
        project = %registration.project,
        root = %registration.root,
        terminal_fault_class = %fault_class,
        recompute_reason = recompute_reason,
        observation_sha256 = observation_sha256,
        sentinel_sha256 = sentinel_sha256,
        "incremental_watcher.registration_fault_sentinel_revalidated"
    );
    Ok(RegistrationRecoveryDisposition::Suppress)
}

fn recompute_after_current_sentinel_error(
    cache_dir: &Path,
    registration: &WatchRegistration,
    fault_code: &str,
    prior_observation: &Value,
    sentinel_error: &str,
) -> Result<RegistrationRecoveryDisposition, DynError> {
    let fault_class = recovery_fault_log_class(fault_code);
    tracing::warn!(
        project = %registration.project,
        root = %registration.root,
        terminal_fault_class = %fault_class,
        error = sentinel_error,
        "incremental_watcher.registration_fault_current_sentinel_unevaluable"
    );
    match registration_recovery_observation(cache_dir, registration, fault_code) {
        Ok(Some(current_observation)) if current_observation == *prior_observation => {
            let observation_sha256 = value_sha256(&current_observation)?;
            Err(format!(
                "ASTRO_WATCHER_REGISTRATION_FAULT_SENTINEL_UNEVALUABLE: current sentinel for project {:?} could not be evaluated ({sentinel_error}); one full observation was recomputed and still matched observation_sha256={observation_sha256}; remediation: preserve the durable transaction/config bytes and repair the sentinel input before resident suppression resumes",
                registration.project
            )
            .into())
        }
        Ok(Some(current_observation)) => {
            let observation_sha256 = value_sha256(&current_observation)?;
            delete_registration_recovery_fault(cache_dir, &registration.project)?;
            tracing::warn!(
                project = %registration.project,
                root = %registration.root,
                terminal_fault_class = %fault_class,
                observation_sha256 = observation_sha256,
                "incremental_watcher.registration_fault_current_sentinel_changed_observation"
            );
            Ok(RegistrationRecoveryDisposition::Proceed)
        }
        Ok(None) => {
            delete_registration_recovery_fault(cache_dir, &registration.project)?;
            Ok(RegistrationRecoveryDisposition::Proceed)
        }
        Err(observation_error) => Err(format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_SENTINEL_UNEVALUABLE: current sentinel for project {:?} could not be evaluated ({sentinel_error}); the required one-shot full observation also failed: {observation_error}; remediation: preserve the durable transaction/config bytes and inspect the named transaction before retrying resident suppression",
            registration.project
        )
        .into()),
    }
}

fn record_registration_reconciliation_refusal(
    cache_dir: &Path,
    registration: &WatchRegistration,
    error: DynError,
) -> Result<(), DynError> {
    let message = error.to_string();
    if let Some(fault_code) = shadow_publication_recovery_error_code(&message)
        && let Some(observation) =
            registration_recovery_observation(cache_dir, registration, fault_code)?
        && let Some(sentinel) = registration_recovery_sentinel(cache_dir, registration, fault_code)?
    {
        let fault = registration_recovery_fault_record(
            registration,
            fault_code,
            observation,
            sentinel,
            &message,
            Some("terminal_fault_recorded"),
        )?;
        let observation_sha256 = fault
            .get("observation_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| -> DynError {
                "ASTRO_WATCHER_REGISTRATION_FAULT_OBSERVATION_HASH_MISSING: constructed recovery fault has no observation hash"
                    .into()
            })?
            .to_string();
        persist_registration_recovery_fault(cache_dir, &registration.project, &fault)?;
        let status = json!({
            "schema": "astrolabe-watcher-tick-v2",
            "status": "registration_reconciliation_refused",
            "project": registration.project,
            "root": registration.root,
            "fault_code": fault_code,
            "observation_sha256": observation_sha256.clone(),
            "transaction_inventory_sha256": fault.get("transaction_inventory_sha256"),
            "publication_config_sha256": fault.get("publication_config_sha256"),
            "sentinel_sha256": fault.get("sentinel_sha256"),
            "transaction_metadata_entries_sha256": fault.get("transaction_metadata_entries_sha256"),
            "full_observation_recomputed": true,
            "freshness": "stale",
            "trust": "verified",
            "worker_started": false,
            "retry_suppressed_until_observation_changes": true,
            "remediation": "repair the durable shadow-publication transaction/config named by watcher_registration_fault_json; unchanged resident intervals are suppressed",
        });
        persist_watcher_status(cache_dir, &registration.project, &status)?;
        tracing::warn!(
            project = %registration.project,
            root = %registration.root,
            fault_code = fault_code,
            observation_sha256 = %observation_sha256,
            "incremental_watcher.registration_reconciliation_refused"
        );
        return Ok(());
    }

    persist_registration_error(
        cache_dir,
        &registration.project,
        &format!("durable source-checkpoint reconciliation failed: {message}"),
    )?;
    tracing::warn!(
        project = %registration.project,
        root = %registration.root,
        error = %message,
        "incremental_watcher.registration_reconciliation_refused"
    );
    Ok(())
}

fn registration_recovery_observation(
    cache_dir: &Path,
    registration: &WatchRegistration,
    fault_code: &str,
) -> Result<Option<Value>, DynError> {
    let Some(shadow_publication) =
        shadow_publication_recovery_observation(cache_dir, &registration.project, fault_code)?
    else {
        return Ok(None);
    };
    Ok(Some(json!({
        "schema": "astrolabe-watcher-registration-recovery-observation-v1",
        "project": registration.project,
        "root": registration.root,
        "fault_code": fault_code,
        "shadow_publication": shadow_publication,
        "executable": executable_observation()?,
    })))
}

fn registration_recovery_sentinel(
    cache_dir: &Path,
    registration: &WatchRegistration,
    fault_code: &str,
) -> Result<Option<Value>, DynError> {
    let Some(shadow_publication) =
        shadow_publication_recovery_sentinel(cache_dir, &registration.project, fault_code)?
    else {
        return Ok(None);
    };
    Ok(Some(json!({
        "schema": "astrolabe-watcher-registration-recovery-sentinel-v1",
        "project": registration.project,
        "root": registration.root,
        "fault_code": fault_code,
        "shadow_publication": shadow_publication,
        "executable": executable_sentinel()?,
    })))
}

fn registration_recovery_fault_record(
    registration: &WatchRegistration,
    fault_code: &str,
    observation: Value,
    sentinel: Value,
    message: &str,
    recompute_reason: Option<&str>,
) -> Result<Value, DynError> {
    let observation_sha256 = value_sha256(&observation)?;
    let sentinel_sha256 = value_sha256(&sentinel)?;
    let transaction_inventory_sha256 =
        registration_recovery_observation_field(&observation, "transaction_inventory_sha256");
    let publication_config_sha256 =
        registration_recovery_observation_field(&observation, "publication_config_sha256");
    let transaction_metadata_entries_sha256 =
        registration_recovery_sentinel_field(&sentinel, "transaction_metadata", "entries_sha256");
    let transaction_metadata_entry_count =
        registration_recovery_sentinel_field(&sentinel, "transaction_metadata", "entry_count");
    let transaction_metadata_file_count =
        registration_recovery_sentinel_field(&sentinel, "transaction_metadata", "file_count");
    let transaction_metadata_directory_count =
        registration_recovery_sentinel_field(&sentinel, "transaction_metadata", "directory_count");
    let transaction_metadata_transaction_count = registration_recovery_sentinel_field(
        &sentinel,
        "transaction_metadata",
        "transaction_count",
    );
    let transaction_metadata_journal_count =
        registration_recovery_sentinel_field(&sentinel, "transaction_metadata", "journal_count");
    let transaction_metadata_artifact_probe_count = registration_recovery_sentinel_field(
        &sentinel,
        "transaction_metadata",
        "artifact_probe_count",
    );
    let transaction_metadata_direct_entry_count = registration_recovery_sentinel_field(
        &sentinel,
        "transaction_metadata",
        "direct_entry_count",
    );
    Ok(json!({
        "schema": "astrolabe-watcher-registration-recovery-fault-v1",
        "status": "terminal_fault",
        "project": registration.project,
        "root": registration.root,
        "fault_code": fault_code,
        "observation": observation,
        "observation_sha256": observation_sha256,
        "sentinel": sentinel,
        "sentinel_sha256": sentinel_sha256,
        "transaction_inventory_sha256": transaction_inventory_sha256,
        "publication_config_sha256": publication_config_sha256,
        "transaction_metadata_entries_sha256": transaction_metadata_entries_sha256,
        "transaction_metadata_entry_count": transaction_metadata_entry_count,
        "transaction_metadata_file_count": transaction_metadata_file_count,
        "transaction_metadata_directory_count": transaction_metadata_directory_count,
        "transaction_metadata_transaction_count": transaction_metadata_transaction_count,
        "transaction_metadata_journal_count": transaction_metadata_journal_count,
        "transaction_metadata_artifact_probe_count": transaction_metadata_artifact_probe_count,
        "transaction_metadata_direct_entry_count": transaction_metadata_direct_entry_count,
        "message": message,
        "worker_started": false,
        "retry_suppressed_until_observation_changes": true,
        "sentinel_kind": "compact_journal_artifact_metadata_plus_config_generation",
        "full_observation_recompute_reason": recompute_reason,
        "remediation": "preserve the exact shadow-publication transaction, repair the named durable bytes or project publication config, then let the resident watcher re-admit reconciliation",
    }))
}

fn validated_registration_recovery_observation(
    fault: &Value,
    registration: &WatchRegistration,
) -> Result<Value, DynError> {
    let project = registration.project.as_str();
    let observation = fault.get("observation").cloned().ok_or_else(|| -> DynError {
        format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_OBSERVATION_MISSING: durable registration fault for {project:?} has no observation; remediation: preserve the config store and inspect watcher_registration_fault_json"
        )
        .into()
    })?;
    let stored_observation_sha256 = fault
        .get("observation_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_WATCHER_REGISTRATION_FAULT_OBSERVATION_HASH_MISSING: durable registration fault for {project:?} has no observation_sha256; remediation: preserve the config store and inspect watcher_registration_fault_json"
            )
            .into()
        })?;
    let actual_observation_sha256 = value_sha256(&observation)?;
    if stored_observation_sha256 != actual_observation_sha256 {
        return Err(format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_OBSERVATION_HASH_MISMATCH: durable registration fault for {project:?} stores observation_sha256={stored_observation_sha256}, but readback observation hashes to {actual_observation_sha256}; remediation: preserve the config store and inspect watcher_registration_fault_json"
        )
        .into());
    }
    if observation.get("schema").and_then(Value::as_str)
        != Some("astrolabe-watcher-registration-recovery-observation-v1")
        || observation.get("project").and_then(Value::as_str) != Some(project)
        || observation.get("root").and_then(Value::as_str) != Some(registration.root.as_str())
    {
        return Err(format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_OBSERVATION_IDENTITY_MISMATCH: durable registration fault observation for {project:?} does not bind the expected schema/project/root; remediation: preserve the config store and inspect watcher_registration_fault_json"
        )
        .into());
    }
    if fault.get("fault_code").and_then(Value::as_str)
        != observation.get("fault_code").and_then(Value::as_str)
    {
        return Err(format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_OBSERVATION_CODE_MISMATCH: durable registration fault for {project:?} has a fault_code that differs from its observation; remediation: preserve the config store and inspect watcher_registration_fault_json"
        )
        .into());
    }
    match observation.get("shadow_publication") {
        Some(shadow_publication)
            if shadow_publication.get("schema").and_then(Value::as_str)
                == Some("astrolabe.shadow-publication-recovery-observation.v1")
                && shadow_publication.get("project").and_then(Value::as_str) == Some(project)
                && shadow_publication.get("fault_code").and_then(Value::as_str)
                    == observation.get("fault_code").and_then(Value::as_str) => {}
        _ => {
            return Err(format!(
                "ASTRO_WATCHER_REGISTRATION_FAULT_OBSERVATION_SHADOW_IDENTITY_MISMATCH: durable registration fault observation for {project:?} has malformed shadow-publication identity; remediation: preserve the config store and inspect watcher_registration_fault_json"
            )
            .into());
        }
    }
    Ok(observation)
}

fn validated_registration_recovery_sentinel(
    fault: &Value,
    registration: &WatchRegistration,
    fault_code: &str,
) -> Result<Value, DynError> {
    let project = registration.project.as_str();
    let sentinel = fault.get("sentinel").cloned().ok_or_else(|| -> DynError {
        format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_SENTINEL_MISSING: durable registration fault for {project:?} has no sentinel; remediation: recompute the full observation once and refresh watcher_registration_fault_json"
        )
        .into()
    })?;
    if sentinel.get("schema").and_then(Value::as_str)
        != Some("astrolabe-watcher-registration-recovery-sentinel-v1")
        || sentinel.get("project").and_then(Value::as_str) != Some(project)
        || sentinel.get("root").and_then(Value::as_str) != Some(registration.root.as_str())
        || sentinel.get("fault_code").and_then(Value::as_str) != Some(fault_code)
    {
        return Err(format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_SENTINEL_IDENTITY_MISMATCH: durable registration fault for {project:?} has a malformed sentinel identity; remediation: recompute the full observation once and refresh watcher_registration_fault_json"
        )
        .into());
    }
    let stored_sentinel_sha256 =
        fault
            .get("sentinel_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_WATCHER_REGISTRATION_FAULT_SENTINEL_HASH_MISSING: durable registration fault for {project:?} has no sentinel_sha256; remediation: recompute the full observation once and refresh watcher_registration_fault_json"
                )
                .into()
            })?;
    let actual_sentinel_sha256 = value_sha256(&sentinel)?;
    if stored_sentinel_sha256 != actual_sentinel_sha256 {
        return Err(format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_SENTINEL_HASH_MISMATCH: durable registration fault for {project:?} stores sentinel_sha256={stored_sentinel_sha256}, but readback sentinel hashes to {actual_sentinel_sha256}; remediation: recompute the full observation once and refresh watcher_registration_fault_json"
        )
        .into());
    }
    match sentinel.get("shadow_publication") {
        Some(shadow_publication)
            if shadow_publication.get("schema").and_then(Value::as_str)
                == Some("astrolabe.shadow-publication-recovery-sentinel.v1")
                && shadow_publication.get("project").and_then(Value::as_str) == Some(project)
                && shadow_publication.get("fault_code").and_then(Value::as_str)
                    == Some(fault_code) => {}
        _ => {
            return Err(format!(
                "ASTRO_WATCHER_REGISTRATION_FAULT_SENTINEL_SHADOW_IDENTITY_MISMATCH: durable registration fault for {project:?} has malformed shadow-publication sentinel identity; remediation: recompute the full observation once and refresh watcher_registration_fault_json"
            )
            .into());
        }
    }
    Ok(sentinel)
}

fn registration_recovery_observation_field(observation: &Value, field: &str) -> Value {
    observation
        .get("shadow_publication")
        .and_then(|value| value.get(field))
        .cloned()
        .unwrap_or(Value::Null)
}

fn registration_recovery_sentinel_field(sentinel: &Value, section: &str, field: &str) -> Value {
    sentinel
        .get("shadow_publication")
        .and_then(|value| value.get(section))
        .and_then(|value| value.get(field))
        .cloned()
        .unwrap_or(Value::Null)
}

fn shadow_publication_recovery_error_code(message: &str) -> Option<&str> {
    message
        .split(|ch: char| !(ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_'))
        .find(|token| {
            token.starts_with("ASTRO_SHADOW_PUBLICATION_RECOVERY_")
                || token.starts_with("ASTRO_SHADOW_ACTION_METADATA_RECOVERY_")
                || token.starts_with("ASTRO_SHADOW_PUBLICATION_JOURNAL_")
                || matches!(
                    *token,
                    "ASTRO_SHADOW_PUBLICATION_LEGACY_PRESERVED"
                        | "ASTRO_SHADOW_PUBLICATION_TRANSACTION_NAME_INVALID"
                )
        })
}

fn recovery_fault_log_class(fault_code: &str) -> String {
    fault_code
        .strip_prefix("ASTRO_")
        .unwrap_or(fault_code)
        .to_ascii_lowercase()
}

fn poll_incremental_watcher(watcher: &mut CbmWatcher) {
    if let Err(error) = watcher.poll_once() {
        tracing::warn!(
            code = %error.envelope().code,
            message = %error.envelope().message,
            "incremental_watcher.poll_failed"
        );
    }
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
) -> Result<bool, DynError> {
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
    persist_watcher_status_transition(cache_dir, project, &status)
}

fn clear_resolved_registration_error(cache_dir: &Path, project: &str) -> Result<bool, DynError> {
    let key = metadata_key(project, WATCHER_TICK_STATUS_KEY);
    let Some(raw) = read_config_value(cache_dir, &key)? else {
        return Ok(false);
    };
    let Ok(status) = serde_json::from_str::<Value>(&raw) else {
        return Ok(false);
    };
    if status.get("schema").and_then(Value::as_str) != Some("astrolabe-watcher-tick-v1")
        || status.get("status").and_then(Value::as_str) != Some("error")
        || status.get("project").and_then(Value::as_str) != Some(project)
        || status.get("code").and_then(Value::as_str) != Some("ASTRO_WATCHER_REGISTRATION_INVALID")
    {
        return Ok(false);
    }
    delete_watcher_fault(cache_dir, &key)?;
    Ok(true)
}

fn registration_recovery_refusal(
    observation: InvalidRegistrationRecoveryObservation,
    error: DynError,
) -> Result<RegistrationRecoveryDisposition, DynError> {
    let message = error.to_string();
    let Some((code, _)) = message.split_once(':') else {
        return Err(format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_VALIDATION_ERROR_UNSTRUCTURED: registration recovery validation returned an error without a named code: {message}"
        )
        .into());
    };
    if !code.starts_with("ASTRO_WATCHER_REGISTRATION_FAULT_") {
        return Err(format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_VALIDATION_ERROR_CODE_INVALID: registration recovery validation returned unexpected code {code:?}: {message}"
        )
        .into());
    }
    Ok(RegistrationRecoveryDisposition::Refuse(
        RegistrationRecoveryRefusal {
            code: code.to_string(),
            message,
            observation,
        },
    ))
}

fn read_registration_recovery_fault_raw(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<String>, DynError> {
    let key = metadata_key(project, WATCHER_REGISTRATION_FAULT_STATUS_KEY);
    read_config_value(cache_dir, &key)
}

fn parse_registration_recovery_fault(raw: &str, project: &str) -> Result<Value, DynError> {
    let fault = serde_json::from_str::<Value>(raw).map_err(|error| -> DynError {
        format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_MALFORMED: durable registration fault row for {project:?} is not valid JSON: {error}; remediation: preserve the config store and inspect watcher_registration_fault_json"
        )
        .into()
    })?;
    if fault.get("schema").and_then(Value::as_str)
        != Some("astrolabe-watcher-registration-recovery-fault-v1")
        || fault.get("status").and_then(Value::as_str) != Some("terminal_fault")
        || fault.get("project").and_then(Value::as_str) != Some(project)
    {
        return Err(format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_IDENTITY_MISMATCH: durable registration fault row for {project:?} does not bind the expected schema/status/project; remediation: preserve the config store and inspect watcher_registration_fault_json"
        )
        .into());
    }
    Ok(fault)
}

fn persist_registration_recovery_validation_refusal(
    cache_dir: &Path,
    registration: &WatchRegistration,
    refusal: &RegistrationRecoveryRefusal,
) -> Result<bool, DynError> {
    let status = json!({
        "schema": "astrolabe-watcher-tick-v2",
        "status": "registration_recovery_validation_refused",
        "project": registration.project,
        "root": registration.root,
        "code": refusal.code,
        "message": refusal.message,
        "observation_kind": "watcher_registration_fault_raw",
        "observation_sha256": refusal.observation.raw_sha256,
        "observation_bytes": refusal.observation.raw_bytes,
        "freshness": "stale",
        "trust": "verified",
        "worker_started": false,
        "retry_suppressed_until_observation_changes": true,
        "remediation": "repair or replace the exact watcher_registration_fault_json bytes; unchanged invalid observations remain refused without repeated parse, write, or log work",
    });
    persist_watcher_status_transition(cache_dir, &registration.project, &status)
}

fn persist_registration_recovery_fault(
    cache_dir: &Path,
    project: &str,
    fault: &Value,
) -> Result<(), DynError> {
    let key = metadata_key(project, WATCHER_REGISTRATION_FAULT_STATUS_KEY);
    let serialized = serde_json::to_string(fault)?;
    write_config_value(cache_dir, &key, &serialized)?;
    if read_config_value(cache_dir, &key)?.as_deref() != Some(serialized.as_str()) {
        return Err(format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_READBACK_MISMATCH: durable registration fault for {project:?} did not equal its exact write"
        )
        .into());
    }
    Ok(())
}

fn delete_registration_recovery_fault(cache_dir: &Path, project: &str) -> Result<(), DynError> {
    let key = metadata_key(project, WATCHER_REGISTRATION_FAULT_STATUS_KEY);
    delete_config_value(cache_dir, &key)?;
    if read_config_value(cache_dir, &key)?.is_some() {
        return Err(format!(
            "ASTRO_WATCHER_REGISTRATION_FAULT_DELETE_READBACK_MISMATCH: durable registration fault row for {project:?} remained after deletion"
        )
        .into());
    }
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
    let response_sha256 = hex_lower(&Sha256::digest(response.as_bytes()));
    let response_value: Value = serde_json::from_str(&response)?;
    if tool_result_is_error(&response)? {
        if let Some(fault_code) = terminal_watcher_fault_code(&response_value) {
            let fault = json!({
                "schema": "astrolabe-watcher-fault-v1",
                "status": "terminal_fault",
                "project": project,
                "fault_code": fault_code.clone(),
                "observation": observation,
                "observation_sha256": observation_sha256,
                "rearm_signature": watcher_rearm_signature(cache_dir, project, &normalized_args)?,
                "response_sha256": response_sha256,
                "response": response_value,
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
                "fault_code": fault_code.clone(),
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
            "response_sha256": response_sha256,
            "response": response_value,
            "remediation": "inspect the index_repository error and retry the watcher tick",
        });
        persist_watcher_status(cache_dir, project, &status)?;
        return Err(format!(
            "watcher index tick failed for {project:?}; response_sha256={response_sha256}; response={response}"
        )
        .into());
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

fn executable_sentinel() -> Result<Value, DynError> {
    static SENTINEL: OnceLock<Result<Value, String>> = OnceLock::new();
    SENTINEL
        .get_or_init(|| {
            let path = std::env::current_exe().map_err(|error| error.to_string())?;
            let metadata = file_metadata_observation(&path).map_err(|error| error.to_string())?;
            Ok(json!({
                "schema": "astrolabe-watcher-executable-sentinel-v1",
                "path": path,
                "metadata": metadata,
            }))
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

fn terminal_watcher_fault_code(response: &Value) -> Option<String> {
    const TERMINAL_CODES: &[&str] = &[
        "CBM_SCHEMA_VERSION_UNSTAMPED",
        "CBM_SCHEMA_VERSION_UNSUPPORTED",
        "CBM_SCHEMA_FRESHNESS_UNREADABLE",
        "CBM_PIPELINE_EMPTY_SOURCE_CORPUS",
        "CBM_STORE_INTEGRITY_FAILED",
        "CBM_STORE_PROVENANCE_FAILED",
        "ASTRO_SHADOW_PROJECT_MISMATCH",
    ];
    let structured_code = response
        .get("structuredContent")
        .and_then(|value| value.get("code"))
        .and_then(Value::as_str)
        .or_else(|| response.get("code").and_then(Value::as_str));
    if let Some(code) = structured_code
        && (TERMINAL_CODES.contains(&code)
            || shadow_publication_recovery_error_code(code).is_some())
    {
        return Some(code.to_string());
    }
    let text = response
        .get("content")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)?;
    if let Ok(inner) = serde_json::from_str::<Value>(text)
        && let Some(code) = inner.get("code").and_then(Value::as_str)
        && (TERMINAL_CODES.contains(&code)
            || shadow_publication_recovery_error_code(code).is_some())
    {
        return Some(code.to_string());
    }
    if let Some(code) = TERMINAL_CODES.iter().copied().find(|code| {
        text.strip_prefix(code)
            .is_some_and(|suffix| suffix.starts_with(':') || suffix.starts_with(' '))
    }) {
        return Some(code.to_string());
    }
    shadow_publication_recovery_error_code(text).map(ToOwned::to_owned)
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

fn persist_watcher_status_transition(
    cache_dir: &Path,
    project: &str,
    status: &Value,
) -> Result<bool, DynError> {
    let key = metadata_key(project, WATCHER_TICK_STATUS_KEY);
    let serialized = serde_json::to_string(status)?;
    if read_config_value(cache_dir, &key)?.as_deref() == Some(serialized.as_str()) {
        return Ok(false);
    }
    write_config_value(cache_dir, &key, &serialized)?;
    if read_config_value(cache_dir, &key)?.as_deref() != Some(serialized.as_str()) {
        return Err(format!(
            "ASTRO_WATCHER_STATUS_READBACK_MISMATCH: durable status transition for {project:?} did not equal its exact write"
        )
        .into());
    }
    Ok(true)
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
