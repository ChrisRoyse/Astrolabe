use super::*;

use std::io::Read;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use astrolabe_bridge::{BridgeError, CbmWatcher, ErrorEnvelope};
use astrolabe_domain::knobs::{
    WATCHER_DEFAULT_POLL_INTERVAL_MS, WATCHER_DEFAULT_ROOT_MISSING_GRACE_MS,
    WATCHER_DEFAULT_TRANSIENT_MAX_ATTEMPTS, WATCHER_ROOT_MISSING_GRACE_MS_KNOB, watcher_knob,
};

use super::dispatch::handle_index_repository;

pub(crate) const WATCHER_TICK_STATUS_KEY: &str = "watcher_tick_json";
pub(crate) const WATCHER_FAULT_STATUS_KEY: &str = "watcher_fault_json";
pub(crate) const WATCHER_REGISTRATION_FAULT_STATUS_KEY: &str = "watcher_registration_fault_json";
pub(crate) const WATCHER_ROOT_FAULT_STATUS_KEY: &str = "watcher_root_fault_json";
const WATCHER_INDEX_OPERATION: &str = "index_repository";
const WATCHER_INDEX_PHASE: &str = "watcher_index_worker";
const CBM_WATCHER_SOURCE_CHANGED: &str = "CBM_WATCHER_SOURCE_CHANGED";
const CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED: &str = "CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED";

#[derive(Debug, Clone, Eq, PartialEq)]
struct WatchRegistration {
    project: String,
    root: String,
    root_identity_raw: Option<String>,
    root_missing_grace_ms_raw: Option<String>,
    root_fault_raw: Option<String>,
}

#[derive(Debug)]
struct MissingRootObservation {
    first_observed_at: Instant,
    first_observed_unix_ms: u64,
    observation_count: u64,
}

#[derive(Debug)]
enum RootAdmissionDisposition {
    Exact { prior_root_fault: Option<Value> },
    Refused,
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

#[derive(Debug)]
struct WatcherErrorEvidence {
    source_error_code: Option<String>,
    code_observations: Vec<Value>,
    classification_error: Option<String>,
    nested_payload: Option<Value>,
    operation: String,
    operation_source: &'static str,
    phase: String,
    phase_source: &'static str,
}

#[derive(Debug)]
enum WatcherErrorDisposition {
    Retryable {
        source_error_code: String,
        basis: &'static str,
    },
    NonRetryable {
        fault_code: String,
        source_error_code: String,
        basis: &'static str,
    },
    ClassificationFault {
        source_error_code: Option<String>,
        basis: String,
    },
}

#[derive(Debug)]
enum TransientAttemptDisposition {
    Attempt(u64),
    ClassificationFault(String),
}

#[derive(Debug)]
struct WatcherIndexArgumentFault {
    observation: Value,
    response: Value,
    evidence: WatcherErrorEvidence,
}

struct BackgroundLaneReleaseGuard;

impl Drop for BackgroundLaneReleaseGuard {
    fn drop(&mut self) {
        match release_background_lane_ownerships() {
            Ok(released) if released != 0 => tracing::info!(
                released_background_lane_owners = released,
                "incremental_watcher.exit_release"
            ),
            Ok(_) => {}
            Err(error) => tracing::error!(
                code = "ASTRO_BACKGROUND_LANE_EXIT_RELEASE_FAILED",
                error = %error,
                "incremental_watcher.exit_release_failed"
            ),
        }
    }
}

pub(crate) fn run_incremental_watcher_loop(shutdown: Arc<AtomicBool>) -> Result<(), DynError> {
    let _lane_release_guard = BackgroundLaneReleaseGuard;
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let runner = Rc::new(CbmToolRunner::new_default()?);
    let callback_runner = Rc::clone(&runner);
    let callback_cache = cache_dir.clone();
    let mut watcher = CbmWatcher::new_for_polling(move |project, root, trigger_code| {
        run_watcher_index_tick(
            &callback_runner,
            &callback_cache,
            project,
            root,
            trigger_code,
        )
        .map_err(watcher_bridge_error)
    })?;
    let mut registered = BTreeMap::<String, String>::new();
    let mut missing_root_observations = BTreeMap::<String, MissingRootObservation>::new();
    let mut invalid_registration_recovery_observations =
        BTreeMap::<String, InvalidRegistrationRecoveryObservation>::new();
    let mut prior_policy_observation = None::<String>;
    let mut prior_activation_observation = None::<String>;

    while !shutdown.load(Ordering::Relaxed) {
        // The retained Windows handle behind this fence denies replacement of
        // active-generation.json for exactly this mutation-capable loop slice.
        // Activation can therefore commit only between slices, never while an
        // old generation can still publish watcher state.
        let activation_fence =
            crate::activation_epoch::require_active_generation("incremental_watcher_tick");
        let activation_observation = match &activation_fence {
            Ok(None) => "workspace".to_string(),
            Ok(Some(fence)) => format!(
                "active:{}:{}:{}",
                fence.epoch, fence.generation_id, fence.record_sha256
            ),
            Err(error) => format!("error:{error}"),
        };
        let activation_changed =
            prior_activation_observation.as_deref() != Some(activation_observation.as_str());
        if activation_changed {
            let released = release_background_lane_ownerships()?;
            unwatch_all(&mut watcher, &mut registered)?;
            missing_root_observations.clear();
            invalid_registration_recovery_observations.clear();
            match &activation_fence {
                Ok(_) => tracing::info!(
                    observation = %activation_observation,
                    released_background_lane_owners = released,
                    "incremental_watcher.activation_admitted"
                ),
                Err(error) => tracing::warn!(
                    code = "ASTRO_ACTIVE_GENERATION_OBSERVATION_FAILED",
                    error = %error,
                    released_background_lane_owners = released,
                    "incremental_watcher.activation_refused"
                ),
            }
            prior_activation_observation = Some(activation_observation);
        }
        let activation_fence = match activation_fence {
            Ok(fence) => fence,
            Err(_) => {
                sleep_watcher_slice(&shutdown);
                continue;
            }
        };

        if shutdown.load(Ordering::Relaxed) {
            drop(activation_fence);
            break;
        }

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
            let released = release_background_lane_ownerships()?;
            unwatch_all(&mut watcher, &mut registered)?;
            missing_root_observations.clear();
            invalid_registration_recovery_observations.clear();
            if released != 0 {
                tracing::info!(
                    released_background_lane_owners = released,
                    "incremental_watcher.policy_release"
                );
            }
            drop(activation_fence);
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
            let released = release_background_lane_ownership_at(&cache_dir, &stale)?;
            watcher.unwatch(&stale)?;
            registered.remove(&stale);
            missing_root_observations.remove(&stale);
            invalid_registration_recovery_observations.remove(&stale);
            if released {
                tracing::info!(project = %stale, "incremental_watcher.project_lane_released");
            }
        }
        for registration in discovered {
            let prior_root_fault = match registration_root_admission(
                &cache_dir,
                &registration,
                &mut missing_root_observations,
            ) {
                Ok(RootAdmissionDisposition::Exact { prior_root_fault }) => prior_root_fault,
                Ok(RootAdmissionDisposition::Refused) => {
                    if registered.contains_key(&registration.project) {
                        watcher.unwatch(&registration.project)?;
                        registered.remove(&registration.project);
                    }
                    continue;
                }
                Err(error) => {
                    if registered.contains_key(&registration.project) {
                        watcher.unwatch(&registration.project)?;
                        registered.remove(&registration.project);
                    }
                    let message = format!("root-identity admission failed: {error}");
                    if persist_registration_error(&cache_dir, &registration.project, &message)? {
                        tracing::warn!(
                            project = %registration.project,
                            root = %registration.root,
                            error = %error,
                            "incremental_watcher.root_identity_admission_refused"
                        );
                    }
                    continue;
                }
            };
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
            if let Some(status) = &catch_up
                && prior_root_fault.is_none()
            {
                persist_watcher_status(&cache_dir, &registration.project, status)?;
                tracing::info!(
                    project = %registration.project,
                    root = %registration.root,
                    verification = status.get("verification").and_then(|value| value.as_str()),
                    "incremental_watcher.catch_up_scheduled"
                );
            }
            if let Some(root_fault) = prior_root_fault.as_ref() {
                clear_resolved_root_fault(
                    &cache_dir,
                    &registration,
                    root_fault,
                    catch_up.as_ref(),
                )?;
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
        drop(activation_fence);
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

fn registration_root_admission(
    cache_dir: &Path,
    registration: &WatchRegistration,
    missing: &mut BTreeMap<String, MissingRootObservation>,
) -> Result<RootAdmissionDisposition, DynError> {
    let grace_ms = root_missing_grace_ms(registration)?;
    let prior_root_fault = registration
        .root_fault_raw
        .as_deref()
        .filter(|raw| !raw.trim().is_empty())
        .map(|raw| parse_root_fault(raw, registration))
        .transpose()?;
    let expected = match registration
        .root_identity_raw
        .as_deref()
        .filter(|raw| !raw.trim().is_empty())
    {
        Some(raw) => parse_root_identity(raw)?,
        None => {
            missing.remove(&registration.project);
            let now = unix_epoch_millis();
            let observation = root_fault_observation(
                registration,
                "ASTRO_WATCHER_ROOT_IDENTITY_MISSING",
                "identity_missing",
                None,
                Value::Null,
                "the published Git source registration has no handle-derived Windows root identity",
            );
            persist_root_fault_transition(
                cache_dir,
                registration,
                &observation,
                now,
                now,
                1,
                grace_ms,
                "explicitly reindex the readable registered root so its volume serial, 128-bit file ID, and final handle path commit with the artifact generation",
            )?;
            return Ok(RootAdmissionDisposition::Refused);
        }
    };

    match observe_root_identity(Path::new(&registration.root), &expected) {
        RootIdentityObservation::Exact(_) => {
            missing.remove(&registration.project);
            Ok(RootAdmissionDisposition::Exact { prior_root_fault })
        }
        RootIdentityObservation::Missing { message } => {
            let now = unix_epoch_millis();
            let state = missing
                .entry(registration.project.clone())
                .or_insert_with(|| MissingRootObservation {
                    first_observed_at: Instant::now(),
                    first_observed_unix_ms: now,
                    observation_count: 0,
                });
            state.observation_count = state.observation_count.checked_add(1).ok_or_else(|| {
                "ASTRO_WATCHER_ROOT_OBSERVATION_OVERFLOW: missing-root observation counter overflowed; remediation: preserve the project and restart only after recording the fault"
            })?;
            if state.first_observed_at.elapsed().as_millis() < u128::from(grace_ms) {
                return Ok(RootAdmissionDisposition::Refused);
            }
            let observation = root_fault_observation(
                registration,
                "ASTRO_WATCHER_ROOT_MISSING",
                "missing",
                Some(&expected),
                Value::Null,
                &message,
            );
            if persist_root_fault_transition(
                cache_dir,
                registration,
                &observation,
                state.first_observed_unix_ms,
                now,
                state.observation_count,
                grace_ms,
                "restore the exact directory object at the registered path; a replacement identity is refused, and explicit project retirement is a separate operator transaction",
            )? {
                tracing::warn!(
                    project = %registration.project,
                    root = %registration.root,
                    grace_ms,
                    observation_count = state.observation_count,
                    "incremental_watcher.root_missing_fault_persisted"
                );
            }
            Ok(RootAdmissionDisposition::Refused)
        }
        RootIdentityObservation::Mismatch { actual, message } => {
            missing.remove(&registration.project);
            let now = unix_epoch_millis();
            let observation = root_fault_observation(
                registration,
                "ASTRO_WATCHER_ROOT_IDENTITY_MISMATCH",
                "identity_mismatch",
                Some(&expected),
                serde_json::to_value(actual)?,
                &message,
            );
            if persist_root_fault_transition(
                cache_dir,
                registration,
                &observation,
                now,
                now,
                1,
                grace_ms,
                "remove the replacement and restore the exact published directory object, or explicitly reindex the replacement to publish a new complete generation",
            )? {
                tracing::warn!(
                    project = %registration.project,
                    root = %registration.root,
                    "incremental_watcher.root_identity_mismatch_persisted"
                );
            }
            Ok(RootAdmissionDisposition::Refused)
        }
        RootIdentityObservation::Unevaluable { message } => {
            missing.remove(&registration.project);
            let now = unix_epoch_millis();
            let observation = root_fault_observation(
                registration,
                "ASTRO_WATCHER_ROOT_IDENTITY_UNEVALUABLE",
                "identity_unevaluable",
                Some(&expected),
                Value::Null,
                &message,
            );
            if persist_root_fault_transition(
                cache_dir,
                registration,
                &observation,
                now,
                now,
                1,
                grace_ms,
                "restore readable filesystem identity metadata for the exact registered directory; preserve every artifact until the observation is evaluable",
            )? {
                tracing::warn!(
                    project = %registration.project,
                    root = %registration.root,
                    "incremental_watcher.root_identity_unevaluable_persisted"
                );
            }
            Ok(RootAdmissionDisposition::Refused)
        }
    }
}

fn root_missing_grace_ms(registration: &WatchRegistration) -> Result<u64, DynError> {
    let declaration = watcher_knob(WATCHER_ROOT_MISSING_GRACE_MS_KNOB).ok_or_else(|| {
        "ASTRO_WATCHER_ROOT_GRACE_KNOB_UNDECLARED: watcher root grace knob is absent from the registry"
    })?;
    let Some(raw) = registration.root_missing_grace_ms_raw.as_deref() else {
        return Ok(WATCHER_DEFAULT_ROOT_MISSING_GRACE_MS);
    };
    if raw.is_empty() || raw != raw.trim() {
        return Err(format!(
            "ASTRO_WATCHER_ROOT_GRACE_INVALID: project {:?} persisted {:?}={raw:?}; expected an unsigned base-10 integer with no surrounding whitespace in {}..={}; remediation: repair the exact config row or delete it to select the declared default {}",
            registration.project,
            declaration.name,
            declaration.min,
            declaration.max,
            declaration.default,
        )
        .into());
    }
    let value = raw.parse::<u64>().map_err(|error| -> DynError {
        format!(
            "ASTRO_WATCHER_ROOT_GRACE_INVALID: project {:?} persisted {:?}={raw:?}: {error}; remediation: write an unsigned base-10 value in {}..={}",
            registration.project, declaration.name, declaration.min, declaration.max,
        )
        .into()
    })?;
    if !(declaration.min..=declaration.max).contains(&value) {
        return Err(format!(
            "ASTRO_WATCHER_ROOT_GRACE_OUT_OF_RANGE: project {:?} persisted {:?}={value}, outside {}..={}; remediation: write a registry-admitted value",
            registration.project, declaration.name, declaration.min, declaration.max,
        )
        .into());
    }
    Ok(value)
}

fn root_fault_observation(
    registration: &WatchRegistration,
    fault_code: &str,
    observation_class: &str,
    expected: Option<&WindowsRootIdentity>,
    actual: Value,
    message: &str,
) -> Value {
    json!({
        "schema": "astrolabe.watcher-root-observation.v1",
        "fault_code": fault_code,
        "observation_class": observation_class,
        "project": registration.project,
        "registered_root": registration.root,
        "expected_root_identity": expected,
        "actual_root_identity": actual,
        "message": message,
    })
}

fn parse_root_fault(raw: &str, registration: &WatchRegistration) -> Result<Value, DynError> {
    let fault: Value = serde_json::from_str(raw).map_err(|error| -> DynError {
        format!(
            "ASTRO_WATCHER_ROOT_FAULT_MALFORMED: durable root fault for {:?} is not valid JSON: {error}; remediation: preserve the config and project artifacts and inspect watcher_root_fault_json",
            registration.project,
        )
        .into()
    })?;
    if fault.get("schema").and_then(Value::as_str) != Some("astrolabe-watcher-root-fault-v1")
        || fault.get("project").and_then(Value::as_str) != Some(&registration.project)
        || fault.get("registered_root").and_then(Value::as_str) != Some(&registration.root)
    {
        return Err(format!(
            "ASTRO_WATCHER_ROOT_FAULT_IDENTITY_MISMATCH: durable root fault does not bind project {:?} and root {:?}; remediation: preserve every byte and inspect the config writer",
            registration.project, registration.root,
        )
        .into());
    }
    let observation = fault.get("observation").ok_or_else(|| -> DynError {
        "ASTRO_WATCHER_ROOT_FAULT_OBSERVATION_MISSING: durable root fault has no observation; remediation: preserve every byte and inspect the config writer".into()
    })?;
    let actual = persisted_json_sha256(observation)?;
    if fault.get("observation_sha256").and_then(Value::as_str) != Some(actual.as_str()) {
        return Err(format!(
            "ASTRO_WATCHER_ROOT_FAULT_OBSERVATION_HASH_MISMATCH: durable root fault observation hashes to {actual}, not its recorded digest; remediation: preserve every byte and inspect the config writer"
        )
        .into());
    }
    Ok(fault)
}

fn prior_publication_evidence(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    let fields = [
        SHADOW_PUBLICATION_GENERATION_KEY,
        GIT_SOURCE_FINGERPRINT_KEY,
        GIT_HISTORY_STATE_KEY,
        GIT_SOURCE_REPO_PATH_KEY,
        GIT_SOURCE_ROOT_IDENTITY_KEY,
        "sqlite_path",
        "vault_fingerprint",
        "cx_id_set_sha256",
        SHADOW_LEDGER_CHECKPOINT_KEY,
        "weave_json",
        "kernel_context_json",
        "lowered_sqlite_path",
        "lowered_artifact_sha256",
        "lowered_vault_fingerprint_sha256",
        "lowered_manifest_seq",
    ];
    let keys = fields
        .iter()
        .map(|field| metadata_key(project, field))
        .collect::<Vec<_>>();
    let values = read_config_values(cache_dir, &keys)?;
    let mut members = Vec::with_capacity(keys.len());
    for ((field, key), value) in fields.iter().zip(keys).zip(values) {
        let member = match value {
            Some(value) => {
                let semantic = match *field {
                    "weave_json" | "kernel_context_json" => serde_json::from_str::<Value>(&value)
                        .ok()
                        .and_then(|parsed| parsed.get("artifact_sha256").cloned()),
                    SHADOW_LEDGER_CHECKPOINT_KEY | GIT_SOURCE_ROOT_IDENTITY_KEY => {
                        serde_json::from_str::<Value>(&value).ok()
                    }
                    _ => Some(Value::String(value.clone())),
                };
                json!({
                    "field": field,
                    "key": key,
                    "state": "present",
                    "bytes": value.len(),
                    "sha256": hex_lower(&Sha256::digest(value.as_bytes())),
                    "semantic_identity": semantic,
                })
            }
            None => json!({"field": field, "key": key, "state": "absent"}),
        };
        members.push(member);
    }
    let members = Value::Array(members);
    Ok(json!({
        "schema": "astrolabe.watcher-prior-publication.v1",
        "project": project,
        "config_members_sha256": persisted_json_sha256(&members)?,
        "config_members": members,
        "derived_surfaces": "last_committed_generation_preserved",
    }))
}

#[allow(clippy::too_many_arguments)]
fn persist_root_fault_transition(
    cache_dir: &Path,
    registration: &WatchRegistration,
    observation: &Value,
    first_observed_unix_ms: u64,
    last_observed_unix_ms: u64,
    observation_count: u64,
    grace_ms: u64,
    remediation: &str,
) -> Result<bool, DynError> {
    let observation_sha256 = persisted_json_sha256(observation)?;
    if let Some(prior) = registration
        .root_fault_raw
        .as_deref()
        .filter(|raw| !raw.trim().is_empty())
        .map(|raw| parse_root_fault(raw, registration))
        .transpose()?
        && prior.get("observation_sha256").and_then(Value::as_str)
            == Some(observation_sha256.as_str())
    {
        return Ok(false);
    }

    let prior_publication = prior_publication_evidence(cache_dir, &registration.project)?;
    let prior_publication_sha256 = persisted_json_sha256(&prior_publication)?;
    let fault_code = observation
        .get("fault_code")
        .and_then(Value::as_str)
        .ok_or_else(|| -> DynError {
            "ASTRO_WATCHER_ROOT_FAULT_CODE_MISSING: root observation has no fault code".into()
        })?;
    let fault = json!({
        "schema": "astrolabe-watcher-root-fault-v1",
        "status": "root_identity_refused",
        "fault_code": fault_code,
        "project": registration.project,
        "registered_root": registration.root,
        "first_observed_unix_ms": first_observed_unix_ms,
        "last_observed_unix_ms": last_observed_unix_ms,
        "observation_count": observation_count,
        "root_missing_grace_ms": grace_ms,
        "observation": observation,
        "observation_sha256": observation_sha256,
        "prior_publication": prior_publication,
        "prior_publication_sha256": prior_publication_sha256,
        "freshness": "stale",
        "trust": "verified",
        "artifacts_preserved": true,
        "automatic_deletion_authorized": false,
        "remediation": remediation,
    });
    let status = json!({
        "schema": "astrolabe-watcher-tick-v3",
        "status": "root_identity_refused",
        "project": registration.project,
        "root": registration.root,
        "fault_code": fault_code,
        "observation_sha256": observation_sha256,
        "prior_publication_sha256": prior_publication_sha256,
        "freshness": "stale",
        "trust": "verified",
        "worker_started": false,
        "artifacts_preserved": true,
        "remediation": remediation,
    });
    persist_root_fault_and_status_atomic(cache_dir, registration, &fault, &status)?;
    Ok(true)
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
        Ok(_) if shadow_publication_recovery_tracks_owner_state(fault_code) => {
            delete_registration_recovery_fault(cache_dir, &registration.project)?;
            Ok(RegistrationRecoveryDisposition::Proceed)
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
            let observation_sha256 = persisted_json_sha256(&current_observation)?;
            Err(format!(
                "ASTRO_WATCHER_REGISTRATION_FAULT_SENTINEL_UNEVALUABLE: current sentinel for project {:?} could not be evaluated ({sentinel_error}); one full observation was recomputed and still matched observation_sha256={observation_sha256}; remediation: preserve the durable transaction/config bytes and repair the sentinel input before resident suppression resumes",
                registration.project
            )
            .into())
        }
        Ok(Some(current_observation)) => {
            let observation_sha256 = persisted_json_sha256(&current_observation)?;
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
    if let Some(fault_code) = shadow_publication_recovery_error_code(&message) {
        let Some(sentinel) = registration_recovery_sentinel(cache_dir, registration, fault_code)?
        else {
            tracing::info!(
                project = %registration.project,
                root = %registration.root,
                fault_code = fault_code,
                "incremental_watcher.registration_reconciliation_fault_cleared_before_capture"
            );
            return Ok(());
        };
        if shadow_publication_recovery_tracks_owner_state(fault_code)
            && !sentinel.get("shadow_publication").is_some_and(|shadow| {
                shadow_publication_recovery_sentinel_confirms_owner_fault(shadow, fault_code)
            })
        {
            tracing::info!(
                project = %registration.project,
                root = %registration.root,
                fault_code = fault_code,
                "incremental_watcher.registration_reconciliation_owner_state_changed_before_capture"
            );
            return Ok(());
        }
        let Some(observation) =
            registration_recovery_observation(cache_dir, registration, fault_code)?
        else {
            tracing::info!(
                project = %registration.project,
                root = %registration.root,
                fault_code = fault_code,
                "incremental_watcher.registration_reconciliation_fault_cleared_before_observation"
            );
            return Ok(());
        };
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
    let observation_sha256 = persisted_json_sha256(&observation)?;
    let sentinel_sha256 = persisted_json_sha256(&sentinel)?;
    let sentinel_kind = if shadow_publication_recovery_tracks_owner_state(fault_code) {
        "compact_journal_artifact_metadata_config_generation_plus_exact_owner_generation_state"
    } else {
        "compact_journal_artifact_metadata_plus_config_generation"
    };
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
        "sentinel_kind": sentinel_kind,
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
    let actual_observation_sha256 = persisted_json_sha256(&observation)?;
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
    let actual_sentinel_sha256 = persisted_json_sha256(&sentinel)?;
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
                        | "ASTRO_SHADOW_PUBLICATION_ACTIVE_GENERATION_CONFLICT"
                        | "ASTRO_SHADOW_PUBLICATION_OWNER_UNEVALUABLE"
                        | "ASTRO_SHADOW_PUBLICATION_OWNER_CLASSIFICATION_DRIFT"
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
    #[derive(Default)]
    struct RegistrationRows {
        root: Option<String>,
        root_identity_raw: Option<String>,
        root_missing_grace_ms_raw: Option<String>,
        root_fault_raw: Option<String>,
    }

    let mut rows_by_project = BTreeMap::<String, RegistrationRows>::new();
    let source_root_suffix = format!(".{GIT_SOURCE_REPO_PATH_KEY}");
    let root_identity_suffix = format!(".{GIT_SOURCE_ROOT_IDENTITY_KEY}");
    let root_grace_suffix = format!(".{WATCHER_ROOT_MISSING_GRACE_MS_KNOB}");
    let root_fault_suffix = format!(".{WATCHER_ROOT_FAULT_STATUS_KEY}");
    for (key, value) in scan_config_prefix(cache_dir, CONFIG_KEY_PREFIX)? {
        let (field, suffix) = if key.ends_with(&source_root_suffix) {
            (GIT_SOURCE_REPO_PATH_KEY, &source_root_suffix)
        } else if key.ends_with(&root_identity_suffix) {
            (GIT_SOURCE_ROOT_IDENTITY_KEY, &root_identity_suffix)
        } else if key.ends_with(&root_grace_suffix) {
            (WATCHER_ROOT_MISSING_GRACE_MS_KNOB, &root_grace_suffix)
        } else if key.ends_with(&root_fault_suffix) {
            (WATCHER_ROOT_FAULT_STATUS_KEY, &root_fault_suffix)
        } else {
            continue;
        };
        let Some(project) = project_from_metadata_key(&key, field) else {
            return Err(format!(
                "ASTRO_WATCHER_REGISTRATION_KEY_INVALID: config key {key:?} ends with {suffix:?} but has no valid project identity; remediation: preserve the config store and repair the malformed row"
            )
            .into());
        };
        let rows = rows_by_project.entry(project).or_default();
        match field {
            GIT_SOURCE_REPO_PATH_KEY => rows.root = Some(value),
            GIT_SOURCE_ROOT_IDENTITY_KEY => rows.root_identity_raw = Some(value),
            WATCHER_ROOT_MISSING_GRACE_MS_KNOB => rows.root_missing_grace_ms_raw = Some(value),
            WATCHER_ROOT_FAULT_STATUS_KEY => rows.root_fault_raw = Some(value),
            _ => unreachable!("registration field classified above"),
        }
    }

    let mut registrations = Vec::new();
    for (project, rows) in rows_by_project {
        let Some(root) = rows.root else {
            continue;
        };
        // Registration identity is the atomically published Git source root,
        // not the mutable arguments used by a later index invocation. If the
        // argument row is absent or malformed, retaining this registration is
        // what lets the next source-level reconcile reach the fail-closed
        // `prepare_watcher_index_args` diagnostic instead of silently
        // unwatching the project. Non-Git imports deliberately publish an
        // empty source-root value and have no native Git watch to register.
        if root.trim().is_empty() {
            continue;
        }
        let ownership = match acquire_background_lane_status_at(cache_dir, &project) {
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
            root,
            root_identity_raw: rows.root_identity_raw,
            root_missing_grace_ms_raw: rows.root_missing_grace_ms_raw,
            root_fault_raw: rows.root_fault_raw,
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
    let resolved_generic_error = status.get("schema").and_then(Value::as_str)
        == Some("astrolabe-watcher-tick-v1")
        && status.get("status").and_then(Value::as_str) == Some("error")
        && status.get("project").and_then(Value::as_str) == Some(project)
        && status.get("code").and_then(Value::as_str) == Some("ASTRO_WATCHER_REGISTRATION_INVALID");
    let resolved_recovery_fault = status.get("schema").and_then(Value::as_str)
        == Some("astrolabe-watcher-tick-v2")
        && status.get("status").and_then(Value::as_str)
            == Some("registration_reconciliation_refused")
        && status.get("project").and_then(Value::as_str) == Some(project)
        && status
            .get("fault_code")
            .and_then(Value::as_str)
            .is_some_and(|code| shadow_publication_recovery_error_code(code).is_some())
        && read_config_value(
            cache_dir,
            &metadata_key(project, WATCHER_REGISTRATION_FAULT_STATUS_KEY),
        )?
        .is_none();
    if !resolved_generic_error && !resolved_recovery_fault {
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

fn prepare_watcher_index_args(
    cache_dir: &Path,
    project: &str,
    root: &str,
) -> Result<Result<(String, Value), WatcherIndexArgumentFault>, DynError> {
    let key = metadata_key(project, SHADOW_INDEX_ARGS_KEY);
    let Some(raw_args) = read_config_value(cache_dir, &key)? else {
        let observation = json!({
            "schema": "astrolabe-watcher-index-args-observation-v1",
            "state": "absent",
            "config_key": key,
        });
        return Ok(Err(watcher_index_argument_fault(
            project,
            root,
            observation,
            "persisted index_repository arguments are absent",
            None,
        )));
    };
    let persisted_sha256 = hex_lower(&Sha256::digest(raw_args.as_bytes()));
    let persisted_bytes = raw_args.len();
    let mut args: Value = match serde_json::from_str(&raw_args) {
        Ok(args) => args,
        Err(error) => {
            let observation = json!({
                "schema": "astrolabe-watcher-index-args-observation-v1",
                "state": "malformed_json",
                "config_key": key,
                "persisted_bytes": persisted_bytes,
                "persisted_sha256": persisted_sha256,
                "parse_error": error.to_string(),
            });
            return Ok(Err(watcher_index_argument_fault(
                project,
                root,
                observation,
                "persisted index_repository arguments are not valid JSON",
                Some(error.to_string()),
            )));
        }
    };
    let json_type = match &args {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    };
    let Some(object) = args.as_object_mut() else {
        let observation = json!({
            "schema": "astrolabe-watcher-index-args-observation-v1",
            "state": "non_object_json",
            "config_key": key,
            "persisted_bytes": persisted_bytes,
            "persisted_sha256": persisted_sha256,
            "json_type": json_type,
        });
        return Ok(Err(watcher_index_argument_fault(
            project,
            root,
            observation,
            "persisted index_repository arguments are valid JSON but not an object",
            None,
        )));
    };
    object.insert("repo_path".to_string(), Value::String(root.to_string()));
    object.insert("calyx".to_string(), Value::String("shadow".to_string()));
    let normalized_args = serde_json::to_string(&args)?;
    let observation = json!({
        "schema": "astrolabe-watcher-index-args-observation-v1",
        "state": "ready",
        "config_key": key,
        "persisted_bytes": persisted_bytes,
        "persisted_sha256": persisted_sha256,
        "effective_bytes": normalized_args.len(),
        "effective_sha256": hex_lower(&Sha256::digest(normalized_args.as_bytes())),
    });
    Ok(Ok((normalized_args, observation)))
}

fn watcher_index_argument_fault(
    project: &str,
    root: &str,
    observation: Value,
    classification_error: &str,
    parse_error: Option<String>,
) -> WatcherIndexArgumentFault {
    let structured = json!({
        "operation": "prepare_watcher_index_args",
        "phase": "watcher_preflight",
        "project": project,
        "root": root,
        "classification_error": classification_error,
        "parse_error": parse_error,
        "index_args_observation": observation.clone(),
        "remediation": "restore the named persisted index_repository argument row as one valid JSON object; no worker or retry is admitted",
    });
    let response = json!({
        "content": [{
            "type": "text",
            "text": format!("watcher index-argument classification fault for {project:?}: {classification_error}"),
        }],
        "isError": true,
        "structuredContent": structured.clone(),
        "watcher_preflight_error": true,
    });
    WatcherIndexArgumentFault {
        observation,
        response,
        evidence: WatcherErrorEvidence {
            source_error_code: None,
            code_observations: Vec::new(),
            classification_error: Some(classification_error.to_string()),
            nested_payload: Some(structured.clone()),
            operation: "prepare_watcher_index_args".to_string(),
            operation_source: "watcher_preflight_context",
            phase: "watcher_preflight".to_string(),
            phase_source: "watcher_preflight_context",
        },
    }
}

fn run_watcher_index_tick(
    runner: &CbmToolRunner,
    cache_dir: &Path,
    project: &str,
    root: &str,
    trigger_code: &str,
) -> Result<(), DynError> {
    if trigger_code == CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED {
        return persist_native_watcher_observation_recovery(cache_dir, project, root);
    }
    let native_observation_failure =
        (trigger_code != CBM_WATCHER_SOURCE_CHANGED).then_some(trigger_code);
    let fault_key = metadata_key(project, WATCHER_FAULT_STATUS_KEY);
    let prior_fault = read_config_value(cache_dir, &fault_key)?
        .map(|raw| serde_json::from_str::<Value>(&raw))
        .transpose()?;
    let (normalized_args, index_args_observation) =
        match prepare_watcher_index_args(cache_dir, project, root)? {
            Ok(prepared) => prepared,
            Err(failure) => {
                let observation = watcher_observation_resilient(
                    cache_dir,
                    project,
                    root,
                    &failure.observation,
                    prior_fault
                        .as_ref()
                        .and_then(|fault| fault.get("observation")),
                    native_observation_failure,
                );
                let observation_sha256 = persisted_json_sha256(&observation)?;
                let response_sha256 = persisted_json_sha256(&failure.response)?;
                persist_nonretryable_watcher_failure(
                    cache_dir,
                    project,
                    root,
                    &fault_key,
                    &failure.observation,
                    &observation,
                    &observation_sha256,
                    &failure.response,
                    &response_sha256,
                    None,
                    0,
                    &failure.evidence,
                    &WatcherErrorDisposition::ClassificationFault {
                        source_error_code: None,
                        basis: failure
                            .evidence
                            .classification_error
                            .clone()
                            .unwrap_or_else(|| {
                                "watcher index arguments were not usable".to_string()
                            }),
                    },
                    false,
                    None,
                )?;
                return Ok(());
            }
        };
    let prior_observation = prior_fault
        .as_ref()
        .and_then(|fault| fault.get("observation"));
    let (observation, preflight_response) = if let Some(native_code) = native_observation_failure {
        let message = format!(
            "native watcher refused the exact registered Git source observation with {native_code}"
        );
        let response = json!({
            "content": [{"type": "text", "text": format!("ASTRO_WATCHER_OBSERVATION_FAILED: {message}")}],
            "isError": true,
            "structuredContent": {
                "code": "ASTRO_WATCHER_OBSERVATION_FAILED",
                "native_code": native_code,
                "operation": "observe_watcher_source_of_truth",
                "phase": "watcher_preflight",
                "message": message,
                "remediation": "repair the direct .git entry and exact registered Git repository; parent-repository discovery is never used",
            },
            "watcher_preflight_error": true,
        });
        (
            watcher_observation_resilient(
                cache_dir,
                project,
                root,
                &index_args_observation,
                prior_observation,
                Some(native_code),
            ),
            Some(serde_json::to_string(&response)?),
        )
    } else {
        match watcher_observation(
            cache_dir,
            project,
            root,
            &index_args_observation,
            prior_observation,
        ) {
            Ok(observation) => (observation, None),
            Err(error) => {
                let message = error.to_string();
                let response = json!({
                    "content": [{"type": "text", "text": format!("ASTRO_WATCHER_OBSERVATION_FAILED: {message}")}],
                    "isError": true,
                    "structuredContent": {
                        "code": "ASTRO_WATCHER_OBSERVATION_FAILED",
                        "operation": "observe_watcher_source_of_truth",
                        "phase": "watcher_preflight",
                        "message": message,
                        "remediation": "restore readable source/store/executable state; retries are bounded for this exact observation",
                    },
                    "watcher_preflight_error": true,
                });
                (
                    watcher_observation_resilient(
                        cache_dir,
                        project,
                        root,
                        &index_args_observation,
                        prior_observation,
                        None,
                    ),
                    Some(serde_json::to_string(&response)?),
                )
            }
        }
    };
    let observation_sha256 = persisted_json_sha256(&observation)?;
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
            "operation": prior_fault.as_ref().and_then(|fault| fault.get("operation")),
            "operation_source": prior_fault.as_ref().and_then(|fault| fault.get("operation_source")),
            "phase": prior_fault.as_ref().and_then(|fault| fault.get("phase")),
            "phase_source": prior_fault.as_ref().and_then(|fault| fault.get("phase_source")),
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
    let worker_started = preflight_response.is_none();
    let response = match preflight_response {
        Some(response) => response,
        None => match handle_index_repository(runner, &normalized_args) {
            Ok(response) => response,
            Err(error) => {
                let message = error.to_string();
                let unwrapped_error_sha256 = hex_lower(&Sha256::digest(message.as_bytes()));
                serde_json::to_string(&json!({
                    "content": [{"type": "text", "text": message}],
                    "isError": true,
                    "structuredContent": {
                        "operation": WATCHER_INDEX_OPERATION,
                        "phase": WATCHER_INDEX_PHASE,
                        "unwrapped_error_sha256": unwrapped_error_sha256,
                    },
                    "watcher_unwrapped_error": true,
                    "unwrapped_error_sha256": unwrapped_error_sha256,
                }))?
            }
        },
    };
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let raw_response_sha256 = hex_lower(&Sha256::digest(response.as_bytes()));
    let response_value: Value = match serde_json::from_str(&response) {
        Ok(response_value) => response_value,
        Err(error) => {
            let evidence = WatcherErrorEvidence {
                source_error_code: None,
                code_observations: Vec::new(),
                classification_error: Some(format!(
                    "index_repository returned malformed JSON: {error}"
                )),
                nested_payload: None,
                operation: WATCHER_INDEX_OPERATION.to_string(),
                operation_source: "watcher_invocation_context",
                phase: WATCHER_INDEX_PHASE.to_string(),
                phase_source: "watcher_invocation_context",
            };
            let diagnostic_response = json!({
                "raw_response": response,
                "raw_response_sha256": raw_response_sha256,
                "parse_error": error.to_string(),
            });
            let response_sha256 = persisted_json_sha256(&diagnostic_response)?;
            persist_nonretryable_watcher_failure(
                cache_dir,
                project,
                root,
                &fault_key,
                &index_args_observation,
                &observation,
                &observation_sha256,
                &diagnostic_response,
                &response_sha256,
                Some(&raw_response_sha256),
                elapsed_ms,
                &evidence,
                &WatcherErrorDisposition::ClassificationFault {
                    source_error_code: None,
                    basis: "malformed_tool_result_envelope".to_string(),
                },
                worker_started,
                None,
            )?;
            return Ok(());
        }
    };
    let response_sha256 = persisted_json_sha256(&response_value)?;
    let is_error = match response_value.get("isError").and_then(Value::as_bool) {
        Some(is_error) => is_error,
        None => {
            let mut evidence = watcher_error_evidence(&response_value);
            let missing_disposition = "tool result has no boolean isError disposition";
            evidence.classification_error = Some(match evidence.classification_error.take() {
                Some(existing) => format!("{existing}; {missing_disposition}"),
                None => missing_disposition.to_string(),
            });
            persist_nonretryable_watcher_failure(
                cache_dir,
                project,
                root,
                &fault_key,
                &index_args_observation,
                &observation,
                &observation_sha256,
                &response_value,
                &response_sha256,
                Some(&raw_response_sha256),
                elapsed_ms,
                &evidence,
                &WatcherErrorDisposition::ClassificationFault {
                    source_error_code: None,
                    basis: "missing_tool_result_error_disposition".to_string(),
                },
                worker_started,
                None,
            )?;
            return Ok(());
        }
    };
    if is_error {
        let evidence = watcher_error_evidence(&response_value);
        let disposition = watcher_error_disposition(&evidence);
        if let WatcherErrorDisposition::Retryable {
            source_error_code,
            basis,
        } = &disposition
        {
            let attempt = match next_transient_watcher_attempt(
                cache_dir,
                project,
                &observation_sha256,
                source_error_code,
            )? {
                TransientAttemptDisposition::Attempt(attempt) => attempt,
                TransientAttemptDisposition::ClassificationFault(attempt_error) => {
                    persist_nonretryable_watcher_failure(
                        cache_dir,
                        project,
                        root,
                        &fault_key,
                        &index_args_observation,
                        &observation,
                        &observation_sha256,
                        &response_value,
                        &response_sha256,
                        Some(&raw_response_sha256),
                        elapsed_ms,
                        &evidence,
                        &WatcherErrorDisposition::ClassificationFault {
                            source_error_code: Some(source_error_code.clone()),
                            basis: attempt_error,
                        },
                        worker_started,
                        None,
                    )?;
                    return Ok(());
                }
            };
            if attempt < WATCHER_DEFAULT_TRANSIENT_MAX_ATTEMPTS {
                let status = json!({
                    "schema": "astrolabe-watcher-tick-v2",
                    "status": "transient_error",
                    "project": project,
                    "elapsed_ms": elapsed_ms,
                    "freshness": "stale",
                    "trust": "provisional",
                    "failure_disposition": "retryable",
                    "disposition_basis": basis,
                    "source_error_code": source_error_code,
                    "error_evidence": watcher_error_evidence_value(&evidence),
                    "operation": evidence.operation,
                    "operation_source": evidence.operation_source,
                    "phase": evidence.phase,
                    "phase_source": evidence.phase_source,
                    "transient_attempt": attempt,
                    "transient_max_attempts": WATCHER_DEFAULT_TRANSIENT_MAX_ATTEMPTS,
                    "observation_sha256": observation_sha256,
                    "response_sha256": response_sha256,
                    "response_hash_basis": PERSISTED_JSON_SHA256_BASIS,
                    "raw_response_sha256": raw_response_sha256,
                    "response": response_value,
                    "worker_started": worker_started,
                    "remediation": "the exact registered transient condition may retry only inside the declared per-observation attempt budget; inspect this status if it does not clear",
                });
                persist_watcher_status(cache_dir, project, &status)?;
                return Err(format!(
                    "ASTRO_WATCHER_EXPLICIT_TRANSIENT: watcher index tick failed for {project:?}; source_error_code={source_error_code}; transient_attempt={attempt}; transient_max_attempts={WATCHER_DEFAULT_TRANSIENT_MAX_ATTEMPTS}; response_sha256={response_sha256}; response={response}"
                )
                .into());
            }
            let exhausted = WatcherErrorDisposition::NonRetryable {
                fault_code: "ASTRO_WATCHER_TRANSIENT_RETRY_EXHAUSTED".to_string(),
                source_error_code: source_error_code.clone(),
                basis: "registered_transient_attempt_budget_exhausted",
            };
            persist_nonretryable_watcher_failure(
                cache_dir,
                project,
                root,
                &fault_key,
                &index_args_observation,
                &observation,
                &observation_sha256,
                &response_value,
                &response_sha256,
                Some(&raw_response_sha256),
                elapsed_ms,
                &evidence,
                &exhausted,
                worker_started,
                Some(attempt),
            )?;
            return Ok(());
        }
        persist_nonretryable_watcher_failure(
            cache_dir,
            project,
            root,
            &fault_key,
            &index_args_observation,
            &observation,
            &observation_sha256,
            &response_value,
            &response_sha256,
            Some(&raw_response_sha256),
            elapsed_ms,
            &evidence,
            &disposition,
            worker_started,
            None,
        )?;
        // The indexing operation failed, but change-detection coordination
        // converged: advancing the C baseline is what prevents a second
        // identical worker. The durable fault remains the serving truth.
        return Ok(());
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
        "response_sha256": response_sha256,
        "response_hash_basis": PERSISTED_JSON_SHA256_BASIS,
        "raw_response_sha256": raw_response_sha256,
        "commit_ood_producer": commit_ood_producer,
        "commit_ood": commit_ood,
    });
    persist_watcher_status(cache_dir, project, &status)?;
    Ok(())
}

fn persist_native_watcher_observation_recovery(
    cache_dir: &Path,
    project: &str,
    root: &str,
) -> Result<(), DynError> {
    let (_, index_args_observation) = match prepare_watcher_index_args(cache_dir, project, root)? {
        Ok(prepared) => prepared,
        Err(failure) => {
            return Err(format!(
                "ASTRO_WATCHER_OBSERVATION_RECOVERY_CONTEXT_INVALID: exact native Git observation recovered for {project:?}, but persisted index arguments remain unusable: {}; remediation: repair the named config row before recovery can commit",
                failure
                    .evidence
                    .classification_error
                    .as_deref()
                    .unwrap_or("watcher index arguments were not usable")
            )
            .into());
        }
    };
    let fault_key = metadata_key(project, WATCHER_FAULT_STATUS_KEY);
    let tick_key = metadata_key(project, WATCHER_TICK_STATUS_KEY);
    let [prior_fault_raw, prior_tick_raw] =
        read_config_values(cache_dir, &[fault_key.clone(), tick_key.clone()])?
            .try_into()
            .map_err(|_| {
                "ASTRO_WATCHER_OBSERVATION_RECOVERY_READBACK_INVALID: exact two-key config read returned the wrong cardinality"
            })?;
    let prior_fault = prior_fault_raw
        .as_deref()
        .map(serde_json::from_str::<Value>)
        .transpose()?;
    let prior_tick = prior_tick_raw
        .as_deref()
        .map(serde_json::from_str::<Value>)
        .transpose()?;
    let prior_observation = prior_fault
        .as_ref()
        .and_then(|fault| fault.get("observation"));
    let observation = watcher_observation(
        cache_dir,
        project,
        root,
        &index_args_observation,
        prior_observation,
    )?;
    let observation_sha256 = persisted_json_sha256(&observation)?;
    let status = json!({
        "schema": "astrolabe-watcher-tick-v2",
        "status": "source_observation_recovered",
        "project": project,
        "root": root,
        "native_trigger_code": CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED,
        "prior_fault_code": prior_fault.as_ref().and_then(|value| value.get("fault_code")),
        "prior_source_error_code": prior_tick.as_ref().and_then(|value| value.get("source_error_code")),
        "observation": observation,
        "observation_sha256": observation_sha256,
        "freshness": "fresh",
        "trust": "verified",
        "worker_started": false,
        "remediation": "none; the exact registered Git source is readable again and no source delta was present",
    });
    let status_json = serde_json::to_string(&status)?;

    let mut connection = open_config(cache_dir)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute("DELETE FROM config WHERE key = ?1", params![fault_key])?;
    transaction.execute(
        "INSERT INTO config (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value \
         WHERE config.value <> excluded.value",
        params![tick_key, status_json],
    )?;
    transaction.commit()?;

    let readback = read_config_values(cache_dir, &[fault_key.clone(), tick_key.clone()])?;
    if readback != vec![None, Some(status_json)] {
        return Err(format!(
            "ASTRO_WATCHER_OBSERVATION_RECOVERY_COMMIT_MISMATCH: recovery for {project:?} did not read back fault-absent/status-present; remediation: preserve the config database and inspect its WAL"
        )
        .into());
    }
    tracing::info!(
        project,
        root,
        observation_sha256,
        "incremental_watcher.source_observation_recovered"
    );
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
        let index_args_observation = match prepare_watcher_index_args(cache_dir, project, root)? {
            Ok((_, observation)) => observation,
            Err(failure) => failure.observation,
        };
        let current = watcher_rearm_signature(cache_dir, project, root, &index_args_observation)?;
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
    index_args_observation: &Value,
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
        "schema": "astrolabe-watcher-observation-v2",
        "project": project,
        "canonical_root": fs::canonicalize(root)?,
        "source_fingerprint": source_fingerprint,
        "index_args": index_args_observation,
        "store_family": members,
        "executable": executable_observation()?,
    }))
}

fn watcher_observation_resilient(
    cache_dir: &Path,
    project: &str,
    root: &str,
    index_args_observation: &Value,
    prior: Option<&Value>,
    native_source_error: Option<&str>,
) -> Value {
    let source_fingerprint = match native_source_error {
        Some(code) => json!({
            "state": "read_error",
            "code": code,
            "source": "native_exact_git_context",
        }),
        None => match astrolabe_anchors::archaeology::git_source_fingerprint(Path::new(root)) {
            Ok(value) => json!({"state": "observed", "value": value}),
            Err(error) => json!({"state": "read_error", "error": error.to_string()}),
        },
    };
    let canonical_root = match fs::canonicalize(root) {
        Ok(path) => json!({"state": "observed", "path": path}),
        Err(error) => json!({"state": "read_error", "error": error.to_string()}),
    };
    let mut members = Vec::new();
    for path in store_family_paths(cache_dir, project) {
        let metadata = match file_metadata_observation(&path) {
            Ok(metadata) => metadata,
            Err(error) => json!({"read_error": error.to_string()}),
        };
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
                .cloned()
                .unwrap_or_else(|| Value::String("absent".to_string()))
        } else if metadata.get("present").and_then(Value::as_bool) == Some(true) {
            match sha256_file(&path) {
                Ok(sha256) => Value::String(sha256),
                Err(error) => json!({"read_error": error.to_string()}),
            }
        } else if metadata.get("present").and_then(Value::as_bool) == Some(false) {
            Value::String("absent".to_string())
        } else {
            json!({"state": "unavailable"})
        };
        members.push(json!({"path": path, "metadata": metadata, "sha256": sha256}));
    }
    let executable = match executable_observation() {
        Ok(value) => json!({"state": "observed", "value": value}),
        Err(error) => json!({"state": "read_error", "error": error.to_string()}),
    };
    json!({
        "schema": "astrolabe-watcher-observation-v2",
        "observation_state": "contains_read_fault",
        "project": project,
        "canonical_root": canonical_root,
        "source_fingerprint": source_fingerprint,
        "index_args": index_args_observation,
        "store_family": members,
        "executable": executable,
    })
}

fn watcher_rearm_signature(
    cache_dir: &Path,
    project: &str,
    root: &str,
    index_args_observation: &Value,
) -> Result<Value, DynError> {
    let store_family = store_family_paths(cache_dir, project)
        .into_iter()
        .map(|path| {
            let metadata = match file_metadata_observation(&path) {
                Ok(metadata) => metadata,
                Err(error) => json!({"read_error": error.to_string()}),
            };
            json!({"path": path, "metadata": metadata})
        })
        .collect::<Vec<_>>();
    let canonical_root = match fs::canonicalize(root) {
        Ok(path) => json!({"state": "observed", "path": path}),
        Err(error) => json!({"state": "read_error", "error": error.to_string()}),
    };
    let root_metadata = match file_metadata_observation(Path::new(root)) {
        Ok(metadata) => metadata,
        Err(error) => json!({"read_error": error.to_string()}),
    };
    let executable = match executable_sentinel() {
        Ok(value) => value,
        Err(error) => json!({"state": "read_error", "error": error.to_string()}),
    };
    Ok(json!({
        "schema": "astrolabe-watcher-rearm-v2",
        "root": {"canonical": canonical_root, "metadata": root_metadata},
        "index_args": index_args_observation,
        "store_family": store_family,
        "executable": executable,
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

fn watcher_error_evidence(response: &Value) -> WatcherErrorEvidence {
    let mut candidates = Vec::<(&'static str, String)>::new();
    let mut defects = Vec::<String>::new();
    let mut nested_payload = None;

    if let Some(structured) = response.get("structuredContent") {
        if structured.is_null() {
            // Legacy text-only errors intentionally carry no structuredContent.
        } else if let Some(object) = structured.as_object() {
            nested_payload = Some(structured.clone());
            if let Some(code) = object.get("code") {
                push_watcher_error_code_candidate(
                    code,
                    "structuredContent.code",
                    &mut candidates,
                    &mut defects,
                );
            }
        } else {
            defects.push("structuredContent is neither an object nor null".to_string());
        }
    }
    if let Some(code) = response.get("code") {
        push_watcher_error_code_candidate(code, "result.code", &mut candidates, &mut defects);
    }

    match response.get("content") {
        Some(Value::Array(items)) if !items.is_empty() => {
            for item in items {
                let Some(text) = item.get("text").and_then(Value::as_str) else {
                    defects.push("error content item has no string text field".to_string());
                    continue;
                };
                match serde_json::from_str::<Value>(text) {
                    Ok(inner) => {
                        if nested_payload.is_none() && inner.is_object() {
                            nested_payload = Some(inner.clone());
                        }
                        if let Some(code) = inner.get("code") {
                            push_watcher_error_code_candidate(
                                code,
                                "content.text.json.code",
                                &mut candidates,
                                &mut defects,
                            );
                        }
                    }
                    Err(_) => {
                        if let Some(code) = plain_watcher_error_code(text) {
                            candidates.push(("content.text.prefix", code));
                        } else if let Some(code) = shadow_publication_recovery_error_code(text) {
                            candidates.push(("content.text.recovery_code", code.to_string()));
                        }
                    }
                }
            }
        }
        Some(Value::Array(_)) => defects.push("error content array is empty".to_string()),
        Some(_) => defects.push("error content is not an array".to_string()),
        None => defects.push("error result has no content field".to_string()),
    }

    let mut distinct_codes = candidates
        .iter()
        .map(|(_, code)| code.as_str())
        .collect::<Vec<_>>();
    distinct_codes.sort_unstable();
    distinct_codes.dedup();
    if distinct_codes.len() > 1 {
        defects.push(format!(
            "conflicting error codes were present: {}",
            distinct_codes.join(", ")
        ));
    }
    let source_error_code = distinct_codes.first().map(|code| (*code).to_string());
    if source_error_code.is_none() {
        defects.push("no exact source error code was present".to_string());
    }
    let (operation, operation_source) = watcher_error_context_field(
        nested_payload.as_ref(),
        &["operation", "failed_operation"],
        WATCHER_INDEX_OPERATION,
        "operation",
        &mut defects,
    );
    let (phase, phase_source) = watcher_error_context_field(
        nested_payload.as_ref(),
        &["phase"],
        WATCHER_INDEX_PHASE,
        "phase",
        &mut defects,
    );
    WatcherErrorEvidence {
        source_error_code,
        code_observations: candidates
            .iter()
            .map(|(source, code)| json!({"source": source, "code": code}))
            .collect(),
        classification_error: (!defects.is_empty()).then(|| defects.join("; ")),
        nested_payload,
        operation,
        operation_source,
        phase,
        phase_source,
    }
}

fn watcher_error_context_field(
    nested_payload: Option<&Value>,
    candidate_keys: &[&'static str],
    invocation_value: &'static str,
    field_name: &'static str,
    defects: &mut Vec<String>,
) -> (String, &'static str) {
    let Some(payload) = nested_payload else {
        return (invocation_value.to_string(), "watcher_invocation_context");
    };
    for key in candidate_keys {
        let Some(value) = payload.get(*key) else {
            continue;
        };
        match value.as_str() {
            Some(value) if !value.trim().is_empty() => {
                return (value.to_string(), "response_payload");
            }
            _ => defects.push(format!(
                "nested payload {field_name} field {key:?} is not a non-empty string"
            )),
        }
    }
    (invocation_value.to_string(), "watcher_invocation_context")
}

fn push_watcher_error_code_candidate(
    value: &Value,
    source: &'static str,
    candidates: &mut Vec<(&'static str, String)>,
    defects: &mut Vec<String>,
) {
    let Some(code) = value.as_str() else {
        defects.push(format!("{source} is not a string"));
        return;
    };
    if !valid_watcher_error_code(code) {
        defects.push(format!("{source} has invalid code syntax {code:?}"));
        return;
    }
    candidates.push((source, code.to_string()));
}

fn valid_watcher_error_code(code: &str) -> bool {
    let mut chars = code.chars();
    chars.next().is_some_and(|first| first.is_ascii_uppercase())
        && chars.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        && code.contains('_')
}

fn plain_watcher_error_code(text: &str) -> Option<String> {
    let trimmed = text.trim_start();
    let prefix = trimmed
        .split_once(|ch: char| ch == ':' || ch.is_ascii_whitespace())
        .map_or(trimmed, |(prefix, _)| prefix);
    if valid_watcher_error_code(prefix) {
        return Some(prefix.to_string());
    }
    trimmed
        .split_ascii_whitespace()
        .find_map(|token| token.strip_prefix("code="))
        .map(|code| code.trim_end_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_'))
        .filter(|code| valid_watcher_error_code(code))
        .map(ToOwned::to_owned)
}

fn watcher_error_disposition(evidence: &WatcherErrorEvidence) -> WatcherErrorDisposition {
    if let Some(error) = evidence.classification_error.as_ref() {
        return WatcherErrorDisposition::ClassificationFault {
            source_error_code: evidence.source_error_code.clone(),
            basis: error.clone(),
        };
    }
    let Some(code) = evidence.source_error_code.as_deref() else {
        return WatcherErrorDisposition::ClassificationFault {
            source_error_code: None,
            basis: "no exact source error code was present".to_string(),
        };
    };
    const RETRYABLE_CODES: &[&str] = &[
        "ASTRO_CONFIG_DB_WAL_CONTENDED",
        "ASTRO_SHADOW_IMPORT_BUSY",
        "ASTRO_SHADOW_NOOP_CONFIG_CHANGED",
        "ASTRO_SHADOW_NOOP_GENERATION_CHANGED",
        "ASTRO_WATCHER_OBSERVATION_FAILED",
        "CALYX_BACKPRESSURE",
        "CALYX_DISK_PRESSURE",
        "CALYX_READER_LEASE_EXPIRED",
        "CBM_INDEX_HOST_BUSY",
        "CBM_INDEX_PROJECT_BUSY",
        "CBM_PROJECT_TRANSITION_ACTIVE",
        "CBM_STORE_VERIFICATION_FAILED",
    ];
    if RETRYABLE_CODES.contains(&code) {
        return WatcherErrorDisposition::Retryable {
            source_error_code: code.to_string(),
            basis: "exact_registered_transient_code",
        };
    }
    const NON_RETRYABLE_CODES: &[&str] = &[
        "ASTRO_SHADOW_PROJECT_MISMATCH",
        "CBM_INCREMENTAL_BRANCH_EDGE_INVALID",
        "CBM_PIPELINE_EMPTY_SOURCE_CORPUS",
        "CBM_SCHEMA_FRESHNESS_UNREADABLE",
        "CBM_SCHEMA_VERSION_UNSTAMPED",
        "CBM_SCHEMA_VERSION_UNSUPPORTED",
        "CBM_STORE_INTEGRITY_FAILED",
        "CBM_STORE_PROVENANCE_FAILED",
    ];
    if NON_RETRYABLE_CODES.contains(&code) || shadow_publication_recovery_error_code(code).is_some()
    {
        return WatcherErrorDisposition::NonRetryable {
            fault_code: code.to_string(),
            source_error_code: code.to_string(),
            basis: "exact_registered_non_retryable_code",
        };
    }
    WatcherErrorDisposition::ClassificationFault {
        source_error_code: Some(code.to_string()),
        basis: format!("unregistered source error code {code:?}"),
    }
}

fn watcher_error_evidence_value(evidence: &WatcherErrorEvidence) -> Value {
    json!({
        "source_error_code": evidence.source_error_code,
        "code_observations": evidence.code_observations,
        "classification_error": evidence.classification_error,
        "operation": evidence.operation,
        "operation_source": evidence.operation_source,
        "phase": evidence.phase,
        "phase_source": evidence.phase_source,
        "nested_payload": evidence.nested_payload,
    })
}

fn next_transient_watcher_attempt(
    cache_dir: &Path,
    project: &str,
    observation_sha256: &str,
    source_error_code: &str,
) -> Result<TransientAttemptDisposition, DynError> {
    let key = metadata_key(project, WATCHER_TICK_STATUS_KEY);
    let Some(raw_status) = read_config_value(cache_dir, &key)? else {
        return Ok(TransientAttemptDisposition::Attempt(1));
    };
    let status: Value = match serde_json::from_str(&raw_status) {
        Ok(status) => status,
        Err(error) => {
            return Ok(TransientAttemptDisposition::ClassificationFault(format!(
                "prior watcher_tick_json is malformed JSON (bytes={}, sha256={}, parse_error={error})",
                raw_status.len(),
                hex_lower(&Sha256::digest(raw_status.as_bytes()))
            )));
        }
    };
    if status.get("status").and_then(Value::as_str) != Some("transient_error")
        || status.get("observation_sha256").and_then(Value::as_str) != Some(observation_sha256)
        || status.get("source_error_code").and_then(Value::as_str) != Some(source_error_code)
    {
        return Ok(TransientAttemptDisposition::Attempt(1));
    }
    let Some(prior) = status.get("transient_attempt").and_then(Value::as_u64) else {
        return Ok(TransientAttemptDisposition::ClassificationFault(format!(
            "prior transient watcher_tick_json for {project:?} has no unsigned transient_attempt"
        )));
    };
    Ok(match prior.checked_add(1) {
        Some(attempt) => TransientAttemptDisposition::Attempt(attempt),
        None => TransientAttemptDisposition::ClassificationFault(format!(
            "prior transient watcher_tick_json for {project:?} would overflow its u64 attempt counter"
        )),
    })
}

#[allow(clippy::too_many_arguments)]
fn persist_nonretryable_watcher_failure(
    cache_dir: &Path,
    project: &str,
    root: &str,
    fault_key: &str,
    index_args_observation: &Value,
    observation: &Value,
    observation_sha256: &str,
    response: &Value,
    response_sha256: &str,
    raw_response_sha256: Option<&str>,
    elapsed_ms: u64,
    evidence: &WatcherErrorEvidence,
    disposition: &WatcherErrorDisposition,
    worker_started: bool,
    transient_attempt: Option<u64>,
) -> Result<(), DynError> {
    let (status_name, fault_status, fault_code, source_error_code, failure_disposition, basis) =
        match disposition {
            WatcherErrorDisposition::Retryable { .. } => {
                return Err(
                    "ASTRO_WATCHER_DISPOSITION_INTERNAL: retryable failure reached non-retryable persistence"
                        .into(),
                );
            }
            WatcherErrorDisposition::NonRetryable {
                fault_code,
                source_error_code,
                basis,
            } if fault_code == "ASTRO_WATCHER_TRANSIENT_RETRY_EXHAUSTED" => (
                "transient_retry_exhausted",
                "transient_retry_exhausted",
                fault_code.clone(),
                Some(source_error_code.clone()),
                "non_retryable",
                (*basis).to_string(),
            ),
            WatcherErrorDisposition::NonRetryable {
                fault_code,
                source_error_code,
                basis,
            } => (
                "terminal_fault_recorded",
                "terminal_fault",
                fault_code.clone(),
                Some(source_error_code.clone()),
                "non_retryable",
                (*basis).to_string(),
            ),
            WatcherErrorDisposition::ClassificationFault {
                source_error_code,
                basis,
            } => (
                "classification_fault_recorded",
                "classification_fault",
                "ASTRO_WATCHER_ERROR_DISPOSITION_UNCLASSIFIED".to_string(),
                source_error_code.clone(),
                "unclassified_non_retryable",
                basis.clone(),
            ),
        };
    let fault = json!({
        "schema": "astrolabe-watcher-fault-v2",
        "status": fault_status,
        "project": project,
        "fault_code": fault_code,
        "source_error_code": source_error_code,
        "failure_disposition": failure_disposition,
        "disposition_basis": basis,
        "error_evidence": watcher_error_evidence_value(evidence),
        "operation": evidence.operation,
        "operation_source": evidence.operation_source,
        "phase": evidence.phase,
        "phase_source": evidence.phase_source,
        "observation": observation,
        "observation_sha256": observation_sha256,
        "rearm_signature": watcher_rearm_signature(cache_dir, project, root, index_args_observation)?,
        "response_sha256": response_sha256,
        "response_hash_basis": PERSISTED_JSON_SHA256_BASIS,
        "raw_response_sha256": raw_response_sha256,
        "response": response,
        "worker_started": worker_started,
        "transient_attempt": transient_attempt,
        "transient_max_attempts": if fault_code == "ASTRO_WATCHER_TRANSIENT_RETRY_EXHAUSTED" {
            Value::from(WATCHER_DEFAULT_TRANSIENT_MAX_ATTEMPTS)
        } else {
            Value::Null
        },
        "retry_suppressed_until_observation_changes": true,
        "remediation": "repair the exact source/store/config state or the named error-disposition contract; unchanged periodic retries are suppressed",
    });
    persist_watcher_fault(cache_dir, project, fault_key, &fault)?;
    let status = json!({
        "schema": "astrolabe-watcher-tick-v2",
        "status": status_name,
        "project": project,
        "fault_code": fault.get("fault_code"),
        "source_error_code": fault.get("source_error_code"),
        "failure_disposition": fault.get("failure_disposition"),
        "disposition_basis": fault.get("disposition_basis"),
        "error_evidence": fault.get("error_evidence"),
        "operation": fault.get("operation"),
        "operation_source": fault.get("operation_source"),
        "phase": fault.get("phase"),
        "phase_source": fault.get("phase_source"),
        "elapsed_ms": elapsed_ms,
        "observation_sha256": fault.get("observation_sha256"),
        "response_sha256": fault.get("response_sha256"),
        "response_hash_basis": fault.get("response_hash_basis"),
        "raw_response_sha256": fault.get("raw_response_sha256"),
        "freshness": "stale",
        "trust": "verified",
        "worker_started": worker_started,
        "transient_attempt": fault.get("transient_attempt"),
        "transient_max_attempts": fault.get("transient_max_attempts"),
        "retry_suppressed_until_observation_changes": true,
    });
    persist_watcher_status(cache_dir, project, &status)
}

fn persist_watcher_fault(
    cache_dir: &Path,
    project: &str,
    fault_key: &str,
    fault: &Value,
) -> Result<(), DynError> {
    verify_embedded_response_sha256(fault, "watcher_fault.before_write")?;
    let serialized = serde_json::to_string(fault)?;
    write_config_value(cache_dir, fault_key, &serialized)?;
    let readback = read_config_value(cache_dir, fault_key)?;
    if readback.as_deref() != Some(serialized.as_str()) {
        return Err(format!(
            "ASTRO_WATCHER_FAULT_READBACK_MISMATCH: persisted fault for {project:?} did not match its exact write"
        )
        .into());
    }
    let readback_value: Value = serde_json::from_str(readback.as_deref().ok_or_else(|| {
        format!("ASTRO_WATCHER_FAULT_READBACK_ABSENT: persisted fault for {project:?} disappeared")
    })?)?;
    verify_embedded_response_sha256(&readback_value, "watcher_fault.after_readback")?;
    Ok(())
}

fn persist_watcher_status(cache_dir: &Path, project: &str, status: &Value) -> Result<(), DynError> {
    verify_embedded_response_sha256(status, "watcher_status.before_write")?;
    let key = metadata_key(project, WATCHER_TICK_STATUS_KEY);
    let serialized = serde_json::to_string(status)?;
    write_config_value(cache_dir, &key, &serialized)?;
    let readback = read_config_value(cache_dir, &key)?;
    if readback.as_deref() != Some(serialized.as_str()) {
        return Err(format!(
            "ASTRO_WATCHER_STATUS_READBACK_MISMATCH: durable status row for {project:?} did not equal its exact write"
        )
        .into());
    }
    let readback_value: Value = serde_json::from_str(readback.as_deref().ok_or_else(|| {
        format!("ASTRO_WATCHER_STATUS_READBACK_ABSENT: durable status for {project:?} disappeared")
    })?)?;
    verify_embedded_response_sha256(&readback_value, "watcher_status.after_readback")?;
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

fn persist_root_fault_and_status_atomic(
    cache_dir: &Path,
    registration: &WatchRegistration,
    fault: &Value,
    status: &Value,
) -> Result<(), DynError> {
    let root_key = metadata_key(&registration.project, WATCHER_ROOT_FAULT_STATUS_KEY);
    let status_key = metadata_key(&registration.project, WATCHER_TICK_STATUS_KEY);
    let fault_json = serde_json::to_string(fault)?;
    let status_json = serde_json::to_string(status)?;
    let mut connection = open_config(cache_dir)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let current_root_fault = transaction
        .query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![root_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if current_root_fault.as_deref() != registration.root_fault_raw.as_deref() {
        return Err(format!(
            "ASTRO_WATCHER_ROOT_FAULT_PREIMAGE_CHANGED: project {:?} root fault changed between registration scan and atomic publication; remediation: preserve both observations and retry from a fresh config snapshot",
            registration.project,
        )
        .into());
    }
    for (key, value) in [(&root_key, &fault_json), (&status_key, &status_json)] {
        transaction.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        let readback = transaction.query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )?;
        if readback != *value {
            return Err(format!(
                "ASTRO_WATCHER_ROOT_FAULT_TRANSACTION_READBACK_MISMATCH: key {key:?} did not equal its exact candidate inside the transaction; remediation: roll back and inspect the config database"
            )
            .into());
        }
    }
    transaction.commit()?;
    let readback = read_config_values(cache_dir, &[root_key.clone(), status_key.clone()])?;
    if readback != vec![Some(fault_json), Some(status_json)] {
        return Err(format!(
            "ASTRO_WATCHER_ROOT_FAULT_COMMIT_READBACK_MISMATCH: project {:?} atomic root-fault/status rows did not read back exactly; remediation: preserve the config database and inspect its WAL before serving the project",
            registration.project,
        )
        .into());
    }
    Ok(())
}

fn clear_resolved_root_fault(
    cache_dir: &Path,
    registration: &WatchRegistration,
    prior_fault: &Value,
    catch_up: Option<&Value>,
) -> Result<(), DynError> {
    let expected_identity = registration
        .root_identity_raw
        .as_deref()
        .ok_or_else(|| -> DynError {
            "ASTRO_WATCHER_ROOT_RESTORE_IDENTITY_MISSING: exact-root recovery has no persisted identity".into()
        })
        .and_then(parse_root_identity)?;
    let status = catch_up.cloned().unwrap_or_else(|| {
        json!({
            "schema": "astrolabe-watcher-tick-v3",
            "status": "root_restored_unchanged",
            "project": registration.project,
            "root": registration.root,
            "root_identity": expected_identity,
            "prior_fault_code": prior_fault.get("fault_code"),
            "prior_observation_sha256": prior_fault.get("observation_sha256"),
            "freshness": "fresh",
            "trust": "verified",
            "worker_started": false,
            "index_work_performed": false,
            "artifacts_preserved": true,
        })
    });
    let status_json = serde_json::to_string(&status)?;
    let root_key = metadata_key(&registration.project, WATCHER_ROOT_FAULT_STATUS_KEY);
    let status_key = metadata_key(&registration.project, WATCHER_TICK_STATUS_KEY);
    let mut connection = open_config(cache_dir)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let current_raw = transaction
        .query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![root_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| -> DynError {
            "ASTRO_WATCHER_ROOT_FAULT_CLEAR_PREIMAGE_ABSENT: root fault disappeared before exact-root recovery committed; remediation: preserve the config database and retry from a fresh observation".into()
        })?;
    let current = parse_root_fault(&current_raw, registration)?;
    if &current != prior_fault {
        return Err(format!(
            "ASTRO_WATCHER_ROOT_FAULT_CLEAR_PREIMAGE_CHANGED: project {:?} root fault changed before exact-root recovery committed; remediation: preserve both observations and retry from a fresh config snapshot",
            registration.project,
        )
        .into());
    }
    transaction.execute("DELETE FROM config WHERE key = ?1", params![root_key])?;
    if transaction
        .query_row(
            "SELECT value FROM config WHERE key = ?1",
            params![root_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .is_some()
    {
        return Err(
            "ASTRO_WATCHER_ROOT_FAULT_CLEAR_TRANSACTION_MISMATCH: root fault remained inside its delete transaction; remediation: roll back and inspect the config database"
                .into(),
        );
    }
    transaction.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
        params![status_key, status_json],
    )?;
    transaction.commit()?;
    let readback = read_config_values(cache_dir, &[root_key, status_key])?;
    if readback != vec![None, Some(status_json)] {
        return Err(format!(
            "ASTRO_WATCHER_ROOT_FAULT_CLEAR_COMMIT_MISMATCH: project {:?} exact-root recovery did not read back fault-absent/status-present; remediation: preserve the config database and inspect its WAL",
            registration.project,
        )
        .into());
    }
    tracing::info!(
        project = %registration.project,
        root = %registration.root,
        catch_up_scheduled = catch_up.is_some(),
        "incremental_watcher.root_fault_cleared"
    );
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
