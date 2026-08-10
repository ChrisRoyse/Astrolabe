use super::*;

use astrolabe_bridge::{
    CbmProjectQuiescence, CbmProjectQuiescenceError, CbmProjectTransition,
    normalize_existing_project_store,
};
use astrolabe_domain::knobs::{
    PROJECT_TRANSITION_QUIESCENCE_TIMEOUT_MS, WATCHER_DEFAULT_POLL_INTERVAL_MS,
};

/// Fail-closed: `repo_path` did not resolve to an existing canonical root.
///
/// A caller-input fault (#910). Declared as a real constant so the code the caller
/// branches on has one definition rather than being spelled inline in a message.
pub(crate) const ASTRO_PROJECT_TRANSITION_ROOT_UNRESOLVED: &str =
    "ASTRO_PROJECT_TRANSITION_ROOT_UNRESOLVED";
pub(crate) const PROJECT_TRANSITION_STATUS_KEY: &str = "project_transition_json";
const PROJECT_TRANSITION_WORKER_GRANT_SCHEMA: &str = "astrolabe-project-transition-worker-grant-v3";

#[derive(Debug)]
struct ProjectNormalizationEvidenceError {
    message: String,
    evidence: Value,
}

impl std::fmt::Display for ProjectNormalizationEvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProjectNormalizationEvidenceError {}

#[derive(Debug, Clone)]
pub(crate) struct ProjectTransitionWorkerGrant {
    schema: String,
    project: String,
    canonical_root: PathBuf,
    canonical_db_path: PathBuf,
    receipt_cache_dir: PathBuf,
    generation: String,
    owner_pid: u32,
    owner_process_start_utc_ticks: u64,
}

impl ProjectTransitionWorkerGrant {
    pub(crate) fn for_worker_cache(&self, worker_cache: &Path) -> Result<Value, DynError> {
        let canonical_worker_cache = fs::canonicalize(worker_cache).map_err(|error| {
            format!(
                "ASTRO_PROJECT_TRANSITION_WORKER_CACHE_UNRESOLVED: canonicalizing worker cache {} failed: {error}; remediation: preserve the index generation and inspect its exact cache directory",
                worker_cache.display()
            )
        })?;
        Ok(json!({
            "schema": self.schema,
            "project": self.project,
            "canonical_root": self.canonical_root,
            "canonical_db_path": self.canonical_db_path,
            "receipt_cache_dir": self.receipt_cache_dir,
            "canonical_worker_cache": canonical_worker_cache,
            "generation": self.generation,
            "owner": {
                "pid": self.owner_pid,
                "process_start_utc_ticks": self.owner_process_start_utc_ticks,
            },
        }))
    }
}

struct ProjectTransitionWorkerGrantEnvelope {
    schema: String,
    project: String,
    canonical_root: PathBuf,
    canonical_db_path: PathBuf,
    receipt_cache_dir: PathBuf,
    canonical_worker_cache: PathBuf,
    generation: String,
    owner: ProjectTransitionWorkerGrantOwner,
}

struct ProjectTransitionWorkerGrantOwner {
    pid: u32,
    process_start_utc_ticks: u64,
}

pub(crate) fn validate_index_worker_transition_grant(
    grant: Value,
    public_args: &Value,
    requested_worker_cache: &Path,
) -> Result<String, DynError> {
    let object = grant.as_object().ok_or_else(|| -> DynError {
        "ASTRO_PROJECT_TRANSITION_WORKER_GRANT_INVALID: the private writer grant is not a JSON object; remediation: preserve the worker request and inspect the parent transition builder".into()
    })?;
    let expected_keys = BTreeSet::from([
        "canonical_db_path",
        "canonical_root",
        "canonical_worker_cache",
        "generation",
        "owner",
        "project",
        "receipt_cache_dir",
        "schema",
    ]);
    let actual_keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_keys != expected_keys {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_GRANT_FIELDS: private writer grant fields are {actual_keys:?}, expected {expected_keys:?}; remediation: rebuild and activate one coherent Astrolabe generation"
        )
        .into());
    }
    let string_field = |name: &str| -> Result<String, DynError> {
        object
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                format!(
                    "ASTRO_PROJECT_TRANSITION_WORKER_GRANT_FIELD_INVALID: field {name:?} must be one non-empty UTF-8 string; remediation: preserve the worker request and inspect the parent grant builder"
                )
                .into()
            })
    };
    let owner = object
        .get("owner")
        .and_then(Value::as_object)
        .ok_or_else(|| -> DynError {
            "ASTRO_PROJECT_TRANSITION_WORKER_GRANT_OWNER_INVALID: grant owner is not an object; remediation: preserve the worker request and inspect the parent grant builder".into()
        })?;
    let owner_keys = owner.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_owner_keys = BTreeSet::from(["pid", "process_start_utc_ticks"]);
    if owner_keys != expected_owner_keys {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_GRANT_OWNER_FIELDS: grant owner fields are {owner_keys:?}, expected {expected_owner_keys:?}; remediation: rebuild and activate one coherent Astrolabe generation"
        )
        .into());
    }
    let owner_pid = owner
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| -> DynError {
            "ASTRO_PROJECT_TRANSITION_WORKER_GRANT_OWNER_PID_INVALID: grant owner PID must be one positive u32; remediation: preserve the worker request and inspect the parent grant builder".into()
        })?;
    let owner_process_start_utc_ticks = owner
        .get("process_start_utc_ticks")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| -> DynError {
            "ASTRO_PROJECT_TRANSITION_WORKER_GRANT_OWNER_TICKS_INVALID: grant owner creation ticks must be one positive u64; remediation: preserve the worker request and inspect the parent grant builder".into()
        })?;
    let grant = ProjectTransitionWorkerGrantEnvelope {
        schema: string_field("schema")?,
        project: string_field("project")?,
        canonical_root: PathBuf::from(string_field("canonical_root")?),
        canonical_db_path: PathBuf::from(string_field("canonical_db_path")?),
        receipt_cache_dir: PathBuf::from(string_field("receipt_cache_dir")?),
        canonical_worker_cache: PathBuf::from(string_field("canonical_worker_cache")?),
        generation: string_field("generation")?,
        owner: ProjectTransitionWorkerGrantOwner {
            pid: owner_pid,
            process_start_utc_ticks: owner_process_start_utc_ticks,
        },
    };
    if grant.schema != PROJECT_TRANSITION_WORKER_GRANT_SCHEMA {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_GRANT_SCHEMA: worker grant schema {:?} is not {:?}; remediation: rebuild and activate one coherent Astrolabe generation",
            grant.schema, PROJECT_TRANSITION_WORKER_GRANT_SCHEMA
        )
        .into());
    }

    let canonical_worker_cache = fs::canonicalize(requested_worker_cache).map_err(|error| {
        format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_CACHE_UNRESOLVED: canonicalizing worker cache {} failed: {error}; remediation: preserve the supervised request and its publication state",
            requested_worker_cache.display()
        )
    })?;
    if canonical_worker_cache != grant.canonical_worker_cache {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_CACHE_MISMATCH: worker resolved cache {} but the grant binds {}; remediation: preserve both paths and inspect the supervisor request",
            canonical_worker_cache.display(),
            grant.canonical_worker_cache.display()
        )
        .into());
    }

    let repo_path = public_args
        .as_object()
        .and_then(|object| object.get("repo_path"))
        .and_then(Value::as_str)
        .ok_or_else(|| -> DynError {
            "ASTRO_PROJECT_TRANSITION_WORKER_ROOT_MISSING: a granted writer requires one UTF-8 repo_path; remediation: preserve the worker request and inspect the parent argument sanitizer".into()
        })?;
    let canonical_root = fs::canonicalize(repo_path).map_err(|error| {
        format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_ROOT_UNRESOLVED: canonicalizing {repo_path:?} failed: {error}; remediation: keep the exact source root present for the complete supervised generation"
        )
    })?;
    if canonical_root != grant.canonical_root {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_ROOT_MISMATCH: worker resolved root {} but the grant binds {}; remediation: preserve both identities and inspect the parent request",
            canonical_root.display(),
            grant.canonical_root.display()
        )
        .into());
    }
    let derived_project = astrolabe_bridge::cbm_project_name_from_path(repo_path)?;
    if derived_project != grant.project {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_PROJECT_MISMATCH: worker derived project {derived_project:?} but the grant binds {:?}; remediation: preserve the request and inspect canonical project derivation",
            grant.project
        )
        .into());
    }
    let expected_db_path = sqlite_path(&grant.receipt_cache_dir, &grant.project);
    if expected_db_path != grant.canonical_db_path {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_DB_MISMATCH: grant database {} does not equal root-derived database {}; remediation: preserve the transition row and inspect cache identity",
            grant.canonical_db_path.display(),
            expected_db_path.display()
        )
        .into());
    }

    let key = metadata_key(&grant.project, PROJECT_TRANSITION_STATUS_KEY);
    let raw = read_config_value(&grant.receipt_cache_dir, &key)?.ok_or_else(|| -> DynError {
        format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_RECEIPT_MISSING: durable transition row {key:?} is absent; remediation: do not run the worker outside its parent-owned transition"
        )
        .into()
    })?;
    let receipt: Value = serde_json::from_str(&raw).map_err(|error| -> DynError {
        format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_RECEIPT_MALFORMED: durable transition row {key:?} is not JSON ({error}); remediation: preserve the config store and worker request"
        )
        .into()
    })?;
    let receipt_matches = receipt.get("schema").and_then(Value::as_str)
        == Some("astrolabe-project-transition-v1")
        && receipt.get("phase").and_then(Value::as_str) == Some("quiesced")
        && receipt.get("generation").and_then(Value::as_str) == Some(grant.generation.as_str())
        && receipt.get("project").and_then(Value::as_str) == Some(grant.project.as_str())
        && receipt.get("canonical_root") == Some(&json!(grant.canonical_root))
        && receipt.get("canonical_db_path") == Some(&json!(grant.canonical_db_path))
        && receipt.pointer("/owner/pid").and_then(Value::as_u64)
            == Some(u64::from(grant.owner.pid))
        && receipt
            .pointer("/owner/process_start_utc_ticks")
            .and_then(Value::as_u64)
            == Some(grant.owner.process_start_utc_ticks)
        && normalization_receipt_matches(&receipt);
    if !receipt_matches {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_RECEIPT_MISMATCH: durable transition row {key:?} does not equal the granted quiesced generation; remediation: preserve its bytes and refuse the worker"
        )
        .into());
    }

    let parent_pid = astrolabe_bridge::parent_process_id().ok_or_else(|| -> DynError {
        "ASTRO_PROJECT_TRANSITION_WORKER_PARENT_UNRESOLVED: the supervised worker could not resolve its immediate parent PID; remediation: inspect the process boundary before retrying".into()
    })?;
    if parent_pid != grant.owner.pid {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_PARENT_MISMATCH: immediate parent PID {parent_pid} does not equal granted owner PID {}; remediation: do not detach or relay a supervised index worker",
            grant.owner.pid
        )
        .into());
    }
    let parent_start = astrolabe_bridge::process_start_utc_ticks(parent_pid)?;
    if parent_start != grant.owner.process_start_utc_ticks {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_PARENT_GENERATION_MISMATCH: parent PID {parent_pid} creation ticks {parent_start} do not equal granted {}; remediation: refuse PID reuse and restart from one live parent transition",
            grant.owner.process_start_utc_ticks
        )
        .into());
    }

    Ok(grant.project)
}

fn normalization_receipt_matches(receipt: &Value) -> bool {
    let Some(normalization) = receipt.get("normalization") else {
        return false;
    };
    let holder_clear = normalization
        .pointer("/post_close_quiescence/holder_inventory_stable")
        .and_then(Value::as_bool)
        == Some(true)
        && normalization
            .pointer("/post_close_quiescence/holder_count")
            .and_then(Value::as_u64)
            == Some(0);
    match normalization.get("status").and_then(Value::as_str) {
        Some("absent") => {
            holder_clear
                && normalization
                    .pointer("/before/db/present")
                    .and_then(Value::as_bool)
                    == Some(false)
                && normalization
                    .pointer("/before/wal/present")
                    .and_then(Value::as_bool)
                    == Some(false)
                && normalization
                    .pointer("/before/shm/present")
                    .and_then(Value::as_bool)
                    == Some(false)
                && normalization.get("before") == normalization.get("after")
        }
        Some("normalized") => {
            holder_clear
                && normalization
                    .pointer("/native/journal_mode_after")
                    .and_then(Value::as_str)
                    == Some("delete")
                && normalization
                    .pointer("/native/wal_remaining_frames")
                    .and_then(Value::as_i64)
                    == Some(0)
                && normalization
                    .pointer("/native/close_connection_destroyed")
                    .and_then(Value::as_bool)
                    == Some(true)
                && normalization
                    .pointer("/after/db/present")
                    .and_then(Value::as_bool)
                    == Some(true)
                && normalization
                    .pointer("/after/wal/present")
                    .and_then(Value::as_bool)
                    == Some(false)
                && normalization
                    .pointer("/after/shm/present")
                    .and_then(Value::as_bool)
                    == Some(false)
        }
        _ => false,
    }
}

pub(crate) fn run_project_index_transition(
    runner: &CbmToolRunner,
    cache_dir: &Path,
    project: &str,
    repo_path: &Path,
    operation: impl FnOnce(&ProjectTransitionWorkerGrant) -> Result<String, DynError>,
) -> Result<String, DynError> {
    let mut transition = ProjectIndexTransition::begin(runner, cache_dir, project, repo_path)?;
    let grant = transition.worker_grant();
    // #976: the pre-operation family is read here, not reused from normalization,
    // so `family_before`/`family_after` bracket exactly the worker's window.
    let family_before = sqlite_family_evidence(&transition.db_path)?;
    let mut outcome = operation(&grant);
    // The durable record must describe the state the request actually left behind.
    // Reading the family only at `begin` published a pre-operation snapshot as if
    // it were terminal, which is how a failed generation could report the store
    // absent while a complete graph sat at the canonical path.
    let family_after = sqlite_family_evidence(&transition.db_path)
        .unwrap_or_else(|error| json!({"read_error": error.to_string()}));
    let mut invalid_response = None;
    let mut terminal = match outcome.as_ref() {
        Ok(response) => match tool_result_is_error(response) {
            Ok(is_error) => {
                let response_value: Value = serde_json::from_str(response)?;
                json!({
                    "status": if is_error { "failed" } else { "completed" },
                    "response_sha256": persisted_json_sha256(&response_value)?,
                    "response_hash_basis": PERSISTED_JSON_SHA256_BASIS,
                    "raw_response_sha256": hex_lower(&Sha256::digest(response.as_bytes())),
                })
            }
            Err(error) => {
                let message = format!(
                    "ASTRO_PROJECT_TRANSITION_RESPONSE_INVALID: the index generation returned malformed JSON: {error}; remediation: preserve the response and inspect the producing worker"
                );
                invalid_response = Some(message.clone());
                json!({
                    "status": "failed",
                    "error": message,
                    "raw_response_sha256": hex_lower(&Sha256::digest(response.as_bytes())),
                })
            }
        },
        Err(error) => json!({
            "status": "failed",
            "error": error.to_string(),
            "error_sha256": hex_lower(&Sha256::digest(error.to_string().as_bytes())),
        }),
    };
    let facts = outcome
        .as_ref()
        .ok()
        .map(|response| index_response_facts(response));
    if let Some(facts) = facts.as_ref() {
        terminal["sqlite_publication_started"] = json!(facts.publication_started);
        if let Some(bootstrap) = facts.artifact_bootstrap.as_ref() {
            terminal["artifact_bootstrap"] = bootstrap.clone();
        }
        if let Some(revert) = facts.artifact_bootstrap_revert.as_ref() {
            terminal["artifact_bootstrap_revert"] = revert.clone();
        }
    }
    terminal["family_before"] = family_before.clone();
    terminal["family_after"] = family_after.clone();

    // The conjunct this record exists to keep honest: a generation that states it
    // never began publishing, over a store that was absent when it started, must
    // leave that store absent. A present database there is *some other* graph —
    // a restored artifact, a partial write — being handed to every later query as
    // though this request had produced it. Refuse and preserve; never report the
    // failure alone and let the contradiction stand.
    let contradiction = facts.as_ref().is_some_and(|facts| {
        !facts.publication_started.unwrap_or(true)
            && family_before
                .pointer("/db/present")
                .and_then(Value::as_bool)
                == Some(false)
            && family_after.pointer("/db/present").and_then(Value::as_bool) == Some(true)
    });
    if contradiction {
        let message = format!(
            "ASTRO_PROJECT_TRANSITION_TERMINAL_STATE_CONTRADICTION: the {project:?} generation reported sqlite_publication_started=false over a store family that was absent before the request, yet {} is present afterwards; remediation: inspect the preserved database family and the preceding artifact.bootstrap_revert diagnostic — it is not a published generation of this request",
            transition.db_path.display()
        );
        terminal["status"] = json!("failed");
        terminal["terminal_state_contradiction"] = json!({
            "code": "ASTRO_PROJECT_TRANSITION_TERMINAL_STATE_CONTRADICTION",
            "message": &message,
            "family_before": family_before,
            "family_after": family_after,
        });
        invalid_response = Some(message);
    }
    if let Some(message) = invalid_response {
        outcome = Err(message.into());
    }
    transition.finish(terminal)?;
    outcome
}

/// The facts the transition record must carry from a worker's own response.
struct IndexResponseFacts {
    publication_started: Option<bool>,
    artifact_bootstrap: Option<Value>,
    artifact_bootstrap_revert: Option<Value>,
}

/// Read the worker's claims out of the MCP envelope (`content[0].text` holds the
/// tool's own JSON). Every field is optional on purpose: a response that omits
/// them yields `None`, and `None` never manufactures a contradiction — only an
/// explicit `sqlite_publication_started=false` can.
fn index_response_facts(response: &str) -> IndexResponseFacts {
    let inner = serde_json::from_str::<Value>(response)
        .ok()
        .and_then(|envelope| {
            envelope
                .pointer("/content/0/text")
                .and_then(Value::as_str)
                .and_then(|text| serde_json::from_str::<Value>(text).ok())
        });
    let Some(inner) = inner else {
        return IndexResponseFacts {
            publication_started: None,
            artifact_bootstrap: None,
            artifact_bootstrap_revert: None,
        };
    };
    IndexResponseFacts {
        publication_started: inner
            .get("sqlite_publication_started")
            .and_then(Value::as_bool),
        artifact_bootstrap: inner.get("artifact_bootstrap").cloned(),
        artifact_bootstrap_revert: inner.get("artifact_bootstrap_revert").cloned(),
    }
}

struct ProjectIndexTransition<'a> {
    native: Option<CbmProjectTransition>,
    cache_dir: &'a Path,
    project: String,
    root: PathBuf,
    db_path: PathBuf,
    generation: String,
    owner_pid: u32,
    owner_process_start_utc_ticks: u64,
    recovered_abandoned_owner: bool,
    acquired_unix_ms: u128,
    quiescence: CbmProjectQuiescence,
    normalization: Value,
    recovery: Value,
}

struct PriorTransitionInspection {
    durable_incomplete_transition: bool,
    recovery: Value,
}

impl<'a> ProjectIndexTransition<'a> {
    fn worker_grant(&self) -> ProjectTransitionWorkerGrant {
        ProjectTransitionWorkerGrant {
            schema: PROJECT_TRANSITION_WORKER_GRANT_SCHEMA.to_string(),
            project: self.project.clone(),
            canonical_root: self.root.clone(),
            canonical_db_path: self.db_path.clone(),
            receipt_cache_dir: self.cache_dir.to_path_buf(),
            generation: self.generation.clone(),
            owner_pid: self.owner_pid,
            owner_process_start_utc_ticks: self.owner_process_start_utc_ticks,
        }
    }

    fn begin(
        runner: &CbmToolRunner,
        cache_dir: &'a Path,
        project: &str,
        repo_path: &Path,
    ) -> Result<Self, DynError> {
        // #910: a repo_path that does not resolve is a *caller input* fault, not an
        // internal one. This used to be a bare formatted string, which carries no type,
        // so the MCP boundary had nothing to recognise and relabelled it
        // `ASTRO_MCP_HANDLER_INTERNAL` with a remediation about inspecting a persisted
        // store or lock -- state this request never touched, for a fault no retry can
        // clear. Carrying it as a `ToolFault` keeps the real code and the real
        // remediation as the fields the caller is contractually told to act on.
        let root = fs::canonicalize(repo_path).map_err(|error| {
            ToolFault::new(
                ASTRO_PROJECT_TRANSITION_ROOT_UNRESOLVED,
                format!("canonicalizing {} failed: {error}", repo_path.display()),
                "pass one existing canonical repository root",
            )
            .with_detail("argument", "repo_path")
            .with_detail("repo_path", repo_path.display().to_string())
        })?;
        runner.close_cached_project_store()?;
        let native = CbmProjectTransition::acquire(project)?;
        let owner_pid = std::process::id();
        let owner_process_start_utc_ticks = native.owner_process_start_utc_ticks;
        let kernel_mutex_abandoned = native.recovered_abandoned_owner;
        let acquired_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let generation = hex_lower(&Sha256::digest(
            format!(
                "astrolabe-project-transition-v1\0{project}\0{}\0{owner_pid}\0{owner_process_start_utc_ticks}\0{acquired_unix_ms}",
                root.display()
            )
            .as_bytes(),
        ));
        let db_path = sqlite_path(cache_dir, project);
        let prior =
            inspect_prior_transition(cache_dir, project, &root, &db_path, kernel_mutex_abandoned)?;
        let recovered_abandoned_owner =
            kernel_mutex_abandoned || prior.durable_incomplete_transition;
        let mut transition = Self {
            native: Some(native),
            cache_dir,
            project: project.to_string(),
            root,
            db_path,
            generation,
            owner_pid,
            owner_process_start_utc_ticks,
            recovered_abandoned_owner,
            acquired_unix_ms,
            quiescence: CbmProjectQuiescence {
                elapsed_ms: 0,
                attempts: 0,
                native_error: 0,
                failed_path: String::new(),
                holder_probe_status: 0,
                holder_probe_native_error: 0,
                holder_inventory_stable: false,
                holder_count: 0,
                first_holder_process_id: 0,
                first_holder_process_start_utc_ticks: 0,
                holder_probe_operation: String::new(),
                first_holder_path: String::new(),
            },
            normalization: json!({"status": "pending"}),
            recovery: prior.recovery,
        };
        transition.persist("active", json!({}))?;
        let db_path = transition.db_path.to_str().ok_or_else(|| -> DynError {
            format!(
                "ASTRO_PROJECT_TRANSITION_DB_PATH_NOT_UTF8: {} cannot cross the native quiescence boundary",
                transition.db_path.display()
            )
            .into()
        })?;
        match transition
            .native
            .as_ref()
            .expect("live project transition")
            .wait_store_quiescent(
                db_path,
                u32::try_from(PROJECT_TRANSITION_QUIESCENCE_TIMEOUT_MS)?,
                u32::try_from(WATCHER_DEFAULT_POLL_INTERVAL_MS)?,
            ) {
            Ok(quiescence) => transition.quiescence = quiescence,
            Err(error) => {
                let CbmProjectQuiescenceError { error, evidence } = error;
                transition.quiescence = *evidence;
                transition.persist("quiescence_failed", json!({"error": error.to_string()}))?;
                return Err(error.into());
            }
        }
        match transition.normalize_store_family() {
            Ok(normalization) => transition.normalization = normalization,
            Err(error) => {
                let error_text = error.to_string();
                transition.normalization = error
                    .as_ref()
                    .downcast_ref::<ProjectNormalizationEvidenceError>()
                    .map(|failure| failure.evidence.clone())
                    .unwrap_or_else(|| {
                        json!({
                            "status": "normalization_failed",
                            "error": &error_text,
                            "family_after_failure": sqlite_family_evidence(&transition.db_path)
                                .unwrap_or_else(|read_error| json!({"read_error": read_error.to_string()})),
                        })
                    });
                transition.persist("normalization_failed", json!({"error": &error_text}))?;
                return Err(error);
            }
        }
        transition.persist("quiesced", json!({}))?;
        Ok(transition)
    }

    fn normalize_store_family(&self) -> Result<Value, DynError> {
        let before = sqlite_family_evidence(&self.db_path)?;
        let db_present = before
            .pointer("/db/present")
            .and_then(Value::as_bool)
            .ok_or_else(|| -> DynError {
                "ASTRO_PROJECT_NORMALIZATION_DB_EVIDENCE_INVALID: DB presence is missing from the physical family readback".into()
            })?;
        let wal_present = before
            .pointer("/wal/present")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let shm_present = before
            .pointer("/shm/present")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !db_present {
            if wal_present || shm_present {
                return Err(format!(
                    "ASTRO_PROJECT_NORMALIZATION_ORPHAN_SIDECAR: DB is absent but WAL/SHM is present for {}; remediation: preserve the complete family and inspect the orphaned SQLite state",
                    self.db_path.display()
                )
                .into());
            }
            let post_quiescence = self.post_normalization_quiescence()?;
            let after = sqlite_family_evidence(&self.db_path)?;
            if after != before {
                return Err(format!(
                    "ASTRO_PROJECT_NORMALIZATION_ABSENT_DRIFT: absent family changed between independent readbacks for {}; remediation: preserve the observed paths and inspect the concurrent owner",
                    self.db_path.display()
                )
                .into());
            }
            return Ok(json!({
                "status": "absent",
                "before": before,
                "after": after,
                "post_close_quiescence": quiescence_json(&post_quiescence),
            }));
        }

        let db_path = self.db_path.to_str().ok_or_else(|| -> DynError {
            format!(
                "ASTRO_PROJECT_NORMALIZATION_DB_PATH_NOT_UTF8: {} cannot cross the native writer boundary",
                self.db_path.display()
            )
            .into()
        })?;
        let normalized = normalize_existing_project_store(db_path, &self.project)?;
        if normalized.journal_mode_after != "delete"
            || !normalized.close_connection_destroyed
            || normalized.wal_remaining_frames != 0
        {
            return Err(format!(
                "ASTRO_PROJECT_NORMALIZATION_RESULT_INVALID: native normalization returned after={:?}, close_destroyed={}, remaining_frames={}; remediation: preserve the family and repair the native normalization contract",
                normalized.journal_mode_after,
                normalized.close_connection_destroyed,
                normalized.wal_remaining_frames
            )
            .into());
        }
        let post_quiescence = self.post_normalization_quiescence()?;
        let after = sqlite_family_evidence(&self.db_path)?;
        let native = json!({
            "journal_mode_before": normalized.journal_mode_before,
            "journal_mode_after": normalized.journal_mode_after,
            "sqlite_error": normalized.sqlite_error,
            "wal_log_frames": normalized.wal_log_frames,
            "wal_checkpointed_frames": normalized.wal_checkpointed_frames,
            "wal_remaining_frames": normalized.wal_remaining_frames,
            "operation": normalized.operation,
            "detail": normalized.detail,
            "sqlite_owned_empty_wal_created": normalized.sqlite_owned_empty_wal_created,
            "close_connection_destroyed": normalized.close_connection_destroyed,
            "close_db_path": normalized.close_db_path,
        });
        let after_db = after.pointer("/db/present").and_then(Value::as_bool) == Some(true);
        let after_wal = after
            .pointer("/wal/present")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let after_shm = after
            .pointer("/shm/present")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !after_db || after_wal || after_shm {
            let message = format!(
                "ASTRO_PROJECT_NORMALIZATION_FAMILY_READBACK_FAILED: post-close family for {} has db_present={after_db}, wal_present={after_wal}, shm_present={after_shm}; remediation: preserve every byte and inspect the exact later SQLite owner",
                self.db_path.display()
            );
            let evidence = json!({
                "status": "normalization_failed",
                "stage": "post_close_family_readback",
                "error": &message,
                "before": before,
                "native": native,
                "post_close_quiescence": quiescence_json(&post_quiescence),
                "after": after,
            });
            return Err(Box::new(ProjectNormalizationEvidenceError {
                message,
                evidence,
            }));
        }
        Ok(json!({
            "status": "normalized",
            "before": before,
            "native": native,
            "after": after,
            "post_close_quiescence": quiescence_json(&post_quiescence),
        }))
    }

    fn post_normalization_quiescence(&self) -> Result<CbmProjectQuiescence, DynError> {
        let db_path = self.db_path.to_str().ok_or_else(|| -> DynError {
            format!(
                "ASTRO_PROJECT_NORMALIZATION_DB_PATH_NOT_UTF8: {} cannot cross the native quiescence boundary",
                self.db_path.display()
            )
            .into()
        })?;
        self.native
            .as_ref()
            .expect("live project transition")
            .wait_store_quiescent(
                db_path,
                u32::try_from(PROJECT_TRANSITION_QUIESCENCE_TIMEOUT_MS)?,
                u32::try_from(WATCHER_DEFAULT_POLL_INTERVAL_MS)?,
            )
            .map_err(|failure| failure.error.into())
    }

    fn finish(&mut self, terminal: Value) -> Result<(), DynError> {
        self.persist("terminal", terminal)?;
        self.native
            .take()
            .expect("live project transition")
            .release()?;
        Ok(())
    }

    fn persist(&self, phase: &str, evidence: Value) -> Result<(), DynError> {
        let value = serde_json::to_string(&json!({
            "schema": "astrolabe-project-transition-v1",
            "phase": phase,
            "generation": self.generation,
            "project": self.project,
            "canonical_root": self.root,
            "canonical_db_path": self.db_path,
            "owner": {
                "pid": self.owner_pid,
                "process_start_utc_ticks": self.owner_process_start_utc_ticks,
            },
            "acquired_unix_ms": self.acquired_unix_ms,
            "recovered_abandoned_owner": self.recovered_abandoned_owner,
            "recovery": self.recovery,
            "quiescence": {
                "elapsed_ms": self.quiescence.elapsed_ms,
                "attempts": self.quiescence.attempts,
                "native_error": self.quiescence.native_error,
                "failed_path": self.quiescence.failed_path,
                "holder_probe_status": self.quiescence.holder_probe_status,
                "holder_probe_native_error": self.quiescence.holder_probe_native_error,
                "holder_inventory_stable": self.quiescence.holder_inventory_stable,
                "holder_count": self.quiescence.holder_count,
                "first_holder_process_id": self.quiescence.first_holder_process_id,
                "first_holder_process_start_utc_ticks": self.quiescence.first_holder_process_start_utc_ticks,
                "holder_probe_operation": self.quiescence.holder_probe_operation,
                "first_holder_path": self.quiescence.first_holder_path,
            },
            "normalization": self.normalization,
            "evidence": evidence,
        }))?;
        let key = metadata_key(&self.project, PROJECT_TRANSITION_STATUS_KEY);
        write_config_value(self.cache_dir, &key, &value)?;
        let readback = read_config_value(self.cache_dir, &key)?;
        if readback.as_deref() != Some(value.as_str()) {
            return Err(format!(
                "ASTRO_PROJECT_TRANSITION_READBACK_MISMATCH: durable config row {key:?} did not equal the just-written {phase:?} receipt; remediation: preserve the config store and inspect its exact row before retrying"
            )
            .into());
        }
        Ok(())
    }
}

fn sqlite_family_member_path(db_path: &Path, suffix: &str) -> PathBuf {
    let mut value = db_path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn sqlite_member_evidence(path: &Path) -> Result<Value, DynError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "ASTRO_PROJECT_NORMALIZATION_MEMBER_TYPE_INVALID: {} is present but is not one ordinary file; remediation: preserve the path and resolve its exact filesystem identity",
                    path.display()
                )
                .into());
            }
            let bytes = metadata.len();
            let sha256 = sha256_file_hex(path)?;
            let readback = fs::symlink_metadata(path).map_err(|error| {
                format!(
                    "ASTRO_PROJECT_NORMALIZATION_MEMBER_READBACK_FAILED: re-reading {} failed after hashing: {error}; remediation: preserve the family and inspect the concurrent owner",
                    path.display()
                )
            })?;
            if !readback.file_type().is_file() || readback.len() != bytes {
                return Err(format!(
                    "ASTRO_PROJECT_NORMALIZATION_MEMBER_DRIFT: {} changed type or length while hashing; remediation: preserve the family and inspect the concurrent owner",
                    path.display()
                )
                .into());
            }
            Ok(json!({
                "path": path,
                "present": true,
                "bytes": bytes,
                "sha256": sha256,
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({
            "path": path,
            "present": false,
            "bytes": 0,
            "sha256": null,
        })),
        Err(error) => Err(format!(
            "ASTRO_PROJECT_NORMALIZATION_MEMBER_PROBE_FAILED: probing {} failed: {error}; remediation: preserve the family and resolve the filesystem error",
            path.display()
        )
        .into()),
    }
}

fn sqlite_family_evidence(db_path: &Path) -> Result<Value, DynError> {
    let wal_path = sqlite_family_member_path(db_path, "-wal");
    let shm_path = sqlite_family_member_path(db_path, "-shm");
    Ok(json!({
        "db": sqlite_member_evidence(db_path)?,
        "wal": sqlite_member_evidence(&wal_path)?,
        "shm": sqlite_member_evidence(&shm_path)?,
    }))
}

fn quiescence_json(value: &CbmProjectQuiescence) -> Value {
    json!({
        "elapsed_ms": value.elapsed_ms,
        "attempts": value.attempts,
        "native_error": value.native_error,
        "failed_path": value.failed_path,
        "holder_probe_status": value.holder_probe_status,
        "holder_probe_native_error": value.holder_probe_native_error,
        "holder_inventory_stable": value.holder_inventory_stable,
        "holder_count": value.holder_count,
        "first_holder_process_id": value.first_holder_process_id,
        "first_holder_process_start_utc_ticks": value.first_holder_process_start_utc_ticks,
        "holder_probe_operation": value.holder_probe_operation,
        "first_holder_path": value.first_holder_path,
    })
}

fn inspect_prior_transition(
    cache_dir: &Path,
    project: &str,
    canonical_root: &Path,
    canonical_db_path: &Path,
    kernel_mutex_abandoned: bool,
) -> Result<PriorTransitionInspection, DynError> {
    let key = metadata_key(project, PROJECT_TRANSITION_STATUS_KEY);
    let Some(raw) = read_config_value(cache_dir, &key)? else {
        return Ok(PriorTransitionInspection {
            durable_incomplete_transition: false,
            recovery: json!({
                "abandoned_owner": kernel_mutex_abandoned,
                "kernel_mutex_abandoned": kernel_mutex_abandoned,
                "durable_incomplete_transition": false,
                "prior_durable_state": "absent_before_first_publication",
            }),
        });
    };
    let value: Value = serde_json::from_str(&raw).map_err(|error| -> DynError {
        format!(
            "ASTRO_PROJECT_TRANSITION_RECOVERY_STATE_MALFORMED: prior transition row {key:?} is not JSON ({error}); remediation: preserve the row and store family for explicit inspection"
        )
        .into()
    })?;
    let schema_matches =
        value.get("schema").and_then(Value::as_str) == Some("astrolabe-project-transition-v1");
    let project_matches = value.get("project").and_then(Value::as_str) == Some(project);
    let root_matches = value.get("canonical_root") == Some(&json!(canonical_root));
    let db_matches = value.get("canonical_db_path") == Some(&json!(canonical_db_path));
    if !(schema_matches && project_matches && root_matches && db_matches) {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_RECOVERY_IDENTITY_MISMATCH: prior transition row {key:?} does not bind the exact schema/project/root/store identity; remediation: preserve its bytes and resolve the identity mismatch before retrying"
        )
        .into());
    }

    let phase = value
        .get("phase")
        .and_then(Value::as_str)
        .filter(|phase| {
            matches!(
                *phase,
                "active"
                    | "quiesced"
                    | "quiescence_failed"
                    | "normalization_failed"
                    | "terminal"
            )
        })
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_PROJECT_TRANSITION_RECOVERY_PHASE_INVALID: prior transition row {key:?} has no recognized phase; remediation: preserve the row and store family for explicit inspection"
            )
            .into()
        })?;
    let generation = value
        .get("generation")
        .and_then(Value::as_str)
        .filter(|generation| !generation.is_empty())
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_PROJECT_TRANSITION_RECOVERY_GENERATION_INVALID: prior transition row {key:?} has no non-empty generation; remediation: preserve the row and store family for explicit inspection"
            )
            .into()
        })?;
    let owner = value
        .get("owner")
        .and_then(Value::as_object)
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_PROJECT_TRANSITION_RECOVERY_OWNER_INVALID: prior transition row {key:?} has no owner object; remediation: preserve the row and store family for explicit inspection"
            )
            .into()
        })?;
    let owner_pid = owner
        .get("pid")
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_PROJECT_TRANSITION_RECOVERY_OWNER_PID_INVALID: prior transition row {key:?} has no positive u32 owner PID; remediation: preserve the row and store family for explicit inspection"
            )
            .into()
        })?;
    let owner_process_start_utc_ticks = owner
        .get("process_start_utc_ticks")
        .and_then(Value::as_u64)
        .filter(|ticks| *ticks > 0)
        .ok_or_else(|| -> DynError {
            format!(
                "ASTRO_PROJECT_TRANSITION_RECOVERY_OWNER_TICKS_INVALID: prior transition row {key:?} has no positive owner creation ticks; remediation: preserve the row and store family for explicit inspection"
            )
            .into()
        })?;
    let durable_incomplete_transition = matches!(phase, "active" | "quiesced");
    let abandoned_owner = kernel_mutex_abandoned || durable_incomplete_transition;

    Ok(PriorTransitionInspection {
        durable_incomplete_transition,
        recovery: json!({
            "abandoned_owner": abandoned_owner,
            "kernel_mutex_abandoned": kernel_mutex_abandoned,
            "durable_incomplete_transition": durable_incomplete_transition,
            "prior_durable_state": "inspected",
            "prior_row_sha256": hex_lower(&Sha256::digest(raw.as_bytes())),
            "prior_generation": generation,
            "prior_phase": phase,
            "prior_owner": {
                "pid": owner_pid,
                "process_start_utc_ticks": owner_process_start_utc_ticks,
            },
        }),
    })
}
