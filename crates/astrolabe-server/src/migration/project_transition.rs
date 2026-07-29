use super::*;

use astrolabe_bridge::{CbmProjectQuiescence, CbmProjectTransition};
use astrolabe_domain::knobs::{
    PROJECT_TRANSITION_QUIESCENCE_TIMEOUT_MS, WATCHER_DEFAULT_POLL_INTERVAL_MS,
};

pub(crate) const PROJECT_TRANSITION_STATUS_KEY: &str = "project_transition_json";
const PROJECT_TRANSITION_WORKER_GRANT_SCHEMA: &str = "astrolabe-project-transition-worker-grant-v1";

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
    pub(crate) fn for_stage(&self, stage_cache: &Path) -> Result<Value, DynError> {
        let canonical_stage_cache = fs::canonicalize(stage_cache).map_err(|error| {
            format!(
                "ASTRO_PROJECT_TRANSITION_STAGE_UNRESOLVED: canonicalizing worker stage {} failed: {error}; remediation: preserve the shadow publication and inspect its exact stage directory",
                stage_cache.display()
            )
        })?;
        Ok(json!({
            "schema": self.schema,
            "project": self.project,
            "canonical_root": self.canonical_root,
            "canonical_db_path": self.canonical_db_path,
            "receipt_cache_dir": self.receipt_cache_dir,
            "canonical_stage_cache": canonical_stage_cache,
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
    canonical_stage_cache: PathBuf,
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
    requested_stage_cache: &Path,
) -> Result<String, DynError> {
    let object = grant.as_object().ok_or_else(|| -> DynError {
        "ASTRO_PROJECT_TRANSITION_WORKER_GRANT_INVALID: the private writer grant is not a JSON object; remediation: preserve the worker request and inspect the parent transition builder".into()
    })?;
    let expected_keys = BTreeSet::from([
        "canonical_db_path",
        "canonical_root",
        "canonical_stage_cache",
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
        canonical_stage_cache: PathBuf::from(string_field("canonical_stage_cache")?),
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

    let canonical_stage_cache = fs::canonicalize(requested_stage_cache).map_err(|error| {
        format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_STAGE_UNRESOLVED: canonicalizing worker stage {} failed: {error}; remediation: preserve the supervised request and shadow publication stage",
            requested_stage_cache.display()
        )
    })?;
    if canonical_stage_cache != grant.canonical_stage_cache {
        return Err(format!(
            "ASTRO_PROJECT_TRANSITION_WORKER_STAGE_MISMATCH: worker resolved stage {} but the grant binds {}; remediation: preserve both paths and inspect the supervisor request",
            canonical_stage_cache.display(),
            grant.canonical_stage_cache.display()
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
            == Some(grant.owner.process_start_utc_ticks);
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

pub(crate) fn run_project_index_transition(
    runner: &CbmToolRunner,
    cache_dir: &Path,
    project: &str,
    repo_path: &Path,
    operation: impl FnOnce(&ProjectTransitionWorkerGrant) -> Result<String, DynError>,
) -> Result<String, DynError> {
    let mut transition = ProjectIndexTransition::begin(runner, cache_dir, project, repo_path)?;
    let grant = transition.worker_grant();
    let mut outcome = operation(&grant);
    let mut invalid_response = None;
    let terminal = match outcome.as_ref() {
        Ok(response) => match tool_result_is_error(response) {
            Ok(is_error) => json!({
                "status": if is_error { "failed" } else { "completed" },
                "response_sha256": hex_lower(&Sha256::digest(response.as_bytes())),
            }),
            Err(error) => {
                let message = format!(
                    "ASTRO_PROJECT_TRANSITION_RESPONSE_INVALID: the index generation returned malformed JSON: {error}; remediation: preserve the response and inspect the producing worker"
                );
                invalid_response = Some(message.clone());
                json!({
                    "status": "failed",
                    "error": message,
                    "response_sha256": hex_lower(&Sha256::digest(response.as_bytes())),
                })
            }
        },
        Err(error) => json!({
            "status": "failed",
            "error": error.to_string(),
            "error_sha256": hex_lower(&Sha256::digest(error.to_string().as_bytes())),
        }),
    };
    if let Some(message) = invalid_response {
        outcome = Err(message.into());
    }
    transition.finish(terminal)?;
    outcome
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
        let root = fs::canonicalize(repo_path).map_err(|error| {
            format!(
                "ASTRO_PROJECT_TRANSITION_ROOT_UNRESOLVED: canonicalizing {} failed: {error}; remediation: pass one existing canonical repository root",
                repo_path.display()
            )
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
            },
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
                transition.persist("quiescence_failed", json!({"error": error.to_string()}))?;
                return Err(error.into());
            }
        }
        transition.persist("quiesced", json!({}))?;
        Ok(transition)
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
            },
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
                "active" | "quiesced" | "quiescence_failed" | "terminal"
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
