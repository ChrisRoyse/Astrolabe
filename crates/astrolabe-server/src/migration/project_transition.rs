use super::*;

use astrolabe_bridge::{CbmProjectQuiescence, CbmProjectTransition};
use astrolabe_domain::knobs::{
    PROJECT_TRANSITION_QUIESCENCE_TIMEOUT_MS, WATCHER_DEFAULT_POLL_INTERVAL_MS,
};

pub(crate) const PROJECT_TRANSITION_STATUS_KEY: &str = "project_transition_json";

pub(crate) fn run_project_index_transition(
    runner: &CbmToolRunner,
    cache_dir: &Path,
    project: &str,
    repo_path: &Path,
    operation: impl FnOnce() -> Result<String, DynError>,
) -> Result<String, DynError> {
    let mut transition = ProjectIndexTransition::begin(runner, cache_dir, project, repo_path)?;
    let mut outcome = operation();
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

impl<'a> ProjectIndexTransition<'a> {
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
        let recovered_abandoned_owner = native.recovered_abandoned_owner;
        let acquired_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let generation = hex_lower(&Sha256::digest(
            format!(
                "astrolabe-project-transition-v1\0{project}\0{}\0{owner_pid}\0{owner_process_start_utc_ticks}\0{acquired_unix_ms}",
                root.display()
            )
            .as_bytes(),
        ));
        let db_path = sqlite_path(cache_dir, project);
        let recovery = if recovered_abandoned_owner {
            inspect_abandoned_transition(cache_dir, project, &root, &db_path)?
        } else {
            json!({"abandoned_owner": false})
        };
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
            recovery,
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

fn inspect_abandoned_transition(
    cache_dir: &Path,
    project: &str,
    canonical_root: &Path,
    canonical_db_path: &Path,
) -> Result<Value, DynError> {
    let key = metadata_key(project, PROJECT_TRANSITION_STATUS_KEY);
    let Some(raw) = read_config_value(cache_dir, &key)? else {
        return Ok(json!({
            "abandoned_owner": true,
            "prior_durable_state": "absent_before_first_publication",
        }));
    };
    let value: Value = serde_json::from_str(&raw).map_err(|error| -> DynError {
        format!(
            "ASTRO_PROJECT_TRANSITION_RECOVERY_STATE_MALFORMED: abandoned owner row {key:?} is not JSON ({error}); remediation: preserve the row and store family for explicit inspection"
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
            "ASTRO_PROJECT_TRANSITION_RECOVERY_IDENTITY_MISMATCH: abandoned owner row {key:?} does not bind the exact schema/project/root/store identity; remediation: preserve its bytes and resolve the identity mismatch before retrying"
        )
        .into());
    }
    Ok(json!({
        "abandoned_owner": true,
        "prior_durable_state": "inspected",
        "prior_row_sha256": hex_lower(&Sha256::digest(raw.as_bytes())),
        "prior_generation": value.get("generation"),
        "prior_phase": value.get("phase"),
        "prior_owner": value.get("owner"),
    }))
}
