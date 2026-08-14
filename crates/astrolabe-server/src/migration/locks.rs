use super::*;
pub(crate) const SHADOW_IMPORT_LOCK_SUFFIX: &str = ".astrolabe-shadow-import.lock";
pub(crate) const BACKGROUND_LANE_LOCK_SUFFIX: &str = ".astrolabe-background-lane.lock";
pub(crate) const VERIFY_CHAIN_LANE_LOCK_NAME: &str = ".astrolabe-verify-chain-lane.lock";
pub(crate) const VERIFY_CHAIN_STARTUP_BARRIER_LOCK_NAME: &str =
    ".astrolabe-verify-chain-startup-barrier.lock";
pub(crate) const LOWERED_SQLITE_LOCK_SUFFIX: &str = ".astrolabe-lowered.lock";
pub(crate) const LOWERED_SQLITE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const LOWERED_SQLITE_LOCK_POLL: Duration = Duration::from_millis(25);

#[derive(Debug)]
pub(crate) struct ShadowImportLock {
    _guard: fs::File,
    path: PathBuf,
}

#[derive(Debug)]
pub(crate) struct LoweredSqliteLock {
    pub(crate) _guard: fs::File,
    pub(crate) path: PathBuf,
}

#[derive(Debug)]
pub(crate) struct BackgroundLaneOwner {
    pub(crate) _file: fs::File,
    pub(crate) _path: PathBuf,
    pub(crate) activation_identity: Option<crate::activation_epoch::ActivationIdentity>,
    pub(crate) owner_fields: Value,
}

/// Exact cache-wide owner of the startup/periodic verify-chain lane (#1123).
///
/// The retained lane lock is the lifetime authority. The startup barrier is
/// acquired before the lane so a follower cannot observe readiness until the
/// elected owner has durably published one terminal startup state.
#[derive(Debug)]
pub(crate) struct VerifyChainLaneOwner {
    _file: fs::File,
    startup_barrier_file: Option<fs::File>,
    pub(crate) path: PathBuf,
    pub(crate) pid: u32,
    pub(crate) process_start_utc_ticks: u64,
}

impl VerifyChainLaneOwner {
    pub(crate) fn identity_json(&self) -> Value {
        json!({
            "pid": self.pid,
            "process_start_utc_ticks": self.process_start_utc_ticks,
        })
    }

    pub(crate) fn release_startup_barrier(&mut self) -> Result<(), DynError> {
        let barrier = self
            .startup_barrier_file
            .as_ref()
            .ok_or_else(|| -> DynError {
                "ASTRO_VERIFY_CHAIN_STARTUP_BARRIER_ALREADY_RELEASED: the elected owner no longer holds its startup barrier. Remediation: preserve the lane/readiness state and repair the duplicate terminal-publication path."
                    .into()
            })?;
        barrier.unlock().map_err(|error| -> DynError {
            format!(
                "ASTRO_VERIFY_CHAIN_STARTUP_BARRIER_RELEASE_FAILED: elected owner \
                 ({},{}) could not release the terminal-readiness barrier: {error}. \
                 Remediation: preserve the owner and readiness bytes and restart only after \
                 diagnosing the exact filesystem failure.",
                self.pid, self.process_start_utc_ticks,
            )
            .into()
        })?;
        self.startup_barrier_file = None;
        Ok(())
    }
}

impl Drop for ShadowImportLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = self._guard.unlock();
    }
}

impl ShadowImportLock {
    /// Proves that this live token owns the exact project import lane requested by
    /// a caller that is about to mutate the shadow vault. The token is constructed
    /// only after the sidecar lock is acquired; matching the bound marker path and
    /// its exact owner record prevents a different project's token from being
    /// reused as ambient authority.
    pub(crate) fn assert_owns(&self, cache_dir: &Path, project: &str) -> Result<(), DynError> {
        let expected_path = shadow_import_lock_path(cache_dir, project);
        if self.path != expected_path {
            return Err(format!(
                "ASTRO_SHADOW_IMPORT_OWNER_MISMATCH: retained import ownership is bound to {}, not the required project lock {}; remediation: preserve both project generations and retry only under the exact project's acquired import token",
                self.path.display(),
                expected_path.display(),
            )
            .into());
        }

        let expected_marker = format!("pid={}\n", std::process::id());
        let marker = fs::read_to_string(&expected_path).map_err(|error| -> DynError {
            format!(
                "ASTRO_SHADOW_IMPORT_OWNER_MARKER_UNREADABLE: retained ownership for project {project:?} cannot read its marker {}: {error}; remediation: preserve the project generation and inspect the exact marker/guard pair before retrying",
                expected_path.display(),
            )
            .into()
        })?;
        if marker != expected_marker {
            return Err(format!(
                "ASTRO_SHADOW_IMPORT_OWNER_MARKER_MISMATCH: retained ownership for project {project:?} expected marker {expected_marker:?} at {}, observed {marker:?}; remediation: preserve the project generation and inspect the exact marker/guard pair before retrying",
                expected_path.display(),
            )
            .into());
        }
        Ok(())
    }
}

impl Drop for LoweredSqliteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = self._guard.unlock();
    }
}

pub(crate) fn shadow_import_lock_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{SHADOW_IMPORT_LOCK_SUFFIX}"))
}

pub(crate) fn try_shadow_import_lock(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<ShadowImportLock>, DynError> {
    fs::create_dir_all(cache_dir)?;
    let lock_path = shadow_import_lock_path(cache_dir, project);
    Ok(
        try_readable_marker_lock(&lock_path)?.map(|guard| ShadowImportLock {
            _guard: guard,
            path: lock_path,
        }),
    )
}

pub(crate) fn try_readable_marker_lock(marker_path: &Path) -> Result<Option<fs::File>, DynError> {
    let guard_path = marker_path.with_extension("lock.guard");
    let guard = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(guard_path)?;
    match guard.try_lock() {
        Ok(()) => {
            // Windows refuses reads of an exclusively locked file, so the marker
            // carries observable ownership metadata while the sidecar owns the lock.
            let mut marker = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(marker_path)?;
            writeln!(marker, "pid={}", std::process::id())?;
            marker.sync_all()?;
            Ok(Some(guard))
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Attempts to elect this exact process generation as the one cache-wide
/// verify-chain owner. Contention is an ordinary follower observation, not an
/// error and never authorizes duplicate verification work.
///
/// Cost is O(1): one exact lock-file open/try-lock and, only for the winner, one
/// process-generation probe plus a bounded owner-record rewrite. The production
/// ledger/project cardinality is deliberately absent from this election path
/// (#1064 PC-03/PC-07/PC-13/PC-32; #1123).
pub(crate) fn try_verify_chain_lane_owner_at(
    cache_dir: &Path,
) -> Result<Option<VerifyChainLaneOwner>, DynError> {
    let _activation_fence =
        crate::activation_epoch::require_active_generation("verify_chain_lane_acquire")?;
    fs::create_dir_all(cache_dir)?;
    let startup_barrier_path = cache_dir.join(VERIFY_CHAIN_STARTUP_BARRIER_LOCK_NAME);
    let startup_barrier_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&startup_barrier_path)?;
    match startup_barrier_file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
        Err(error) => {
            return Err(format!(
                "ASTRO_VERIFY_CHAIN_STARTUP_BARRIER_LOCK_FAILED: acquiring startup barrier {} \
                 failed: {error}. Remediation: preserve the barrier, lane lock, and config \
                 database; inspect the exact filesystem failure and restart without bypassing \
                 startup serialization.",
                startup_barrier_path.display(),
            )
            .into());
        }
    }
    let path = cache_dir.join(VERIFY_CHAIN_LANE_LOCK_NAME);
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    match file.try_lock() {
        Ok(()) => {
            crate::activation_epoch::verify_activation_fence(
                _activation_fence.as_ref(),
                "verify_chain_lane_owner_publish",
            )?;
            let pid = std::process::id();
            let process_start_utc_ticks =
                astrolabe_bridge::process_start_utc_ticks(pid).map_err(|error| -> DynError {
                    format!(
                        "ASTRO_VERIFY_CHAIN_OWNER_IDENTITY_UNAVAILABLE: exact creation ticks for \
                         cache-wide verify-chain owner PID {pid} could not be read: {error}. \
                         Remediation: preserve the config database and lane lock, repair native \
                         process-query access, and restart; never publish PID-only ownership."
                    )
                    .into()
                })?;
            file.set_len(0)?;
            writeln!(
                file,
                "{}",
                serde_json::to_string(&json!({
                    "schema": "astrolabe.verify-chain-lane-owner.v1",
                    "pid": pid,
                    "process_start_utc_ticks": process_start_utc_ticks,
                }))?
            )?;
            file.sync_all()?;
            Ok(Some(VerifyChainLaneOwner {
                _file: file,
                startup_barrier_file: Some(startup_barrier_file),
                path,
                pid,
                process_start_utc_ticks,
            }))
        }
        Err(std::fs::TryLockError::WouldBlock) => {
            startup_barrier_file.unlock()?;
            Ok(None)
        }
        Err(error) => Err(format!(
            "ASTRO_VERIFY_CHAIN_LANE_LOCK_FAILED: acquiring cache-wide verify-chain lane {} \
             failed: {error}. Remediation: preserve the lock and config database, inspect the \
             exact filesystem failure, and restart without bypassing the lane.",
            path.display(),
        )
        .into()),
    }
}

/// Waits for the elected owner to publish a terminal startup row, then releases
/// the barrier immediately. The wait count is independent of project/ledger N:
/// each follower crosses the barrier once and performs one readiness read
/// (#1064 PC-03/PC-07/PC-13/PC-32; #1123).
pub(crate) fn wait_verify_chain_startup_barrier_at(cache_dir: &Path) -> Result<(), DynError> {
    let activation_fence =
        crate::activation_epoch::require_active_generation("verify_chain_startup_barrier_wait")?;
    fs::create_dir_all(cache_dir)?;
    let path = cache_dir.join(VERIFY_CHAIN_STARTUP_BARRIER_LOCK_NAME);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    file.lock().map_err(|error| -> DynError {
        format!(
            "ASTRO_VERIFY_CHAIN_STARTUP_BARRIER_WAIT_FAILED: waiting for elected-owner terminal \
             publication at {} failed: {error}. Remediation: preserve the barrier/lane/config \
             state and repair the exact filesystem failure without admitting foreground work.",
            path.display(),
        )
        .into()
    })?;
    crate::activation_epoch::verify_activation_fence(
        activation_fence.as_ref(),
        "verify_chain_startup_barrier_observed",
    )?;
    file.unlock().map_err(|error| -> DynError {
        format!(
            "ASTRO_VERIFY_CHAIN_STARTUP_BARRIER_OBSERVER_RELEASE_FAILED: follower could not \
             release observed startup barrier {}: {error}. Remediation: preserve state and \
             repair the exact filesystem failure before restarting.",
            path.display(),
        )
        .into()
    })?;
    Ok(())
}

pub(crate) fn background_lane_owners() -> &'static Mutex<BTreeMap<String, BackgroundLaneOwner>> {
    static OWNERS: OnceLock<Mutex<BTreeMap<String, BackgroundLaneOwner>>> = OnceLock::new();
    OWNERS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn background_lane_status_at(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let lock_path = background_lane_lock_path(cache_dir, project);
    let lock_key = lock_path.to_string_lossy().into_owned();
    let owners = background_lane_owners()
        .lock()
        .map_err(|_| "background lane owner registry poisoned")?;
    if let Some(owner) = owners.get(&lock_key) {
        return background_lane_owner_summary(&lock_path, &owner.owner_fields);
    }
    drop(owners);

    let metadata = match fs::symlink_metadata(&lock_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return background_lane_available_summary(&lock_path);
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "ASTRO_BACKGROUND_LANE_LOCK_TYPE_INVALID: {} is not one ordinary file; remediation: preserve the entry and repair the exact project lane before background work resumes",
            lock_path.display()
        )
        .into());
    }
    let lock = OpenOptions::new().read(true).write(true).open(&lock_path)?;
    match lock.try_lock() {
        Ok(()) => {
            lock.unlock()?;
            background_lane_available_summary(&lock_path)
        }
        Err(std::fs::TryLockError::WouldBlock) => background_lane_follower_summary(&lock_path),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn acquire_background_lane_status_at(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let fence = crate::activation_epoch::require_active_generation("background_lane_acquire")?;
    fs::create_dir_all(cache_dir)?;
    let lock_path = background_lane_lock_path(cache_dir, project);
    let lock_key = lock_path.to_string_lossy().into_owned();
    let mut owners = background_lane_owners()
        .lock()
        .map_err(|_| "background lane owner registry poisoned")?;
    let fence_identity = fence.as_ref().map(|value| value.identity());
    if let Some(owner) = owners.get(&lock_key) {
        if owner.activation_identity == fence_identity {
            return background_lane_owner_summary(&lock_path, &owner.owner_fields);
        }
        owners.remove(&lock_key);
    }

    let mut lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    match lock.try_lock() {
        Ok(()) => {
            crate::activation_epoch::verify_activation_fence(
                fence.as_ref(),
                "background_lane_owner_publish",
            )?;
            let owner_fields = crate::activation_epoch::installed_owner_fields()?;
            lock.set_len(0)?;
            writeln!(
                lock,
                "{}",
                serde_json::to_string(&json!({
                    "schema": "astrolabe-background-lane-v2",
                    "project": project,
                    "pid": std::process::id(),
                    "owner": owner_fields,
                }))?
            )?;
            lock.sync_all()?;
            owners.insert(
                lock_key,
                BackgroundLaneOwner {
                    _file: lock,
                    _path: lock_path.clone(),
                    activation_identity: fence_identity,
                    owner_fields: owner_fields.clone(),
                },
            );
            background_lane_owner_summary(&lock_path, &owner_fields)
        }
        Err(std::fs::TryLockError::WouldBlock) => background_lane_follower_summary(&lock_path),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn release_background_lane_ownerships() -> Result<usize, DynError> {
    let mut owners = background_lane_owners()
        .lock()
        .map_err(|_| "background lane owner registry poisoned")?;
    let released = owners.len();
    owners.clear();
    Ok(released)
}

pub(crate) fn release_background_lane_ownership_at(
    cache_dir: &Path,
    project: &str,
) -> Result<bool, DynError> {
    let lock_key = background_lane_lock_path(cache_dir, project)
        .to_string_lossy()
        .into_owned();
    let mut owners = background_lane_owners()
        .lock()
        .map_err(|_| "background lane owner registry poisoned")?;
    Ok(owners.remove(&lock_key).is_some())
}

pub(crate) fn background_lane_lock_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{BACKGROUND_LANE_LOCK_SUFFIX}"))
}

pub(crate) fn background_lane_owner_summary(
    lock_path: &Path,
    owner_fields: &Value,
) -> Result<Value, DynError> {
    background_lane_summary(
        "owner",
        "this-process",
        "fresh",
        "verified",
        lock_path,
        true,
        Some(owner_fields),
    )
}

pub(crate) fn background_lane_follower_summary(lock_path: &Path) -> Result<Value, DynError> {
    background_lane_summary(
        "follower",
        "another-process",
        "stale_ok",
        "provisional",
        lock_path,
        false,
        None,
    )
}

pub(crate) fn background_lane_available_summary(lock_path: &Path) -> Result<Value, DynError> {
    background_lane_summary(
        "available",
        "none",
        "fresh",
        "verified",
        lock_path,
        false,
        None,
    )
}

pub(crate) fn background_lane_summary(
    status: &str,
    owner: &str,
    freshness: &str,
    trust: &str,
    lock_path: &Path,
    eligible_owner: bool,
    owner_fields: Option<&Value>,
) -> Result<Value, DynError> {
    Ok(json!({
        "schema": "astrolabe-background-lane-v2",
        "status": status,
        "owner": owner,
        "pid": if eligible_owner {
            Value::from(u64::from(std::process::id()))
        } else {
            Value::Null
        },
        "lock_path": lock_path,
        "freshness": freshness,
        "trust": trust,
        "single_owner": eligible_owner,
        "owner_identity": owner_fields,
        "activation": crate::activation_epoch::activation_status_json()?,
        "remediation": if eligible_owner {
            Value::Null
        } else {
            Value::String("use the elected owner process for vault-backed background work, or stop that process and retry".to_string())
        },
        "lanes": {
            "watcher": background_lane_worker_summary(eligible_owner),
            "anneal": background_lane_worker_summary(eligible_owner),
        },
    }))
}

pub(crate) fn background_lane_worker_summary(eligible_owner: bool) -> Value {
    json!({
        "eligible_owner": eligible_owner,
        "active": false,
        "activation": "not_enabled_in_shadow_stage",
        "trust": "verified",
    })
}

pub(crate) fn with_lowered_sqlite_lock<T>(
    cache_dir: &Path,
    project: &str,
    work: impl FnOnce() -> Result<T, DynError>,
) -> Result<T, DynError> {
    let started = Instant::now();
    loop {
        if let Some(_lock) = try_lowered_sqlite_lock(cache_dir, project)? {
            return work();
        }
        if started.elapsed() >= LOWERED_SQLITE_LOCK_TIMEOUT {
            return Err(format!(
                "timed out waiting for lowered SQLite lock: {}",
                lowered_sqlite_lock_path(cache_dir, project).display()
            )
            .into());
        }
        thread::sleep(LOWERED_SQLITE_LOCK_POLL);
    }
}

pub(crate) fn try_lowered_sqlite_lock(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<LoweredSqliteLock>, DynError> {
    fs::create_dir_all(cache_dir)?;
    let lock_path = lowered_sqlite_lock_path(cache_dir, project);
    Ok(
        try_readable_marker_lock(&lock_path)?.map(|guard| LoweredSqliteLock {
            _guard: guard,
            path: lock_path,
        }),
    )
}

pub(crate) fn lowered_sqlite_lock_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{LOWERED_SQLITE_LOCK_SUFFIX}"))
}
