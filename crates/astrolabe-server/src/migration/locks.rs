use super::*;
pub(crate) const SHADOW_IMPORT_LOCK_SUFFIX: &str = ".astrolabe-shadow-import.lock";
pub(crate) const BACKGROUND_LANE_LOCK_SUFFIX: &str = ".astrolabe-background-lane.lock";
pub(crate) const LOWERED_SQLITE_LOCK_SUFFIX: &str = ".astrolabe-lowered.lock";
pub(crate) const LOWERED_SQLITE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const LOWERED_SQLITE_LOCK_POLL: Duration = Duration::from_millis(25);

#[derive(Debug)]
pub(crate) struct ShadowImportLock {
    pub(crate) _guard: fs::File,
    pub(crate) path: PathBuf,
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
}

impl Drop for ShadowImportLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = self._guard.unlock();
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

pub(crate) fn background_lane_owners() -> &'static Mutex<BTreeMap<String, BackgroundLaneOwner>> {
    static OWNERS: OnceLock<Mutex<BTreeMap<String, BackgroundLaneOwner>>> = OnceLock::new();
    OWNERS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn background_lane_status_at(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    fs::create_dir_all(cache_dir)?;
    let lock_path = background_lane_lock_path(cache_dir, project);
    let lock_key = lock_path.to_string_lossy().into_owned();
    let mut owners = background_lane_owners()
        .lock()
        .map_err(|_| "background lane owner registry poisoned")?;
    if owners.contains_key(&lock_key) {
        return Ok(background_lane_owner_summary(&lock_path));
    }

    let mut lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    match lock.try_lock() {
        Ok(()) => {
            lock.set_len(0)?;
            writeln!(lock, "schema=astrolabe-background-lane-v1")?;
            writeln!(lock, "project={project}")?;
            writeln!(lock, "pid={}", std::process::id())?;
            lock.sync_all()?;
            owners.insert(
                lock_key,
                BackgroundLaneOwner {
                    _file: lock,
                    _path: lock_path.clone(),
                },
            );
            Ok(background_lane_owner_summary(&lock_path))
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(background_lane_follower_summary(&lock_path)),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn background_lane_lock_path(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{BACKGROUND_LANE_LOCK_SUFFIX}"))
}

pub(crate) fn background_lane_owner_summary(lock_path: &Path) -> Value {
    background_lane_summary(
        "owner",
        "this-process",
        "fresh",
        "verified",
        lock_path,
        true,
    )
}

pub(crate) fn background_lane_follower_summary(lock_path: &Path) -> Value {
    background_lane_summary(
        "follower",
        "another-process",
        "stale_ok",
        "provisional",
        lock_path,
        false,
    )
}

pub(crate) fn background_lane_summary(
    status: &str,
    owner: &str,
    freshness: &str,
    trust: &str,
    lock_path: &Path,
    eligible_owner: bool,
) -> Value {
    json!({
        "schema": "astrolabe-background-lane-v1",
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
        "remediation": if eligible_owner {
            Value::Null
        } else {
            Value::String("use the elected owner process for vault-backed background work, or stop that process and retry".to_string())
        },
        "lanes": {
            "watcher": background_lane_worker_summary(eligible_owner),
            "anneal": background_lane_worker_summary(eligible_owner),
        },
    })
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
