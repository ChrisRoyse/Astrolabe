use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::error::{CliError, CliResult};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
static PROCESS_MUTATION_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, &'static Mutex<()>>>> =
    OnceLock::new();
const MAX_TEMP_CREATE_ATTEMPTS: usize = 1_024;

pub(crate) struct DurableMutationLock {
    _process_guard: MutexGuard<'static, ()>,
    _file: File,
}

impl DurableMutationLock {
    pub(crate) fn acquire(lock_path: &Path, operation: &str, subject: &Path) -> CliResult<Self> {
        let key = canonical_lock_key(lock_path)?;
        let process_mutex = durable_process_mutex(&key)?;
        let process_guard = process_mutex
            .lock()
            .map_err(|_| CliError::runtime("durable mutation process mutex poisoned"))?;
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&key)
            .map_err(|error| {
                CliError::io(format!(
                    "open durable mutation lock {} failed: {error}",
                    key.display()
                ))
            })?;
        file.lock().map_err(|error| {
            CliError::runtime(format!(
                "acquire durable mutation lock {} failed: {error}",
                key.display()
            ))
        })?;
        let record = serde_json::json!({
            "pid": std::process::id(),
            "started_unix_ms": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| CliError::runtime(format!("system clock precedes Unix epoch: {error}")))?
                .as_millis(),
            "operation": operation,
            "subject": subject,
        });
        let bytes = serde_json::to_vec(&record).map_err(|error| {
            CliError::runtime(format!("serialize mutation lock owner: {error}"))
        })?;
        file.set_len(0).map_err(|error| {
            CliError::io(format!(
                "truncate durable mutation lock {} failed: {error}",
                key.display()
            ))
        })?;
        file.seek(SeekFrom::Start(0)).map_err(|error| {
            CliError::io(format!(
                "seek durable mutation lock {} failed: {error}",
                key.display()
            ))
        })?;
        file.write_all(&bytes).map_err(|error| {
            CliError::io(format!(
                "write durable mutation lock {} failed: {error}",
                key.display()
            ))
        })?;
        file.sync_all().map_err(|error| {
            CliError::io(format!(
                "sync durable mutation lock {} failed: {error}",
                key.display()
            ))
        })?;
        Ok(Self {
            _process_guard: process_guard,
            _file: file,
        })
    }
}

pub(crate) fn write_json_value_atomic(path: &Path, value: &Value, label: &str) -> CliResult {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| CliError::runtime(format!("serialize {label}: {error}")))?;
    bytes.push(10);
    write_bytes_atomic(path, &bytes, label)
}

pub(crate) fn write_bytes_atomic(path: &Path, bytes: &[u8], label: &str) -> CliResult {
    let parent = path
        .parent()
        .ok_or_else(|| CliError::io(format!("{label} path {} has no parent", path.display())))?;
    fs::create_dir_all(parent).map_err(|error| {
        CliError::io(format!(
            "create {label} parent directory {} failed: {error}",
            parent.display()
        ))
    })?;
    let (tmp, mut file) = create_unique_temp(path, label)?;
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        return Err(cleanup_after_failure(
            &tmp,
            label,
            CliError::io(format!(
                "write temporary {label} {} failed: {error}",
                tmp.display()
            )),
        ));
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        return Err(cleanup_after_failure(
            &tmp,
            label,
            CliError::io(format!(
                "sync temporary {label} {} failed: {error}",
                tmp.display()
            )),
        ));
    }
    drop(file);
    if let Err(error) = replace_file(&tmp, path, label) {
        return Err(cleanup_after_failure(&tmp, label, error));
    }
    sync_parent_dir(parent, label)
}

pub(crate) fn write_bytes_immutable(path: &Path, bytes: &[u8], label: &str) -> CliResult {
    let parent = path
        .parent()
        .ok_or_else(|| CliError::io(format!("{label} path {} has no parent", path.display())))?;
    fs::create_dir_all(parent).map_err(|error| {
        CliError::io(format!(
            "create {label} parent directory {} failed: {error}",
            parent.display()
        ))
    })?;
    match fs::read(path) {
        Ok(existing) => return require_immutable_bytes(path, &existing, bytes, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(CliError::io(format!(
                "read immutable {label} {} failed: {error}",
                path.display()
            )));
        }
    }
    let (tmp, mut file) = create_unique_temp(path, label)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        return Err(cleanup_after_failure(
            &tmp,
            label,
            CliError::io(format!(
                "write and sync temporary immutable {label} {} failed: {error}",
                tmp.display()
            )),
        ));
    }
    drop(file);
    let published = match publish_immutable(&tmp, path, label) {
        Ok(published) => published,
        Err(error) => return Err(cleanup_after_failure(&tmp, label, error)),
    };
    match published {
        ImmutablePublish::Published => sync_parent_dir(parent, label),
        ImmutablePublish::AlreadyExists => {
            fs::remove_file(&tmp).map_err(|error| {
                CliError::io(format!(
                    "remove losing temporary immutable {label} {} failed: {error}",
                    tmp.display()
                ))
            })?;
            let existing = fs::read(path).map_err(|error| {
                CliError::io(format!(
                    "read concurrently published immutable {label} {} failed: {error}",
                    path.display()
                ))
            })?;
            require_immutable_bytes(path, &existing, bytes, label)
        }
    }
}

enum ImmutablePublish {
    Published,
    AlreadyExists,
}

fn require_immutable_bytes(
    path: &Path,
    existing: &[u8],
    expected: &[u8],
    label: &str,
) -> CliResult {
    if existing == expected {
        return Ok(());
    }
    Err(CliError::io(format!(
        "immutable {label} {} already exists with different bytes",
        path.display()
    )))
}

fn create_unique_temp(path: &Path, label: &str) -> CliResult<(PathBuf, File)> {
    for _ in 0..MAX_TEMP_CREATE_ATTEMPTS {
        let tmp = temp_path(path)?;
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(CliError::io(format!(
                    "create temporary {label} {} failed: {error}",
                    tmp.display()
                )));
            }
        }
    }
    Err(CliError::io(format!(
        "create temporary {label} beside {} failed after {MAX_TEMP_CREATE_ATTEMPTS} unique attempts",
        path.display()
    )))
}

fn temp_path(path: &Path) -> CliResult<PathBuf> {
    let filename = path.file_name().ok_or_else(|| {
        CliError::io(format!(
            "atomic write path {} has no filename",
            path.display()
        ))
    })?;
    let mut tmp_name = OsString::from(".");
    tmp_name.push(filename);
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    tmp_name.push(format!(".{}.{id}.tmp", std::process::id()));
    Ok(path.with_file_name(tmp_name))
}

fn canonical_lock_key(path: &Path) -> CliResult<PathBuf> {
    let parent = path.parent().ok_or_else(|| {
        CliError::io(format!(
            "mutation lock path {} has no parent",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        CliError::io(format!(
            "create mutation lock parent {} failed: {error}",
            parent.display()
        ))
    })?;
    let parent = parent.canonicalize().map_err(|error| {
        CliError::io(format!(
            "canonicalize mutation lock parent {} failed: {error}",
            parent.display()
        ))
    })?;
    let name = path.file_name().ok_or_else(|| {
        CliError::io(format!(
            "mutation lock path {} has no file name",
            path.display()
        ))
    })?;
    Ok(parent.join(name))
}

fn durable_process_mutex(path: &Path) -> CliResult<&'static Mutex<()>> {
    let locks = PROCESS_MUTATION_LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut locks = locks
        .lock()
        .map_err(|_| CliError::runtime("durable mutation lock registry mutex poisoned"))?;
    if let Some(lock) = locks.get(path) {
        return Ok(lock);
    }
    let lock = Box::leak(Box::new(Mutex::new(())));
    locks.insert(path.to_path_buf(), lock);
    Ok(lock)
}

fn cleanup_after_failure(tmp: &Path, label: &str, failure: CliError) -> CliError {
    match fs::remove_file(tmp) {
        Ok(()) => failure,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => failure,
        Err(error) => CliError::io(format!(
            "{}; cleanup of temporary {label} {} also failed: {error}",
            failure.message(),
            tmp.display()
        )),
    }
}

#[cfg(windows)]
fn replace_file(tmp: &Path, path: &Path, label: &str) -> CliResult {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let mut tmp_wide = tmp.as_os_str().encode_wide().collect::<Vec<_>>();
    if tmp_wide.contains(&0) {
        return Err(CliError::io(format!(
            "temporary {label} path {} contains an interior NUL",
            tmp.display()
        )));
    }
    tmp_wide.push(0);
    let mut path_wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if path_wide.contains(&0) {
        return Err(CliError::io(format!(
            "destination {label} path {} contains an interior NUL",
            path.display()
        )));
    }
    path_wide.push(0);
    // SAFETY: both paths are NUL-terminated UTF-16 buffers that remain alive
    // for the call, and MoveFileExW does not retain either pointer.
    let moved = unsafe {
        MoveFileExW(
            tmp_wide.as_ptr(),
            path_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(CliError::io(format!(
            "publish {label} {} -> {} with MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH) failed: {}",
            tmp.display(),
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(tmp: &Path, path: &Path, label: &str) -> CliResult {
    fs::rename(tmp, path).map_err(|error| {
        CliError::io(format!(
            "publish {label} {} -> {} failed: {error}",
            tmp.display(),
            path.display()
        ))
    })
}

#[cfg(windows)]
fn publish_immutable(tmp: &Path, path: &Path, label: &str) -> CliResult<ImmutablePublish> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let mut tmp_wide = tmp.as_os_str().encode_wide().collect::<Vec<_>>();
    let mut path_wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if tmp_wide.contains(&0) || path_wide.contains(&0) {
        return Err(CliError::io(format!(
            "immutable {label} path contains an interior NUL: {} -> {}",
            tmp.display(),
            path.display()
        )));
    }
    tmp_wide.push(0);
    path_wide.push(0);
    // SAFETY: both paths are NUL-terminated UTF-16 buffers retained for the
    // call. Omitting REPLACE_EXISTING makes destination creation fail closed.
    let moved = unsafe {
        MoveFileExW(
            tmp_wide.as_ptr(),
            path_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved != 0 {
        return Ok(ImmutablePublish::Published);
    }
    let error = std::io::Error::last_os_error();
    if error
        .raw_os_error()
        .map(|code| code as u32)
        .is_some_and(|code| code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS)
    {
        return Ok(ImmutablePublish::AlreadyExists);
    }
    Err(CliError::io(format!(
        "publish immutable {label} {} -> {} with MoveFileExW(WRITE_THROUGH,no-replace) failed: {error}",
        tmp.display(),
        path.display()
    )))
}

#[cfg(not(windows))]
fn publish_immutable(tmp: &Path, path: &Path, label: &str) -> CliResult<ImmutablePublish> {
    match fs::hard_link(tmp, path) {
        Ok(()) => {
            fs::remove_file(tmp).map_err(|error| {
                CliError::io(format!(
                    "remove published temporary immutable {label} {} failed: {error}",
                    tmp.display()
                ))
            })?;
            Ok(ImmutablePublish::Published)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(ImmutablePublish::AlreadyExists)
        }
        Err(error) => Err(CliError::io(format!(
            "publish immutable {label} {} -> {} failed: {error}",
            tmp.display(),
            path.display()
        ))),
    }
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path, label: &str) -> CliResult {
    let dir = File::open(parent).map_err(|error| {
        CliError::io(format!(
            "open {label} parent directory {} for sync failed: {error}",
            parent.display()
        ))
    })?;
    dir.sync_all().map_err(|error| {
        CliError::io(format!(
            "sync {label} parent directory {} failed: {error}",
            parent.display()
        ))
    })
}

#[cfg(windows)]
fn sync_parent_dir(parent: &Path, label: &str) -> CliResult {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

    let dir = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(parent)
        .map_err(|error| {
            CliError::io(format!(
                "open {label} parent directory {} for Windows sync failed: {error}",
                parent.display()
            ))
        })?;
    dir.sync_all().map_err(|error| {
        CliError::io(format!(
            "sync {label} parent directory {} on Windows failed: {error}",
            parent.display()
        ))
    })
}
