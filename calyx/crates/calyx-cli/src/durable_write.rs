use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

use crate::error::{CliError, CliResult};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
const MAX_TEMP_CREATE_ATTEMPTS: usize = 1_024;

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
