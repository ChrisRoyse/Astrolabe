use std::path::Path;

use calyx_core::{CalyxError, Result};

pub(crate) fn sync_parent(path: &Path, label: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| CalyxError::disk_pressure(format!("{label} path has no parent")))?;
    sync_dir(parent, label)
}

#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path, label: &str) -> Result<()> {
    use std::fs::File;

    ensure_directory(dir, label)?;
    File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| {
            CalyxError::disk_pressure(format!(
                "sync {label} parent directory {}: {error}",
                dir.display()
            ))
        })
}

#[cfg(windows)]
pub(crate) fn sync_dir(dir: &Path, label: &str) -> Result<()> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

    ensure_directory(dir, label)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| {
            CalyxError::disk_pressure(format!(
                "sync {label} parent directory {} on Windows: {error}",
                dir.display()
            ))
        })
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn sync_dir(dir: &Path, label: &str) -> Result<()> {
    ensure_directory(dir, label)?;
    Err(CalyxError::disk_pressure(format!(
        "sync {label} parent directory {}: unsupported platform",
        dir.display()
    )))
}

fn ensure_directory(dir: &Path, label: &str) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    Err(CalyxError::disk_pressure(format!(
        "sync {label} parent directory {}: not a directory",
        dir.display()
    )))
}
