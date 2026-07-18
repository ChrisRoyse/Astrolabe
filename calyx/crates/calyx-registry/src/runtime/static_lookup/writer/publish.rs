//! Single-commit immutable artifact publication.

use std::path::Path;

use calyx_core::Result;

use super::{artifact_exists, export_io};

#[cfg(windows)]
pub(super) fn publish_immutable(staged: &Path, target: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let staged_wide = staged
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let target_wide = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // MOVEFILE_REPLACE_EXISTING is deliberately absent: a concurrent frozen
    // artifact publication must fail, never overwrite. The staged file is in
    // the same directory, already synced and production-reader verified;
    // WRITE_THROUGH makes this rename the single durable commit point.
    let moved = unsafe {
        MoveFileExW(
            staged_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        let error = std::io::Error::last_os_error();
        if target.exists() {
            return Err(artifact_exists(target));
        }
        return Err(export_io(
            "publish immutable artifact with MoveFileExW(MOVEFILE_WRITE_THROUGH)",
            target,
            error,
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn publish_immutable(staged: &Path, target: &Path) -> Result<()> {
    use std::fs::{self, File};

    fs::hard_link(staged, target)
        .map_err(|error| export_io("publish immutable artifact", target, error))?;
    File::open(target)
        .and_then(|file| file.sync_all())
        .map_err(|error| export_io("sync published artifact", target, error))?;
    fs::remove_file(staged).map_err(|error| export_io("remove staging link", staged, error))?;
    let parent = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| export_io("sync output directory", parent, error))
}
