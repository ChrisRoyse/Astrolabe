use super::AsterVault;
use calyx_core::{CalyxError, Clock, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Creates a byte-verified, point-in-time copy of this durable vault.
    ///
    /// A write-capable source takes the durable commit lock for the complete
    /// copy. A read-only source reuses the shared snapshot lock retained from
    /// open, which keeps writers excluded without recovering or rewriting the
    /// source vault. The destination must not exist; refusing replacement
    /// prevents this primitive from becoming an implicit overwrite or rollback
    /// mechanism.
    pub fn copy_durable_snapshot_to(&self, destination: &Path) -> Result<()> {
        let source = self.durable_root.as_deref().ok_or_else(|| CalyxError {
            code: "CALYX_DURABLE_SNAPSHOT_SOURCE_REQUIRED",
            message: "a volatile Aster vault has no durable bytes to snapshot".to_string(),
            remediation: "open the source vault with AsterVault::open before requesting a durable snapshot",
        })?;
        if destination.try_exists().map_err(|error| {
            snapshot_io("probe durable snapshot destination", destination, error)
        })? {
            return Err(CalyxError {
                code: "CALYX_DURABLE_SNAPSHOT_DESTINATION_EXISTS",
                message: format!(
                    "durable snapshot destination already exists: {}",
                    destination.display()
                ),
                remediation: "use a new empty transaction-owned destination; never overwrite an existing vault snapshot",
            });
        }
        self.authorize_external_copy(destination)?;
        if self.read_only {
            if self._read_snapshot_guard.is_none() {
                return Err(CalyxError {
                    code: "CALYX_DURABLE_SNAPSHOT_READ_LOCK_MISSING",
                    message: "read-only durable snapshot source has no retained shared commit lock"
                        .to_string(),
                    remediation: "discard this handle and reopen the source vault read-only before snapshotting",
                });
            }
            return copy_durable_tree_under_lock(source, destination);
        }
        self.with_durable_commit_lock(|| copy_durable_tree_under_lock(source, destination))
    }
}

fn copy_durable_tree_under_lock(source: &Path, destination: &Path) -> Result<()> {
    let snapshot = copy_tree_verified(source, source, destination)
        .and_then(|()| initialize_snapshot_coordination_files(destination));
    if let Err(copy_error) = snapshot {
        let cleanup = fs::remove_dir_all(destination);
        return Err(match cleanup {
            Ok(()) => copy_error,
            Err(cleanup_error) => CalyxError {
                code: "CALYX_DURABLE_SNAPSHOT_CLEANUP_FAILED",
                message: format!(
                    "durable snapshot failed ({copy_error}); exact new destination {} also could not be removed: {cleanup_error}",
                    destination.display()
                ),
                remediation: "preserve and inspect the exact incomplete destination; do not use it as a vault snapshot",
            },
        });
    }
    Ok(())
}

fn initialize_snapshot_coordination_files(destination: &Path) -> Result<()> {
    for relative in [
        Path::new("locks").join("durable.commit.lock"),
        Path::new("wal").join(".append.lock"),
    ] {
        let path = destination.join(relative);
        let parent = path.parent().ok_or_else(|| CalyxError {
            code: "CALYX_DURABLE_SNAPSHOT_COORDINATION_PATH",
            message: format!(
                "snapshot coordination path has no parent: {}",
                path.display()
            ),
            remediation:
                "discard the transaction-owned destination and inspect the snapshot path boundary",
        })?;
        let parent_metadata = fs::metadata(parent)
            .map_err(|error| snapshot_io("inspect snapshot coordination parent", parent, error))?;
        if !parent_metadata.is_dir() {
            return Err(CalyxError {
                code: "CALYX_DURABLE_SNAPSHOT_COORDINATION_PARENT_MISSING",
                message: format!(
                    "snapshot coordination parent is absent or not a directory: {}",
                    parent.display()
                ),
                remediation: "discard the transaction-owned destination and inspect the source vault's required locks/wal layout",
            });
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|error| {
                snapshot_io("create fresh destination coordination file", &path, error)
            })?;
        file.sync_all().map_err(|error| {
            snapshot_io("sync fresh destination coordination file", &path, error)
        })?;
        drop(file);

        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            snapshot_io("read back destination coordination file", &path, error)
        })?;
        if !metadata.file_type().is_file() || metadata.len() != 0 {
            return Err(CalyxError {
                code: "CALYX_DURABLE_SNAPSHOT_COORDINATION_READBACK_MISMATCH",
                message: format!(
                    "fresh destination coordination object {} read back with file={} bytes={}",
                    path.display(),
                    metadata.file_type().is_file(),
                    metadata.len()
                ),
                remediation: "discard the transaction-owned destination and inspect the storage device before retrying",
            });
        }
    }
    Ok(())
}

fn copy_tree_verified(root: &Path, source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination)
        .map_err(|error| snapshot_io("create destination directory", destination, error))?;
    let mut entries = fs::read_dir(source)
        .map_err(|error| snapshot_io("read source directory", source, error))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| snapshot_io("enumerate source directory", source, error))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let relative = source_path
            .strip_prefix(root)
            .map_err(|error| snapshot_path("derive vault-relative path", &source_path, error))?;
        // These two files coordinate writers; they are not durable vault data.
        // The snapshot already holds durable.commit.lock, so reading that file
        // would conflict with our own Windows byte-range lock. Fresh
        // destination-owned coordinators are initialized after the data copy.
        if relative == Path::new("locks").join("durable.commit.lock")
            || relative == Path::new("wal").join(".append.lock")
        {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| snapshot_io("read source file type", &source_path, error))?;
        if file_type.is_symlink() {
            return Err(CalyxError {
                code: "CALYX_DURABLE_SNAPSHOT_SYMLINK_REFUSED",
                message: format!(
                    "durable vault contains a symbolic link or reparse point: {}",
                    source_path.display()
                ),
                remediation: "quarantine the vault and restore it from verified ordinary files; snapshots never follow links outside the vault root",
            });
        }
        if file_type.is_dir() {
            copy_tree_verified(root, &source_path, &destination_path)?;
        } else if file_type.is_file() {
            copy_file_verified(&source_path, &destination_path)?;
        } else {
            return Err(CalyxError {
                code: "CALYX_DURABLE_SNAPSHOT_SPECIAL_FILE_REFUSED",
                message: format!(
                    "durable vault contains a non-file, non-directory entry: {}",
                    source_path.display()
                ),
                remediation: "quarantine the vault and remove the unsupported special entry before retrying",
            });
        }
    }
    Ok(())
}

fn copy_file_verified(source: &Path, destination: &Path) -> Result<()> {
    let mut reader =
        File::open(source).map_err(|error| snapshot_io("open source file", source, error))?;
    let mut writer = File::create_new(destination)
        .map_err(|error| snapshot_io("create destination file", destination, error))?;
    let mut source_hash = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| snapshot_io("read source file", source, error))?;
        if read == 0 {
            break;
        }
        source_hash.update(&buffer[..read]);
        writer
            .write_all(&buffer[..read])
            .map_err(|error| snapshot_io("write destination file", destination, error))?;
    }
    writer
        .sync_all()
        .map_err(|error| snapshot_io("sync destination file", destination, error))?;
    drop(writer);

    let expected = source_hash.finalize();
    let actual = sha256_file(destination)?;
    if expected.as_slice() != actual.as_slice() {
        return Err(CalyxError {
            code: "CALYX_DURABLE_SNAPSHOT_READBACK_MISMATCH",
            message: format!(
                "durable snapshot readback hash differs for {} -> {}",
                source.display(),
                destination.display()
            ),
            remediation: "discard the transaction-owned destination and inspect the storage device for write corruption before retrying",
        });
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<Vec<u8>> {
    let mut file =
        File::open(path).map_err(|error| snapshot_io("open readback file", path, error))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| snapshot_io("read back destination file", path, error))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hash.finalize().to_vec())
}

fn snapshot_io(action: &str, path: &Path, error: std::io::Error) -> CalyxError {
    CalyxError {
        code: "CALYX_DURABLE_SNAPSHOT_IO",
        message: format!("{action} {}: {error}", path.display()),
        remediation: "verify the source and transaction-owned destination are writable ordinary files on healthy storage, then retry",
    }
}

fn snapshot_path(action: &str, path: &Path, error: std::path::StripPrefixError) -> CalyxError {
    CalyxError {
        code: "CALYX_DURABLE_SNAPSHOT_PATH",
        message: format!("{action} {}: {error}", path.display()),
        remediation: "preserve the incomplete transaction and inspect the vault root/path boundary before retrying",
    }
}
