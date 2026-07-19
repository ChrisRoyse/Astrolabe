//! One technically-immutable byte snapshot of a frozen learned-model artifact.
//!
//! A frozen learned-lens contract derives three independent views from the same
//! on-disk file: the content-addressed frozen digest, the declared source
//! tensor profile, and the executable model. When each view opens the path
//! separately, a concurrent writer can substitute, truncate, rename, or rewrite
//! the bytes between opens so the digest, profile, and model describe different
//! byte sets. The frozen identity must instead be established once, against a
//! single snapshot, before any derived metadata is parsed (#524).
//!
//! [`FrozenArtifactSnapshot`] establishes that snapshot at acquisition time:
//!
//! * **Native Windows** — the handle is opened denying write and delete
//!   sharing ([`FILE_SHARE_READ`] only). For the lease lifetime the kernel
//!   refuses in-place writes, truncation, rename, replacement, and deletion,
//!   and a pre-existing writer that holds incompatible sharing makes
//!   acquisition fail closed.
//! * **Every platform** — the verified bytes are additionally copied into an
//!   owned private buffer under the same open handle. Once captured, no later
//!   mutation of the on-disk path can change the snapshot's identity, so a POSIX
//!   host without mandatory sharing still holds technically-immutable bytes
//!   rather than a cooperative advisory lock. This is the "owned immutable
//!   bytes" non-Windows strategy the issue requires — never a cooperative lock.
//!
//! All derived views (individual SHA, artifact-set SHA, source profile, model
//! load) must read [`bytes`](FrozenArtifactSnapshot::bytes) rather than reopen
//! [`path`](FrozenArtifactSnapshot::path), which is what makes them provably
//! come from one byte set.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use calyx_core::{CalyxError, Result};
use sha2::{Digest, Sha256};

/// Acquisition-time identity of the leased file, retained so a pre/post lease
/// identity change can be reported with the observed and expected values rather
/// than silently retrying a different file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FrozenArtifactIdentity {
    /// Byte length observed at acquisition.
    len: u64,
    /// Unix device + inode when available. `None` on platforms that do not
    /// expose a stable file identity through [`std::fs::Metadata`].
    unix_dev_ino: Option<(u64, u64)>,
}

impl FrozenArtifactIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            unix_dev_ino: unix_dev_ino(metadata),
        }
    }

    /// Human-readable form for structured error messages.
    fn summary(&self) -> String {
        match self.unix_dev_ino {
            Some((dev, ino)) => format!("len={} dev={dev} ino={ino}", self.len),
            None => format!("len={}", self.len),
        }
    }
}

#[cfg(unix)]
fn unix_dev_ino(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn unix_dev_ino(_metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

/// A single immutable byte snapshot of one frozen artifact file.
pub(crate) struct FrozenArtifactSnapshot {
    path: PathBuf,
    /// Retained for the lease lifetime. On Windows this handle carries the
    /// write/delete-deny share mode; dropping the snapshot releases the lease.
    /// The bytes below are the authoritative snapshot regardless of platform.
    _handle: File,
    identity: FrozenArtifactIdentity,
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl std::fmt::Debug for FrozenArtifactSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrozenArtifactSnapshot")
            .field("path", &self.path)
            .field("len", &self.len())
            .field("sha256", &self.sha256_hex())
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl FrozenArtifactSnapshot {
    /// Acquires a leased, immutable snapshot of `path`.
    ///
    /// Fails closed with [`CALYX_LENS_CONFIG_INVALID`](CalyxError) if the file
    /// cannot be opened under the deny-write lease (for example a pre-existing
    /// writer on Windows) or cannot be read in full.
    pub(crate) fn acquire(path: &Path) -> Result<Self> {
        let handle = open_leased(path)?;
        let metadata = handle.metadata().map_err(|err| CalyxError {
            code: "CALYX_LENS_CONFIG_INVALID",
            message: format!(
                "stat leased frozen artifact {} failed: {err}",
                path.display()
            ),
            remediation: "ensure the frozen artifact path is a regular readable file",
        })?;
        let identity = FrozenArtifactIdentity::from_metadata(&metadata);
        // Read the full file from the already-leased handle. On Windows the
        // deny-write share mode guarantees these bytes cannot change while the
        // handle is open; on every platform the owned buffer is the snapshot.
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&handle)
            .read_to_end(&mut bytes)
            .map_err(|err| CalyxError {
                code: "CALYX_LENS_CONFIG_INVALID",
                message: format!(
                    "read leased frozen artifact {} failed: {err}",
                    path.display()
                ),
                remediation: "ensure the frozen artifact path is a regular readable file",
            })?;
        let sha256: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            hasher.finalize().into()
        };
        Ok(Self {
            path: path.to_path_buf(),
            _handle: handle,
            identity,
            bytes,
            sha256,
        })
    }

    /// The immutable snapshot bytes. All derived views must read these bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Snapshot byte length.
    pub(crate) fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Lowercase hex SHA-256 of the snapshot bytes.
    pub(crate) fn sha256_hex(&self) -> String {
        hex_from_bytes(&self.sha256)
    }

    /// Verifies the snapshot digest equals `expected_hex` before any derived
    /// metadata is parsed. A mismatch is a frozen-identity violation, never a
    /// recoverable condition: there is no alternate file, dtype, or provider to
    /// retry.
    pub(crate) fn verify_expected_hex(&self, expected_hex: &str) -> Result<()> {
        let actual = self.sha256_hex();
        if !actual.eq_ignore_ascii_case(expected_hex.trim()) {
            return Err(CalyxError::lens_frozen_violation(format!(
                "frozen artifact {} sha256 {actual} != expected {}; leased snapshot identity {}",
                self.path.display(),
                expected_hex.trim(),
                self.identity.summary()
            )));
        }
        Ok(())
    }
}

/// Lowercase hex encoding of a 32-byte digest.
fn hex_from_bytes(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(windows)]
fn open_leased(path: &Path) -> Result<File> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

    // Omitting FILE_SHARE_WRITE and FILE_SHARE_DELETE kernel-denies in-place
    // writes, replacement, rename, and deletion for the lease lifetime; a
    // pre-existing writer that holds incompatible sharing makes this open fail.
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|err| CalyxError {
            code: "CALYX_LENS_CONFIG_INVALID",
            message: format!(
                "acquire write-denied lease on frozen artifact {} failed: {err}; a concurrent writer may hold it",
                path.display()
            ),
            remediation: "close any process writing the artifact, then reload; never load an artifact under active mutation",
        })
}

#[cfg(not(windows))]
fn open_leased(path: &Path) -> Result<File> {
    // POSIX hosts have no mandatory write-deny sharing, so immutability is
    // established by owning the bytes (read in full by the caller) rather than
    // by the handle. The open itself only needs to succeed.
    File::open(path).map_err(|err| CalyxError {
        code: "CALYX_LENS_CONFIG_INVALID",
        message: format!(
            "open frozen artifact {} for immutable snapshot failed: {err}",
            path.display()
        ),
        remediation: "ensure the frozen artifact path is a regular readable file",
    })
}
