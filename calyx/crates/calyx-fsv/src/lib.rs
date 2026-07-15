//! Canonical resolution of FSV evidence-root environment variables.
//!
//! Cargo sets the working directory of every unit/integration test to the
//! root of the crate under test, not the workspace root, so a relative
//! `CALYX_FSV_ROOT` scatters evidence under `crates/<name>/...` while
//! operators read back `target/fsv/...` at the workspace root (issue #1014).
//! An evidence root is only deterministic when it is absolute, so a set
//! value that is empty or relative is a fatal configuration error: every
//! consumer in the workspace must resolve the variable through this crate
//! and fail closed instead of writing to a cwd-dependent location.

use std::ffi::OsString;
use std::path::PathBuf;

pub mod scratch;
pub use scratch::{ScratchDir, scratch_or_temp};

/// The workspace-wide FSV evidence root variable.
pub const FSV_ROOT_ENV: &str = "CALYX_FSV_ROOT";

/// A set-but-unusable FSV root variable. Fatal by design: there is no
/// correct directory to fall back to once the operator asked for a
/// specific evidence root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsvRootError {
    /// Stable machine-readable code: `CALYX_FSV_ROOT_EMPTY` or
    /// `CALYX_FSV_ROOT_NOT_ABSOLUTE`.
    pub code: &'static str,
    /// The environment variable that held the rejected value.
    pub var: String,
    /// The rejected value, byte-for-byte.
    pub value: OsString,
    /// The process working directory the relative value would have
    /// silently resolved against.
    pub cwd: PathBuf,
}

impl std::fmt::Display for FsvRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{code} var={var} value={value:?} cwd={cwd} remediation=\"set {var} to an \
             absolute path; relative values resolve against the per-crate test cwd and \
             scatter FSV artifacts (issue #1014)\"",
            code = self.code,
            var = self.var,
            value = self.value,
            cwd = self.cwd.display(),
        )
    }
}

impl std::error::Error for FsvRootError {}

/// Reads `var` as an FSV evidence root.
///
/// Unset means the caller owns its root (`Ok(None)`); a set value must be
/// an absolute path or the caller gets a structured [`FsvRootError`].
pub fn env_fsv_root(var: &str) -> Result<Option<PathBuf>, FsvRootError> {
    let Some(raw) = std::env::var_os(var) else {
        return Ok(None);
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("<unknown-cwd>"));
    if raw.is_empty() {
        return Err(FsvRootError {
            code: "CALYX_FSV_ROOT_EMPTY",
            var: var.to_string(),
            value: raw,
            cwd,
        });
    }
    let path = PathBuf::from(&raw);
    if !path.is_absolute() {
        return Err(FsvRootError {
            code: "CALYX_FSV_ROOT_NOT_ABSOLUTE",
            var: var.to_string(),
            value: raw,
            cwd,
        });
    }
    Ok(Some(path))
}

/// [`env_fsv_root`] for tests: panics with the structured message on a
/// set-but-invalid value.
pub fn fsv_root(var: &str) -> Option<PathBuf> {
    match env_fsv_root(var) {
        Ok(root) => root,
        Err(error) => panic!("{error}"),
    }
}

/// [`fsv_root`] with a caller-owned fallback for when `var` is unset.
pub fn fsv_root_or_else(var: &str, fallback: impl FnOnce() -> PathBuf) -> PathBuf {
    fsv_root(var).unwrap_or_else(fallback)
}

/// [`fsv_root`] for manual-FSV tests that cannot run without an operator
/// supplied evidence root: panics when `var` is unset or invalid.
pub fn required_fsv_root(var: &str) -> PathBuf {
    fsv_root(var).unwrap_or_else(|| {
        panic!(
            "CALYX_FSV_ROOT_UNSET var={var} remediation=\"set {var} to an absolute \
             evidence directory before running this manual FSV\""
        )
    })
}
