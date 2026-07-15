//! RAII scratch directories for FSV/test evidence roots (ASTROLABE #260).
//!
//! ## The defect this closes
//! Every Calyx FSV/test helper that needs a scratch directory falls back to
//! `std::env::temp_dir().join(format!("{prefix}-{pid}"))` and removes it only
//! on the happy path (or not at all). On a panicking or early-returning test
//! the directory survives, so hygiene depends entirely on the harness
//! redirecting `TMP` (ASTROLABE #246) or on a Unix-only post-run sweep. When a
//! process runs one of these paths without the sandbox `TMP` in effect the
//! scratch dir leaks straight into the operator's real `%TEMP%` — the
//! intermittent aggregate RED tracked in #237/#260/#278.
//!
//! ## Design constraints (deliberate)
//! * **std-only.** `calyx-fsv` (and Calyx as a whole) depend on `tempfile` in
//!   zero crates; this guard uses only `std::fs`, matching that convention.
//! * **RAII.** The directory is removed in [`Drop`], so it is cleaned on normal
//!   return, on early `?`/`return`, and while the stack unwinds through a panic.
//! * **Disarmable.** When the operator points a suite at a real evidence root
//!   (via a `CALYX_*_FSV_ROOT` variable) they want the artifacts to survive for
//!   inspection, so that path is [`ScratchDir::kept`] — never removed.
//! * **Honest hard-kill boundary.** `Drop` does not run on `SIGKILL`/`abort()`
//!   or a launcher hard-timeout; that residual is covered by the harness
//!   process-boundary sandbox (#246). This module closes the panic /
//!   early-return path — the intermittent one that flaked the aggregate — not
//!   the hard-kill path, and must not be oversold as total containment.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide monotonic counter so parallel tests in one binary never collide
/// (mirrors the existing per-crate `TEMP_ROOT_SEQ` helpers).
static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

/// An RAII scratch directory.
///
/// While `armed`, the directory is removed in [`Drop`] — on normal return, on
/// early return, and while the stack unwinds through a panic. A `kept` guard is
/// disarmed: it names an operator-supplied evidence root that must survive the
/// run for inspection.
///
/// [`ScratchDir`] derefs to [`Path`], so an existing call site that used a
/// `PathBuf` (`root.join(..)`, `&root`, `root.display()`, `fs::create_dir_all(&root)`)
/// keeps compiling once it binds the guard for the test's lifetime.
#[derive(Debug)]
pub struct ScratchDir {
    path: PathBuf,
    armed: bool,
}

impl ScratchDir {
    /// Creates `{root}/{prefix}-{pid}-{seq}` fresh (any stale predecessor is
    /// removed first) and arms cleanup. `seq` is process-wide monotonic.
    pub fn new_in(root: &Path, prefix: &str) -> std::io::Result<Self> {
        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!("{prefix}-{}-{seq}", process::id()));
        // Fresh: a re-used pid+seq from a crashed prior run must not carry state.
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path, armed: true })
    }

    /// [`ScratchDir::new_in`] under `std::env::temp_dir()` (honors
    /// `TMP`/`TEMP`/`TMPDIR`).
    pub fn new_temp(prefix: &str) -> std::io::Result<Self> {
        Self::new_in(&std::env::temp_dir(), prefix)
    }

    /// Wraps an operator-supplied root, disarmed: it is never removed on drop.
    /// The directory is created if missing so callers can write immediately.
    pub fn kept(path: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&path);
        Self { path, armed: false }
    }

    /// The scratch path. Borrow it for the test's lifetime; keep the guard live.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this guard will NOT remove its directory on drop (i.e. it names an
    /// operator-supplied evidence root). Replaces the `keep`/`preserve` boolean
    /// the pre-RAII `(PathBuf, bool)` helpers returned.
    pub fn is_kept(&self) -> bool {
        !self.armed
    }

    /// Disarms cleanup and returns the owned path — for the rare caller that must
    /// hand the directory to something that outlives the guard. After this the
    /// directory is the caller's responsibility.
    pub fn into_kept(mut self) -> PathBuf {
        self.armed = false;
        std::mem::take(&mut self.path)
    }
}

impl Deref for ScratchDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for ScratchDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if self.armed {
            // Best-effort: a failed removal must never mask the test's own
            // panic. The harness process-boundary sandbox (#246) is the backstop.
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Resolves an FSV scratch root as an RAII guard: the operator's configured
/// root (via [`crate::fsv_root`]) is [`ScratchDir::kept`] (survives for
/// inspection); an unset variable yields an armed [`ScratchDir::new_temp`]
/// fallback that self-cleans on drop, including on panic.
///
/// This is the RAII replacement for the `(PathBuf, bool)` fallback helpers such
/// as `calyx-aster/tests/fsv_support::fsv_root`. Callers bind the returned guard
/// for the test's lifetime and read [`ScratchDir::is_kept`] where they used the
/// old boolean.
///
/// # Panics
/// Panics via [`crate::fsv_root`] if the variable is set to an empty or relative
/// value (fail-closed misconfiguration, issue #1014), and if the fallback
/// directory cannot be created.
pub fn scratch_or_temp(env_key: &str, fallback_prefix: &str) -> ScratchDir {
    match crate::fsv_root(env_key) {
        Some(root) => ScratchDir::kept(root),
        None => ScratchDir::new_temp(fallback_prefix)
            .unwrap_or_else(|e| panic!("create fallback scratch dir {fallback_prefix}: {e}")),
    }
}
