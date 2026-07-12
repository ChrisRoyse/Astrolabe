//! Upstream-pending reference module for Calyx (ASTROLABE #260).
//!
//! Drop-in destination: `vendor/calyx/crates/calyx-fsv/src/scratch_dir.rs`,
//! re-exported from `calyx-fsv/src/lib.rs` as `pub mod scratch_dir;`.
//!
//! ## Why this exists
//! Every Calyx FSV/test helper that resolves a scratch root falls back to
//! `std::env::temp_dir().join(format!("{prefix}-{pid}..."))` and never removes
//! the directory on the panic / early-return path (see the producer census in
//! `patches/calyx/README.md`). On a panicking or aborting test the scratch dir
//! survives, so hygiene depends entirely on the harness redirecting `TMP`
//! (Astrolabe #246) or on a Unix-only post-run sweep
//! (`vendor/calyx/scripts/tmp_scratch_guard.sh`, which does not run on Windows).
//!
//! ## Design constraints (deliberate)
//! * **std-only.** Calyx depends on `tempfile` in **zero** crates; introducing
//!   it would add a new dependency to 40+ crates. This guard uses only
//!   `std::fs`, matching Calyx's existing convention.
//! * **RAII.** The directory is removed in `Drop`, so it is cleaned on normal
//!   return, on early `?`/return, and while the stack unwinds through a panic.
//! * **Disarmable.** When the operator sets the suite's evidence-root env key
//!   they want to inspect the artifacts, so that path is *kept* (never guarded).
//! * **Fail-closed for hard-kill.** `Drop` does not run on `SIGKILL`/`abort()`
//!   or a launcher hard-timeout; that residual is covered by the harness
//!   process-boundary sandbox (Astrolabe #246) or the suite sweep. This module
//!   closes the panic/early-return path — the intermittent one that flaked the
//!   aggregate (#278 attribution) — not the hard-kill path.

use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

/// An RAII scratch directory. Created eagerly on construction; removed on
/// `Drop` unless [`ScratchDir::keep`] disarmed it.
#[derive(Debug)]
pub struct ScratchDir {
    path: PathBuf,
    armed: bool,
}

impl ScratchDir {
    /// Creates `{root}/{prefix}-{name}-{pid}-{seq}` and arms cleanup.
    ///
    /// `seq` is a process-wide monotonic counter so parallel tests in one
    /// binary never collide (mirrors the existing `TEMP_ROOT_SEQ` helpers).
    pub fn new(root: &Path, prefix: &str, name: &str) -> std::io::Result<Self> {
        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!("{prefix}-{name}-{}-{seq}", process::id()));
        std::fs::create_dir_all(&path)?;
        Ok(ScratchDir { path, armed: true })
    }

    /// Convenience: scratch under `std::env::temp_dir()` (honors `TMP`/`TEMP`).
    pub fn in_temp(prefix: &str, name: &str) -> std::io::Result<Self> {
        Self::new(&std::env::temp_dir(), prefix, name)
    }

    /// The scratch path. Borrow it for the test's lifetime; keep the guard live.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Disarm cleanup and take ownership of the path — for the operator-supplied
    /// evidence root that must survive for inspection.
    pub fn keep(mut self) -> PathBuf {
        self.armed = false;
        std::mem::take(&mut self.path)
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
            // panic. The harness sweep is the backstop for that rare case.
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Resolves an FSV evidence root: the operator's `env_key` root if set (kept),
/// otherwise an armed `ScratchDir` fallback that self-cleans on drop.
///
/// This is the RAII replacement for the `(PathBuf, keep_bool)` helpers such as
/// `calyx-aster/tests/fsv_support/mod.rs::fsv_root` and `calyx-testkit`'s
/// `fsv::fsv_root`. Callers hold the returned value for the test's lifetime.
pub enum FsvScratch {
    /// Operator-supplied root (env key set) — inspected after the run, not removed.
    Kept(PathBuf),
    /// Fallback scratch — removed on drop (incl. panic/early-return).
    Owned(ScratchDir),
}

impl FsvScratch {
    pub fn resolve(
        env_key: &str,
        prefix: &str,
        name: &str,
    ) -> std::io::Result<Self> {
        // `env_fsv_root` is the existing calyx-fsv resolver; upstream call site
        // uses `crate::env_fsv_root(env_key)`. Reproduced here as var_os for the
        // standalone self-test build.
        match std::env::var_os(env_key) {
            Some(v) if !v.is_empty() => Ok(FsvScratch::Kept(PathBuf::from(v))),
            _ => Ok(FsvScratch::Owned(ScratchDir::new(
                &std::env::temp_dir(),
                prefix,
                name,
            )?)),
        }
    }

    pub fn path(&self) -> &Path {
        match self {
            FsvScratch::Kept(p) => p,
            FsvScratch::Owned(s) => s.path(),
        }
    }
}
