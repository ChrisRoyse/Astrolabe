//! Cross-session farm lock (#527): single-writer exclusion for mutating fleet
//! passes over one catalog root.
//!
//! 2026-07-16 two sessions raced retry-release pipelines over the same
//! production store within 68 s of each other; both wrote one repo vault
//! concurrently and produced `CALYX_LEDGER_APPEND_ONLY_VIOLATION: Aster ledger
//! head regressed` (evidence on #460). Nothing in the fleet detected the race.
//!
//! The lock is a **kernel-enforced advisory file lock** (`std::fs::File::try_lock`,
//! `LockFileEx` on Windows, stable since Rust 1.89): the OS releases it when the
//! holder's handle closes — including on kill, crash, or power loss — so the
//! stale-dead-PID lock class is eliminated by construction instead of being
//! probed and broken (#197's pidfile discipline exists because pidfiles CAN go
//! stale; a kernel lock cannot). Holder metadata lives in a sidecar
//! `farm.lock.info` (JSON: pid, verb, started) that a refused contender can
//! always read — the lock file itself stays exclusively held and unreadable.
//!
//! Mutating verbs (`catalog-init`, `register`, `set-state`, `discover`,
//! `clone`, `pipeline`, `grow`, `report`, `dedup-census`, `compose`) must
//! acquire; read verbs (`get`, `list`, `ledger-scan`, `report-read`,
//! `report-list`, `run-report-read`, `probe-vault-keys`, `kernel-read`) stay
//! lock-free. A held lock refuses the contender fail-closed with
//! [`ASTRO_FLEET_FARM_LOCKED`] naming the holder — never queues silently,
//! never races.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use calyx_core::CalyxError;

/// Structured refusal code when another live process holds the farm lock.
pub const ASTRO_FLEET_FARM_LOCKED: &str = "ASTRO_FLEET_FARM_LOCKED";
/// Structured code when the lock file itself cannot be created or locked.
pub const ASTRO_FLEET_FARM_LOCK_IO: &str = "ASTRO_FLEET_FARM_LOCK_IO";

/// Lock file name inside the catalog root.
const LOCK_FILE: &str = "farm.lock";
/// Human/machine-readable holder metadata beside the lock file.
const LOCK_INFO_FILE: &str = "farm.lock.info";

/// RAII guard over the farm lock: the exclusive OS lock is released when this
/// guard (and its file handle) drops, including on abnormal process death.
#[derive(Debug)]
pub struct FarmLock {
    // Held only for its OS-level exclusive lock; dropped (= unlocked) with the guard.
    _file: File,
    info_path: PathBuf,
}

impl FarmLock {
    /// Acquires the single-writer farm lock for `verb` under `catalog_root`,
    /// creating the root directory if needed (mirrors `FleetCatalog::open`,
    /// which is invoked after this and also creates it).
    ///
    /// Fails closed with [`ASTRO_FLEET_FARM_LOCKED`] if another live process
    /// holds the lock — the error message carries the holder's recorded
    /// metadata so the operator can find the owning run instead of guessing
    /// from process lists.
    pub fn acquire(catalog_root: &Path, verb: &str) -> Result<Self, CalyxError> {
        std::fs::create_dir_all(catalog_root).map_err(|error| CalyxError {
            code: ASTRO_FLEET_FARM_LOCK_IO,
            message: format!(
                "create catalog root {} for the farm lock: {error}",
                catalog_root.display()
            ),
            remediation: "point --root at a creatable directory",
        })?;
        let lock_path = catalog_root.join(LOCK_FILE);
        let info_path = catalog_root.join(LOCK_INFO_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| CalyxError {
                code: ASTRO_FLEET_FARM_LOCK_IO,
                message: format!("open farm lock {}: {error}", lock_path.display()),
                remediation: "ensure the catalog root is writable and retry",
            })?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                let holder = std::fs::read_to_string(&info_path)
                    .unwrap_or_else(|_| "<holder metadata unavailable>".to_string());
                return Err(CalyxError {
                    code: ASTRO_FLEET_FARM_LOCKED,
                    message: format!(
                        "another live fleet process holds the farm lock {}; holder: {}",
                        lock_path.display(),
                        holder.trim()
                    ),
                    remediation: "wait for the holding pass to finish (the OS releases the \
                                  lock the moment its process exits, even on kill) and re-run; \
                                  never run two mutating fleet passes against one catalog root",
                });
            }
            Err(TryLockError::Error(error)) => {
                return Err(CalyxError {
                    code: ASTRO_FLEET_FARM_LOCK_IO,
                    message: format!("lock farm lock {}: {error}", lock_path.display()),
                    remediation: "ensure the catalog root filesystem supports file locking",
                });
            }
        }
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let info = serde_json::json!({
            "pid": std::process::id(),
            "verb": verb,
            "started_unix_secs": started,
        });
        // Best-effort metadata: the kernel lock is the exclusion mechanism; the
        // sidecar only serves the contender's error message. A failed write must
        // not fail the acquired pass, but it must not be silent either.
        if let Err(error) = std::fs::write(&info_path, format!("{info}\n")) {
            eprintln!(
                "{}",
                serde_json::json!({
                    "code": "ASTRO_FLEET_FARM_LOCK_INFO_UNWRITTEN",
                    "message": format!(
                        "farm lock acquired but holder metadata {} could not be written: {error}",
                        info_path.display()
                    ),
                    "remediation": "contenders will see '<holder metadata unavailable>'; \
                                    check catalog-root permissions",
                })
            );
        }
        // Flush is best-effort for the same reason (the handle stays open for
        // the lock's lifetime; content durability is not the point of the file).
        let _ = std::io::stderr().flush();
        Ok(Self {
            _file: file,
            info_path,
        })
    }
}

impl Drop for FarmLock {
    fn drop(&mut self) {
        // The OS releases the exclusive lock when `_file` closes. Clearing the
        // sidecar is cosmetic; a leftover info file never blocks anyone.
        let _ = std::fs::remove_file(&self.info_path);
    }
}
