//! Durable erase-intent record (write-ahead intent, issue #561).
//!
//! A lawful erase spans two sources of truth: Aster core CFs (tombstoned
//! atomically under the durable commit lock) and derived state owned by external
//! [`EraseHandler`](super::EraseHandler)s (mutated **outside** the lock, in two
//! phases). To recover an interrupted erase without ever treating partial work
//! as success, Phase A persists this intent record — using the crash-safe
//! temp-write + fsync-file + atomic-rename + fsync-parent sequence — before any
//! handler side effect. The record is the sole authority for resuming: on a
//! later erase for the same scope, its presence plus the core tombstone state
//! decides resume-commit vs. clean-abort. Success/abort deletes it (and fsyncs
//! the directory).
//!
//! Volatile vaults have no durable root and skip persistence entirely: nothing
//! survives a crash there by construction, so there is no interrupted state to
//! resume.

use std::path::{Path, PathBuf};

use calyx_core::{CalyxError, Result, VaultId};
use serde::{Deserialize, Serialize};

use super::EraseScope;

const ERASE_INTENT_DIR: &str = "erase_intent";

/// Format identity of the on-disk intent record. Not a tunable measurement — a
/// schema version bumped only on an incompatible layout change.
pub(super) const ERASE_INTENT_VERSION: u32 = 1;

/// Durable record of an in-flight erase, addressed by a blake3 digest of the
/// scope so concurrent erases of different scopes never collide.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct EraseIntent {
    /// On-disk format identity (currently [`ERASE_INTENT_VERSION`]).
    pub version: u32,
    /// The erase scope this intent covers.
    pub scope: EraseScope,
    /// Vault the erase targets (guards against a misfiled record).
    pub vault_id: VaultId,
    /// Vault sequence at which Phase A selected the erase targets.
    pub selected_seq: u64,
    /// Base constellations selected for deletion.
    pub records_deleted: usize,
    /// CF rows selected for tombstoning.
    pub rows_tombstoned: usize,
    /// Whether the vault key must be crypto-shredded for this scope.
    pub shred_key: bool,
    /// Names of the handlers whose commits must complete for the erase to be done.
    pub handler_names: Vec<String>,
}

fn intent_dir(root: &Path) -> PathBuf {
    root.join(ERASE_INTENT_DIR)
}

/// Filesystem path of the intent record for `scope` under durable `root`.
pub(super) fn intent_path(root: &Path, scope: &EraseScope) -> PathBuf {
    intent_dir(root).join(format!("{}.json", scope_digest(scope)))
}

/// Human-readable path used in diagnostics (never a control-flow input).
pub(super) fn intent_path_display(root: &Path, scope: &EraseScope) -> String {
    intent_path(root, scope).display().to_string()
}

/// Stable blake3 digest of the scope's canonical byte encoding.
fn scope_digest(scope: &EraseScope) -> String {
    let mut hasher = blake3::Hasher::new();
    match scope {
        EraseScope::Vault => hasher.update(b"vault"),
        EraseScope::Cx(id) => {
            hasher.update(b"cx:");
            hasher.update(id.as_bytes())
        }
        EraseScope::Subject(subject) => {
            hasher.update(b"subject:");
            hasher.update(super::subject_metadata_value(subject).as_bytes())
        }
    };
    hasher.finalize().to_hex().to_string()
}

/// Persists `intent` durably: temp write, fsync file, atomic rename, fsync dir.
pub(super) fn write_intent(root: &Path, intent: &EraseIntent) -> Result<()> {
    use std::fs::File;
    use std::io::Write;

    let path = intent_path(root, &intent.scope);
    let dir = intent_dir(root);
    std::fs::create_dir_all(&dir)
        .map_err(|error| CalyxError::disk_pressure(format!("create erase intent dir: {error}")))?;
    let bytes = serde_json::to_vec(intent)
        .map_err(|error| CalyxError::ledger_corrupt(format!("encode erase intent: {error}")))?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = File::create(&tmp).map_err(|error| {
            CalyxError::disk_pressure(format!("create erase intent temp: {error}"))
        })?;
        file.write_all(&bytes).map_err(|error| {
            CalyxError::disk_pressure(format!("write erase intent temp: {error}"))
        })?;
        file.sync_all()
            .map_err(|error| CalyxError::disk_pressure(format!("sync erase intent: {error}")))?;
    }
    replace_file(&tmp, &path)?;
    crate::fsync::sync_dir(&dir, "erase intent")
}

/// Loads the intent record for `scope`, if present.
///
/// # Errors
/// [`CalyxError::ledger_corrupt`] if the record exists but does not decode, or
/// its recorded format version is not [`ERASE_INTENT_VERSION`] — a mismatched
/// record is a corrupt-state signal, never silently ignored.
pub(super) fn load_intent(root: &Path, scope: &EraseScope) -> Result<Option<EraseIntent>> {
    let path = intent_path(root, scope);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)
        .map_err(|error| CalyxError::disk_pressure(format!("read erase intent: {error}")))?;
    let intent: EraseIntent = serde_json::from_slice(&bytes)
        .map_err(|error| CalyxError::ledger_corrupt(format!("decode erase intent: {error}")))?;
    if intent.version != ERASE_INTENT_VERSION {
        return Err(CalyxError::ledger_corrupt(format!(
            "erase intent at {} has unsupported version {} (expected {ERASE_INTENT_VERSION})",
            path.display(),
            intent.version
        )));
    }
    Ok(Some(intent))
}

/// Removes the intent record for `scope` and fsyncs the directory. A missing
/// record is not an error (idempotent cleanup).
pub(super) fn remove_intent(root: &Path, scope: &EraseScope) -> Result<()> {
    let path = intent_path(root, scope);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(CalyxError::disk_pressure(format!(
                "remove erase intent {}: {error}",
                path.display()
            )));
        }
    }
    crate::fsync::sync_dir(&intent_dir(root), "erase intent")
}

fn replace_file(tmp: &Path, path: &Path) -> Result<()> {
    #[cfg(windows)]
    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|error| CalyxError::disk_pressure(format!("replace erase intent: {error}")))?;
    }
    std::fs::rename(tmp, path)
        .map_err(|error| CalyxError::disk_pressure(format!("rename erase intent: {error}")))
}
