//! `delete_project` host-side interceptor (#417).
//!
//! The libcbm `delete_project` handler erases only the project store itself —
//! `<name>.db` and its `-wal`/`-shm`. Every Astrolabe host-owned per-project
//! artifact (the lowered-SQLite mirror, the Aster vault, the lock family, the
//! search-index manifest, and the per-project config rows) is created by the
//! Rust host and was left orphaned on disk after a delete — post-#414 invisible
//! to enumeration, but still real bytes and a privacy/erasure concern (#61).
//!
//! This interceptor runs the C delete first (it closes the store, takes the
//! pipeline lock, and erases the `.db`), then removes the full host-side family,
//! **fail-closed per artifact**: a survivor is never silent — it is named, with
//! its OS error and a remediation, and turns the whole result into an error.
//!
//! ## Vault deletion semantics (the deliberate #61 decision)
//!
//! The Aster vault is an append-only, ledgered store, so the erasure doctrine
//! (`astrolabe-ingest::erasure_scrub`, #61/P9.3) asks whether a vault with
//! ledger entries should be *tombstoned* rather than raw-deleted. That doctrine
//! governs erasing **one subject's scope out of a vault that keeps living** — it
//! tombstones the scope's rows and scrubs the WAL so no plaintext survives while
//! the vault (and its immutable audit ledger) remain readable.
//!
//! `delete_project` is the opposite operation: the **entire** project — vault,
//! ledger and all — ceases to exist. Here the strongest and *only* correct
//! erasure posture is **full physical deletion of the vault directory**
//! (`remove_dir_all`), which unlinks the plaintext AND the WAL segments in one
//! step with zero residue. A `.tombstone` rename would do the exact opposite of
//! what this issue fixes: it would *retain* the erased plaintext under a renamed
//! path (the privacy hazard). A scrub-then-delete would be redundant — deleting
//! the directory already removes the WAL residue the scrub exists to reach. The
//! audit trail for the deletion is the labeled, per-artifact cleanup report this
//! interceptor returns (and the `index.*`/tool-result record it lands in), not a
//! surviving in-vault ledger — the vault it would live in is precisely what is
//! being destroyed. A durable host-level erasure *ledger* separate from the
//! per-project vault is #61/P9.3 territory, tracked there, not here.

use super::*;

/// Whether a per-project artifact is a single file or a directory subtree.
#[derive(Clone, Copy)]
enum SidecarKind {
    File,
    Dir,
}

/// One host-owned persisted artifact of a project, targeted for deletion.
struct Sidecar {
    path: PathBuf,
    kind: SidecarKind,
}

impl Sidecar {
    fn file(path: PathBuf) -> Self {
        Self {
            path,
            kind: SidecarKind::File,
        }
    }

    fn dir(path: PathBuf) -> Self {
        Self {
            path,
            kind: SidecarKind::Dir,
        }
    }

    /// Remove the artifact. `Ok(true)` = it existed and was removed; `Ok(false)`
    /// = it did not exist (nothing to do — a counted no-op, never a silent skip);
    /// `Err` = it is present but could not be removed (fail-closed: the caller
    /// names it as a survivor). `std::fs` is long-path safe on Windows via
    /// `maybe_verbatim`, so a deep sidecar path is not MAX_PATH-bound (#412/#415).
    fn remove(&self) -> Result<bool, std::io::Error> {
        let result = match self.kind {
            SidecarKind::File => fs::remove_file(&self.path),
            SidecarKind::Dir => fs::remove_dir_all(&self.path),
        };
        match result {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// Append raw bytes to a path without a lossy round-trip through `str`, so the
/// SQLite `-wal`/`-shm` companions and the `.guard` lock siblings are matched
/// byte-for-byte regardless of the (possibly non-UTF-8) cache dir.
fn appended(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

/// The canonical full family of host-owned persisted file/dir artifacts for a
/// project, built from the same suffix constants and path helpers the writers
/// use so cleanup and the sidecar identity can never drift. When a config store
/// already exists, a config-relocated lowered mirror or vault dir is resolved
/// from it (falling back to the default layout) so a relocated artifact is never
/// left orphaned. `has_config` gates the config read so this never *creates* a
/// `_config.db` as a side effect of a delete.
fn project_sidecars(
    cache_dir: &Path,
    project: &str,
    has_config: bool,
) -> Result<Vec<Sidecar>, DynError> {
    let lowered = if has_config {
        read_config_value(cache_dir, &metadata_key(project, "lowered_sqlite_path"))?
            .map(PathBuf::from)
            .unwrap_or_else(|| lowered_sqlite_path(cache_dir, project))
    } else {
        lowered_sqlite_path(cache_dir, project)
    };
    let vault = if has_config {
        read_config_value(cache_dir, &metadata_key(project, "vault_dir"))?
            .map(PathBuf::from)
            .unwrap_or_else(|| vault_dir(cache_dir, project))
    } else {
        vault_dir(cache_dir, project)
    };

    let mut sidecars = vec![
        // Lowered-SQLite mirror + its transient WAL/SHM companions.
        Sidecar::file(appended(&lowered, "-wal")),
        Sidecar::file(appended(&lowered, "-shm")),
        Sidecar::file(lowered),
        // Aster vault (append-only ledger dir) — full physical erasure, recursive
        // (see the module-level vault-semantics decision).
        Sidecar::dir(vault),
        // Search-index manifest.
        Sidecar::file(manifest_cache_path(cache_dir, project)),
    ];
    // Lock family. Each lock file may have a sibling `.lock.guard` (the
    // exclusive-lock holder written beside the observable marker via
    // `try_readable_marker_lock`); a lock without a guard simply yields a counted
    // no-op for the `.guard` entry. Delete the guard first, then the marker.
    for lock in [
        shadow_import_lock_path(cache_dir, project),
        background_lane_lock_path(cache_dir, project),
        lowered_sqlite_lock_path(cache_dir, project),
    ] {
        sidecars.push(Sidecar::file(appended(&lock, ".guard")));
        sidecars.push(Sidecar::file(lock));
    }
    Ok(sidecars)
}

/// The per-project config keys to clear: the migration dial (exact key) plus
/// every metadata row under the `astrolabe.calyx.<project>.` prefix (vault_dir,
/// lowered_sqlite_path, search-scale, …). The trailing dot on the metadata
/// prefix keeps a sibling project whose name is a prefix of this one untouched.
fn project_config_keys(cache_dir: &Path, project: &str) -> Result<Vec<String>, DynError> {
    let mut keys = vec![dial_key(project)];
    let metadata_prefix = format!("{}.", dial_key(project));
    for (key, _value) in scan_config_prefix(cache_dir, &metadata_prefix)? {
        keys.push(key);
    }
    Ok(keys)
}

pub(crate) fn handle_delete_project(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    // Delegate to the C handler FIRST: it closes the store if open, takes the
    // pipeline lock, and erases the project's `<name>.db` + `-wal`/`-shm`. Its
    // JSON result is the base we augment with the host-side cleanup report.
    let base_result = runner.handle_tool_raw("delete_project", args_json)?;

    // Resolve the project name exactly as the C handler did (same arg aliases +
    // path->name normalization) so the sidecar filenames match what was written.
    // A missing/invalid project means the C handler already reported it — return
    // its result untouched rather than inventing a second error.
    let args: Value = serde_json::from_str(args_json).unwrap_or(Value::Null);
    let project = match args.as_object() {
        Some(object) => status_project_from_args(object)?,
        None => None,
    };
    let Some(project) = project else {
        return Ok(base_result);
    };

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    // Guard every config-store touch on the store already existing: `open_config`
    // creates `_config.db` on open, and a delete must never leave a fresh empty
    // config store behind.
    let has_config = cache_dir.join("_config.db").exists();

    // Remove the file/dir sidecar family, fail-closed per artifact.
    let sidecars = project_sidecars(&cache_dir, &project, has_config)?;
    let mut removed: Vec<String> = Vec::new();
    let mut survived: Vec<Value> = Vec::new();
    for sidecar in &sidecars {
        match sidecar.remove() {
            Ok(true) => removed.push(sidecar.path.display().to_string()),
            Ok(false) => {}
            Err(error) => survived.push(json!({
                "path": sidecar.path.display().to_string(),
                "error": error.to_string(),
            })),
        }
    }

    // Clear the per-project config rows (dial + metadata) so a re-created project
    // never inherits a stale dial or a stale vault/lowered relocation. Only when
    // a config store already exists (see `has_config`).
    let mut config_cleared: Vec<String> = Vec::new();
    let mut config_survived: Vec<Value> = Vec::new();
    if has_config {
        match project_config_keys(&cache_dir, &project) {
            Ok(keys) => {
                for key in keys {
                    match delete_config_value(&cache_dir, &key) {
                        Ok(()) => config_cleared.push(key),
                        Err(error) => config_survived.push(json!({
                            "key": key,
                            "error": error.to_string(),
                        })),
                    }
                }
            }
            Err(error) => config_survived.push(json!({
                "scan_error": error.to_string(),
            })),
        }
    }

    let complete = survived.is_empty() && config_survived.is_empty();
    let cleanup = json!({
        "project": project,
        "vault_semantics": "physical_erasure",
        "removed": removed,
        "removed_count": removed.len(),
        "survived": survived,
        "survived_count": survived.len(),
        "config_rows_cleared": config_cleared,
        "config_rows_survived": config_survived,
        "complete": complete,
    });

    if complete {
        let base_was_error = tool_result_is_error(&base_result).unwrap_or(false);
        if !base_was_error {
            // Happy path: the C store delete succeeded ("deleted"). Fold the
            // cleanup report into the C result so the caller sees both the store
            // deletion outcome and exactly which sidecars were removed. Unchanged.
            return augment_tool_result(
                &base_result,
                json!({ "astrolabe_sidecar_cleanup": cleanup }),
            );
        }

        // The C store delete reported an error. Only a "not_found" is eligible
        // for the residue-recovery remap (#429): a genuine "delete_failed" means
        // `<name>.db` is present but its unlink failed — that MUST stay an error,
        // never masked. Read the C status (absent from structuredContent on an
        // error result, so `tool_result_c_status` also parses content[0].text).
        let c_status = tool_result_c_status(&base_result);
        // Did THIS call actually erase host-owned residue? Use the file/dir sidecar
        // removals (`removed`) as the signal: every ASTRO_DELETE_PROJECT_SIDECAR_
        // RESIDUE partial delete leaves at least one file/dir survivor (the locked
        // vault dir / lowered mirror), so on recovery it lands in `removed`. Config
        // rows are deliberately NOT part of this signal: `delete_config_value` is
        // idempotent and succeeds on an absent key, and `project_config_keys`
        // always prepends the dial key, so `config_cleared` is non-empty even for a
        // name that never existed — using it would misreport a genuine not-found as
        // a recovery. `removed` only ever contains artifacts that truly existed.
        let sidecars_cleaned_this_call = !removed.is_empty();

        if c_status.as_deref() == Some("not_found") && sidecars_cleaned_this_call {
            // #429 residue-recovery re-run: an earlier partial delete already
            // erased `<name>.db` (locked-vault residue left the sidecars behind),
            // so the C handler now legitimately reports not-found — but the host
            // sidecars really existed and were cleaned THIS call, so the documented
            // recovery SUCCEEDED. Report isError:false, carrying the C not-found as
            // data (`store_delete_status`) rather than letting it mask the success.
            let mut cleanup = cleanup;
            if let Some(object) = cleanup.as_object_mut() {
                object.insert("store_delete_status".to_string(), json!("not_found"));
                object.insert("recovered_from_residue".to_string(), json!(true));
            }
            return tool_json_result(json!({
                "project": project,
                // The resource as a whole no longer exists (db erased earlier +
                // sidecars erased now): the delete's intended effect is achieved.
                "status": "deleted",
                "store_delete_status": "not_found",
                "astrolabe_sidecar_cleanup": cleanup,
            }));
        }

        // Genuine full not-found (C not-found AND nothing to clean this call) or
        // any other C error (e.g. delete_failed): surface the C result unchanged,
        // augmented with the cleanup report so `removed_count` is visible.
        // `augment_tool_result` preserves the base isError, so the error stands.
        augment_tool_result(
            &base_result,
            json!({ "astrolabe_sidecar_cleanup": cleanup }),
        )
    } else {
        // Fail closed: the project store was erased but at least one host artifact
        // could not be removed. Name every survivor so partial deletion is never
        // silent, and surface the base outcome for context.
        let base_was_error = tool_result_is_error(&base_result).unwrap_or(false);
        tool_json_error_result(json!({
            "code": "ASTRO_DELETE_PROJECT_SIDECAR_RESIDUE",
            "message": format!(
                "delete_project erased the project store but {} host sidecar artifact(s) and {} \
                 config row(s) for project {project:?} could not be removed and remain on disk",
                survived.len(),
                config_survived.len(),
            ),
            "remediation":
                "Stop any process still holding these files (an in-progress index or an open \
                 lowered mirror/vault handle), then re-run delete_project; each surviving path is \
                 listed under astrolabe_sidecar_cleanup.survived / .config_rows_survived.",
            "base_store_delete_was_error": base_was_error,
            "astrolabe_sidecar_cleanup": cleanup,
        }))
    }
}
