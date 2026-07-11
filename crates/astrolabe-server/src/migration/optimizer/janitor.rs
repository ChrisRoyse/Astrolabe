use super::*;

pub(crate) fn optimizer_budget_json(background_lane: &Value, janitor: Value) -> Value {
    let anneal_active = background_lane
        .get("lanes")
        .and_then(|lanes| lanes.get("anneal"))
        .and_then(|anneal| anneal.get("active"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    json!({
        "status": if anneal_active { "active" } else { "inactive" },
        "source": "background_lane_lock",
        "freshness": background_lane.get("freshness").and_then(Value::as_str).unwrap_or("fresh"),
        "trust": background_lane.get("trust").and_then(Value::as_str).unwrap_or("provisional"),
        "background_lane": background_lane,
        "janitor": janitor,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct OptimizerJanitorFile {
    pub(crate) path: PathBuf,
    pub(crate) relative_key: String,
    pub(crate) len: u64,
}

#[derive(Debug, Default)]
pub(crate) struct OptimizerJanitorScan {
    pub(crate) files: Vec<OptimizerJanitorFile>,
    pub(crate) symlink_entries: usize,
    pub(crate) special_entries: usize,
}

impl OptimizerJanitorScan {
    fn bytes_pending(&self) -> Result<u64, DynError> {
        let mut total = 0_u64;
        for file in &self.files {
            total = total
                .checked_add(file.len)
                .ok_or_else(|| "optimizer janitor pending byte count overflow".to_string())?;
        }
        Ok(total)
    }
}

pub(crate) fn optimizer_janitor_status_json_at(
    cache_dir: &Path,
    project: &str,
    max_bytes_per_tick: u64,
) -> Value {
    match optimizer_janitor_tick_json_at(cache_dir, project, max_bytes_per_tick) {
        Ok(value) => value,
        Err(error) => {
            let root = optimizer_janitor_root(cache_dir, project);
            json!({
                "schema": OPTIMIZER_JANITOR_SCHEMA,
                "status": "error",
                "active": false,
                "code": "ASTRO_OPTIMIZER_JANITOR_ERROR",
                "message": error.to_string(),
                "root": root,
                "max_bytes_per_tick": max_bytes_per_tick,
                "max_bytes_per_tick_source": "policy:P8.6-janitor-bound",
                "source": optimizer_janitor_source(&optimizer_janitor_root(cache_dir, project)),
                "freshness": "fresh",
                "trust": "provisional",
                "remediation": "inspect the janitor root permissions and retry optimizer_status before trusting artifact cleanup state",
            })
        }
    }
}

pub(crate) fn optimizer_janitor_tick_json_at(
    cache_dir: &Path,
    project: &str,
    max_bytes_per_tick: u64,
) -> Result<Value, DynError> {
    let root = optimizer_janitor_root(cache_dir, project);
    if max_bytes_per_tick == 0 {
        return Ok(json!({
            "schema": OPTIMIZER_JANITOR_SCHEMA,
            "status": "disabled",
            "active": false,
            "root": root,
            "root_exists": root.exists(),
            "max_bytes_per_tick": max_bytes_per_tick,
            "max_bytes_per_tick_source": "policy:P8.6-janitor-bound",
            "bytes_pending_before": Value::Null,
            "bytes_cleaned_last_tick": 0,
            "bytes_pending_after": Value::Null,
            "files_pending_before": Value::Null,
            "files_deleted_last_tick": 0,
            "files_pending_after": Value::Null,
            "skipped": Value::Null,
            "source": optimizer_janitor_source(&root),
            "freshness": "fresh",
            "trust": "verified",
            "reason": "janitor byte budget is zero",
            "remediation": "set a positive policy byte budget before relying on optimizer artifact cleanup",
        }));
    }

    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({
                "schema": OPTIMIZER_JANITOR_SCHEMA,
                "status": "empty",
                "active": true,
                "root": root,
                "root_exists": false,
                "max_bytes_per_tick": max_bytes_per_tick,
                "max_bytes_per_tick_source": "policy:P8.6-janitor-bound",
                "bytes_pending_before": 0,
                "bytes_cleaned_last_tick": 0,
                "bytes_pending_after": 0,
                "files_pending_before": 0,
                "files_deleted_last_tick": 0,
                "files_pending_after": 0,
                "skipped": {
                    "symlink_entries_before": 0,
                    "special_entries_before": 0,
                    "oversize_files_last_tick": 0,
                    "budget_deferred_files_last_tick": 0,
                    "delete_error_files_last_tick": 0,
                    "symlink_entries_after": 0,
                    "special_entries_after": 0,
                },
                "source": optimizer_janitor_source(&root),
                "freshness": "fresh",
                "trust": "verified",
                "reason": Value::Null,
                "remediation": Value::Null,
            }));
        }
        Err(error) => return Err(error.into()),
    };

    let file_type = metadata.file_type();
    if file_type.is_symlink() || !metadata.is_dir() {
        return Ok(json!({
            "schema": OPTIMIZER_JANITOR_SCHEMA,
            "status": "invalid_root",
            "active": false,
            "code": "ASTRO_OPTIMIZER_JANITOR_INVALID_ROOT",
            "root": root,
            "root_exists": true,
            "max_bytes_per_tick": max_bytes_per_tick,
            "max_bytes_per_tick_source": "policy:P8.6-janitor-bound",
            "bytes_pending_before": Value::Null,
            "bytes_cleaned_last_tick": 0,
            "bytes_pending_after": Value::Null,
            "files_pending_before": Value::Null,
            "files_deleted_last_tick": 0,
            "files_pending_after": Value::Null,
            "skipped": Value::Null,
            "source": optimizer_janitor_source(&root),
            "freshness": "fresh",
            "trust": "provisional",
            "reason": "optimizer janitor root is not a directory owned by this cache namespace",
            "remediation": "move or remove the invalid optimizer janitor root before retrying optimizer_status",
        }));
    }

    let scan_before = optimizer_janitor_scan(&root)?;
    let bytes_pending_before = scan_before.bytes_pending()?;
    let files_pending_before = scan_before.files.len();
    let mut bytes_cleaned = 0_u64;
    let mut files_deleted = 0_usize;
    let mut skipped_oversize = 0_usize;
    let mut skipped_budget = 0_usize;
    let mut delete_errors = Vec::<Value>::new();

    for file in &scan_before.files {
        if file.len > max_bytes_per_tick {
            skipped_oversize += 1;
            continue;
        }
        if bytes_cleaned > max_bytes_per_tick.saturating_sub(file.len) {
            skipped_budget += 1;
            continue;
        }
        match fs::remove_file(&file.path) {
            Ok(()) => {
                bytes_cleaned += file.len;
                files_deleted += 1;
            }
            Err(error) => {
                delete_errors.push(json!({
                    "path": file.path,
                    "relative_path": file.relative_key,
                    "message": error.to_string(),
                }));
            }
        }
    }

    let scan_after = optimizer_janitor_scan(&root)?;
    let bytes_pending_after = scan_after.bytes_pending()?;
    let files_pending_after = scan_after.files.len();
    let delete_error_count = delete_errors.len();
    let status = if delete_error_count > 0 {
        "partial"
    } else if files_pending_before == 0 {
        "empty"
    } else {
        "tick_complete"
    };
    let trust = if delete_error_count == 0 {
        "verified"
    } else {
        "provisional"
    };
    let remediation = if delete_error_count > 0 {
        Value::String(
            "inspect delete errors and permissions before trusting optimizer artifact cleanup state"
                .to_string(),
        )
    } else if skipped_oversize > 0 {
        Value::String(
            "split oversized optimizer artifacts or raise the policy after review; oversized files are not deleted by this tick"
                .to_string(),
        )
    } else if skipped_budget > 0 {
        Value::String("run another optimizer_status tick or background janitor tick to continue bounded cleanup".to_string())
    } else {
        Value::Null
    };

    Ok(json!({
        "schema": OPTIMIZER_JANITOR_SCHEMA,
        "status": status,
        "active": true,
        "root": root,
        "root_exists": true,
        "max_bytes_per_tick": max_bytes_per_tick,
        "max_bytes_per_tick_source": "policy:P8.6-janitor-bound",
        "bytes_pending_before": bytes_pending_before,
        "bytes_cleaned_last_tick": bytes_cleaned,
        "bytes_pending_after": bytes_pending_after,
        "files_pending_before": files_pending_before,
        "files_deleted_last_tick": files_deleted,
        "files_pending_after": files_pending_after,
        "skipped": {
            "symlink_entries_before": scan_before.symlink_entries,
            "special_entries_before": scan_before.special_entries,
            "oversize_files_last_tick": skipped_oversize,
            "budget_deferred_files_last_tick": skipped_budget,
            "delete_error_files_last_tick": delete_error_count,
            "symlink_entries_after": scan_after.symlink_entries,
            "special_entries_after": scan_after.special_entries,
        },
        "errors": delete_errors,
        "source": optimizer_janitor_source(&root),
        "freshness": "fresh",
        "trust": trust,
        "reason": Value::Null,
        "remediation": remediation,
    }))
}

pub(crate) fn optimizer_janitor_root(cache_dir: &Path, project: &str) -> PathBuf {
    cache_dir.join(format!("{project}{OPTIMIZER_JANITOR_DIR_SUFFIX}"))
}

pub(crate) fn optimizer_janitor_source(root: &Path) -> String {
    format!(
        "filesystem:astrolabe-owned-optimizer-artifacts:{}",
        root.display()
    )
}

pub(crate) fn optimizer_janitor_scan(root: &Path) -> Result<OptimizerJanitorScan, DynError> {
    let mut scan = OptimizerJanitorScan::default();
    optimizer_janitor_collect(root, root, &mut scan)?;
    scan.files
        .sort_by(|left, right| left.relative_key.cmp(&right.relative_key));
    Ok(scan)
}

pub(crate) fn optimizer_janitor_collect(
    root: &Path,
    dir: &Path,
    scan: &mut OptimizerJanitorScan,
) -> Result<(), DynError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir)? {
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            scan.symlink_entries += 1;
        } else if metadata.is_file() {
            scan.files.push(OptimizerJanitorFile {
                relative_key: optimizer_janitor_relative_key(root, &path),
                path,
                len: metadata.len(),
            });
        } else if metadata.is_dir() {
            optimizer_janitor_collect(root, &path, scan)?;
        } else {
            scan.special_entries += 1;
        }
    }
    Ok(())
}

pub(crate) fn optimizer_janitor_relative_key(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
