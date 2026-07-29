use super::*;
pub(crate) const HEALTH_SURFACE_SCHEMA: &str = "astrolabe.health.v1";
pub(crate) const PERIODIC_VERIFY_CHAIN_SCHEMA: &str = "astrolabe.periodic_verify_chain.v1";
pub(crate) const PERIODIC_VERIFY_CHAIN_TICK_SCHEMA: &str =
    "astrolabe.periodic_verify_chain_tick.v1";

pub(crate) fn shadow_status_summary(project: &str) -> Result<Value, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    shadow_status_summary_at(&cache_dir, project)
}

pub(crate) fn shadow_status_summary_at(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    let lowering_debounce = drive_project_lowering(cache_dir, project)?;
    let sqlite_path = sqlite_path(cache_dir, project);
    let configured_vault_dir = read_config_value(cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(cache_dir, project));
    let lowered_path = read_config_value(cache_dir, &metadata_key(project, "lowered_sqlite_path"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| lowered_sqlite_path(cache_dir, project));
    let fingerprint = read_config_value(cache_dir, &metadata_key(project, "vault_fingerprint"))?;
    let ledger_seq = read_config_value(cache_dir, &metadata_key(project, "ledger_seq"))?
        .and_then(|value| value.parse::<u64>().ok());
    let new_cx_ids = read_config_value(cache_dir, &metadata_key(project, "new_cx_ids"))?
        .and_then(|value| value.parse::<usize>().ok());
    let reused_cx_ids = read_config_value(cache_dir, &metadata_key(project, "reused_cx_ids"))?
        .and_then(|value| value.parse::<usize>().ok());
    let graph_rows_written =
        read_config_value(cache_dir, &metadata_key(project, "graph_rows_written"))?
            .and_then(|value| value.parse::<usize>().ok());
    let edge_rows_written =
        read_config_value(cache_dir, &metadata_key(project, "edge_rows_written"))?
            .and_then(|value| value.parse::<usize>().ok());
    let panel_version = read_config_value(cache_dir, &metadata_key(project, "panel_version"))?
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(DEFAULT_PANEL_VERSION);
    // #96: one chain verify per index_status response. The result computed here is
    // shared with the content-freshness gate below instead of that gate re-walking
    // the whole ledger a second time within the same call.
    let (verify_status, verify_intact) = if configured_vault_dir.exists() {
        match astrolabe_ingest::verify_chain_vault_path(&configured_vault_dir) {
            Ok(report) => {
                let intact = report.is_intact();
                (report.status, intact)
            }
            Err(error) => (format!("error:{error}"), false),
        }
    } else {
        ("missing".to_string(), false)
    };
    let ledger_rows = read_config_value(cache_dir, &metadata_key(project, "ledger_rows"))?
        .and_then(|value| value.parse::<u64>().ok());
    let lowered_exists = lowered_path.exists();
    // Content-verified shadow freshness (#93): recomputes the live CBM SQLite
    // fingerprint and compares it to the persisted watermark rather than trusting
    // artifact existence. (`verify_status`/`lowered_exists` above remain the raw
    // structural inputs the health surface reports.)
    let content_verdict = evaluate_shadow_content_freshness_with_verify(
        cache_dir,
        project,
        Some(KnownChainVerify {
            vault_dir: &configured_vault_dir,
            intact: verify_intact,
        }),
    )?;
    let background_lane = background_lane_status_at(cache_dir, project)?;
    let periodic_verify = periodic_verify_status_at(cache_dir, project)?;
    let health = health_surface_json(
        project,
        &verify_status,
        lowered_exists,
        ledger_seq,
        ledger_rows,
        Some(&background_lane),
        Some(&periodic_verify),
    );

    Ok(json!({
        "calyx": "shadow",
        "vault_fingerprint": fingerprint,
        "vault_ledger_head": ledger_seq,
        "panel_version": panel_version,
        "shadow_import": shadow_import_current_summary(&content_verdict),
        "background_lane": background_lane,
        "periodic_verify": periodic_verify,
        "health": health,
        "idempotency": {
            "new_cx_ids": new_cx_ids,
            "reused_cx_ids": reused_cx_ids,
            "graph_rows_written": graph_rows_written,
            "edge_rows_written": edge_rows_written,
            "cx_id_set_sha256": read_config_value(cache_dir, &metadata_key(project, "cx_id_set_sha256"))?,
        },
        "vault_import": vault_import_summary(
            read_config_value(cache_dir, &metadata_key(project, "vault_import_source"))?
                .as_deref()
                .unwrap_or("unknown"),
            read_config_value(cache_dir, &metadata_key(project, "vault_import_fallback_reason"))?
                .as_deref(),
        ),
        "security_screen": read_security_screen_metadata(cache_dir, project)?,
        "search_scale": read_search_scale_metadata(cache_dir, project)?,
        "skill_tree": read_skill_tree_metadata(cache_dir, project)?,
        "bridges": read_bridges_metadata(cache_dir, project)?,
        "kernel_context": read_kernel_context_metadata(cache_dir, project)?,
        "anomalies": read_anomaly_report(cache_dir, project)?,
        "provenance": read_provenance_metadata(cache_dir, project)?,
        "invalidations": read_invalidation_metadata(cache_dir, project)?,
        "lowering_debounce": lowering_debounce,
        "lowered_sqlite": lowered_summary(
            &lowered_path,
            read_config_value(cache_dir, &metadata_key(project, "lowered_artifact_sha256"))?.as_ref(),
            read_config_value(cache_dir, &metadata_key(project, "lowered_vault_fingerprint_sha256"))?.as_ref(),
            read_config_value(cache_dir, &metadata_key(project, "lowered_manifest_seq"))?
                .and_then(|value| value.parse::<u64>().ok()),
            read_config_value(cache_dir, &metadata_key(project, "lowered_nodes"))?
                .and_then(|value| value.parse::<usize>().ok()),
            read_config_value(cache_dir, &metadata_key(project, "lowered_edges"))?
                .and_then(|value| value.parse::<usize>().ok()),
            read_config_value(cache_dir, &metadata_key(project, "lowered_skipped_edges"))?
                .and_then(|value| value.parse::<usize>().ok()),
        ),
        "stores": stores_summary(&sqlite_path, &configured_vault_dir, Some(&lowered_path)),
        "vault": {
            "dir": configured_vault_dir,
            "id": read_config_value(cache_dir, &metadata_key(project, "vault_id"))?
                .unwrap_or_else(|| SHADOW_VAULT_ID.to_string()),
            "salt": read_config_value(cache_dir, &metadata_key(project, "vault_salt"))?
                .unwrap_or_else(|| vault_salt(project)),
            "ledger_head": ledger_seq,
            "verify_chain": verify_status,
        },
    }))
}

#[derive(Debug, Clone)]
pub(crate) struct PeriodicVerifyProject {
    pub(crate) project: String,
    pub(crate) vault_dir: PathBuf,
}

pub(crate) fn periodic_verify_chain_tick() -> Result<Value, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    periodic_verify_chain_tick_at(&cache_dir)
}

pub(crate) fn periodic_verify_chain_tick_at(cache_dir: &Path) -> Result<Value, DynError> {
    let checked_at_unix_ms = unix_epoch_millis();
    let projects = discover_periodic_verify_projects_at(cache_dir)?;
    let mut results = Vec::with_capacity(projects.len());
    for project in projects {
        results.push(periodic_verify_project_at(
            cache_dir,
            &project.project,
            &project.vault_dir,
            checked_at_unix_ms,
        )?);
    }
    Ok(json!({
        "schema": PERIODIC_VERIFY_CHAIN_TICK_SCHEMA,
        "checked_at_unix_ms": checked_at_unix_ms,
        "checked_projects": results.len(),
        "results": results,
        "freshness": "fresh",
        "trust": "verified",
    }))
}

pub(crate) fn discover_periodic_verify_projects_at(
    cache_dir: &Path,
) -> Result<Vec<PeriodicVerifyProject>, DynError> {
    let conn = open_config(cache_dir)?;
    let pattern = format!("{CONFIG_KEY_PREFIX}%.vault_dir");
    let mut statement =
        conn.prepare("SELECT key, value FROM config WHERE key LIKE ? ORDER BY key")?;
    let rows = statement.query_map(params![pattern], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut projects = Vec::new();
    for row in rows {
        let (key, vault_dir) = row?;
        let Some(project) = project_from_metadata_key(&key, "vault_dir") else {
            continue;
        };
        if project.trim().is_empty() {
            continue;
        }
        projects.push(PeriodicVerifyProject {
            project,
            vault_dir: PathBuf::from(vault_dir),
        });
    }
    Ok(projects)
}

pub(crate) fn project_from_metadata_key(key: &str, field: &str) -> Option<String> {
    let suffix = format!(".{field}");
    key.strip_prefix(CONFIG_KEY_PREFIX)?
        .strip_suffix(&suffix)
        .map(ToOwned::to_owned)
}

/// The bounded per-tick outcome of one FSV janitor scrub step (#277). Carries the
/// persisted checkpoint watermark and the (bounded) slice this tick re-hashed —
/// never a whole-ledger count, so the cost is O(budget knob) regardless of ledger
/// length.
pub(crate) struct PeriodicScrubOutcome {
    pub(crate) status: String,
    pub(crate) verified_through: u64,
    pub(crate) scrubbed: bool,
    pub(crate) slice_start: Option<u64>,
    pub(crate) slice_end: Option<u64>,
    pub(crate) error_text: Option<String>,
    /// #178: the unforgeable [`astrolabe_domain::fsv::FsvAck`] envelope this tick
    /// earned, present only when the scrub committed a witnessed mutation (its
    /// checkpoint row + Measure entry were read back byte-identical and the paired
    /// ledger entry exists). `None` on an idle catch-up — labeled absence, never a
    /// fabricated `fsv:verified`.
    pub(crate) fsv: Option<Value>,
}

/// Serializes an [`astrolabe_domain::fsv::FsvAck`] into the server response
/// envelope's `fsv` block (#178). The `label` is minted by the ack itself
/// (`fsv:verified` for a full readback, `fsv:verified-sampled` for a sample) — the
/// server can only relay it, never assert it.
pub(crate) fn fsv_ack_envelope(ack: &astrolabe_domain::fsv::FsvAck) -> Value {
    json!({
        "label": ack.label(),
        "scope": ack.scope(),
        "full_readback": ack.is_full_readback(),
        "rows_read_back": ack.rows_read_back(),
        "bytes_read_back": ack.bytes_read_back(),
        "ledger_seq": ack.ledger_seq(),
        "ledger_entry_hash": ack.ledger_entry_hash(),
    })
}

/// Runs one bounded [`astrolabe_ingest::run_janitor_scrub_step`] against the
/// project's shadow vault, under the shadow-import lock so a concurrent
/// index_repository never races the scrub write (#277).
///
/// Returns `Ok(None)` when the shadow-import lock is held (an import is in
/// flight): the tick is skipped, labeled, and leaves the last persisted status
/// intact rather than blocking or re-walking. A fail-closed chain-damage refusal
/// surfaces as `status: "error"` with the refusal code, never a silent pass.
pub(crate) fn periodic_verify_scrub_project(
    cache_dir: &Path,
    project: &str,
    vault_dir: &Path,
) -> Result<Option<PeriodicScrubOutcome>, DynError> {
    // Serialize against the importer: the scrub commits a checkpoint row + Measure
    // ledger entry, so it must not run concurrently with a shadow import that is
    // itself appending to the same ledger.
    let Some(_shadow_import_lock) = try_shadow_import_lock(cache_dir, project)? else {
        return Ok(None);
    };
    let vault_id = read_config_value(cache_dir, &metadata_key(project, "vault_id"))?
        .unwrap_or_else(|| SHADOW_VAULT_ID.to_string());
    let vault_salt = read_config_value(cache_dir, &metadata_key(project, "vault_salt"))?
        .unwrap_or_else(|| vault_salt(project));
    // Writable handle: the scrub advances the persisted JanitorCheckpoint and
    // appends the witnessed Measure scrub record. selected_cfs=None (all CFs).
    let vault = open_shadow_vault_writable(vault_dir, &vault_id, &vault_salt, Vec::new())?;
    match astrolabe_ingest::run_janitor_scrub_step(&vault, None) {
        Ok(report) => {
            let checkpoint = report.checkpoint();
            let (slice_start, slice_end, fsv) = match &report {
                astrolabe_ingest::JanitorStepReport::Scrubbed { slice, ack, .. } => (
                    Some(slice.slice_start),
                    Some(slice.slice_end),
                    // #178: relay the scrub's real FsvAck envelope. The ack was
                    // minted by verify_committed (readback + ledger pairing), so
                    // this is a witnessed `fsv:verified`, not a server claim.
                    Some(fsv_ack_envelope(ack)),
                ),
                astrolabe_ingest::JanitorStepReport::CaughtUp { .. } => (None, None, None),
            };
            Ok(Some(PeriodicScrubOutcome {
                status: "intact".to_string(),
                verified_through: checkpoint.verified_through,
                scrubbed: report.scrubbed(),
                slice_start,
                slice_end,
                error_text: None,
                fsv,
            }))
        }
        Err(error) => Ok(Some(PeriodicScrubOutcome {
            // Fail closed: the janitor detected chain damage (or a corrupt
            // checkpoint) and made no mutation. Surface the exact refusal.
            status: "error".to_string(),
            verified_through: 0,
            scrubbed: false,
            slice_start: None,
            slice_end: None,
            error_text: Some(error.to_string()),
            fsv: None,
        })),
    }
}

pub(crate) fn periodic_verify_project_at(
    cache_dir: &Path,
    project: &str,
    vault_dir: &Path,
    checked_at_unix_ms: u64,
) -> Result<Value, DynError> {
    if !vault_dir.exists() {
        let status = "missing".to_string();
        persist_periodic_verify_status_at(
            cache_dir,
            project,
            &status,
            vault_dir,
            checked_at_unix_ms,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
        )?;
        return Ok(periodic_verify_result_json(
            project,
            &status,
            vault_dir,
            checked_at_unix_ms,
            None,
            None,
            None,
            None,
            None,
            false,
            "scrub",
            None,
        ));
    }

    // #277: bounded janitor scrub step instead of a full verify_chain re-walk on
    // every tick (the #96 anti-pattern). Cost is O(FSV janitor budget knob),
    // independent of ledger length. The one-time deep full-chain sweep now lives
    // in the named startup gate (`janitor_startup_verify_projects_at`).
    match periodic_verify_scrub_project(cache_dir, project, vault_dir)? {
        Some(outcome) => {
            let verified_through = Some(outcome.verified_through);
            persist_periodic_verify_status_at(
                cache_dir,
                project,
                &outcome.status,
                vault_dir,
                checked_at_unix_ms,
                verified_through,
                outcome.slice_start,
                outcome.slice_end,
                outcome.error_text.as_deref(),
                verified_through,
                outcome.scrubbed,
                outcome.fsv.as_ref(),
            )?;
            Ok(periodic_verify_result_json(
                project,
                &outcome.status,
                vault_dir,
                checked_at_unix_ms,
                verified_through,
                outcome.slice_start,
                outcome.slice_end,
                outcome.error_text.as_deref(),
                verified_through,
                outcome.scrubbed,
                "scrub",
                outcome.fsv.as_ref(),
            ))
        }
        None => {
            // Import in flight: the shadow-import lock is held. Skip this tick,
            // labeled, without overwriting the last persisted verify status.
            Ok(json!({
                "schema": PERIODIC_VERIFY_CHAIN_SCHEMA,
                "project": project,
                "status": "skipped_import_in_progress",
                "vault_dir": vault_dir,
                "checked_at_unix_ms": checked_at_unix_ms,
                "freshness": "fresh",
                "trust": "provisional",
                "mode": "skipped_import_in_progress",
                "remediation": "the shadow-import lock is held; the FSV janitor scrub tick was skipped and will resume from its persisted checkpoint on the next tick after the import releases the lock",
            }))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn periodic_verify_result_json(
    project: &str,
    status: &str,
    vault_dir: &Path,
    checked_at_unix_ms: u64,
    ledger_rows: Option<u64>,
    checked_range_start: Option<u64>,
    checked_range_end: Option<u64>,
    error_text: Option<&str>,
    verified_through: Option<u64>,
    scrubbed: bool,
    mode: &str,
    fsv: Option<&Value>,
) -> Value {
    json!({
        "schema": PERIODIC_VERIFY_CHAIN_SCHEMA,
        "project": project,
        "status": status,
        "vault_dir": vault_dir,
        "checked_at_unix_ms": checked_at_unix_ms,
        "ledger_rows": ledger_rows,
        "checked_range_start": checked_range_start,
        "checked_range_end": checked_range_end,
        "verified_through": verified_through,
        "scrubbed": scrubbed,
        "mode": mode,
        "fsv": fsv,
        "error": error_text,
        "freshness": "fresh",
        "trust": if status == "intact" { "verified" } else { "provisional" },
        "remediation": periodic_verify_remediation(status),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_periodic_verify_status_at(
    cache_dir: &Path,
    project: &str,
    status: &str,
    vault_dir: &Path,
    checked_at_unix_ms: u64,
    ledger_rows: Option<u64>,
    checked_range_start: Option<u64>,
    checked_range_end: Option<u64>,
    error_text: Option<&str>,
    verified_through: Option<u64>,
    scrubbed: bool,
    fsv: Option<&Value>,
) -> Result<(), DynError> {
    let mut conn = open_config(cache_dir)?;
    // #178: the last tick's FsvAck envelope, or empty when the tick performed no
    // witnessed mutation (idle / error / missing) — labeled absence on readback.
    let fsv_serialized = fsv
        .map(serde_json::to_string)
        .transpose()?
        .unwrap_or_default();
    // Atomic multi-key persist — a crash mid-write must not leave torn
    // periodic-verify metadata that a status reader would treat as current (#95).
    let tx = conn.transaction()?;
    for (key, value) in [
        ("periodic_verify_fsv", fsv_serialized),
        ("periodic_verify_status", status.to_string()),
        (
            "periodic_verify_checked_unix_ms",
            checked_at_unix_ms.to_string(),
        ),
        ("periodic_verify_vault_dir", vault_dir.display().to_string()),
        (
            "periodic_verify_ledger_rows",
            ledger_rows
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        (
            "periodic_verify_checked_range_start",
            checked_range_start
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        (
            "periodic_verify_checked_range_end",
            checked_range_end
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        (
            // #277: the persisted FSV-janitor checkpoint watermark this tick
            // resumed from / advanced to. Independent readback across ticks and
            // restarts proves the janitor never re-walks from genesis.
            "periodic_verify_verified_through",
            verified_through
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        (
            "periodic_verify_scrubbed",
            if scrubbed { "1" } else { "0" }.to_string(),
        ),
        (
            "periodic_verify_error",
            error_text.unwrap_or_default().to_string(),
        ),
    ] {
        tx.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            params![metadata_key(project, key), value],
        )?;
    }
    tx.commit()?;
    Ok(())
}

pub(crate) fn periodic_verify_status_at(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let Some(status) =
        read_config_value(cache_dir, &metadata_key(project, "periodic_verify_status"))?
    else {
        return Ok(periodic_verify_unobserved_json(project));
    };
    let checked_at_unix_ms =
        read_config_u64(cache_dir, project, "periodic_verify_checked_unix_ms")?;
    let ledger_rows = read_config_optional_u64(cache_dir, project, "periodic_verify_ledger_rows")?;
    let checked_range_start =
        read_config_optional_u64(cache_dir, project, "periodic_verify_checked_range_start")?;
    let checked_range_end =
        read_config_optional_u64(cache_dir, project, "periodic_verify_checked_range_end")?;
    let verified_through =
        read_config_optional_u64(cache_dir, project, "periodic_verify_verified_through")?;
    let scrubbed = read_config_value(
        cache_dir,
        &metadata_key(project, "periodic_verify_scrubbed"),
    )?
    .map(|value| value.trim() == "1")
    .unwrap_or(false);
    let vault_dir = read_config_value(
        cache_dir,
        &metadata_key(project, "periodic_verify_vault_dir"),
    )?
    .filter(|value| !value.trim().is_empty());
    let error = read_config_value(cache_dir, &metadata_key(project, "periodic_verify_error"))?
        .filter(|value| !value.trim().is_empty());
    // #178: the last tick's FsvAck envelope (labeled absence when the tick made no
    // witnessed mutation). Parsed back from the persisted JSON, never fabricated.
    let fsv = read_config_value(cache_dir, &metadata_key(project, "periodic_verify_fsv"))?
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| serde_json::from_str::<Value>(&value).ok());
    Ok(json!({
        "schema": PERIODIC_VERIFY_CHAIN_SCHEMA,
        "project": project,
        "status": status.clone(),
        "vault_dir": vault_dir,
        "checked_at_unix_ms": checked_at_unix_ms,
        "ledger_rows": ledger_rows,
        "checked_range_start": checked_range_start,
        "checked_range_end": checked_range_end,
        "verified_through": verified_through,
        "scrubbed": scrubbed,
        "fsv": fsv,
        "error": error,
        "freshness": "last_observed",
        "trust": if status == "intact" { "verified" } else { "provisional" },
        "remediation": periodic_verify_remediation(&status),
    }))
}

pub(crate) fn periodic_verify_unobserved_json(project: &str) -> Value {
    json!({
        "schema": PERIODIC_VERIFY_CHAIN_SCHEMA,
        "project": project,
        "status": "unobserved",
        "vault_dir": Value::Null,
        "checked_at_unix_ms": Value::Null,
        "ledger_rows": Value::Null,
        "checked_range_start": Value::Null,
        "checked_range_end": Value::Null,
        "verified_through": Value::Null,
        "scrubbed": false,
        "fsv": Value::Null,
        "error": Value::Null,
        "freshness": "unknown",
        "trust": "provisional",
        "remediation": "wait for the server periodic verify_chain loop or call index_status for immediate verify_chain readback",
    })
}

pub(crate) fn periodic_verify_remediation(status: &str) -> Value {
    match status {
        "intact" => Value::Null,
        "missing" => Value::String(
            "rerun index_repository with calyx=\"shadow\" so the server has a vault to verify"
                .to_string(),
        ),
        "error" => Value::String(
            "inspect the stored periodic_verify_error, then run astrolabe verify --deep before trusting vault-backed surfaces"
                .to_string(),
        ),
        _ => Value::String(
            "run astrolabe verify --deep and reindex before trusting vault-backed surfaces"
                .to_string(),
        ),
    }
}

pub(crate) fn health_surface_json(
    project: &str,
    verify_status: &str,
    lowered_exists: bool,
    ledger_head: Option<u64>,
    ledger_rows: Option<u64>,
    background_lane: Option<&Value>,
    periodic_verify: Option<&Value>,
) -> Value {
    let chain_intact = verify_status == "intact";
    let periodic_verify = periodic_verify
        .cloned()
        .unwrap_or_else(|| periodic_verify_unobserved_json(project));
    let mut blocking_checks = Vec::new();
    if !chain_intact {
        blocking_checks.push("verify_chain");
    }
    if !lowered_exists {
        blocking_checks.push("lowered_sqlite");
    }
    if ledger_head.is_none() {
        blocking_checks.push("ledger_head");
    }
    let ready = blocking_checks.is_empty();
    let trust = if ready { "verified" } else { "provisional" };
    let metrics_text = health_metrics_text(
        project,
        chain_intact,
        lowered_exists,
        ready,
        ledger_head,
        ledger_rows,
        &periodic_verify,
    );
    let trajectory_ndjson = health_trajectory_ndjson(
        project,
        verify_status,
        lowered_exists,
        ready,
        trust,
        background_lane,
        &periodic_verify,
    );

    json!({
        "schema": HEALTH_SURFACE_SCHEMA,
        "status": if ready { "ready" } else { "degraded" },
        "freshness": "fresh",
        "trust": trust,
        "readiness": {
            "ready": ready,
            "blocking_checks": blocking_checks,
            "remediation": if ready {
                Value::Null
            } else {
                Value::String("rerun index_status after shadow import completes; if verify_chain is not intact, run astrolabe verify --deep and reindex before trusting vault-backed surfaces".to_string())
            },
        },
        "chain_verify": {
            "status": verify_status,
            "intact": chain_intact,
            "gauge": if chain_intact { 1 } else { 0 },
            "ledger_head": ledger_head,
            "ledger_rows": ledger_rows,
        },
        "lowered_sqlite": {
            "exists": lowered_exists,
            "gauge": if lowered_exists { 1 } else { 0 },
        },
        "periodic_verify": periodic_verify,
        "metrics_format": "prometheus_text_v0",
        "metrics_text": metrics_text,
        "trajectory_format": "ndjson",
        "trajectory_ndjson": trajectory_ndjson,
    })
}

pub(crate) fn health_metrics_text(
    project: &str,
    chain_intact: bool,
    lowered_exists: bool,
    ready: bool,
    ledger_head: Option<u64>,
    ledger_rows: Option<u64>,
    periodic_verify: &Value,
) -> String {
    let project = prom_label_value(project);
    let mut lines = vec![
        "# TYPE astrolabe_verify_chain_intact gauge".to_string(),
        format!(
            "astrolabe_verify_chain_intact{{project=\"{project}\"}} {}",
            if chain_intact { 1 } else { 0 }
        ),
        "# TYPE astrolabe_lowered_sqlite_exists gauge".to_string(),
        format!(
            "astrolabe_lowered_sqlite_exists{{project=\"{project}\"}} {}",
            if lowered_exists { 1 } else { 0 }
        ),
        "# TYPE astrolabe_readiness gauge".to_string(),
        format!(
            "astrolabe_readiness{{project=\"{project}\"}} {}",
            if ready { 1 } else { 0 }
        ),
        "# TYPE astrolabe_periodic_verify_last_intact gauge".to_string(),
        format!(
            "astrolabe_periodic_verify_last_intact{{project=\"{project}\"}} {}",
            if periodic_verify_status_is_intact(periodic_verify) {
                1
            } else {
                0
            }
        ),
    ];
    if let Some(checked_at) = periodic_verify
        .get("checked_at_unix_ms")
        .and_then(Value::as_u64)
    {
        lines.push("# TYPE astrolabe_periodic_verify_checked_unix_ms gauge".to_string());
        lines.push(format!(
            "astrolabe_periodic_verify_checked_unix_ms{{project=\"{project}\"}} {checked_at}"
        ));
    }
    if let Some(ledger_head) = ledger_head {
        lines.push("# TYPE astrolabe_ledger_head gauge".to_string());
        lines.push(format!(
            "astrolabe_ledger_head{{project=\"{project}\"}} {ledger_head}"
        ));
    }
    if let Some(ledger_rows) = ledger_rows {
        lines.push("# TYPE astrolabe_ledger_rows gauge".to_string());
        lines.push(format!(
            "astrolabe_ledger_rows{{project=\"{project}\"}} {ledger_rows}"
        ));
    }
    lines.join("\n")
}

pub(crate) fn periodic_verify_status_is_intact(periodic_verify: &Value) -> bool {
    periodic_verify.get("status").and_then(Value::as_str) == Some("intact")
}

pub(crate) fn health_trajectory_ndjson(
    project: &str,
    verify_status: &str,
    lowered_exists: bool,
    ready: bool,
    trust: &str,
    background_lane: Option<&Value>,
    periodic_verify: &Value,
) -> String {
    let mut events = vec![json!({
        "schema": HEALTH_SURFACE_SCHEMA,
        "event": "shadow_health",
        "project": project,
        "verify_chain": verify_status,
        "lowered_sqlite_exists": lowered_exists,
        "ready": ready,
        "trust": trust,
    })];
    if let Some(background_lane) = background_lane {
        events.push(json!({
            "schema": HEALTH_SURFACE_SCHEMA,
            "event": "background_lane",
            "project": project,
            "status": background_lane.get("status").and_then(Value::as_str),
            "trust": background_lane.get("trust").and_then(Value::as_str),
        }));
    }
    events.push(json!({
        "schema": HEALTH_SURFACE_SCHEMA,
        "event": "periodic_verify_chain",
        "project": project,
        "status": periodic_verify.get("status").and_then(Value::as_str),
        "checked_at_unix_ms": periodic_verify.get("checked_at_unix_ms").and_then(Value::as_u64),
        "trust": periodic_verify.get("trust").and_then(Value::as_str),
    }));
    events
        .into_iter()
        .map(|event| serde_json::to_string(&event).expect("health event serializes"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One-time boot integrity gate (#277): re-hashes each discovered project's whole
/// persisted ledger chain from genesis in bounded slices via
/// [`astrolabe_ingest::janitor_startup_verify`] — the deliberate deep full sweep
/// the steady-state per-tick scrub never performs (#96) — and persists the
/// outcome so `index_status` surfaces a tampered store as `status: "error"` with
/// the exact refusal code.
///
/// Fails **closed** per project: a damaged chain is recorded as
/// `periodic_verify_status = "error"` with the janitor refusal, never a silent
/// pass. Returns the number of projects whose boot sweep failed closed.
/// Resolves the CBM cache dir and runs the one-time [`janitor_startup_verify_projects_at`]
/// boot gate over every discovered shadow project. Called once at server startup.
pub(crate) fn janitor_startup_verify_projects() -> Result<u64, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    janitor_startup_verify_projects_at(&cache_dir)
}

pub(crate) fn janitor_startup_verify_projects_at(cache_dir: &Path) -> Result<u64, DynError> {
    let checked_at_unix_ms = unix_epoch_millis();
    let projects = discover_periodic_verify_projects_at(cache_dir)?;
    let mut damaged = 0u64;
    for project in projects {
        if !project.vault_dir.exists() {
            continue;
        }
        let vault_id = read_config_value(cache_dir, &metadata_key(&project.project, "vault_id"))?
            .unwrap_or_else(|| SHADOW_VAULT_ID.to_string());
        let salt = read_config_value(cache_dir, &metadata_key(&project.project, "vault_salt"))?
            .unwrap_or_else(|| vault_salt(&project.project));
        let vault = match open_shadow_vault_read_only(
            &project.vault_dir,
            &vault_id,
            &salt,
            vec![ColumnFamily::Kv, ColumnFamily::Ledger],
        ) {
            Ok(vault) => vault,
            Err(error) => {
                damaged += 1;
                persist_periodic_verify_status_at(
                    cache_dir,
                    &project.project,
                    "error",
                    &project.vault_dir,
                    checked_at_unix_ms,
                    None,
                    None,
                    None,
                    Some(&error.to_string()),
                    None,
                    false,
                    None,
                )?;
                continue;
            }
        };
        match astrolabe_ingest::janitor_startup_verify(&vault, None) {
            Ok(slice) => {
                // Clean boot sweep: the persisted chain re-hashes end to end.
                let verified_through = Some(slice.checkpoint.verified_through);
                persist_periodic_verify_status_at(
                    cache_dir,
                    &project.project,
                    "intact",
                    &project.vault_dir,
                    checked_at_unix_ms,
                    verified_through,
                    Some(slice.slice_start),
                    Some(slice.slice_end),
                    None,
                    verified_through,
                    false,
                    None,
                )?;
            }
            Err(error) => {
                // Fail closed: a tampered/damaged chain is surfaced, never a pass.
                damaged += 1;
                persist_periodic_verify_status_at(
                    cache_dir,
                    &project.project,
                    "error",
                    &project.vault_dir,
                    checked_at_unix_ms,
                    None,
                    None,
                    None,
                    Some(&error.to_string()),
                    None,
                    false,
                    None,
                )?;
            }
        }
    }
    Ok(damaged)
}

pub(crate) fn prom_label_value(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\n' | '\r' => "_".chars().collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect()
}
