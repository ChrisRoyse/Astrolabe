use super::*;
pub(crate) const HEALTH_SURFACE_SCHEMA: &str = "astrolabe.health.v1";
pub(crate) const PERIODIC_VERIFY_CHAIN_SCHEMA: &str = "astrolabe.periodic_verify_chain.v2";
pub(crate) const PERIODIC_VERIFY_CHAIN_TICK_SCHEMA: &str =
    "astrolabe.periodic_verify_chain_tick.v3";
const VERIFY_CHAIN_STARTUP_READINESS_SCHEMA: &str = "astrolabe.verify_chain_startup_readiness.v1";
const VERIFY_CHAIN_STARTUP_READINESS_KEY: &str = "astrolabe.verify_chain_startup_readiness_json";
const STARTUP_VERIFY_OPERATION: &str = "janitor_startup_verify";
const STARTUP_VERIFY_ADMISSION_ORDER: &str = "completed_before_foreground_admission";
const PERIODIC_VERIFY_OPERATION: &str = "periodic_verify_scrub_project";
const PERIODIC_VERIFY_MISSING_OPERATION: &str = "periodic_verify_missing_vault_probe";
const PERIODIC_VERIFY_ADMISSION_ORDER: &str = "executed_after_foreground_admission";
pub(crate) const POST_PUBLISH_VERIFY_OPERATION: &str = "post_publish_verify_scrub_project";
const POST_PUBLISH_VERIFY_ADMISSION_ORDER: &str = "completed_before_index_success";

#[derive(Debug, Clone, Copy)]
pub(crate) struct JanitorStartupVerifyReport {
    pub(crate) discovered_projects: u64,
    pub(crate) checked_projects: u64,
    pub(crate) damaged_projects: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PeriodicVerifyChainTickSummary {
    pub(crate) checked_projects: u64,
    pub(crate) skipped_import_in_progress_projects: u64,
}

pub(crate) fn shadow_status_summary(project: &str) -> Result<Value, DynError> {
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    shadow_status_summary_at(&cache_dir, project)
}

pub(crate) fn shadow_status_summary_at(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    let lowering_debounce = lowering_status_snapshot(cache_dir, project)?;
    let sqlite_path = sqlite_path(cache_dir, project);
    let configured_vault_dir = read_config_value(cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(cache_dir, project));
    let lowered_path = read_config_value(cache_dir, &metadata_key(project, "lowered_sqlite_path"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| lowered_sqlite_path(cache_dir, project));
    let fingerprint = read_config_value(cache_dir, &metadata_key(project, "vault_fingerprint"))?;
    let shadow_ledger_checkpoint = configured_vault_dir
        .exists()
        .then(|| read_shadow_ledger_checkpoint(cache_dir, project))
        .transpose()?;
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
    let (verify_status, verify_intact, ledger_head, ledger_rows) = if configured_vault_dir.exists()
    {
        match astrolabe_ingest::verify_chain_vault_path(&configured_vault_dir) {
            Ok(report) => {
                let intact = report.is_intact();
                let ledger_head = report.checked_range_end.checked_sub(1);
                let ledger_rows = Some(report.ledger_rows);
                (report.status, intact, ledger_head, ledger_rows)
            }
            Err(error) => (format!("error:{error}"), false, None, None),
        }
    } else {
        ("missing".to_string(), false, None, None)
    };
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
        ledger_head,
        ledger_rows,
        Some(&background_lane),
        Some(&periodic_verify),
    );

    Ok(json!({
        "calyx": "shadow",
        "vault_fingerprint": fingerprint,
        "vault_ledger_head": ledger_head,
        "vault_ledger_rows": ledger_rows,
        "shadow_ledger_checkpoint": shadow_ledger_checkpoint,
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
        "security_screen": compact_persisted_surface_ref(
            cache_dir,
            project,
            "security_screen",
            "security_screen_json",
        )?,
        "search_scale": compact_persisted_surface_ref(
            cache_dir,
            project,
            "search_scale",
            "search_scale_json",
        )?,
        "skill_tree": compact_persisted_surface_ref(
            cache_dir,
            project,
            "skill_tree",
            "skill_tree_json",
        )?,
        "bridges": compact_persisted_surface_ref(
            cache_dir,
            project,
            "bridges",
            "bridge_reports_json",
        )?,
        "kernel_context": compact_persisted_surface_ref(
            cache_dir,
            project,
            "kernel_context",
            "kernel_context_json",
        )?,
        "anomalies": compact_persisted_surface_ref(
            cache_dir,
            project,
            "anomalies",
            "anomaly_report_json",
        )?,
        "provenance": compact_persisted_surface_ref(
            cache_dir,
            project,
            "provenance",
            "provenance_json",
        )?,
        "invalidations": compact_persisted_surface_ref(
            cache_dir,
            project,
            "invalidations",
            "invalidations_json",
        )?,
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
            "ledger_head": ledger_head,
            "ledger_rows": ledger_rows,
            "shadow_ledger_checkpoint": shadow_ledger_checkpoint,
            "verify_chain": verify_status,
        },
    }))
}

#[derive(Debug, Clone)]
pub(crate) struct PeriodicVerifyProject {
    pub(crate) project: String,
    pub(crate) vault_dir: PathBuf,
}

pub(crate) fn periodic_verify_chain_tick() -> Result<PeriodicVerifyChainTickSummary, DynError> {
    let _activation_fence =
        crate::activation_epoch::require_active_generation("periodic_verify_chain_tick")?;
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let report = periodic_verify_chain_tick_at(&cache_dir)?;
    let schema = report
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| -> DynError {
            "ASTRO_VERIFY_CHAIN_TICK_REPORT_INVALID: periodic verification report omitted required \
             string field 'schema'. Remediation: preserve the server log and inspect \
             periodic_verify_chain_tick_at report construction; do not infer a compatible report."
                .into()
        })?;
    if schema != PERIODIC_VERIFY_CHAIN_TICK_SCHEMA {
        return Err(format!(
            "ASTRO_VERIFY_CHAIN_TICK_REPORT_SCHEMA_MISMATCH: periodic verification report schema \
             '{schema}' does not match expected '{}'. Remediation: preserve the server log and \
             update the producer and consumer as one protocol generation.",
            PERIODIC_VERIFY_CHAIN_TICK_SCHEMA
        )
        .into());
    }
    let required_u64 = |field: &str| -> Result<u64, DynError> {
        report.get(field).and_then(Value::as_u64).ok_or_else(|| {
            format!(
                "ASTRO_VERIFY_CHAIN_TICK_REPORT_INVALID: periodic verification report schema \
                     '{}' omitted required u64 field '{field}'. Remediation: preserve the server \
                     log and inspect periodic_verify_chain_tick_at report construction; do not \
                     infer a zero count.",
                schema
            )
            .into()
        })
    };
    Ok(PeriodicVerifyChainTickSummary {
        checked_projects: required_u64("checked_projects")?,
        skipped_import_in_progress_projects: required_u64("skipped_import_in_progress_projects")?,
    })
}

pub(crate) fn periodic_verify_chain_tick_at(cache_dir: &Path) -> Result<Value, DynError> {
    let checked_at_unix_ms = unix_epoch_millis();
    let projects = discover_periodic_verify_projects_at(cache_dir)?;
    let mut results = Vec::with_capacity(projects.len());
    let mut skipped_import_in_progress_projects = 0u64;
    for project in projects {
        let result = periodic_verify_project_at(
            cache_dir,
            &project.project,
            &project.vault_dir,
            checked_at_unix_ms,
        )?;
        let status = result
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_VERIFY_CHAIN_PROJECT_REPORT_INVALID: periodic verification for project \
                     '{}' omitted required string field 'status'. Remediation: preserve the server \
                     log and inspect periodic_verify_project_at report construction; do not infer \
                     a completed scrub.",
                    project.project
                )
                .into()
            })?;
        if status == "skipped_import_in_progress" {
            skipped_import_in_progress_projects = skipped_import_in_progress_projects
                .checked_add(1)
                .ok_or_else(|| -> DynError {
                    "ASTRO_VERIFY_CHAIN_SKIP_COUNT_OVERFLOW: skipped-project telemetry exceeded \
                     u64. Remediation: preserve the server log and inspect project discovery for \
                     duplicate or unbounded rows."
                        .into()
                })?;
        }
        results.push(result);
    }
    let checked_projects = u64::try_from(results.len()).map_err(|error| -> DynError {
        format!(
            "ASTRO_VERIFY_CHAIN_PROJECT_COUNT_OVERFLOW: checked project count cannot be \
             represented as u64: {error}. Remediation: preserve the config database and inspect \
             project discovery cardinality."
        )
        .into()
    })?;
    Ok(json!({
        "schema": PERIODIC_VERIFY_CHAIN_TICK_SCHEMA,
        "checked_at_unix_ms": checked_at_unix_ms,
        "checked_projects": checked_projects,
        "skipped_import_in_progress_projects": skipped_import_in_progress_projects,
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

/// The logical per-tick outcome of one FSV janitor scrub step (#277). Carries the
/// persisted checkpoint watermark and the requested slice this tick re-hashed.
/// These fields do not characterize physical cost: vault open/materialization and
/// ledger-height discovery remain dependent on the real vault and ledger (#1064,
/// PC-03/PC-09/PC-40/PC-41).
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
    let Some(shadow_import_lock) = try_shadow_import_lock(cache_dir, project)? else {
        return Ok(None);
    };
    let identity_keys = [
        metadata_key(project, "vault_id"),
        metadata_key(project, "vault_salt"),
    ];
    let identity_values = read_config_values(cache_dir, &identity_keys)?;
    let vault_id = identity_values[0]
        .clone()
        .unwrap_or_else(|| SHADOW_VAULT_ID.to_string());
    let vault_salt = identity_values[1]
        .clone()
        .unwrap_or_else(|| vault_salt(project));
    scrub_project_with_import_owner(
        cache_dir,
        project,
        vault_dir,
        &vault_id,
        &vault_salt,
        &shadow_import_lock,
    )
    .map(Some)
}

/// Executes the mutating janitor slice under an already-acquired exact project
/// owner. This is shared by the periodic lane and the post-publication readiness
/// barrier so the latter never reacquires, waits on, or bypasses its own import
/// lock (#1085).
fn scrub_project_with_import_owner(
    cache_dir: &Path,
    project: &str,
    vault_dir: &Path,
    vault_id: &str,
    vault_salt: &str,
    shadow_import_lock: &ShadowImportLock,
) -> Result<PeriodicScrubOutcome, DynError> {
    shadow_import_lock.assert_owns(cache_dir, project)?;
    // Writable handle: the scrub advances the persisted JanitorCheckpoint and
    // appends the witnessed Measure scrub record. selected_cfs=None (all CFs).
    let vault = open_shadow_vault_writable(vault_dir, &vault_id, &vault_salt, Vec::new())?;
    scrub_open_vault(&vault)
}

fn scrub_project_with_generation_clock(
    cache_dir: &Path,
    project: &str,
    outcome: &ShadowImportOutcome,
    shadow_import_lock: &ShadowImportLock,
) -> Result<PeriodicScrubOutcome, DynError> {
    shadow_import_lock.assert_owns(cache_dir, project)?;
    let vault = open_shadow_vault_writable_with_generation_clock(
        &outcome.vault_dir,
        &outcome.vault_id,
        &outcome.vault_salt,
        outcome.generation_observed_at_ms,
    )?;
    scrub_open_vault(&vault)
}

fn scrub_open_vault<C: Clock>(vault: &AsterVault<C>) -> Result<PeriodicScrubOutcome, DynError> {
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
            Ok(PeriodicScrubOutcome {
                status: "intact".to_string(),
                verified_through: checkpoint.verified_through,
                scrubbed: report.scrubbed(),
                slice_start,
                slice_end,
                error_text: None,
                fsv,
            })
        }
        Err(error) => Ok(PeriodicScrubOutcome {
            // Fail closed: the janitor detected chain damage (or a corrupt
            // checkpoint) and made no mutation. Surface the exact refusal.
            status: "error".to_string(),
            verified_through: 0,
            scrubbed: false,
            slice_start: None,
            slice_end: None,
            error_text: Some(error.to_string()),
            fsv: None,
        }),
    }
}

/// Completes and reads back the first bounded scrub for a newly published shadow
/// generation before `index_repository` may return success (#1085).
///
/// Cost contract: exactly one call per artifact publication, while the existing
/// project import owner is still held. There is no request/poll loop here. Logical
/// verification is janitor-budget bounded; physical vault-open/materialization
/// cost remains dependent on the real vault and ledger (#1064 PC-03/09/40/41).
pub(crate) fn post_publish_verify_project(
    cache_dir: &Path,
    project: &str,
    outcome: &ShadowImportOutcome,
    shadow_import_lock: &ShadowImportLock,
) -> Result<Value, DynError> {
    let checked_at_unix_ms = unix_epoch_millis();
    let scrub = scrub_project_with_generation_clock(
        cache_dir,
        project,
        outcome,
        shadow_import_lock,
    )
    .map_err(|error| -> DynError {
        ToolFault::new(
            "ASTRO_POST_PUBLISH_VERIFY_EXECUTION_FAILED",
            format!(
                "project {project:?} published its artifact generation but the first scrub could not execute: {error}"
            ),
            "preserve the published source/lowered/vault/config generation and inspect the exact owner, vault-open, or scrub failure before retrying",
        )
        .with_detail("project", Value::String(project.to_string()))
        .with_detail(
            "vault_dir",
            Value::String(outcome.vault_dir.display().to_string()),
        )
        .with_detail("source_error", Value::String(error.to_string()))
        .into()
    })?;
    let verified_through = Some(scrub.verified_through);
    persist_periodic_verify_status_at(
        cache_dir,
        project,
        &scrub.status,
        &outcome.vault_dir,
        checked_at_unix_ms,
        verified_through,
        scrub.slice_start,
        scrub.slice_end,
        scrub.error_text.as_deref(),
        verified_through,
        scrub.scrubbed,
        scrub.fsv.as_ref(),
        POST_PUBLISH_VERIFY_OPERATION,
        POST_PUBLISH_VERIFY_ADMISSION_ORDER,
    )
    .map_err(|error| -> DynError {
        ToolFault::new(
            "ASTRO_POST_PUBLISH_VERIFY_STATUS_PERSIST_FAILED",
            format!(
                "project {project:?} published its artifact generation but could not persist the first scrub receipt: {error}"
            ),
            "preserve the published source/lowered/vault/config generation and inspect the exact config write failure before retrying",
        )
        .with_detail("project", Value::String(project.to_string()))
        .with_detail(
            "vault_dir",
            Value::String(outcome.vault_dir.display().to_string()),
        )
        .with_detail("source_error", Value::String(error.to_string()))
        .into()
    })?;

    // A successful config commit is not accepted as evidence by return value.
    // Re-open and parse the physical rows through the ordinary status read path,
    // then compare every readiness-bearing field to the exact write intent.
    let readback = periodic_verify_status_at(cache_dir, project).map_err(|error| -> DynError {
        ToolFault::new(
            "ASTRO_POST_PUBLISH_VERIFY_STATUS_READBACK_FAILED",
            format!(
                "project {project:?} published its artifact generation and wrote the first scrub receipt, but independent config readback failed: {error}"
            ),
            "preserve the published generation and inspect the exact config rows before retrying",
        )
        .with_detail("project", Value::String(project.to_string()))
        .with_detail(
            "vault_dir",
            Value::String(outcome.vault_dir.display().to_string()),
        )
        .with_detail("source_error", Value::String(error.to_string()))
        .into()
    })?;
    let expected = json!({
        "schema": PERIODIC_VERIFY_CHAIN_SCHEMA,
        "project": project,
        "status": scrub.status,
        "vault_dir": outcome.vault_dir.display().to_string(),
        "checked_at_unix_ms": checked_at_unix_ms,
        "ledger_rows": verified_through,
        "checked_range_start": scrub.slice_start,
        "checked_range_end": scrub.slice_end,
        "verified_through": verified_through,
        "scrubbed": scrub.scrubbed,
        "operation": POST_PUBLISH_VERIFY_OPERATION,
        "foreground_admission_order": POST_PUBLISH_VERIFY_ADMISSION_ORDER,
        "fsv": scrub.fsv,
        "error": scrub.error_text,
    });
    for (field, expected_value) in expected
        .as_object()
        .expect("post-publish expected receipt is a JSON object")
    {
        if readback.get(field) != Some(expected_value) {
            return Err(ToolFault::new(
                "ASTRO_POST_PUBLISH_VERIFY_STATUS_READBACK_MISMATCH",
                format!(
                    "project {project:?} field {field:?} expected {expected_value}, observed {}",
                    readback.get(field).unwrap_or(&Value::Null),
                ),
                "preserve the published generation and repair the exact torn or divergent config state before retrying",
            )
            .with_detail("project", Value::String(project.to_string()))
            .with_detail("field", Value::String(field.clone()))
            .with_detail("expected", expected_value.clone())
            .with_detail(
                "observed",
                readback.get(field).cloned().unwrap_or(Value::Null),
            )
            .with_detail("complete_readback", readback.clone())
            .into());
        }
    }
    if scrub.status != "intact" {
        let scrub_error = scrub
            .error_text
            .as_deref()
            .unwrap_or("unclassified scrub failure");
        return Err(ToolFault::new(
            "ASTRO_POST_PUBLISH_VERIFY_REFUSED",
            format!(
                "project {project:?} published its artifact generation but the first bounded scrub failed closed: {scrub_error}"
            ),
            "preserve the published generation and repair the exact reported vault/checkpoint damage before retrying",
        )
        .with_detail("project", Value::String(project.to_string()))
        .with_detail("scrub_error", Value::String(scrub_error.to_string()))
        .with_detail("persisted_readback", readback)
        .into());
    }
    Ok(readback)
}

fn caught_up_receipt_matches(
    cache_dir: &Path,
    project: &str,
    vault_dir: &Path,
    verified_through: u64,
) -> Result<bool, DynError> {
    let receipt = periodic_verify_status_at(cache_dir, project)?;
    let expected_vault_dir = vault_dir.display().to_string();
    Ok(
        receipt.get("schema").and_then(Value::as_str) == Some(PERIODIC_VERIFY_CHAIN_SCHEMA)
            && receipt.get("project").and_then(Value::as_str) == Some(project)
            && receipt.get("status").and_then(Value::as_str) == Some("intact")
            && receipt.get("vault_dir").and_then(Value::as_str)
                == Some(expected_vault_dir.as_str())
            && receipt.get("verified_through").and_then(Value::as_u64) == Some(verified_through)
            && receipt.get("operation").and_then(Value::as_str).is_some()
            && receipt
                .get("foreground_admission_order")
                .and_then(Value::as_str)
                .is_some()
            && receipt.get("error").is_some_and(Value::is_null),
    )
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
            PERIODIC_VERIFY_MISSING_OPERATION,
            PERIODIC_VERIFY_ADMISSION_ORDER,
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
            PERIODIC_VERIFY_MISSING_OPERATION,
        ));
    }

    // #277: the logical ledger slice is registry-bounded instead of deliberately
    // re-walking the chain from genesis. The physical vault-open/materialization
    // cost is not independent of ledger length and remains tracked by #1064
    // (PC-03/09/40/41). The deep full-chain sweep lives only in the startup gate.
    match periodic_verify_scrub_project(cache_dir, project, vault_dir)? {
        Some(outcome) => {
            let verified_through = Some(outcome.verified_through);
            // A caught-up slice has verified that the vault checkpoint already
            // reaches the current tail. When the durable receipt proves that same
            // fact, rewriting only its timestamp would be a permanent no-op write
            // tax and would create false state drift (#1085, #1064 PC-03/PC-28).
            // Any changed/error/absent receipt still persists normally.
            let persist = outcome.scrubbed
                || outcome.status != "intact"
                || !caught_up_receipt_matches(
                    cache_dir,
                    project,
                    vault_dir,
                    outcome.verified_through,
                )?;
            if persist {
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
                    PERIODIC_VERIFY_OPERATION,
                    PERIODIC_VERIFY_ADMISSION_ORDER,
                )?;
            }
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
                PERIODIC_VERIFY_OPERATION,
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
                "operation": PERIODIC_VERIFY_OPERATION,
                "foreground_admission_order": PERIODIC_VERIFY_ADMISSION_ORDER,
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
    operation: &str,
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
        "operation": operation,
        "foreground_admission_order": PERIODIC_VERIFY_ADMISSION_ORDER,
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
    operation: &str,
    foreground_admission_order: &str,
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
        ("periodic_verify_operation", operation.to_string()),
        (
            "periodic_verify_foreground_admission_order",
            foreground_admission_order.to_string(),
        ),
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
            // #277: the persisted logical checkpoint this tick resumed from or
            // advanced to. Independent readback proves logical continuity only;
            // physical vault open/materialization and ledger-height discovery may
            // still revisit earlier bytes (#1064 PC-40/PC-41).
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
    let keys = [
        metadata_key(project, "periodic_verify_status"),
        metadata_key(project, "periodic_verify_checked_unix_ms"),
        metadata_key(project, "periodic_verify_ledger_rows"),
        metadata_key(project, "periodic_verify_checked_range_start"),
        metadata_key(project, "periodic_verify_checked_range_end"),
        metadata_key(project, "periodic_verify_verified_through"),
        metadata_key(project, "periodic_verify_scrubbed"),
        metadata_key(project, "periodic_verify_vault_dir"),
        metadata_key(project, "periodic_verify_error"),
        metadata_key(project, "periodic_verify_fsv"),
        metadata_key(project, "periodic_verify_operation"),
        metadata_key(project, "periodic_verify_foreground_admission_order"),
        VERIFY_CHAIN_STARTUP_READINESS_KEY.to_string(),
    ];
    let values = read_config_values(cache_dir, &keys)?;
    let startup_readiness = parse_batched_config_json(&keys[12], values[12].as_deref())?;
    let Some(status) = values[0].as_deref() else {
        return Ok(periodic_verify_unobserved_json_with_startup(
            project,
            startup_readiness,
        ));
    };
    let checked_at_unix_ms = parse_batched_config_u64(&keys[1], values[1].as_deref(), false)?;
    let ledger_rows = parse_batched_config_u64(&keys[2], values[2].as_deref(), true)?;
    let checked_range_start = parse_batched_config_u64(&keys[3], values[3].as_deref(), true)?;
    let checked_range_end = parse_batched_config_u64(&keys[4], values[4].as_deref(), true)?;
    let verified_through = parse_batched_config_u64(&keys[5], values[5].as_deref(), true)?;
    let scrubbed = match values[6].as_deref() {
        None | Some("0") => false,
        Some("1") => true,
        Some(value) => {
            return Err(format!(
                "ASTRO_PERIODIC_VERIFY_SCRUBBED_CORRUPT: persisted config key {:?} is {value:?}, \
                 expected exactly \"0\" or \"1\". Remediation: repair the exact corrupt row \
                 before trusting periodic verification status.",
                keys[6],
            )
            .into());
        }
    };
    let vault_dir = values[7].as_deref().filter(|value| !value.is_empty());
    let error = values[8].as_deref().filter(|value| !value.is_empty());
    // #178: the last tick's FsvAck envelope (labeled absence when the tick made no
    // witnessed mutation). Parsed back from the persisted JSON, never fabricated.
    let fsv = parse_batched_config_json(&keys[9], values[9].as_deref())?;
    let operation = values[10].as_deref().filter(|value| !value.is_empty());
    let foreground_admission_order = values[11].as_deref().filter(|value| !value.is_empty());
    Ok(json!({
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
        "operation": operation,
        "foreground_admission_order": foreground_admission_order,
        "startup_readiness": startup_readiness,
        "fsv": fsv,
        "error": error,
        "freshness": "last_observed",
        "trust": if status == "intact" { "verified" } else { "provisional" },
        "remediation": periodic_verify_remediation(&status),
    }))
}

fn parse_batched_config_u64(
    key: &str,
    value: Option<&str>,
    empty_is_none: bool,
) -> Result<Option<u64>, DynError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if empty_is_none && value.is_empty() {
        return Ok(None);
    }
    value.parse::<u64>().map(Some).map_err(|error| {
        format!(
            "ASTRO_CONFIG_U64_CORRUPT: persisted config value for key {key:?} is {value:?}, \
             not an unsigned 64-bit integer{}: {error}. Remediation: repair or remove the \
             exact corrupt config row before retrying; Astrolabe will not substitute a default \
             for persisted invalid state.",
            if empty_is_none {
                " or the exact empty optional-value sentinel"
            } else {
                ""
            },
        )
        .into()
    })
}

fn parse_batched_config_json(key: &str, value: Option<&str>) -> Result<Option<Value>, DynError> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    serde_json::from_str::<Value>(value)
        .map(Some)
        .map_err(|error| {
            format!(
                "ASTRO_VERIFY_STATUS_JSON_CORRUPT: persisted config value for key {key:?} is \
                 not valid JSON: {error}. Remediation: preserve and inspect the exact corrupt \
                 row before repairing it; Astrolabe will not report malformed verification \
                 evidence as absent."
            )
            .into()
        })
}

pub(crate) fn periodic_verify_unobserved_json(project: &str) -> Value {
    periodic_verify_unobserved_json_with_startup(project, None)
}

fn periodic_verify_unobserved_json_with_startup(
    project: &str,
    startup_readiness: Option<Value>,
) -> Value {
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
        "operation": Value::Null,
        "foreground_admission_order": Value::Null,
        "startup_readiness": startup_readiness,
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
/// pass. Returns exact discovered, checked, and damaged project counts.
/// Resolves the CBM cache dir and runs the one-time [`janitor_startup_verify_projects_at`]
/// boot gate over every discovered shadow project. Called once at server startup.
pub(crate) fn janitor_startup_verify_projects(
    periodic_interval_ms: u64,
) -> Result<JanitorStartupVerifyReport, DynError> {
    let _activation_fence =
        crate::activation_epoch::require_active_generation("janitor_startup_verify_projects")?;
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    janitor_startup_verify_projects_at(&cache_dir, periodic_interval_ms)
}

pub(crate) fn janitor_startup_verify_projects_at(
    cache_dir: &Path,
    periodic_interval_ms: u64,
) -> Result<JanitorStartupVerifyReport, DynError> {
    let started_at_unix_ms = unix_epoch_millis();
    persist_verify_chain_startup_readiness_at(
        cache_dir,
        &json!({
            "schema": VERIFY_CHAIN_STARTUP_READINESS_SCHEMA,
            "status": "verifying",
            "operation": "janitor_startup_verify_projects",
            "foreground_admission": "blocked",
            "started_at_unix_ms": started_at_unix_ms,
            "completed_at_unix_ms": Value::Null,
            "discovered_projects": Value::Null,
            "checked_projects": Value::Null,
            "damaged_projects": Value::Null,
            "periodic_interval_ms": periodic_interval_ms,
            "first_periodic_tick_not_before_unix_ms": Value::Null,
            "error": Value::Null,
        }),
    )?;
    let result = janitor_startup_verify_projects_inner(cache_dir, started_at_unix_ms);
    match result {
        Ok(report) => {
            let completed_at_unix_ms = unix_epoch_millis();
            let ready = report.damaged_projects == 0;
            persist_verify_chain_startup_readiness_at(
                cache_dir,
                &json!({
                    "schema": VERIFY_CHAIN_STARTUP_READINESS_SCHEMA,
                    "status": if ready { "ready" } else { "refused_damaged_chain" },
                    "operation": "janitor_startup_verify_projects",
                    "foreground_admission": if ready { "released" } else { "refused" },
                    "started_at_unix_ms": started_at_unix_ms,
                    "completed_at_unix_ms": completed_at_unix_ms,
                    "discovered_projects": report.discovered_projects,
                    "checked_projects": report.checked_projects,
                    "damaged_projects": report.damaged_projects,
                    "periodic_interval_ms": periodic_interval_ms,
                    "first_periodic_tick_not_before_unix_ms": ready.then_some(
                        completed_at_unix_ms.saturating_add(periodic_interval_ms)
                    ),
                    "error": Value::Null,
                }),
            )?;
            Ok(report)
        }
        Err(error) => {
            let error_text = error.to_string();
            let readiness = json!({
                "schema": VERIFY_CHAIN_STARTUP_READINESS_SCHEMA,
                "status": "error",
                "operation": "janitor_startup_verify_projects",
                "foreground_admission": "refused",
                "started_at_unix_ms": started_at_unix_ms,
                "completed_at_unix_ms": unix_epoch_millis(),
                "discovered_projects": Value::Null,
                "checked_projects": Value::Null,
                "damaged_projects": Value::Null,
                "periodic_interval_ms": periodic_interval_ms,
                "first_periodic_tick_not_before_unix_ms": Value::Null,
                "error": error_text,
            });
            persist_verify_chain_startup_readiness_at(cache_dir, &readiness).map_err(
                |persist_error| -> DynError {
                    format!(
                        "ASTRO_VERIFY_CHAIN_STARTUP_TELEMETRY_FAILED: startup verification failed \
                         with {error}; persisting its terminal readiness state also failed with \
                         {persist_error}. Remediation: preserve and inspect the config database \
                         and vault bytes before restarting the server."
                    )
                    .into()
                },
            )?;
            Err(error)
        }
    }
}

fn janitor_startup_verify_projects_inner(
    cache_dir: &Path,
    checked_at_unix_ms: u64,
) -> Result<JanitorStartupVerifyReport, DynError> {
    let projects = discover_periodic_verify_projects_at(cache_dir)?;
    let discovered_projects = u64::try_from(projects.len()).map_err(|error| -> DynError {
        format!(
            "ASTRO_VERIFY_CHAIN_PROJECT_COUNT_OVERFLOW: discovered project count cannot be \
             represented as u64: {error}. Remediation: inspect the config project inventory \
             before restarting the server."
        )
        .into()
    })?;
    let mut checked_projects = 0u64;
    let mut damaged = 0u64;
    for project in projects {
        if !project.vault_dir.exists() {
            continue;
        }
        checked_projects = checked_projects.checked_add(1).ok_or_else(|| -> DynError {
            "ASTRO_VERIFY_CHAIN_PROJECT_COUNT_OVERFLOW: checked project count overflowed u64. \
             Remediation: inspect the config project inventory before restarting the server."
                .into()
        })?;
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
                damaged = damaged.checked_add(1).ok_or_else(|| -> DynError {
                    "ASTRO_VERIFY_CHAIN_PROJECT_COUNT_OVERFLOW: damaged project count overflowed \
                     u64. Remediation: inspect the config project inventory before restarting \
                     the server."
                        .into()
                })?;
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
                    STARTUP_VERIFY_OPERATION,
                    STARTUP_VERIFY_ADMISSION_ORDER,
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
                    STARTUP_VERIFY_OPERATION,
                    STARTUP_VERIFY_ADMISSION_ORDER,
                )?;
            }
            Err(error) => {
                // Fail closed: a tampered/damaged chain is surfaced, never a pass.
                damaged = damaged.checked_add(1).ok_or_else(|| -> DynError {
                    "ASTRO_VERIFY_CHAIN_PROJECT_COUNT_OVERFLOW: damaged project count overflowed \
                     u64. Remediation: inspect the config project inventory before restarting \
                     the server."
                        .into()
                })?;
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
                    STARTUP_VERIFY_OPERATION,
                    STARTUP_VERIFY_ADMISSION_ORDER,
                )?;
            }
        }
    }
    Ok(JanitorStartupVerifyReport {
        discovered_projects,
        checked_projects,
        damaged_projects: damaged,
    })
}

fn persist_verify_chain_startup_readiness_at(
    cache_dir: &Path,
    readiness: &Value,
) -> Result<(), DynError> {
    let serialized = serde_json::to_string(readiness)?;
    write_config_value(cache_dir, VERIFY_CHAIN_STARTUP_READINESS_KEY, &serialized)?;
    let readback = read_config_value(cache_dir, VERIFY_CHAIN_STARTUP_READINESS_KEY)?;
    if readback.as_deref() != Some(serialized.as_str()) {
        return Err(format!(
            "ASTRO_VERIFY_CHAIN_STARTUP_READBACK_MISMATCH: startup readiness config row did not \
             read back byte-exactly after persistence; expected {serialized:?}, observed \
             {readback:?}. Remediation: preserve and inspect the config database before \
             restarting the server."
        )
        .into());
    }
    Ok(())
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
