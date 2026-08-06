use super::*;

mod propose;
pub(crate) use propose::*;
mod deficits_producer;
mod triggers;
pub(crate) use triggers::*;
mod janitor;
pub(crate) use janitor::*;
mod profiles;
pub(crate) use profiles::*;
mod ledger;
pub(crate) use ledger::*;
pub(crate) const OPTIMIZER_STATUS_SCHEMA: &str = "astrolabe.optimizer_status.v1";
pub(crate) const OPTIMIZER_TRIGGER_ACK_SCHEMA: &str = "astrolabe.optimizer_trigger_ack.v1";
pub(crate) const OPTIMIZER_JANITOR_SCHEMA: &str = "astrolabe.optimizer_janitor.v1";
pub(crate) const OPTIMIZER_GUARD_HEALTH_SCHEMA: &str = "astrolabe.optimizer_guard_health.v1";
pub(crate) const OPTIMIZER_TRIPWIRES_SCHEMA: &str = "astrolabe.optimizer_tripwires.v1";
pub(crate) const OPTIMIZER_PROPOSALS_SCHEMA: &str = "astrolabe.optimizer_proposals.v1";
pub(crate) const OPTIMIZER_DEFICITS_SCHEMA: &str = "astrolabe.optimizer_deficits.v1";
pub(crate) const OPTIMIZER_RECENT_CHANGE_LIMIT: usize = 16;
pub(crate) const OPTIMIZER_JANITOR_DIR_SUFFIX: &str = ".astrolabe-optimizer-artifacts";
pub(crate) const OPTIMIZER_JANITOR_POLICY_MAX_BYTES_PER_TICK: u64 = 100 * 1024 * 1024;
pub(crate) const OPTIMIZER_TRIGGER_ACK_ACTOR: &str = "astrolabe-server-optimizer-status";

pub(crate) fn optimizer_status_json_at(
    cache_dir: &Path,
    project: &str,
    astrolabe_anneal_env: Option<&str>,
) -> Result<Value, DynError> {
    let (vault_dir, vault_id, _vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    let (verify_status, ledger_head, ledger_rows) = if vault_dir.exists() {
        match astrolabe_ingest::verify_chain_vault_path(&vault_dir) {
            Ok(report) => (
                report.status,
                report.checked_range_end.checked_sub(1),
                Some(report.ledger_rows),
            ),
            Err(error) => (format!("error:{error}"), None, None),
        }
    } else {
        ("missing".to_string(), None, None)
    };
    let shadow_ledger_checkpoint = vault_dir
        .exists()
        .then(|| read_shadow_ledger_checkpoint(cache_dir, project))
        .transpose()?;
    let background_lane = background_lane_status_at(cache_dir, project)?;
    let kill_switch = optimizer_kill_switch_json(astrolabe_anneal_env);
    let global_freeze = kill_switch["global_freeze"].as_bool().unwrap_or(false);
    let frozen_knobs = optimizer_freeze_status_json(cache_dir, project, global_freeze)?;
    let recent_changes = optimizer_recent_changes_json(cache_dir, project);
    let reactive_triggers = optimizer_reactive_triggers_json(cache_dir, project);
    let drift_alarms = optimizer_drift_alarms_json(cache_dir, project);
    let janitor = optimizer_janitor_status_json_at(
        cache_dir,
        project,
        OPTIMIZER_JANITOR_POLICY_MAX_BYTES_PER_TICK,
    );
    let status = if global_freeze { "frozen" } else { "inactive" };

    Ok(json!({
        "schema": OPTIMIZER_STATUS_SCHEMA,
        "project": project,
        "status": status,
        "freshness": "fresh",
        "trust": "provisional",
        "reason": "anneal optimizer workers are not enabled in the current shadow stage",
        "remediation": "use this surface as an operations readback; keep optimizer_status issue open until proposal, guard-profile, and live tripwire paths are wired and FSV-tested",
        "source_state": {
            "vault_dir": vault_dir,
            "vault_id": vault_id,
            "vault_salt_source": metadata_key(project, "vault_salt"),
            "chain_verify": verify_status,
            "ledger_head": ledger_head,
            "ledger_rows": ledger_rows,
            "shadow_ledger_checkpoint": shadow_ledger_checkpoint,
            "metadata_refs": [
                metadata_key(project, "vault_dir"),
                metadata_key(project, "vault_id"),
                metadata_key(project, "vault_salt"),
                metadata_key(project, SHADOW_LEDGER_CHECKPOINT_KEY),
                metadata_key(project, "optimizer_freezes_json"),
                metadata_key(project, "optimizer_deficits_json"),
                metadata_key(project, "optimizer_proposals_json")
            ],
        },
        "kill_switch": kill_switch,
        "frozen_knobs": frozen_knobs,
        "tripwires": optimizer_tripwires_json(cache_dir, project)?,
        "budget": optimizer_budget_json(&background_lane, janitor),
        "recent_changes": recent_changes,
        "pending_proposals": optimizer_pending_proposals_json(cache_dir, project)?,
        "guard_health": optimizer_guard_health_json(cache_dir, project)?,
        "guard_drift": drift_proposals_section(cache_dir, project),
        "commit_ood": commit_ood_reviews_section(cache_dir, project),
        "drift_alarms": drift_alarms,
        "reactive_triggers": reactive_triggers,
        "capabilities": {
            "status": "enabled",
            "propose": "enabled_from_measured_deficits_to_persisted_queue",
            "trigger_ack": "enabled_durable_ledger_action",
            "janitor": "enabled_budgeted_tick",
        },
    }))
}

pub(crate) fn shadow_vault_config_at(
    cache_dir: &Path,
    project: &str,
) -> Result<(PathBuf, String, String), DynError> {
    let vault_dir = read_config_value(cache_dir, &metadata_key(project, "vault_dir"))?
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_dir(cache_dir, project));
    let vault_id = read_config_value(cache_dir, &metadata_key(project, "vault_id"))?
        .unwrap_or_else(|| SHADOW_VAULT_ID.to_string());
    let vault_salt = read_config_value(cache_dir, &metadata_key(project, "vault_salt"))?
        .unwrap_or_else(|| vault_salt(project));
    Ok((vault_dir, vault_id, vault_salt))
}

pub(crate) fn optimizer_unavailable_json(section: &str, reason: &str, remediation: &str) -> Value {
    json!({
        "status": "unavailable",
        "section": section,
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": remediation,
    })
}
