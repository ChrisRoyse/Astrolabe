use super::*;

pub(crate) fn optimizer_ack_triggers_json_at(
    cache_dir: &Path,
    project: &str,
    subscription_id: SubscriptionId,
) -> Result<Value, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(json!({
            "schema": OPTIMIZER_TRIGGER_ACK_SCHEMA,
            "status": "refused",
            "project": project,
            "subscription_id": subscription_id.to_string(),
            "code": "ASTRO_OPTIMIZER_ACK_VAULT_MISSING",
            "message": format!("shadow vault dir missing: {}", vault_dir.display()),
            "remediation": "rerun index_repository with calyx=\"shadow\" before acknowledging reactive triggers",
            "freshness": "fresh",
            "trust": "verified",
        }));
    }

    let vault = open_shadow_vault_writable(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Ledger, ColumnFamily::Reactive],
    )?;
    let report = match acknowledge_reactive_subscription(
        &vault,
        subscription_id,
        OPTIMIZER_TRIGGER_ACK_ACTOR.to_string(),
    ) {
        Ok(report) => report,
        Err(error) => {
            return Ok(json!({
                "schema": OPTIMIZER_TRIGGER_ACK_SCHEMA,
                "status": "refused",
                "project": project,
                "subscription_id": subscription_id.to_string(),
                "code": error.code,
                "message": error.message,
                "remediation": error.remediation,
                "freshness": "fresh",
                "trust": "verified",
            }));
        }
    };
    drop(vault);

    let readback = optimizer_reactive_triggers_json_result(cache_dir, project)?;
    let status = if report.acked_count == 0 {
        "noop"
    } else if report.pending_after == 0 {
        "acked"
    } else {
        "partial"
    };
    let trust = if report.pending_after == 0 {
        "verified"
    } else {
        "provisional"
    };
    let ledger_ref = report
        .ledger_ref
        .as_ref()
        .map(ledger_ref_json)
        .unwrap_or(Value::Null);
    Ok(json!({
        "schema": OPTIMIZER_TRIGGER_ACK_SCHEMA,
        "status": status,
        "project": project,
        "subscription_id": report.subscription_id.to_string(),
        "pending_before": report.pending_before,
        "acked_count": report.acked_count,
        "pending_after": report.pending_after,
        "ledger_ref": ledger_ref,
        "acknowledged_events": serde_json::to_value(&report.acknowledged_events)?,
        "readback": readback,
        "source": "AsterVault:ColumnFamily::Ledger",
        "freshness": "fresh",
        "trust": trust,
        "remediation": if report.pending_after == 0 {
            Value::Null
        } else {
            Value::String("inspect reactive trigger readback; pending events remained after acknowledgement".to_string())
        },
    }))
}

pub(crate) fn optimizer_tripwires_json(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    let key = metadata_key(project, "optimizer_tripwires_json");
    if let Some(raw) = read_config_value(cache_dir, &key)? {
        return Ok(match serde_json::from_str::<Value>(&raw) {
            Ok(value) => optimizer_tripwires_config_json(value, &key),
            Err(error) => optimizer_tripwires_invalid_json(
                &key,
                format!("stored optimizer_tripwires_json invalid: {error}"),
            ),
        });
    }
    let states = [
        "recall_at_k",
        "guard_far",
        "guard_frr",
        "search_p99",
        "ingest_p95",
    ]
    .into_iter()
    .map(|name| {
        json!({
            "name": name,
            "state": "not_armed",
            "measured_value": Value::Null,
            "threshold": Value::Null,
            "freshness": "not_evaluated",
            "trust": "provisional",
            "source": "anneal_engine:not_enabled_in_shadow_stage",
            "remediation": "wire the anneal shadow-test gate and persist measured tripwire state before treating this tripwire as armed",
        })
    })
    .collect::<Vec<_>>();

    Ok(json!({
        "status": "inactive",
        "state_count": states.len(),
        "states": states,
        "freshness": "not_evaluated",
        "trust": "provisional",
        "source": format!("config:{key}:missing"),
    }))
}

pub(crate) fn optimizer_tripwires_config_json(value: Value, key: &str) -> Value {
    let Some(object) = value.as_object() else {
        return optimizer_tripwires_invalid_json(key, "optimizer_tripwires_json must be an object");
    };
    if object.get("schema").and_then(Value::as_str) != Some(OPTIMIZER_TRIPWIRES_SCHEMA) {
        return optimizer_tripwires_invalid_json(
            key,
            format!("optimizer_tripwires_json schema must be {OPTIMIZER_TRIPWIRES_SCHEMA}"),
        );
    }
    let Some(states) = object.get("states").and_then(Value::as_array) else {
        return optimizer_tripwires_invalid_json(
            key,
            "optimizer_tripwires_json states must be an array",
        );
    };
    if object.get("status").and_then(Value::as_str).is_none()
        || object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return optimizer_tripwires_invalid_json(
            key,
            "optimizer_tripwires_json requires status, freshness, and trust labels",
        );
    }
    for (index, state) in states.iter().enumerate() {
        if let Some(reason) = optimizer_tripwire_state_invalid(state) {
            return optimizer_tripwires_invalid_json(
                key,
                format!("optimizer_tripwires_json states[{index}] {reason}"),
            );
        }
    }

    let mut out = object.clone();
    out.insert("state_count".to_string(), json!(states.len()));
    out.insert("source".to_string(), json!(format!("config:{key}")));
    out.insert(
        "remediation".to_string(),
        object.get("remediation").cloned().unwrap_or(Value::Null),
    );
    Value::Object(out)
}

pub(crate) fn optimizer_tripwire_state_invalid(state: &Value) -> Option<&'static str> {
    let Some(object) = state.as_object() else {
        return Some("must be an object");
    };
    if object.get("name").and_then(Value::as_str).is_none()
        || object.get("state").and_then(Value::as_str).is_none()
    {
        return Some("requires string name and state");
    }
    for field in ["measured_value", "threshold"] {
        if object.get(field).and_then(Value::as_f64).is_none() {
            return Some("requires numeric measured_value and threshold");
        }
    }
    if object
        .get("last_evaluated_ledger_seq")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Some("requires last_evaluated_ledger_seq");
    }
    if object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return Some("requires freshness and trust labels");
    }
    None
}

pub(crate) fn optimizer_tripwires_invalid_json(key: &str, reason: impl Into<String>) -> Value {
    json!({
        "status": "invalid",
        "state_count": Value::Null,
        "states": [],
        "freshness": "fresh",
        "trust": "provisional",
        "source": format!("config:{key}"),
        "reason": reason.into(),
        "remediation": "repair optimizer_tripwires_json before treating tripwire state as measured",
    })
}

pub(crate) fn optimizer_drift_alarms_json(cache_dir: &Path, project: &str) -> Value {
    match optimizer_drift_alarms_json_result(cache_dir, project) {
        Ok(value) => value,
        Err(error) => optimizer_unavailable_json(
            "drift_alarms",
            &format!("drift anomaly report read failed: {error}"),
            "repair anomaly report metadata or live XTerm/Assay/Reactive CF rows before trusting optimizer drift alarms",
        ),
    }
}

pub(crate) fn optimizer_drift_alarms_json_result(cache_dir: &Path, project: &str) -> Result<Value, DynError> {
    let report = read_anomaly_report(cache_dir, project)?;
    if report.get("status").and_then(Value::as_str) == Some("unavailable") {
        return Ok(json!({
            "status": "unavailable",
            "alarm_count": Value::Null,
            "alarms": [],
            "skipped_count": Value::Null,
            "skipped": [],
            "freshness": "not_evaluated",
            "trust": "provisional",
            "source": "detect_anomalies:kind=drift",
            "reason": report.get("reason").cloned().unwrap_or_else(|| json!("drift anomaly report unavailable")),
            "remediation": report.get("remediation").cloned().unwrap_or_else(|| json!("rerun index_repository with anomaly substrate metadata or live drift rows")),
        }));
    }

    let filtered = filter_anomaly_report_json(report, Some("drift"))?;
    let alarms = filtered
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let skipped = filtered
        .get("skipped")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let status = if !skipped.is_empty() {
        "partial"
    } else if alarms.is_empty() {
        "empty"
    } else {
        "read"
    };
    let trust = if filtered.get("trust").and_then(Value::as_str) == Some("verified")
        && skipped.is_empty()
    {
        "verified"
    } else {
        "provisional"
    };
    Ok(json!({
        "status": status,
        "alarm_count": alarms.len(),
        "alarms": alarms,
        "skipped_count": skipped.len(),
        "skipped": skipped,
        "freshness": filtered.get("freshness").cloned().unwrap_or_else(|| json!("fresh")),
        "trust": trust,
        "source": "detect_anomalies:kind=drift",
        "source_state": filtered.get("source_state").cloned().unwrap_or_else(|| json!({
            "source": format!("config:{}", metadata_key(project, "anomaly_report_json")),
        })),
        "artifact_sha256": filtered.get("artifact_sha256").cloned().unwrap_or(Value::Null),
    }))
}

pub(crate) fn optimizer_recent_changes_json(cache_dir: &Path, project: &str) -> Value {
    match optimizer_recent_changes_json_result(cache_dir, project) {
        Ok(value) => value,
        Err(error) => optimizer_unavailable_json(
            "recent_changes",
            &format!("ledger tail read failed: {error}"),
            "repair or reindex the shadow vault, then retry optimizer_status",
        ),
    }
}

pub(crate) fn optimizer_recent_changes_json_result(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(optimizer_unavailable_json(
            "recent_changes",
            &format!("shadow vault dir missing: {}", vault_dir.display()),
            "rerun index_repository with calyx=\"shadow\" before reading optimizer recent changes",
        ));
    }
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Ledger],
    )?;
    let snapshot = vault.snapshot();
    let mut entries = Vec::new();
    for (key, bytes) in vault.scan_cf_at(snapshot, ColumnFamily::Ledger)? {
        let key_seq = parse_aster_ledger_seq(&key)?;
        let entry = decode_ledger(&bytes)?;
        if entry.seq != key_seq {
            return Ok(optimizer_unavailable_json(
                "recent_changes",
                &format!(
                    "ledger key seq {key_seq} does not match encoded seq {}",
                    entry.seq
                ),
                "repair the Ledger CF before trusting optimizer recent changes",
            ));
        }
        if !entry.verify() {
            return Ok(optimizer_unavailable_json(
                "recent_changes",
                &format!("ledger entry {} failed hash verification", entry.seq),
                "repair the Ledger CF before trusting optimizer recent changes",
            ));
        }
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.seq);
    let total_rows = entries.len();
    let mut tail = entries
        .iter()
        .rev()
        .take(OPTIMIZER_RECENT_CHANGE_LIMIT)
        .map(ledger_entry_status_json)
        .collect::<Vec<_>>();
    tail.reverse();
    Ok(json!({
        "status": "read",
        "source": "AsterVault:ColumnFamily::Ledger",
        "vault_dir": vault_dir,
        "snapshot": snapshot,
        "limit": OPTIMIZER_RECENT_CHANGE_LIMIT,
        "ledger_rows_read": total_rows,
        "entry_count": tail.len(),
        "entries": tail,
        "freshness": "fresh",
        "trust": "verified",
    }))
}

pub(crate) fn optimizer_reactive_triggers_json(cache_dir: &Path, project: &str) -> Value {
    match optimizer_reactive_triggers_json_result(cache_dir, project) {
        Ok(value) => value,
        Err(error) => optimizer_unavailable_json(
            "reactive_triggers",
            &format!("reactive trigger recovery failed: {error}"),
            "repair or rebuild reactive Ledger/CF rows before trusting optimizer reactive trigger status",
        ),
    }
}

pub(crate) fn optimizer_reactive_triggers_json_result(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(optimizer_unavailable_json(
            "reactive_triggers",
            &format!("shadow vault dir missing: {}", vault_dir.display()),
            "rerun index_repository with calyx=\"shadow\" before reading reactive triggers",
        ));
    }
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Ledger, ColumnFamily::Reactive],
    )?;
    let state = recover_reactive_state(&vault)?;
    let subscriptions = state
        .subscriptions
        .iter()
        .map(|subscription| {
            json!({
                "subscription_id": subscription.subscription_id.to_string(),
                "trigger_id": subscription.trigger_id.to_string(),
                "condition": serde_json::to_value(&subscription.condition).unwrap_or(Value::Null),
                "owner": subscription.owner.clone(),
                "max_drain_buf": subscription.max_drain_buf,
                "created_ledger_seq": subscription.created_ledger_seq,
                "pending_count": subscription.pending_events.len(),
                "overflowed": subscription.overflowed,
                "pending_events": subscription.pending_events.iter()
                    .map(|event| serde_json::to_value(event).unwrap_or(Value::Null))
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let unacknowledged_count = state.pending_event_count();
    Ok(json!({
        "status": "read",
        "source": "AsterVault:ColumnFamily::Ledger+Reactive",
        "vault_dir": vault_dir,
        "subscription_count": state.subscriptions.len(),
        "fired_event_count": state.fired_events.len(),
        "unacknowledged_count": unacknowledged_count,
        "subscriptions": subscriptions,
        "ack": {
            "status": "enabled_durable_ledger_action",
            "mode": "ack_triggers",
            "freshness": "fresh",
            "trust": "verified",
            "remediation": if unacknowledged_count == 0 {
                Value::Null
            } else {
                Value::String("call optimizer_status with mode=\"ack_triggers\" and a subscription_id from this readback".to_string())
            },
        },
        "freshness": "fresh",
        "trust": "verified",
    }))
}
