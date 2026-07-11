use super::*;

pub(crate) fn optimizer_kill_switch_json(astrolabe_anneal_env: Option<&str>) -> Value {
    let global_freeze = astrolabe_anneal_env.is_some_and(|value| value.trim() == "0");
    json!({
        "env_var": "ASTRO_ANNEAL",
        "source": "process_env",
        "value": astrolabe_anneal_env,
        "global_freeze": global_freeze,
        "tuning_allowed_by_env": !global_freeze,
        "freshness": "fresh",
        "trust": "verified",
        "remediation": if global_freeze {
            Value::String("unset ASTRO_ANNEAL or set it to a non-zero value before allowing optimizer mutations".to_string())
        } else {
            Value::Null
        },
    })
}

pub(crate) fn optimizer_freeze_status_json(
    cache_dir: &Path,
    project: &str,
    global_freeze: bool,
) -> Result<Value, DynError> {
    let key = metadata_key(project, "optimizer_freezes_json");
    let raw = read_config_value(cache_dir, &key)?;
    let mut knobs = Vec::<Value>::new();
    let mut status = "read";
    let mut trust = "verified";
    let mut reason = Value::Null;

    if let Some(raw) = raw {
        match serde_json::from_str::<Value>(&raw) {
            Ok(Value::Array(values)) => {
                knobs = values;
            }
            Ok(other) => {
                status = "invalid";
                trust = "provisional";
                reason = Value::String(format!(
                    "optimizer_freezes_json must be an array, found {}",
                    json_type_name(&other)
                ));
            }
            Err(error) => {
                status = "invalid";
                trust = "provisional";
                reason = Value::String(format!("stored optimizer_freezes_json invalid: {error}"));
            }
        }
    }

    let frozen_count = knobs.len();
    Ok(json!({
        "schema": "astrolabe.optimizer_freezes.v1",
        "status": status,
        "source": format!("config:{key}"),
        "freshness": "fresh",
        "trust": trust,
        "global_freeze": global_freeze,
        "knobs": knobs,
        "frozen_count": frozen_count,
        "reason": reason,
        "remediation": if status == "invalid" {
            Value::String("repair optimizer_freezes_json before allowing optimizer mutations".to_string())
        } else if global_freeze {
            Value::String("global ASTRO_ANNEAL=0 freeze blocks optimizer mutations even when no per-knob freeze is recorded".to_string())
        } else {
            Value::Null
        },
    }))
}

pub(crate) fn optimizer_guard_health_json(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let security_screen = read_security_screen_metadata(cache_dir, project)?;
    let security_screen_status = security_screen
        .get("status")
        .cloned()
        .unwrap_or(Value::Null);
    let key = metadata_key(project, "optimizer_guard_health_json");
    if let Some(raw) = read_config_value(cache_dir, &key)? {
        return Ok(match serde_json::from_str::<Value>(&raw) {
            Ok(value) => optimizer_guard_health_config_json(value, &key, security_screen_status),
            Err(error) => optimizer_guard_health_invalid_json(
                &key,
                format!("stored optimizer_guard_health_json invalid: {error}"),
                security_screen_status,
            ),
        });
    }
    Ok(json!({
        "status": "unavailable",
        "slot_count": Value::Null,
        "slots": [],
        "freshness": "not_evaluated",
        "trust": "provisional",
        "source": format!("config:{key}:missing"),
        "security_screen_status": security_screen_status,
        "reason": "per-slot FAR/FRR/drift calibration profiles are not persisted in the current shadow metadata",
        "remediation": "wire guard_calibrate profile storage and readback before reporting guard health as measured",
    }))
}

pub(crate) fn optimizer_guard_health_config_json(
    value: Value,
    key: &str,
    security_screen_status: Value,
) -> Value {
    let Some(object) = value.as_object() else {
        return optimizer_guard_health_invalid_json(
            key,
            "optimizer_guard_health_json must be an object",
            security_screen_status,
        );
    };
    if object.get("schema").and_then(Value::as_str) != Some(OPTIMIZER_GUARD_HEALTH_SCHEMA) {
        return optimizer_guard_health_invalid_json(
            key,
            format!("optimizer_guard_health_json schema must be {OPTIMIZER_GUARD_HEALTH_SCHEMA}"),
            security_screen_status,
        );
    }
    if object.get("status").and_then(Value::as_str) != Some("measured") {
        return optimizer_guard_health_invalid_json(
            key,
            "optimizer_guard_health_json status must be measured",
            security_screen_status,
        );
    }
    if object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return optimizer_guard_health_invalid_json(
            key,
            "optimizer_guard_health_json requires freshness and trust labels",
            security_screen_status,
        );
    }
    let Some(slots) = object.get("slots").and_then(Value::as_array) else {
        return optimizer_guard_health_invalid_json(
            key,
            "optimizer_guard_health_json slots must be an array",
            security_screen_status,
        );
    };
    for (index, slot) in slots.iter().enumerate() {
        if let Some(reason) = optimizer_guard_health_slot_invalid(slot) {
            return optimizer_guard_health_invalid_json(
                key,
                format!("optimizer_guard_health_json slots[{index}] {reason}"),
                security_screen_status,
            );
        }
    }

    let mut out = object.clone();
    out.insert("slot_count".to_string(), json!(slots.len()));
    out.insert("source".to_string(), json!(format!("config:{key}")));
    out.insert("security_screen_status".to_string(), security_screen_status);
    out.insert(
        "remediation".to_string(),
        object.get("remediation").cloned().unwrap_or(Value::Null),
    );
    Value::Object(out)
}

pub(crate) fn optimizer_guard_health_slot_invalid(slot: &Value) -> Option<&'static str> {
    let Some(object) = slot.as_object() else {
        return Some("must be an object");
    };
    if object.get("slot").and_then(Value::as_str).is_none() {
        return Some("requires string slot");
    }
    for field in ["far", "frr", "drift"] {
        if object.get(field).and_then(Value::as_f64).is_none() {
            return Some("requires numeric far, frr, and drift fields");
        }
    }
    if object
        .get("last_calibrated_ledger_seq")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Some("requires last_calibrated_ledger_seq");
    }
    if object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return Some("requires freshness and trust labels");
    }
    None
}

pub(crate) fn optimizer_guard_health_invalid_json(
    key: &str,
    reason: impl Into<String>,
    security_screen_status: Value,
) -> Value {
    json!({
        "status": "invalid",
        "slot_count": Value::Null,
        "slots": [],
        "freshness": "fresh",
        "trust": "provisional",
        "source": format!("config:{key}"),
        "security_screen_status": security_screen_status,
        "reason": reason.into(),
        "remediation": "repair optimizer_guard_health_json before treating guard health as measured",
    })
}
