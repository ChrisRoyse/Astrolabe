use super::*;
pub(crate) const IMPUTE_FIELDS_SCHEMA: &str = "astrolabe.impute_fields.v1";

pub(crate) fn impute_fields_json_at(
    cache_dir: &Path,
    project: &str,
    target: &str,
    field: &str,
    write_as_trusted: bool,
) -> Result<Value, DynError> {
    if write_as_trusted {
        return Ok(json!({
            "schema": IMPUTE_FIELDS_SCHEMA,
            "project": project,
            "target": target,
            "field": field,
            "status": "refused",
            "code": "ASTRO_IMPUTE_TRUSTED_WRITE_REFUSED",
            "message": "imputed values are inferred/provisional and cannot be written as trusted data",
            "remediation": "serve the proposal with inferred/provisional tags, then require a separate trusted source before merging",
            "proposal_count": Value::Null,
            "proposals": [],
            "source": "request:write_as_trusted",
            "freshness": "fresh",
            "trust": "verified",
        }));
    }

    let key = metadata_key(project, "impute_fields_json");
    let Some(raw) = read_config_value(cache_dir, &key)? else {
        return Ok(json!({
            "schema": IMPUTE_FIELDS_SCHEMA,
            "project": project,
            "target": target,
            "field": field,
            "status": "unavailable",
            "proposal_count": Value::Null,
            "proposals": [],
            "source": format!("config:{key}:missing"),
            "freshness": "not_evaluated",
            "trust": "provisional",
            "reason": "imputation proposal store is not persisted for this project",
            "remediation": "run the oracle imputation pipeline and persist inferred/provisional proposals before calling impute_fields",
        }));
    };
    let value = match serde_json::from_str::<Value>(&raw) {
        Ok(value) => value,
        Err(error) => {
            return Ok(impute_fields_invalid_json(
                project,
                target,
                field,
                &key,
                format!("stored impute_fields_json invalid: {error}"),
            ));
        }
    };
    let value = match impute_fields_config_value(value, &key) {
        Ok(value) => value,
        Err(reason) => {
            return Ok(impute_fields_invalid_json(
                project, target, field, &key, reason,
            ));
        }
    };
    let proposals = value
        .get("proposals")
        .and_then(Value::as_array)
        .expect("validated imputation proposals array")
        .iter()
        .filter(|proposal| {
            proposal.get("target").and_then(Value::as_str) == Some(target)
                && proposal.get("field").and_then(Value::as_str) == Some(field)
        })
        .cloned()
        .collect::<Vec<_>>();
    let proposal_count = proposals.len();
    Ok(json!({
        "schema": IMPUTE_FIELDS_SCHEMA,
        "project": project,
        "target": target,
        "field": field,
        "status": "read",
        "proposal_count": proposal_count,
        "proposals": proposals,
        "source": format!("config:{key}"),
        "freshness": value.get("freshness").cloned().unwrap_or_else(|| json!("fresh")),
        "trust": value.get("trust").cloned().unwrap_or_else(|| json!("provisional")),
        "remediation": if proposal_count == 0 {
            Value::String("no inferred/provisional proposal matched the requested target and field".to_string())
        } else {
            Value::Null
        },
    }))
}

pub(crate) fn impute_fields_config_value(value: Value, key: &str) -> Result<Value, String> {
    let Some(object) = value.as_object() else {
        return Err("impute_fields_json must be an object".to_string());
    };
    if object.get("schema").and_then(Value::as_str) != Some(IMPUTE_FIELDS_SCHEMA) {
        return Err(format!(
            "impute_fields_json schema must be {IMPUTE_FIELDS_SCHEMA}"
        ));
    }
    if object.get("status").and_then(Value::as_str).is_none()
        || object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str).is_none()
    {
        return Err("impute_fields_json requires status, freshness, and trust labels".to_string());
    }
    let Some(proposals) = object.get("proposals").and_then(Value::as_array) else {
        return Err("impute_fields_json proposals must be an array".to_string());
    };
    for (index, proposal) in proposals.iter().enumerate() {
        if let Some(reason) = impute_field_proposal_invalid(proposal) {
            return Err(format!("impute_fields_json proposals[{index}] {reason}"));
        }
    }
    let mut out = object.clone();
    out.insert("source".to_string(), json!(format!("config:{key}")));
    Ok(Value::Object(out))
}

pub(crate) fn impute_field_proposal_invalid(proposal: &Value) -> Option<&'static str> {
    let Some(object) = proposal.as_object() else {
        return Some("must be an object");
    };
    if object.get("target").and_then(Value::as_str).is_none() {
        return Some("requires string target");
    }
    let Some(field) = object.get("field").and_then(Value::as_str) else {
        return Some("requires string field");
    };
    if !matches!(field, "doc" | "types" | "callees" | "tests") {
        return Some("field must be doc, types, callees, or tests");
    }
    if object.get("value").is_none() {
        return Some("requires value");
    }
    if object.get("freshness").and_then(Value::as_str).is_none()
        || object.get("trust").and_then(Value::as_str) != Some("provisional")
    {
        return Some("requires freshness and trust=provisional");
    }
    let tags = object.get("tags");
    if !json_string_array_contains(tags, "inferred")
        || !json_string_array_contains(tags, "provisional")
    {
        return Some("requires inferred and provisional tags");
    }
    if !json_string_array_nonempty(object.get("provenance")) {
        return Some("requires non-empty string provenance");
    }
    if field == "doc" && !imputed_doc_guard_check_passed(object.get("guard_check")) {
        return Some("doc proposals require guard_check.status=passed with labels and provenance");
    }
    None
}

pub(crate) fn imputed_doc_guard_check_passed(guard_check: Option<&Value>) -> bool {
    let Some(object) = guard_check.and_then(Value::as_object) else {
        return false;
    };
    object.get("status").and_then(Value::as_str) == Some("passed")
        && object.get("freshness").and_then(Value::as_str).is_some()
        && object.get("trust").and_then(Value::as_str).is_some()
        && json_string_array_nonempty(object.get("provenance"))
}

pub(crate) fn impute_fields_invalid_json(
    project: &str,
    target: &str,
    field: &str,
    key: &str,
    reason: impl Into<String>,
) -> Value {
    json!({
        "schema": IMPUTE_FIELDS_SCHEMA,
        "project": project,
        "target": target,
        "field": field,
        "status": "invalid",
        "proposal_count": Value::Null,
        "proposals": [],
        "source": format!("config:{key}"),
        "freshness": "fresh",
        "trust": "provisional",
        "reason": reason.into(),
        "remediation": "repair impute_fields_json before serving imputation proposals",
    })
}
