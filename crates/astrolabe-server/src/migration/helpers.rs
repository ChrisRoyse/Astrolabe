use super::*;

pub(crate) fn string_array_field(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn value_map(entries: impl IntoIterator<Item = (String, Value)>) -> Value {
    Value::Object(entries.into_iter().collect())
}

pub(crate) fn required_value_field<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a Value, DynError> {
    required_object(value, "object")?
        .get(field)
        .ok_or_else(|| format!("missing field {field}").into())
}

pub(crate) fn required_string_field(value: &Value, field: &str) -> Result<String, DynError> {
    required_value_field(value, field)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("field {field} must be a string").into())
}

pub(crate) fn required_u64_field(value: &Value, field: &str) -> Result<u64, DynError> {
    required_value_field(value, field)?
        .as_u64()
        .ok_or_else(|| format!("field {field} must be an unsigned integer").into())
}

pub(crate) fn required_object<'a>(
    value: &'a Value,
    context: &str,
) -> Result<&'a Map<String, Value>, DynError> {
    value
        .as_object()
        .ok_or_else(|| format!("{context} must be a JSON object").into())
}

pub(crate) fn unix_epoch_millis() -> u64 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

pub(crate) fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub(crate) fn json_string_array_nonempty(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty() && values.iter().all(Value::is_string))
}

pub(crate) fn json_string_array_contains(value: Option<&Value>, needle: &str) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(needle)))
}

pub(crate) fn augment_tool_result(result: &str, additions: Value) -> Result<String, DynError> {
    let additions = additions
        .as_object()
        .ok_or("tool result additions must be a JSON object")?;
    let mut value: Value = serde_json::from_str(result)?;
    if let Some(structured) = value
        .get_mut("structuredContent")
        .and_then(Value::as_object_mut)
    {
        merge_object(structured, additions);
    }

    if let Some(text) = value
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(|item| item.get_mut("text"))
        && let Some(raw_text) = text.as_str()
        && let Ok(mut text_value) = serde_json::from_str::<Value>(raw_text)
        && let Some(text_obj) = text_value.as_object_mut()
    {
        merge_object(text_obj, additions);
        *text = Value::String(serde_json::to_string(&text_value)?);
    }

    Ok(serde_json::to_string(&value)?)
}

pub(crate) fn merge_object(target: &mut Map<String, Value>, additions: &Map<String, Value>) {
    for (key, value) in additions {
        target.insert(key.clone(), value.clone());
    }
}

pub(crate) fn strip_calyx_arg(args: &Map<String, Value>) -> Result<String, DynError> {
    let mut sanitized = args.clone();
    sanitized.remove("calyx");
    sanitized.remove("calyx_search");
    // #198: an Astrolabe-side knob, never forwarded to the CBM tool, which would reject it as
    // an unknown argument.
    sanitized.remove("calyx_skills");
    Ok(serde_json::to_string(&Value::Object(sanitized))?)
}

pub(crate) fn index_project_from_args(
    args: &Map<String, Value>,
) -> Result<Option<String>, DynError> {
    Ok(string_arg(args, "repo_path")
        .map(astrolabe_bridge::cbm_project_name_from_path)
        .transpose()?)
}

pub(crate) fn status_project_from_args(
    args: &Map<String, Value>,
) -> Result<Option<String>, DynError> {
    for key in ["project", "project_name", "project_id", "projectName"] {
        if let Some(project) = string_arg(args, key) {
            if project.contains('/') || project.contains('\\') {
                return Ok(Some(astrolabe_bridge::cbm_project_name_from_path(project)?));
            }
            return Ok(Some(project.to_string()));
        }
    }
    Ok(None)
}

pub(crate) fn string_arg<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

pub(crate) fn project_from_tool_result(result: &str) -> Option<String> {
    let value: Value = serde_json::from_str(result).ok()?;
    value
        .get("structuredContent")
        .and_then(|content| content.get("project"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

/// Read the libcbm `delete_project` `status` field ("deleted" / "not_found" /
/// "delete_failed") out of a wrapped tool result. On an *error* result the C
/// handler emits no `structuredContent` (see `cbm_mcp_text_result` — it only
/// mirrors the payload into `structuredContent` when `is_error` is false), so
/// the status then lives ONLY in the `content[0].text` JSON. Probe both, so this
/// works for the success ("deleted") and error ("not_found"/"delete_failed")
/// results alike. Returns `None` when the field is absent or unparseable.
pub(crate) fn tool_result_c_status(result: &str) -> Option<String> {
    let value: Value = serde_json::from_str(result).ok()?;
    if let Some(status) = value
        .get("structuredContent")
        .and_then(|content| content.get("status"))
        .and_then(Value::as_str)
    {
        return Some(status.to_string());
    }
    let text = value
        .get("content")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)?;
    let text_value: Value = serde_json::from_str(text).ok()?;
    text_value
        .get("status")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

pub(crate) fn tool_result_is_error(result: &str) -> Result<bool, DynError> {
    let value: Value = serde_json::from_str(result)?;
    Ok(value
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

pub(crate) fn tool_error_result(message: impl Into<String>) -> Result<String, DynError> {
    Ok(serde_json::to_string(&json!({
        "content": [{"type": "text", "text": message.into()}],
        "isError": true,
    }))?)
}

pub(crate) fn tool_json_result(value: Value) -> Result<String, DynError> {
    let text = serde_json::to_string(&value)?;
    Ok(serde_json::to_string(&json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": value,
        "isError": false,
    }))?)
}

pub(crate) fn tool_json_error_result(value: Value) -> Result<String, DynError> {
    let text = serde_json::to_string(&value)?;
    Ok(serde_json::to_string(&json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": value,
        "isError": true,
    }))?)
}

pub(crate) fn refresh_value_artifact_hash(value: &mut Value) {
    let mut artifact_source = value.clone();
    if let Some(object) = artifact_source.as_object_mut() {
        object.remove("artifact_sha256");
    }
    let artifact_bytes = serde_json::to_vec(&artifact_source).unwrap_or_default();
    value["artifact_sha256"] = json!(hex_lower(&Sha256::digest(&artifact_bytes)));
}

pub(crate) fn jsonrpc_result_response(id: Value, result_raw: &str) -> Result<String, DynError> {
    let result: Value = serde_json::from_str(result_raw)?;
    Ok(serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    }))?)
}

pub(crate) fn cx_id_set_sha256(ids: &[calyx_core::CxId]) -> String {
    let mut sorted = ids.to_vec();
    sorted.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"astrolabe-shadow-cx-id-set-v1");
    for id in sorted {
        hasher.update(id.as_bytes());
    }
    hex_lower(&hasher.finalize())
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
