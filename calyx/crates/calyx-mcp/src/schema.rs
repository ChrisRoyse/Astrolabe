//! JSON Schema constructors for MCP tool input declarations.
//!
//! Tool modules declare their `inputSchema` with these helpers instead of
//! hand-writing `json!` blocks, so every tool produces a consistent,
//! draft-07-compatible object schema (`type`/`properties`/`required`).

use serde_json::{Map, Value, json};

/// `{"type":"string"}`.
pub fn string_schema() -> Value {
    json!({ "type": "string" })
}

/// `{"type":"number"}`.
pub fn number_schema() -> Value {
    json!({ "type": "number" })
}

/// `{"type":"integer"}`.
pub fn integer_schema() -> Value {
    json!({ "type": "integer" })
}

/// `{"type":"boolean"}`.
pub fn boolean_schema() -> Value {
    json!({ "type": "boolean" })
}

/// `{"type":"array","items":<items>}`.
pub fn array_schema(items: Value) -> Value {
    json!({ "type": "array", "items": items })
}

/// Builds an object schema from `(name, sub-schema, required)` triples.
///
/// Property order follows the slice order. `required` lists only the entries
/// whose `bool` is `true`, and is always present (empty array when none are
/// required) so the wire shape is uniform.
pub fn object_schema(props: &[(&str, Value, bool)]) -> Value {
    let mut properties = Map::with_capacity(props.len());
    let mut required: Vec<Value> = Vec::new();
    for (name, schema, is_required) in props {
        properties.insert((*name).to_string(), schema.clone());
        if *is_required {
            required.push(Value::String((*name).to_string()));
        }
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": Value::Array(required),
    })
}
