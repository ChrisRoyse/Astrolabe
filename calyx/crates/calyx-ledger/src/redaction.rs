//! Explicit ledger payload retention and actor-redaction policy.

use calyx_core::InputRef;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::entry::ActorId;

/// Per-vault explicit retention and actor-redaction policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RedactionPolicy {
    pub store_raw_input: bool,
    pub redact_actor_name: bool,
}

impl RedactionPolicy {
    pub const fn new(store_raw_input: bool, redact_actor_name: bool) -> Self {
        Self {
            store_raw_input,
            redact_actor_name,
        }
    }

    /// Redacts the raw input pointer while preserving the stable content hash.
    pub const fn redact_input_ref(&self, input_ref: &InputRef) -> RedactedInput {
        RedactedInput {
            hash: input_ref.hash,
            redacted: true,
            pointer: None,
        }
    }

    /// Applies explicit raw-input retention to a richer payload builder.
    ///
    /// All non-raw field values are preserved through JSON serialization.
    /// Payload content is domain data and is never classified by the ledger
    /// layer.
    pub fn apply_to_payload(&self, raw: &PayloadBuilder) -> Vec<u8> {
        let filtered = filter_payload_value(raw.value(), self.store_raw_input);
        serde_json::to_vec(&filtered).expect("serde_json::Value serializes")
    }

    pub fn apply_to_actor(&self, actor: ActorId) -> ActorId {
        if !self.redact_actor_name {
            return actor;
        }
        match actor {
            ActorId::Agent(_) => ActorId::Agent("redacted".to_string()),
            ActorId::Service(_) => ActorId::Service("redacted".to_string()),
            ActorId::System => ActorId::System,
        }
    }
}

/// Input reference with the pointer explicitly omitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedInput {
    pub hash: [u8; 32],
    pub redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
}

/// Small JSON payload builder for explicit retention before append.
#[derive(Clone, Debug, PartialEq)]
pub struct PayloadBuilder {
    value: Value,
}

impl Default for PayloadBuilder {
    fn default() -> Self {
        Self::object()
    }
}

impl PayloadBuilder {
    pub fn object() -> Self {
        Self {
            value: Value::Object(Map::new()),
        }
    }

    pub fn from_value(value: Value) -> Self {
        Self { value }
    }

    pub fn insert_value(&mut self, key: impl Into<String>, value: Value) -> &mut Self {
        if !self.value.is_object() {
            self.value = Value::Object(Map::new());
        }
        self.value
            .as_object_mut()
            .expect("value was just normalized to object")
            .insert(key.into(), value);
        self
    }

    pub fn insert_str(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.insert_value(key, Value::String(value.into()))
    }

    pub fn insert_u64(&mut self, key: impl Into<String>, value: u64) -> &mut Self {
        self.insert_value(key, Value::Number(value.into()))
    }

    pub const fn value(&self) -> &Value {
        &self.value
    }
}

fn normalized_field(field: &str) -> String {
    field
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn filter_payload_value(value: &Value, store_raw_input: bool) -> Value {
    match value {
        Value::Object(map) => {
            let mut filtered = Map::new();
            for (key, child) in map {
                if key == "input_ref" {
                    filtered.insert(key.clone(), filter_input_ref(child));
                    continue;
                }
                if keep_payload_field(key, store_raw_input) {
                    filtered.insert(key.clone(), filter_payload_value(child, store_raw_input));
                }
            }
            Value::Object(filtered)
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|child| filter_payload_value(child, store_raw_input))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn filter_input_ref(value: &Value) -> Value {
    let mut filtered = Map::new();
    if let Some(hash) = value.get("hash") {
        filtered.insert("hash".to_string(), hash.clone());
    }
    filtered.insert("redacted".to_string(), Value::Bool(true));
    Value::Object(filtered)
}

fn keep_payload_field(field: &str, store_raw_input: bool) -> bool {
    let field = normalized_field(field);
    !is_raw_field(&field) || store_raw_input
}

fn is_raw_field(field: &str) -> bool {
    matches!(
        field,
        "raw" | "raw_bytes" | "raw_input" | "input_bytes" | "plaintext"
    ) || field.ends_with("_raw")
        || field.ends_with("_bytes")
}
