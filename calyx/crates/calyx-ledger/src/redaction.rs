//! Ledger payload redaction and secret guardrails.

use calyx_core::{CalyxError, InputRef, METADATA_CHUNK_ID, METADATA_DATABASE_NAME, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::entry::ActorId;

const SECRET_TOKEN_MIN: usize = 40;
const MAX_HASH_OR_ID_LEN: usize = 64;
const MAX_DISCOVERY_MANIFEST_TOKEN_LEN: usize = 160;
const MAX_QUANT_SLOT_METADATA_LEN: usize = 4096;
const MAX_SOURCE_METADATA_LEN: usize = 128;
const MAX_STABLE_CODE_LEN: usize = 128;

/// Per-vault ledger redaction policy.
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

    /// Rejects payloads that contain secret-like fields or token material.
    pub fn check_payload(payload: &[u8]) -> Result<()> {
        Self::default().check_payload_with_policy(payload)
    }

    /// Rejects payloads using this policy's scanner settings.
    pub fn check_payload_with_policy(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        match serde_json::from_slice::<Value>(payload) {
            Ok(value) => check_json_value(&value, None),
            Err(_) => check_text_tokens(&String::from_utf8_lossy(payload), None),
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

    /// Builds a hash/id-only payload from a richer payload builder.
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

/// Hash-only input reference safe for ledger payloads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedInput {
    pub hash: [u8; 32],
    pub redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
}

/// Small JSON payload builder for redaction before append.
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

fn check_json_value(value: &Value, field: Option<&str>) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if is_secret_field(key) {
                    return Err(secret_error(format!(
                        "ledger payload field `{key}` is secret-like"
                    )));
                }
                check_json_value(child, Some(key))?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for child in values {
                check_json_value(child, field)?;
            }
            Ok(())
        }
        Value::String(text) => check_text_tokens(text, field),
        _ => Ok(()),
    }
}

fn check_text_tokens(text: &str, field: Option<&str>) -> Result<()> {
    if text.trim().is_empty() {
        return Ok(());
    }
    if text_has_no_space_printable_run(text) && !allowed_stable_identifier(text, field) {
        return Err(secret_error(
            "ledger payload contains a long non-whitespace token",
        ));
    }
    for token in token_candidates(text) {
        if token.len() >= SECRET_TOKEN_MIN && !allowed_stable_identifier(token, field) {
            return Err(secret_error("ledger payload contains a token-like secret"));
        }
    }
    Ok(())
}

fn token_candidates(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = None;
    for (index, ch) in text.char_indices() {
        if is_token_char(ch) {
            start.get_or_insert(index);
            continue;
        }
        if let Some(begin) = start.take() {
            out.push(&text[begin..index]);
        }
    }
    if let Some(begin) = start {
        out.push(&text[begin..]);
    }
    out
}

fn text_has_no_space_printable_run(text: &str) -> bool {
    text.chars().count() >= SECRET_TOKEN_MIN
        && text.chars().all(|ch| ch.is_ascii_graphic())
        && text.chars().all(|ch| !ch.is_whitespace())
}

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '_' | '-' | '.')
}

/// Field names whose values are provably a git object name, not a secret.
///
/// `git_sha` is the explicit provenance field; `commit` / `historical_commit`
/// are the import-archaeology metadata fields the Astrolabe shadow index and
/// git-archaeology writers populate with the HEAD / historical commit SHA. A
/// non-git shadow import records a short `shadow-import-v1:<project>` label that
/// never reaches this check.
const GIT_SHA_FIELDS: &[&str] = &["git_sha", "commit", "historical_commit"];

/// Field names whose values are a discovery/run manifest slug.
const MANIFEST_SLUG_FIELDS: &[&str] = &[
    "run_id",
    "corpus_vault_id",
    "stage_id",
    "upstream_stage_id",
    "command",
];

/// Field names whose values are a 32-byte public verification key (64 hex).
const PUBLIC_KEY_FIELDS: &[&str] = &["signer_pubkey", "public_key", "verifying_key"];

/// Declared, ordered registry of ledger fields that legitimately carry a
/// non-secret identifier-shaped value, paired with the exact token shape that is
/// provably non-secret for that field. A new ledger writer that emits an
/// identifier-shaped metadata value adds a row here (matcher + shape) instead of
/// growing an ad-hoc allowlist branch in the scanner. Any field with no matching
/// row is treated fail-closed: a long/high-entropy token in it is rejected as a
/// possible secret (`allowed_stable_identifier` returns `false`).
///
/// Rows are evaluated top-to-bottom; the first matching row decides the shape,
/// so specific fields (e.g. `signature` = 128-hex) must precede the broad
/// generic-identifier row.
const IDENTIFIER_FIELD_REGISTRY: &[IdentifierFieldRule] = &[
    // Source-path provenance metadata (chunk / database identifiers).
    IdentifierFieldRule::new(
        FieldMatcher::AnyOf(&[METADATA_CHUNK_ID, METADATA_DATABASE_NAME]),
        IdentifierShape::SourceMetadata,
    ),
    // GitHub `owner/name` repo slug recorded by the fleet discovery writer
    // (#450): bounded alnum + `_-.:/`, provably a public repository name.
    IdentifierFieldRule::new(
        FieldMatcher::Exact("full_name"),
        IdentifierShape::SourceMetadata,
    ),
    // Fleet discovery run-report file name (#450): `discovery-<ts>-<pid>.json`.
    IdentifierFieldRule::new(
        FieldMatcher::Exact("report_file"),
        IdentifierShape::ManifestSlug,
    ),
    // Stable `CALYX_*` diagnostic code.
    IdentifierFieldRule::new(FieldMatcher::Exact("code"), IdentifierShape::CalyxCode),
    // Ed25519 signature (64 bytes -> 128 hex).
    IdentifierFieldRule::new(
        FieldMatcher::Exact("signature"),
        IdentifierShape::HexExact(128),
    ),
    // Git object names recorded as import provenance.
    IdentifierFieldRule::new(FieldMatcher::AnyOf(GIT_SHA_FIELDS), IdentifierShape::GitSha),
    // Filesystem-derived project slug (deeply-nested repo path -> long slug).
    IdentifierFieldRule::new(FieldMatcher::Exact("project"), IdentifierShape::PathSlug),
    // Discovery/run manifest slugs.
    IdentifierFieldRule::new(
        FieldMatcher::AnyOf(MANIFEST_SLUG_FIELDS),
        IdentifierShape::ManifestSlug,
    ),
    // Public verification keys (32 bytes -> 64 hex).
    IdentifierFieldRule::new(
        FieldMatcher::AnyOf(PUBLIC_KEY_FIELDS),
        IdentifierShape::HexExact(MAX_HASH_OR_ID_LEN),
    ),
    // Quantization slot hex metadata.
    IdentifierFieldRule::new(
        FieldMatcher::Prefix("quant_slot_"),
        IdentifierShape::HexBounded(MAX_QUANT_SLOT_METADATA_LEN),
    ),
    // Generic stable identifiers: hash / *_id / *_hash / *_sha256 / *_digest and
    // the explicit id/hash fields enumerated in `field_allows_stable_identifier`.
    IdentifierFieldRule::new(
        FieldMatcher::Predicate(field_allows_stable_identifier),
        IdentifierShape::StableIdentifier,
    ),
];

/// One declared row of [`IDENTIFIER_FIELD_REGISTRY`].
struct IdentifierFieldRule {
    matcher: FieldMatcher,
    shape: IdentifierShape,
}

impl IdentifierFieldRule {
    const fn new(matcher: FieldMatcher, shape: IdentifierShape) -> Self {
        Self { matcher, shape }
    }
}

/// How a registry row matches a (normalized) ledger field name.
enum FieldMatcher {
    /// Exact normalized field name.
    Exact(&'static str),
    /// Membership in a fixed set of normalized field names.
    AnyOf(&'static [&'static str]),
    /// Normalized field name starts with this prefix.
    Prefix(&'static str),
    /// Arbitrary predicate over the normalized field name.
    Predicate(fn(&str) -> bool),
}

impl FieldMatcher {
    fn matches(&self, field: &str) -> bool {
        match self {
            Self::Exact(name) => field == *name,
            Self::AnyOf(names) => names.contains(&field),
            Self::Prefix(prefix) => field.starts_with(prefix),
            Self::Predicate(predicate) => predicate(field),
        }
    }
}

/// The provably-non-secret token shape a registered field's value must satisfy.
#[derive(Clone, Copy)]
enum IdentifierShape {
    /// Bounded source-path metadata (alnum + `_-.:/`, <= 128 chars).
    SourceMetadata,
    /// Stable `CALYX_*` diagnostic code.
    CalyxCode,
    /// Hex digest of exactly `n` chars.
    HexExact(usize),
    /// Git object name: 7..=40 hex chars (short or full SHA-1).
    GitSha,
    /// Filesystem-derived path slug (ascii alnum + `-_.`).
    PathSlug,
    /// Discovery/run manifest slug (bounded, alnum + `-_:/.`).
    ManifestSlug,
    /// Hex digest bounded to `n` chars.
    HexBounded(usize),
    /// Generic stable identifier: hex / base58 / uuid, bounded to 64 chars.
    StableIdentifier,
}

impl IdentifierShape {
    fn accepts(self, token: &str) -> bool {
        match self {
            Self::SourceMetadata => allowed_source_metadata_value(token),
            Self::CalyxCode => allowed_stable_code(token),
            Self::HexExact(len) => token.len() == len && is_hex(token),
            Self::GitSha => matches!(token.len(), 7..=40) && is_hex(token),
            Self::PathSlug => token
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')),
            Self::ManifestSlug => is_manifest_slug(token),
            Self::HexBounded(max) => token.len() <= max && is_hex(token),
            Self::StableIdentifier => {
                token.len() <= MAX_HASH_OR_ID_LEN
                    && (is_hex(token) || is_base58(token) || is_uuid(token))
            }
        }
    }
}

/// Returns whether `token` is a provably-non-secret identifier for `field`,
/// resolved through the declared [`IDENTIFIER_FIELD_REGISTRY`]. A field with no
/// registered row is fail-closed (`false`): a long/high-entropy token in an
/// unregistered field is treated as a possible secret and rejected.
fn allowed_stable_identifier(token: &str, field: Option<&str>) -> bool {
    let Some(field) = field else {
        return false;
    };
    let field = normalized_field(field);
    IDENTIFIER_FIELD_REGISTRY
        .iter()
        .find(|rule| rule.matcher.matches(&field))
        .is_some_and(|rule| rule.shape.accepts(token))
}

fn allowed_stable_code(token: &str) -> bool {
    token.starts_with("CALYX_")
        && token.len() <= MAX_STABLE_CODE_LEN
        && token
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

fn field_allows_stable_identifier(field: &str) -> bool {
    let field = normalized_field(field);
    field == "hash"
        || field == "metadata"
        || is_source_metadata_field(&field)
        || field == "input_hash"
        || field == "root"
        || field == "signature"
        || field == "git_sha"
        || field == "weights_sha256"
        || is_public_key_field(&field)
        || field.ends_with("_hash")
        || field.ends_with("_id")
        || field.ends_with("_sha256")
        || field.ends_with("_digest")
}

fn is_manifest_slug(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_DISCOVERY_MANIFEST_TOKEN_LEN
        && token
            .chars()
            .any(|ch| matches!(ch, '-' | '_' | ':' | '/' | '.'))
        && token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':' | '/' | '.'))
}

fn is_source_metadata_field(field: &str) -> bool {
    matches!(field, METADATA_CHUNK_ID | METADATA_DATABASE_NAME)
}

fn allowed_source_metadata_value(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_SOURCE_METADATA_LEN
        && token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '/'))
}

fn is_secret_field(field: &str) -> bool {
    let field = normalized_field(field);
    if is_public_key_field(&field) {
        return false;
    }
    matches!(
        field.as_str(),
        "password" | "passwd" | "token" | "secret" | "key"
    ) || field.ends_with("_password")
        || field.ends_with("_passwd")
        || field.ends_with("_token")
        || field.ends_with("_secret")
        || field.ends_with("_key")
}

fn is_public_key_field(field: &str) -> bool {
    PUBLIC_KEY_FIELDS.contains(&field)
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

fn is_hex(token: &str) -> bool {
    token.len().is_multiple_of(2) && token.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn is_base58(token: &str) -> bool {
    token
        .chars()
        .all(|ch| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(ch))
}

fn is_uuid(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() == 36
        && matches!(bytes[8], b'-')
        && matches!(bytes[13], b'-')
        && matches!(bytes[18], b'-')
        && matches!(bytes[23], b'-')
        && token
            .chars()
            .filter(|ch| *ch != '-')
            .all(|ch| ch.is_ascii_hexdigit())
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
    if is_secret_field(&field) {
        return false;
    }
    if is_raw_field(&field) {
        return store_raw_input;
    }
    field == "ts" || field == "redacted" || field_allows_stable_identifier(&field)
}

fn is_raw_field(field: &str) -> bool {
    matches!(
        field,
        "raw" | "raw_bytes" | "raw_input" | "input_bytes" | "plaintext"
    ) || field.ends_with("_raw")
        || field.ends_with("_bytes")
}

fn secret_error(message: impl Into<String>) -> CalyxError {
    CalyxError::ledger_secret_in_payload(message)
}
