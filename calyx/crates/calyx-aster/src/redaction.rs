//! PII input redaction modes for privacy-preserving ingest.

use calyx_core::{CalyxError, Result};
use serde::{Deserialize, Serialize};

/// Module-local error for raw PII at a hash-only ingest boundary.
pub const CALYX_PII_REDACTION_REQUIRED: &str = "CALYX_PII_REDACTION_REQUIRED";

/// How an ingest caller allows Calyx to persist source input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputMode {
    /// Persist the raw input text.
    Full(String),
    /// Persist only the BLAKE3 hash of the raw bytes.
    HashOnly([u8; 32]),
    /// Persist neither raw bytes nor a source hash; vectors only.
    Redacted,
}

/// Converts raw input text to deterministic hash-only mode.
pub fn redact_to_hash(raw: &str) -> InputMode {
    InputMode::HashOnly(*blake3::hash(raw.as_bytes()).as_bytes())
}

/// Ensures a value is safe for a hash-only ingest boundary.
pub fn assert_hash_only_mode(mode: &InputMode) -> Result<()> {
    match mode {
        InputMode::HashOnly(_) | InputMode::Redacted => Ok(()),
        InputMode::Full(_) => Err(pii_redaction_required(
            "raw input text is not allowed when hash-only input is required",
        )),
    }
}

/// Builds the input mode expected by the ingest boundary.
pub fn pii_input_for_ingest(raw: &str, require_redacted: bool) -> InputMode {
    if require_redacted {
        redact_to_hash(raw)
    } else {
        InputMode::Full(raw.to_string())
    }
}

fn pii_redaction_required(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_PII_REDACTION_REQUIRED,
        message: message.into(),
        remediation: "use HashOnly or Redacted input mode before crossing the ingest boundary",
    }
}
