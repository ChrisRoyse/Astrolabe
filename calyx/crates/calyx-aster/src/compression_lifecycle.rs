//! Append-only per-slot compression generation lifecycle records (issue #562).
//!
//! Every lawful mutation of a compressed slot generation — the initial
//! `Create`, a legacy `Migrate`, a full `Reseal`, an `AppendReseal`, an
//! `EraseReseal`, or a full-generation `DeleteGeneration` — writes exactly one
//! [`GenerationLifecycleRecord`] into the `compression` CF in the same
//! seq-guarded conditional batch that mutates the manifest and slot rows. The
//! record is the append-only audit trail of each atomic catalog swap: it pairs
//! the transition kind with the observed prior sequence, the resulting
//! generation geometry, and the affected `CxId`s.
//!
//! The type lives in `calyx-aster` (not `calyx-registry`) so the vault's
//! erase path can stage a `DeleteGeneration` record without a dependency cycle,
//! and so the commit-time guard in [`crate::mvcc`] can parse and validate the
//! record before a batch is admitted to the WAL.

use calyx_core::{CalyxError, Result, Seq};
use serde::{Deserialize, Serialize};

/// Structured error code for every fail-closed lifecycle-record refusal.
pub const CALYX_COMPRESSION_LIFECYCLE_INVALID: &str = "CALYX_COMPRESSION_LIFECYCLE_INVALID";

/// Schema tag embedded in every encoded lifecycle record, so a foreign or
/// future-versioned payload is refused rather than silently reinterpreted.
const LIFECYCLE_SCHEMA: &str = "calyx.compression.generation_lifecycle.v1";

/// The lawful transitions of a compressed slot generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationTransition {
    /// First compression of a previously raw slot column.
    Create,
    /// In-place upgrade of a legacy unmanifested compressed column.
    Migrate,
    /// Whole-column re-encode of an already-manifested generation.
    Reseal,
    /// Add new rows to a manifested generation, resealing every row.
    AppendReseal,
    /// Remove a strict subset of rows, resealing the survivors.
    EraseReseal,
    /// Coordinated removal of an entire generation (manifest + all rows).
    DeleteGeneration,
}

impl GenerationTransition {
    /// Whether this transition writes a live generation manifest (a manifest
    /// put). [`Self::DeleteGeneration`] is the only manifest-tombstone transition.
    pub const fn writes_manifest(self) -> bool {
        !matches!(self, Self::DeleteGeneration)
    }

    /// Stable snake_case name, used in structured refusals and ledger payloads.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Migrate => "migrate",
            Self::Reseal => "reseal",
            Self::AppendReseal => "append_reseal",
            Self::EraseReseal => "erase_reseal",
            Self::DeleteGeneration => "delete_generation",
        }
    }
}

/// One append-only lifecycle record for a compressed slot generation transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationLifecycleRecord {
    /// Fixed schema tag; must equal [`LIFECYCLE_SCHEMA`].
    pub schema: String,
    /// The transition this record witnesses.
    pub transition: GenerationTransition,
    /// The slot whose generation transitioned.
    pub slot_id: u16,
    /// The vault sequence the transition observed as current (its conditional
    /// commit guard). Also the addressing component of the record's CF key.
    pub prior_seq: Seq,
    /// Row count of the resulting generation (`0` for `DeleteGeneration`).
    pub generation_rows: u32,
    /// Lowercase-hex SHA-256 of the resulting compressed generation root
    /// (empty for `DeleteGeneration`).
    pub generation_root_sha256: String,
    /// Lowercase-hex SHA-256 of the resulting raw-sidecar generation root
    /// (empty for `DeleteGeneration`).
    pub raw_generation_root_sha256: String,
    /// Lowercase-hex 16-byte `CxId`s this transition added or removed
    /// (semantics depend on `transition`).
    pub affected_cx_ids: Vec<String>,
}

impl GenerationLifecycleRecord {
    /// Builds a record, validating its internal invariants immediately.
    pub fn new(
        transition: GenerationTransition,
        slot_id: u16,
        prior_seq: Seq,
        generation_rows: u32,
        generation_root_sha256: String,
        raw_generation_root_sha256: String,
        affected_cx_ids: Vec<String>,
    ) -> Result<Self> {
        let record = Self {
            schema: LIFECYCLE_SCHEMA.to_string(),
            transition,
            slot_id,
            prior_seq,
            generation_rows,
            generation_root_sha256,
            raw_generation_root_sha256,
            affected_cx_ids,
        };
        record.validate()?;
        Ok(record)
    }

    /// Serializes the record to its canonical JSON bytes, failing closed if any
    /// invariant is violated.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| {
            lifecycle_error(format!("failed to encode generation lifecycle record: {error}"))
        })
    }

    /// Parses and validates a lifecycle record from stored bytes, failing closed
    /// on any malformed payload, unknown field, wrong schema, or broken invariant.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let record: Self = serde_json::from_slice(bytes).map_err(|error| {
            lifecycle_error(format!("failed to parse generation lifecycle record: {error}"))
        })?;
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != LIFECYCLE_SCHEMA {
            return Err(lifecycle_error(format!(
                "generation lifecycle record schema {:?} does not match expected {LIFECYCLE_SCHEMA:?}",
                self.schema
            )));
        }
        if self.transition.writes_manifest() {
            if self.generation_rows == 0 {
                return Err(lifecycle_error(format!(
                    "{} transition for slot {} must declare a non-zero generation row count",
                    self.transition.as_str(),
                    self.slot_id
                )));
            }
            validate_hex_root(&self.generation_root_sha256, "generation_root_sha256")?;
            validate_hex_root(&self.raw_generation_root_sha256, "raw_generation_root_sha256")?;
        } else {
            if self.generation_rows != 0 {
                return Err(lifecycle_error(format!(
                    "delete_generation transition for slot {} must declare zero generation rows, got {}",
                    self.slot_id, self.generation_rows
                )));
            }
            if !self.generation_root_sha256.is_empty()
                || !self.raw_generation_root_sha256.is_empty()
            {
                return Err(lifecycle_error(format!(
                    "delete_generation transition for slot {} must carry empty generation roots",
                    self.slot_id
                )));
            }
        }
        for cx_hex in &self.affected_cx_ids {
            validate_hex_cx_id(cx_hex)?;
        }
        Ok(())
    }
}

fn validate_hex_root(value: &str, field: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(is_lower_hex) {
        return Err(lifecycle_error(format!(
            "lifecycle record {field} must be 64 lowercase-hex characters, got {value:?}"
        )));
    }
    Ok(())
}

fn validate_hex_cx_id(value: &str) -> Result<()> {
    if value.len() != 32 || !value.bytes().all(is_lower_hex) {
        return Err(lifecycle_error(format!(
            "lifecycle record affected CxId must be 32 lowercase-hex characters, got {value:?}"
        )));
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn lifecycle_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_COMPRESSION_LIFECYCLE_INVALID,
        message: message.into(),
        remediation: "write compressed slot generation transitions through the registry lifecycle API so each manifest mutation carries its append-only lifecycle record and ledger entry",
    }
}
