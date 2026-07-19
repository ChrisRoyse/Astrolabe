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

use calyx_core::{CalyxError, Result, Seq, SlotId};
use calyx_ledger::SubjectId;
use serde::{Deserialize, Serialize};

/// Structured error code for every fail-closed lifecycle-record refusal.
pub const CALYX_COMPRESSION_LIFECYCLE_INVALID: &str = "CALYX_COMPRESSION_LIFECYCLE_INVALID";

/// Reserved marker at the front of every compression-generation Ledger subject
/// and inside every compression-generation Ledger payload.
///
/// Subject bytes use `SLOT_COMPRESSION_GENERATION ':' slot_id_be_u16`. Keeping
/// the codec beside [`GenerationLifecycleRecord`] gives producers and the MVCC
/// admission guard one canonical slot identity rather than parallel string
/// construction.
pub const COMPRESSION_GENERATION_MARKER: &str = "SLOT_COMPRESSION_GENERATION";

/// Schema tag embedded in every encoded lifecycle record, so a foreign or
/// future-versioned payload is refused rather than silently reinterpreted.
const LIFECYCLE_SCHEMA: &str = "calyx.compression.generation_lifecycle.v1";

#[derive(Debug, Deserialize)]
struct CompressionGenerationLedgerPayload {
    marker: String,
    transition: GenerationTransition,
    slot_id: u16,
    rows: u32,
    #[serde(default)]
    generation_root_sha256: Option<String>,
    #[serde(default)]
    raw_generation_root_sha256: Option<String>,
    affected_cx_ids: Vec<String>,
}

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
            lifecycle_error(format!(
                "failed to encode generation lifecycle record: {error}"
            ))
        })
    }

    /// Parses and validates a lifecycle record from stored bytes, failing closed
    /// on any malformed payload, unknown field, wrong schema, or broken invariant.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let record: Self = serde_json::from_slice(bytes).map_err(|error| {
            lifecycle_error(format!(
                "failed to parse generation lifecycle record: {error}"
            ))
        })?;
        record.validate()?;
        Ok(record)
    }

    /// Encodes the canonical minimal Ledger payload for this transition.
    ///
    /// Registry producers may add codec-specific fields, but these identity and
    /// geometry fields are mandatory and are validated by the commit guard.
    pub fn ledger_payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut payload = serde_json::Map::new();
        payload.insert(
            "marker".to_string(),
            serde_json::Value::String(COMPRESSION_GENERATION_MARKER.to_string()),
        );
        payload.insert(
            "transition".to_string(),
            serde_json::Value::String(self.transition.as_str().to_string()),
        );
        payload.insert("slot_id".to_string(), serde_json::json!(self.slot_id));
        payload.insert("rows".to_string(), serde_json::json!(self.generation_rows));
        if self.transition.writes_manifest() {
            payload.insert(
                "generation_root_sha256".to_string(),
                serde_json::Value::String(self.generation_root_sha256.clone()),
            );
            payload.insert(
                "raw_generation_root_sha256".to_string(),
                serde_json::Value::String(self.raw_generation_root_sha256.clone()),
            );
        }
        payload.insert(
            "affected_cx_ids".to_string(),
            serde_json::to_value(&self.affected_cx_ids).map_err(|error| {
                lifecycle_error(format!(
                    "failed to encode generation Ledger affected_cx_ids: {error}"
                ))
            })?,
        );
        serde_json::to_vec(&payload).map_err(|error| {
            lifecycle_error(format!(
                "failed to encode generation Ledger payload: {error}"
            ))
        })
    }

    /// Verifies that a hash-checked Ledger payload describes this exact
    /// lifecycle transition. Extra producer-specific fields are allowed, but
    /// the slot, transition, resulting geometry, roots, and affected identities
    /// must match byte-for-byte.
    pub fn validate_ledger_payload(&self, bytes: &[u8]) -> Result<()> {
        self.validate()?;
        let payload: CompressionGenerationLedgerPayload =
            serde_json::from_slice(bytes).map_err(|error| {
                lifecycle_error(format!(
                    "failed to parse compression-generation Ledger payload: {error}"
                ))
            })?;
        if payload.marker != COMPRESSION_GENERATION_MARKER {
            return Err(lifecycle_error(format!(
                "compression-generation Ledger payload marker {:?} does not match expected {COMPRESSION_GENERATION_MARKER:?}",
                payload.marker
            )));
        }
        if payload.transition != self.transition {
            return Err(lifecycle_error(format!(
                "slot {} Ledger transition {} does not match lifecycle transition {}",
                self.slot_id,
                payload.transition.as_str(),
                self.transition.as_str()
            )));
        }
        if payload.slot_id != self.slot_id {
            return Err(lifecycle_error(format!(
                "compression-generation Ledger payload slot {} does not match lifecycle slot {}",
                payload.slot_id, self.slot_id
            )));
        }
        if payload.rows != self.generation_rows {
            return Err(lifecycle_error(format!(
                "slot {} Ledger payload declares {} rows but lifecycle record declares {}",
                self.slot_id, payload.rows, self.generation_rows
            )));
        }
        if payload.affected_cx_ids != self.affected_cx_ids {
            return Err(lifecycle_error(format!(
                "slot {} Ledger affected_cx_ids do not match its lifecycle record",
                self.slot_id
            )));
        }
        if self.transition.writes_manifest() {
            if payload.generation_root_sha256.as_deref()
                != Some(self.generation_root_sha256.as_str())
            {
                return Err(lifecycle_error(format!(
                    "slot {} Ledger generation_root_sha256 does not match its lifecycle record",
                    self.slot_id
                )));
            }
            if payload.raw_generation_root_sha256.as_deref()
                != Some(self.raw_generation_root_sha256.as_str())
            {
                return Err(lifecycle_error(format!(
                    "slot {} Ledger raw_generation_root_sha256 does not match its lifecycle record",
                    self.slot_id
                )));
            }
        } else if payload.generation_root_sha256.is_some()
            || payload.raw_generation_root_sha256.is_some()
        {
            return Err(lifecycle_error(format!(
                "delete_generation Ledger payload for slot {} must not claim generation roots",
                self.slot_id
            )));
        }
        Ok(())
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
            validate_hex_root(
                &self.raw_generation_root_sha256,
                "raw_generation_root_sha256",
            )?;
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

/// Canonical hash-chained Ledger subject for one compressed slot generation.
pub fn compression_generation_subject(slot: SlotId) -> SubjectId {
    let mut subject = Vec::with_capacity(COMPRESSION_GENERATION_MARKER.len() + 3);
    subject.extend_from_slice(COMPRESSION_GENERATION_MARKER.as_bytes());
    subject.push(b':');
    subject.extend_from_slice(&slot.get().to_be_bytes());
    SubjectId::Query(subject)
}

/// Parses the reserved compression-generation subject namespace.
///
/// Non-compression subjects return `Ok(None)`. Any query subject beginning with
/// the reserved marker but not matching its exact delimiter and two-byte slot
/// shape is rejected, so malformed provenance cannot be reclassified as an
/// unrelated query.
pub fn compression_generation_slot_from_subject(subject: &SubjectId) -> Result<Option<SlotId>> {
    let SubjectId::Query(bytes) = subject else {
        return Ok(None);
    };
    let marker = COMPRESSION_GENERATION_MARKER.as_bytes();
    if !bytes.starts_with(marker) {
        return Ok(None);
    }
    let expected_len = marker.len() + 1 + std::mem::size_of::<u16>();
    if bytes.len() != expected_len || bytes.get(marker.len()).copied() != Some(b':') {
        return Err(lifecycle_error(format!(
            "reserved compression-generation Ledger subject must be {COMPRESSION_GENERATION_MARKER:?} followed by ':' and exactly two big-endian slot bytes; got {} bytes",
            bytes.len()
        )));
    }
    let offset = marker.len() + 1;
    Ok(Some(SlotId::new(u16::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
    ]))))
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
