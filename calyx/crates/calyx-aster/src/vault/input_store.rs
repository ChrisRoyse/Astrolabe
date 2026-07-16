//! Content-addressed **input store**: the raw canonical input bytes that a
//! constellation was measured from, persisted in the [`ColumnFamily::Blob`]
//! column family and linked from `Constellation.input_ref.pointer`.
//!
//! Calyx ingest historically hashed the input bytes into `InputRef.hash` and
//! then discarded the bytes, leaving an external corpus's source text
//! unrecoverable from the vault (issue #446). This module stores those bytes so
//! the document-store role Calyx claims (BUILDING_ON_CALYX section 2) is real.
//!
//! # Keyspace
//!
//! Rows live in the Blob CF under a **reserved discriminant byte** ([`DISC`],
//! `0xCA`) followed by [`NAMESPACE`] (`b"cxinput:v1:"`). The collection blob
//! layer ([`crate::layers::blob`]) keys every row under `0x05`, so the two
//! keyspaces are byte-disjoint and can never collide.
//!
//! ```text
//! chunk    row: 0xCA ‖ "cxinput:v1:" ‖ 0x00 ‖ input_hash[32] ‖ chunk_idx_be(4) -> chunk bytes
//! manifest row: 0xCA ‖ "cxinput:v1:" ‖ 0x01 ‖ input_hash[32]                   -> manifest
//! ```
//!
//! The manifest is the terminal record: it carries `total_len`, `chunk_count`,
//! and the BLAKE3 content hash, so a truncated readback (a missing chunk, a
//! short reassembly, or a hash divergence) fails closed instead of returning
//! partial bytes.
//!
//! # Content addressing
//!
//! The store is keyed by `input_hash`, which ingest derives as
//! `blake3(canonical_input_bytes)` (`calyx_registry::measure::input_hash`).
//! [`encode_input_rows`] records `blake3(bytes)` as the manifest content hash,
//! and [`read_input_bytes`] fails closed unless the reassembled payload hashes
//! back to the addressing key — the read is self-verifying. Re-storing the same
//! bytes is idempotent (same key, same rows), matching content-address doctrine.

use calyx_core::{CalyxError, Clock, Result};
use serde::{Deserialize, Serialize};

use crate::cf::ColumnFamily;
use crate::layers::blob::{BLOB_CHUNK_SIZE, MAX_BLOB_BYTES};
use crate::vault::AsterVault;
use crate::vault::encode::WriteRow;

/// Returned when no input-store manifest exists for the requested hash.
pub const CALYX_INPUT_STORE_MISSING: &str = "CALYX_INPUT_STORE_MISSING";
/// Returned when the stored input is present but fails structural or hash
/// verification on readback (missing chunk, wrong length, hash divergence).
pub const CALYX_INPUT_STORE_CORRUPT: &str = "CALYX_INPUT_STORE_CORRUPT";
/// Returned when a caller asks to store more than [`MAX_BLOB_BYTES`].
pub const CALYX_INPUT_STORE_TOO_LARGE: &str = "CALYX_INPUT_STORE_TOO_LARGE";

/// Reserved leading discriminant byte for every input-store row. Distinct from
/// the collection blob layer's `0x05`, so the two Blob-CF keyspaces are disjoint.
const DISC: u8 = 0xCA;
/// Versioned namespace tag; bump the suffix on any on-disk layout change.
const NAMESPACE: &[u8] = b"cxinput:v1:";
const KIND_CHUNK: u8 = 0x00;
const KIND_MANIFEST: u8 = 0x01;
const HASH_BYTES: usize = 32;
/// `version(1) ‖ total_len_be(8) ‖ chunk_count_be(4) ‖ content_hash(32)`.
const MANIFEST_VALUE_BYTES: usize = 1 + 8 + 4 + HASH_BYTES;
const MANIFEST_VERSION: u8 = 1;

/// Typed pointer prefix written into `InputRef.pointer` when input bytes are
/// retained. The hex-encoded `input_hash` follows.
pub const INPUT_POINTER_PREFIX: &str = "cxinput:v1:";

/// Per-vault retention policy for raw input bytes (issue #446, invariant 4:
/// declared knob, never a hidden constant). `Persist` is the default so every
/// ingest keeps its source bytes unless an operator explicitly opts out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputRetention {
    /// Store the canonical input bytes in the content-addressed input store.
    #[default]
    Persist,
    /// Do not store input bytes; the constellation's `input_ref.redacted` is set
    /// so the omission is explicit and labeled, never silent.
    Redact,
}

impl InputRetention {
    /// Stable lowercase name for CLI/manifest surfaces.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Persist => "persist",
            Self::Redact => "redact",
        }
    }

    /// Parses a policy name, failing closed on anything unrecognized.
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "persist" => Ok(Self::Persist),
            "redact" => Ok(Self::Redact),
            other => Err(CalyxError {
                code: "CALYX_INPUT_RETENTION_INVALID",
                message: format!("unknown input retention policy {other:?}; expected persist|redact"),
                remediation: "pass --input-retention persist or --input-retention redact",
            }),
        }
    }
}

/// Decoded input-store manifest — the terminal per-input record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputManifest {
    /// Total stored byte length.
    pub total_len: u64,
    /// Number of chunk rows (`0` for a valid empty input).
    pub chunk_count: u32,
    /// BLAKE3 of the stored bytes; equals the addressing `input_hash`.
    pub content_hash: [u8; HASH_BYTES],
}

/// The typed pointer for `input_hash`, e.g. `cxinput:v1:<64-hex>`.
pub fn input_pointer(input_hash: &[u8; HASH_BYTES]) -> String {
    let mut out = String::with_capacity(INPUT_POINTER_PREFIX.len() + HASH_BYTES * 2);
    out.push_str(INPUT_POINTER_PREFIX);
    for byte in input_hash {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Number of chunks a payload of `len` bytes occupies (`0` for empty).
pub fn chunk_count_for(len: usize) -> u32 {
    if len == 0 {
        0
    } else {
        len.div_ceil(BLOB_CHUNK_SIZE) as u32
    }
}

fn key_prefix(kind: u8, input_hash: &[u8; HASH_BYTES]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + NAMESPACE.len() + 1 + HASH_BYTES + 4);
    key.push(DISC);
    key.extend_from_slice(NAMESPACE);
    key.push(kind);
    key.extend_from_slice(input_hash);
    key
}

/// `0xCA ‖ "cxinput:v1:" ‖ 0x00 ‖ input_hash ‖ chunk_idx_be`.
pub fn input_chunk_key(input_hash: &[u8; HASH_BYTES], idx: u32) -> Vec<u8> {
    let mut key = key_prefix(KIND_CHUNK, input_hash);
    key.extend_from_slice(&idx.to_be_bytes());
    key
}

/// `0xCA ‖ "cxinput:v1:" ‖ 0x01 ‖ input_hash`.
pub fn input_manifest_key(input_hash: &[u8; HASH_BYTES]) -> Vec<u8> {
    key_prefix(KIND_MANIFEST, input_hash)
}

fn encode_manifest(manifest: &InputManifest) -> Vec<u8> {
    let mut out = Vec::with_capacity(MANIFEST_VALUE_BYTES);
    out.push(MANIFEST_VERSION);
    out.extend_from_slice(&manifest.total_len.to_be_bytes());
    out.extend_from_slice(&manifest.chunk_count.to_be_bytes());
    out.extend_from_slice(&manifest.content_hash);
    out
}

fn decode_manifest(bytes: &[u8]) -> Result<InputManifest> {
    if bytes.len() != MANIFEST_VALUE_BYTES {
        return Err(corrupt(format!(
            "input manifest must be {MANIFEST_VALUE_BYTES} bytes, got {}",
            bytes.len()
        )));
    }
    if bytes[0] != MANIFEST_VERSION {
        return Err(corrupt(format!(
            "input manifest version {} is not the supported {MANIFEST_VERSION}",
            bytes[0]
        )));
    }
    let total_len = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
    let chunk_count = u32::from_be_bytes(bytes[9..13].try_into().unwrap());
    let mut content_hash = [0_u8; HASH_BYTES];
    content_hash.copy_from_slice(&bytes[13..45]);
    Ok(InputManifest {
        total_len,
        chunk_count,
        content_hash,
    })
}

/// Stages the chunk rows plus the terminal manifest row for `bytes`, addressed
/// by `input_hash`. The rows are content-addressed and idempotent: staging the
/// same bytes twice yields byte-identical rows under the same keys. Callers
/// commit these in the SAME atomic write batch as the base record (see
/// [`AsterVault::put_with_input_rows`]).
///
/// Fails closed if `bytes` exceeds [`MAX_BLOB_BYTES`].
pub fn encode_input_rows(input_hash: &[u8; HASH_BYTES], bytes: &[u8]) -> Result<Vec<WriteRow>> {
    if bytes.len() > MAX_BLOB_BYTES {
        return Err(CalyxError {
            code: CALYX_INPUT_STORE_TOO_LARGE,
            message: format!(
                "input of {} bytes exceeds the {MAX_BLOB_BYTES}-byte input-store ceiling",
                bytes.len()
            ),
            remediation: "split the input or raise the input-store ceiling",
        });
    }
    let content_hash = *blake3::hash(bytes).as_bytes();
    let chunk_count = chunk_count_for(bytes.len());
    let mut rows = Vec::with_capacity(chunk_count as usize + 1);
    if !bytes.is_empty() {
        for (idx, chunk) in bytes.chunks(BLOB_CHUNK_SIZE).enumerate() {
            rows.push(WriteRow {
                cf: ColumnFamily::Blob,
                key: input_chunk_key(input_hash, idx as u32),
                value: chunk.to_vec(),
            });
        }
    }
    rows.push(WriteRow {
        cf: ColumnFamily::Blob,
        key: input_manifest_key(input_hash),
        value: encode_manifest(&InputManifest {
            total_len: bytes.len() as u64,
            chunk_count,
            content_hash,
        }),
    });
    Ok(rows)
}

/// Reassembles and verifies the stored bytes for `input_hash` using an
/// arbitrary row fetcher, so both the live-vault reader ([`read_input_bytes`])
/// and independent readback tools (the CLI `input-read` verb over raw SST/WAL
/// rows) share one fail-closed verification path.
///
/// `fetch(key)` returns the Blob-CF value for `key`, or `None` if absent. Any
/// missing chunk, wrong reassembled length, or hash divergence fails closed.
pub fn reassemble_and_verify(
    input_hash: &[u8; HASH_BYTES],
    mut fetch: impl FnMut(&[u8]) -> Result<Option<Vec<u8>>>,
) -> Result<Vec<u8>> {
    let manifest_key = input_manifest_key(input_hash);
    let Some(manifest_bytes) = fetch(&manifest_key)? else {
        return Err(CalyxError {
            code: CALYX_INPUT_STORE_MISSING,
            message: format!(
                "no input-store manifest for input_hash {}",
                hex(input_hash)
            ),
            remediation: "ingest the input with input_retention=persist, or read a hash that was persisted",
        });
    };
    let manifest = decode_manifest(&manifest_bytes)?;
    if &manifest.content_hash != input_hash {
        return Err(corrupt(format!(
            "input manifest content hash {} does not match addressing key {}",
            hex(&manifest.content_hash),
            hex(input_hash)
        )));
    }
    let expected_chunks = chunk_count_for(manifest.total_len as usize);
    if manifest.chunk_count != expected_chunks {
        return Err(corrupt(format!(
            "input manifest declares {} chunks but {} bytes require {expected_chunks}",
            manifest.chunk_count, manifest.total_len
        )));
    }
    let mut data = Vec::with_capacity(manifest.total_len as usize);
    for idx in 0..manifest.chunk_count {
        let chunk = fetch(&input_chunk_key(input_hash, idx))?.ok_or_else(|| {
            corrupt(format!(
                "input manifest claims {} chunks but chunk {idx} is missing",
                manifest.chunk_count
            ))
        })?;
        data.extend_from_slice(&chunk);
    }
    if data.len() as u64 != manifest.total_len {
        return Err(corrupt(format!(
            "input reassembled to {} bytes but manifest says {}",
            data.len(),
            manifest.total_len
        )));
    }
    if blake3::hash(&data).as_bytes() != &manifest.content_hash {
        return Err(corrupt(
            "input content hash mismatch on read — stored bytes are corrupt",
        ));
    }
    Ok(data)
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Effective raw-input retention policy for this vault (#446): the durable
    /// manifest's declared `input_retention` knob, or [`InputRetention::Persist`]
    /// for an in-memory vault, which has no manifest to declare otherwise.
    /// Redaction is always an explicit opt-out, never an implicit state.
    pub fn input_retention(&self) -> Result<InputRetention> {
        match &self.durable {
            Some(durable) => durable.manifest_input_retention(),
            None => Ok(InputRetention::default()),
        }
    }
}

/// Reads the input-store manifest for `input_hash` from a live vault, or `None`
/// if the input was never stored (e.g. `input_retention=redact`).
pub fn input_manifest<C: Clock>(
    vault: &AsterVault<C>,
    input_hash: &[u8; HASH_BYTES],
) -> Result<Option<InputManifest>> {
    let snapshot = vault.latest_seq();
    vault
        .read_cf_at(snapshot, ColumnFamily::Blob, &input_manifest_key(input_hash))?
        .map(|bytes| decode_manifest(&bytes))
        .transpose()
}

/// Reads and verifies the raw input bytes for `input_hash` from a live vault.
/// Fails closed with [`CALYX_INPUT_STORE_MISSING`] if absent, or
/// [`CALYX_INPUT_STORE_CORRUPT`] on any truncation or hash divergence.
pub fn read_input_bytes<C: Clock>(
    vault: &AsterVault<C>,
    input_hash: &[u8; HASH_BYTES],
) -> Result<Vec<u8>> {
    let snapshot = vault.latest_seq();
    reassemble_and_verify(input_hash, |key| {
        vault.read_cf_at(snapshot, ColumnFamily::Blob, key)
    })
}

fn corrupt(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_INPUT_STORE_CORRUPT,
        message: message.into(),
        remediation: "the stored input is truncated or corrupt; re-ingest the source input",
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
