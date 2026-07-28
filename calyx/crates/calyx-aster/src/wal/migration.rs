//! Explicit, backup-preserving migration of unambiguous legacy WAL tails.
//!
//! Ordinary Aster open deliberately refuses the legacy one-byte CF encoding.
//! This module is the only conversion boundary: it runs offline behind the
//! real WAL append lock, binds the manifest and every segment by SHA-256,
//! converts only records above the manifest durability floor, and retains the
//! byte-identical original of every replaced segment.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use calyx_core::{CalyxError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::record::LogicalStatus;
use super::{record, replay, segment, storage_error};
use crate::manifest::ManifestStore;
use crate::vault::cf_codec::decode_fixed_cf;
use crate::vault::encode::{WriteRow, decode_write_batch, encode_write_batch};

pub const CALYX_ASTER_WAL_MIGRATION_LOCKED: &str = "CALYX_ASTER_WAL_MIGRATION_LOCKED";
pub const CALYX_ASTER_WAL_MIGRATION_AMBIGUOUS_CF: &str = "CALYX_ASTER_WAL_MIGRATION_AMBIGUOUS_CF";
pub const CALYX_ASTER_WAL_MIGRATION_UNKNOWN_CF: &str = "CALYX_ASTER_WAL_MIGRATION_UNKNOWN_CF";
pub const CALYX_ASTER_WAL_MIGRATION_MALFORMED: &str = "CALYX_ASTER_WAL_MIGRATION_MALFORMED";
pub const CALYX_ASTER_WAL_MIGRATION_DRIFT: &str = "CALYX_ASTER_WAL_MIGRATION_DRIFT";
pub const CALYX_ASTER_WAL_MIGRATION_STATE: &str = "CALYX_ASTER_WAL_MIGRATION_STATE";
pub const CALYX_ASTER_WAL_MIGRATION_PUBLICATION: &str = "CALYX_ASTER_WAL_MIGRATION_PUBLICATION";

const MIGRATION_SCHEMA: u32 = 1;
const MIGRATION_ROOT: &str = "migrations/wal-v2";
const V2_MAGIC: &[u8; 8] = b"CXLWAL2\0";

/// Terminal disposition of an explicit WAL-tail migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyWalMigrationDisposition {
    /// Every live tail record was already CXLWAL2, or no live tail existed.
    Noop,
    /// This call prepared and committed a new migration transaction.
    Migrated,
    /// This call completed an already-durable interrupted transaction.
    Recovered,
}

/// Hash evidence for one retained original segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LegacyWalBackup {
    pub segment_index: u64,
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
}

/// Per-row identity recorded without copying value bytes into the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyWalMigratedRow {
    pub sequence: u64,
    pub row_index: usize,
    pub column_family: String,
    pub legacy_tag: u8,
    pub key_bytes: u64,
    pub key_sha256: String,
    pub value_bytes: u64,
    pub value_sha256: String,
}

/// Durable result returned by the low-level operation and serialized by the
/// fleet command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LegacyWalMigrationReport {
    pub vault_path: PathBuf,
    pub disposition: LegacyWalMigrationDisposition,
    pub manifest_pointer: String,
    pub manifest_sha256: String,
    pub manifest_durable_seq: u64,
    pub latest_seq_before: u64,
    pub latest_seq_after: u64,
    pub segments_examined: usize,
    pub segments_migrated: usize,
    pub records_examined: usize,
    pub records_migrated: usize,
    pub rows_migrated: usize,
    pub transaction_id: Option<String>,
    pub transaction_dir: Option<PathBuf>,
    pub completion_receipt: Option<PathBuf>,
    pub retained_backups: Vec<LegacyWalBackup>,
    pub migrated_rows: Vec<LegacyWalMigratedRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestBinding {
    current_bytes: u64,
    current_sha256: String,
    pointer: String,
    manifest_relative_path: String,
    manifest_bytes: u64,
    manifest_sha256: String,
    durable_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MigratedRecordReceipt {
    sequence: u64,
    source_payload_bytes: u64,
    source_payload_sha256: String,
    replacement_payload_bytes: u64,
    replacement_payload_sha256: String,
    rows: Vec<LegacyWalMigratedRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SegmentIntent {
    index: u64,
    relative_path: String,
    source_bytes: u64,
    source_sha256: String,
    replacement_bytes: u64,
    replacement_sha256: String,
    stage_relative_path: Option<String>,
    backup_relative_path: Option<String>,
    migrated_records: Vec<MigratedRecordReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MigrationIntent {
    schema: u32,
    transaction_id: String,
    vault_path: String,
    manifest: ManifestBinding,
    latest_seq_before: u64,
    records_examined: usize,
    segments: Vec<SegmentIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PublicationMarker {
    schema: u32,
    transaction_id: String,
    phase: String,
    segment_index: u64,
    source_sha256: String,
    replacement_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CompletionReceipt {
    schema: u32,
    transaction_id: String,
    manifest: ManifestBinding,
    latest_seq_before: u64,
    latest_seq_after: u64,
    segments_migrated: usize,
    records_migrated: usize,
    rows_migrated: usize,
    retained_backups: Vec<CompletionBackup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CompletionBackup {
    segment_index: u64,
    relative_path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug)]
struct SegmentPlan {
    intent: SegmentIntent,
    replacement: Vec<u8>,
    logical_sequences: Vec<u64>,
    migrated_values: BTreeMap<u64, Vec<WriteRow>>,
}

#[derive(Debug)]
struct MigrationPlan {
    latest_seq: u64,
    records_examined: usize,
    segments: Vec<SegmentPlan>,
}

/// Converts only unambiguous legacy records newer than the current manifest.
///
/// The call is intentionally explicit and fail-fast. It never changes ordinary
/// open/replay behavior, never guesses a slot family, and never publishes
/// without a byte-identical retained backup.
pub fn migrate_legacy_wal_tail(vault_dir: impl AsRef<Path>) -> Result<LegacyWalMigrationReport> {
    let vault_dir = fs::canonicalize(vault_dir.as_ref()).map_err(|error| CalyxError {
        code: CALYX_ASTER_WAL_MIGRATION_STATE,
        message: format!(
            "canonicalize WAL migration vault {}: {error}",
            vault_dir.as_ref().display()
        ),
        remediation: "pass one existing Aster vault directory and preserve its bytes on failure",
    })?;
    if !vault_dir.is_dir() {
        return Err(state_error(format!(
            "WAL migration target {} is not a directory",
            vault_dir.display()
        )));
    }
    let wal_dir = vault_dir.join("wal");
    if !wal_dir.is_dir() {
        return Err(state_error(format!(
            "WAL migration target {} has no wal directory",
            vault_dir.display()
        )));
    }

    let _append_lock = crate::file_lock::FileLockGuard::try_acquire(
        &wal_dir.join(".append.lock"),
        migration_locked,
    )?;
    let manifest = read_manifest_binding(&vault_dir)?;
    let migration_root = vault_dir.join(MIGRATION_ROOT);

    if let Some(transaction_dir) = find_incomplete_transaction(&migration_root)? {
        let intent = read_json::<MigrationIntent>(&transaction_dir.join("intent.json"))?;
        validate_intent(&vault_dir, &transaction_dir, &manifest, &intent)?;
        return execute_transaction(
            &vault_dir,
            &wal_dir,
            &transaction_dir,
            &intent,
            LegacyWalMigrationDisposition::Recovered,
        );
    }

    let plan = plan_migration(&wal_dir, manifest.durable_seq)?;
    let migrated_segments = plan
        .segments
        .iter()
        .filter(|segment| !segment.intent.migrated_records.is_empty())
        .count();
    if migrated_segments == 0 {
        return Ok(LegacyWalMigrationReport {
            vault_path: vault_dir,
            disposition: LegacyWalMigrationDisposition::Noop,
            manifest_pointer: manifest.pointer.clone(),
            manifest_sha256: manifest.manifest_sha256.clone(),
            manifest_durable_seq: manifest.durable_seq,
            latest_seq_before: plan.latest_seq,
            latest_seq_after: plan.latest_seq,
            segments_examined: plan.segments.len(),
            segments_migrated: 0,
            records_examined: plan.records_examined,
            records_migrated: 0,
            rows_migrated: 0,
            transaction_id: None,
            transaction_dir: None,
            completion_receipt: None,
            retained_backups: Vec::new(),
            migrated_rows: Vec::new(),
        });
    }

    let transaction_id = transaction_id(&vault_dir, &manifest, &plan.segments)?;
    let transaction_dir = migration_root.join(&transaction_id);
    let intent = build_intent(
        &vault_dir,
        manifest,
        plan.latest_seq,
        &transaction_id,
        &plan,
    );
    prepare_transaction(&migration_root, &transaction_dir, &intent, &plan)?;
    execute_transaction(
        &vault_dir,
        &wal_dir,
        &transaction_dir,
        &intent,
        LegacyWalMigrationDisposition::Migrated,
    )
}

fn read_manifest_binding(vault_dir: &Path) -> Result<ManifestBinding> {
    let current_path = vault_dir.join("CURRENT");
    let current_before = fs::read(&current_path)
        .map_err(|error| storage_error("read WAL migration CURRENT", error))?;
    let pointer = std::str::from_utf8(&current_before)
        .map_err(|error| malformed(format!("CURRENT is not UTF-8: {error}")))?
        .trim()
        .to_string();
    if pointer.is_empty() {
        return Err(malformed("CURRENT is empty"));
    }
    let manifest_path = vault_dir.join(&pointer);
    let manifest_before = fs::read(&manifest_path)
        .map_err(|error| storage_error("read WAL migration manifest", error))?;
    let manifest = ManifestStore::open(vault_dir).load_current()?;
    let current_after = fs::read(&current_path)
        .map_err(|error| storage_error("re-read WAL migration CURRENT", error))?;
    let manifest_after = fs::read(&manifest_path)
        .map_err(|error| storage_error("re-read WAL migration manifest", error))?;
    if current_before != current_after || manifest_before != manifest_after {
        return Err(drift_error(format!(
            "manifest identity changed while admitting migration for {}",
            vault_dir.display()
        )));
    }
    Ok(ManifestBinding {
        current_bytes: current_before.len() as u64,
        current_sha256: sha256(&current_before),
        pointer: pointer.clone(),
        manifest_relative_path: pointer,
        manifest_bytes: manifest_before.len() as u64,
        manifest_sha256: sha256(&manifest_before),
        durable_seq: manifest.durable_seq,
    })
}

fn plan_migration(wal_dir: &Path, durable_seq: u64) -> Result<MigrationPlan> {
    let mut segments = Vec::new();
    let mut records_examined = 0usize;
    let mut all_sequences = Vec::new();
    let mut live_sequences = Vec::new();
    let mut latest_seq = durable_seq;
    for (index, path) in segment::list_segments(wal_dir)? {
        let relative = format!(
            "wal/{}",
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| malformed("WAL segment name is not UTF-8"))?
        );
        let plan = plan_segment(index, &path, &relative, durable_seq)?;
        records_examined = records_examined.saturating_add(plan.logical_sequences.len());
        for sequence in &plan.logical_sequences {
            latest_seq = latest_seq.max(*sequence);
            all_sequences.push(*sequence);
            if *sequence > durable_seq {
                live_sequences.push(*sequence);
            }
        }
        segments.push(plan);
    }
    for pair in all_sequences.windows(2) {
        if pair[1] <= pair[0] {
            return Err(malformed(format!(
                "WAL logical sequences are not strictly increasing across segments: {} is followed by {}",
                pair[0], pair[1]
            )));
        }
    }
    for (position, sequence) in live_sequences.iter().enumerate() {
        let expected = durable_seq
            .checked_add(position as u64 + 1)
            .ok_or_else(|| malformed("WAL live-tail sequence overflow"))?;
        if *sequence != expected {
            return Err(malformed(format!(
                "WAL live tail is not contiguous above manifest floor {durable_seq}: expected seq {expected}, found {sequence}"
            )));
        }
    }
    Ok(MigrationPlan {
        latest_seq,
        records_examined,
        segments,
    })
}

fn plan_segment(
    index: u64,
    path: &Path,
    relative_path: &str,
    durable_seq: u64,
) -> Result<SegmentPlan> {
    let source =
        fs::read(path).map_err(|error| storage_error("read WAL migration segment", error))?;
    let mut file =
        File::open(path).map_err(|error| storage_error("open WAL migration segment", error))?;
    let mut replacement = Vec::with_capacity(source.len());
    let mut logical_sequences = Vec::new();
    let mut migrated_records = Vec::new();
    let mut migrated_values = BTreeMap::new();
    let mut offset = 0u64;
    loop {
        let decoded = match record::decode_logical_at(&mut file, offset)
            .map_err(|error| storage_error("decode WAL migration record", error))?
        {
            LogicalStatus::Complete(decoded) => decoded,
            LogicalStatus::Eof => break,
            LogicalStatus::Torn { offset, message } => {
                return Err(malformed(format!(
                    "WAL segment {} is torn at byte {offset}: {message}",
                    path.display()
                )));
            }
        };
        if logical_sequences
            .last()
            .is_some_and(|previous| decoded.seq <= *previous)
        {
            return Err(malformed(format!(
                "WAL segment {} sequence {} is not strictly greater than the prior sequence",
                path.display(),
                decoded.seq
            )));
        }
        logical_sequences.push(decoded.seq);
        let start = usize::try_from(decoded.start_offset)
            .map_err(|_| malformed("WAL record start offset exceeds usize"))?;
        let end = usize::try_from(decoded.end_offset)
            .map_err(|_| malformed("WAL record end offset exceeds usize"))?;
        let original_record = source.get(start..end).ok_or_else(|| {
            malformed(format!(
                "decoded WAL range {start}..{end} exceeds {} bytes in {}",
                source.len(),
                path.display()
            ))
        })?;

        if decoded.seq <= durable_seq || decoded.payload.starts_with(V2_MAGIC) {
            if decoded.seq > durable_seq {
                decode_write_batch(&decoded.payload)?;
            }
            replacement.extend_from_slice(original_record);
        } else {
            let (rows, receipts) = decode_unambiguous_legacy_batch(decoded.seq, &decoded.payload)?;
            let encoded = encode_write_batch(&rows)?;
            replacement.extend_from_slice(&encode_logical_record(decoded.seq, &encoded)?);
            migrated_records.push(MigratedRecordReceipt {
                sequence: decoded.seq,
                source_payload_bytes: decoded.payload.len() as u64,
                source_payload_sha256: sha256(&decoded.payload),
                replacement_payload_bytes: encoded.len() as u64,
                replacement_payload_sha256: sha256(&encoded),
                rows: receipts,
            });
            if migrated_values.insert(decoded.seq, rows).is_some() {
                return Err(malformed(format!(
                    "WAL sequence {} appears more than once",
                    decoded.seq
                )));
            }
        }
        offset = decoded.end_offset;
    }
    if usize::try_from(offset).ok() != Some(source.len()) {
        return Err(malformed(format!(
            "WAL segment {} ended at decoded offset {offset}, not physical length {}",
            path.display(),
            source.len()
        )));
    }

    let changed = !migrated_records.is_empty();
    let transaction_placeholder = "TRANSACTION";
    let stage_relative_path = changed
        .then(|| format!("{MIGRATION_ROOT}/{transaction_placeholder}/staged-{index:020}.wal"));
    let backup_relative_path = changed
        .then(|| format!("{MIGRATION_ROOT}/{transaction_placeholder}/backup-{index:020}.wal"));
    Ok(SegmentPlan {
        intent: SegmentIntent {
            index,
            relative_path: relative_path.to_string(),
            source_bytes: source.len() as u64,
            source_sha256: sha256(&source),
            replacement_bytes: replacement.len() as u64,
            replacement_sha256: sha256(&replacement),
            stage_relative_path,
            backup_relative_path,
            migrated_records,
        },
        replacement,
        logical_sequences,
        migrated_values,
    })
}

fn decode_unambiguous_legacy_batch(
    sequence: u64,
    bytes: &[u8],
) -> Result<(Vec<WriteRow>, Vec<LegacyWalMigratedRow>)> {
    let mut cursor = LegacyCursor::new(bytes);
    let count = cursor.u32()? as usize;
    const MINIMUM_LEGACY_ROW_BYTES: usize = 9;
    if count > cursor.remaining() / MINIMUM_LEGACY_ROW_BYTES {
        return Err(malformed(format!(
            "legacy WAL seq {sequence} declares {count} rows but {} remaining bytes cannot hold them",
            cursor.remaining()
        )));
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(count)
        .map_err(|error| malformed(format!("reserve {count} legacy rows failed: {error}")))?;
    let mut receipts = Vec::new();
    receipts
        .try_reserve_exact(count)
        .map_err(|error| malformed(format!("reserve {count} row receipts failed: {error}")))?;
    for row_index in 0..count {
        let tag = cursor.u8()?;
        if (16..=111).contains(&tag) {
            return Err(CalyxError {
                code: CALYX_ASTER_WAL_MIGRATION_AMBIGUOUS_CF,
                message: format!(
                    "legacy WAL seq {sequence} row {row_index} uses ambiguous one-byte slot tag {tag}"
                ),
                remediation: "preserve the vault and re-ingest from its provenanced source; no format-only migration can recover the lost slot family/id distinction",
            });
        }
        let cf = decode_fixed_cf(tag).map_err(|_| CalyxError {
            code: CALYX_ASTER_WAL_MIGRATION_UNKNOWN_CF,
            message: format!(
                "legacy WAL seq {sequence} row {row_index} uses unknown fixed column-family tag {tag}"
            ),
            remediation: "preserve the vault and identify the exact historical encoder before adding an explicit format migration",
        })?;
        let key = cursor.bytes_prefixed()?.to_vec();
        let value = cursor.bytes_prefixed()?.to_vec();
        receipts.push(LegacyWalMigratedRow {
            sequence,
            row_index,
            column_family: cf.name(),
            legacy_tag: tag,
            key_bytes: key.len() as u64,
            key_sha256: sha256(&key),
            value_bytes: value.len() as u64,
            value_sha256: sha256(&value),
        });
        rows.push(WriteRow { cf, key, value });
    }
    if cursor.remaining() != 0 {
        return Err(malformed(format!(
            "legacy WAL seq {sequence} has {} trailing bytes after {count} declared rows",
            cursor.remaining()
        )));
    }
    Ok((rows, receipts))
}

fn encode_logical_record(sequence: u64, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() <= record::CHUNK_TARGET_BYTES as usize {
        return record::encode(sequence, payload)
            .map_err(|error| storage_error("encode migrated WAL record", error));
    }
    let chunks = payload.len().div_ceil(record::CHUNK_TARGET_BYTES as usize);
    let chunk_count = u32::try_from(chunks)
        .map_err(|_| malformed("migrated WAL record needs more than u32 group members"))?;
    let mut encoded = Vec::new();
    for (index, chunk) in payload
        .chunks(record::CHUNK_TARGET_BYTES as usize)
        .enumerate()
    {
        encoded.extend_from_slice(
            &record::encode_group_member(sequence, index as u32, chunk_count, chunk)
                .map_err(|error| storage_error("encode migrated WAL group member", error))?,
        );
    }
    Ok(encoded)
}

fn transaction_id(
    vault_dir: &Path,
    manifest: &ManifestBinding,
    segments: &[SegmentPlan],
) -> Result<String> {
    let identity = serde_json::json!({
        "schema": MIGRATION_SCHEMA,
        "vault_path": vault_dir.to_string_lossy(),
        "manifest": manifest,
        "segments": segments.iter().map(|segment| serde_json::json!({
            "index": segment.intent.index,
            "relative_path": segment.intent.relative_path,
            "source_bytes": segment.intent.source_bytes,
            "source_sha256": segment.intent.source_sha256,
            "replacement_bytes": segment.intent.replacement_bytes,
            "replacement_sha256": segment.intent.replacement_sha256,
        })).collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&identity)
        .map_err(|error| malformed(format!("serialize WAL transaction identity: {error}")))?;
    Ok(sha256(&bytes))
}

fn transaction_id_from_intent(intent: &MigrationIntent) -> Result<String> {
    let identity = serde_json::json!({
        "schema": MIGRATION_SCHEMA,
        "vault_path": intent.vault_path,
        "manifest": intent.manifest,
        "segments": intent.segments.iter().map(|segment| serde_json::json!({
            "index": segment.index,
            "relative_path": segment.relative_path,
            "source_bytes": segment.source_bytes,
            "source_sha256": segment.source_sha256,
            "replacement_bytes": segment.replacement_bytes,
            "replacement_sha256": segment.replacement_sha256,
        })).collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&identity)
        .map_err(|error| malformed(format!("serialize WAL transaction identity: {error}")))?;
    Ok(sha256(&bytes))
}

fn build_intent(
    vault_dir: &Path,
    manifest: ManifestBinding,
    latest_seq_before: u64,
    transaction_id: &str,
    plan: &MigrationPlan,
) -> MigrationIntent {
    let segments = plan
        .segments
        .iter()
        .map(|segment| {
            let mut intent = segment.intent.clone();
            if intent.stage_relative_path.is_some() {
                intent.stage_relative_path = Some(format!(
                    "{MIGRATION_ROOT}/{transaction_id}/staged-{:020}.wal",
                    intent.index
                ));
                intent.backup_relative_path = Some(format!(
                    "{MIGRATION_ROOT}/{transaction_id}/backup-{:020}.wal",
                    intent.index
                ));
            }
            intent
        })
        .collect();
    MigrationIntent {
        schema: MIGRATION_SCHEMA,
        transaction_id: transaction_id.to_string(),
        vault_path: vault_dir.to_string_lossy().into_owned(),
        manifest,
        latest_seq_before,
        records_examined: plan.records_examined,
        segments,
    }
}

fn prepare_transaction(
    migration_root: &Path,
    transaction_dir: &Path,
    intent: &MigrationIntent,
    plan: &MigrationPlan,
) -> Result<()> {
    if transaction_dir.exists() {
        return Err(state_error(format!(
            "new WAL migration transaction path {} already exists",
            transaction_dir.display()
        )));
    }
    fs::create_dir_all(transaction_dir)
        .map_err(|error| storage_error("create WAL migration transaction", error))?;
    crate::fsync::sync_parent(transaction_dir, "WAL migration transaction")?;
    write_json_new(&transaction_dir.join("intent.json"), intent)?;
    for segment in &plan.segments {
        if segment.intent.migrated_records.is_empty() {
            continue;
        }
        let stage = transaction_dir.join(format!("staged-{:020}.wal", segment.intent.index));
        write_bytes_new(&stage, &segment.replacement)?;
        verify_file_identity(
            &stage,
            segment.intent.replacement_bytes,
            &segment.intent.replacement_sha256,
            "staged replacement",
        )?;
    }
    crate::fsync::sync_dir(transaction_dir, "WAL migration transaction")?;
    crate::fsync::sync_dir(migration_root, "WAL migration root")?;
    Ok(())
}

fn find_incomplete_transaction(migration_root: &Path) -> Result<Option<PathBuf>> {
    if !migration_root.exists() {
        return Ok(None);
    }
    if !migration_root.is_dir() {
        return Err(state_error(format!(
            "WAL migration root {} is not a directory",
            migration_root.display()
        )));
    }
    let mut incomplete = Vec::new();
    for entry in fs::read_dir(migration_root)
        .map_err(|error| storage_error("list WAL migration transactions", error))?
    {
        let entry =
            entry.map_err(|error| storage_error("read WAL migration transaction entry", error))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| state_error("WAL migration transaction name is not UTF-8"))?
            .to_string();
        if !path.is_dir()
            || name.len() != 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(state_error(format!(
                "unexpected entry {} in WAL migration root; preserving every byte",
                path.display()
            )));
        }
        if path.join("completion.json").is_file() {
            let completion = read_json::<CompletionReceipt>(&path.join("completion.json"))?;
            if completion.schema != MIGRATION_SCHEMA || completion.transaction_id != name {
                return Err(state_error(format!(
                    "completed WAL migration receipt {} does not match its transaction directory",
                    path.join("completion.json").display()
                )));
            }
        } else {
            if !path.join("intent.json").is_file() {
                return Err(state_error(format!(
                    "incomplete WAL migration {} has no durable intent; preserving every byte",
                    path.display()
                )));
            }
            incomplete.push(path);
        }
    }
    if incomplete.len() > 1 {
        return Err(state_error(format!(
            "{} incomplete WAL migrations exist under {}; explicit reconciliation is required",
            incomplete.len(),
            migration_root.display()
        )));
    }
    Ok(incomplete.pop())
}

fn validate_intent(
    vault_dir: &Path,
    transaction_dir: &Path,
    manifest: &ManifestBinding,
    intent: &MigrationIntent,
) -> Result<()> {
    if intent.schema != MIGRATION_SCHEMA {
        return Err(state_error(format!(
            "WAL migration intent schema {} is unsupported",
            intent.schema
        )));
    }
    let directory_id = transaction_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| state_error("WAL migration transaction directory is not UTF-8"))?;
    if intent.transaction_id != directory_id
        || transaction_id_from_intent(intent)? != intent.transaction_id
    {
        return Err(state_error(format!(
            "WAL migration intent identity does not match {}",
            transaction_dir.display()
        )));
    }
    if intent.vault_path != vault_dir.to_string_lossy() {
        return Err(state_error(format!(
            "WAL migration intent binds vault {:?}, not {}",
            intent.vault_path,
            vault_dir.display()
        )));
    }
    if &intent.manifest != manifest {
        return Err(drift_error(format!(
            "CURRENT/manifest changed after WAL migration intent {}",
            transaction_dir.display()
        )));
    }
    validate_segment_names(intent)?;
    Ok(())
}

fn validate_segment_names(intent: &MigrationIntent) -> Result<()> {
    let mut previous = None;
    for segment in &intent.segments {
        if previous.is_some_and(|index| segment.index <= index) {
            return Err(state_error(
                "WAL migration intent segment indexes are not strictly increasing",
            ));
        }
        previous = Some(segment.index);
        let expected_source = format!("wal/{:020}.wal", segment.index);
        if segment.relative_path != expected_source {
            return Err(state_error(format!(
                "WAL migration segment {} binds unexpected path {:?}",
                segment.index, segment.relative_path
            )));
        }
        let changed = !segment.migrated_records.is_empty();
        let expected_stage = format!(
            "{MIGRATION_ROOT}/{}/staged-{:020}.wal",
            intent.transaction_id, segment.index
        );
        let expected_backup = format!(
            "{MIGRATION_ROOT}/{}/backup-{:020}.wal",
            intent.transaction_id, segment.index
        );
        if changed
            && (segment.stage_relative_path.as_deref() != Some(expected_stage.as_str())
                || segment.backup_relative_path.as_deref() != Some(expected_backup.as_str()))
        {
            return Err(state_error(format!(
                "WAL migration segment {} stage/backup paths are not transaction-bound",
                segment.index
            )));
        }
        if !changed
            && (segment.stage_relative_path.is_some() || segment.backup_relative_path.is_some())
        {
            return Err(state_error(format!(
                "unchanged WAL segment {} unexpectedly has publication paths",
                segment.index
            )));
        }
    }
    Ok(())
}

fn execute_transaction(
    vault_dir: &Path,
    wal_dir: &Path,
    transaction_dir: &Path,
    intent: &MigrationIntent,
    disposition: LegacyWalMigrationDisposition,
) -> Result<LegacyWalMigrationReport> {
    validate_canonical_segment_set(wal_dir, &intent.segments)?;
    for segment in &intent.segments {
        let source = vault_dir.join(&segment.relative_path);
        if segment.migrated_records.is_empty() {
            verify_file_identity(
                &source,
                segment.source_bytes,
                &segment.source_sha256,
                "unchanged WAL segment",
            )?;
            continue;
        }
        publish_segment(vault_dir, transaction_dir, intent, segment)?;
    }

    let manifest_after = read_manifest_binding(vault_dir)?;
    if manifest_after != intent.manifest {
        return Err(drift_error(format!(
            "CURRENT/manifest changed before WAL migration readback for {}",
            transaction_dir.display()
        )));
    }
    validate_canonical_segment_set(wal_dir, &intent.segments)?;
    let mut backups = Vec::new();
    for segment in &intent.segments {
        let source = vault_dir.join(&segment.relative_path);
        let expected_bytes = if segment.migrated_records.is_empty() {
            segment.source_bytes
        } else {
            segment.replacement_bytes
        };
        let expected_hash = if segment.migrated_records.is_empty() {
            &segment.source_sha256
        } else {
            &segment.replacement_sha256
        };
        verify_file_identity(
            &source,
            expected_bytes,
            expected_hash,
            "published WAL segment",
        )?;
        if let Some(relative) = &segment.backup_relative_path {
            let backup = vault_dir.join(relative);
            verify_file_identity(
                &backup,
                segment.source_bytes,
                &segment.source_sha256,
                "retained WAL backup",
            )?;
            backups.push(LegacyWalBackup {
                segment_index: segment.index,
                path: backup,
                bytes: segment.source_bytes,
                sha256: segment.source_sha256.clone(),
            });
        }
    }

    let replay = replay::replay_dir_read_only_locked_after(wal_dir, intent.manifest.durable_seq)?;
    let latest_seq_after = replay
        .records
        .last()
        .map_or(intent.manifest.durable_seq, |record| record.seq);
    if latest_seq_after != intent.latest_seq_before {
        return Err(drift_error(format!(
            "WAL latest seq changed across migration: before {}, after {latest_seq_after}",
            intent.latest_seq_before
        )));
    }
    let expected_rows = expected_migrated_values(vault_dir, intent)?;
    let mut observed_rows = BTreeMap::new();
    for record in replay.records {
        let rows = decode_write_batch(&record.payload)?;
        if expected_rows.contains_key(&record.seq) {
            observed_rows.insert(record.seq, rows);
        }
    }
    if observed_rows != expected_rows {
        return Err(drift_error(format!(
            "published CXLWAL2 row readback differs from the intent in {}",
            transaction_dir.display()
        )));
    }

    let records_migrated = intent
        .segments
        .iter()
        .map(|segment| segment.migrated_records.len())
        .sum();
    let rows_migrated = intent
        .segments
        .iter()
        .flat_map(|segment| &segment.migrated_records)
        .map(|record| record.rows.len())
        .sum();
    let completion = CompletionReceipt {
        schema: MIGRATION_SCHEMA,
        transaction_id: intent.transaction_id.clone(),
        manifest: intent.manifest.clone(),
        latest_seq_before: intent.latest_seq_before,
        latest_seq_after,
        segments_migrated: backups.len(),
        records_migrated,
        rows_migrated,
        retained_backups: backups
            .iter()
            .map(|backup| CompletionBackup {
                segment_index: backup.segment_index,
                relative_path: backup
                    .path
                    .strip_prefix(vault_dir)
                    .expect("backup is vault-relative")
                    .to_string_lossy()
                    .replace('\\', "/"),
                bytes: backup.bytes,
                sha256: backup.sha256.clone(),
            })
            .collect(),
    };
    let completion_path = transaction_dir.join("completion.json");
    write_json_new(&completion_path, &completion)?;
    let completion_readback = read_json::<CompletionReceipt>(&completion_path)?;
    if completion_readback != completion {
        return Err(state_error(format!(
            "WAL migration completion receipt {} failed readback",
            completion_path.display()
        )));
    }

    let migrated_rows = intent
        .segments
        .iter()
        .flat_map(|segment| &segment.migrated_records)
        .flat_map(|record| record.rows.clone())
        .collect::<Vec<_>>();
    Ok(LegacyWalMigrationReport {
        vault_path: vault_dir.to_path_buf(),
        disposition,
        manifest_pointer: intent.manifest.pointer.clone(),
        manifest_sha256: intent.manifest.manifest_sha256.clone(),
        manifest_durable_seq: intent.manifest.durable_seq,
        latest_seq_before: intent.latest_seq_before,
        latest_seq_after,
        segments_examined: intent.segments.len(),
        segments_migrated: backups.len(),
        records_examined: intent.records_examined,
        records_migrated,
        rows_migrated,
        transaction_id: Some(intent.transaction_id.clone()),
        transaction_dir: Some(transaction_dir.to_path_buf()),
        completion_receipt: Some(completion_path),
        retained_backups: backups,
        migrated_rows,
    })
}

fn publish_segment(
    vault_dir: &Path,
    transaction_dir: &Path,
    intent: &MigrationIntent,
    segment: &SegmentIntent,
) -> Result<()> {
    let source = vault_dir.join(&segment.relative_path);
    let stage = vault_dir.join(
        segment
            .stage_relative_path
            .as_deref()
            .ok_or_else(|| state_error("changed segment has no stage path"))?,
    );
    let backup = vault_dir.join(
        segment
            .backup_relative_path
            .as_deref()
            .ok_or_else(|| state_error("changed segment has no backup path"))?,
    );

    let mut source_identity = optional_file_identity(&source)?;
    let backup_identity = optional_file_identity(&backup)?;
    let stage_identity = optional_file_identity(&stage)?;
    if let Some((bytes, hash)) = &stage_identity
        && (*bytes != segment.replacement_bytes || hash != &segment.replacement_sha256)
    {
        return Err(drift_error(format!(
            "staged replacement {} drifted: expected {} bytes/{}, got {bytes}/{hash}",
            stage.display(),
            segment.replacement_bytes,
            segment.replacement_sha256
        )));
    }
    if let Some((bytes, hash)) = &backup_identity
        && (*bytes != segment.source_bytes || hash != &segment.source_sha256)
    {
        return Err(drift_error(format!(
            "retained backup {} drifted: expected {} bytes/{}, got {bytes}/{hash}",
            backup.display(),
            segment.source_bytes,
            segment.source_sha256
        )));
    }
    if source_identity.as_ref().is_some_and(|(bytes, hash)| {
        (*bytes, hash.as_str()) == (segment.replacement_bytes, &segment.replacement_sha256)
    }) && backup_identity.is_some()
    {
        ensure_publication_marker(transaction_dir, intent, segment, "completed")?;
        return Ok(());
    }

    if stage_identity.is_none() {
        let legacy_source = if source_identity.as_ref().is_some_and(|(bytes, hash)| {
            (*bytes, hash.as_str()) == (segment.source_bytes, &segment.source_sha256)
        }) {
            &source
        } else if backup_identity.is_some() {
            &backup
        } else {
            return Err(drift_error(format!(
                "cannot rebuild missing stage for segment {}: neither source nor backup matches the intent",
                segment.index
            )));
        };
        let rebuilt = plan_segment(
            segment.index,
            legacy_source,
            &segment.relative_path,
            intent.manifest.durable_seq,
        )?;
        if rebuilt.intent.source_bytes != segment.source_bytes
            || rebuilt.intent.source_sha256 != segment.source_sha256
            || rebuilt.intent.replacement_bytes != segment.replacement_bytes
            || rebuilt.intent.replacement_sha256 != segment.replacement_sha256
            || rebuilt.intent.migrated_records != segment.migrated_records
        {
            return Err(drift_error(format!(
                "reconstructed stage for segment {} does not match durable intent",
                segment.index
            )));
        }
        write_bytes_new(&stage, &rebuilt.replacement)?;
    }
    verify_file_identity(
        &stage,
        segment.replacement_bytes,
        &segment.replacement_sha256,
        "staged replacement",
    )?;
    ensure_publication_marker(transaction_dir, intent, segment, "started")?;

    source_identity = optional_file_identity(&source)?;
    let backup_identity = optional_file_identity(&backup)?;
    match (source_identity, backup_identity) {
        (Some((source_bytes, source_hash)), None)
            if source_bytes == segment.source_bytes && source_hash == segment.source_sha256 =>
        {
            replace_file_with_backup(&source, &stage, &backup)?;
        }
        (Some((source_bytes, source_hash)), Some((backup_bytes, backup_hash)))
            if source_bytes == segment.source_bytes
                && source_hash == segment.source_sha256
                && backup_bytes == segment.source_bytes
                && backup_hash == segment.source_sha256 =>
        {
            move_file_replace(&stage, &source)?;
        }
        (None, Some((backup_bytes, backup_hash)))
            if backup_bytes == segment.source_bytes && backup_hash == segment.source_sha256 =>
        {
            move_file_replace(&stage, &source)?;
        }
        (Some((source_bytes, source_hash)), Some((backup_bytes, backup_hash)))
            if source_bytes == segment.replacement_bytes
                && source_hash == segment.replacement_sha256
                && backup_bytes == segment.source_bytes
                && backup_hash == segment.source_sha256 => {}
        (source_state, backup_state) => {
            return Err(drift_error(format!(
                "segment {} publication state does not match source/replacement/backup identities: source={source_state:?}, backup={backup_state:?}",
                segment.index
            )));
        }
    }
    crate::fsync::sync_dir(
        source
            .parent()
            .ok_or_else(|| state_error("WAL source has no parent"))?,
        "published WAL directory",
    )?;
    crate::fsync::sync_dir(transaction_dir, "WAL migration transaction")?;
    verify_file_identity(
        &source,
        segment.replacement_bytes,
        &segment.replacement_sha256,
        "published WAL segment",
    )?;
    verify_file_identity(
        &backup,
        segment.source_bytes,
        &segment.source_sha256,
        "retained WAL backup",
    )?;
    ensure_publication_marker(transaction_dir, intent, segment, "completed")
}

fn expected_migrated_values(
    vault_dir: &Path,
    intent: &MigrationIntent,
) -> Result<BTreeMap<u64, Vec<WriteRow>>> {
    let mut expected = BTreeMap::new();
    for segment in &intent.segments {
        if segment.migrated_records.is_empty() {
            continue;
        }
        let backup = vault_dir.join(
            segment
                .backup_relative_path
                .as_deref()
                .ok_or_else(|| state_error("changed segment has no backup path"))?,
        );
        let plan = plan_segment(
            segment.index,
            &backup,
            &segment.relative_path,
            intent.manifest.durable_seq,
        )?;
        if plan.intent.migrated_records != segment.migrated_records {
            return Err(drift_error(format!(
                "retained backup {} no longer decodes to the durable migration intent",
                backup.display()
            )));
        }
        for (sequence, rows) in plan.migrated_values {
            if expected.insert(sequence, rows).is_some() {
                return Err(state_error(format!(
                    "duplicate migrated WAL sequence {sequence} across segments"
                )));
            }
        }
    }
    Ok(expected)
}

fn validate_canonical_segment_set(wal_dir: &Path, expected: &[SegmentIntent]) -> Result<()> {
    let actual = segment::list_segments(wal_dir)?;
    let actual_indexes = actual.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    let expected_indexes = expected
        .iter()
        .map(|segment| segment.index)
        .collect::<Vec<_>>();
    if actual_indexes != expected_indexes {
        return Err(drift_error(format!(
            "canonical WAL segment set changed: expected {expected_indexes:?}, got {actual_indexes:?}"
        )));
    }
    Ok(())
}

fn ensure_publication_marker(
    transaction_dir: &Path,
    intent: &MigrationIntent,
    segment: &SegmentIntent,
    phase: &str,
) -> Result<()> {
    let marker = PublicationMarker {
        schema: MIGRATION_SCHEMA,
        transaction_id: intent.transaction_id.clone(),
        phase: phase.to_string(),
        segment_index: segment.index,
        source_sha256: segment.source_sha256.clone(),
        replacement_sha256: segment.replacement_sha256.clone(),
    };
    let path = transaction_dir.join(format!("{phase}-{:020}.json", segment.index));
    if path.exists() {
        let actual = read_json::<PublicationMarker>(&path)?;
        if actual != marker {
            return Err(state_error(format!(
                "WAL migration marker {} does not match its transaction",
                path.display()
            )));
        }
        return Ok(());
    }
    write_json_new(&path, &marker)
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| malformed(format!("encode {}: {error}", path.display())))?;
    bytes.push(b'\n');
    write_bytes_new(path, &bytes)
}

fn write_bytes_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| storage_error("create WAL migration file", error))?;
    file.write_all(bytes)
        .map_err(|error| storage_error("write WAL migration file", error))?;
    file.sync_all()
        .map_err(|error| storage_error("fsync WAL migration file", error))?;
    crate::fsync::sync_parent(path, "WAL migration file")
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes =
        fs::read(path).map_err(|error| storage_error("read WAL migration receipt", error))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        state_error(format!(
            "decode WAL migration receipt {}: {error}; preserving every byte",
            path.display()
        ))
    })
}

fn optional_file_identity(path: &Path) -> Result<Option<(u64, String)>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some((bytes.len() as u64, sha256(&bytes)))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(storage_error("read WAL migration identity", error)),
    }
}

fn verify_file_identity(path: &Path, bytes: u64, hash: &str, label: &str) -> Result<()> {
    let (actual_bytes, actual_hash) = optional_file_identity(path)?
        .ok_or_else(|| drift_error(format!("expected {label} {} is absent", path.display())))?;
    if actual_bytes != bytes || actual_hash != hash {
        return Err(drift_error(format!(
            "{label} {} identity mismatch: expected {bytes} bytes/{hash}, got {actual_bytes}/{actual_hash}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn replace_file_with_backup(source: &Path, stage: &Path, backup: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{REPLACEFILE_WRITE_THROUGH, ReplaceFileW};

    let source_wide = wide_path(source)?;
    let stage_wide = wide_path(stage)?;
    let backup_wide = wide_path(backup)?;
    let replaced = unsafe {
        ReplaceFileW(
            source_wide.as_ptr(),
            stage_wide.as_ptr(),
            backup_wide.as_ptr(),
            REPLACEFILE_WRITE_THROUGH,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if replaced == 0 {
        return Err(publication_error(format!(
            "ReplaceFileW({}, {}, backup={}) failed: {}; the durable intent and stage were preserved",
            source.display(),
            stage.display(),
            backup.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_file_with_backup(_source: &Path, _stage: &Path, _backup: &Path) -> Result<()> {
    Err(publication_error(
        "backup-preserving WAL migration is available only on the current Windows target",
    ))
}

#[cfg(windows)]
fn move_file_replace(stage: &Path, source: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let stage_wide = wide_path(stage)?;
    let source_wide = wide_path(source)?;
    let moved = unsafe {
        MoveFileExW(
            stage_wide.as_ptr(),
            source_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(publication_error(format!(
            "MoveFileExW recovery publication {} -> {} failed: {}; the retained backup and stage were preserved",
            stage.display(),
            source.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn move_file_replace(_stage: &Path, _source: &Path) -> Result<()> {
    Err(publication_error(
        "WAL migration recovery publication is available only on the current Windows target",
    ))
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(state_error(format!(
            "WAL migration path {} contains an interior NUL",
            path.display()
        )));
    }
    wide.push(0);
    Ok(wide)
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

struct LegacyCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> LegacyCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| malformed("legacy WAL cursor offset overflow"))?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            malformed(format!(
                "legacy WAL bytes truncated at offset {}: need {len}, have {}",
                self.offset,
                self.remaining()
            ))
        })?;
        self.offset = end;
        Ok(value)
    }

    fn bytes_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.bytes(4)?.try_into().expect("four-byte cursor slice"),
        ))
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}

fn migration_locked(message: String) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_WAL_MIGRATION_LOCKED,
        message,
        remediation: "close the exact live vault writer and rerun the explicit migration; never bypass the WAL append lock",
    }
}

fn malformed(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_WAL_MIGRATION_MALFORMED,
        message: message.into(),
        remediation: "preserve the vault bytes and identify the exact historical format before retrying",
    }
}

fn drift_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_WAL_MIGRATION_DRIFT,
        message: message.into(),
        remediation: "preserve the source, stage, backup, and receipts; reconcile the exact hashes before resuming",
    }
}

fn state_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_WAL_MIGRATION_STATE,
        message: message.into(),
        remediation: "preserve every migration byte and resume only the exact hash-bound transaction",
    }
}

fn publication_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_WAL_MIGRATION_PUBLICATION,
        message: message.into(),
        remediation: "remove the exact external handle or storage fault, then rerun to resume the durable transaction; never delete its stage or backup",
    }
}
