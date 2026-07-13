//! Physical erasure-scrub policy for the Aster vault WAL (#61, P9.3).
//!
//! # The gap this closes
//!
//! Lawful erasure ([`calyx_aster::erase`]) tombstones a scope's rows and, via
//! [`AsterVault::purge_tombstoned_cfs`], compacts the affected column families so
//! the erased plaintext leaves the SST tier — this mirrors RocksDB, where
//! deleted-key space "is reclaimed only later, during compaction, and only once
//! the tombstone reaches the bottommost level". But the *write-ahead log* still
//! physically holds the original append records: their value bytes (the erased
//! plaintext) sit in the WAL segment files until the log is checkpointed *and
//! truncated*. This is the exact hazard SQLite documents — under WAL journal
//! mode "old content may remain in the WAL file even after the checkpoint until
//! it's truncated" — and it is why a byte-grep of a freshly-erased vault still
//! finds the erased marker under `wal/`.
//!
//! The engine's own [`calyx_aster::gc::wal_recycler`] never closes this gap for a
//! small vault: it only recycles *non-active* segments whose records are already
//! durable, and it deliberately leaves the *active* segment intact. In a vault
//! whose entire history fits in one (active) segment — the common case for a
//! per-repository code graph — that means the erased plaintext is never removed.
//!
//! # The policy
//!
//! This module implements the SQLite `PRAGMA wal_checkpoint(TRUNCATE)` posture as
//! a lawful, ledgered, fail-closed erasure step over the Aster vault:
//!
//! 1. **Checkpoint.** [`AsterVault::flush`] drives every committed batch into
//!    durable-batch SSTs and advances the manifest `durable_seq` to cover the
//!    whole WAL (the storage engine already enforces this coverage invariant —
//!    see `verified_durable_coverage_seq`).
//! 2. **Prove coverage.** [`calyx_aster::manifest::recover_vault`] is read back:
//!    if any WAL record has a seq beyond `durable_seq`, or the WAL has a torn
//!    tail, the scrub **fails closed** rather than truncate un-checkpointed
//!    records. This is the analogue of SQLite requiring the checkpoint to precede
//!    the truncation.
//! 3. **Ledger.** An [`EntryKind::Admin`] entry records the scrub (scope subject,
//!    durable seq, and the pre-scrub WAL byte/segment inventory) so the physical
//!    mutation is paired with an immutable audit row, per the standing invariant.
//! 4. **Truncate.** Every WAL segment file — including the active one, which the
//!    recycler will not touch — is truncated to zero bytes and fsynced. Because
//!    coverage was proven, the truncated records are fully recoverable from the
//!    SST tier; the vault reopens cleanly with an empty WAL replayed above the
//!    `durable_seq` floor.
//!
//! # Handle discipline
//!
//! [`scrub_erased_wal_history`] **consumes** the vault and drops it before it
//! touches the WAL files, so no live append handle observes the truncation. The
//! caller reopens the vault (with the same directory) for post-scrub reads. The
//! batch granularity is the registry-declared knob
//! [`astrolabe_domain::knobs::ERASURE_SCRUB_SEGMENTS_PER_FSYNC_BATCH_KNOB`].

use std::fs;
use std::path::{Path, PathBuf};

use astrolabe_domain::knobs::{
    ERASURE_SCRUB_MAX_SEGMENTS_PER_FSYNC_BATCH, ERASURE_SCRUB_SEGMENTS_PER_FSYNC_BATCH_KNOB,
    erasure_scrub_knob,
};
use calyx_aster::manifest::recover_vault;
use calyx_aster::vault::AsterVault;
use calyx_core::{Clock, LedgerRef};
use calyx_ledger::{ActorId, EntryKind, SubjectId};
use serde_json::json;

use crate::registry::{IngestError, IngestResult};

/// Refusal: the WAL still holds records beyond the durable checkpoint, so
/// truncating it would discard un-checkpointed data. The caller must flush first.
pub const ASTRO_ERASURE_SCRUB_WAL_UNCOVERED: &str = "ASTRO_ERASURE_SCRUB_WAL_UNCOVERED";
/// Refusal: the WAL has a torn tail; scrubbing a damaged log is unsafe.
pub const ASTRO_ERASURE_SCRUB_TORN_WAL: &str = "ASTRO_ERASURE_SCRUB_TORN_WAL";
/// Refusal: the target is not a durable on-disk vault (no `wal/` directory).
pub const ASTRO_ERASURE_SCRUB_NOT_DURABLE: &str = "ASTRO_ERASURE_SCRUB_NOT_DURABLE";
/// Refusal: the requested fsync-batch size is outside the declared knob bounds.
pub const ASTRO_ERASURE_SCRUB_BATCH_INVALID: &str = "ASTRO_ERASURE_SCRUB_BATCH_INVALID";
/// Refusal: a WAL segment file could not be truncated or fsynced.
pub const ASTRO_ERASURE_SCRUB_IO: &str = "ASTRO_ERASURE_SCRUB_IO";

const WAL_UNCOVERED_REMEDIATION: &str = "Flush the vault so the manifest durable_seq covers the whole WAL before scrubbing; the WAL tail carries records not yet in the SST tier.";
const TORN_WAL_REMEDIATION: &str =
    "Recover the vault (reopen it) to heal the torn WAL tail, then retry the scrub.";
const NOT_DURABLE_REMEDIATION: &str = "Run the physical erasure scrub only against a durable on-disk vault directory that contains a wal/ segment tree.";
const BATCH_REMEDIATION: &str = "Set the erasure-scrub fsync-batch size inside the declared knob bounds, or use WalScrubParams::from_registry() for the registry default.";
const IO_REMEDIATION: &str = "Ensure the vault directory is writable and no other process holds the WAL segment files, then retry the scrub.";

/// Schema tag stamped on the scrub's Admin ledger payload.
pub const WAL_SCRUB_LEDGER_SCHEMA: &str = "astrolabe-erasure-wal-scrub-v1";

const WAL_DIR_NAME: &str = "wal";
const WAL_SEGMENT_EXT: &str = "wal";

/// Registry-bounded parameters for the physical erasure scrub.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalScrubParams {
    segments_per_fsync_batch: u64,
}

impl WalScrubParams {
    /// Builds params from the registry-declared default batch knob.
    pub fn from_registry() -> Self {
        let knob = erasure_scrub_knob(ERASURE_SCRUB_SEGMENTS_PER_FSYNC_BATCH_KNOB)
            .expect("erasure-scrub batch knob is declared in the knob registry");
        Self {
            segments_per_fsync_batch: knob.default,
        }
    }

    /// Builds params with an explicit batch size, validated against the knob
    /// bounds. Fails closed with [`ASTRO_ERASURE_SCRUB_BATCH_INVALID`] otherwise.
    pub fn with_segments_per_fsync_batch(segments_per_fsync_batch: u64) -> IngestResult<Self> {
        let knob = erasure_scrub_knob(ERASURE_SCRUB_SEGMENTS_PER_FSYNC_BATCH_KNOB)
            .expect("erasure-scrub batch knob is declared in the knob registry");
        if !knob.accepts(segments_per_fsync_batch) {
            return Err(IngestError::refused(
                ASTRO_ERASURE_SCRUB_BATCH_INVALID,
                format!(
                    "erasure-scrub fsync-batch size {segments_per_fsync_batch} is outside the declared knob bounds [{}, {}]",
                    knob.min, knob.max
                ),
                BATCH_REMEDIATION,
            ));
        }
        Ok(Self {
            segments_per_fsync_batch,
        })
    }

    /// The validated fsync-batch size in segments.
    pub fn segments_per_fsync_batch(&self) -> u64 {
        self.segments_per_fsync_batch
    }
}

impl Default for WalScrubParams {
    fn default() -> Self {
        Self::from_registry()
    }
}

/// Outcome of a completed physical erasure scrub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalScrubReport {
    /// Manifest `durable_seq` proven to cover the entire WAL before truncation.
    pub durable_seq: u64,
    /// Ledger seq of the paired [`EntryKind::Admin`] scrub-audit entry.
    pub ledger_seq: u64,
    /// WAL segment files present at truncation time.
    pub wal_segments_total: usize,
    /// WAL segment files truncated to zero bytes by this scrub.
    pub wal_segments_scrubbed: usize,
    /// Physical WAL bytes reclaimed (sum of truncated segment lengths).
    pub wal_bytes_reclaimed: u64,
    /// Total WAL bytes remaining after the scrub. Zero on a completed scrub.
    pub wal_bytes_remaining: u64,
}

impl WalScrubReport {
    /// True only when every WAL segment is zero bytes after the scrub.
    pub fn wal_is_quiescent(&self) -> bool {
        self.wal_bytes_remaining == 0
    }
}

/// Honest physical-WAL status, independent of any scrub claim.
///
/// Used to report the crash-before-scrub state truthfully: after a tombstone but
/// before a scrub, `wal_bytes` is non-zero and [`Self::is_wal_quiescent`] is
/// false — the caller must never report such a vault as physically erased.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalScrubStatus {
    /// Total bytes across every WAL segment file.
    pub wal_bytes: u64,
    /// Count of WAL segment files that still hold bytes.
    pub wal_segments_nonempty: usize,
    /// True when the manifest `durable_seq` covers the whole WAL (checkpointed).
    pub checkpoint_covers_wal: bool,
}

impl WalScrubStatus {
    /// True only when no WAL segment holds any bytes.
    pub fn is_wal_quiescent(&self) -> bool {
        self.wal_bytes == 0
    }
}

/// Reads the honest physical-WAL status of a durable vault directory.
///
/// This performs no mutation and makes no erasure claim. It fails closed if the
/// directory is not a durable vault.
pub fn wal_scrub_status(vault_dir: &Path) -> IngestResult<WalScrubStatus> {
    ensure_durable(vault_dir)?;
    let segments = inventory_segments(vault_dir)?;
    let wal_bytes = segments.iter().map(|segment| segment.bytes).sum();
    let wal_segments_nonempty = segments.iter().filter(|segment| segment.bytes > 0).count();
    let recovery = recover_vault(vault_dir)?;
    let checkpoint_covers_wal = recovery.torn_tail.is_none() && recovery.wal_records.is_empty();
    Ok(WalScrubStatus {
        wal_bytes,
        wal_segments_nonempty,
        checkpoint_covers_wal,
    })
}

/// Drives the physical store to a state where an erased scope's plaintext is
/// gone from the WAL, provably. See the module docs for the policy.
///
/// The vault is **consumed** and dropped before any WAL file is touched, so no
/// live append handle observes the truncation; reopen the same directory for
/// post-scrub reads. `subject`/`actor` identify the erased scope and the caller
/// in the paired Admin ledger entry.
///
/// Fails closed (never a silent partial scrub) if the WAL is not fully
/// checkpointed ([`ASTRO_ERASURE_SCRUB_WAL_UNCOVERED`]), the WAL is torn
/// ([`ASTRO_ERASURE_SCRUB_TORN_WAL`]), the target is not durable
/// ([`ASTRO_ERASURE_SCRUB_NOT_DURABLE`]), or a segment cannot be truncated
/// ([`ASTRO_ERASURE_SCRUB_IO`]).
pub fn scrub_erased_wal_history<C>(
    vault: AsterVault<C>,
    vault_dir: &Path,
    params: &WalScrubParams,
    subject: SubjectId,
    actor: ActorId,
) -> IngestResult<WalScrubReport>
where
    C: Clock,
{
    ensure_durable(vault_dir)?;

    // 1. Checkpoint: push every committed batch into the durable SST tier and
    //    advance the manifest durable_seq to cover the whole WAL.
    vault.flush()?;

    // 2. Prove coverage before we record intent, so an un-checkpointed WAL is
    //    refused before any ledger row is written.
    assert_wal_checkpointed(vault_dir)?;
    let pre = inventory_segments(vault_dir)?;
    let wal_bytes_before: u64 = pre.iter().map(|segment| segment.bytes).sum();

    // 3. Ledger: pair the physical scrub with an immutable Admin audit entry. The
    //    payload carries only counts and the durable seq — never plaintext.
    let durable_seq_before = recover_vault(vault_dir)?.manifest.durable_seq;
    let payload = serde_json::to_vec(&json!({
        "schema": WAL_SCRUB_LEDGER_SCHEMA,
        "durable_seq": durable_seq_before,
        "wal_segments_present": pre.len(),
        "wal_bytes_present": wal_bytes_before,
        "policy": "wal_checkpoint_truncate",
    }))?;
    let ledger_ref: LedgerRef =
        vault.append_ledger_entry(EntryKind::Admin, subject, payload, actor)?;

    // 4. Re-checkpoint so the audit entry's own WAL record is itself durable, and
    //    re-prove coverage before truncating.
    vault.flush()?;
    assert_wal_checkpointed(vault_dir)?;
    let durable_seq = recover_vault(vault_dir)?.manifest.durable_seq;

    // 5. Drop the vault BEFORE touching WAL files so no live append handle
    //    observes the truncation.
    drop(vault);

    // 6. Truncate every segment to zero bytes, in registry-bounded fsync batches.
    let segments = inventory_segments(vault_dir)?;
    let wal_segments_total = segments.len();
    let batch = params
        .segments_per_fsync_batch
        .clamp(1, ERASURE_SCRUB_MAX_SEGMENTS_PER_FSYNC_BATCH) as usize;
    let mut wal_segments_scrubbed = 0usize;
    let mut wal_bytes_reclaimed = 0u64;
    for chunk in segments.chunks(batch) {
        for segment in chunk {
            if segment.bytes == 0 {
                continue;
            }
            truncate_segment(&segment.path)?;
            wal_segments_scrubbed += 1;
            wal_bytes_reclaimed = wal_bytes_reclaimed.saturating_add(segment.bytes);
        }
    }

    let after = inventory_segments(vault_dir)?;
    let wal_bytes_remaining = after.iter().map(|segment| segment.bytes).sum();

    Ok(WalScrubReport {
        durable_seq,
        ledger_seq: ledger_ref.seq,
        wal_segments_total,
        wal_segments_scrubbed,
        wal_bytes_reclaimed,
        wal_bytes_remaining,
    })
}

struct SegmentEntry {
    path: PathBuf,
    bytes: u64,
}

fn wal_dir(vault_dir: &Path) -> PathBuf {
    vault_dir.join(WAL_DIR_NAME)
}

fn ensure_durable(vault_dir: &Path) -> IngestResult<()> {
    if wal_dir(vault_dir).is_dir() {
        return Ok(());
    }
    Err(IngestError::refused(
        ASTRO_ERASURE_SCRUB_NOT_DURABLE,
        format!(
            "vault directory {} has no wal/ segment tree; it is not a durable on-disk vault",
            vault_dir.display()
        ),
        NOT_DURABLE_REMEDIATION,
    ))
}

/// Fails closed unless the WAL is fully covered by the durable checkpoint.
fn assert_wal_checkpointed(vault_dir: &Path) -> IngestResult<()> {
    let recovery = recover_vault(vault_dir)?;
    if recovery.torn_tail.is_some() {
        return Err(IngestError::refused(
            ASTRO_ERASURE_SCRUB_TORN_WAL,
            format!(
                "vault {} has a torn WAL tail; refusing to scrub a damaged log",
                vault_dir.display()
            ),
            TORN_WAL_REMEDIATION,
        ));
    }
    if !recovery.wal_records.is_empty() {
        return Err(IngestError::refused(
            ASTRO_ERASURE_SCRUB_WAL_UNCOVERED,
            format!(
                "vault {} has {} WAL record(s) beyond durable_seq {}; the WAL is not fully checkpointed",
                vault_dir.display(),
                recovery.wal_records.len(),
                recovery.manifest.durable_seq
            ),
            WAL_UNCOVERED_REMEDIATION,
        ));
    }
    Ok(())
}

fn inventory_segments(vault_dir: &Path) -> IngestResult<Vec<SegmentEntry>> {
    let dir = wal_dir(vault_dir);
    let mut segments = Vec::new();
    let entries = fs::read_dir(&dir).map_err(|error| {
        IngestError::refused(
            ASTRO_ERASURE_SCRUB_IO,
            format!("read WAL directory {}: {error}", dir.display()),
            IO_REMEDIATION,
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            IngestError::refused(
                ASTRO_ERASURE_SCRUB_IO,
                format!("read WAL directory entry in {}: {error}", dir.display()),
                IO_REMEDIATION,
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some(WAL_SEGMENT_EXT) {
            continue;
        }
        let bytes = fs::metadata(&path)
            .map_err(|error| {
                IngestError::refused(
                    ASTRO_ERASURE_SCRUB_IO,
                    format!("stat WAL segment {}: {error}", path.display()),
                    IO_REMEDIATION,
                )
            })?
            .len();
        segments.push(SegmentEntry { path, bytes });
    }
    segments.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(segments)
}

fn truncate_segment(path: &Path) -> IngestResult<()> {
    let file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| {
            IngestError::refused(
                ASTRO_ERASURE_SCRUB_IO,
                format!(
                    "open WAL segment {} for truncation: {error}",
                    path.display()
                ),
                IO_REMEDIATION,
            )
        })?;
    file.set_len(0).map_err(|error| {
        IngestError::refused(
            ASTRO_ERASURE_SCRUB_IO,
            format!("truncate WAL segment {}: {error}", path.display()),
            IO_REMEDIATION,
        )
    })?;
    file.sync_data().map_err(|error| {
        IngestError::refused(
            ASTRO_ERASURE_SCRUB_IO,
            format!("fsync truncated WAL segment {}: {error}", path.display()),
            IO_REMEDIATION,
        )
    })?;
    Ok(())
}
