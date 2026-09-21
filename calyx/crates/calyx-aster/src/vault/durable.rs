mod checkpointing;
mod manifest_ops;
mod recovery_readback;
pub(in crate::vault) mod router_coverage;
mod router_handoff_state;

use recovery_readback::read_manifested_batches;

use super::encode::{WriteRow, decode_write_batch, encode_write_batch};
use crate::cf::ColumnFamily;
use crate::compaction::TieringPolicy;
use crate::dedup::DedupPolicy;
use crate::manifest::{recover_vault, recover_vault_read_only};
use crate::pressure::DiskPressureGuard;
use crate::resource::ResourceCounters;
use crate::sst::SstSummary;
use crate::timetravel::RetentionHorizon;
use crate::wal::{GroupCommitBatcher, WalOptions, replay_dir, replay_dir_read_only_after};
use calyx_core::{CalyxError, Panel, Result, SystemClock, TemporalPolicy};
use calyx_ledger::CheckpointConfig;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct VaultOptions {
    pub wal_options: WalOptions,
    pub memtable_byte_cap: usize,
    pub tiering_policy: Option<TieringPolicy>,
    pub ledger_checkpoint: Option<CheckpointConfig>,
    pub temporal_policy: Option<TemporalPolicy>,
    pub dedup_policy: Option<DedupPolicy>,
    pub retention_horizon: RetentionHorizon,
    pub panel: Option<Panel>,
    /// Optional data-residency pin (PRD `30 §4`). When set, the vault's storage
    /// location is pinned and off-dataset writes/copies fail closed.
    pub residency: Option<crate::residency::Residency>,
    pub disk_pressure_guard: Option<DiskPressureGuard>,
    /// Restores checkpointed durable-batch/compacted SST rows plus the WAL
    /// tail into the in-memory MVCC table on open. Router memtable-flush SSTs
    /// carry flush ordinals, not commit seqs, so they are never restored; the
    /// open fails closed with `CALYX_ASTER_ROUTER_ONLY_ROWS` if any router
    /// row lacks a commit-domain durable home (issue #1132). Disable for
    /// latest-read workloads that use the CF router as the source of truth
    /// and do not request historical reads.
    pub restore_mvcc_rows: bool,
    /// Restores the full in-memory ledger hook on open. Disable only for
    /// explicitly read-only handles that verify/search latest state without
    /// appending ledger entries.
    pub restore_ledger_hook: bool,
    /// Opens the vault as a read-only handle. Any write through this handle
    /// fails before WAL append or MVCC mutation.
    pub read_only: bool,
    /// Restricts router recovery to a concrete CF set. This keeps analytical
    /// reads and narrowly scoped generation writers from enumerating unrelated
    /// large CFs. A write-capable selection is accepted only when the restored
    /// ledger hook is enabled and both Ledger and TimeIndex are explicit.
    /// Any point, batch, or range read of a CF outside this set fails with
    /// `CALYX_ASTER_CF_NOT_SELECTED`; it never reports synthetic absence.
    pub selected_cfs: Option<Vec<ColumnFamily>>,
    /// Explicit admission for a write-capable selected-CF handle. This is never
    /// inferred from `read_only=false`; callers must opt into the narrow mode
    /// and still include Ledger plus TimeIndex below.
    pub writable_selected_cfs: bool,
}

impl Default for VaultOptions {
    fn default() -> Self {
        Self {
            wal_options: WalOptions::default(),
            memtable_byte_cap: 0,
            tiering_policy: None,
            ledger_checkpoint: Some(CheckpointConfig::default()),
            temporal_policy: Some(TemporalPolicy::default()),
            dedup_policy: Some(DedupPolicy::default()),
            retention_horizon: RetentionHorizon::default(),
            panel: None,
            residency: None,
            disk_pressure_guard: None,
            restore_mvcc_rows: true,
            restore_ledger_hook: true,
            read_only: false,
            selected_cfs: None,
            writable_selected_cfs: false,
        }
    }
}

#[derive(Debug)]
pub(super) struct DurableVault {
    root: PathBuf,
    batcher: GroupCommitBatcher,
    tiering_policy: Option<TieringPolicy>,
    ledger_checkpoint: Option<CheckpointConfig>,
    temporal_policy: Option<TemporalPolicy>,
    dedup_policy: Option<DedupPolicy>,
    retention_horizon: Mutex<RetentionHorizon>,
    panel: Option<Panel>,
    disk_pressure_guard: Option<DiskPressureGuard>,
    /// Exact write capability retained for cross-process router refresh.
    selected_cfs: Option<Vec<ColumnFamily>>,
    pending_checkpoint: Mutex<Vec<(u64, Vec<WriteRow>)>>,
    /// Max checkpointed seq whose batch wrote derived-search-content CF rows
    /// (issue #1100); persisted into every manifest write as
    /// `derived_content_seq`, clamped to that manifest's `durable_seq`.
    checkpointed_derived_content_seq: AtomicU64,
    /// Exact last checkpointed mutation sequence for every CF this handle has
    /// flushed. Manifest publication merges this bounded map with the current
    /// durable manifest under the commit lock.
    checkpointed_cf_content_generations: Mutex<BTreeMap<ColumnFamily, u64>>,
    /// Exact manifest control generation last incorporated by this handle.
    observed_manifest_seq: AtomicU64,
}

pub(super) struct RecoveredBatch {
    pub seq: u64,
    pub rows: Vec<WriteRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecoveryMode {
    FullMvcc,
    LatestRouter,
}

impl RecoveryMode {
    fn from_options(options: &VaultOptions) -> Self {
        if options.restore_mvcc_rows {
            Self::FullMvcc
        } else {
            Self::LatestRouter
        }
    }
}

pub(super) struct RecoveredBatches {
    pub batches: Vec<RecoveredBatch>,
    pub last_recovered_seq: u64,
    pub manifest_seq: u64,
    pub wal_replay_floor_seq: u64,
    /// Durably recorded derived-content watermark floor for seqs at or below
    /// `wal_replay_floor_seq`; WAL replay re-derives the rest per batch.
    pub derived_content_floor_seq: u64,
    /// Durable per-CF generation floor from the current manifest (legacy
    /// manifests conservatively use their durable tip).
    pub cf_content_generation_floor_seq: u64,
    /// Exact per-CF generations above the floor, including the WAL tail.
    pub cf_content_generations: BTreeMap<ColumnFamily, u64>,
    pub torn_tail: Option<crate::wal::TornTail>,
    pub temporal_policy: Option<TemporalPolicy>,
    pub dedup_policy: Option<DedupPolicy>,
    pub retention_horizon: RetentionHorizon,
    pub mode: RecoveryMode,
}

impl DurableVault {
    pub(super) fn validate_options(options: &VaultOptions) -> Result<()> {
        if let Some(policy) = &options.temporal_policy {
            policy.validate()?;
        }
        if let Some(policy) = &options.dedup_policy {
            validate_dedup_policy(policy, options.panel.as_ref())?;
        }
        options.retention_horizon.validate()?;
        if !options.restore_ledger_hook && !options.read_only {
            return Err(CalyxError {
                code: "CALYX_VAULT_OPTIONS_INVALID",
                message:
                    "restore_ledger_hook=false requires read_only=true to prevent unverified writes"
                        .to_string(),
                remediation: "open read workloads with read_only=true, or keep restore_ledger_hook=true for write-capable handles",
            });
        }
        if options.read_only && options.restore_ledger_hook {
            return Err(CalyxError {
                code: "CALYX_VAULT_OPTIONS_INVALID",
                message: "read_only=true cannot restore a write-capable ledger hook".to_string(),
                remediation: "set restore_ledger_hook=false for read-only vault handles",
            });
        }
        if options.read_only && options.residency.is_some() {
            return Err(CalyxError {
                code: "CALYX_VAULT_OPTIONS_INVALID",
                message: "read_only=true cannot persist a new residency pin".to_string(),
                remediation: "persist residency with a write-capable open before opening read-only handles",
            });
        }
        if let Some(selected) = &options.selected_cfs
            && !options.read_only
            && (!options.writable_selected_cfs
                || !options.restore_ledger_hook
                || !selected.contains(&ColumnFamily::Ledger)
                || !selected.contains(&ColumnFamily::TimeIndex))
        {
            return Err(CalyxError {
                code: "CALYX_VAULT_OPTIONS_INVALID",
                message: "write-capable selected_cfs requires writable_selected_cfs=true, restore_ledger_hook=true, and explicit Ledger plus TimeIndex column families".to_string(),
                remediation: "explicitly opt into narrow writes and include every application CF the transaction may touch plus Ledger and TimeIndex, or open a full write-capable vault",
            });
        }
        if options.writable_selected_cfs && (options.read_only || options.selected_cfs.is_none()) {
            return Err(CalyxError {
                code: "CALYX_VAULT_OPTIONS_INVALID",
                message: "writable_selected_cfs=true requires a write-capable non-empty selected_cfs scope".to_string(),
                remediation: "disable writable_selected_cfs for ordinary/read-only opens, or name the exact write scope",
            });
        }
        if options.selected_cfs.as_ref().is_some_and(Vec::is_empty) {
            return Err(CalyxError {
                code: "CALYX_VAULT_OPTIONS_INVALID",
                message: "selected_cfs cannot be empty".to_string(),
                remediation: "omit selected_cfs or include every CF required by the read workload",
            });
        }
        if options.selected_cfs.is_some() && options.tiering_policy.is_some() {
            return Err(CalyxError {
                code: "CALYX_VAULT_OPTIONS_INVALID",
                message: "selected_cfs with tiering_policy is not implemented".to_string(),
                remediation: "open a full read-only tiered handle or add selected tier-aware CF routing first",
            });
        }
        Ok(())
    }

    pub(super) fn open_after(
        root: impl AsRef<Path>,
        options: &VaultOptions,
        wal_replay_floor_seq: u64,
    ) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        Self::validate_options(options)?;
        fs::create_dir_all(root.join("cf"))
            .map_err(|error| storage_error("create durable CF root", error))?;
        if let Some(policy) = &options.tiering_policy {
            for tier_root in policy.tier_roots() {
                fs::create_dir_all(tier_root.join("cf"))
                    .map_err(|error| storage_error("create tiered durable CF root", error))?;
            }
        }
        let wal = crate::wal::Wal::open_after(
            root.join("wal"),
            options.wal_options,
            wal_replay_floor_seq,
        )?;
        let batcher = GroupCommitBatcher::new(
            wal,
            options.wal_options.group_commit_window,
            Arc::new(SystemClock),
        )?;
        let durable = Self {
            root,
            batcher,
            tiering_policy: options.tiering_policy.clone(),
            ledger_checkpoint: options.ledger_checkpoint.clone(),
            temporal_policy: options.temporal_policy,
            dedup_policy: options.dedup_policy.clone(),
            retention_horizon: Mutex::new(options.retention_horizon.clone()),
            panel: options.panel.clone(),
            disk_pressure_guard: options.disk_pressure_guard.clone(),
            selected_cfs: options.selected_cfs.clone(),
            pending_checkpoint: Mutex::new(Vec::new()),
            checkpointed_derived_content_seq: AtomicU64::new(0),
            checkpointed_cf_content_generations: Mutex::new(BTreeMap::new()),
            observed_manifest_seq: AtomicU64::new(0),
        };
        let current_path = durable.root.join("CURRENT");
        let current_present = current_path
            .try_exists()
            .map_err(|error| storage_error("inspect durable CURRENT", error))?;
        if current_present {
            let manifest = crate::manifest::ManifestStore::open(&durable.root).load_current()?;
            durable
                .checkpointed_derived_content_seq
                .store(manifest.effective_derived_content_seq(), Ordering::Release);
            durable
                .observed_manifest_seq
                .store(manifest.manifest_seq, Ordering::Release);
        }
        if durable.panel.is_some() && !current_present {
            durable.write_manifest_with_seq(1, 0)?;
        }
        Ok(durable)
    }

    pub(super) fn recover_batches(
        root: impl AsRef<Path>,
        options: &VaultOptions,
    ) -> Result<RecoveredBatches> {
        Self::validate_options(options)?;
        let root = root.as_ref();
        let selected_cfs = options
            .selected_cfs
            .as_ref()
            .map(|selected| selected.iter().copied().collect::<BTreeSet<_>>());
        let current_present = root
            .join("CURRENT")
            .try_exists()
            .map_err(|error| storage_error("inspect recovery CURRENT", error))?;
        if current_present {
            let recovery = if options.read_only {
                recover_vault_read_only(root)?
            } else {
                recover_vault(root)?
            };
            if let Some(policy) = &recovery.manifest.dedup_policy {
                validate_dedup_policy(policy, options.panel.as_ref())?;
            }
            let mode = RecoveryMode::from_options(options);
            let mut batches = if mode == RecoveryMode::FullMvcc {
                read_manifested_batches(
                    root,
                    options.tiering_policy.as_ref(),
                    recovery.manifest.durable_seq,
                    selected_cfs.as_ref(),
                )?
            } else {
                Vec::new()
            };
            let cf_content_generation_floor_seq = recovery
                .manifest
                .effective_cf_content_generation_floor_seq();
            let mut cf_content_generations = recovery.manifest.decoded_cf_content_generations()?;
            validate_replay_sequence(
                recovery.manifest.durable_seq,
                recovery.wal_records.iter().map(|record| record.seq),
            )?;
            for record in recovery.wal_records {
                let rows = decode_write_batch(&record.payload)?;
                advance_cf_generation_map(
                    &mut cf_content_generations,
                    cf_content_generation_floor_seq,
                    record.seq,
                    &rows,
                );
                batches.push(RecoveredBatch {
                    seq: record.seq,
                    rows,
                });
            }
            return Ok(RecoveredBatches {
                batches,
                last_recovered_seq: recovery.last_recovered_seq,
                manifest_seq: recovery.manifest.manifest_seq,
                wal_replay_floor_seq: recovery.manifest.durable_seq,
                derived_content_floor_seq: recovery.manifest.effective_derived_content_seq(),
                cf_content_generation_floor_seq,
                cf_content_generations,
                torn_tail: recovery.torn_tail,
                temporal_policy: recovery.manifest.temporal_policy,
                dedup_policy: recovery.manifest.dedup_policy,
                retention_horizon: recovery.manifest.retention_horizon,
                mode,
            });
        }

        let replay = if options.read_only {
            replay_dir_read_only_after(root.join("wal"), 0)?
        } else {
            replay_dir(root.join("wal"))?
        };
        let last_recovered_seq = replay.records.last().map_or(0, |record| record.seq);
        validate_replay_sequence(0, replay.records.iter().map(|record| record.seq))?;
        // A vault does not need a CURRENT manifest before its router SSTs and
        // WAL are valid latest-state sources. Honor the caller's router mode in
        // this bootstrap state exactly as the manifested branch above does.
        // With no manifest the whole WAL is uncheckpointed tail, so both modes
        // must restore it: latest readers compose that tail over router SSTs,
        // while historical readers rebuild MVCC from the same committed rows.
        let mode = RecoveryMode::from_options(options);
        let cf_content_generation_floor_seq = 0;
        let mut cf_content_generations = BTreeMap::new();
        let mut batches = Vec::with_capacity(replay.records.len());
        for record in &replay.records {
            let rows = decode_write_batch(&record.payload)?;
            advance_cf_generation_map(
                &mut cf_content_generations,
                cf_content_generation_floor_seq,
                record.seq,
                &rows,
            );
            batches.push(RecoveredBatch {
                seq: record.seq,
                rows,
            });
        }
        Ok(RecoveredBatches {
            batches,
            last_recovered_seq,
            manifest_seq: 0,
            wal_replay_floor_seq: 0,
            derived_content_floor_seq: 0,
            cf_content_generation_floor_seq,
            cf_content_generations,
            torn_tail: replay.torn_tail,
            temporal_policy: options.temporal_policy,
            dedup_policy: options.dedup_policy.clone(),
            retention_horizon: options.retention_horizon.clone(),
            mode,
        })
    }

    pub(super) fn append_batch(&self, rows: &[WriteRow]) -> Result<u64> {
        let row_count = rows.len();
        let serialize = crate::commit_timing::start();
        let payload = encode_write_batch(rows)?;
        let payload_len = payload.len();
        serialize.stop("wal_serialize", row_count, payload_len);
        // `submit` blocks the caller thread on the group-commit batcher, which
        // performs the WAL page-write + fsync (broken out further as
        // `wal_page_write`/`wal_fsync` on the batcher thread). This span is the
        // caller-observed durable-append latency including that handoff.
        let submit = crate::commit_timing::start();
        let ack = self.batcher.submit(payload)?;
        submit.stop("wal_submit", row_count, payload_len);
        Ok(ack.seq)
    }

    pub(super) fn ensure_disk_write_allowed(&self, counters: &ResourceCounters) -> Result<()> {
        let Some(guard) = &self.disk_pressure_guard else {
            return Ok(());
        };
        match guard.check() {
            Ok(_) => Ok(()),
            Err(error) if error.code == "CALYX_DISK_PRESSURE" => {
                counters.record_disk_pressure();
                guard.request_spill();
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn durable_tip_seq(&self) -> Result<u64> {
        self.batcher.tip_seq()
    }

    fn advance_checkpointed_derived_content(&self, seq: u64, rows: &[WriteRow]) {
        if rows.iter().any(|row| row.cf.feeds_derived_search_content()) {
            self.checkpointed_derived_content_seq
                .fetch_max(seq, Ordering::AcqRel);
        }
    }

    fn advance_checkpointed_cf_content_generations(
        &self,
        seq: u64,
        rows: &[WriteRow],
    ) -> Result<()> {
        let mut generations = self
            .checkpointed_cf_content_generations
            .lock()
            .map_err(|_| CalyxError::backpressure("checkpointed CF generation lock poisoned"))?;
        advance_cf_generation_map(&mut generations, 0, seq, rows);
        Ok(())
    }

    /// Watermark value a manifest written at `durable_seq` may vouch for.
    pub(super) fn derived_content_seq_for_manifest(&self, durable_seq: u64) -> u64 {
        self.checkpointed_derived_content_seq
            .load(Ordering::Acquire)
            .min(durable_seq)
    }

    /// Adopts a foreign writer's checkpointed watermark (picked up from the
    /// on-disk manifest under the commit lock) so later manifest writes from
    /// this handle vouch for content it did not checkpoint itself (#1100).
    pub(in crate::vault) fn advance_derived_content_watermark_to_at_least(&self, seq: u64) {
        self.checkpointed_derived_content_seq
            .fetch_max(seq, Ordering::AcqRel);
    }

    pub(super) fn flush(&self) -> Result<Vec<SstSummary>> {
        self.batcher.flush_sync()?;
        self.flush_pending_checkpoints()
    }

    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn recurrence_lock_path(&self) -> PathBuf {
        self.root.join("locks").join("recurrence.write.lock")
    }

    pub(super) fn commit_lock_path(&self) -> PathBuf {
        self.root.join("locks").join("durable.commit.lock")
    }

    pub(super) fn recover_current_batches(&self, mode: RecoveryMode) -> Result<RecoveredBatches> {
        let options = VaultOptions {
            tiering_policy: self.tiering_policy.clone(),
            ledger_checkpoint: self.ledger_checkpoint.clone(),
            temporal_policy: self.temporal_policy,
            dedup_policy: self.dedup_policy.clone(),
            retention_horizon: self.retention_horizon()?,
            panel: self.panel.clone(),
            disk_pressure_guard: self.disk_pressure_guard.clone(),
            selected_cfs: self.selected_cfs.clone(),
            writable_selected_cfs: self.selected_cfs.is_some(),
            restore_mvcc_rows: mode == RecoveryMode::FullMvcc,
            ..VaultOptions::default()
        };
        Self::recover_batches(&self.root, &options)
    }

    pub(super) fn ledger_checkpoint(&self) -> Option<CheckpointConfig> {
        self.ledger_checkpoint.clone()
    }

    pub(super) fn tiering_policy(&self) -> Option<&TieringPolicy> {
        self.tiering_policy.as_ref()
    }

    pub(super) fn selected_cfs(&self) -> Option<&[ColumnFamily]> {
        self.selected_cfs.as_deref()
    }

    pub(super) fn observed_manifest_seq(&self) -> u64 {
        self.observed_manifest_seq.load(Ordering::Acquire)
    }

    pub(in crate::vault) fn observe_manifest_seq(&self, manifest_seq: u64) {
        self.observed_manifest_seq
            .store(manifest_seq, Ordering::Release);
    }

    pub(super) fn compaction_output_path(&self, cf: ColumnFamily, seq: u64) -> PathBuf {
        self.cf_dir(cf).join(format!("compacted-{seq:020}.sst"))
    }

    fn cf_dir(&self, cf: ColumnFamily) -> PathBuf {
        self.tiering_policy.as_ref().map_or_else(
            || self.root.join("cf").join(cf.name()),
            |policy| policy.place_current_cf(cf).absolute_dir(),
        )
    }
}

fn validate_replay_sequence(floor: u64, sequences: impl IntoIterator<Item = u64>) -> Result<()> {
    let mut previous = floor;
    for observed in sequences {
        let expected = previous.checked_add(1).ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "WAL sequence overflow after durable replay floor {previous}"
            ))
        })?;
        if observed != expected {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "WAL sequence is not contiguous after durable replay floor {floor}: expected {expected}, observed {observed}"
            )));
        }
        previous = observed;
    }
    Ok(())
}

fn advance_cf_generation_map(
    generations: &mut BTreeMap<ColumnFamily, u64>,
    floor: u64,
    seq: u64,
    rows: &[WriteRow],
) {
    if seq <= floor {
        return;
    }
    for row in rows {
        generations
            .entry(row.cf)
            .and_modify(|generation| *generation = (*generation).max(seq))
            .or_insert(seq);
    }
}

fn validate_dedup_policy(policy: &DedupPolicy, panel: Option<&Panel>) -> Result<()> {
    if let Some(panel) = panel {
        policy.validate(panel)
    } else {
        policy.validate_manifest()
    }
}

fn storage_error(context: &str, error: io::Error) -> CalyxError {
    CalyxError::disk_pressure(format!("{context}: {error}"))
}
