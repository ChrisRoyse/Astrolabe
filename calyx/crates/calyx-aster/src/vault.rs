//! Aster `VaultStore` implementation over the PH08 MVCC CF table.

mod accessors;
mod anchor_codec;
mod anchor_merge;
mod batch_ingest;
pub(crate) mod cf_codec;
mod commit;
mod compaction_bridge;
pub mod context;
mod cursor;
mod dedup_commit;
mod durable;
mod durable_snapshot;
pub mod encode;
mod failpoints;
mod flush_readback;
mod gc_bridge;
pub mod grant;
mod htap;
pub mod input_store;
mod key;
pub mod keyspace;
mod layer_commit;
mod ledger_anchor_batch;
mod ledger_append;
mod ledger_bound_group_batch;
mod ledger_hook;
pub mod ledger_stub;
mod open;
mod physical_inventory;
pub mod quota;
mod retention_horizon;
mod router_bridge;
mod scan;
mod seq_readback;
mod slot_backfill;
mod slot_column;
mod slot_resolution;
mod snapshot_lease;
mod store;
mod temporal_xterm;
use crate::cf::{
    CfRouter, ColumnFamily, KeyRange, RouterManifestHandoffReport, anchor_key, base_key, slot_key,
};
use crate::compaction::TieringPolicy;
use crate::dedup::DedupPolicy;
use crate::file_lock::FileLockGuard;
use crate::mvcc::{Freshness, ReadBarrier, Snapshot, VersionedCfStore};
use crate::resource::{ResourceStatus, VramBudgetStatus, collect_resource_status};
use crate::sst::SstSummary;
use crate::timetravel::RetentionHorizon;
use crate::vault::durable::DurableVault;
use crate::vault::ledger_hook::AsterLedgerHook;
use crate::wal::TornTail;
use calyx_core::{CalyxError, Clock, Constellation, CxId, Result, Seq, SystemClock, VaultId};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub use anchor_merge::{
    ExistingBaseAnchorMerge, ExistingBaseAnchorMergeCommit, ExistingBaseAnchorMergeResult,
};
pub use batch_ingest::{
    AnchorMarkerLedgerDraft, AnchorMarkerLedgerReceipt, BatchIngestWithExistingMergeCommit,
    MediaArtifactIngestCommit,
};
pub use commit::CALYX_DURABLE_COMMIT_RECONCILIATION_REQUIRED;
pub use compaction_bridge::VaultCompactionScheduler;
pub use context::VaultContext;
pub use durable::VaultOptions;
pub use failpoints::{
    CRASH_FSV_ARMED_IN_PRODUCTION, crash_fsv_guard_decision, guard_against_production_failpoints,
};
pub use grant::{AuditEvent, GrantEntry, GrantStore};
pub use htap::HtapDualRead;
pub use input_store::{
    CALYX_INPUT_STORE_CORRUPT, CALYX_INPUT_STORE_MISSING, CALYX_INPUT_STORE_TOO_LARGE,
    INPUT_POINTER_PREFIX, InputManifest, InputRetention, encode_input_rows, input_manifest,
    input_pointer, read_input_bytes,
};
pub use key::{CALYX_DECRYPTION_FAILED, CALYX_ENCRYPTION_FAILED, CALYX_VAULT_KEY_MISSING};
pub use keyspace::{
    CALYX_VAULT_KEYSPACE_MISMATCH, KeyspaceGuard, VaultWriteLock, VaultWriteLockGuard, vault_prefix,
};
pub use ledger_append::CALYX_ASTER_RAW_LEDGER_COMMIT_BOUNDARY;
pub use ledger_bound_group_batch::{
    LedgerBoundGroupBatchReceipt, LedgerBoundGroupReceipt, LedgerBoundWriteGroup,
};
pub use physical_inventory::{
    CALYX_ASTER_PHYSICAL_COMMIT_INVENTORY_INVALID, PhysicalCommitComponent,
    PhysicalCommitComponentRole, PhysicalCommitContainer, PhysicalCommitInventory,
    PhysicalCommitRowDigest, PhysicalWalCommitInventory,
};
pub use quota::{CALYX_QUOTA_EXCEEDED, QuotaConfig, QuotaGuard};
pub use seq_readback::{CALYX_LEDGER_RANGE_SNAPSHOT_INVALID, LedgerRangeSnapshot};
pub use slot_column::{
    SlotColumnManifest, SlotColumnMaterialization, SlotColumnReadback, SlotColumnRow,
    read_materialized_slot_column,
};
pub use slot_resolution::{
    CALYX_ASTER_SLOT_CONTEXT_REQUIRED, SlotVectorResolver, StrictRawSlotResolver,
    decode_strict_raw_slot_value,
};
pub use snapshot_lease::{RetainedSnapshot, SstReadSession};

/// Digest-only receipt for one ledger-bound data row.
///
/// Values deliberately never escape group commit: the receipt preserves the
/// exact readback expectation in 32 bytes while the sole value allocation moves
/// into the durable checkpoint queue.
#[derive(Debug)]
pub struct LedgerBoundRowDigest {
    pub cf: ColumnFamily,
    pub key: Vec<u8>,
    pub value_blake3: [u8; 32],
    pub tombstoned: bool,
}

/// Exact result of a ledger-paired data commit with compact persisted-state
/// expectations for every caller-owned data row.
#[derive(Debug)]
pub struct LedgerBoundCommit {
    /// MVCC sequence assigned to the atomic data + ledger + time-index batch.
    pub seq: Seq,
    /// Provenance reference stamped into every eligible data row.
    pub ledger_ref: calyx_core::LedgerRef,
    /// Digests of committed data rows after provenance binding, excluding the
    /// internal Ledger and time-index rows.
    pub data_row_digests: Vec<LedgerBoundRowDigest>,
}

/// One borrowed `(column family, key)` in an ordered persisted-readback plan.
/// `ordinal` remains stable when the engine reorders the physical reads for SST
/// locality, allowing an upper-layer verifier to bind every returned value to
/// its original digest expectation without duplicating key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderedCfRead<'a> {
    pub ordinal: usize,
    pub cf: ColumnFamily,
    pub key: &'a [u8],
}

impl<'a> OrderedCfRead<'a> {
    pub const fn new(ordinal: usize, cf: ColumnFamily, key: &'a [u8]) -> Self {
        Self { ordinal, cf, key }
    }
}

/// Physical SST publication receipt for one explicit vault flush.
///
/// Durable checkpoint files and router memtable files are reported separately
/// so callers can measure write amplification from persisted bytes rather than
/// infer it from a successful return value. Paths name this vault's exact CF
/// directories; no rows or value buffers are retained by the receipt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultFlushReport {
    /// Manifest-covered durable-batch SSTs written by the checkpoint layer.
    pub durable_ssts: Vec<SstSummary>,
    /// Router memtable SSTs written for the live latest-state view.
    /// Durable vaults use `router_handoff` instead and leave this empty.
    pub router_ssts: Vec<SstSummary>,
    /// Manifest-bound durable-to-router reconciliation for durable vaults.
    pub router_handoff: Option<VaultRouterHandoffReport>,
}

impl VaultFlushReport {
    /// Total number of physical SST files published by this flush.
    pub fn sst_files(&self) -> usize {
        self.durable_ssts.len() + self.router_ssts.len()
    }

    /// Total encoded rows across all physical SST files in this flush.
    pub fn sst_entries(&self) -> usize {
        self.durable_ssts
            .iter()
            .chain(&self.router_ssts)
            .map(|summary| summary.entries)
            .sum()
    }

    /// Total physical SST bytes published by this flush.
    pub fn sst_bytes(&self) -> u64 {
        self.durable_ssts
            .iter()
            .chain(&self.router_ssts)
            .map(|summary| summary.bytes)
            .sum()
    }
}

/// Physical receipt for one manifest-bound durable-to-router handoff.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultRouterHandoffReport {
    /// Exact immutable manifest generation that authorizes the handoff.
    pub manifest_seq: u64,
    /// Highest commit sequence covered by that manifest.
    pub durable_seq: u64,
    /// Whether an absent/behind marker required a complete CF inventory.
    pub full_inventory: bool,
    /// Column families reconciled under the router write lock.
    pub column_families: usize,
    /// Immutable SST files retained in the verified candidate levels.
    pub candidate_sst_files: usize,
    /// Newly published durable files attached with validated lookup metadata.
    pub durable_sst_files_attached: usize,
    /// Active mutable rows independently matched to immutable bytes.
    pub memtable_rows_verified: usize,
    /// Covered router-flush files whose rows/order were independently checked.
    pub flush_sst_files_verified: usize,
    /// Covered router-flush rows checked before retirement.
    pub flush_sst_entries_verified: usize,
    /// Covered router-flush bytes checked before retirement.
    pub flush_sst_bytes_verified: u64,
    /// Covered router-flush files removed and read back absent.
    pub flush_sst_files_retired: usize,
    /// Covered router-flush bytes removed and read back absent.
    pub flush_sst_bytes_retired: u64,
    /// Manifest-covered router-flush debt remaining after readback.
    pub covered_flush_debt_files_after: usize,
    /// Manifest-covered router-flush bytes remaining after readback.
    pub covered_flush_debt_bytes_after: u64,
    /// Durable completion marker independently read back after publication.
    pub state_path: PathBuf,
}

impl VaultRouterHandoffReport {
    fn from_internal(
        manifest_seq: u64,
        durable_seq: u64,
        state_path: PathBuf,
        report: RouterManifestHandoffReport,
    ) -> Self {
        Self {
            manifest_seq,
            durable_seq,
            full_inventory: report.full_inventory,
            column_families: report.column_families,
            candidate_sst_files: report.candidate_sst_files,
            durable_sst_files_attached: report.durable_sst_files_attached,
            memtable_rows_verified: report.memtable_rows_verified,
            flush_sst_files_verified: report.flush_sst_files_verified,
            flush_sst_entries_verified: report.flush_sst_entries_verified,
            flush_sst_bytes_verified: report.flush_sst_bytes_verified,
            flush_sst_files_retired: report.flush_sst_files_retired,
            flush_sst_bytes_retired: report.flush_sst_bytes_retired,
            covered_flush_debt_files_after: report.covered_flush_debt_files_after,
            covered_flush_debt_bytes_after: report.covered_flush_debt_bytes_after,
            state_path,
        }
    }
}

/// Single-vault Aster store with content-addressed ingest semantics.
#[derive(Debug)]
pub struct AsterVault<C = SystemClock> {
    vault_id: VaultId,
    vault_salt: Vec<u8>,
    clock: Arc<C>,
    rows: VersionedCfStore,
    durable: Option<DurableVault>,
    durable_root: Option<PathBuf>,
    durable_tiering_policy: Option<TieringPolicy>,
    dedup_policy: DedupPolicy,
    retention_horizon: Mutex<RetentionHorizon>,
    ledger_hook: Option<AsterLedgerHook<C>>,
    read_only: bool,
    recurrence_write_lock: Mutex<()>,
    recovery_report: VaultRecoveryReport,
    residency: Option<crate::residency::Residency>,
    _read_snapshot_guard: Option<FileLockGuard>,
    open_diagnostics: VaultOpenDiagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRecoveryReport {
    pub last_recovered_seq: Seq,
    pub torn_tail: Option<TornTail>,
}

/// Measured phases of one durable vault open.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VaultOpenDiagnostics {
    /// Wall time spent acquiring the retained read-snapshot lock.
    pub read_snapshot_lock_us: u64,
    /// Native process-counter delta while acquiring the snapshot lock.
    pub read_snapshot_lock_usage: VaultPhaseUsage,
    /// Wall time spent reading the manifest and replaying the WAL tail.
    pub recovery_us: u64,
    /// Native process-counter delta during durable recovery.
    pub recovery_usage: VaultPhaseUsage,
    /// Wall time spent reconstructing the optional ledger hook.
    pub ledger_hook_us: u64,
    /// Native process-counter delta during ledger-hook reconstruction.
    pub ledger_hook_usage: VaultPhaseUsage,
    /// Wall time spent opening the column-family router.
    pub router_us: u64,
    /// Native process-counter delta while opening the router.
    pub router_usage: VaultPhaseUsage,
    /// End-to-end wall time for the durable vault open.
    pub total_us: u64,
    /// End-to-end native process-counter delta for the durable vault open.
    pub total_usage: VaultPhaseUsage,
}

/// Native process counters attributed to one measured open phase.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VaultPhaseUsage {
    /// Kernel-mode CPU time consumed during the phase, in 100 ns units.
    pub kernel_time_100ns: u64,
    /// User-mode CPU time consumed during the phase, in 100 ns units.
    pub user_time_100ns: u64,
    /// Process read-operation count accumulated during the phase.
    pub read_operations: u64,
    /// Process read-transfer bytes accumulated during the phase.
    pub read_bytes: u64,
    /// Process write-operation count accumulated during the phase.
    pub write_operations: u64,
    /// Process write-transfer bytes accumulated during the phase.
    pub write_bytes: u64,
    /// Process page faults accumulated during the phase.
    pub page_faults: u64,
    /// Process working-set bytes sampled after the phase.
    pub working_set_bytes_after: u64,
    /// Process peak working-set bytes sampled after the phase.
    pub peak_working_set_bytes_after: u64,
    /// Process private committed bytes sampled after the phase.
    pub private_bytes_after: u64,
    /// Process peak private committed bytes sampled after the phase.
    pub peak_private_bytes_after: u64,
}

/// One native process-counter snapshot for explicit pipeline attribution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VaultProcessUsage {
    /// Cumulative kernel-mode CPU time, in 100 ns units.
    pub kernel_time_100ns: u64,
    /// Cumulative user-mode CPU time, in 100 ns units.
    pub user_time_100ns: u64,
    /// Cumulative process read operations.
    pub read_operations: u64,
    /// Cumulative process read-transfer bytes.
    pub read_bytes: u64,
    /// Cumulative process write operations.
    pub write_operations: u64,
    /// Cumulative process write-transfer bytes.
    pub write_bytes: u64,
    /// Cumulative page faults.
    pub page_faults: u64,
    /// Current working-set bytes.
    pub working_set_bytes: u64,
    /// Peak working-set bytes since process start.
    pub peak_working_set_bytes: u64,
    /// Current private committed bytes.
    pub private_bytes: u64,
    /// Peak private committed bytes since process start.
    pub peak_private_bytes: u64,
}

impl VaultProcessUsage {
    /// Attributes cumulative-counter deltas and end-state memory to one phase.
    pub fn phase_since(self, before: Self) -> VaultPhaseUsage {
        VaultPhaseUsage {
            kernel_time_100ns: self
                .kernel_time_100ns
                .saturating_sub(before.kernel_time_100ns),
            user_time_100ns: self.user_time_100ns.saturating_sub(before.user_time_100ns),
            read_operations: self.read_operations.saturating_sub(before.read_operations),
            read_bytes: self.read_bytes.saturating_sub(before.read_bytes),
            write_operations: self
                .write_operations
                .saturating_sub(before.write_operations),
            write_bytes: self.write_bytes.saturating_sub(before.write_bytes),
            page_faults: self.page_faults.saturating_sub(before.page_faults),
            working_set_bytes_after: self.working_set_bytes,
            peak_working_set_bytes_after: self.peak_working_set_bytes,
            private_bytes_after: self.private_bytes,
            peak_private_bytes_after: self.peak_private_bytes,
        }
    }
}

impl AsterVault<SystemClock> {
    /// Creates a vault using the system clock.
    pub fn new(vault_id: VaultId, vault_salt: impl Into<Vec<u8>>) -> Self {
        Self::with_clock(vault_id, vault_salt, SystemClock)
    }

    pub fn new_durable(
        vault_dir: impl AsRef<Path>,
        vault_id: VaultId,
        vault_salt: impl Into<Vec<u8>>,
        options: VaultOptions,
    ) -> Result<Self> {
        Self::open(vault_dir, vault_id, vault_salt, options)
    }

    pub fn open(
        vault_dir: impl AsRef<Path>,
        vault_id: VaultId,
        vault_salt: impl Into<Vec<u8>>,
        options: VaultOptions,
    ) -> Result<Self> {
        AsterVault::open_with_clock(vault_dir, vault_id, vault_salt, options, SystemClock)
    }
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Opens a durable vault with an injected clock.
    ///
    /// Production callers use [`AsterVault::open`] with [`SystemClock`]. This
    /// constructor exists for deterministic FSV: the vault remains fully
    /// durable, but group commits stamp `time_index` rows from `clock`.
    pub fn new_durable_with_clock(
        vault_dir: impl AsRef<Path>,
        vault_id: VaultId,
        vault_salt: impl Into<Vec<u8>>,
        options: VaultOptions,
        clock: C,
    ) -> Result<Self> {
        Self::open_with_clock(vault_dir, vault_id, vault_salt, options, clock)
    }

    /// Creates a vault with an injected clock.
    pub fn with_clock(vault_id: VaultId, vault_salt: impl Into<Vec<u8>>, clock: C) -> Self {
        Self {
            vault_id,
            vault_salt: vault_salt.into(),
            clock: Arc::new(clock),
            rows: VersionedCfStore::default(),
            durable: None,
            durable_root: None,
            durable_tiering_policy: None,
            dedup_policy: DedupPolicy::default(),
            retention_horizon: Mutex::new(RetentionHorizon::default()),
            ledger_hook: None,
            read_only: false,
            recurrence_write_lock: Mutex::new(()),
            recovery_report: VaultRecoveryReport {
                last_recovered_seq: 0,
                torn_tail: None,
            },
            residency: None,
            _read_snapshot_guard: None,
            open_diagnostics: VaultOpenDiagnostics::default(),
        }
    }

    /// Returns the vault's data-residency pin, if one is set (PRD `30 §4`).
    pub fn residency(&self) -> Option<&crate::residency::Residency> {
        self.residency.as_ref()
    }

    pub(crate) fn ensure_writeable(&self, operation: &str) -> Result<()> {
        if !self.read_only {
            return Ok(());
        }
        Err(CalyxError {
            code: "CALYX_VAULT_READ_ONLY",
            message: format!("read-only Aster vault handle rejected {operation}"),
            remediation: "open a write-capable vault handle with read_only=false for mutating operations",
        })
    }

    /// Authorizes an external copy/export to `target` against the residency pin.
    /// With no pin set, every target is authorized. On a violation, an
    /// `EntryKind::Admin` governance entry is written to the Ledger (the audit
    /// trail) and `CALYX_RESIDENCY_VIOLATION` is returned — fail closed, never a
    /// silent off-dataset copy.
    pub fn authorize_external_copy(&self, target: &std::path::Path) -> Result<()> {
        let Some(residency) = &self.residency else {
            return Ok(());
        };
        match residency.authorize(target) {
            Ok(()) => Ok(()),
            Err(violation) => {
                // Keep the immutable audit independent of host-specific path
                // spellings by binding paths through their normalized digests.
                let payload = serde_json::to_vec(&serde_json::json!({
                    "event": "residency_violation",
                    "dataset_root_hash": residency.dataset_root_digest(),
                    "attempted_target_hash": crate::residency::Residency::path_digest(target),
                    "allow_off_dataset": residency.allow_off_dataset,
                }))
                .map_err(|error| CalyxError {
                    code: "CALYX_RESIDENCY_CORRUPT",
                    message: format!("encode residency audit payload: {error}"),
                    remediation: "report this bug; residency audit payload must be serializable",
                })?;
                self.append_ledger_entry(
                    calyx_ledger::EntryKind::Admin,
                    calyx_ledger::SubjectId::Guard(residency.audit_subject()),
                    payload,
                    calyx_ledger::ActorId::System,
                )?;
                Err(violation)
            }
        }
    }

    pub fn with_clock_and_dedup_policy(
        vault_id: VaultId,
        vault_salt: impl Into<Vec<u8>>,
        clock: C,
        dedup_policy: DedupPolicy,
    ) -> Result<Self> {
        dedup_policy.validate_manifest()?;
        let mut vault = Self::with_clock(vault_id, vault_salt, clock);
        vault.dedup_policy = dedup_policy;
        Ok(vault)
    }

    /// Computes the PRD content-addressed id for raw input bytes.
    pub fn cx_id_for_input(&self, input_bytes: &[u8], panel_version: u32) -> CxId {
        CxId::from_input(input_bytes, panel_version, &self.vault_salt)
    }

    /// Returns the latest committed vault sequence.
    pub fn latest_seq(&self) -> Seq {
        self.rows.current_seq()
    }

    /// Latest committed seq whose batch wrote derived-search-content inputs
    /// (issue #1100). Content-neutral commits (idempotency-ledger appends,
    /// time-index sentinels) advance [`Self::latest_seq`] but not this.
    pub fn derived_content_seq(&self) -> Seq {
        self.rows.derived_content_seq()
    }

    pub fn recovery_report(&self) -> &VaultRecoveryReport {
        &self.recovery_report
    }

    /// Returns the native wall-time and process-counter attribution captured
    /// while this durable vault handle opened.
    pub fn open_diagnostics(&self) -> VaultOpenDiagnostics {
        self.open_diagnostics
    }

    /// Samples native CPU, I/O, page-fault, working-set, and private-memory
    /// counters for explicit pipeline-phase attribution.
    pub fn process_usage_snapshot(&self) -> Result<VaultProcessUsage> {
        open::current_process_usage()
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub(crate) fn clock_now(&self) -> u64 {
        self.clock.now()
    }

    /// Filesystem root of the durable store, or `None` for a volatile vault.
    ///
    /// Crate-internal: erase-intent persistence (issue #561) addresses the
    /// durable intent record under this root. Volatile vaults have no root and
    /// skip intent persistence — nothing survives a crash there by construction.
    pub(crate) fn durable_root(&self) -> Option<&Path> {
        self.durable.as_ref().map(DurableVault::root)
    }

    pub fn dedup_policy(&self) -> &DedupPolicy {
        &self.dedup_policy
    }

    pub(super) fn stage_constellation_rows(
        &self,
        rows: &mut Vec<encode::WriteRow>,
        constellation: &Constellation,
    ) -> Result<()> {
        constellation.validate_schema()?;
        let id = constellation.cx_id;
        rows.push(encode::WriteRow {
            cf: ColumnFamily::Base,
            key: base_key(id),
            value: encode::encode_constellation_base(constellation)?,
        });
        for (slot, vector) in &constellation.slots {
            rows.push(encode::WriteRow {
                cf: ColumnFamily::slot(*slot),
                key: slot_key(id),
                value: encode::encode_slot_vector(vector)?,
            });
        }
        for anchor in &constellation.anchors {
            rows.push(encode::WriteRow {
                cf: ColumnFamily::Anchors,
                key: anchor_key(id, &anchor.kind),
                value: encode::encode_anchor(anchor)?,
            });
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.flush_with_report().map(|_| ())
    }

    /// Flushes pending durable and router state and returns exact physical SST
    /// publication metadata for independent accounting.
    pub fn flush_with_report(&self) -> Result<VaultFlushReport> {
        self.with_durable_commit_lock(|| self.flush_locked())
    }

    pub(crate) fn flush_locked(&self) -> Result<VaultFlushReport> {
        self.ensure_writeable("flush")?;
        let Some(durable) = &self.durable else {
            return Ok(VaultFlushReport {
                durable_ssts: Vec::new(),
                router_ssts: self.rows.flush_all_cfs()?,
                router_handoff: None,
            });
        };

        let before = durable.current_manifest_identity()?;
        let full_inventory = durable.router_handoff_needs_full_inventory(before.as_ref())?;
        let durable_ssts = durable.flush()?;
        let Some(after) = durable.current_manifest_identity()? else {
            if durable_ssts.is_empty() {
                return Ok(VaultFlushReport {
                    durable_ssts,
                    router_ssts: Vec::new(),
                    router_handoff: None,
                });
            }
            return Err(CalyxError::aster_corrupt_shard(
                "durable checkpoint SSTs were published while CURRENT remained absent",
            ));
        };
        if after.durable_seq != self.latest_seq() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "router handoff requires manifest durable_seq {} to equal live latest seq {}",
                after.durable_seq,
                self.latest_seq()
            )));
        }
        let internal =
            self.rows
                .handoff_manifested_ssts(after.durable_seq, full_inventory, &durable_ssts)?;
        let state_path = durable.publish_router_handoff(&after)?;
        Ok(VaultFlushReport {
            durable_ssts,
            router_ssts: Vec::new(),
            router_handoff: Some(VaultRouterHandoffReport::from_internal(
                after.manifest_seq,
                after.durable_seq,
                state_path,
                internal,
            )),
        })
    }

    /// Pins an explicit reader lease tracked for oldest-pinned-seq accounting.
    ///
    /// Unlike scoped vault-internal snapshot handles, explicit pins remain in
    /// the store lease registry after one read call, until
    /// [`Self::release_reader`] or lease expiry.
    pub fn pin_reader(&self, freshness: Freshness, max_age_ms: u64) -> Snapshot {
        self.rows.pin_snapshot(freshness, &self.clock, max_age_ms)
    }

    /// Releases an explicit reader lease; returns whether it was still live.
    pub fn release_reader(&self, lease_id: u64) -> bool {
        self.rows.release_lease(lease_id)
    }

    /// Pins a reader lease at a historical `seq` (time-travel) and returns its
    /// lease id, which the caller must release with [`Self::release_reader`].
    pub fn pin_reader_at(&self, seq: Seq, max_age_ms: u64) -> u64 {
        self.rows
            .pin_snapshot_at(seq, Freshness::FreshDerived, &self.clock, max_age_ms)
            .lease()
            .id()
    }

    /// Opens a time-travel snapshot as of wall-clock `t_millis` (PRD `17 §8`).
    pub fn as_of(&self, t_millis: u64) -> Result<crate::timetravel::TimeTravelSnapshot<'_, C>> {
        crate::timetravel::TimeTravelSnapshot::open(self, t_millis)
    }

    /// Collects the aggregate resource status for this vault (PRD 18 §4).
    ///
    /// `vault_dir` is the durable root this vault was opened from; `vram` is
    /// the VRAM budget section sourced from the vault Anneal budget config.
    pub fn resource_status(
        &self,
        vault_dir: &Path,
        vram: VramBudgetStatus,
    ) -> Result<ResourceStatus> {
        collect_resource_status(vault_dir, vram, &self.rows, self.clock.now())
    }

    pub fn install_read_barrier(&self, barrier: ReadBarrier) {
        self.rows.install_read_barrier(barrier);
    }

    pub fn remove_read_barrier(&self, id: &str) -> bool {
        self.rows.remove_read_barrier(id)
    }

    pub fn read_barriers(&self) -> Vec<ReadBarrier> {
        self.rows.read_barriers()
    }
}
