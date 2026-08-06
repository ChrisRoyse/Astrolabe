//! In-memory MVCC row table used to define the cross-CF snapshot contract.

mod compression_guard;
mod gc;
mod read;
mod scan_pages;
use crate::cf::{
    COMPRESSED_SLOT_VALUE_TAG, CfRouter, ColumnFamily, KeyRange, RouterManifestHandoffReport,
    SlotFamilyKind, compression_manifest_key,
};
use crate::gc::{SnapshotGcCounters, SnapshotGcReclaimer, SnapshotGcTick};
use crate::mvcc::{
    Freshness, ReadBarrier, ReaderLease, SeqAllocator, Snapshot, read_barrier::first_blocking,
};
use crate::resource::{
    LeaseRegistry, LeaseView, MemtableCfStatus, MemtableStatus, ResourceCounters,
};
use crate::sst::{SstEntry, SstSummary};
use calyx_core::{CalyxError, Clock, Result, Seq, Ts};
use compression_guard::validate_compression_writes;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

const TOMBSTONE_VALUE: &[u8] = b"\0CALYX_ASTER_TOMBSTONE_V1";

/// A compression lifecycle mutation requires the complete MVCC keyset and is
/// therefore refused by a latest-only writable handle.
pub const CALYX_ASTER_LATEST_ONLY_COMPRESSION_REQUIRES_MVCC: &str =
    "CALYX_ASTER_LATEST_ONLY_COMPRESSION_REQUIRES_MVCC";

/// A selected-CF vault handle was asked to read a column family it did not
/// open. Absence cannot be inferred from an unavailable keyspace.
pub const CALYX_ASTER_CF_NOT_SELECTED: &str = "CALYX_ASTER_CF_NOT_SELECTED";

#[derive(Clone, Debug, PartialEq, Eq)]
struct VersionedValue {
    seq: Seq,
    value: Vec<u8>,
}

type CfKey = (ColumnFamily, Vec<u8>);
type VersionChain = Vec<VersionedValue>;
type RowTable = BTreeMap<CfKey, VersionChain>;

fn sequence_conflict(expected: Seq, current: Seq) -> CalyxError {
    CalyxError {
        code: "CALYX_ASTER_SEQUENCE_CONFLICT",
        message: format!(
            "conditional MVCC batch expected seq {expected}, current seq is {current}; no rows were written"
        ),
        remediation: "re-read the current snapshot, revalidate the complete replacement, and retry with that exact sequence",
    }
}

/// One batch row borrowed for the commit-time compression guard. Borrowing (vs
/// owning) lets the pre-WAL admission check and the in-commit check share one
/// validator without cloning the batch (issue #562).
type CompressionGuardRow<'a> = (ColumnFamily, &'a [u8], &'a [u8]);

/// A row representation accepted by the shared commit implementation.
///
/// Normal callers hand ownership to MVCC, so [`CommitRow::into_owned`] moves
/// their buffers into the version table. Durable group commit must retain its
/// canonical WAL/checkpoint rows until the post-MVCC checkpoint stage, so it
/// supplies borrowed rows and pays exactly the one copy that becomes persistent
/// MVCC state instead of first cloning a second corpus-sized staging batch.
trait CommitRow {
    fn cf(&self) -> ColumnFamily;
    fn key(&self) -> &[u8];
    fn value(&self) -> &[u8];
    fn into_owned(self) -> (ColumnFamily, Vec<u8>, Vec<u8>);
}

impl CommitRow for (ColumnFamily, Vec<u8>, Vec<u8>) {
    fn cf(&self) -> ColumnFamily {
        self.0
    }

    fn key(&self) -> &[u8] {
        &self.1
    }

    fn value(&self) -> &[u8] {
        &self.2
    }

    fn into_owned(self) -> (ColumnFamily, Vec<u8>, Vec<u8>) {
        self
    }
}

impl CommitRow for (ColumnFamily, &[u8], &[u8]) {
    fn cf(&self) -> ColumnFamily {
        self.0
    }

    fn key(&self) -> &[u8] {
        self.1
    }

    fn value(&self) -> &[u8] {
        self.2
    }

    fn into_owned(self) -> (ColumnFamily, Vec<u8>, Vec<u8>) {
        (self.0, self.1.to_vec(), self.2.to_vec())
    }
}

/// One CF/key read requested against a snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CfRead {
    pub cf: ColumnFamily,
    pub key: Vec<u8>,
}

/// Physical accounting for one storage-local ordered readback plan.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OrderedReadbackMetrics {
    /// Planned rows delivered to the caller, including physical tombstones and
    /// explicit absences.
    pub rows_read_back: u64,
    /// Persisted value bytes borrowed or read for those rows.
    pub bytes_read_back: u64,
    /// Column-family batches traversed under one pinned snapshot.
    pub read_batches: u64,
    /// Row-table/memtable/SST sources consulted.
    pub source_read_operations: u64,
    /// Immutable SST generations opened. Each generation is opened at most once
    /// per column-family batch, regardless of the number of planned keys in it.
    pub sst_files_opened: u64,
    /// Peak transient ordinal/CF/key-reference index bytes retained at once
    /// while ordering and resolving the plan.
    pub plan_index_bytes: u64,
    /// Largest persisted value borrowed at once. The ordered path never retains
    /// the complete value corpus.
    pub max_readback_batch_bytes: u64,
}

impl OrderedReadbackMetrics {
    pub(crate) fn checked_merge(&mut self, other: Self) -> Result<()> {
        self.rows_read_back =
            checked_metric_add(self.rows_read_back, other.rows_read_back, "rows_read_back")?;
        self.bytes_read_back = checked_metric_add(
            self.bytes_read_back,
            other.bytes_read_back,
            "bytes_read_back",
        )?;
        self.read_batches =
            checked_metric_add(self.read_batches, other.read_batches, "read_batches")?;
        self.source_read_operations = checked_metric_add(
            self.source_read_operations,
            other.source_read_operations,
            "source_read_operations",
        )?;
        self.sst_files_opened = checked_metric_add(
            self.sst_files_opened,
            other.sst_files_opened,
            "sst_files_opened",
        )?;
        self.plan_index_bytes = self.plan_index_bytes.max(other.plan_index_bytes);
        self.max_readback_batch_bytes = self
            .max_readback_batch_bytes
            .max(other.max_readback_batch_bytes);
        Ok(())
    }
}

fn checked_metric_add(left: u64, right: u64, name: &str) -> Result<u64> {
    left.checked_add(right).ok_or_else(|| {
        CalyxError::aster_corrupt_shard(format!("ordered readback metric {name} overflowed u64"))
    })
}

impl CfRead {
    pub fn new(cf: ColumnFamily, key: impl Into<Vec<u8>>) -> Self {
        Self {
            cf,
            key: key.into(),
        }
    }
}

pub fn tombstone_value() -> Vec<u8> {
    TOMBSTONE_VALUE.to_vec()
}

pub fn is_tombstone_value(value: &[u8]) -> bool {
    value == TOMBSTONE_VALUE
}

/// Versioned row table with a single vault-wide sequence.
#[derive(Debug)]
pub struct VersionedCfStore {
    seqs: SeqAllocator,
    /// Max committed seq whose batch wrote at least one row in a CF that
    /// feeds derived search content (issue #1100). Advances inside the row
    /// write lock *before* the seq becomes visible, so any reader that
    /// observes a content commit's seq also observes its watermark.
    derived_content_seq: AtomicU64,
    next_lease_id: AtomicU64,
    rows: RwLock<RowTable>,
    router: RwLock<Option<CfRouter>>,
    /// Read capability inherited from a selected-CF durable router. Keeping it
    /// at the MVCC boundary also covers replayed in-memory rows: an unselected
    /// CF can never leak through the WAL overlay or masquerade as empty.
    selected_cfs: Option<BTreeSet<ColumnFamily>>,
    router_latest_readback: AtomicBool,
    read_barriers: RwLock<Vec<ReadBarrier>>,
    leases: LeaseRegistry,
    resource_counters: Arc<ResourceCounters>,
    snapshot_gc: SnapshotGcReclaimer,
    snapshot_gc_counters: SnapshotGcCounters,
}

impl VersionedCfStore {
    pub fn new(start_seq: Seq) -> Self {
        Self {
            seqs: SeqAllocator::new(start_seq),
            derived_content_seq: AtomicU64::new(0),
            next_lease_id: AtomicU64::new(0),
            rows: RwLock::new(BTreeMap::new()),
            router: RwLock::new(None),
            selected_cfs: None,
            router_latest_readback: AtomicBool::new(false),
            read_barriers: RwLock::new(Vec::new()),
            leases: LeaseRegistry::default(),
            resource_counters: Arc::new(ResourceCounters::default()),
            snapshot_gc: SnapshotGcReclaimer::default(),
            snapshot_gc_counters: SnapshotGcCounters::default(),
        }
    }

    pub fn new_with_router(start_seq: Seq, router: CfRouter) -> Self {
        let resource_counters = router.resource_counters();
        let selected_cfs = router.selected_cfs().cloned();
        Self {
            seqs: SeqAllocator::new(start_seq),
            derived_content_seq: AtomicU64::new(0),
            next_lease_id: AtomicU64::new(0),
            rows: RwLock::new(BTreeMap::new()),
            router: RwLock::new(Some(router)),
            selected_cfs,
            router_latest_readback: AtomicBool::new(false),
            read_barriers: RwLock::new(Vec::new()),
            leases: LeaseRegistry::default(),
            resource_counters,
            snapshot_gc: SnapshotGcReclaimer::default(),
            snapshot_gc_counters: SnapshotGcCounters::default(),
        }
    }

    pub fn new_with_router_latest_readback(start_seq: Seq, router: CfRouter) -> Self {
        let store = Self::new_with_router(start_seq, router);
        store.router_latest_readback.store(true, Ordering::Release);
        store
    }

    /// Latest committed sequence.
    pub fn current_seq(&self) -> Seq {
        self.seqs.current()
    }

    pub fn set_start_seq(&self, seq: Seq) -> Result<()> {
        self.seqs.set_start_seq(seq)
    }

    pub fn advance_to_at_least(&self, seq: Seq) {
        self.seqs.advance_to_at_least(seq);
    }

    /// Latest committed seq whose batch wrote derived-search-content inputs.
    /// See [`crate::cf::ColumnFamily::feeds_derived_search_content`].
    pub fn derived_content_seq(&self) -> Seq {
        self.derived_content_seq.load(Ordering::Acquire)
    }

    /// Raises the derived-content watermark to a durably recorded floor
    /// (vault MANIFEST readback, foreign-process checkpoint refresh).
    pub fn advance_derived_content_seq_to_at_least(&self, seq: Seq) {
        self.derived_content_seq.fetch_max(seq, Ordering::AcqRel);
    }

    /// Pins a snapshot at the latest committed sequence.
    ///
    /// The lease is registered for oldest-pinned-seq gap accounting; it leaves
    /// the registry on [`Self::release_lease`] or when its `max_age_ms` expires.
    pub fn pin_snapshot(
        &self,
        freshness: Freshness,
        clock: &dyn Clock,
        max_age_ms: u64,
    ) -> Snapshot {
        let seq = self.current_seq();
        let lease_id = self.next_lease_id.fetch_add(1, Ordering::AcqRel) + 1;
        let lease = ReaderLease::new(lease_id, seq, clock.now(), max_age_ms);
        self.leases.register(lease);
        Snapshot::new(seq, freshness, lease)
            .with_derived_content_seq(self.derived_content_seq_at(seq))
    }

    /// Pins a reader lease at an explicit historical `seq` (time-travel). The
    /// lease participates in oldest-pinned-seq accounting so version GC cannot
    /// reclaim versions at or below `seq` until it is released.
    pub fn pin_snapshot_at(
        &self,
        seq: Seq,
        freshness: Freshness,
        clock: &dyn Clock,
        max_age_ms: u64,
    ) -> Snapshot {
        let lease_id = self.next_lease_id.fetch_add(1, Ordering::AcqRel) + 1;
        let lease = ReaderLease::new(lease_id, seq, clock.now(), max_age_ms);
        self.leases.register(lease);
        Snapshot::new(seq, freshness, lease)
            .with_derived_content_seq(self.derived_content_seq_at(seq))
    }

    /// Derived-content watermark as knowable for a pin at `seq`, clamped
    /// fail-closed: if the live watermark exceeds `seq` (content committed
    /// after the pin, or a historical pin below the watermark), the watermark
    /// at `seq` is unknowable from the live counter and the pin falls back to
    /// `seq` itself — the pre-#1100 exact-equality behavior, never laxer.
    fn derived_content_seq_at(&self, seq: Seq) -> Seq {
        self.derived_content_seq().min(seq)
    }

    /// Releases one pinned reader lease; returns whether it was still live.
    pub fn release_lease(&self, lease_id: u64) -> bool {
        self.leases.release(lease_id)
    }

    /// Live reader-lease view at `now` for resource accounting.
    pub fn lease_view(&self, now: Ts) -> LeaseView {
        self.leases.live_view(now)
    }

    /// Background snapshot-GC tick hook, intended for the 1 s GC scheduler.
    pub fn snapshot_gc_tick(&self, clock: &dyn Clock, max_gap_seqs: u64) -> SnapshotGcTick {
        let now = clock.now();
        let aborted_readers = self.leases.check_and_abort_expired(now);
        let gap_alert = self.leases.check_gap(self.current_seq(), now, max_gap_seqs);
        let metrics = self.leases.metrics(self.current_seq(), now);
        SnapshotGcTick {
            aborted_readers,
            gap_alert,
            metrics,
        }
    }

    /// Backpressure counters shared with this store's CF router.
    pub fn resource_counters(&self) -> &ResourceCounters {
        &self.resource_counters
    }

    /// Live memtable byte-cap status shared with resource readback.
    pub fn memtable_status(&self) -> MemtableStatus {
        let router = self.router.read().expect("mvcc router poisoned");
        let Some(router) = router.as_ref() else {
            return MemtableStatus::default();
        };
        let per_cf = router
            .memtable_usage_by_cf()
            .into_iter()
            .map(|(cf, usage)| MemtableCfStatus {
                cf: cf.name().to_string(),
                used_bytes: usage.used_bytes as u64,
                cap_bytes: usage.cap_bytes as u64,
                high_water_bytes: usage.high_water_bytes as u64,
                flush_triggered: usage.flush_triggered,
            })
            .collect::<Vec<_>>();
        let total_used_bytes = per_cf.iter().map(|cf| cf.used_bytes).sum();
        let total_cap_bytes = per_cf.iter().map(|cf| cf.cap_bytes).sum();
        MemtableStatus {
            total_used_bytes,
            total_cap_bytes,
            per_cf,
        }
    }

    /// Admission check for rows that cannot fit even in an empty memtable.
    pub fn ensure_memtable_admission<I, K, V>(&self, rows: I) -> Result<()>
    where
        I: IntoIterator<Item = (ColumnFamily, K, V)>,
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.router
            .read()
            .expect("mvcc router poisoned")
            .as_ref()
            .map_or(Ok(()), |router| router.ensure_batch_admitted(rows))
    }

    /// Pre-durability admission check for compression generation invariants
    /// (issue #562).
    ///
    /// Validates the batch against the visible state **before** the durable
    /// commit path appends it to the WAL, so a refused generation mutation never
    /// becomes durable and the post-WAL reconciliation arm can no longer persist
    /// a refused batch. Callers hold the durable commit lock, so the visible
    /// state cannot advance between this check and the commit. The in-commit
    /// [`validate_compression_writes`] remains as defense in depth (it alone
    /// protects the volatile path, which is already atomic on refusal).
    pub(crate) fn validate_batch_admission(
        &self,
        rows: &[(ColumnFamily, &[u8], &[u8])],
    ) -> Result<()> {
        let table = self.rows.read().expect("mvcc row table poisoned");
        let current = self.current_seq();
        self.validate_latest_only_compression_admission(rows)?;
        validate_compression_writes(&table, current, rows)
    }

    /// Latest-only mode deliberately does not retain the complete MVCC keyset.
    /// Ordinary rows are safe because their latest state lives in the router;
    /// compression generation changes are not, because the lifecycle validator
    /// must reconcile the complete primary/raw keysets. Refuse those operations
    /// before WAL append and also refuse ordinary mutations to any slot whose
    /// live manifest is visible in the router.
    fn validate_latest_only_compression_admission(
        &self,
        rows: &[CompressionGuardRow<'_>],
    ) -> Result<()> {
        if !self.router_latest_readback.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut touched_slots = BTreeSet::new();
        for &(cf, _key, value) in rows {
            match cf {
                ColumnFamily::Compression => {
                    return Err(latest_only_compression_error(
                        "a compression manifest or lifecycle row was included in the batch"
                            .to_string(),
                    ));
                }
                ColumnFamily::Slot { slot, kind } => {
                    touched_slots.insert(slot);
                    if kind == SlotFamilyKind::Quantized
                        && !is_tombstone_value(value)
                        && value.first().copied() == Some(COMPRESSED_SLOT_VALUE_TAG)
                    {
                        return Err(latest_only_compression_error(format!(
                            "slot {} contains a compressed-tagged primary value",
                            slot.get()
                        )));
                    }
                }
                _ => {}
            }
        }
        if touched_slots.is_empty() {
            return Ok(());
        }

        let router = self.router.read().expect("mvcc router poisoned");
        let router = router.as_ref().ok_or_else(|| {
            CalyxError::aster_corrupt_shard(
                "latest-only MVCC mode has no column-family router for compression admission",
            )
        })?;
        for slot in touched_slots {
            if router
                .get(ColumnFamily::Compression, &compression_manifest_key(slot))?
                .is_some_and(|value| !is_tombstone_value(&value))
            {
                return Err(latest_only_compression_error(format!(
                    "slot {} has a live compression manifest in durable router state",
                    slot.get()
                )));
            }
        }
        Ok(())
    }

    /// Atomically commits one write group across any number of CFs.
    pub fn commit_batch<I, K, V>(&self, rows: I) -> Result<Seq>
    where
        I: IntoIterator<Item = (ColumnFamily, K, V)>,
        K: Into<Vec<u8>>,
        V: Into<Vec<u8>>,
    {
        let rows = rows
            .into_iter()
            .map(|(cf, key, value)| (cf, key.into(), value.into()))
            .collect();
        self.commit_batch_inner(None, rows, false)
    }

    /// Applies one write group to the live MVCC memtable WITHOUT the in-commit
    /// compression-generation guard. Reserved for legacy-generation reconstruction
    /// (see `AsterVault::commit_legacy_generation_reconstruction_if_seq`), whose
    /// dedicated ingress fail-closed-validates the legacy shape before any commit
    /// and whose durably-appended WAL batch this call must mirror into MVCC even
    /// though the manifested-regime guard would refuse the unmanifested shape.
    pub(crate) fn commit_batch_unguarded<I, K, V>(&self, rows: I) -> Result<Seq>
    where
        I: IntoIterator<Item = (ColumnFamily, K, V)>,
        K: Into<Vec<u8>>,
        V: Into<Vec<u8>>,
    {
        let rows = rows
            .into_iter()
            .map(|(cf, key, value)| (cf, key.into(), value.into()))
            .collect();
        self.commit_batch_inner(None, rows, true)
    }

    /// Commits a borrowed write group while retaining the caller's canonical
    /// buffers for WAL checkpointing and exact persisted-state verification.
    /// Only the final MVCC versions allocate owned key/value bytes; there is no
    /// intermediate owned batch proportional to the corpus.
    pub(crate) fn commit_batch_borrowed(&self, rows: &[CompressionGuardRow<'_>]) -> Result<Seq> {
        self.commit_batch_inner(None, rows.to_vec(), false)
    }

    /// Borrowed counterpart of [`Self::commit_batch_unguarded`], reserved for
    /// the same fail-closed legacy reconstruction path.
    pub(crate) fn commit_batch_unguarded_borrowed(
        &self,
        rows: &[CompressionGuardRow<'_>],
    ) -> Result<Seq> {
        self.commit_batch_inner(None, rows.to_vec(), true)
    }

    /// Atomically commits one write group only when the current sequence still
    /// equals `expected_seq`.
    pub fn commit_batch_if_current<I, K, V>(&self, expected_seq: Seq, rows: I) -> Result<Seq>
    where
        I: IntoIterator<Item = (ColumnFamily, K, V)>,
        K: Into<Vec<u8>>,
        V: Into<Vec<u8>>,
    {
        let rows = rows
            .into_iter()
            .map(|(cf, key, value)| (cf, key.into(), value.into()))
            .collect();
        self.commit_batch_inner(Some(expected_seq), rows, false)
    }

    fn commit_batch_inner<R>(
        &self,
        expected_seq: Option<Seq>,
        rows: Vec<R>,
        skip_compression_guard: bool,
    ) -> Result<Seq>
    where
        R: CommitRow,
    {
        if rows.is_empty() {
            let current = self.current_seq();
            if let Some(expected) = expected_seq
                && current != expected
            {
                return Err(sequence_conflict(expected, current));
            }
            return Ok(current);
        }

        let mut table = self.rows.write().expect("mvcc row table poisoned");
        let current = self.current_seq();
        if let Some(expected) = expected_seq
            && current != expected
        {
            return Err(sequence_conflict(expected, current));
        }
        let borrowed: Vec<CompressionGuardRow<'_>> = rows
            .iter()
            .map(|row| (row.cf(), row.key(), row.value()))
            .collect();
        self.validate_latest_only_compression_admission(&borrowed)?;
        if !skip_compression_guard {
            validate_compression_writes(&table, current, &borrowed)?;
        }
        if let Some(router) = self.router.write().expect("mvcc router poisoned").as_mut() {
            // Rows written here belong to the seq allocated below (current + 1,
            // exact because all allocations happen under the row write lock
            // held here). A memtable flush triggered by these puts must carry
            // that commit watermark so the flush SST orders correctly against
            // durable batches (issue #1138).
            let commit_watermark = self.current_seq() + 1;
            for row in &rows {
                router.put_at(row.cf(), row.key(), row.value(), commit_watermark)?;
            }
        }
        // Advance the derived-content watermark BEFORE allocating the seq:
        // readers pin without taking the row lock, so a reader that observes
        // this commit's seq must already observe its watermark (issue #1100).
        // All allocations happen under the row write lock held here, so the
        // next allocated seq is exactly current + 1 (asserted by the vault
        // commit path's time-index seqno prediction).
        if rows
            .iter()
            .any(|row| row.cf().feeds_derived_search_content())
        {
            self.derived_content_seq
                .fetch_max(self.current_seq() + 1, Ordering::AcqRel);
        }
        let seq = self.seqs.allocate();
        if !self.router_latest_readback.load(Ordering::Acquire) {
            for row in rows {
                let (cf, key, value) = row.into_owned();
                table
                    .entry((cf, key))
                    .or_default()
                    .push(VersionedValue { seq, value });
            }
        }
        Ok(seq)
    }

    /// Restores one durable write group at its original sequence before live writes begin.
    pub fn restore_batch<I, K, V>(&self, seq: Seq, rows: I) -> Result<()>
    where
        I: IntoIterator<Item = (ColumnFamily, K, V)>,
        K: Into<Vec<u8>>,
        V: Into<Vec<u8>>,
    {
        let rows: Vec<_> = rows
            .into_iter()
            .map(|(cf, key, value)| (cf, key.into(), value.into()))
            .collect();
        let mut table = self.rows.write().expect("mvcc row table poisoned");
        if rows
            .iter()
            .any(|(cf, _, _)| cf.feeds_derived_search_content())
        {
            self.derived_content_seq.fetch_max(seq, Ordering::AcqRel);
        }
        for (cf, key, value) in rows {
            table
                .entry((cf, key))
                .or_default()
                .push(VersionedValue { seq, value });
        }
        Ok(())
    }

    /// Whether any version (live or tombstone) exists for `cf`/`key` in the
    /// row table. Recovery-time physical coverage checks only (issue #1132);
    /// snapshot reads must keep using the seq-visible accessors.
    pub(crate) fn has_any_version(&self, cf: ColumnFamily, key: &[u8]) -> bool {
        self.rows
            .read()
            .expect("mvcc row table poisoned")
            .contains_key(&(cf, key.to_vec()))
    }

    pub fn flush_all_cfs(&self) -> Result<Vec<SstSummary>> {
        let mut router = self.router.write().expect("mvcc router poisoned");
        let Some(router) = router.as_mut() else {
            return Ok(Vec::new());
        };
        // Read the watermark while holding the router lock: every commit at or
        // below `current_seq()` has already routed its rows into the memtables
        // (puts happen before seq allocation), and an in-flight commit whose
        // seq is not yet allocated only understates the watermark, which is
        // the safe direction (issue #1138).
        let commit_watermark = self.current_seq();
        router.flush_pending_at(commit_watermark)
    }

    /// Reconciles the live router with manifest-covered durable SSTs while the
    /// vault-wide durable commit lock is held by the caller.
    pub(crate) fn handoff_manifested_ssts(
        &self,
        durable_seq: u64,
        full_inventory: bool,
        durable_ssts: &[SstSummary],
    ) -> Result<RouterManifestHandoffReport> {
        let mut router = self.router.write().expect("mvcc router poisoned");
        let Some(router) = router.as_mut() else {
            return Ok(RouterManifestHandoffReport::default());
        };
        router.handoff_manifested_ssts(durable_seq, full_inventory, durable_ssts)
    }

    pub fn install_read_barrier(&self, barrier: ReadBarrier) {
        let mut barriers = self
            .read_barriers
            .write()
            .expect("mvcc read barriers poisoned");
        barriers.retain(|existing| existing.id() != barrier.id());
        barriers.push(barrier);
    }

    pub fn remove_read_barrier(&self, id: &str) -> bool {
        let mut barriers = self
            .read_barriers
            .write()
            .expect("mvcc read barriers poisoned");
        let before = barriers.len();
        barriers.retain(|existing| existing.id() != id);
        barriers.len() != before
    }

    pub fn read_barriers(&self) -> Vec<ReadBarrier> {
        self.read_barriers
            .read()
            .expect("mvcc read barriers poisoned")
            .clone()
    }
}

fn latest_only_compression_error(reason: String) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_LATEST_ONLY_COMPRESSION_REQUIRES_MVCC,
        message: format!(
            "latest-only vault cannot validate this compression-sensitive write: {reason}"
        ),
        remediation: "reopen the vault with restore_mvcc_rows=true before mutating a compressed slot or its generation lifecycle",
    }
}

impl Default for VersionedCfStore {
    fn default() -> Self {
        Self::new(0)
    }
}
