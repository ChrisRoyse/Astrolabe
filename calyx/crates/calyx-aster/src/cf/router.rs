use super::ColumnFamily;
use crate::compaction::TieringPolicy;
use crate::memtable::{Memtable, MemtableUsage};
use crate::resource::ResourceCounters;
use crate::sst::level::{SstLevel, SstPlanReadMetrics};
use crate::sst::{SstEntry, SstSummary};
use crate::storage_names::flush_sst_file_name;
use calyx_core::{CalyxError, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_MEMTABLE_BYTES: usize = 8 * 1024 * 1024;

/// Commit watermark for router writes that have no commit domain (raw
/// `CfRouter` users such as drills and standalone stores). Flushes at this
/// watermark sort at the very start of the commit domain, which is exact for
/// standalone directories (there are no commit-domain files) and never
/// shadows commit-domain data elsewhere.
pub const NO_COMMIT_DOMAIN: u64 = 0;

#[derive(Debug)]
pub struct CfRouter {
    vault_dir: PathBuf,
    tiering_policy: Option<TieringPolicy>,
    pub(super) memtables: HashMap<ColumnFamily, Memtable>,
    pub(super) levels: HashMap<ColumnFamily, SstLevel>,
    pub(super) next_file: HashMap<ColumnFamily, u64>,
    pub(super) memtable_byte_cap: usize,
    resource_counters: Arc<ResourceCounters>,
    pub(super) existing_only: bool,
    pub(super) eager_lookup_cfs: BTreeSet<ColumnFamily>,
    pub(super) eager_lookup_all: bool,
    /// Exact read capability for a selected-CF handle. `None` means the
    /// router was opened over the complete vault; `Some` means every access
    /// outside this set must fail instead of synthesizing an empty keyspace.
    selected_cfs: Option<BTreeSet<ColumnFamily>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RouterPlanReadMetrics {
    pub source_read_operations: u64,
    pub sst_files_opened: u64,
    pub sst_key_probes: u64,
    pub sst_map_reuses: u64,
    pub max_value_bytes: u64,
    pub plan_index_bytes: u64,
}

impl CfRouter {
    /// Configured hard byte cap for every active column-family memtable.
    pub const fn memtable_byte_cap(&self) -> usize {
        self.memtable_byte_cap
    }

    pub fn open(vault_dir: impl AsRef<Path>, memtable_byte_cap: usize) -> Result<Self> {
        Self::open_with_tiering(vault_dir, memtable_byte_cap, None)
    }

    pub(crate) fn open_selected_cfs(
        vault_dir: impl AsRef<Path>,
        memtable_byte_cap: usize,
        cfs: impl IntoIterator<Item = ColumnFamily>,
    ) -> Result<Self> {
        Self::open_selected_cfs_with_tiering(vault_dir, memtable_byte_cap, cfs, None)
    }

    pub(crate) fn open_selected_existing_cfs(
        vault_dir: impl AsRef<Path>,
        memtable_byte_cap: usize,
        cfs: impl IntoIterator<Item = ColumnFamily>,
    ) -> Result<Self> {
        let selected = cfs.into_iter().collect::<BTreeSet<_>>();
        if selected.is_empty() {
            return Err(CalyxError::aster_corrupt_shard(
                "selected existing CF router open requires at least one column family",
            ));
        }
        let mut router = Self::new_existing(vault_dir, memtable_byte_cap)?;
        router.eager_lookup_cfs = selected.clone();
        router.selected_cfs = Some(selected.clone());
        for cf in &selected {
            router.ensure_existing_cf(*cf)?;
        }
        router.load_existing_cfs(&selected.into_iter().collect::<Vec<_>>())?;
        Ok(router)
    }

    pub(crate) fn open_existing(
        vault_dir: impl AsRef<Path>,
        memtable_byte_cap: usize,
    ) -> Result<Self> {
        let mut router = Self::new_existing(vault_dir, memtable_byte_cap)?;
        router.load_existing()?;
        Ok(router)
    }

    /// Opens an existing current-state router and validates/caches immutable
    /// SST index metadata once for every discovered column family.
    pub(crate) fn open_existing_latest(
        vault_dir: impl AsRef<Path>,
        memtable_byte_cap: usize,
    ) -> Result<Self> {
        let mut router = Self::new_existing(vault_dir, memtable_byte_cap)?;
        router.eager_lookup_all = true;
        router.load_existing()?;
        Ok(router)
    }

    pub(crate) fn open_selected_cfs_with_tiering(
        vault_dir: impl AsRef<Path>,
        memtable_byte_cap: usize,
        cfs: impl IntoIterator<Item = ColumnFamily>,
        tiering_policy: Option<TieringPolicy>,
    ) -> Result<Self> {
        let selected = cfs.into_iter().collect::<BTreeSet<_>>();
        if selected.is_empty() {
            return Err(CalyxError::aster_corrupt_shard(
                "selected CF router open requires at least one column family",
            ));
        }
        let mut router = Self::new_empty(vault_dir, memtable_byte_cap, tiering_policy)?;
        router.eager_lookup_cfs = selected.clone();
        router.selected_cfs = Some(selected.clone());
        for cf in &selected {
            router.ensure_cf(*cf)?;
        }
        router.load_existing_cfs(&selected.into_iter().collect::<Vec<_>>())?;
        Ok(router)
    }

    pub fn open_with_tiering(
        vault_dir: impl AsRef<Path>,
        memtable_byte_cap: usize,
        tiering_policy: Option<TieringPolicy>,
    ) -> Result<Self> {
        let mut router = Self::new_empty(vault_dir, memtable_byte_cap, tiering_policy)?;
        for cf in ColumnFamily::STATIC {
            router.ensure_cf(cf)?;
        }
        router.load_existing()?;
        Ok(router)
    }

    /// Opens a writable current-state router with one shared validated lookup
    /// descriptor for each existing immutable SST. Newly flushed SSTs enter
    /// the same metadata-bearing path through `push_with_lookup`.
    pub(crate) fn open_with_tiering_latest(
        vault_dir: impl AsRef<Path>,
        memtable_byte_cap: usize,
        tiering_policy: Option<TieringPolicy>,
    ) -> Result<Self> {
        let mut router = Self::new_empty(vault_dir, memtable_byte_cap, tiering_policy)?;
        router.eager_lookup_all = true;
        for cf in ColumnFamily::STATIC {
            router.ensure_cf(cf)?;
        }
        router.load_existing()?;
        Ok(router)
    }

    fn new_empty(
        vault_dir: impl AsRef<Path>,
        memtable_byte_cap: usize,
        tiering_policy: Option<TieringPolicy>,
    ) -> Result<Self> {
        let vault_dir = vault_dir.as_ref().to_path_buf();
        let memtable_byte_cap = if memtable_byte_cap == 0 {
            DEFAULT_MEMTABLE_BYTES
        } else {
            memtable_byte_cap
        };
        fs::create_dir_all(vault_dir.join("cf"))
            .map_err(|error| CalyxError::disk_pressure(format!("create CF root: {error}")))?;
        if let Some(policy) = &tiering_policy {
            for tier_root in policy.tier_roots() {
                fs::create_dir_all(tier_root.join("cf")).map_err(|error| {
                    CalyxError::disk_pressure(format!("create tiered CF root: {error}"))
                })?;
            }
        }
        Ok(Self {
            vault_dir,
            tiering_policy,
            memtables: HashMap::new(),
            levels: HashMap::new(),
            next_file: HashMap::new(),
            memtable_byte_cap,
            resource_counters: Arc::new(ResourceCounters::default()),
            existing_only: false,
            eager_lookup_cfs: BTreeSet::new(),
            eager_lookup_all: false,
            selected_cfs: None,
        })
    }

    fn new_existing(vault_dir: impl AsRef<Path>, memtable_byte_cap: usize) -> Result<Self> {
        let vault_dir = vault_dir.as_ref().to_path_buf();
        let cf_root = vault_dir.join("cf");
        if !cf_root.is_dir() {
            return Err(CalyxError {
                code: "CALYX_READ_ONLY_CF_ROOT_MISSING",
                message: format!(
                    "read-only CF root {} is absent; refusing to create it",
                    cf_root.display()
                ),
                remediation: "initialize the durable vault through a write-capable handle before reading",
            });
        }
        let memtable_byte_cap = if memtable_byte_cap == 0 {
            DEFAULT_MEMTABLE_BYTES
        } else {
            memtable_byte_cap
        };
        Ok(Self {
            vault_dir,
            tiering_policy: None,
            memtables: HashMap::new(),
            levels: HashMap::new(),
            next_file: HashMap::new(),
            memtable_byte_cap,
            resource_counters: Arc::new(ResourceCounters::default()),
            existing_only: true,
            eager_lookup_cfs: BTreeSet::new(),
            eager_lookup_all: false,
            selected_cfs: None,
        })
    }

    /// Returns the exact column-family capability of a selected-CF router.
    /// Full-vault routers return `None`.
    pub(crate) fn selected_cfs(&self) -> Option<&BTreeSet<ColumnFamily>> {
        self.selected_cfs.as_ref()
    }

    /// Raw write with no commit domain; see [`Self::put_at`].
    pub fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) -> Result<()> {
        self.put_at(cf, key, value, NO_COMMIT_DOMAIN)
    }

    /// Writes one row; any memtable flush this write triggers is stamped with
    /// `commit_watermark` (the highest commit seq whose rows can be in the
    /// flushed memtable), so the flush SST orders exactly against durable
    /// batches in the commit domain (issue #1138).
    pub fn put_at(
        &mut self,
        cf: ColumnFamily,
        key: &[u8],
        value: &[u8],
        commit_watermark: u64,
    ) -> Result<()> {
        self.ensure_cf(cf)?;
        let mut counted_backpressure = false;
        let ack = match self.memtable_mut(cf).write(key, value, 0) {
            Ok(ack) => ack,
            Err(error) => {
                if error.code != "CALYX_BACKPRESSURE" {
                    return Err(error);
                }
                self.flush_cf_at(cf, commit_watermark)?;
                match self.memtable_mut(cf).write(key, value, 0) {
                    Ok(ack) => {
                        self.resource_counters.record_memtable_absorbed();
                        counted_backpressure = true;
                        ack
                    }
                    Err(retry_error) => {
                        if retry_error.code == "CALYX_BACKPRESSURE" {
                            self.resource_counters.record_memtable_rejected();
                        }
                        return Err(retry_error);
                    }
                }
            }
        };
        if ack.flush_triggered {
            if !counted_backpressure {
                self.resource_counters.record_memtable_absorbed();
            }
            self.flush_cf_at(cf, commit_watermark)?;
        }
        Ok(())
    }

    /// Fails closed before WAL append when a row can never fit in one memtable.
    pub fn ensure_batch_admitted<I, K, V>(&self, rows: I) -> Result<()>
    where
        I: IntoIterator<Item = (ColumnFamily, K, V)>,
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        for (cf, key, value) in rows {
            let row_bytes = Memtable::entry_size(key.as_ref(), value.as_ref());
            if row_bytes > self.memtable_byte_cap {
                self.resource_counters.record_memtable_rejected();
                return Err(CalyxError::backpressure(format!(
                    "memtable byte cap {} cannot fit {} row of {} bytes",
                    self.memtable_byte_cap,
                    cf.name(),
                    row_bytes
                )));
            }
        }
        Ok(())
    }

    /// Shares the backpressure counters this router increments.
    pub fn resource_counters(&self) -> Arc<ResourceCounters> {
        Arc::clone(&self.resource_counters)
    }

    pub fn memtable_usage_by_cf(&self) -> Vec<(ColumnFamily, MemtableUsage)> {
        let mut usage = self
            .memtables
            .iter()
            .map(|(cf, table)| (*cf, table.usage()))
            .collect::<Vec<_>>();
        usage.sort_by_key(|left| left.0.name());
        usage
    }

    /// Raw flush with no commit domain; see [`Self::flush_cf_at`].
    pub fn flush_cf(&mut self, cf: ColumnFamily) -> Result<SstSummary> {
        self.flush_cf_at(cf, NO_COMMIT_DOMAIN)
    }

    /// Flushes one CF's memtable to a commit-anchored flush SST
    /// (`flush-{watermark:020}-{ordinal:04}.sst`). `commit_watermark` must be
    /// the highest commit seq whose rows can be in the memtable; understating
    /// it is safe (the file sorts earlier and committed rows keep their
    /// durable-batch home), overstating it can shadow newer durable batches.
    pub fn flush_cf_at(&mut self, cf: ColumnFamily, commit_watermark: u64) -> Result<SstSummary> {
        self.ensure_cf(cf)?;
        let fresh = Memtable::new(self.memtable_byte_cap);
        let frozen = std::mem::replace(self.memtable_mut(cf), fresh).freeze();
        let ordinal = self.next_sequence(cf);
        let ordinal = usize::try_from(ordinal).map_err(|_| {
            CalyxError::aster_corrupt_shard(format!(
                "flush ordinal {ordinal} for {} exceeds the platform's usize range",
                cf.name()
            ))
        })?;
        let path = self
            .cf_dir(cf)
            .join(flush_sst_file_name(commit_watermark, ordinal));
        let summary = frozen.flush_to_sst(&path)?;
        self.levels
            .entry(cf)
            .or_default()
            .push_with_lookup(summary.path.clone())?;
        Ok(summary)
    }

    pub fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(value) = self.memtables.get(&cf).and_then(|table| table.get(key)) {
            return Ok(Some(value));
        }
        self.levels
            .get(&cf)
            .map_or(Ok(None), |level| level.get(key))
    }

    /// Visits one column family's exact read plan without reopening an SST for
    /// every key or retaining all returned values.
    pub(crate) fn visit_key_plan<E, F>(
        &self,
        cf: ColumnFamily,
        keys: &[(usize, &[u8])],
        on_value: &mut F,
    ) -> std::result::Result<RouterPlanReadMetrics, E>
    where
        E: From<CalyxError>,
        F: FnMut(usize, Option<&[u8]>) -> std::result::Result<(), E>,
    {
        let mut metrics = RouterPlanReadMetrics::default();
        let mut resolved = vec![false; keys.len()];
        let mut memtable_values: Vec<Option<Vec<u8>>> = vec![None; keys.len()];
        metrics.plan_index_bytes = resolved
            .capacity()
            .checked_add(7)
            .map(|bits| bits / 8)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                E::from(CalyxError::aster_corrupt_shard(
                    "router ordered-readback resolution-index byte count overflow",
                ))
            })?;
        if let Some(table) = self.memtables.get(&cf) {
            metrics.source_read_operations = metrics
                .source_read_operations
                .checked_add(1)
                .ok_or_else(|| {
                    E::from(CalyxError::aster_corrupt_shard(
                        "router ordered-readback source counter overflow",
                    ))
                })?;
            for (position, (_, key)) in keys.iter().enumerate() {
                if let Some(value) = table.get(key) {
                    metrics.max_value_bytes = metrics.max_value_bytes.max(value.len() as u64);
                    memtable_values[position] = Some(value);
                    resolved[position] = true;
                }
            }
        }
        let level_metrics = self
            .levels
            .get(&cf)
            .cloned()
            .unwrap_or_default()
            .visit_key_plan(keys, &mut resolved, on_value)?;
        merge_sst_plan_metrics(&mut metrics, level_metrics)?;
        for (position, (ordinal, _)) in keys.iter().enumerate() {
            if let Some(value) = memtable_values[position].as_deref() {
                on_value(*ordinal, Some(value))?;
            }
        }
        Ok(metrics)
    }

    pub fn range(&self, cf: ColumnFamily, start: &[u8], end: &[u8]) -> Result<Vec<SstEntry>> {
        let mut rows = BTreeMap::new();
        if let Some(level) = self.levels.get(&cf) {
            for entry in level.range(start, end)? {
                rows.insert(entry.key, entry.value);
            }
        }
        if let Some(table) = self.memtables.get(&cf) {
            for (key, value) in table.iter() {
                if key.as_slice() >= start && key.as_slice() < end {
                    rows.insert(key, value);
                }
            }
        }
        Ok(rows
            .into_iter()
            .map(|(key, value)| SstEntry { key, value })
            .collect())
    }

    pub fn range_page_until(
        &self,
        cf: ColumnFamily,
        start: &[u8],
        end: Option<&[u8]>,
        after_key: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<SstEntry>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let overlay = self
            .memtables
            .get(&cf)
            .map(|table| {
                table
                    .iter()
                    .filter(|(key, _)| key.as_slice() >= start)
                    .filter(|(key, _)| end.is_none_or(|end| key.as_slice() < end))
                    .map(|(key, value)| SstEntry { key, value })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        self.levels
            .get(&cf)
            .cloned()
            .unwrap_or_default()
            .range_page_with_overlay(start, end, after_key, limit, overlay)
    }

    pub fn range_keys(&self, cf: ColumnFamily, start: &[u8], end: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.range_keys_until(cf, start, Some(end))
    }

    pub fn range_keys_until(
        &self,
        cf: ColumnFamily,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>> {
        let mut rows = BTreeMap::<Vec<u8>, bool>::new();
        if let Some(level) = self.levels.get(&cf) {
            for key in level.range_keys_until(start, end)? {
                rows.insert(key, false);
            }
        }
        if let Some(table) = self.memtables.get(&cf) {
            for (key, value) in table.iter() {
                if key.as_slice() >= start && end.is_none_or(|end| key.as_slice() < end) {
                    rows.insert(key, crate::mvcc::is_tombstone_value(&value));
                }
            }
        }
        Ok(rows
            .into_iter()
            .filter_map(|(key, is_tombstone)| (!is_tombstone).then_some(key))
            .collect())
    }

    pub fn iter_cf(&self, cf: ColumnFamily) -> Result<Vec<SstEntry>> {
        let mut rows = BTreeMap::new();
        if let Some(level) = self.levels.get(&cf) {
            for entry in level.iter()? {
                rows.insert(entry.key, entry.value);
            }
        }
        if let Some(table) = self.memtables.get(&cf) {
            for (key, value) in table.iter() {
                rows.insert(key, value);
            }
        }
        Ok(rows
            .into_iter()
            .map(|(key, value)| SstEntry { key, value })
            .collect())
    }

    pub fn level_file_count(&self, cf: ColumnFamily) -> usize {
        self.levels.get(&cf).map_or(0, SstLevel::file_count)
    }

    /// Raw flush with no commit domain; see [`Self::flush_pending_at`].
    pub fn flush_pending(&mut self) -> Result<Vec<SstSummary>> {
        self.flush_pending_at(NO_COMMIT_DOMAIN)
    }

    /// Flushes every non-empty memtable at `commit_watermark`; see
    /// [`Self::flush_cf_at`] for the watermark contract.
    pub fn flush_pending_at(&mut self, commit_watermark: u64) -> Result<Vec<SstSummary>> {
        let cfs = self
            .memtables
            .iter()
            .filter_map(|(cf, table)| (!table.is_empty()).then_some(*cf))
            .collect::<Vec<_>>();
        let mut summaries = Vec::with_capacity(cfs.len());
        for cf in cfs {
            summaries.push(self.flush_cf_at(cf, commit_watermark)?);
        }
        Ok(summaries)
    }

    pub(super) fn ensure_cf(&mut self, cf: ColumnFamily) -> Result<()> {
        // The on-disk CF directory only needs creating the first time this
        // router handle sees the CF. `create_dir_all` was previously run on
        // EVERY put, and on Windows that filesystem syscall (~40 us/row) was
        // the dominant `mvcc_commit` cost of a bulk import: #433 attributed
        // 88-89% of `write_import_rows` to `group_commit`, and this per-row
        // syscall was that path's linear-in-rows term (issue #444). The
        // directory is idempotent, so creating it once per CF is byte-identical
        // to creating it per row. `self.memtables` is the create-once marker —
        // an entry is inserted here alongside the directory and is never
        // removed (a flush swaps the memtable in place, keeping the key), so
        // its presence proves the directory already exists. The remaining entry
        // ensures below are cheap map lookups kept for robustness.
        if !self.memtables.contains_key(&cf) {
            fs::create_dir_all(self.cf_dir(cf))
                .map_err(|error| CalyxError::disk_pressure(format!("create CF dir: {error}")))?;
        }
        self.memtables
            .entry(cf)
            .or_insert_with(|| Memtable::new(self.memtable_byte_cap));
        self.levels.entry(cf).or_default();
        self.next_file.entry(cf).or_insert(1);
        Ok(())
    }

    pub(super) fn ensure_existing_cf(&mut self, cf: ColumnFamily) -> Result<()> {
        let path = self.cf_dir(cf);
        if !path.is_dir() {
            return Err(CalyxError {
                code: "CALYX_READ_ONLY_CF_MISSING",
                message: format!(
                    "selected read-only column family {} is absent at {}",
                    cf.name(),
                    path.display()
                ),
                remediation: "open only column families persisted by this vault, or initialize the missing family through a write-capable handle",
            });
        }
        self.memtables
            .entry(cf)
            .or_insert_with(|| Memtable::new(self.memtable_byte_cap));
        self.levels.entry(cf).or_default();
        self.next_file.entry(cf).or_insert(1);
        Ok(())
    }

    fn memtable_mut(&mut self, cf: ColumnFamily) -> &mut Memtable {
        self.memtables
            .entry(cf)
            .or_insert_with(|| Memtable::new(self.memtable_byte_cap))
    }

    fn next_sequence(&mut self, cf: ColumnFamily) -> u64 {
        let next = self.next_file.entry(cf).or_insert(1);
        let seq = *next;
        *next += 1;
        seq
    }

    fn cf_dir(&self, cf: ColumnFamily) -> PathBuf {
        self.tiering_policy.as_ref().map_or_else(
            || self.vault_dir.join("cf").join(cf.name()),
            |policy| policy.place_current_cf(cf).absolute_dir(),
        )
    }

    pub(super) fn cf_roots(&self) -> Vec<PathBuf> {
        let mut roots = vec![self.vault_dir.join("cf")];
        if let Some(policy) = &self.tiering_policy {
            for tier_root in policy.tier_roots() {
                let cf_root = tier_root.join("cf");
                if !roots.contains(&cf_root) {
                    roots.push(cf_root);
                }
            }
        }
        roots
    }
}

fn merge_sst_plan_metrics<E>(
    metrics: &mut RouterPlanReadMetrics,
    sst: SstPlanReadMetrics,
) -> std::result::Result<(), E>
where
    E: From<CalyxError>,
{
    metrics.sst_files_opened = metrics
        .sst_files_opened
        .checked_add(sst.files_opened)
        .ok_or_else(|| {
            E::from(CalyxError::aster_corrupt_shard(
                "router ordered-readback SST-open counter overflow",
            ))
        })?;
    metrics.source_read_operations = metrics
        .source_read_operations
        .checked_add(sst.files_opened)
        .ok_or_else(|| {
            E::from(CalyxError::aster_corrupt_shard(
                "router ordered-readback source counter overflow",
            ))
        })?;
    metrics.sst_key_probes = metrics
        .sst_key_probes
        .checked_add(sst.key_probes)
        .ok_or_else(|| {
            E::from(CalyxError::aster_corrupt_shard(
                "router ordered-readback SST key-probe counter overflow",
            ))
        })?;
    metrics.sst_map_reuses = metrics
        .sst_map_reuses
        .checked_add(sst.map_reuses)
        .ok_or_else(|| {
            E::from(CalyxError::aster_corrupt_shard(
                "router ordered-readback SST map-reuse counter overflow",
            ))
        })?;
    metrics.max_value_bytes = metrics.max_value_bytes.max(sst.max_value_bytes);
    metrics.plan_index_bytes = metrics
        .plan_index_bytes
        .checked_add(sst.plan_index_bytes)
        .ok_or_else(|| {
            E::from(CalyxError::aster_corrupt_shard(
                "router ordered-readback plan-index byte count overflow",
            ))
        })?;
    Ok(())
}
