use super::*;

impl VersionedCfStore {
    /// Reads one CF/key at the pinned sequence.
    pub fn read_at(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        key: &[u8],
        clock: &dyn Clock,
    ) -> Result<Option<Vec<u8>>> {
        self.ensure_cf_selected(cf)?;
        self.ensure_snapshot_live(snapshot, clock)?;
        self.ensure_unbarriered(cf, key)?;
        {
            let table = self.rows.read().expect("mvcc row table poisoned");
            if let Some(value) = table
                .get(&(cf, key.to_vec()))
                .and_then(|versions| visible_value_state(versions, snapshot.seq()))
            {
                return Ok(value.into_option());
            }
        }
        self.router_latest_value(snapshot, cf, key)
    }

    /// Returns the visible version sequence for one CF/key at the pinned sequence.
    pub fn seq_for_key_at(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        key: &[u8],
        clock: &dyn Clock,
    ) -> Result<Option<Seq>> {
        self.ensure_cf_selected(cf)?;
        self.ensure_snapshot_live(snapshot, clock)?;
        self.ensure_unbarriered(cf, key)?;
        let table = self.rows.read().expect("mvcc row table poisoned");
        let seq = table
            .get(&(cf, key.to_vec()))
            .and_then(|versions| visible_version(versions, snapshot.seq()))
            .map(|version| version.seq);
        if seq.is_some() || !self.router_latest_readback.load(Ordering::Acquire) {
            return Ok(seq);
        }
        self.ensure_router_latest_snapshot(snapshot)?;
        Err(latest_only_error(format!(
            "row sequence for {} key {} is unavailable because this vault was opened in latest-only recovery mode",
            cf.name(),
            hex_prefix(key)
        )))
    }

    /// Resolves all requested CF/key rows at the same pinned sequence.
    pub fn read_batch(
        &self,
        snapshot: Snapshot,
        reads: &[CfRead],
        clock: &dyn Clock,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        self.ensure_snapshot_live(snapshot, clock)?;
        if reads.is_empty() {
            return Ok(Vec::new());
        }
        let mut order = (0..reads.len()).collect::<Vec<_>>();
        order.sort_unstable_by(|left, right| {
            reads[*left]
                .cf
                .cmp(&reads[*right].cf)
                .then_with(|| reads[*left].key.cmp(&reads[*right].key))
                .then_with(|| left.cmp(right))
        });
        let mut values = vec![None; reads.len()];
        let mut start = 0;
        while start < order.len() {
            let cf = reads[order[start]].cf;
            let mut end = start + 1;
            while end < order.len() && reads[order[end]].cf == cf {
                end += 1;
            }
            let keys = order[start..end]
                .iter()
                .map(|ordinal| (*ordinal, reads[*ordinal].key.as_slice()))
                .collect::<Vec<_>>();
            self.visit_cf_key_plan::<CalyxError, _>(
                snapshot,
                cf,
                &keys,
                clock,
                &mut |ordinal, value| {
                    values[ordinal] = value
                        .filter(|bytes| !is_tombstone_value(bytes))
                        .map(ToOwned::to_owned);
                    Ok(())
                },
            )?;
            start = end;
        }
        Ok(values)
    }

    /// Visits a sorted exact-key plan for one column family under one pinned
    /// snapshot. The row table is merge-walked without allocating a key per
    /// lookup; the latest-state router then opens each candidate SST at most
    /// once for every still-unresolved key set.
    pub fn visit_cf_key_plan<E, F>(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        keys: &[(usize, &[u8])],
        clock: &dyn Clock,
        on_value: &mut F,
    ) -> std::result::Result<OrderedReadbackMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, Option<&[u8]>) -> std::result::Result<(), E>,
    {
        self.visit_cf_key_plan_inner(snapshot, cf, keys, clock, None, on_value)
    }

    /// Ordered-plan counterpart used by an operation-scoped physical read
    /// generation. Latest-only handles reuse the retained router inventory;
    /// full-MVCC handles keep resolving the pinned sequence from version rows.
    pub(crate) fn visit_cf_key_plan_in_generation<E, F>(
        &self,
        generation: &SstReadGeneration<'_>,
        snapshot: Snapshot,
        cf: ColumnFamily,
        keys: &[(usize, &[u8])],
        clock: &dyn Clock,
        on_value: &mut F,
    ) -> std::result::Result<OrderedReadbackMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, Option<&[u8]>) -> std::result::Result<(), E>,
    {
        if !generation.belongs_to(self) {
            return Err(E::from(calyx_core::CalyxError::aster_corrupt_shard(
                "ordered readback generation belongs to a different MVCC store",
            )));
        }
        self.visit_cf_key_plan_inner(snapshot, cf, keys, clock, Some(generation), on_value)
    }

    fn visit_cf_key_plan_inner<E, F>(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        keys: &[(usize, &[u8])],
        clock: &dyn Clock,
        generation: Option<&SstReadGeneration<'_>>,
        on_value: &mut F,
    ) -> std::result::Result<OrderedReadbackMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, Option<&[u8]>) -> std::result::Result<(), E>,
    {
        self.ensure_cf_selected(cf).map_err(E::from)?;
        self.ensure_snapshot_live(snapshot, clock)
            .map_err(E::from)?;
        if keys.windows(2).any(|pair| pair[0].1 > pair[1].1) {
            return Err(E::from(calyx_core::CalyxError::aster_corrupt_shard(
                format!("ordered readback keys for {} are not sorted", cf.name()),
            )));
        }
        {
            let barriers = self
                .read_barriers
                .read()
                .expect("mvcc read barriers poisoned");
            for (_, key) in keys {
                if let Some(error) = first_blocking(&barriers, cf, key) {
                    return Err(E::from(error));
                }
            }
        }

        let mut metrics = OrderedReadbackMetrics {
            session_snapshot_seq: snapshot.seq(),
            requested_keys: u64::try_from(keys.len()).map_err(|_| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback key count exceeds u64",
                ))
            })?,
            read_batches: 1,
            ..OrderedReadbackMetrics::default()
        };
        if keys.is_empty() {
            return Ok(metrics);
        }
        let mut resolved = vec![false; keys.len()];
        metrics.plan_index_bytes = resolved
            .capacity()
            .checked_add(7)
            .map(|bits| bits / 8)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback resolution-index byte count overflow",
                ))
            })?;
        let latest_only = self.router_latest_readback.load(Ordering::Acquire);
        if !latest_only {
            let table = self.rows.read().expect("mvcc row table poisoned");
            if !table.is_empty() {
                metrics.source_read_operations = 1;
                let lower = Bound::Included((cf, keys[0].1.to_vec()));
                let mut rows = table.range((lower, Bound::Unbounded)).peekable();
                for (position, (ordinal, key)) in keys.iter().enumerate() {
                    loop {
                        let Some(((row_cf, row_key), versions)) = rows.peek() else {
                            break;
                        };
                        if *row_cf != cf || row_key.as_slice() > *key {
                            break;
                        }
                        if row_key.as_slice() < *key {
                            rows.next();
                            continue;
                        }
                        if let Some(version) = visible_version(versions, snapshot.seq()) {
                            metrics.bytes_read_back = metrics
                                .bytes_read_back
                                .checked_add(version.value.len() as u64)
                                .ok_or_else(|| {
                                    E::from(calyx_core::CalyxError::aster_corrupt_shard(
                                        "ordered readback byte counter overflow",
                                    ))
                                })?;
                            metrics.max_readback_batch_bytes = metrics
                                .max_readback_batch_bytes
                                .max(version.value.len() as u64);
                            // One resolved row is demonstrated forward progress (#980).
                            self.record_reader_progress(snapshot, clock);
                            on_value(*ordinal, Some(&version.value))?;
                            metrics.rows_read_back =
                                metrics.rows_read_back.checked_add(1).ok_or_else(|| {
                                    E::from(calyx_core::CalyxError::aster_corrupt_shard(
                                        "ordered readback row counter overflow",
                                    ))
                                })?;
                            resolved[position] = true;
                        }
                        break;
                    }
                }
            }
        }

        let unresolved = keys
            .iter()
            .enumerate()
            .filter_map(|(position, key)| (!resolved[position]).then_some(*key))
            .collect::<Vec<_>>();
        let unresolved_bytes = unresolved
            .capacity()
            .checked_mul(std::mem::size_of::<(usize, &[u8])>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback unresolved-index byte count overflow",
                ))
            })?;
        metrics.plan_index_bytes = metrics
            .plan_index_bytes
            .checked_add(unresolved_bytes)
            .ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback plan-index byte count overflow",
                ))
            })?;
        if unresolved.is_empty() {
            return Ok(metrics);
        }
        if !latest_only {
            for (ordinal, _) in unresolved {
                on_value(ordinal, None)?;
                metrics.rows_read_back =
                    metrics.rows_read_back.checked_add(1).ok_or_else(|| {
                        E::from(calyx_core::CalyxError::aster_corrupt_shard(
                            "ordered readback row counter overflow",
                        ))
                    })?;
            }
            return Ok(metrics);
        }

        self.ensure_router_latest_snapshot(snapshot)
            .map_err(E::from)?;
        if let Some(generation) = generation {
            let router = generation.router().ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "latest-only ordered readback generation did not retain its router",
                ))
            })?;
            return self.visit_router_key_plan(
                snapshot,
                cf,
                &unresolved,
                metrics,
                router,
                clock,
                on_value,
            );
        }
        let router_guard = self.router.read().expect("mvcc router poisoned");
        let Some(router) = router_guard.as_ref() else {
            for (ordinal, _) in unresolved {
                on_value(ordinal, None)?;
                metrics.rows_read_back =
                    metrics.rows_read_back.checked_add(1).ok_or_else(|| {
                        E::from(calyx_core::CalyxError::aster_corrupt_shard(
                            "ordered readback row counter overflow",
                        ))
                    })?;
            }
            return Ok(metrics);
        };
        self.visit_router_key_plan(snapshot, cf, &unresolved, metrics, router, clock, on_value)
    }

    fn visit_router_key_plan<E, F>(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        unresolved: &[(usize, &[u8])],
        mut metrics: OrderedReadbackMetrics,
        router: &CfRouter,
        clock: &dyn Clock,
        on_value: &mut F,
    ) -> std::result::Result<OrderedReadbackMetrics, E>
    where
        E: From<calyx_core::CalyxError>,
        F: FnMut(usize, Option<&[u8]>) -> std::result::Result<(), E>,
    {
        let mut router_rows = 0_u64;
        let mut router_bytes = 0_u64;
        let mut max_value_bytes = 0_u64;
        let router_metrics = router.visit_key_plan(cf, &unresolved, &mut |ordinal, value| {
            // Every row resolved from an immutable generation is demonstrated
            // forward progress. This is the loop that runs for minutes on a
            // corpus-sized plan, so it owns keeping the lease alive (#980).
            self.record_reader_progress(snapshot, clock);
            router_rows = router_rows.checked_add(1).ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback row counter overflow",
                ))
            })?;
            if let Some(bytes) = value {
                router_bytes = router_bytes
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| {
                        E::from(calyx_core::CalyxError::aster_corrupt_shard(
                            "ordered readback byte counter overflow",
                        ))
                    })?;
                max_value_bytes = max_value_bytes.max(bytes.len() as u64);
            }
            on_value(ordinal, value)
        })?;
        metrics.rows_read_back =
            metrics
                .rows_read_back
                .checked_add(router_rows)
                .ok_or_else(|| {
                    E::from(calyx_core::CalyxError::aster_corrupt_shard(
                        "ordered readback row counter overflow",
                    ))
                })?;
        metrics.bytes_read_back = metrics
            .bytes_read_back
            .checked_add(router_bytes)
            .ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback byte counter overflow",
                ))
            })?;
        metrics.source_read_operations = metrics
            .source_read_operations
            .checked_add(router_metrics.source_read_operations)
            .ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback source counter overflow",
                ))
            })?;
        metrics.sst_files_opened = router_metrics.sst_files_opened;
        metrics.unique_sst_generations = router_metrics.sst_files_opened;
        metrics.sst_key_probes = router_metrics.sst_key_probes;
        metrics.sst_map_reuses = router_metrics.sst_map_reuses;
        metrics.sst_exact_route_lookups = router_metrics.sst_exact_route_lookups;
        metrics.sst_exact_route_hits = router_metrics.sst_exact_route_hits;
        metrics.sst_fallback_file_key_checks = router_metrics.sst_fallback_file_key_checks;
        metrics.plan_index_bytes = metrics
            .plan_index_bytes
            .checked_add(router_metrics.plan_index_bytes)
            .ok_or_else(|| {
                E::from(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered readback router plan-index byte count overflow",
                ))
            })?;
        metrics.max_readback_batch_bytes = metrics
            .max_readback_batch_bytes
            .max(max_value_bytes)
            .max(router_metrics.max_value_bytes);
        Ok(metrics)
    }

    /// Scans visible rows for one CF at the pinned sequence, ordered by key.
    pub fn scan_cf_at(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        clock: &dyn Clock,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.ensure_cf_selected(cf)?;
        self.ensure_snapshot_live(snapshot, clock)?;
        let mut rows = self.router_latest_rows(snapshot, cf, None)?;
        self.overlay_table_rows(snapshot, cf, None, &mut rows);
        for key in rows.keys() {
            self.ensure_unbarriered(cf, key)?;
        }
        Ok(rows.into_iter().collect())
    }

    /// Scans visible rows for one CF and key range at the pinned sequence.
    pub fn scan_cf_range_at(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        range: &KeyRange,
        clock: &dyn Clock,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.ensure_cf_selected(cf)?;
        self.ensure_snapshot_live(snapshot, clock)?;
        let mut rows = self.router_latest_rows(snapshot, cf, Some(range))?;
        self.overlay_table_rows(snapshot, cf, Some(range), &mut rows);
        for key in rows.keys() {
            self.ensure_unbarriered(cf, key)?;
        }
        Ok(rows.into_iter().collect())
    }

    /// Scans visible row keys for one CF and key range at the pinned sequence.
    pub fn scan_cf_range_keys_at(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        range: &KeyRange,
        clock: &dyn Clock,
    ) -> Result<Vec<Vec<u8>>> {
        self.ensure_cf_selected(cf)?;
        self.ensure_snapshot_live(snapshot, clock)?;
        let mut keys = self.router_latest_keys(snapshot, cf, range)?;
        self.overlay_table_keys(snapshot, cf, range, &mut keys);
        for key in keys.keys() {
            self.ensure_unbarriered(cf, key)?;
        }
        Ok(keys.into_keys().collect())
    }

    /// Scans at most `limit` visible rows in a range after `after_key`.
    pub fn scan_cf_range_page_at(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        range: &KeyRange,
        after_key: Option<&[u8]>,
        limit: usize,
        clock: &dyn Clock,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.ensure_cf_selected(cf)?;
        self.ensure_snapshot_live(snapshot, clock)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        if self.router_latest_readback.load(Ordering::Acquire) {
            let mut rows = self.router_latest_rows_page(snapshot, cf, range, after_key, limit)?;
            self.overlay_table_rows(snapshot, cf, Some(range), &mut rows);
            for key in rows.keys() {
                self.ensure_unbarriered(cf, key)?;
            }
            return Ok(rows
                .into_iter()
                .filter(|(key, _)| range.contains(key))
                .filter(|(key, _)| after_key.is_none_or(|after| key.as_slice() > after))
                .take(limit)
                .collect());
        }
        let start = after_key.unwrap_or(&range.start).to_vec();
        let lower = if after_key.is_some() {
            Bound::Excluded((cf, start))
        } else {
            Bound::Included((cf, start))
        };
        let table = self.rows.read().expect("mvcc row table poisoned");
        let mut rows = Vec::with_capacity(limit);
        for ((row_cf, key), versions) in table.range((lower, Bound::Unbounded)) {
            if *row_cf != cf {
                if *row_cf > cf {
                    break;
                }
                continue;
            }
            if !range.contains(key) {
                if range.end.as_ref().is_some_and(|end| key >= end) {
                    break;
                }
                continue;
            }
            if let Some(value) = visible_value(versions, snapshot.seq()) {
                self.ensure_unbarriered(cf, key)?;
                rows.push((key.clone(), value));
                if rows.len() == limit {
                    break;
                }
            }
        }
        Ok(rows)
    }

    pub(super) fn ensure_unbarriered(&self, cf: ColumnFamily, key: &[u8]) -> Result<()> {
        let barriers = self
            .read_barriers
            .read()
            .expect("mvcc read barriers poisoned");
        if let Some(error) = first_blocking(&barriers, cf, key) {
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn ensure_cf_selected(&self, cf: ColumnFamily) -> Result<()> {
        if let Some(selected) = &self.selected_cfs
            && !selected.contains(&cf)
        {
            let selected_names = selected
                .iter()
                .map(|selected_cf| selected_cf.name())
                .collect::<Vec<_>>()
                .join(",");
            return Err(CalyxError {
                code: CALYX_ASTER_CF_NOT_SELECTED,
                message: format!(
                    "column family {} was not opened by this selected-CF vault handle; selected=[{}]",
                    cf.name(),
                    selected_names
                ),
                remediation: "open a new read-only vault handle whose selected_cfs explicitly includes every column family required by the operation",
            });
        }
        Ok(())
    }

    fn router_latest_value(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        if !self.router_latest_readback.load(Ordering::Acquire) {
            return Ok(None);
        }
        self.ensure_router_latest_snapshot(snapshot)?;
        let router = self.router.read().expect("mvcc router poisoned");
        let Some(router) = router.as_ref() else {
            return Ok(None);
        };
        Ok(router
            .get(cf, key)?
            .filter(|value| !is_tombstone_value(value)))
    }

    fn router_latest_rows_page(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        range: &KeyRange,
        after_key: Option<&[u8]>,
        limit: usize,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        if !self.router_latest_readback.load(Ordering::Acquire) {
            return Ok(BTreeMap::new());
        }
        self.ensure_router_latest_snapshot(snapshot)?;
        let router = self.router.read().expect("mvcc router poisoned");
        let Some(router) = router.as_ref() else {
            return Ok(BTreeMap::new());
        };
        Ok(router
            .range_page_until(cf, &range.start, range.end.as_deref(), after_key, limit)?
            .into_iter()
            .filter_map(|row| (!is_tombstone_value(&row.value)).then_some((row.key, row.value)))
            .collect())
    }

    fn router_latest_rows(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        range: Option<&KeyRange>,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        if !self.router_latest_readback.load(Ordering::Acquire) {
            return Ok(BTreeMap::new());
        }
        self.ensure_router_latest_snapshot(snapshot)?;
        let router = self.router.read().expect("mvcc router poisoned");
        let Some(router) = router.as_ref() else {
            return Ok(BTreeMap::new());
        };
        let rows = match range {
            Some(range) => match range.end.as_deref() {
                Some(end) => router.range(cf, &range.start, end)?,
                None => router
                    .iter_cf(cf)?
                    .into_iter()
                    .filter(|row| row.key.as_slice() >= range.start.as_slice())
                    .collect(),
            },
            None => router.iter_cf(cf)?,
        };
        Ok(rows
            .into_iter()
            .filter_map(|row| (!is_tombstone_value(&row.value)).then_some((row.key, row.value)))
            .collect())
    }

    fn router_latest_keys(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        range: &KeyRange,
    ) -> Result<BTreeMap<Vec<u8>, ()>> {
        if !self.router_latest_readback.load(Ordering::Acquire) {
            return Ok(BTreeMap::new());
        }
        self.ensure_router_latest_snapshot(snapshot)?;
        let router = self.router.read().expect("mvcc router poisoned");
        let Some(router) = router.as_ref() else {
            return Ok(BTreeMap::new());
        };
        Ok(router
            .range_keys_until(cf, &range.start, range.end.as_deref())?
            .into_iter()
            .map(|key| (key, ()))
            .collect())
    }

    fn overlay_table_rows(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        range: Option<&KeyRange>,
        rows: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    ) {
        let table = self.rows.read().expect("mvcc row table poisoned");
        for ((row_cf, key), versions) in table.iter() {
            if *row_cf != cf || range.is_some_and(|range| !range.contains(key)) {
                continue;
            }
            match visible_value_state(versions, snapshot.seq()) {
                Some(VisibleValue::Live(value)) => {
                    rows.insert(key.clone(), value);
                }
                Some(VisibleValue::Tombstone) => {
                    rows.remove(key);
                }
                None => {}
            }
        }
    }

    fn overlay_table_keys(
        &self,
        snapshot: Snapshot,
        cf: ColumnFamily,
        range: &KeyRange,
        keys: &mut BTreeMap<Vec<u8>, ()>,
    ) {
        let table = self.rows.read().expect("mvcc row table poisoned");
        for ((row_cf, key), versions) in table.iter() {
            if *row_cf != cf || !range.contains(key) {
                continue;
            }
            match visible_value_state(versions, snapshot.seq()) {
                Some(VisibleValue::Live(_)) => {
                    keys.insert(key.clone(), ());
                }
                Some(VisibleValue::Tombstone) => {
                    keys.remove(key);
                }
                None => {}
            }
        }
    }

    pub(super) fn ensure_router_latest_snapshot(&self, snapshot: Snapshot) -> Result<()> {
        let latest = self.current_seq();
        if snapshot.seq() == latest {
            return Ok(());
        }
        Err(latest_only_error(format!(
            "historical snapshot {} requested from latest-only recovered vault at seq {}",
            snapshot.seq(),
            latest
        )))
    }

    /// Fail-closed read guard for one pinned snapshot.
    ///
    /// `snapshot` is an immutable `Copy` stamped at pin time, so its own window
    /// only ever describes the moment the lease was issued. The **registry** owns
    /// the authoritative deadline: a holder that keeps demonstrating forward
    /// progress refreshes its entry in place through
    /// [`Self::record_reader_progress`] (#980). While that entry is live, every
    /// version at or below `pinned_seq` is still pinned against version GC, so
    /// reading at this snapshot stays correct no matter how long the operation
    /// has legitimately been running.
    ///
    /// Expiry is therefore reserved for a reader that genuinely stopped making
    /// progress for a whole stall window — its pin is reclaimable and the read
    /// must not continue.
    ///
    /// A lease with no registry entry is refused outright (#1038). Every
    /// `Snapshot` is born registered — `pin_snapshot` and `pin_snapshot_at` are
    /// the only constructors and both register — so a missing entry means the
    /// lease was released, aborted, or reclaimed, and versions at or below
    /// `pinned_seq` are already reclaimable. Consulting the immutable copy's own
    /// window here would let a read outlive its pin for up to `max_age_ms`,
    /// which is the operation-budget semantics #980 removed.
    pub(super) fn ensure_snapshot_live(&self, snapshot: Snapshot, clock: &dyn Clock) -> Result<()> {
        let now = clock.now();
        let lease = snapshot.lease();
        match self.leases.progress_state(lease.id(), now) {
            Some((true, _)) => Ok(()),
            Some((false, stalled_for_ms)) => {
                self.leases.abort_registered_if_expired(lease.id(), now);
                Err(calyx_core::CalyxError::reader_lease_expired(format!(
                    "reader lease {} for seq {} expired: holder made no observable progress for \
                     {stalled_for_ms} ms (stall window max_age_ms={}, pinned at {}, observed at \
                     {now}). The pin was released so version GC can reclaim seq <= {}",
                    lease.id(),
                    lease.pinned_seq(),
                    lease.max_age_ms(),
                    lease.issued_at(),
                    lease.pinned_seq()
                )))
            }
            None => Err(calyx_core::CalyxError::reader_lease_expired(format!(
                "reader lease {} for seq {} is not registered: its snapshot pin was released, \
                 aborted, or reclaimed before this read (pinned at {}, stall window \
                 max_age_ms={}, observed at {now}). Version GC may already have reclaimed seq \
                 <= {}, so this read is refused; pin a fresh snapshot and retry",
                lease.id(),
                lease.pinned_seq(),
                lease.issued_at(),
                lease.max_age_ms(),
                lease.pinned_seq()
            ))),
        }
    }

    /// Records that `snapshot`'s reader demonstrated forward progress (#980).
    ///
    /// Called from read loops that legitimately run far longer than one stall
    /// window. Only the registry's stall window moves; the pinned sequence, the
    /// lease id, and the version-GC floor are untouched, so this can never widen
    /// visibility or unpin a version the holder can still read. A reader stuck
    /// *inside* one step never reaches these calls, so it still expires.
    pub(crate) fn record_reader_progress(&self, snapshot: Snapshot, clock: &dyn Clock) {
        self.leases
            .record_progress(snapshot.lease().id(), clock.now());
    }
}

fn visible_value(versions: &[VersionedValue], seq: Seq) -> Option<Vec<u8>> {
    visible_value_state(versions, seq).and_then(VisibleValue::into_option)
}

enum VisibleValue {
    Live(Vec<u8>),
    Tombstone,
}

impl VisibleValue {
    fn into_option(self) -> Option<Vec<u8>> {
        match self {
            Self::Live(value) => Some(value),
            Self::Tombstone => None,
        }
    }
}

fn visible_value_state(versions: &[VersionedValue], seq: Seq) -> Option<VisibleValue> {
    visible_version(versions, seq).map(|version| {
        if is_tombstone_value(&version.value) {
            VisibleValue::Tombstone
        } else {
            VisibleValue::Live(version.value.clone())
        }
    })
}

fn visible_version(versions: &[VersionedValue], seq: Seq) -> Option<&VersionedValue> {
    versions.iter().rev().find(|version| version.seq <= seq)
}

fn latest_only_error(message: impl Into<String>) -> calyx_core::CalyxError {
    calyx_core::CalyxError {
        code: "CALYX_ASTER_LATEST_ONLY_HISTORY_UNAVAILABLE",
        message: message.into(),
        remediation: "open the vault with full MVCC recovery before requesting historical row state",
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    let mut value = String::new();
    for byte in bytes.iter().take(12) {
        value.push_str(&format!("{byte:02x}"));
    }
    if bytes.len() > 12 {
        value.push_str("...");
    }
    value
}
