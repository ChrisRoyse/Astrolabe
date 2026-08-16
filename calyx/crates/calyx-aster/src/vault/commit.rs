mod generation_injection;

use super::{AsterVault, durable, encode, ledger_hook};
use crate::cf::{CfRouter, ColumnFamily, compression_membership_proof_prefix_range};
use calyx_core::{CalyxError, Clock, Result, Seq};
use generation_injection::validate_generation_injection_shape;

/// The WAL append is durable, but the live MVCC/router apply failed and the
/// caller must reconcile the reported sequence before retrying.
pub const CALYX_DURABLE_COMMIT_RECONCILIATION_REQUIRED: &str =
    "CALYX_DURABLE_COMMIT_RECONCILIATION_REQUIRED";

impl<C> AsterVault<C>
where
    C: Clock,
{
    pub(crate) fn with_durable_commit_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let Some(durable) = &self.durable else {
            return f();
        };
        let _commit_guard = crate::file_lock::FileLockGuard::acquire(&durable.commit_lock_path())?;
        if durable.durable_tip_seq()? > self.latest_seq() {
            self.refresh_from_durable()?;
        }
        f()
    }

    pub(crate) fn with_recurrence_write_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let _guard = self
            .recurrence_write_lock
            .lock()
            .map_err(|_| CalyxError::backpressure("recurrence write lock poisoned"))?;
        let _file_guard = self
            .durable
            .as_ref()
            .map(|durable| {
                crate::file_lock::FileLockGuard::acquire(&durable.recurrence_lock_path())
            })
            .transpose()?;
        if self
            .durable
            .as_ref()
            .map(|durable| durable.durable_tip_seq())
            .transpose()?
            .is_some_and(|tip| tip > self.latest_seq())
        {
            self.refresh_from_durable()?;
        }
        f()
    }

    fn refresh_from_durable(&self) -> Result<()> {
        let Some(durable) = &self.durable else {
            return Ok(());
        };
        let current = self.latest_seq();
        let mode = if self.rows.uses_latest_router() {
            durable::RecoveryMode::LatestRouter
        } else {
            durable::RecoveryMode::FullMvcc
        };
        let recovered = durable.recover_current_batches(mode)?;
        let latest_candidate = if mode == durable::RecoveryMode::LatestRouter {
            let mut router = CfRouter::open_with_tiering_latest(
                durable.root(),
                self.rows.latest_router_memtable_byte_cap()?,
                durable.tiering_policy().cloned(),
            )?;
            router.replay_latest_rows(recovered.batches.iter().flat_map(|batch| {
                batch
                    .rows
                    .iter()
                    .map(move |row| (batch.seq, row.cf, row.key.as_slice(), row.value.as_slice()))
            }))?;
            Some(router)
        } else {
            None
        };
        if let Some(hook) = &self.ledger_hook {
            ledger_hook::refresh_hook(
                hook,
                durable.root(),
                &recovered,
                durable.ledger_checkpoint(),
                durable.tiering_policy(),
                std::sync::Arc::clone(&self.clock),
            )?;
        }
        self.replace_retention_horizon(recovered.retention_horizon.clone())?;
        durable.advance_derived_content_watermark_to_at_least(recovered.derived_content_floor_seq);
        // WAL-tail batches from a foreign writer have no durable-batch SSTs
        // yet; stage them here so this handle's next checkpoint flush cannot
        // advance the manifest past them if that writer dies (issue #1132).
        match mode {
            durable::RecoveryMode::FullMvcc => {
                self.rows
                    .advance_derived_content_seq_to_at_least(recovered.derived_content_floor_seq);
                for batch in &recovered.batches {
                    if batch.seq <= current {
                        continue;
                    }
                    let rows_at_seq = batch
                        .rows
                        .iter()
                        .map(|row| (row.cf, row.key.clone(), row.value.clone()));
                    self.rows.restore_mvcc_batch(batch.seq, rows_at_seq)?;
                }
                self.rows.advance_to_at_least(recovered.last_recovered_seq);
            }
            durable::RecoveryMode::LatestRouter => {
                let candidate = latest_candidate.ok_or_else(|| {
                    CalyxError::aster_corrupt_shard(
                        "latest-router refresh completed recovery without a candidate router",
                    )
                })?;
                self.rows.replace_latest_recovered_router(
                    current,
                    recovered.last_recovered_seq,
                    recovered.wal_replay_floor_seq,
                    recovered.derived_content_floor_seq,
                    recovered
                        .batches
                        .iter()
                        .flat_map(|batch| batch.rows.iter().map(move |row| (batch.seq, row.cf))),
                    candidate,
                )?;
            }
        }
        durable.stage_recovered_wal_batches(
            recovered
                .batches
                .iter()
                .filter(|batch| batch.seq > recovered.wal_replay_floor_seq)
                .map(|batch| (batch.seq, batch.rows.clone()))
                .collect(),
        )?;
        Ok(())
    }

    pub(super) fn commit_rows(&self, rows: &[encode::WriteRow]) -> Result<Seq> {
        self.with_durable_commit_lock(|| self.commit_rows_locked(rows))
    }

    pub(crate) fn commit_rows_locked(&self, rows: &[encode::WriteRow]) -> Result<Seq> {
        // Slice callers keep the historical one-copy contract: materialize the
        // batch once here, then hand ownership to the shared path below. The
        // owned path is byte-identical — the copy is simply hoisted to the caller
        // boundary, and the hot import path (`write_cf_batch_with_ledger_entry`)
        // that already owns its `Vec` skips it entirely via `_owned` (#444).
        self.commit_rows_locked_owned(rows.to_vec(), false)
    }

    /// Adversarial / historical persisted-state injection for one compressed slot
    /// column, skipping the compression-generation admission guard. It exists so
    /// migration tooling and FSV drivers can stage two persisted states that the
    /// lawful guard deliberately refuses to synthesize through `write_cf_batch*`:
    ///
    /// * **legacy reconstruction** — the exact unmanifested, un-lifecycled
    ///   compressed column a pre-#562 binary wrote and that WAL recovery replays
    ///   unguarded (tombstone the manifest and its lifecycle records); the
    ///   `Migrate` transition (`Registry::write_compressed_slot_batch`) is the
    ///   production surface that upgrades it; and
    /// * **in-place persisted corruption** — a byte-tampered compressed row in an
    ///   already-manifested generation, used to prove the index's cryptographic
    ///   generation-root verification detects on-disk corruption (leave the
    ///   manifest untouched).
    ///
    /// This is NOT a lawful application write path. It is fail-closed by its own
    /// contract on `rows`, checked BEFORE any commit, so it can never publish a
    /// manifest or lifecycle record and therefore can never forge a manifested
    /// generation (that remains the lawful lifecycle guard's exclusive right):
    ///
    /// * every row targets exactly one slot;
    /// * the `Compression` CF carries tombstones ONLY (an existing manifest and/or
    ///   its append-only lifecycle records may be torn down only when no
    ///   membership proofs exist; a manifest put, lifecycle-record put, or proof
    ///   mutation is refused);
    /// * every quantized primary row is a compressed-tagged put, every raw row is a
    ///   put, and the primary and raw key sets are identical and non-empty;
    /// * no other column family and no primary/raw tombstone appears.
    ///
    /// Durable-only and seq-conditional, mirroring
    /// [`AsterVault::write_cf_batch_if_seq`]: it observes `expected_seq` under the
    /// durable commit lock and fails closed on divergence.
    pub fn commit_generation_injection_if_seq(
        &self,
        expected_seq: Seq,
        rows: impl IntoIterator<Item = (ColumnFamily, Vec<u8>, Vec<u8>)>,
    ) -> Result<Seq> {
        let rows = rows
            .into_iter()
            .map(|(cf, key, value)| encode::WriteRow { cf, key, value })
            .collect::<Vec<_>>();
        validate_generation_injection_shape(&rows)?;
        if self.durable.is_none() {
            return Err(CalyxError {
                code: "CALYX_ASTER_GENERATION_INJECTION_DURABLE_ONLY",
                message:
                    "generation-state injection requires a durable vault so the injected on-disk state persists across reopen"
                        .to_string(),
                remediation:
                    "open the target vault as a durable AsterVault before injecting a legacy or corrupted generation fixture",
            });
        }
        self.with_durable_commit_lock(|| {
            let current_seq = self.latest_seq();
            if current_seq != expected_seq {
                return Err(CalyxError {
                    code: "CALYX_ASTER_SEQUENCE_CONFLICT",
                    message: format!(
                        "generation-state injection expected seq {expected_seq}, current seq is {current_seq}; no rows were written"
                    ),
                    remediation:
                        "re-read the current snapshot, rebuild the injection batch, and retry with that exact sequence",
                });
            }
            let torn_down_slot = rows.iter().find_map(|row| {
                (row.cf == ColumnFamily::Compression && row.key.len() == 2)
                    .then(|| calyx_core::SlotId::new(u16::from_be_bytes([row.key[0], row.key[1]])))
            });
            if let Some(slot) = torn_down_slot {
                let live_proofs = self.scan_cf_range_at(
                    current_seq,
                    ColumnFamily::Compression,
                    &compression_membership_proof_prefix_range(slot),
                )?;
                if !live_proofs.is_empty() {
                    return Err(CalyxError {
                        code: generation_injection::CALYX_ASTER_GENERATION_INJECTION_INVALID,
                        message: format!(
                            "generation injection cannot tombstone slot {} manifest while {} membership-proof row(s) are live",
                            slot.get(),
                            live_proofs.len()
                        ),
                        remediation: "delete or reseal a proof-bearing generation through the registry lifecycle API; historical reconstruction cannot orphan membership proofs",
                    });
                }
            }
            self.commit_rows_locked_owned(rows, true)
        })
    }

    pub(crate) fn commit_rows_if_current_volatile(
        &self,
        expected_seq: Seq,
        mut rows: Vec<encode::WriteRow>,
    ) -> Result<Seq> {
        if self.durable.is_some() {
            return Err(CalyxError::aster_corrupt_shard(
                "volatile conditional commit called for a durable vault",
            ));
        }
        if rows.is_empty() {
            return self.rows.commit_batch_if_current(
                expected_seq,
                std::iter::empty::<(crate::cf::ColumnFamily, Vec<u8>, Vec<u8>)>(),
            );
        }
        self.ensure_writeable("conditional commit")?;
        let predicted = expected_seq.checked_add(1).ok_or_else(|| {
            CalyxError::aster_corrupt_shard("conditional commit sequence overflow")
        })?;
        let (cf, key, value) = crate::timetravel::entry_row(self.clock.now(), predicted);
        rows.push(encode::WriteRow { cf, key, value });
        self.rows.ensure_memtable_admission(
            rows.iter()
                .map(|row| (row.cf, row.key.as_slice(), row.value.as_slice())),
        )?;
        let committed = self.rows.commit_batch_if_current(
            expected_seq,
            rows.into_iter().map(|row| (row.cf, row.key, row.value)),
        )?;
        if committed != predicted {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "conditional commit predicted seq {predicted}, committed seq {committed}"
            )));
        }
        Ok(committed)
    }

    /// Ownership-taking group commit. Identical committed bytes to
    /// [`Self::commit_rows_locked`] — the batch plus its single appended
    /// time-index row, in the same order — but appends the time-index row into
    /// the caller's already-owned `Vec` in place instead of deep-cloning the
    /// whole batch just to grow it by one row (#444: `group_commit` is 88–89% of
    /// import write time and every full-batch copy in that path is linear in
    /// rows). Byte-equivalence is structural, not incidental: `commit_prepared_rows`
    /// observes the same slice contents either way.
    pub(crate) fn commit_rows_locked_owned(
        &self,
        mut rows: Vec<encode::WriteRow>,
        skip_compression_guard: bool,
    ) -> Result<Seq> {
        if rows.is_empty() {
            // Empty commit: do not advance the seq or stamp a time-index entry.
            return self.commit_prepared_rows_owned(rows, skip_compression_guard);
        }
        // Time-travel (PH72 T04): stamp this group-commit with one time-index
        // entry in the SAME batch as the data, so the (millis -> seqno) mapping
        // is atomic with the write — a crash can never leave a write without its
        // time mapping (A15). We hold the durable commit lock here, so the next
        // allocated seq is exactly current_seq()+1; we assert that against the
        // committed seq below and fail loud on any divergence (never silent).
        let predicted = self.rows.current_seq().saturating_add(1);
        let (cf, key, value) = crate::timetravel::entry_row(self.clock.now(), predicted);
        rows.push(encode::WriteRow { cf, key, value });
        let committed = self.commit_prepared_rows_owned(rows, skip_compression_guard)?;
        if committed != predicted {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "time-index seqno prediction {predicted} diverged from committed seq {committed}"
            )));
        }
        Ok(committed)
    }

    fn commit_prepared_rows_owned(
        &self,
        rows: Vec<encode::WriteRow>,
        skip_compression_guard: bool,
    ) -> Result<Seq> {
        let row_count = rows.len();
        if !rows.is_empty() {
            self.ensure_writeable("commit")?;
        }
        let admission = crate::commit_timing::start();
        self.rows.ensure_memtable_admission(
            rows.iter()
                .map(|row| (row.cf, row.key.as_slice(), row.value.as_slice())),
        )?;
        admission.stop("memtable_admission", row_count, 0);
        // Pre-WAL compression-generation admission (issue #562): reject an
        // unlawful generation mutation BEFORE it is appended to the WAL, so a
        // refused batch never becomes durable and the post-WAL reconciliation
        // arm below can never persist it. Runs under the durable commit lock, so
        // the visible state is stable through the subsequent commit.
        //
        // The one exception is legacy-generation reconstruction (see
        // [`AsterVault::commit_legacy_generation_reconstruction_if_seq`]): it
        // synthesizes the exact pre-#562 on-disk shape (compressed primary rows
        // with a raw sidecar and NO manifest) that a lawful pre-lifecycle binary
        // wrote and that WAL recovery replays unguarded. That ingress does its own
        // fail-closed legacy-shape validation before reaching here, so the
        // manifested-regime admission guard — which by design refuses to
        // synthesize an unmanifested compressed column — is skipped for it alone.
        if !skip_compression_guard {
            let compression_admission: Vec<(ColumnFamily, &[u8], &[u8])> = rows
                .iter()
                .map(|row| (row.cf, row.key.as_slice(), row.value.as_slice()))
                .collect();
            self.rows.validate_batch_admission(&compression_admission)?;
        }
        let Some(durable) = &self.durable else {
            let mvcc = crate::commit_timing::start();
            let seq = self.commit_owned_rows_to_mvcc(rows, skip_compression_guard);
            mvcc.stop("mvcc_commit_volatile", row_count, 0);
            return seq;
        };

        durable.ensure_disk_write_allowed(self.rows.resource_counters())?;
        let durable_seq = durable.append_batch(&rows)?;
        // Persist the durable ledger head anchor (the external witness) as part
        // of completing the WAL-backed ledger commit, BEFORE the crash-fsv
        // failpoint. #287 candidate 4 (fail closed when a non-empty durable
        // ledger has no head anchor) makes the anchor mandatory for reopen; the
        // owned crash-fsv failpoint (Cluster B) simulates a crash right after a
        // *completed* durable ledger commit, so the anchor must already be
        // durable at that point or a killed-mid-commit vault could never reopen
        // (regressing the crash-fsv recovery guarantee). A genuine crash in the
        // narrow window between the WAL fsync and this anchor fsync still fails
        // closed on reopen — exactly candidate 4's intended no-silent-truncation
        // behavior.
        let anchor_timer = crate::commit_timing::start();
        if let Some(anchor) = crate::ledger_head::newest_anchor_from_rows(&rows)? {
            crate::ledger_head::write_head_anchor(durable.root(), &anchor)?;
        }
        anchor_timer.stop("ledger_head_anchor", row_count, 0);
        #[cfg(any(test, feature = "crash-fsv"))]
        crash_fsv_after_wal_append(durable_seq)?;
        let mvcc = crate::commit_timing::start();
        let mvcc_result = self.commit_rows_to_mvcc(&rows, skip_compression_guard);
        mvcc.stop("mvcc_commit", row_count, 0);
        let mvcc_seq = match mvcc_result {
            Ok(seq) => seq,
            Err(mvcc_error) => {
                let restore = self.refresh_from_durable();
                let checkpoint = match &restore {
                    Ok(()) => self.flush_locked().map(|_| ()),
                    Err(error) => Err(CalyxError {
                        code: CALYX_DURABLE_COMMIT_RECONCILIATION_REQUIRED,
                        message: format!(
                            "checkpoint skipped because durable refresh failed first: [{}] {}",
                            error.code, error.message
                        ),
                        remediation: "reopen the vault to reconstruct the exact durable generation before attempting a checkpoint",
                    }),
                };
                return Err(post_wal_commit_error(
                    durable_seq,
                    &mvcc_error,
                    &restore,
                    &checkpoint,
                ));
            }
        };
        if mvcc_seq != durable_seq {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "durable WAL seq {durable_seq} diverged from MVCC seq {mvcc_seq}"
            )));
        }
        let stage = crate::commit_timing::start();
        durable.stage_checkpoint_batch_owned(durable_seq, rows)?;
        stage.stop("checkpoint_stage", row_count, 0);
        // Crash boundary (#276): the batch is now in the WAL and the MVCC
        // memtable and staged for checkpoint, but its checkpoint SST + manifest
        // advance have not happened. A crash here recovers via WAL replay with a
        // manifest still behind the committed seq.
        #[cfg(any(test, feature = "crash-fsv"))]
        crate::vault::failpoints::crash_fsv_after_mvcc_commit(mvcc_seq)?;
        Ok(mvcc_seq)
    }

    fn commit_owned_rows_to_mvcc(
        &self,
        rows: Vec<encode::WriteRow>,
        skip_compression_guard: bool,
    ) -> Result<Seq> {
        let batch = rows.into_iter().map(|row| (row.cf, row.key, row.value));
        if skip_compression_guard {
            self.rows.commit_batch_unguarded(batch)
        } else {
            self.rows.commit_batch(batch)
        }
    }

    fn commit_rows_to_mvcc(
        &self,
        rows: &[encode::WriteRow],
        skip_compression_guard: bool,
    ) -> Result<Seq> {
        let batch = rows
            .iter()
            .map(|row| (row.cf, row.key.as_slice(), row.value.as_slice()))
            .collect::<Vec<_>>();
        if skip_compression_guard {
            self.rows.commit_batch_unguarded_borrowed(&batch)
        } else {
            self.rows.commit_batch_borrowed(&batch)
        }
    }
}

fn post_wal_commit_error(
    durable_seq: Seq,
    mvcc_error: &CalyxError,
    restore: &Result<()>,
    checkpoint: &Result<()>,
) -> CalyxError {
    CalyxError {
        code: CALYX_DURABLE_COMMIT_RECONCILIATION_REQUIRED,
        message: format!(
            "WAL commit is durable but live MVCC/router application failed; wal_seq={durable_seq} \
             mvcc=error[{}]: {} restore={} checkpoint={}",
            mvcc_error.code,
            mvcc_error.message,
            reconciliation_outcome(restore),
            reconciliation_outcome(checkpoint),
        ),
        remediation: "treat wal_seq as durably committed; reconcile by idempotency/readback or reopen the vault before retrying",
    }
}

fn reconciliation_outcome(result: &Result<()>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(error) => format!("error[{}]: {}", error.code, error.message),
    }
}

#[cfg(any(test, feature = "crash-fsv"))]
fn crash_fsv_after_wal_append(seq: Seq) -> Result<()> {
    let Some(marker) = std::env::var_os("CALYX_ASTER_CRASH_FSV_AFTER_WAL_APPEND_MARKER") else {
        return Ok(());
    };
    std::fs::write(&marker, format!("{seq}\n")).map_err(|error| {
        CalyxError::disk_pressure(format!("write crash FSV marker {:?}: {error}", marker))
    })?;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
