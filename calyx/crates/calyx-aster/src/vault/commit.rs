mod generation_injection;

use super::{AsterVault, durable, encode, ledger_hook};
use crate::cf::{CfRouter, ColumnFamily, compression_membership_proof_prefix_range};
use crate::mvcc::LatestRouterRecoveryState;
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
    /// Explicitly refreshes this handle from the latest durable generation
    /// without creating a commit.
    ///
    /// This is the named, commit-free cross-process synchronization boundary:
    /// it acquires the durable commit lock, replays a newer durable tip through
    /// the handle's configured recovery mode, mutates the handle's router,
    /// generation, Ledger-hook, retention, and pending-checkpoint state, and
    /// returns the observed latest sequence. Writable recovery may also
    /// truncate a detected torn WAL tail; it never fabricates a compensating
    /// commit. Callers must hoist it outside row/item loops. With `W` retained
    /// WAL bytes, `S` immutable SST bytes, `K` SST index keys/routes, `R`
    /// recovered tail rows, and `H` bounded Ledger hydration work, the existing
    /// latest-router recovery costs `O(W + S + K log K + R log R + H)` time and
    /// `O(K + R + differing-tail bytes + H)` memory. Production values remain
    /// unmeasured; a manual fixture is not their bound (PC-04, PC-18, PC-41,
    /// PC-43). Cost-hypothesis owner: #1147; expires at the first
    /// production-sized durable-refresh receipt.
    pub fn refresh_latest_from_durable(&self) -> Result<Seq> {
        self.ensure_writeable("durable latest-generation refresh")?;
        self.rows.ensure_no_terminal_durable_fault()?;
        let Some(durable) = &self.durable else {
            return Err(CalyxError {
                code: "CALYX_ASTER_DURABLE_REFRESH_REQUIRED",
                message: "latest-generation refresh requires a durable Aster vault handle"
                    .to_string(),
                remediation: "open the exact durable vault write-capable before requesting a cross-process latest-generation refresh",
            });
        };
        let _commit_guard = crate::file_lock::FileLockGuard::acquire(&durable.commit_lock_path())?;
        self.refresh_from_durable()?;
        Ok(self.latest_seq())
    }

    pub(crate) fn with_durable_commit_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let Some(durable) = &self.durable else {
            return f();
        };
        // Automatic admission refresh must never erase a terminal post-WAL
        // fault. Only the explicitly named refresh API may attempt recovery;
        // ordinary reads/writes keep returning the original exact diagnostic.
        self.rows.ensure_no_terminal_durable_fault()?;
        let _commit_guard = crate::file_lock::FileLockGuard::acquire(&durable.commit_lock_path())?;
        if durable.durable_tip_seq()? != self.latest_seq()
            || durable.manifest_seq_on_disk()? != durable.observed_manifest_seq()
        {
            self.refresh_from_durable()?;
        }
        let durable_tip = durable.durable_tip_seq()?;
        if durable_tip != self.latest_seq() {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "durable commit admission could not reconcile WAL tip {durable_tip} with live sequence {}; no WAL bytes were appended",
                self.latest_seq()
            )));
        }
        f()
    }

    pub(crate) fn with_recurrence_write_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.rows.ensure_no_terminal_durable_fault()?;
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
        if let Some(durable) = &self.durable {
            if durable.durable_tip_seq()? != self.latest_seq()
                || durable.manifest_seq_on_disk()? != durable.observed_manifest_seq()
            {
                let _commit_guard =
                    crate::file_lock::FileLockGuard::acquire(&durable.commit_lock_path())?;
                if durable.durable_tip_seq()? != self.latest_seq()
                    || durable.manifest_seq_on_disk()? != durable.observed_manifest_seq()
                {
                    self.refresh_from_durable()?;
                }
                let durable_tip = durable.durable_tip_seq()?;
                if durable_tip != self.latest_seq() {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "recurrence write admission could not reconcile WAL tip {durable_tip} with live sequence {}; no recurrence rows were evaluated or written",
                        self.latest_seq()
                    )));
                }
            }
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
        let recovered_derived_seq = recovered.batches.iter().fold(
            recovered.derived_content_floor_seq,
            |derived_seq, batch| {
                if batch
                    .rows
                    .iter()
                    .any(|row| row.cf.feeds_derived_search_content())
                {
                    derived_seq.max(batch.seq)
                } else {
                    derived_seq
                }
            },
        );
        let latest_candidate = if mode == durable::RecoveryMode::LatestRouter {
            let memtable_byte_cap = self.rows.latest_router_memtable_byte_cap()?;
            let mut router = match durable.selected_cfs() {
                Some(selected) => CfRouter::open_selected_cfs(
                    durable.root(),
                    memtable_byte_cap,
                    selected.iter().copied(),
                )?,
                None => CfRouter::open_with_tiering_latest(
                    durable.root(),
                    memtable_byte_cap,
                    durable.tiering_policy().cloned(),
                )?,
            };
            router.replay_latest_rows(recovered.batches.iter().flat_map(|batch| {
                batch.rows.iter().filter_map(move |row| {
                    durable
                        .selected_cfs()
                        .is_none_or(|selected| selected.contains(&row.cf))
                        .then_some((batch.seq, row.cf, row.key.as_slice(), row.value.as_slice()))
                })
            }))?;
            Some(router)
        } else {
            None
        };
        if let Some(candidate) = latest_candidate.as_ref() {
            let expected_selected = durable.selected_cfs().map(|selected| {
                selected
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
            });
            if candidate.selected_cfs() != expected_selected.as_ref() {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "latest-router refresh candidate capability differs from retained writer scope: candidate={:?}, expected={expected_selected:?}",
                    candidate.selected_cfs()
                )));
            }
        }
        let prepared_hook = if self.ledger_hook.is_some() {
            Some(ledger_hook::prepare_hook_refresh(
                durable.root(),
                &recovered,
                durable.ledger_checkpoint(),
                durable.tiering_policy(),
                std::sync::Arc::clone(&self.clock),
            )?)
        } else {
            None
        };
        durable.stage_recovered_wal_batches(
            recovered
                .batches
                .iter()
                .filter(|batch| batch.seq > recovered.wal_replay_floor_seq)
                .map(|batch| (batch.seq, batch.rows.clone()))
                .collect(),
        )?;
        let mut hook_guard = self
            .ledger_hook
            .as_ref()
            .map(ledger_hook::lock_hook)
            .transpose()?;
        let mut retention_guard = self
            .retention_horizon
            .lock()
            .map_err(|_| CalyxError::backpressure("retention horizon lock poisoned"))?;
        // WAL-tail batches from a foreign writer have no durable-batch SSTs
        // yet; stage them here so this handle's next checkpoint flush cannot
        // advance the manifest past them if that writer dies (issue #1132).
        let publication: Result<()> = (|| match mode {
            durable::RecoveryMode::FullMvcc => {
                let future_batches = recovered
                    .batches
                    .iter()
                    .filter(|batch| batch.seq > current)
                    .map(|batch| {
                        let rows = batch
                            .rows
                            .iter()
                            .filter(|row| {
                                durable
                                    .selected_cfs()
                                    .is_none_or(|selected| selected.contains(&row.cf))
                            })
                            .map(|row| (row.cf, row.key.clone(), row.value.clone()))
                            .collect();
                        (batch.seq, rows)
                    })
                    .collect();
                self.rows.publish_recovered_full_mvcc_state(
                    current,
                    recovered.last_recovered_seq,
                    recovered_derived_seq,
                    recovered.cf_content_generation_floor_seq,
                    recovered.cf_content_generations.clone(),
                    future_batches,
                )
            }
            durable::RecoveryMode::LatestRouter => {
                let candidate = latest_candidate.ok_or_else(|| {
                    CalyxError::aster_corrupt_shard(
                        "latest-router refresh completed recovery without a candidate router",
                    )
                })?;
                self.rows.replace_latest_recovered_router(
                    LatestRouterRecoveryState {
                        expected_current: current,
                        recovered_seq: recovered.last_recovered_seq,
                        content_generation_floor_seq: recovered.cf_content_generation_floor_seq,
                        content_generations: recovered.cf_content_generations.clone(),
                        derived_content_floor_seq: recovered.derived_content_floor_seq,
                    },
                    recovered
                        .batches
                        .iter()
                        .flat_map(|batch| batch.rows.iter().map(move |row| (batch.seq, row.cf))),
                    candidate,
                )
            }
        })();
        if let Err(error) = publication {
            let terminal = refresh_publication_error(&error);
            self.rows
                .latch_terminal_durable_fault_requires_reopen(terminal.clone());
            return Err(terminal);
        }
        let generation_readback = (|| {
            let durable_tip = durable.durable_tip_seq()?;
            let manifest_seq = durable.manifest_seq_on_disk()?;
            let live_seq = self.latest_seq();
            if durable_tip != recovered.last_recovered_seq
                || live_seq != recovered.last_recovered_seq
                || manifest_seq != recovered.manifest_seq
            {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "durable refresh generation readback diverged: recovered_seq={}, live_seq={live_seq}, durable_tip={durable_tip}, recovered_manifest_seq={}, disk_manifest_seq={manifest_seq}",
                    recovered.last_recovered_seq, recovered.manifest_seq
                )));
            }
            Ok(())
        })();
        if let Err(error) = generation_readback {
            let terminal = refresh_publication_error(&error);
            self.rows
                .latch_terminal_durable_fault_requires_reopen(terminal.clone());
            return Err(terminal);
        }
        if let (Some(guard), Some(replacement)) = (hook_guard.as_mut(), prepared_hook) {
            **guard = replacement;
        }
        *retention_guard = recovered.retention_horizon.clone();
        durable.advance_derived_content_watermark_to_at_least(recovered_derived_seq);
        durable.observe_manifest_seq(recovered.manifest_seq);
        Ok(())
    }

    pub(super) fn commit_rows(&self, rows: &[encode::WriteRow]) -> Result<Seq> {
        self.with_durable_commit_lock(|| self.commit_rows_locked(rows))
    }

    pub(crate) fn commit_rows_if_seq(
        &self,
        expected_seq: Seq,
        rows: Vec<encode::WriteRow>,
        operation: &'static str,
    ) -> Result<Seq> {
        if self.durable.is_none() {
            return self.commit_rows_if_current_volatile(expected_seq, rows);
        }
        self.with_durable_commit_lock(|| {
            let current_seq = self.latest_seq();
            if current_seq != expected_seq {
                return Err(CalyxError {
                    code: "CALYX_ASTER_SEQUENCE_CONFLICT",
                    message: format!(
                        "{operation} evaluated seq {expected_seq}, but the current seq is {current_seq}; no rows were written"
                    ),
                    remediation:
                        "re-read the current snapshot and explicitly submit a newly derived operation; the vault does not retry stale derivations",
                });
            }
            if rows.is_empty() {
                return Ok(current_seq);
            }
            self.commit_rows_locked_owned(rows, false)
        })
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
        let predicted = self.rows.current_seq().checked_add(1).ok_or_else(|| {
            CalyxError::aster_corrupt_shard(
                "vault sequence exhausted at u64::MAX before time-index staging",
            )
        })?;
        let (cf, key, value) = crate::timetravel::entry_row(self.clock.now(), predicted);
        rows.push(encode::WriteRow { cf, key, value });
        let committed = self.commit_prepared_rows_owned(rows, skip_compression_guard)?;
        if committed != predicted {
            let mismatch = CalyxError::aster_corrupt_shard(format!(
                "time-index seqno prediction {predicted} diverged from committed seq {committed}"
            ));
            if self.durable.is_some() {
                return Err(self.reconcile_post_wal_failure(
                    committed,
                    "time_index_sequence_readback",
                    &mismatch,
                ));
            }
            return Err(mismatch);
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
        let anchor_result = (|| {
            if let Some(anchor) = crate::ledger_head::newest_anchor_from_rows(&rows)? {
                crate::ledger_head::write_head_anchor(durable.root(), &anchor)?;
            }
            Ok(())
        })();
        anchor_timer.stop("ledger_head_anchor", row_count, 0);
        if let Err(anchor_error) = anchor_result {
            return Err(self.reconcile_post_wal_failure(
                durable_seq,
                "ledger_head_anchor",
                &anchor_error,
            ));
        }
        #[cfg(any(test, feature = "crash-fsv"))]
        if let Err(error) = crash_fsv_after_wal_append(durable_seq) {
            return Err(self.reconcile_post_wal_failure(
                durable_seq,
                "crash_fsv_after_wal_append",
                &error,
            ));
        }
        let mvcc = crate::commit_timing::start();
        let mvcc_result = self.commit_rows_to_mvcc(&rows, skip_compression_guard);
        mvcc.stop("mvcc_commit", row_count, 0);
        let mvcc_seq = match mvcc_result {
            Ok(seq) => seq,
            Err(mvcc_error) => {
                return Err(self.reconcile_post_wal_failure(
                    durable_seq,
                    "mvcc_apply",
                    &mvcc_error,
                ));
            }
        };
        if mvcc_seq != durable_seq {
            let mismatch = CalyxError::aster_corrupt_shard(format!(
                "durable WAL seq {durable_seq} diverged from MVCC seq {mvcc_seq}"
            ));
            return Err(self.reconcile_post_wal_failure(
                durable_seq,
                "mvcc_sequence_readback",
                &mismatch,
            ));
        }
        let stage = crate::commit_timing::start();
        let stage_result = durable.stage_checkpoint_batch_owned(durable_seq, rows);
        stage.stop("checkpoint_stage", row_count, 0);
        if let Err(stage_error) = stage_result {
            return Err(self.reconcile_post_wal_failure(
                durable_seq,
                "checkpoint_stage",
                &stage_error,
            ));
        }
        // Crash boundary (#276): the batch is now in the WAL and the MVCC
        // memtable and staged for checkpoint, but its checkpoint SST + manifest
        // advance have not happened. A crash here recovers via WAL replay with a
        // manifest still behind the committed seq.
        #[cfg(any(test, feature = "crash-fsv"))]
        if let Err(error) = crate::vault::failpoints::crash_fsv_after_mvcc_commit(mvcc_seq) {
            return Err(self.reconcile_post_wal_failure(
                durable_seq,
                "crash_fsv_after_mvcc_commit",
                &error,
            ));
        }
        Ok(mvcc_seq)
    }

    fn reconcile_post_wal_failure(
        &self,
        durable_seq: Seq,
        failed_stage: &str,
        stage_error: &CalyxError,
    ) -> CalyxError {
        // Every core commit entrypoint may retain its Ledger-hook guard while
        // this boundary executes. Attempting in-place refresh would reacquire
        // that same mutex and self-deadlock. More importantly, a post-WAL
        // failure means the live router/MVCC/witness/checkpoint tuple is no
        // longer one provable generation. Preserve it and require a fresh open.
        let restore = Err(CalyxError {
            code: CALYX_DURABLE_COMMIT_RECONCILIATION_REQUIRED,
            message: format!(
                "automatic refresh refused after {failed_stage}: mandatory post-WAL state cannot be proven identical to the durable WAL generation while caller-owned commit guards remain retained"
            ),
            remediation: "discard this handle and reopen the vault so only the exact durable WAL generation is reconstructed",
        });
        let checkpoint = Err(CalyxError {
            code: CALYX_DURABLE_COMMIT_RECONCILIATION_REQUIRED,
            message: "checkpoint skipped because a fresh durable reopen is required first"
                .to_string(),
            remediation: "reopen the vault to reconstruct the exact durable generation before attempting a checkpoint",
        });
        let terminal = post_wal_commit_error(
            durable_seq,
            failed_stage,
            stage_error,
            &restore,
            &checkpoint,
        );
        self.rows
            .latch_terminal_durable_fault_requires_reopen(terminal.clone());
        terminal
    }

    /// Classifies an in-memory Ledger-hook finalization failure that occurred
    /// after the exact Ledger rows were already committed with the data batch.
    /// Callers invoke this while retaining the failed hook guard, so attempting
    /// an in-place hook refresh here would self-deadlock. The handle is therefore
    /// latched terminal and a fresh durable reopen is required to reconstruct
    /// the hook from the committed physical rows. A volatile handle has no such
    /// reconstruction source and must be discarded. In either case the caller
    /// receives the failure instead of a false success.
    pub(crate) fn reconcile_post_commit_ledger_hook_failure(
        &self,
        committed_seq: Seq,
        error: &CalyxError,
    ) -> CalyxError {
        let durable = self.durable.is_some();
        let terminal = CalyxError {
            code: CALYX_DURABLE_COMMIT_RECONCILIATION_REQUIRED,
            message: format!(
                "commit {committed_seq} reached {} but its in-memory Ledger hook failed to finalize: [{}] {}",
                if durable {
                    "durable WAL/MVCC"
                } else {
                    "volatile MVCC"
                },
                error.code,
                error.message
            ),
            remediation: if durable {
                "discard this handle and reopen the vault so the Ledger hook is reconstructed from the exact committed physical Ledger rows"
            } else {
                "discard this volatile vault handle; no durable source exists from which to reconstruct the failed Ledger hook"
            },
        };
        self.rows
            .latch_terminal_durable_fault_requires_reopen(terminal.clone());
        terminal
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
    failed_stage: &str,
    stage_error: &CalyxError,
    restore: &Result<()>,
    checkpoint: &Result<()>,
) -> CalyxError {
    CalyxError {
        code: CALYX_DURABLE_COMMIT_RECONCILIATION_REQUIRED,
        message: format!(
            "WAL commit is durable but post-WAL stage {failed_stage} failed; wal_seq={durable_seq} \
             stage_error=error[{}]: {} restore={} checkpoint={}",
            stage_error.code,
            stage_error.message,
            reconciliation_outcome(restore),
            reconciliation_outcome(checkpoint),
        ),
        remediation: "treat wal_seq as durably committed; reconcile by idempotency/readback or reopen the vault before retrying",
    }
}

fn refresh_publication_error(error: &CalyxError) -> CalyxError {
    CalyxError {
        code: CALYX_DURABLE_COMMIT_RECONCILIATION_REQUIRED,
        message: format!(
            "durable refresh reconstructed source bytes but could not publish one coherent live generation: underlying=error[{}]: {}",
            error.code, error.message
        ),
        remediation: "discard this terminally faulted handle and reopen the vault; do not read or write through the partial live generation",
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
