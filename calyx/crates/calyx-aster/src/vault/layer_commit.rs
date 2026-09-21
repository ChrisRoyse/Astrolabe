use super::{AsterVault, LedgerBoundCommit, LedgerBoundRowDigest, durable, encode, ledger_hook};
use crate::cf::ColumnFamily;
use calyx_core::{CalyxError, Clock, CxId, LedgerRef, Result, Seq};
use calyx_ledger::{ActorId, EntryKind, SubjectId};

struct LedgerBoundWriteRequest {
    data_rows: Vec<encode::WriteRow>,
    expected_seq: Option<Seq>,
    kind: EntryKind,
    subject: SubjectId,
    payload: Vec<u8>,
    actor: ActorId,
    collect_row_digests: bool,
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    pub fn write_cf_batch_with_ledger_entry(
        &self,
        rows: impl IntoIterator<Item = (ColumnFamily, Vec<u8>, Vec<u8>)>,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<Seq> {
        let data_rows = rows
            .into_iter()
            .map(|(cf, key, value)| encode::WriteRow { cf, key, value })
            .collect::<Vec<_>>();
        if data_rows.is_empty() {
            return Ok(self.latest_seq());
        }

        self.write_cf_batch_with_ledger_entry_owned(
            LedgerBoundWriteRequest {
                data_rows,
                expected_seq: None,
                kind,
                subject,
                payload,
                actor,
                collect_row_digests: false,
            },
            |_, _| Ok((Vec::new(), ())),
        )
        .map(|(commit, ())| commit.seq)
    }

    /// Atomically writes one ledger-paired data batch and returns digest-only
    /// expectations for its exact post-bind data rows. Values are hashed after
    /// provenance binding and before their sole allocations move into durable
    /// checkpoint state.
    ///
    /// # Errors
    ///
    /// An empty data batch is invalid because it cannot produce a ledger-bound
    /// commit receipt. All ordinary group-commit failures are propagated.
    pub fn write_cf_batch_with_ledger_entry_with_row_digests(
        &self,
        rows: impl IntoIterator<Item = (ColumnFamily, Vec<u8>, Vec<u8>)>,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<LedgerBoundCommit> {
        let data_rows = rows
            .into_iter()
            .map(|(cf, key, value)| encode::WriteRow { cf, key, value })
            .collect::<Vec<_>>();
        if data_rows.is_empty() {
            return Err(CalyxError::ledger_group_commit_failed(
                "digest-bearing group commit requires at least one data row",
            ));
        }
        self.write_cf_batch_with_ledger_entry_owned(
            LedgerBoundWriteRequest {
                data_rows,
                expected_seq: None,
                kind,
                subject,
                payload,
                actor,
                collect_row_digests: true,
            },
            |_, _| Ok((Vec::new(), ())),
        )
        .map(|(commit, ())| commit)
    }

    /// Atomically writes one ledger-paired data batch plus rows derived from the
    /// exact provenance-bound source bytes.
    ///
    /// `derive_rows` runs under the durable commit lock after the ledger entry
    /// has been staged and after its exact [`LedgerRef`] has been attached to
    /// every caller-supplied Base and Graph row. The returned rows join the same
    /// digest plan and durable commit; no source generation is observable
    /// without its required derived state. The callback receives the staged
    /// [`encode::WriteRow`] values by reference.
    ///
    /// # Errors
    ///
    /// The operation refuses before durable commit if source binding, derived
    /// row construction, or the group commit fails. The combined batch must
    /// contain at least one data row.
    pub fn write_cf_batch_with_ledger_entry_with_row_digests_and_derived<T, F>(
        &self,
        rows: impl IntoIterator<Item = (ColumnFamily, Vec<u8>, Vec<u8>)>,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
        derive_rows: F,
    ) -> Result<(LedgerBoundCommit, T)>
    where
        F: FnOnce(
            &LedgerRef,
            &[encode::WriteRow],
        ) -> Result<(Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>, T)>,
    {
        let data_rows = rows
            .into_iter()
            .map(|(cf, key, value)| encode::WriteRow { cf, key, value })
            .collect::<Vec<_>>();
        self.write_cf_batch_with_ledger_entry_owned(
            LedgerBoundWriteRequest {
                data_rows,
                expected_seq: None,
                kind,
                subject,
                payload,
                actor,
                collect_row_digests: true,
            },
            derive_rows,
        )
    }

    /// Atomically writes one sequence-guarded, ledger-paired batch plus rows
    /// derived from the exact staged [`LedgerRef`].
    ///
    /// The sequence comparison runs under the same durable commit lock that
    /// stages the Ledger entry, invokes `derive_rows`, and commits the combined
    /// batch. A stale `expected_seq` therefore invokes no callback and writes no
    /// data, Ledger, or time-index row. This is the publication primitive for a
    /// current pointer whose bytes must name the Ledger row committed beside it;
    /// callers must never predict or repair that reference in a later commit.
    ///
    /// # Errors
    ///
    /// Returns `CALYX_ASTER_SEQUENCE_CONFLICT` before staging any row when the
    /// retained vault generation differs from `expected_seq`. All derived-row,
    /// ledger-staging, and group-commit failures propagate without a fallback.
    pub fn write_cf_batch_with_ledger_entry_with_row_digests_and_derived_if_seq<T, F>(
        &self,
        expected_seq: Seq,
        rows: impl IntoIterator<Item = (ColumnFamily, Vec<u8>, Vec<u8>)>,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
        derive_rows: F,
    ) -> Result<(LedgerBoundCommit, T)>
    where
        F: FnOnce(
            &LedgerRef,
            &[encode::WriteRow],
        ) -> Result<(Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>, T)>,
    {
        let data_rows = rows
            .into_iter()
            .map(|(cf, key, value)| encode::WriteRow { cf, key, value })
            .collect::<Vec<_>>();
        self.write_cf_batch_with_ledger_entry_owned(
            LedgerBoundWriteRequest {
                data_rows,
                expected_seq: Some(expected_seq),
                kind,
                subject,
                payload,
                actor,
                collect_row_digests: true,
            },
            derive_rows,
        )
    }

    fn write_cf_batch_with_ledger_entry_owned<T, F>(
        &self,
        request: LedgerBoundWriteRequest,
        derive_rows: F,
    ) -> Result<(LedgerBoundCommit, T)>
    where
        F: FnOnce(
            &LedgerRef,
            &[encode::WriteRow],
        ) -> Result<(Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>, T)>,
    {
        let LedgerBoundWriteRequest {
            mut data_rows,
            expected_seq,
            kind,
            subject,
            payload,
            actor,
            collect_row_digests,
        } = request;
        self.with_durable_commit_lock(|| {
            if let Some(expected_seq) = expected_seq {
                let current_seq = self.latest_seq();
                if current_seq != expected_seq {
                    return Err(CalyxError {
                        code: "CALYX_ASTER_SEQUENCE_CONFLICT",
                        message: format!(
                            "ledger-bound derived batch expected seq {expected_seq}, current seq is {current_seq}; no rows were staged or written"
                        ),
                        remediation: "re-read the current snapshot, rebuild every derived row from that exact generation, and retry once with its sequence",
                    });
                }
            }
            let mut derive_rows = Some(derive_rows);
            if let Some(hook) = &self.ledger_hook {
                let mut hook = ledger_hook::lock_hook(hook)?;
                let mut rows = Vec::with_capacity(data_rows.len() + 2);
                // Ledger-bind: stage the ledger entry and stamp its ref into every
                // Base/Graph provenance field (decode + re-encode per row) — the
                // #444 breakdown isolates this from the durable commit that follows.
                let bind = crate::commit_timing::start();
                let staged = ledger_hook::stage_entry_payload(
                    &hook, &mut rows, kind, subject, payload, actor,
                )?;
                let ledger_ref = staged_ledger_ref(&staged)?;
                attach_ledger_ref_to_rows(&mut data_rows, &ledger_ref)?;
                let (derived_rows, derived) = derive_rows
                    .take()
                    .ok_or_else(|| {
                        CalyxError::ledger_group_commit_failed(
                            "ledger-bound derived-row callback was already consumed",
                        )
                    })?(&ledger_ref, &data_rows)?;
                append_derived_rows(&mut data_rows, derived_rows, &ledger_ref)?;
                if data_rows.is_empty() {
                    return Err(CalyxError::ledger_group_commit_failed(
                        "ledger-bound group commit requires at least one source or derived data row",
                    ));
                }
                let data_row_count = data_rows.len();
                let data_row_digests = if collect_row_digests {
                    digest_rows(&data_rows)
                } else {
                    Vec::new()
                };
                rows.extend(data_rows);
                bind.stop("ledger_bind", data_row_count, 0);
                // Ownership handed straight to the commit path: no full-batch copy
                // to append the time-index row (#444 lever).
                let seq = self.commit_rows_locked_owned(rows, false)?;
                ledger_hook::commit_staged(&mut hook, &staged).map_err(|error| {
                    self.reconcile_post_commit_ledger_hook_failure(seq, &error)
                })?;
                return Ok((
                    LedgerBoundCommit {
                        seq,
                        ledger_ref,
                        data_row_digests,
                    },
                    derived,
                ));
            }

            let mut transient = self.transient_ledger_hook()?;
            let hook = transient
                .get_mut()
                .map_err(|_| CalyxError::ledger_group_commit_failed("transient hook poisoned"))?;
            let mut rows = Vec::with_capacity(data_rows.len() + 1);
            let bind = crate::commit_timing::start();
            let staged =
                ledger_hook::stage_entry_payload(hook, &mut rows, kind, subject, payload, actor)?;
            let ledger_ref = staged_ledger_ref(&staged)?;
            attach_ledger_ref_to_rows(&mut data_rows, &ledger_ref)?;
            let (derived_rows, derived) = derive_rows
                .take()
                .ok_or_else(|| {
                    CalyxError::ledger_group_commit_failed(
                        "ledger-bound derived-row callback was already consumed",
                    )
                })?(&ledger_ref, &data_rows)?;
            append_derived_rows(&mut data_rows, derived_rows, &ledger_ref)?;
            if data_rows.is_empty() {
                return Err(CalyxError::ledger_group_commit_failed(
                    "ledger-bound group commit requires at least one source or derived data row",
                ));
            }
            let data_row_count = data_rows.len();
            let data_row_digests = if collect_row_digests {
                digest_rows(&data_rows)
            } else {
                Vec::new()
            };
            rows.extend(data_rows);
            bind.stop("ledger_bind", data_row_count, 0);
            let seq = self.commit_rows_locked_owned(rows, false)?;
            ledger_hook::commit_staged(hook, &staged)
                .map_err(|error| self.reconcile_post_commit_ledger_hook_failure(seq, &error))?;
            Ok((
                LedgerBoundCommit {
                    seq,
                    ledger_ref,
                    data_row_digests,
                },
                derived,
            ))
        })
    }

    fn transient_ledger_hook(&self) -> Result<ledger_hook::AsterLedgerHook<C>> {
        let ledger_rows = self
            .scan_cf_at(self.latest_seq(), ColumnFamily::Ledger)?
            .into_iter()
            .map(|(key, value)| encode::WriteRow {
                cf: ColumnFamily::Ledger,
                key,
                value,
            })
            .collect::<Vec<_>>();
        let batches = if ledger_rows.is_empty() {
            Vec::new()
        } else {
            vec![durable::RecoveredBatch {
                seq: self.latest_seq(),
                rows: ledger_rows,
            }]
        };
        ledger_hook::recover_hook(
            &durable::RecoveredBatches {
                batches,
                last_recovered_seq: self.latest_seq(),
                manifest_seq: 0,
                wal_replay_floor_seq: 0,
                derived_content_floor_seq: 0,
                cf_content_generation_floor_seq: 0,
                cf_content_generations: if self.latest_seq() == 0 {
                    std::collections::BTreeMap::new()
                } else {
                    std::collections::BTreeMap::from([(ColumnFamily::Ledger, self.latest_seq())])
                },
                torn_tail: None,
                temporal_policy: None,
                dedup_policy: None,
                retention_horizon: crate::timetravel::RetentionHorizon::default(),
                mode: durable::RecoveryMode::FullMvcc,
            },
            None,
            std::sync::Arc::clone(&self.clock),
        )
    }
}

fn append_derived_rows(
    data_rows: &mut Vec<encode::WriteRow>,
    derived_rows: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>,
    ledger_ref: &LedgerRef,
) -> Result<()> {
    let mut derived_rows = derived_rows
        .into_iter()
        .map(|(cf, key, value)| encode::WriteRow { cf, key, value })
        .collect::<Vec<_>>();
    attach_ledger_ref_to_rows(&mut derived_rows, ledger_ref)?;
    data_rows.extend(derived_rows);
    Ok(())
}

pub(super) fn digest_rows(rows: &[encode::WriteRow]) -> Vec<LedgerBoundRowDigest> {
    rows.iter()
        .map(|row| LedgerBoundRowDigest {
            cf: row.cf,
            key: row.key.clone(),
            value_blake3: *blake3::hash(&row.value).as_bytes(),
            tombstoned: crate::mvcc::is_tombstone_value(&row.value),
        })
        .collect()
}

fn staged_ledger_ref(staged: &[calyx_ledger::StagedLedgerRow]) -> Result<calyx_core::LedgerRef> {
    staged
        .first()
        .map(calyx_ledger::StagedLedgerRow::ledger_ref)
        .ok_or_else(|| CalyxError::ledger_group_commit_failed("no staged ledger rows"))
}

pub(super) fn attach_ledger_ref_to_rows(
    rows: &mut [encode::WriteRow],
    ledger_ref: &LedgerRef,
) -> Result<()> {
    for row in rows.iter_mut().filter(|row| row.cf == ColumnFamily::Base) {
        // Stamp the ledger ref through the lossless BaseRecord so the immutable
        // per-slot BLAKE3 hashes staged by the caller survive this rewrite
        // byte-for-byte; a decode -> encode_constellation_base round-trip would
        // replace them with placeholder-slot hashes.
        let key_cx_id = base_row_cx_id(&row.key)?;
        let mut record = encode::BaseRecord::decode_for_key(key_cx_id, &row.value)?;
        record.set_provenance(ledger_ref.clone());
        row.value = record.encode()?;
    }
    for row in rows.iter_mut().filter(|row| row.cf == ColumnFamily::Graph) {
        attach_ledger_ref_to_graph_json_row(row, ledger_ref)?;
    }
    Ok(())
}

fn base_row_cx_id(key: &[u8]) -> Result<CxId> {
    let bytes: [u8; 16] = key.try_into().map_err(|_| {
        CalyxError::aster_corrupt_shard(format!(
            "Base CF key is {} bytes, not a 16-byte CxId",
            key.len()
        ))
    })?;
    Ok(CxId::from_bytes(bytes))
}

fn attach_ledger_ref_to_graph_json_row(
    row: &mut encode::WriteRow,
    ledger_ref: &LedgerRef,
) -> Result<()> {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&row.value) else {
        return Ok(());
    };
    let Some(object) = value.as_object_mut() else {
        return Ok(());
    };
    if !object.contains_key("provenance") {
        return Ok(());
    }
    object.insert(
        "provenance".to_string(),
        serde_json::to_value(ledger_ref).map_err(|error| {
            CalyxError::aster_corrupt_shard(format!("encode graph provenance: {error}"))
        })?,
    );
    row.value = serde_json::to_vec(&value)
        .map_err(|error| CalyxError::aster_corrupt_shard(format!("encode graph row: {error}")))?;
    Ok(())
}
