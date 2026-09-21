use std::collections::{BTreeMap, BTreeSet};

use super::{AsterVault, anchor_merge, encode, ledger_append, ledger_hook, ledger_stub};
use crate::cf::{ColumnFamily, base_key, ledger_key};
use crate::media_artifact::{
    DerivedMediaArtifactDraft, DerivedMediaArtifactRecord, derived_media_artifact_write_rows,
    ensure_no_artifact_collision,
};
use crate::mvcc::{Snapshot, is_tombstone_value};
use calyx_core::{
    Anchor, AnchorKind, CalyxError, Clock, Constellation, CxId, LedgerRef, Result, Seq, VaultStore,
};
use calyx_ledger::{
    ActorId, EntryKind, LedgerEntryInput, PayloadBuilder, RedactionPolicy, SubjectId,
};
use serde_json::json;

const BATCH_ACTOR: &str = "calyx-aster-batch-ingest";

#[derive(Clone, Debug)]
pub struct MediaArtifactIngestCommit {
    pub ids: Vec<CxId>,
    pub artifact: DerivedMediaArtifactRecord,
    /// Snapshot containing the artifact and every returned Base record.
    pub readback_seq: Seq,
    /// Exact final Base records for CxIds created by this commit.
    pub new_records: Vec<encode::BaseRecord>,
}

/// Receipt for one atomic batch containing freshly created constellations and
/// lossless anchor merges into existing Base rows.
#[derive(Debug)]
pub struct BatchIngestWithExistingMergeCommit {
    /// Snapshot containing every returned final Base record.
    pub readback_seq: Seq,
    /// Assigned group-commit sequence, or `None` when the request contained no
    /// new constellation and every existing anchor was already materialized.
    pub commit_seq: Option<Seq>,
    /// Exact final Base records for newly created CxIds, in first-occurrence
    /// order after duplicate-new rows have been merged.
    pub new_records: Vec<encode::BaseRecord>,
    /// Exact final records and actually added anchors for existing CxIds, in
    /// request order.
    pub existing_results: Vec<anchor_merge::ExistingBaseAnchorMergeResult>,
    /// Marker-ledger refs selected for anchors actually created by this commit,
    /// in caller draft order.
    pub marker_ledger_receipts: Vec<AnchorMarkerLedgerReceipt>,
}

/// One ordered candidate marker Ledger entry for an incoming anchor.
#[derive(Clone, Debug)]
pub struct AnchorMarkerLedgerDraft {
    /// CxId whose incoming anchor may require this marker.
    pub cx_id: CxId,
    /// Exact proposed observation; `observed_at` does not affect replay
    /// compatibility, but the first selected observation is persisted exactly.
    pub anchor: Anchor,
    /// Logical Ledger entry staged if and only if the anchor is created.
    pub entry: LedgerEntryInput,
}

/// Exact marker Ledger receipt for an anchor created by the atomic batch.
#[derive(Clone, Debug)]
pub struct AnchorMarkerLedgerReceipt {
    /// CxId whose anchor was created.
    pub cx_id: CxId,
    /// Exact Anchor written to Base and Anchors CF.
    pub anchor: Anchor,
    /// Exact logical entry staged for this marker.
    pub entry: LedgerEntryInput,
    /// Persisted Ledger identity for `entry`.
    pub ledger_ref: LedgerRef,
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    pub fn put_batch<I>(&self, constellations: I) -> Result<Vec<CxId>>
    where
        I: IntoIterator<Item = Constellation>,
    {
        self.put_batch_with_input_rows(constellations, Vec::new())
    }

    /// [`AsterVault::put_batch`] plus content-addressed input-store rows (#446)
    /// committed in the SAME atomic group commit as the batch's base records,
    /// so no constellation of the batch is durable without its retained input
    /// bytes. `input_rows` come from
    /// [`crate::vault::input_store::encode_input_rows`]; rows addressing inputs
    /// whose constellations dedup against existing records are harmless
    /// re-writes of byte-identical content-addressed rows. If the entire batch
    /// dedups (no accepted constellation), the input rows are not committed —
    /// the first ingest of each input already committed identical rows.
    pub fn put_batch_with_input_rows<I>(
        &self,
        constellations: I,
        input_rows: Vec<encode::WriteRow>,
    ) -> Result<Vec<CxId>>
    where
        I: IntoIterator<Item = Constellation>,
    {
        let input = constellations.into_iter().collect::<Vec<_>>();
        if input.is_empty() {
            return Ok(Vec::new());
        }
        self.with_durable_commit_lock(|| self.put_batch_locked(input, input_rows))
    }

    /// Atomically creates a batch of new constellations and merges anchors into
    /// existing lossless Base records.
    ///
    /// New CxIds must still be absent and every existing request must still
    /// match its canonical Base identity when the durable commit lock is held.
    /// All Base, Anchors, slot, input-store, and ingest-ledger rows are staged
    /// only after the complete request validates, then published in one group
    /// commit. Duplicate-new rows are merged in first-occurrence order.
    pub fn put_batch_with_input_rows_and_existing_base_anchor_merges<I>(
        &self,
        constellations: I,
        input_rows: Vec<encode::WriteRow>,
        existing_requests: Vec<anchor_merge::ExistingBaseAnchorMerge>,
    ) -> Result<BatchIngestWithExistingMergeCommit>
    where
        I: IntoIterator<Item = Constellation>,
    {
        self.put_batch_with_input_rows_existing_anchor_merges_and_optional_marker_ledgers(
            constellations.into_iter().collect(),
            input_rows,
            existing_requests,
            None,
        )
    }

    /// Extends the atomic mixed batch with ordered candidate marker Ledger
    /// entries. Only drafts whose exact anchor is actually created are staged;
    /// already-materialized proposals produce no duplicate marker.
    pub fn put_batch_with_input_rows_existing_anchor_merges_and_marker_ledgers<I>(
        &self,
        constellations: I,
        input_rows: Vec<encode::WriteRow>,
        existing_requests: Vec<anchor_merge::ExistingBaseAnchorMerge>,
        marker_drafts: Vec<AnchorMarkerLedgerDraft>,
    ) -> Result<BatchIngestWithExistingMergeCommit>
    where
        I: IntoIterator<Item = Constellation>,
    {
        self.put_batch_with_input_rows_existing_anchor_merges_and_optional_marker_ledgers(
            constellations.into_iter().collect(),
            input_rows,
            existing_requests,
            Some(marker_drafts),
        )
    }

    fn put_batch_with_input_rows_existing_anchor_merges_and_optional_marker_ledgers(
        &self,
        input: Vec<Constellation>,
        input_rows: Vec<encode::WriteRow>,
        existing_requests: Vec<anchor_merge::ExistingBaseAnchorMerge>,
        marker_drafts: Option<Vec<AnchorMarkerLedgerDraft>>,
    ) -> Result<BatchIngestWithExistingMergeCommit> {
        if input.is_empty() && existing_requests.is_empty() {
            if !input_rows.is_empty() {
                return Err(CalyxError::aster_corrupt_shard(
                    "atomic mixed batch supplied input-store rows without a new constellation",
                ));
            }
            if marker_drafts
                .as_ref()
                .is_some_and(|drafts| !drafts.is_empty())
            {
                return Err(CalyxError::aster_corrupt_shard(
                    "atomic mixed batch supplied anchor marker drafts without an anchor request",
                ));
            }
            return Ok(BatchIngestWithExistingMergeCommit {
                readback_seq: self.snapshot(),
                commit_seq: None,
                new_records: Vec::new(),
                existing_results: Vec::new(),
                marker_ledger_receipts: Vec::new(),
            });
        }
        self.with_durable_commit_lock(|| {
            let latest = self.snapshot();
            let snapshot = self.snapshot_handle(latest);
            let existing_ids = existing_requests
                .iter()
                .map(|request| request.expected.cx_id())
                .collect::<BTreeSet<_>>();
            let mut accepted_indexes = BTreeMap::<Vec<u8>, usize>::new();
            let mut accepted = Vec::<Constellation>::new();
            for constellation in input {
                let pinned = snapshot.snapshot();
                self.rows.record_reader_progress(pinned, &self.clock);
                if constellation.vault_id != self.vault_id {
                    return Err(CalyxError::vault_access_denied(
                        "constellation belongs to another vault",
                    ));
                }
                constellation.validate_schema()?;
                let id = constellation.cx_id;
                if existing_ids.contains(&id) {
                    return Err(CalyxError::stale_derived(format!(
                        "atomic mixed batch classified cx {id} as both new and existing"
                    )));
                }
                let key = base_key(id);
                if let Some(index) = accepted_indexes.get(&key).copied() {
                    anchor_merge::merge_duplicate_anchors(
                        &mut accepted[index],
                        &constellation,
                    )?;
                    continue;
                }
                accepted_indexes.insert(key, accepted.len());
                accepted.push(constellation);
            }
            let accepted_ids = accepted
                .iter()
                .map(|constellation| constellation.cx_id)
                .collect::<Vec<_>>();
            let accepted_base =
                self.read_live_base_rows_for_ingest(snapshot.snapshot(), &accepted_ids)?;
            if let Some((index, _)) = accepted_base
                .iter()
                .enumerate()
                .find(|(_, value)| value.is_some())
            {
                return Err(CalyxError::stale_derived(format!(
                    "atomic mixed batch expected new cx {}, but Base is present at snapshot {latest}",
                    accepted_ids[index]
                )));
            }

            let mut proposed_anchors = BTreeMap::<(CxId, AnchorKind), Anchor>::new();
            for constellation in &accepted {
                for anchor in &constellation.anchors {
                    proposed_anchors.insert(
                        (constellation.cx_id, anchor.kind.clone()),
                        anchor.clone(),
                    );
                }
            }
            for request in &existing_requests {
                for anchor in &request.incoming {
                    let key = (request.expected.cx_id(), anchor.kind.clone());
                    if let Some(current) = proposed_anchors.get(&key)
                        && !anchor_merge::same_anchor_observation(current, anchor)
                    {
                        return Err(CalyxError::aster_corrupt_shard(format!(
                            "atomic mixed batch changed the observation for cx {} anchor {:?}",
                            key.0, key.1
                        )));
                    }
                    proposed_anchors.entry(key).or_insert_with(|| anchor.clone());
                }
            }
            let existing = self
                .prepare_existing_base_anchor_merges_locked(existing_requests, latest)?;
            if accepted.is_empty() && !input_rows.is_empty() {
                return Err(CalyxError::aster_corrupt_shard(
                    "atomic mixed batch supplied input-store rows without a new constellation",
                ));
            }

            let mut rows = existing.rows;
            let mut new_records = Vec::with_capacity(accepted.len());
            let mut actual_added = BTreeMap::<(CxId, AnchorKind), Anchor>::new();
            for constellation in &accepted {
                for anchor in &constellation.anchors {
                    actual_added.insert(
                        (constellation.cx_id, anchor.kind.clone()),
                        anchor.clone(),
                    );
                }
            }
            for result in &existing.results {
                for anchor in &result.added {
                    let key = (result.record.cx_id(), anchor.kind.clone());
                    if actual_added.insert(key.clone(), anchor.clone()).is_some() {
                        return Err(CalyxError::aster_corrupt_shard(format!(
                            "atomic mixed batch produced duplicate added anchor for cx {} kind {:?}",
                            key.0, key.1
                        )));
                    }
                }
            }
            let mut selected_markers = Vec::new();
            if let Some(marker_drafts) = marker_drafts {
                for draft in marker_drafts {
                    draft.anchor.validate_schema()?;
                    if draft.entry.kind != EntryKind::Ingest
                        || draft.entry.subject != SubjectId::Cx(draft.cx_id)
                    {
                        return Err(CalyxError::ledger_group_commit_failed(format!(
                            "anchor marker draft for cx {} must be an ingest entry with that Cx subject",
                            draft.cx_id
                        )));
                    }
                    let key = (draft.cx_id, draft.anchor.kind.clone());
                    let proposed = proposed_anchors.get(&key).ok_or_else(|| {
                        CalyxError::aster_corrupt_shard(format!(
                            "anchor marker draft for cx {} kind {:?} has no matching anchor request",
                            draft.cx_id, draft.anchor.kind
                        ))
                    })?;
                    if !anchor_merge::same_anchor_observation(proposed, &draft.anchor) {
                        return Err(CalyxError::aster_corrupt_shard(format!(
                            "anchor marker draft changed the observation for cx {} kind {:?}",
                            draft.cx_id, draft.anchor.kind
                        )));
                    }
                    if let Some(actual) = actual_added.remove(&key) {
                        selected_markers.push((draft, actual));
                    }
                }
                if let Some(((cx_id, kind), _)) = actual_added.first_key_value() {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "atomic mixed batch has no marker Ledger draft for added cx {cx_id} anchor {kind:?}"
                    )));
                }
            }

            let has_new = !accepted.is_empty();
            let mut ledger_entries = Vec::with_capacity(
                usize::from(has_new).saturating_add(selected_markers.len()),
            );
            if has_new {
                ledger_entries.push(LedgerEntryInput::new(
                    EntryKind::Ingest,
                    SubjectId::Cx(
                        accepted
                            .first()
                            .expect("non-empty accepted batch has a first constellation")
                            .cx_id,
                    ),
                    batch_payload(&accepted),
                    ActorId::Service("calyx-aster".to_string()),
                ));
            }
            ledger_entries.extend(
                selected_markers
                    .iter()
                    .map(|(draft, _)| draft.entry.clone()),
            );
            let entry_count = ledger_entries.len();
            let (mut hook_guard, staged_ledger, ledger_refs) = if ledger_entries.is_empty() {
                (None, None, Vec::new())
            } else if let Some(hook) = &self.ledger_hook {
                let guard = ledger_hook::lock_hook(hook)?;
                let staged = guard.stage_many_with_checkpoints(ledger_entries)?;
                let refs = ledger_append::logical_ledger_refs(&staged, entry_count)?;
                rows.extend(staged.iter().map(|row| encode::WriteRow {
                    cf: ColumnFamily::Ledger,
                    key: row.key().to_vec(),
                    value: row.value().to_vec(),
                }));
                (Some(guard), Some(staged), refs)
            } else {
                let (ledger_rows, refs) = self.raw_prepared_ledger_rows(ledger_entries)?;
                rows.extend(ledger_rows);
                (None, None, refs)
            };
            let mut ledger_refs = ledger_refs.into_iter();
            let ingest_ledger_ref = if has_new {
                Some(ledger_refs.next().ok_or_else(|| {
                    CalyxError::ledger_group_commit_failed(
                        "atomic mixed batch omitted its new-ingest Ledger ref",
                    )
                })?)
            } else {
                None
            };
            let mut marker_ledger_receipts = Vec::with_capacity(selected_markers.len());
            for (draft, actual) in selected_markers {
                let ledger_ref = ledger_refs.next().ok_or_else(|| {
                    CalyxError::ledger_group_commit_failed(
                        "atomic mixed batch omitted an anchor-marker Ledger ref",
                    )
                })?;
                marker_ledger_receipts.push(AnchorMarkerLedgerReceipt {
                    cx_id: draft.cx_id,
                    anchor: actual,
                    entry: draft.entry,
                    ledger_ref,
                });
            }
            if ledger_refs.next().is_some() {
                return Err(CalyxError::ledger_group_commit_failed(
                    "atomic mixed batch returned an unassigned Ledger ref",
                ));
            }
            for mut constellation in accepted {
                constellation.provenance = ingest_ledger_ref.clone().ok_or_else(|| {
                    CalyxError::ledger_group_commit_failed(
                        "new constellation batch has no ingest Ledger ref",
                    )
                })?;
                self.stage_constellation_rows(&mut rows, &constellation)?;
                let bytes = encode::encode_constellation_base(&constellation)?;
                new_records.push(encode::BaseRecord::decode_for_key(
                    constellation.cx_id,
                    &bytes,
                )?);
            }
            rows.extend(input_rows);
            let commit_seq = if rows.is_empty() {
                None
            } else {
                Some(self.commit_rows_locked(&rows)?)
            };
            if let (Some(hook), Some(staged)) =
                (hook_guard.as_deref_mut(), staged_ledger.as_ref())
            {
                let committed_seq = commit_seq.ok_or_else(|| {
                    CalyxError::ledger_group_commit_failed(
                        "staged Ledger rows exist without a committed data sequence",
                    )
                })?;
                ledger_hook::commit_staged(hook, staged).map_err(|error| {
                    self.reconcile_post_commit_ledger_hook_failure(committed_seq, &error)
                })?;
            }
            Ok(BatchIngestWithExistingMergeCommit {
                readback_seq: commit_seq.unwrap_or(latest),
                commit_seq,
                new_records,
                existing_results: existing.results,
                marker_ledger_receipts,
            })
        })
    }

    pub fn put_batch_with_ingest_ledger<I>(
        &self,
        constellations: I,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<Vec<CxId>>
    where
        I: IntoIterator<Item = Constellation>,
    {
        let input = constellations.into_iter().collect::<Vec<_>>();
        if input.is_empty() {
            return Ok(Vec::new());
        }
        self.with_durable_commit_lock(|| {
            self.put_batch_locked_with_ledger(
                input,
                Some(BatchLedgerEntry {
                    subject,
                    payload,
                    actor,
                }),
                Vec::new(),
            )
        })
    }

    pub fn put_batch_with_ingest_ledger_and_media_artifact<I>(
        &self,
        constellations: I,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
        artifact: DerivedMediaArtifactDraft,
    ) -> Result<MediaArtifactIngestCommit>
    where
        I: IntoIterator<Item = Constellation>,
    {
        self.put_batch_with_ingest_ledger_and_media_artifact_guarded(
            None,
            constellations,
            subject,
            payload,
            actor,
            artifact,
        )
    }

    /// Commits a media derivation only when the vault still exposes the exact
    /// sequence whose existing Base rows the caller preflighted.
    ///
    /// The sequence comparison runs under the durable commit lock after a
    /// cross-process refresh and before any ledger or artifact row is staged,
    /// so a stale preflight cannot publish a derivation against different Base
    /// state. The caller must repeat its complete measurement and Base
    /// preflight after a sequence conflict.
    pub fn put_batch_with_ingest_ledger_and_media_artifact_if_current<I>(
        &self,
        expected_seq: Seq,
        constellations: I,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
        artifact: DerivedMediaArtifactDraft,
    ) -> Result<MediaArtifactIngestCommit>
    where
        I: IntoIterator<Item = Constellation>,
    {
        self.put_batch_with_ingest_ledger_and_media_artifact_guarded(
            Some(expected_seq),
            constellations,
            subject,
            payload,
            actor,
            artifact,
        )
    }

    fn put_batch_with_ingest_ledger_and_media_artifact_guarded<I>(
        &self,
        expected_seq: Option<Seq>,
        constellations: I,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
        artifact: DerivedMediaArtifactDraft,
    ) -> Result<MediaArtifactIngestCommit>
    where
        I: IntoIterator<Item = Constellation>,
    {
        let input = constellations.into_iter().collect::<Vec<_>>();
        self.with_durable_commit_lock(|| {
            if let Some(expected_seq) = expected_seq {
                let current_seq = self.latest_seq();
                if current_seq != expected_seq {
                    return Err(CalyxError {
                        code: "CALYX_ASTER_SEQUENCE_CONFLICT",
                        message: format!(
                            "media artifact ingest preflight used seq {expected_seq}, current seq is {current_seq}; no vault rows were written"
                        ),
                        remediation: "repeat media derivation, measurement, and Base preflight against the current vault state",
                    });
                }
            }
            let commit = self.put_batch_locked_with_options(
                input,
                Some(BatchLedgerEntry {
                    subject,
                    payload,
                    actor,
                }),
                Some(artifact),
                Vec::new(),
            )?;
            let artifact = commit.artifact.ok_or_else(|| {
                CalyxError::aster_corrupt_shard(
                    "media artifact ingest committed without returning artifact record",
                )
            })?;
            Ok(MediaArtifactIngestCommit {
                ids: commit.ids,
                artifact,
                readback_seq: commit.readback_seq,
                new_records: commit.new_records,
            })
        })
    }

    fn put_batch_locked(
        &self,
        input: Vec<Constellation>,
        input_rows: Vec<encode::WriteRow>,
    ) -> Result<Vec<CxId>> {
        self.put_batch_locked_with_ledger(input, None, input_rows)
    }

    fn put_batch_locked_with_ledger(
        &self,
        input: Vec<Constellation>,
        ledger_entry: Option<BatchLedgerEntry>,
        input_rows: Vec<encode::WriteRow>,
    ) -> Result<Vec<CxId>> {
        self.put_batch_locked_with_options(input, ledger_entry, None, input_rows)
            .map(|commit| commit.ids)
    }

    fn put_batch_locked_with_options(
        &self,
        input: Vec<Constellation>,
        ledger_entry: Option<BatchLedgerEntry>,
        artifact: Option<DerivedMediaArtifactDraft>,
        input_rows: Vec<encode::WriteRow>,
    ) -> Result<BatchIngestCommit> {
        let latest = self.snapshot();
        let snapshot = self.snapshot_handle(latest);
        let mut accepted_indexes = BTreeMap::<Vec<u8>, usize>::new();
        let mut existing_merge_indexes = BTreeMap::<Vec<u8>, usize>::new();
        let mut existing_merges = Vec::<(CxId, encode::BaseRecord, Vec<calyx_core::Anchor>)>::new();
        let mut accepted = Vec::<Constellation>::new();
        let mut ids = Vec::with_capacity(input.len());
        for constellation in input {
            // Each constellation resolved is demonstrated forward progress, so the
            // retained read lease is kept alive rather than timing the batch out
            // against its own size (#980).
            let pinned = snapshot.snapshot();
            self.rows.record_reader_progress(pinned, &self.clock);
            if constellation.vault_id != self.vault_id {
                return Err(CalyxError::vault_access_denied(
                    "constellation belongs to another vault",
                ));
            }
            constellation.validate_schema()?;
            let id = constellation.cx_id;
            let key = base_key(id);
            let base = encode::encode_constellation_base(&constellation)?;
            if let Some(existing) = self.read_live_base_for_ingest(pinned, id)? {
                if existing == base {
                    ids.push(id);
                    continue;
                }
                let merge_index = if let Some(index) = existing_merge_indexes.get(&key).copied() {
                    index
                } else {
                    let index = existing_merges.len();
                    existing_merge_indexes.insert(key.clone(), index);
                    let record = encode::BaseRecord::decode_for_key(id, &existing)?;
                    if existing != record.encode()? {
                        return Err(CalyxError::aster_corrupt_shard(format!(
                            "persisted Base row for cx {id} is not canonically encoded"
                        )));
                    }
                    if record.vault_id() != self.vault_id {
                        return Err(CalyxError::vault_access_denied(format!(
                            "persisted Base row for cx {id} belongs to another vault"
                        )));
                    }
                    existing_merges.push((id, record, Vec::new()));
                    index
                };
                let (_, merged, all_added) = &mut existing_merges[merge_index];
                let added = anchor_merge::merge_duplicate_anchors_base(merged, &constellation)?;
                all_added.extend(added);
                ids.push(id);
                continue;
            }
            if let Some(index) = accepted_indexes.get(&key).copied() {
                anchor_merge::merge_duplicate_anchors(&mut accepted[index], &constellation)?;
                ids.push(id);
                continue;
            }
            accepted_indexes.insert(key, accepted.len());
            ids.push(id);
            accepted.push(constellation);
        }
        let mut anchor_merge_rows = Vec::new();
        for (id, merged, added) in existing_merges {
            if !added.is_empty() {
                anchor_merge_rows.extend(anchor_merge::stage_anchor_merge_base_rows(
                    id, &merged, &added,
                )?);
            }
        }
        if accepted.is_empty() && artifact.is_none() {
            let commit_seq = if anchor_merge_rows.is_empty() {
                None
            } else {
                Some(self.commit_rows_locked(&anchor_merge_rows)?)
            };
            return Ok(BatchIngestCommit {
                ids,
                artifact: None,
                readback_seq: commit_seq.unwrap_or(latest),
                new_records: Vec::new(),
            });
        }
        let mut rows = anchor_merge_rows;
        let predicted_seq = self.latest_seq().checked_add(1).ok_or_else(|| {
            CalyxError::aster_corrupt_shard(
                "vault sequence exhausted at u64::MAX before batch-ingest ledger staging",
            )
        })?;
        let mut hook_guard = match &self.ledger_hook {
            Some(hook) => Some(ledger_hook::lock_hook(hook)?),
            None => None,
        };
        let staged_ledger = if let Some(hook) = hook_guard.as_deref() {
            Some(match ledger_entry {
                Some(entry) => ledger_hook::stage_entry_payload(
                    hook,
                    &mut rows,
                    EntryKind::Ingest,
                    entry.subject,
                    entry.payload,
                    entry.actor,
                )?,
                None => ledger_hook::stage_ingest_payload(
                    hook,
                    &mut rows,
                    accepted
                        .first()
                        .ok_or_else(|| {
                            CalyxError::ledger_group_commit_failed(
                                "batch ingest without accepted rows requires explicit ledger entry",
                            )
                        })?
                        .cx_id,
                    batch_payload(&accepted),
                )?,
            })
        } else {
            rows.push(encode::WriteRow {
                cf: ColumnFamily::Ledger,
                key: ledger_key(predicted_seq),
                value: ledger_stub::encode(predicted_seq),
            });
            None
        };
        let ledger_ref = staged_ledger
            .as_ref()
            .and_then(|staged| staged.first())
            .map(|row| row.ledger_ref())
            .unwrap_or(LedgerRef {
                seq: predicted_seq,
                hash: [0; 32],
            });
        let artifact_record = if let Some(artifact) = artifact {
            let record = artifact.into_record(ledger_ref.clone())?;
            ensure_no_artifact_collision(self, latest, &record)?;
            rows.extend(derived_media_artifact_write_rows(&record)?);
            Some(record)
        } else {
            None
        };
        let mut new_records = Vec::with_capacity(accepted.len());
        for mut constellation in accepted {
            constellation.provenance = ledger_ref.clone();
            self.stage_constellation_rows(&mut rows, &constellation)?;
            let bytes = encode::encode_constellation_base(&constellation)?;
            new_records.push(encode::BaseRecord::decode_for_key(
                constellation.cx_id,
                &bytes,
            )?);
        }
        // Input-store rows (#446) ride the same atomic batch as the base records.
        rows.extend(input_rows);
        let commit_seq = self.commit_rows_locked(&rows)?;
        if let (Some(hook), Some(staged)) = (hook_guard.as_deref_mut(), staged_ledger.as_ref()) {
            ledger_hook::commit_staged(hook, staged).map_err(|error| {
                self.reconcile_post_commit_ledger_hook_failure(commit_seq, &error)
            })?;
        }
        Ok(BatchIngestCommit {
            ids,
            artifact: artifact_record,
            readback_seq: commit_seq,
            new_records,
        })
    }

    /// Reads one Base key without collapsing a visible tombstone into absence.
    /// This runs while the caller holds the durable commit lock, so a row erased
    /// after preflight cannot be resurrected by a put under the same CxId.
    fn read_live_base_for_ingest(
        &self,
        snapshot: Snapshot,
        cx_id: CxId,
    ) -> Result<Option<Vec<u8>>> {
        self.read_live_base_rows_for_ingest(snapshot, &[cx_id])?
            .into_iter()
            .next()
            .ok_or_else(|| {
                CalyxError::aster_corrupt_shard(format!(
                    "Base ingest point read omitted cx {cx_id}"
                ))
            })
    }

    pub(super) fn read_live_base_rows_for_ingest(
        &self,
        snapshot: Snapshot,
        cx_ids: &[CxId],
    ) -> Result<Vec<Option<Vec<u8>>>> {
        if cx_ids.is_empty() {
            return Ok(Vec::new());
        }
        let keys = cx_ids
            .iter()
            .map(|cx_id| base_key(*cx_id))
            .collect::<Vec<_>>();
        let mut order = (0..keys.len()).collect::<Vec<_>>();
        order.sort_unstable_by(|left, right| {
            keys[*left].cmp(&keys[*right]).then_with(|| left.cmp(right))
        });
        let plan = order
            .iter()
            .map(|ordinal| (*ordinal, keys[*ordinal].as_slice()))
            .collect::<Vec<_>>();
        let mut observed = vec![None::<Option<Vec<u8>>>; cx_ids.len()];
        let metrics = self.rows.visit_cf_key_plan::<CalyxError, _>(
            snapshot,
            ColumnFamily::Base,
            &plan,
            &self.clock,
            &mut |ordinal, value| {
                if ordinal >= cx_ids.len() || observed[ordinal].is_some() {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "Base ingest plan returned duplicate or mismatched ordinal {ordinal}"
                    )));
                }
                observed[ordinal] = Some(value.map(ToOwned::to_owned));
                Ok(())
            },
        )?;
        if metrics.session_snapshot_seq != snapshot.seq()
            || metrics.requested_keys != cx_ids.len() as u64
            || metrics.rows_read_back != cx_ids.len() as u64
            || metrics.sst_fallback_file_key_checks != 0
        {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "Base ingest plan accounting mismatch: snapshot={} requested={} rows={} fallback_checks={} expected_rows={}",
                metrics.session_snapshot_seq,
                metrics.requested_keys,
                metrics.rows_read_back,
                metrics.sst_fallback_file_key_checks,
                cx_ids.len()
            )));
        }
        let mut values = Vec::with_capacity(cx_ids.len());
        for (cx_id, observed) in cx_ids.iter().zip(observed) {
            let value = observed.ok_or_else(|| {
                CalyxError::aster_corrupt_shard(format!("Base ingest plan omitted cx {cx_id}"))
            })?;
            if value.as_deref().is_some_and(is_tombstone_value) {
                return Err(CalyxError {
                    code: "CALYX_INGEST_TOMBSTONED_CX",
                    message: format!(
                        "cx {cx_id} has a visible Base tombstone; refusing to resurrect erased data"
                    ),
                    remediation: "ingest intentionally new content with different bytes instead of reusing an erased CxId",
                });
            }
            values.push(value);
        }
        Ok(values)
    }
}

struct BatchIngestCommit {
    ids: Vec<CxId>,
    artifact: Option<DerivedMediaArtifactRecord>,
    readback_seq: Seq,
    new_records: Vec<encode::BaseRecord>,
}

struct BatchLedgerEntry {
    subject: SubjectId,
    payload: Vec<u8>,
    actor: ActorId,
}

fn batch_payload(constellations: &[Constellation]) -> Vec<u8> {
    let mut payload = PayloadBuilder::default();
    let cx_ids = constellations
        .iter()
        .map(|cx| cx.cx_id.to_string())
        .collect::<Vec<_>>();
    let hashes = constellations
        .iter()
        .map(|cx| hex(&cx.input_ref.hash))
        .collect::<Vec<_>>();
    payload
        .insert_str("mode", BATCH_ACTOR)
        .insert_u64("count", constellations.len() as u64)
        .insert_value("cx_id", json!(cx_ids))
        .insert_str("first_cx_id", constellations[0].cx_id.to_string())
        .insert_str(
            "last_cx_id",
            constellations
                .last()
                .expect("non-empty batch")
                .cx_id
                .to_string(),
        )
        .insert_value("input_hash", json!(hashes));
    RedactionPolicy::default().apply_to_payload(&payload)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
