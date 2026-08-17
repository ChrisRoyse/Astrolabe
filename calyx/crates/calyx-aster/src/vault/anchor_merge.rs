use std::collections::{BTreeMap, BTreeSet};

use super::AsterVault;
use super::encode::{self, BaseRecord, WriteRow};
use crate::cf::{ColumnFamily, anchor_key, base_key};
use crate::dedup::{AnchorConflictResult, check_anchor_conflict};
use calyx_core::{
    Anchor, AnchorKind, CalyxError, Clock, Constellation, CxId, LedgerRef, Result, Seq, VaultStore,
};

/// One lossless existing-Base anchor merge request.
///
/// `expected` is the exact Base record whose non-anchor identity the caller
/// validated. The merge re-reads Base while holding the durable commit lock and
/// refuses if that identity changed. `incoming` may repeat already-materialized
/// anchor kinds with compatible values; only actually missing kinds are written.
#[derive(Clone, Debug)]
pub struct ExistingBaseAnchorMerge {
    pub expected: BaseRecord,
    pub incoming: Vec<Anchor>,
}

/// Result for one [`ExistingBaseAnchorMerge`], preserving request order.
#[derive(Debug)]
pub struct ExistingBaseAnchorMergeResult {
    pub record: BaseRecord,
    pub added: Vec<Anchor>,
}

/// Atomic receipt for one existing-Base anchor-merge batch.
#[derive(Debug)]
pub struct ExistingBaseAnchorMergeCommit {
    /// Snapshot containing the returned records: the commit sequence when rows
    /// were added, otherwise the under-lock snapshot that proved the no-op.
    pub readback_seq: Seq,
    /// Assigned group-commit sequence, or `None` when every candidate kind was
    /// already materialized and no row was written.
    pub commit_seq: Option<Seq>,
    /// One exact final lossless record per request, in request order.
    pub results: Vec<ExistingBaseAnchorMergeResult>,
}

pub(super) struct PreparedExistingBaseAnchorMerges {
    pub rows: Vec<WriteRow>,
    pub results: Vec<ExistingBaseAnchorMergeResult>,
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Atomically merges missing anchors into existing Base records without
    /// hydrating any slot payload.
    ///
    /// The complete request is validated under one durable commit lock before
    /// one Base+Anchors CF group commit. Each requested anchor kind that already
    /// exists must be byte-consistent between Base and Anchors CF; request CxIds and per-request
    /// anchor kinds must be unique, and the current non-anchor Base identity must
    /// still equal the caller's lossless `expected` record. Compatible
    /// already-present anchors are no-ops; conflicting values fail before
    /// mutation.
    pub fn merge_existing_base_anchors(
        &self,
        requests: Vec<ExistingBaseAnchorMerge>,
    ) -> Result<ExistingBaseAnchorMergeCommit> {
        if requests.is_empty() {
            return Ok(ExistingBaseAnchorMergeCommit {
                readback_seq: self.snapshot(),
                commit_seq: None,
                results: Vec::new(),
            });
        }
        self.with_durable_commit_lock(|| {
            let snapshot = self.snapshot();
            let prepared = self.prepare_existing_base_anchor_merges_locked(requests, snapshot)?;
            let commit_seq = if prepared.rows.is_empty() {
                None
            } else {
                Some(self.commit_rows_locked(&prepared.rows)?)
            };
            Ok(ExistingBaseAnchorMergeCommit {
                readback_seq: commit_seq.unwrap_or(snapshot),
                commit_seq,
                results: prepared.results,
            })
        })
    }

    pub(super) fn prepare_existing_base_anchor_merges_locked(
        &self,
        requests: Vec<ExistingBaseAnchorMerge>,
        snapshot: Seq,
    ) -> Result<PreparedExistingBaseAnchorMerges> {
        let mut requested_ids = BTreeSet::new();
        for request in &requests {
            let cx_id = request.expected.cx_id();
            if !requested_ids.insert(cx_id) {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "existing Base anchor merge contains duplicate CxId {cx_id}"
                )));
            }
            if request.expected.vault_id() != self.vault_id {
                return Err(CalyxError::vault_access_denied(format!(
                    "existing Base anchor merge for cx {cx_id} belongs to another vault"
                )));
            }
            let mut incoming_kinds = BTreeSet::new();
            for anchor in &request.incoming {
                anchor.validate_schema()?;
                if !incoming_kinds.insert(anchor.kind.clone()) {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "existing Base anchor merge for cx {cx_id} contains duplicate anchor kind {:?}",
                        anchor.kind
                    )));
                }
            }
        }
        let requested_ids = requests
            .iter()
            .map(|request| request.expected.cx_id())
            .collect::<Vec<_>>();
        let base_rows = self.read_live_base_rows_for_ingest(
            self.snapshot_handle(snapshot).snapshot(),
            &requested_ids,
        )?;
        let mut staged_rows = Vec::new();
        let mut results = Vec::with_capacity(requests.len());
        for (request, base) in requests.into_iter().zip(base_rows) {
            let cx_id = request.expected.cx_id();
            let base = base.ok_or_else(|| {
                CalyxError::stale_derived(format!(
                    "existing Base anchor merge cannot find cx {cx_id} at snapshot {snapshot}"
                ))
            })?;
            let mut current = BaseRecord::decode_for_key(cx_id, &base)?;
            if base != current.encode()? {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "persisted Base row for cx {cx_id} is not canonically encoded"
                )));
            }
            if current.vault_id() != self.vault_id {
                return Err(CalyxError::vault_access_denied(format!(
                    "persisted Base row for cx {cx_id} belongs to another vault"
                )));
            }
            if current.anchor_merge_identity()? != request.expected.anchor_merge_identity()? {
                return Err(CalyxError::stale_derived(format!(
                    "existing Base non-anchor identity changed before anchor merge for cx {cx_id}"
                )));
            }

            let mut current_by_kind = BTreeMap::<AnchorKind, Anchor>::new();
            for anchor in &current.constellation().anchors {
                if current_by_kind
                    .insert(anchor.kind.clone(), anchor.clone())
                    .is_some()
                {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "persisted Base row for cx {cx_id} contains duplicate anchor kind {:?}",
                        anchor.kind
                    )));
                }
            }

            let mut incoming_view = current.constellation().clone();
            incoming_view.anchors = request.incoming.clone();
            if let AnchorConflictResult::Conflicting {
                anchor_type,
                reason,
            } = check_anchor_conflict(&incoming_view, current.constellation())
            {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "idempotent Base anchor merge for cx {cx_id} has conflicting {anchor_type:?} anchor: {reason:?}"
                )));
            }

            let mut added = Vec::new();
            for anchor in request.incoming {
                let key = anchor_key(cx_id, &anchor.kind);
                if let Some(current_anchor) = current_by_kind.get(&anchor.kind) {
                    let indexed = self
                        .read_cf_at(snapshot, ColumnFamily::Anchors, &key)?
                        .ok_or_else(|| {
                            CalyxError::aster_corrupt_shard(format!(
                                "persisted Base row for cx {cx_id} contains anchor {:?} missing from Anchors CF",
                                anchor.kind
                            ))
                        })?;
                    if indexed != encode::encode_anchor(current_anchor)? {
                        return Err(CalyxError::aster_corrupt_shard(format!(
                            "persisted Base and Anchors CF rows disagree for cx {cx_id} anchor {:?}",
                            anchor.kind
                        )));
                    }
                    if !same_anchor_observation(current_anchor, &anchor) {
                        return Err(CalyxError::aster_corrupt_shard(format!(
                            "idempotent Base anchor merge for cx {cx_id} changed source or confidence for anchor {:?}",
                            anchor.kind
                        )));
                    }
                    continue;
                }
                if self
                    .read_cf_at(snapshot, ColumnFamily::Anchors, &key)?
                    .is_some()
                {
                    return Err(CalyxError::aster_corrupt_shard(format!(
                        "Anchors CF contains {:?} for cx {cx_id} but the Base row does not",
                        anchor.kind
                    )));
                }
                current_by_kind.insert(anchor.kind.clone(), anchor.clone());
                current.anchors_mut().push(anchor.clone());
                added.push(anchor);
            }
            if !added.is_empty() {
                let ungrounded = current.constellation().anchors.is_empty();
                current.flags_mut().ungrounded = ungrounded;
                current.constellation().validate_schema()?;
                staged_rows.extend(stage_anchor_merge_base_rows(cx_id, &current, &added)?);
            }
            results.push(ExistingBaseAnchorMergeResult {
                record: current,
                added,
            });
        }
        Ok(PreparedExistingBaseAnchorMerges {
            rows: staged_rows,
            results,
        })
    }
}

pub(super) fn merge_duplicate_anchors(
    existing: &mut Constellation,
    incoming: &Constellation,
) -> Result<Vec<Anchor>> {
    if !same_anchor_merge_identity(existing, incoming)? {
        return Err(CalyxError::aster_corrupt_shard(
            "CxId collision or non-idempotent duplicate constellation",
        ));
    }
    if let AnchorConflictResult::Conflicting {
        anchor_type,
        reason,
    } = check_anchor_conflict(incoming, existing)
    {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "CxId duplicate has conflicting {anchor_type:?} anchor: {reason:?}"
        )));
    }

    let mut existing_by_kind = existing
        .anchors
        .iter()
        .map(|anchor| (anchor.kind.clone(), anchor.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut added = Vec::new();
    for anchor in &incoming.anchors {
        if let Some(current) = existing_by_kind.get(&anchor.kind) {
            if !same_anchor_observation(current, anchor) {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "CxId duplicate changed source or confidence for anchor {:?}",
                    anchor.kind
                )));
            }
            continue;
        }
        existing_by_kind.insert(anchor.kind.clone(), anchor.clone());
        existing.anchors.push(anchor.clone());
        added.push(anchor.clone());
    }
    if !added.is_empty() {
        existing.flags.ungrounded = existing.anchors.is_empty();
        existing.validate_schema()?;
    }
    Ok(added)
}

/// Merges duplicate-ingest anchors into a lossless Base view. This is the
/// compressed-generation-safe path: it never hydrates slots, and Base's exact
/// persisted slot hashes remain sealed by [`encode::BaseRecord`].
pub(super) fn merge_duplicate_anchors_base(
    existing: &mut encode::BaseRecord,
    incoming: &Constellation,
) -> Result<Vec<Anchor>> {
    let incoming_bytes = encode::encode_constellation_base(incoming)?;
    let incoming_record = encode::BaseRecord::decode_for_key(incoming.cx_id, &incoming_bytes)?;
    if existing.anchor_merge_identity()? != incoming_record.anchor_merge_identity()? {
        return Err(CalyxError::aster_corrupt_shard(
            "CxId collision or non-idempotent duplicate constellation",
        ));
    }
    if let AnchorConflictResult::Conflicting {
        anchor_type,
        reason,
    } = check_anchor_conflict(incoming, existing.constellation())
    {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "CxId duplicate has conflicting {anchor_type:?} anchor: {reason:?}"
        )));
    }

    let mut existing_by_kind = existing
        .constellation()
        .anchors
        .iter()
        .map(|anchor| (anchor.kind.clone(), anchor.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut added = Vec::new();
    for anchor in &incoming.anchors {
        if let Some(current) = existing_by_kind.get(&anchor.kind) {
            if !same_anchor_observation(current, anchor) {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "CxId duplicate changed source or confidence for anchor {:?}",
                    anchor.kind
                )));
            }
            continue;
        }
        existing_by_kind.insert(anchor.kind.clone(), anchor.clone());
        existing.anchors_mut().push(anchor.clone());
        added.push(anchor.clone());
    }
    if !added.is_empty() {
        let ungrounded = existing.constellation().anchors.is_empty();
        existing.flags_mut().ungrounded = ungrounded;
        existing.constellation().validate_schema()?;
    }
    Ok(added)
}

pub(super) fn stage_anchor_merge_base_rows(
    id: CxId,
    merged: &encode::BaseRecord,
    added: &[Anchor],
) -> Result<Vec<WriteRow>> {
    let mut rows = Vec::with_capacity(1 + added.len());
    rows.push(WriteRow {
        cf: ColumnFamily::Base,
        key: base_key(id),
        value: merged.encode()?,
    });
    for anchor in added {
        rows.push(WriteRow {
            cf: ColumnFamily::Anchors,
            key: anchor_key(id, &anchor.kind),
            value: encode::encode_anchor(anchor)?,
        });
    }
    Ok(rows)
}

fn same_anchor_merge_identity(left: &Constellation, right: &Constellation) -> Result<bool> {
    Ok(normalized_anchor_identity(left)? == normalized_anchor_identity(right)?)
}

fn normalized_anchor_identity(cx: &Constellation) -> Result<Vec<u8>> {
    let mut normalized = cx.clone();
    normalized.anchors.clear();
    normalized.created_at = 0;
    normalized.flags.ungrounded = false;
    normalized.provenance = LedgerRef {
        seq: 0,
        hash: [0; 32],
    };
    encode::encode_constellation_base(&normalized)
}

pub(super) fn same_anchor_observation(left: &Anchor, right: &Anchor) -> bool {
    left.kind == right.kind
        && left.value == right.value
        && left.source == right.source
        && left.confidence.to_bits() == right.confidence.to_bits()
}
