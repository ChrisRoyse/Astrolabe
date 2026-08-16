use std::collections::BTreeSet;

use super::encode::{self, WriteRow};
use crate::cf::{ColumnFamily, anchor_key, base_key};
use crate::dedup::{AnchorConflictResult, check_anchor_conflict};
use calyx_core::{Anchor, CalyxError, Constellation, CxId, LedgerRef, Result};

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

    let mut existing_kinds = existing
        .anchors
        .iter()
        .map(|anchor| anchor.kind.clone())
        .collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    for anchor in &incoming.anchors {
        if existing_kinds.insert(anchor.kind.clone()) {
            existing.anchors.push(anchor.clone());
            added.push(anchor.clone());
        }
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

    let mut existing_kinds = existing
        .constellation()
        .anchors
        .iter()
        .map(|anchor| anchor.kind.clone())
        .collect::<BTreeSet<_>>();
    let mut added = Vec::new();
    for anchor in &incoming.anchors {
        if existing_kinds.insert(anchor.kind.clone()) {
            existing.anchors_mut().push(anchor.clone());
            added.push(anchor.clone());
        }
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
