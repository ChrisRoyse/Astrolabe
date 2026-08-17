use calyx_aster::mvcc::is_tombstone_value;
use calyx_aster::vault::OrderedCfRead;

use super::*;

#[derive(Debug)]
pub(super) struct BatchBaseState {
    pub(super) visible: BTreeSet<CxId>,
    pub(super) tombstoned: BTreeSet<CxId>,
}

/// Reads exactly the requested Base keys through one ordered latest-state plan.
/// The ordered callback deliberately exposes tombstone bytes so erased CxIds
/// cannot be mistaken for never-materialized rows and resurrected by ingest.
pub(super) fn batch_base_state(
    vault: &AsterVault,
    snapshot: u64,
    cx_ids: &BTreeSet<CxId>,
) -> CliResult<BatchBaseState> {
    if cx_ids.is_empty() {
        return Ok(BatchBaseState {
            visible: BTreeSet::new(),
            tombstoned: BTreeSet::new(),
        });
    }
    let ids = cx_ids.iter().copied().collect::<Vec<_>>();
    let keys = ids.iter().map(|cx_id| base_key(*cx_id)).collect::<Vec<_>>();
    let reads = keys
        .iter()
        .enumerate()
        .map(|(ordinal, key)| OrderedCfRead::new(ordinal, ColumnFamily::Base, key))
        .collect::<Vec<_>>();
    let mut seen = vec![false; ids.len()];
    let mut visible = BTreeSet::new();
    let mut tombstoned = BTreeSet::new();
    let metrics = vault.visit_ordered_cf_plan_at(
        snapshot,
        &reads,
        |ordinal, cf, key, value| -> CliResult<()> {
            if ordinal >= ids.len()
                || cf != ColumnFamily::Base
                || key != keys[ordinal].as_slice()
                || std::mem::replace(&mut seen[ordinal], true)
            {
                return Err(calyx_core::CalyxError::aster_corrupt_shard(
                    "ordered batch Base preflight returned a duplicate or mismatched row",
                )
                .into());
            }
            let Some(value) = value else {
                return Ok(());
            };
            if is_tombstone_value(value) {
                tombstoned.insert(ids[ordinal]);
                return Ok(());
            }
            let record = encode::BaseRecord::decode_for_key(ids[ordinal], value)?;
            if record.vault_id() != vault.vault_id() {
                return Err(calyx_core::CalyxError::vault_access_denied(format!(
                    "physical Base row for cx {} belongs to another vault",
                    ids[ordinal]
                ))
                .into());
            }
            visible.insert(ids[ordinal]);
            Ok(())
        },
    )?;
    if seen.iter().any(|seen| !seen)
        || metrics.session_snapshot_seq != snapshot
        || metrics.requested_keys != ids.len() as u64
        || metrics.rows_read_back != ids.len() as u64
        || metrics.sst_fallback_file_key_checks != 0
    {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "ordered batch Base preflight accounting mismatch: snapshot={} requested={} rows={} fallback_checks={} expected_rows={}",
            metrics.session_snapshot_seq,
            metrics.requested_keys,
            metrics.rows_read_back,
            metrics.sst_fallback_file_key_checks,
            ids.len()
        ))
        .into());
    }
    Ok(BatchBaseState {
        visible,
        tombstoned,
    })
}

pub(super) fn reject_tombstoned_batch_ids(state: &BatchBaseState) -> CliResult<()> {
    if state.tombstoned.is_empty() {
        return Ok(());
    }
    let ids = sample_ids(&state.tombstoned);
    Err(calyx_core::CalyxError {
        code: "CALYX_INGEST_TOMBSTONED_CX",
        message: format!(
            "batch contains {} Cx IDs whose latest Base rows are tombstones; refusing to resurrect erased data (sample_cx_ids={ids})",
            state.tombstoned.len()
        ),
        remediation:
            "remove tombstoned inputs from the batch or ingest intentionally new content with different bytes",
    }
    .into())
}

/// Finalizes the summary from the before-state plus the exact per-chunk
/// commit-owned SST and snapshot readbacks already completed by the write path.
pub(super) fn reconcile_summary_with_verified_base(
    summary: &mut BatchIngestSummary,
    before: &BatchBaseState,
    after: &BatchBaseState,
    planned_ids: &BTreeSet<CxId>,
    expected_row_count: usize,
) -> CliResult<()> {
    if summary.batch_cx_ids != *planned_ids
        || summary.row_count != expected_row_count
        || summary.verified_base_rows != summary.row_count
        || !before.tombstoned.is_empty()
        || !after.tombstoned.is_empty()
        || after.visible != *planned_ids
    {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "batch Base receipt accounting mismatch: planned_distinct={} reported_distinct={} visible_after={} expected_rows={} rows={} verified_rows={} tombstoned_before={} tombstoned_after={}",
            planned_ids.len(),
            summary.batch_cx_ids.len(),
            after.visible.len(),
            expected_row_count,
            summary.row_count,
            summary.verified_base_rows,
            before.tombstoned.len(),
            after.tombstoned.len()
        ))
        .into());
    }
    if summary.runtime_new_count + summary.runtime_already_count != summary.row_count {
        return Err(calyx_core::CalyxError::aster_corrupt_shard(format!(
            "batch Base receipt/runtime disagreement: runtime_new={} runtime_already={} rows={}",
            summary.runtime_new_count, summary.runtime_already_count, summary.row_count
        ))
        .into());
    }
    summary.distinct_cx_count = planned_ids.len();
    summary.batch_base_visible_before = before.visible.len();
    summary.batch_base_visible_after = after.visible.len();
    summary.batch_base_materialized_count = summary.runtime_new_count;
    summary.batch_base_tombstoned_before = 0;
    summary.batch_base_tombstoned_after = 0;
    summary.new_count = summary.runtime_new_count;
    summary.already_count = summary.runtime_already_count;
    ingest_runtime_log(format_args!(
        "phase=batch_base_receipt_readback_ok row_count={} distinct_cx={} new_count={} already_count={} visible_before={} visible_after={}",
        summary.row_count,
        summary.distinct_cx_count,
        summary.new_count,
        summary.already_count,
        summary.batch_base_visible_before,
        summary.batch_base_visible_after
    ));
    Ok(())
}

fn sample_ids(ids: &BTreeSet<CxId>) -> String {
    ids.iter()
        .take(8)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}
