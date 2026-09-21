use super::{
    AsterVault, LedgerBoundRowDigest, encode,
    layer_commit::{attach_ledger_ref_to_rows, digest_rows},
    ledger_append::logical_ledger_refs,
    ledger_hook,
};
use crate::cf::ColumnFamily;
use calyx_core::{CalyxError, Clock, LedgerRef, Result, Seq};
use calyx_ledger::LedgerEntryInput;
use std::collections::BTreeSet;

/// One logical provenance entry and the exact data rows it owns.
///
/// Groups are committed in input order. Base/Graph rows are stamped with this
/// group's exact Ledger ref before their digest receipt is computed. A group
/// may have zero data rows so dedup-only logical transitions remain durable.
#[derive(Debug, Clone)]
pub struct LedgerBoundWriteGroup {
    pub rows: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>,
    pub entry: LedgerEntryInput,
}

impl LedgerBoundWriteGroup {
    pub fn new(rows: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>, entry: LedgerEntryInput) -> Self {
        Self { rows, entry }
    }
}

/// Exact post-bind receipt for one logical write group.
#[derive(Debug)]
pub struct LedgerBoundGroupReceipt {
    pub ledger_ref: LedgerRef,
    pub data_row_digests: Vec<LedgerBoundRowDigest>,
}

/// One MVCC/WAL commit containing several ordered logical write groups.
#[derive(Debug)]
pub struct LedgerBoundGroupBatchReceipt {
    pub seq: Seq,
    pub groups: Vec<LedgerBoundGroupReceipt>,
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Atomically commits ordered ledger-bound groups at one exact snapshot.
    ///
    /// Every logical Ledger entry/checkpoint and all caller rows share one
    /// MVCC/WAL commit. Duplicate caller `(CF,key)` rows are rejected before
    /// mutation; callers cannot inject Ledger or time-index rows. Any sequence,
    /// staging, provenance-binding, commit, or hook-finalization failure is
    /// returned directly—there is no singular-write retry path.
    pub fn write_ledger_bound_groups_if_seq(
        &self,
        expected_seq: Seq,
        groups: Vec<LedgerBoundWriteGroup>,
    ) -> Result<LedgerBoundGroupBatchReceipt> {
        validate_groups(&groups)?;
        self.with_durable_commit_lock(|| {
            let current = self.latest_seq();
            if current != expected_seq {
                return Err(CalyxError {
                    code: "CALYX_ASTER_SEQUENCE_CONFLICT",
                    message: format!(
                        "ordered ledger-bound group batch expected seq {expected_seq}, current seq is {current}; no rows were written"
                    ),
                    remediation: "re-read the current snapshot, rebuild and revalidate the complete ordered group window, then retry with that exact sequence",
                });
            }

            let entries = groups
                .iter()
                .map(|group| group.entry.clone())
                .collect::<Vec<_>>();
            if let Some(hook) = &self.ledger_hook {
                let mut guard = ledger_hook::lock_hook(hook)?;
                let staged = guard.stage_many_with_checkpoints(entries)?;
                let refs = logical_ledger_refs(&staged, groups.len())?;
                let (mut rows, receipts) = bind_groups(groups, refs)?;
                rows.extend(staged.iter().map(|row| encode::WriteRow {
                    cf: ColumnFamily::Ledger,
                    key: row.key().to_vec(),
                    value: row.value().to_vec(),
                }));
                let seq = self.commit_rows_locked_owned(rows, false)?;
                ledger_hook::commit_staged(&mut guard, &staged).map_err(|error| {
                    self.reconcile_post_commit_ledger_hook_failure(seq, &error)
                })?;
                return Ok(LedgerBoundGroupBatchReceipt {
                    seq,
                    groups: receipts,
                });
            }

            let (ledger_rows, refs) = self.raw_prepared_ledger_rows(entries)?;
            let (mut rows, receipts) = bind_groups(groups, refs)?;
            rows.extend(ledger_rows);
            let seq = self.commit_rows_locked_owned(rows, false)?;
            Ok(LedgerBoundGroupBatchReceipt {
                seq,
                groups: receipts,
            })
        })
    }
}

fn validate_groups(groups: &[LedgerBoundWriteGroup]) -> Result<()> {
    if groups.is_empty() {
        return Err(CalyxError::ledger_group_commit_failed(
            "ordered ledger-bound group batch requires at least one logical group",
        ));
    }
    let mut keys = BTreeSet::new();
    for (group_ordinal, group) in groups.iter().enumerate() {
        for (cf, key, _) in &group.rows {
            if matches!(cf, ColumnFamily::Ledger | ColumnFamily::TimeIndex) {
                return Err(CalyxError::ledger_group_commit_failed(format!(
                    "ordered ledger-bound group {group_ordinal} attempted to supply internal {} rows",
                    cf.name()
                )));
            }
            if !keys.insert((*cf, key.clone())) {
                return Err(CalyxError::ledger_group_commit_failed(format!(
                    "ordered ledger-bound groups contain duplicate {} key {}",
                    cf.name(),
                    hex_lower(key)
                )));
            }
        }
    }
    Ok(())
}

fn bind_groups(
    groups: Vec<LedgerBoundWriteGroup>,
    refs: Vec<LedgerRef>,
) -> Result<(Vec<encode::WriteRow>, Vec<LedgerBoundGroupReceipt>)> {
    if groups.len() != refs.len() {
        return Err(CalyxError::ledger_group_commit_failed(format!(
            "ordered ledger-bound batch staged {} caller refs for {} groups",
            refs.len(),
            groups.len()
        )));
    }
    let row_capacity = groups.iter().try_fold(0usize, |total, group| {
        total.checked_add(group.rows.len()).ok_or_else(|| {
            CalyxError::ledger_group_commit_failed(
                "ordered ledger-bound group row count overflowed usize",
            )
        })
    })?;
    let mut rows = Vec::with_capacity(row_capacity);
    let mut receipts = Vec::with_capacity(groups.len());
    for (group, ledger_ref) in groups.into_iter().zip(refs) {
        let mut group_rows = group
            .rows
            .into_iter()
            .map(|(cf, key, value)| encode::WriteRow { cf, key, value })
            .collect::<Vec<_>>();
        attach_ledger_ref_to_rows(&mut group_rows, &ledger_ref)?;
        let data_row_digests = digest_rows(&group_rows);
        rows.extend(group_rows);
        receipts.push(LedgerBoundGroupReceipt {
            ledger_ref,
            data_row_digests,
        });
    }
    Ok((rows, receipts))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}
