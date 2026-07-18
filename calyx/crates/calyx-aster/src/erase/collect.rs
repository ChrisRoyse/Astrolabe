//! Erase target selection: walking the vault snapshot to gather every CF row a
//! scope tombstones, applying the compression-erase policy (issue #562), and the
//! ledger-free `erase_cf_records` core-tombstone path.

use super::handler::{EraseScope, METADATA_SUBJECT_ID};
use crate::cf::{
    ColumnFamily, KeyRange, anchor_prefix_range, base_key, compression_lifecycle_key,
    compression_manifest_key, recurrence_prefix_range, slot_key, temporal_xterm_prefix_range,
    xterm_prefix_range,
};
use crate::compression_lifecycle::{
    CALYX_COMPRESSION_LIFECYCLE_INVALID, GenerationLifecycleRecord, GenerationTransition,
};
use crate::mvcc::{is_tombstone_value, tombstone_value};
use crate::vault::{AsterVault, VaultContext, encode};
use calyx_core::{CalyxError, Clock, Constellation, CxId, Result, SlotId};
use calyx_ledger::SubjectId;
use std::collections::BTreeSet;

/// How a lawful erase treats a targeted slot that carries a live compressed
/// generation manifest (issue #562).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompressionErasePolicy {
    /// Constellation- and subject-scoped erases cannot shed a single row from a
    /// compressed generation; they fail closed and route the caller to a reseal.
    RouteReseal,
    /// A full-vault erase removes each generation wholesale, staging a
    /// coordinated manifest tombstone plus a `DeleteGeneration` lifecycle record.
    CoordinatedDelete,
}

/// Tombstones all visible Aster CF rows selected by `scope` through the normal
/// durable commit path. The committed tombstone is the WAL crash-safety record.
pub fn erase_cf_records<C>(
    vault: &AsterVault<C>,
    scope: &EraseScope,
    vault_ctx: &VaultContext,
) -> Result<usize>
where
    C: Clock,
{
    Ok(erase_cf_records_summary(vault, scope, vault_ctx)?.records_deleted)
}

fn erase_cf_records_summary<C>(
    vault: &AsterVault<C>,
    scope: &EraseScope,
    vault_ctx: &VaultContext,
) -> Result<EraseWriteSummary>
where
    C: Clock,
{
    if vault_ctx.vault_id() != vault.vault_id() {
        return Err(CalyxError::vault_access_denied(
            "erase VaultContext belongs to another vault",
        ));
    }
    vault.with_durable_commit_lock(|| {
        let snapshot = vault.latest_seq();
        let targets = collect_targets(vault, scope, snapshot)?;
        if !targets.lifecycle_writes.is_empty() {
            // This ledger-free path cannot pair a manifest tombstone with its
            // DeleteGeneration record; fail closed rather than trip the commit
            // guard (issue #562). A coordinated generation delete must go through
            // `AsterVault::erase`, whose Phase C batches the manifest tombstone,
            // the DeleteGeneration lifecycle record, and the ledger entry.
            return Err(CalyxError {
                code: CALYX_COMPRESSION_LIFECYCLE_INVALID,
                message: format!(
                    "erase_cf_records cannot delete {} compressed slot generation(s) without a ledgered coordinated delete",
                    targets.lifecycle_writes.len()
                ),
                remediation: "use AsterVault::erase on a vault opened with its ledger hook so each generation delete records its DeleteGeneration transition",
            });
        }
        if targets.rows.is_empty() {
            return Ok(EraseWriteSummary {
                records_deleted: targets.records_deleted,
            });
        }
        let tombstone = tombstone_value();
        let rows = targets
            .rows
            .iter()
            .map(|target| encode::WriteRow {
                cf: target.cf,
                key: target.key.clone(),
                value: tombstone.clone(),
            })
            .collect::<Vec<_>>();
        vault.commit_rows_locked(&rows)?;
        vault.purge_tombstoned_cfs_locked(&affected_cfs(&targets.rows))?;
        Ok(EraseWriteSummary {
            records_deleted: targets.records_deleted,
        })
    })
}

pub fn subject_metadata_value(subject: &SubjectId) -> String {
    match subject {
        SubjectId::Cx(id) => format!("cx:{id}"),
        SubjectId::Lens(id) => format!("lens:{id}"),
        SubjectId::Kernel(bytes) => format!("kernel:{}", hex(bytes)),
        SubjectId::Guard(bytes) => format!("guard:{}", hex(bytes)),
        SubjectId::Query(bytes) => format!("query:{}", hex(bytes)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct EraseTarget {
    pub(super) cf: ColumnFamily,
    pub(super) key: Vec<u8>,
}

#[derive(Debug, Default)]
pub(super) struct EraseTargets {
    pub(super) rows: Vec<EraseTarget>,
    pub(super) records_deleted: usize,
    /// Non-tombstone rows (DeleteGeneration lifecycle records) that must be
    /// committed alongside the tombstones for a coordinated generation delete.
    pub(super) lifecycle_writes: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>,
    /// Slots whose full-generation delete has already been staged, so a slot
    /// referenced by several constellations is deleted exactly once.
    staged_delete_slots: BTreeSet<u16>,
}

#[derive(Debug)]
struct EraseWriteSummary {
    records_deleted: usize,
}

pub(super) fn collect_targets<C>(
    vault: &AsterVault<C>,
    scope: &EraseScope,
    snapshot: u64,
) -> Result<EraseTargets>
where
    C: Clock,
{
    match scope {
        EraseScope::Vault => collect_vault_targets(vault, snapshot),
        EraseScope::Cx(cx_id) => collect_cx_targets(vault, snapshot, *cx_id, None),
        EraseScope::Subject(subject) => collect_subject_targets(vault, snapshot, subject),
    }
}

fn collect_vault_targets<C>(vault: &AsterVault<C>, snapshot: u64) -> Result<EraseTargets>
where
    C: Clock,
{
    let mut targets = EraseTargets::default();
    for cf in ColumnFamily::STATIC {
        // Ledger is append-only; Compression is handled per-generation below so a
        // manifest tombstone is always paired with its DeleteGeneration record and
        // append-only lifecycle records are never tombstoned (issue #562).
        if cf == ColumnFamily::Ledger || cf == ColumnFamily::Compression {
            continue;
        }
        for (key, _) in vault.scan_cf_at(snapshot, cf)? {
            push_unique(&mut targets.rows, cf, key);
        }
    }
    for (_, base) in vault.scan_cf_at(snapshot, ColumnFamily::Base)? {
        let cx = encode::decode_constellation_base(&base)?;
        targets.records_deleted += 1;
        collect_slot_targets(
            vault,
            snapshot,
            &cx,
            &mut targets,
            CompressionErasePolicy::CoordinatedDelete,
        )?;
    }
    // Sweep any compressed generation not reached through a base constellation.
    for (key, value) in vault.scan_cf_at(snapshot, ColumnFamily::Compression)? {
        if key.len() == 2 && !is_tombstone_value(&value) {
            let slot = SlotId::new(u16::from_be_bytes([key[0], key[1]]));
            stage_generation_delete(vault, snapshot, slot, &mut targets)?;
        }
    }
    Ok(targets)
}

fn collect_subject_targets<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    subject: &SubjectId,
) -> Result<EraseTargets>
where
    C: Clock,
{
    let expected = subject_metadata_value(subject);
    let mut targets = EraseTargets::default();
    for (_, base) in vault.scan_cf_at(snapshot, ColumnFamily::Base)? {
        let cx = encode::decode_constellation_base(&base)?;
        if cx.metadata_value(METADATA_SUBJECT_ID) != Some(expected.as_str()) {
            continue;
        }
        let cx_targets = collect_cx_targets(vault, snapshot, cx.cx_id, Some(cx))?;
        targets.records_deleted += cx_targets.records_deleted;
        for target in cx_targets.rows {
            push_unique(&mut targets.rows, target.cf, target.key);
        }
    }
    Ok(targets)
}

fn collect_cx_targets<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    cx_id: CxId,
    base: Option<Constellation>,
) -> Result<EraseTargets>
where
    C: Clock,
{
    let mut targets = EraseTargets::default();
    let base = match base {
        Some(cx) => Some(cx),
        None => vault
            .read_cf_at(snapshot, ColumnFamily::Base, &base_key(cx_id))?
            .map(|bytes| encode::decode_constellation_base(&bytes))
            .transpose()?,
    };
    if let Some(cx) = &base {
        push_unique(&mut targets.rows, ColumnFamily::Base, base_key(cx.cx_id));
        targets.records_deleted = 1;
        collect_slot_targets(
            vault,
            snapshot,
            cx,
            &mut targets,
            CompressionErasePolicy::RouteReseal,
        )?;
    }
    collect_range_targets(
        vault,
        snapshot,
        ColumnFamily::Anchors,
        &anchor_prefix_range(cx_id),
        &mut targets.rows,
    )?;
    collect_range_targets(
        vault,
        snapshot,
        ColumnFamily::XTerm,
        &xterm_prefix_range(cx_id),
        &mut targets.rows,
    )?;
    collect_range_targets(
        vault,
        snapshot,
        ColumnFamily::Recurrence,
        &recurrence_prefix_range(cx_id),
        &mut targets.rows,
    )?;
    collect_temporal_xterm_targets(vault, snapshot, cx_id, &mut targets.rows)?;
    collect_scalar_targets(vault, snapshot, cx_id, &mut targets.rows)?;
    Ok(targets)
}

fn collect_slot_targets<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    cx: &Constellation,
    targets: &mut EraseTargets,
    policy: CompressionErasePolicy,
) -> Result<()>
where
    C: Clock,
{
    for slot in cx.slots.keys().copied() {
        if slot_has_live_manifest(vault, snapshot, slot)? {
            match policy {
                CompressionErasePolicy::RouteReseal => return Err(lifecycle_route_error(slot)),
                CompressionErasePolicy::CoordinatedDelete => {
                    stage_generation_delete(vault, snapshot, slot, targets)?;
                    continue;
                }
            }
        }
        let key = slot_key(cx.cx_id);
        push_if_visible(
            vault,
            snapshot,
            ColumnFamily::slot(slot),
            key.clone(),
            &mut targets.rows,
        )?;
        push_if_visible(
            vault,
            snapshot,
            ColumnFamily::slot_raw(slot),
            key,
            &mut targets.rows,
        )?;
    }
    Ok(())
}

fn slot_has_live_manifest<C>(vault: &AsterVault<C>, snapshot: u64, slot: SlotId) -> Result<bool>
where
    C: Clock,
{
    Ok(vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_manifest_key(slot),
        )?
        .is_some())
}

/// Stages a coordinated full-generation delete for one manifested slot: tombstone
/// every compressed primary row and raw sidecar, tombstone the manifest, and add
/// one append-only DeleteGeneration lifecycle record. Idempotent per slot.
fn stage_generation_delete<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    slot: SlotId,
    targets: &mut EraseTargets,
) -> Result<()>
where
    C: Clock,
{
    if !targets.staged_delete_slots.insert(slot.get()) {
        return Ok(());
    }
    let mut deleted: Vec<CxId> = Vec::new();
    let mut deleted_set: BTreeSet<CxId> = BTreeSet::new();
    for (key, _) in vault.scan_cf_at(snapshot, ColumnFamily::slot(slot))? {
        if let Some(cx_id) = cx_id_from_slot_key(&key)
            && deleted_set.insert(cx_id)
        {
            deleted.push(cx_id);
        }
        push_unique(&mut targets.rows, ColumnFamily::slot(slot), key);
    }
    for (key, _) in vault.scan_cf_at(snapshot, ColumnFamily::slot_raw(slot))? {
        if let Some(cx_id) = cx_id_from_slot_key(&key)
            && deleted_set.insert(cx_id)
        {
            deleted.push(cx_id);
        }
        push_unique(&mut targets.rows, ColumnFamily::slot_raw(slot), key);
    }
    push_unique(
        &mut targets.rows,
        ColumnFamily::Compression,
        compression_manifest_key(slot),
    );
    let record = GenerationLifecycleRecord::new(
        GenerationTransition::DeleteGeneration,
        slot.get(),
        snapshot,
        0,
        String::new(),
        String::new(),
        deleted.iter().map(|cx_id| hex(cx_id.as_bytes())).collect(),
    )?;
    targets.lifecycle_writes.push((
        ColumnFamily::Compression,
        compression_lifecycle_key(slot, snapshot),
        record.encode()?,
    ));
    Ok(())
}

fn cx_id_from_slot_key(key: &[u8]) -> Option<CxId> {
    <[u8; 16]>::try_from(key).ok().map(CxId::from_bytes)
}

fn lifecycle_route_error(slot: SlotId) -> CalyxError {
    CalyxError {
        code: CALYX_COMPRESSION_LIFECYCLE_INVALID,
        message: format!(
            "cannot erase individual constellation rows from compressed slot {} generation; a compressed generation sheds rows only by resealing the whole column",
            slot.get()
        ),
        remediation: "run the EraseReseal transition (Registry::erase_compressed_slot_rows) for the slot, or delete the whole generation, then retry the constellation erase",
    }
}

fn collect_range_targets<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    cf: ColumnFamily,
    range: &KeyRange,
    targets: &mut Vec<EraseTarget>,
) -> Result<()>
where
    C: Clock,
{
    for (key, _) in vault.scan_cf_range_at(snapshot, cf, range)? {
        push_unique(targets, cf, key);
    }
    Ok(())
}

fn collect_temporal_xterm_targets<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    cx_id: CxId,
    targets: &mut Vec<EraseTarget>,
) -> Result<()>
where
    C: Clock,
{
    collect_range_targets(
        vault,
        snapshot,
        ColumnFamily::TemporalXTerm,
        &temporal_xterm_prefix_range(cx_id),
        targets,
    )?;
    let id_bytes = cx_id.as_bytes();
    for (key, _) in vault.scan_cf_at(snapshot, ColumnFamily::TemporalXTerm)? {
        if key.len() >= 32 && &key[16..32] == id_bytes {
            push_unique(targets, ColumnFamily::TemporalXTerm, key);
        }
    }
    Ok(())
}

fn collect_scalar_targets<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    cx_id: CxId,
    targets: &mut Vec<EraseTarget>,
) -> Result<()>
where
    C: Clock,
{
    for (key, _) in vault.scan_cf_at(snapshot, ColumnFamily::Scalars)? {
        if key.len() >= 20 && &key[4..20] == cx_id.as_bytes() {
            push_unique(targets, ColumnFamily::Scalars, key);
        }
    }
    Ok(())
}

fn push_if_visible<C>(
    vault: &AsterVault<C>,
    snapshot: u64,
    cf: ColumnFamily,
    key: Vec<u8>,
    targets: &mut Vec<EraseTarget>,
) -> Result<()>
where
    C: Clock,
{
    if vault.read_cf_at(snapshot, cf, &key)?.is_some() {
        push_unique(targets, cf, key);
    }
    Ok(())
}

pub(super) fn affected_cfs(targets: &[EraseTarget]) -> Vec<ColumnFamily> {
    let mut cfs = Vec::new();
    for target in targets {
        if !cfs.contains(&target.cf) {
            cfs.push(target.cf);
        }
    }
    cfs
}

fn push_unique(targets: &mut Vec<EraseTarget>, cf: ColumnFamily, key: Vec<u8>) {
    if !targets
        .iter()
        .any(|target| target.cf == cf && target.key == key)
    {
        targets.push(EraseTarget { cf, key });
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
