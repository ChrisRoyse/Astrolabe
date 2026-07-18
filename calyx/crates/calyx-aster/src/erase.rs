//! Lawful/user-requested erasure for Aster vault content (PH61 T01).

mod ledger;

use std::collections::BTreeSet;

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
use calyx_core::{CalyxError, Clock, Constellation, CxId, Result, SlotId, Ts, VaultId};
use calyx_ledger::{EntryKind, SubjectId};
use serde::{Deserialize, Serialize};

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

/// Metadata key used by `EraseScope::Subject`.
///
/// Store `subject_metadata_value(subject)` in constellation metadata under this
/// key to make a subject-level erasure select that constellation.
pub const METADATA_SUBJECT_ID: &str = "subject_id";

/// One lawful erase target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EraseScope {
    Vault,
    Cx(CxId),
    Subject(SubjectId),
}

/// Result of an erase operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EraseResult {
    pub scope: EraseScope,
    /// Number of base constellations erased. Derived CF rows are tombstoned too.
    pub records_deleted: usize,
    pub shredded_at: Ts,
}

/// Pluggable cleanup hook for derived data owned outside Aster's core CFs.
pub trait EraseHandler: Send + Sync {
    fn erase(&self, scope: &EraseScope, vault_id: VaultId) -> Result<()>;
}

/// Handler collection run during erasure.
#[derive(Default)]
pub struct EraseRegistry {
    handlers: Vec<Box<dyn EraseHandler>>,
}

impl EraseRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_handler<H>(&mut self, handler: H)
    where
        H: EraseHandler + 'static,
    {
        self.handlers.push(Box::new(handler));
    }

    pub fn run_all(&self, scope: &EraseScope, vault_id: VaultId) -> Result<()> {
        for handler in &self.handlers {
            handler.erase(scope, vault_id)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for EraseRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EraseRegistry")
            .field("handler_count", &self.handlers.len())
            .finish()
    }
}

/// No-op derived-data eraser for crates that have no rows to remove yet.
#[derive(Debug, Default)]
pub struct NoopEraseHandler;

impl EraseHandler for NoopEraseHandler {
    fn erase(&self, _scope: &EraseScope, _vault_id: VaultId) -> Result<()> {
        Ok(())
    }
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    pub fn erase(
        &self,
        scope: EraseScope,
        vault_ctx: &mut VaultContext,
        registry: &EraseRegistry,
    ) -> Result<EraseResult> {
        erase(self, scope, vault_ctx, registry)
    }
}

// A25 ("never delete to compress") does NOT forbid this operation.
// Erasure is lawful/user-requested deletion, explicitly required by A33.
// No reviewer may reject a lawful erase citing A25.
pub fn erase<C>(
    vault: &AsterVault<C>,
    scope: EraseScope,
    vault_ctx: &mut VaultContext,
    registry: &EraseRegistry,
) -> Result<EraseResult>
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
        let real_ledger = vault.has_real_ledger_hook();
        if real_ledger && let Some(tombstone) = ledger::existing_tombstone(vault, &scope, snapshot)?
        {
            if scope == EraseScope::Vault || tombstone.records_deleted > 0 {
                vault_ctx.shred_key_for_erasure();
            }
            return Err(CalyxError::erase_already_tombstoned(format!(
                "erase scope already has ledger tombstone at seq {}",
                tombstone.seq
            )));
        }
        let targets = collect_targets(vault, &scope, snapshot)?;
        registry.run_all(&scope, vault.vault_id())?;
        let rows_tombstoned = targets.rows.len();
        if scope != EraseScope::Vault && rows_tombstoned == 0 {
            return Ok(EraseResult {
                scope,
                records_deleted: targets.records_deleted,
                shredded_at: vault.clock_now(),
            });
        }
        let affected = affected_cfs(&targets.rows);
        let row_tombstone = tombstone_value();
        let mut rows = targets
            .rows
            .iter()
            .map(|target| encode::WriteRow {
                cf: target.cf,
                key: target.key.clone(),
                value: row_tombstone.clone(),
            })
            .collect::<Vec<_>>();
        // Issue #562: a coordinated full-generation delete must carry its
        // append-only DeleteGeneration lifecycle record and a paired ledger entry
        // in the same batch, or the commit-time guard refuses the manifest
        // tombstone. Without a real ledger hook there is no lawful way to record
        // the transition, so the vault erase fails closed.
        if !targets.lifecycle_writes.is_empty() {
            if !real_ledger {
                return Err(CalyxError {
                    code: CALYX_COMPRESSION_LIFECYCLE_INVALID,
                    message: format!(
                        "vault erase of {} compressed slot generation(s) requires a real ledger hook to record each DeleteGeneration transition",
                        targets.lifecycle_writes.len()
                    ),
                    remediation: "open the vault with its ledger hook so the coordinated generation delete can pair its manifest tombstone with a hash-chained ledger entry",
                });
            }
            for (cf, key, value) in &targets.lifecycle_writes {
                rows.push(encode::WriteRow {
                    cf: *cf,
                    key: key.clone(),
                    value: value.clone(),
                });
            }
        }
        if real_ledger {
            let tombstone =
                ledger::tombstone_for(vault, &scope, targets.records_deleted, vault.clock_now())?;
            let ledger_ref = vault.commit_rows_with_ledger_entry_locked(
                rows,
                EntryKind::Erase,
                ledger::tombstone_subject(&tombstone),
                tombstone.as_ledger_payload(),
                tombstone.actor.clone(),
            )?;
            debug_assert_eq!(ledger_ref.seq, tombstone.seq);
        } else {
            vault.commit_rows_locked(&rows)?;
        }
        if rows_tombstoned > 0 {
            vault.purge_tombstoned_cfs_locked(&affected)?;
        }
        if scope == EraseScope::Vault || rows_tombstoned > 0 {
            vault_ctx.shred_key_for_erasure();
        }
        Ok(EraseResult {
            scope,
            records_deleted: targets.records_deleted,
            shredded_at: vault.clock_now(),
        })
    })
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
    Ok(erase_cf_records_summary(vault, scope, vault_ctx, None)?.records_deleted)
}

fn erase_cf_records_summary<C>(
    vault: &AsterVault<C>,
    scope: &EraseScope,
    vault_ctx: &VaultContext,
    registry: Option<&EraseRegistry>,
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
        if let Some(registry) = registry {
            registry.run_all(scope, vault.vault_id())?;
        }
        if !targets.lifecycle_writes.is_empty() {
            // This ledger-free path cannot pair a manifest tombstone with its
            // DeleteGeneration record; fail closed rather than trip the commit
            // guard (issue #562).
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
struct EraseTarget {
    cf: ColumnFamily,
    key: Vec<u8>,
}

#[derive(Debug, Default)]
struct EraseTargets {
    rows: Vec<EraseTarget>,
    records_deleted: usize,
    /// Non-tombstone rows (DeleteGeneration lifecycle records) that must be
    /// committed alongside the tombstones for a coordinated generation delete.
    lifecycle_writes: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>,
    /// Slots whose full-generation delete has already been staged, so a slot
    /// referenced by several constellations is deleted exactly once.
    staged_delete_slots: BTreeSet<u16>,
}

#[derive(Debug)]
struct EraseWriteSummary {
    records_deleted: usize,
}

fn collect_targets<C>(
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

fn affected_cfs(targets: &[EraseTarget]) -> Vec<ColumnFamily> {
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
