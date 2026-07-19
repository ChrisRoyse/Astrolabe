//! The four-phase erase driver (issue #561/#562): Phase A selection under the
//! durable commit lock, unlocked handler prepare, Phase C revalidated core
//! commit, and unlocked handler commit, plus the resume path for interrupted
//! runs and the fail-closed error builders those phases raise.

use super::collect::{affected_cfs, collect_targets};
use super::handler::{
    CALYX_ERASE_HANDLER_COMMIT_INCOMPLETE, CALYX_ERASE_SEQUENCE_CONFLICT, EraseRegistry,
    EraseResult, EraseScope,
};
use super::intent::{self, EraseIntent};
use super::ledger;
use crate::cf::ColumnFamily;
use crate::compression_lifecycle::{
    CALYX_COMPRESSION_LIFECYCLE_INVALID, GenerationLifecycleRecord, GenerationTransition,
    compression_generation_subject,
};
use crate::mvcc::tombstone_value;
use crate::vault::{AsterVault, VaultContext, encode};
use calyx_core::{CalyxError, Clock, Result, SlotId};
use calyx_ledger::{EntryKind, LedgerEntryInput};
use std::collections::BTreeSet;
use std::path::Path;

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
//
// Four phases (issue #561), bounding handler work outside the durable lock,
// with the compression-erase policy (issue #562) folded into A and C:
//   A (locked)   select targets and classify the compression-erase policy — a
//                RouteReseal refusal fails closed here, before any handler runs;
//                a CoordinatedDelete stages the manifest tombstone + one
//                DeleteGeneration lifecycle record per generation. Resolve
//                interrupted/already-done runs, write the durable intent record,
//                then release the lock.
//   B (unlocked) prepare every handler; a failure aborts prepared handlers and
//                fails closed with no core write.
//   C (locked)   revalidate the selection (including the staged lifecycle
//                writes) against current vault state; on a match, atomically
//                commit the tombstone rows + coordinated DeleteGeneration
//                lifecycle record(s) + ledger evidence in one batch.
//   D (unlocked) commit every handler; a failure retains the intent for resume.
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
    // Phase A: everything that touches the selected snapshot runs under the lock.
    let decision = vault.with_durable_commit_lock(|| erase_phase_a(vault, &scope, registry))?;
    match decision {
        EraseDecision::AlreadyTombstoned { seq, shred } => {
            if shred {
                vault_ctx.shred_key_for_erasure();
            }
            Err(CalyxError::erase_already_tombstoned(format!(
                "erase scope already has ledger tombstone at seq {seq}"
            )))
        }
        EraseDecision::ResumeCommit { intent } => {
            resume_commit(vault, &scope, vault_ctx, registry, &intent)
        }
        EraseDecision::EmptyScope { records_deleted } => {
            // Non-Vault scope with nothing to tombstone. Handlers still run (they
            // may own derived rows keyed differently) but there is no core commit
            // and no crash-consistency gap to record, so no intent is persisted.
            registry.prepare_all(&scope, vault.vault_id())?;
            if let Err(failures) = registry.commit_all(&scope, vault.vault_id()) {
                return Err(commit_incomplete_error(None, &failures));
            }
            Ok(EraseResult {
                scope,
                records_deleted,
                shredded_at: vault.clock_now(),
            })
        }
        EraseDecision::Selected(selection) => {
            erase_selected(vault, scope, vault_ctx, registry, selection)
        }
    }
}

/// The Phase A outcome, computed under the durable commit lock.
enum EraseDecision {
    /// Scope already tombstoned with no pending intent: idempotent no-op error.
    AlreadyTombstoned { seq: u64, shred: bool },
    /// Interrupted run: core tombstone is durable, handler commits may be
    /// incomplete. Resume Phase D only.
    ResumeCommit { intent: EraseIntent },
    /// Non-Vault scope with no rows to tombstone: run handlers, no core commit.
    EmptyScope { records_deleted: usize },
    /// Full erase selection prepared (and, for durable vaults, intent persisted).
    Selected(Selection),
}

/// The tombstone selection carried from Phase A to Phase C.
struct Selection {
    snapshot: u64,
    real_ledger: bool,
    rows: Vec<encode::WriteRow>,
    /// Coordinated compressed-generation delete writes (issue #562): the
    /// append-only `DeleteGeneration` lifecycle record(s) that must be committed
    /// in the same Phase C batch as the manifest and row tombstones, or the MVCC
    /// lifecycle guard refuses the batch. Empty unless a full-vault erase touched
    /// a live compressed generation.
    lifecycle_writes: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)>,
    affected: Vec<ColumnFamily>,
    records_deleted: usize,
    rows_tombstoned: usize,
    shred: bool,
}

fn erase_phase_a<C>(
    vault: &AsterVault<C>,
    scope: &EraseScope,
    registry: &EraseRegistry,
) -> Result<EraseDecision>
where
    C: Clock,
{
    let snapshot = vault.latest_seq();
    let real_ledger = vault.has_real_ledger_hook();
    let durable_root = vault.durable_root().map(Path::to_path_buf);

    let existing_intent = match &durable_root {
        Some(root) => intent::load_intent(root, scope)?,
        None => None,
    };
    let tombstone = if real_ledger {
        ledger::existing_tombstone(vault, scope, snapshot)?
    } else {
        None
    };

    match (tombstone, existing_intent) {
        (Some(_), Some(intent)) => {
            // Core tombstone durable + intent present: crashed during Phase D.
            return Ok(EraseDecision::ResumeCommit { intent });
        }
        (Some(ts), None) => {
            let shred = *scope == EraseScope::Vault || ts.records_deleted > 0;
            return Ok(EraseDecision::AlreadyTombstoned { seq: ts.seq, shred });
        }
        (None, Some(_stale)) => {
            // Intent present but no core tombstone: crashed before the Phase C
            // core commit. The prior attempt's handlers only ever prepared;
            // abort them (idempotent) and drop the stale intent, then reselect.
            registry.abort_all(scope, vault.vault_id());
            if let Some(root) = &durable_root {
                intent::remove_intent(root, scope)?;
            }
        }
        (None, None) => {}
    }

    // `collect_targets` applies the compression-erase policy (issue #562):
    // `RouteReseal` for Cx/Subject scopes that touch a live compressed generation
    // fails closed HERE — under the Phase A lock, before any handler prepare —
    // routing the caller to a reseal; `CoordinatedDelete` for a full-vault erase
    // stages the manifest/row tombstones plus one DeleteGeneration lifecycle
    // record per generation into `targets.lifecycle_writes`.
    let targets = collect_targets(vault, scope, snapshot)?;
    let rows_tombstoned = targets.rows.len();
    if *scope != EraseScope::Vault && rows_tombstoned == 0 {
        return Ok(EraseDecision::EmptyScope {
            records_deleted: targets.records_deleted,
        });
    }
    // Issue #562: a coordinated full-generation delete must pair its append-only
    // DeleteGeneration lifecycle record with a hash-chained ledger entry in the
    // same Phase C batch. Without a real ledger hook there is no lawful way to
    // record the transition, so the erase fails closed before any handler runs.
    if !targets.lifecycle_writes.is_empty() && !real_ledger {
        return Err(CalyxError {
            code: CALYX_COMPRESSION_LIFECYCLE_INVALID,
            message: format!(
                "vault erase of {} compressed slot generation(s) requires a real ledger hook to record each DeleteGeneration transition",
                targets.lifecycle_writes.len()
            ),
            remediation: "open the vault with its ledger hook so the coordinated generation delete can pair its manifest tombstone with a hash-chained ledger entry",
        });
    }
    let affected = affected_cfs(&targets.rows);
    let row_tombstone = tombstone_value();
    let rows = targets
        .rows
        .iter()
        .map(|target| encode::WriteRow {
            cf: target.cf,
            key: target.key.clone(),
            value: row_tombstone.clone(),
        })
        .collect::<Vec<_>>();
    let lifecycle_writes = targets.lifecycle_writes.clone();
    let shred = *scope == EraseScope::Vault || rows_tombstoned > 0;
    if let Some(root) = &durable_root {
        let intent = EraseIntent {
            version: intent::ERASE_INTENT_VERSION,
            scope: scope.clone(),
            vault_id: vault.vault_id(),
            selected_seq: snapshot,
            records_deleted: targets.records_deleted,
            rows_tombstoned,
            shred_key: shred,
            handler_names: registry.handler_names(),
        };
        intent::write_intent(root, &intent)?;
    }
    Ok(EraseDecision::Selected(Selection {
        snapshot,
        real_ledger,
        rows,
        lifecycle_writes,
        affected,
        records_deleted: targets.records_deleted,
        rows_tombstoned,
        shred,
    }))
}

fn erase_selected<C>(
    vault: &AsterVault<C>,
    scope: EraseScope,
    vault_ctx: &mut VaultContext,
    registry: &EraseRegistry,
    selection: Selection,
) -> Result<EraseResult>
where
    C: Clock,
{
    let vault_id = vault.vault_id();
    let durable_root = vault.durable_root().map(Path::to_path_buf);

    // Phase B (UNLOCKED): prepare handlers. prepare_all self-aborts on failure.
    if let Err(error) = registry.prepare_all(&scope, vault_id) {
        if let Some(root) = &durable_root {
            intent::remove_intent(root, &scope)?;
        }
        return Err(error);
    }

    // Phase C (LOCKED): revalidate the selection, then commit atomically.
    let commit_outcome =
        vault.with_durable_commit_lock(|| erase_phase_c(vault, &scope, &selection));
    let records_deleted = match commit_outcome {
        Ok(records) => records,
        Err(error) => {
            // A sequence conflict is a pre-commit divergence: nothing was
            // written, so it is safe to abort handlers and drop the intent. Any
            // other error may have committed the WAL batch, so keep the intent
            // (resume-able) and leave prepared handlers untouched.
            if error.code == CALYX_ERASE_SEQUENCE_CONFLICT {
                registry.abort_all(&scope, vault_id);
                if let Some(root) = &durable_root {
                    intent::remove_intent(root, &scope)?;
                }
            }
            return Err(error);
        }
    };

    // Core tombstones are now durable.
    if selection.shred {
        vault_ctx.shred_key_for_erasure();
    }

    // Phase D (UNLOCKED): commit handlers.
    match registry.commit_all(&scope, vault_id) {
        Ok(()) => {
            if let Some(root) = &durable_root {
                intent::remove_intent(root, &scope)?;
            }
            Ok(EraseResult {
                scope,
                records_deleted,
                shredded_at: vault.clock_now(),
            })
        }
        Err(failures) => Err(commit_incomplete_error(
            durable_root
                .as_deref()
                .map(|root| intent::intent_path_display(root, &scope)),
            &failures,
        )),
    }
}

/// Phase C: revalidate the Phase A selection under the lock and, on a match,
/// commit the tombstone rows plus ledger evidence in one atomic group commit.
///
/// For a coordinated compressed-generation delete (issue #562) the same batch
/// also carries the staged `DeleteGeneration` lifecycle record(s) alongside the
/// manifest and row tombstones, so the MVCC lifecycle guard admits the manifest
/// tombstone (an isolated manifest tombstone, or one missing its lifecycle
/// record, is refused). The revalidation includes the lifecycle-write count so a
/// generation that appeared or was resealed between Phase A and Phase C fails
/// closed with a sequence conflict rather than committing a stale batch.
fn erase_phase_c<C>(
    vault: &AsterVault<C>,
    scope: &EraseScope,
    selection: &Selection,
) -> Result<usize>
where
    C: Clock,
{
    let current_seq = vault.latest_seq();
    // A concurrent erase may have already tombstoned this scope.
    if selection.real_ledger && ledger::existing_tombstone(vault, scope, current_seq)?.is_some() {
        return Err(sequence_conflict_error(selection.snapshot, current_seq));
    }
    let targets = collect_targets(vault, scope, current_seq)?;
    let now: BTreeSet<(ColumnFamily, Vec<u8>)> = targets
        .rows
        .iter()
        .map(|target| (target.cf, target.key.clone()))
        .collect();
    let selected: BTreeSet<(ColumnFamily, Vec<u8>)> = selection
        .rows
        .iter()
        .map(|row| (row.cf, row.key.clone()))
        .collect();
    if now != selected
        || targets.records_deleted != selection.records_deleted
        || targets.lifecycle_writes.len() != selection.lifecycle_writes.len()
    {
        return Err(sequence_conflict_error(selection.snapshot, current_seq));
    }
    // Commit the row tombstones and, for a coordinated generation delete, the
    // append-only DeleteGeneration lifecycle record(s) in ONE batch so the MVCC
    // lifecycle guard admits the manifest tombstone (issue #562). The lifecycle
    // records were staged at the Phase A snapshot and are replayed verbatim now
    // that the selection revalidated unchanged.
    let mut commit_rows = selection.rows.clone();
    for (cf, key, value) in &selection.lifecycle_writes {
        commit_rows.push(encode::WriteRow {
            cf: *cf,
            key: key.clone(),
            value: value.clone(),
        });
    }
    if selection.real_ledger {
        let tombstone =
            ledger::tombstone_for(vault, scope, selection.records_deleted, vault.clock_now())?;
        let mut delete_records = selection
            .lifecycle_writes
            .iter()
            .map(|(_, _, value)| GenerationLifecycleRecord::parse(value))
            .collect::<Result<Vec<_>>>()?;
        delete_records.sort_by_key(|record| record.slot_id);
        let mut ledger_entries = Vec::with_capacity(delete_records.len() + 1);
        ledger_entries.push(LedgerEntryInput::new(
            EntryKind::Erase,
            ledger::tombstone_subject(&tombstone),
            tombstone.as_ledger_payload(),
            tombstone.actor.clone(),
        ));
        for record in delete_records {
            if record.transition != GenerationTransition::DeleteGeneration {
                return Err(CalyxError {
                    code: CALYX_COMPRESSION_LIFECYCLE_INVALID,
                    message: format!(
                        "vault erase staged non-delete compression transition {} for slot {}",
                        record.transition.as_str(),
                        record.slot_id
                    ),
                    remediation: "reselect the vault erase so every manifested slot stages exactly one DeleteGeneration lifecycle record",
                });
            }
            ledger_entries.push(LedgerEntryInput::new(
                EntryKind::Erase,
                compression_generation_subject(SlotId::new(record.slot_id)),
                record.ledger_payload()?,
                tombstone.actor.clone(),
            ));
        }
        let ledger_refs =
            vault.commit_rows_with_ledger_entries_locked(commit_rows, ledger_entries)?;
        debug_assert_eq!(
            ledger_refs.first().map(|ledger_ref| ledger_ref.seq),
            Some(tombstone.seq)
        );
    } else {
        // A non-ledger vault never reaches here with lifecycle writes: Phase A
        // fails closed on `CALYX_COMPRESSION_LIFECYCLE_INVALID` first.
        vault.commit_rows_locked(&commit_rows)?;
    }
    if selection.rows_tombstoned > 0 {
        vault.purge_tombstoned_cfs_locked(&selection.affected)?;
    }
    Ok(selection.records_deleted)
}

/// Resume an erase whose core tombstones are durable but whose handler commits
/// were interrupted (Phase D only). Idempotent: re-runs `commit` on all handlers.
fn resume_commit<C>(
    vault: &AsterVault<C>,
    scope: &EraseScope,
    vault_ctx: &mut VaultContext,
    registry: &EraseRegistry,
    intent: &EraseIntent,
) -> Result<EraseResult>
where
    C: Clock,
{
    let vault_id = vault.vault_id();
    let durable_root = vault.durable_root().map(Path::to_path_buf);
    if intent.shred_key {
        vault_ctx.shred_key_for_erasure();
    }
    match registry.commit_all(scope, vault_id) {
        Ok(()) => {
            if let Some(root) = &durable_root {
                intent::remove_intent(root, scope)?;
            }
            Ok(EraseResult {
                scope: scope.clone(),
                records_deleted: intent.records_deleted,
                shredded_at: vault.clock_now(),
            })
        }
        Err(failures) => Err(commit_incomplete_error(
            durable_root
                .as_deref()
                .map(|root| intent::intent_path_display(root, scope)),
            &failures,
        )),
    }
}

fn sequence_conflict_error(selected_seq: u64, current_seq: u64) -> CalyxError {
    CalyxError {
        code: CALYX_ERASE_SEQUENCE_CONFLICT,
        message: format!(
            "erase selection at seq {selected_seq} no longer matches vault state at seq {current_seq}; no rows were written"
        ),
        remediation: "re-run erase against current state",
    }
}

fn commit_incomplete_error(intent_path: Option<String>, failures: &[String]) -> CalyxError {
    let path = intent_path.unwrap_or_else(|| "(volatile vault: no intent record)".to_string());
    CalyxError {
        code: CALYX_ERASE_HANDLER_COMMIT_INCOMPLETE,
        message: format!(
            "core tombstones are durable but {} erase handler commit(s) are incomplete [{}]; intent record retained at {path}",
            failures.len(),
            failures.join("; ")
        ),
        remediation: "re-run erase for the same scope to resume the incomplete handler commits from the retained intent record",
    }
}
