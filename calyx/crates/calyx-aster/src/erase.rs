//! Lawful/user-requested erasure for Aster vault content (PH61 T01).
//!
//! Erasure is a two-source-of-truth operation: Aster core CFs (tombstoned
//! atomically under the durable commit lock) and derived state owned by external
//! [`EraseHandler`]s. Issue #561 splits handler work into an explicit two-phase
//! contract run **outside** the durable commit lock, with a durable
//! [intent record](intent) written before any handler side effect so an
//! interrupted erase resumes deterministically and never reports partial work as
//! success.
//!
//! Issue #562 layers the compression-erase policy onto that selection. A slot
//! carrying a live compressed generation manifest is classified during Phase A
//! selection (and revalidated in Phase C): a Constellation/Subject-scoped erase
//! fails closed with [`CompressionErasePolicy::RouteReseal`] — before any handler
//! prepare — routing the caller to a reseal, while a full-vault erase takes
//! [`CompressionErasePolicy::CoordinatedDelete`], staging the manifest tombstone,
//! every compressed primary/raw row tombstone, and exactly one append-only
//! `DeleteGeneration` lifecycle record per generation. Those lifecycle records
//! ride the Phase C core commit in the same batch as the tombstones so the MVCC
//! lifecycle guard admits the manifest tombstone. Every ledger write — the
//! erase-intent tombstone entry included — flows through the single durable-lock
//! acquisition commit path (issue #560).

mod intent;
mod ledger;

use std::collections::BTreeSet;
use std::path::Path;

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
use intent::EraseIntent;
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

/// Fail-closed error code: an erase handler's `prepare` phase failed. No core
/// rows were written; all previously prepared handlers were aborted.
pub const CALYX_ERASE_HANDLER_PREPARE_FAILED: &str = "CALYX_ERASE_HANDLER_PREPARE_FAILED";

/// Fail-closed error code: the erase selection made under the lock in Phase A no
/// longer matches vault state at the Phase C revalidation. No rows were written.
pub const CALYX_ERASE_SEQUENCE_CONFLICT: &str = "CALYX_ERASE_SEQUENCE_CONFLICT";

/// Fail-closed error code: the Aster core tombstones committed durably, but one
/// or more handler commits did not complete. The intent record is retained so a
/// re-run of erase for the same scope resumes the incomplete handler commits.
pub const CALYX_ERASE_HANDLER_COMMIT_INCOMPLETE: &str = "CALYX_ERASE_HANDLER_COMMIT_INCOMPLETE";

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

/// Two-phase cleanup hook for derived data owned outside Aster's core CFs.
///
/// Handlers run **outside** the durable commit lock (issue #561), so a handler
/// may safely call back into any durable vault write without deadlocking. The
/// two phases bound side effects to a revalidated core commit:
///
/// - [`prepare`](EraseHandler::prepare): stage/validate the derived erase
///   without irreversibly destroying anything. Runs before the core tombstone
///   commit; a failure aborts the erase with no core write.
/// - [`commit`](EraseHandler::commit): perform the irreversible derived erase.
///   Runs only after the Aster core tombstones are durable.
/// - [`abort`](EraseHandler::abort): undo a `prepare` when the erase is not
///   going to commit (prepare failure elsewhere, or a sequence conflict).
///
/// `commit` and `abort` MUST be idempotent: a resumed erase re-invokes `commit`,
/// and `abort` may run against handlers that never prepared.
pub trait EraseHandler: Send + Sync {
    /// Stable handler name used in diagnostics and the intent record.
    fn name(&self) -> &str;

    /// Phase B: reversibly stage the derived erase. Must not destroy state.
    fn prepare(&self, scope: &EraseScope, vault_id: VaultId) -> Result<()>;

    /// Phase D: irreversibly complete the derived erase. Must be idempotent.
    fn commit(&self, scope: &EraseScope, vault_id: VaultId) -> Result<()>;

    /// Undo a prepared but uncommitted derived erase. Must be idempotent.
    fn abort(&self, scope: &EraseScope, vault_id: VaultId) -> Result<()>;
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

    /// Owned names of every registered handler (recorded in the intent record).
    fn handler_names(&self) -> Vec<String> {
        self.handlers
            .iter()
            .map(|handler| handler.name().to_string())
            .collect()
    }

    /// Phase B: prepare every handler in registration order (outside the lock).
    ///
    /// On the first failure, aborts every already-prepared handler in reverse
    /// order (collecting their outcomes) and returns a fail-closed
    /// [`CALYX_ERASE_HANDLER_PREPARE_FAILED`] naming the failing handler. On
    /// success every handler is prepared.
    fn prepare_all(&self, scope: &EraseScope, vault_id: VaultId) -> Result<()> {
        let mut prepared = 0usize;
        for handler in &self.handlers {
            match handler.prepare(scope, vault_id) {
                Ok(()) => prepared += 1,
                Err(error) => {
                    let outcomes = self.abort_prepared(prepared, scope, vault_id);
                    return Err(prepare_failed_error(handler.name(), &error, &outcomes));
                }
            }
        }
        Ok(())
    }

    /// Phase D: commit every handler (all attempted; first error reported).
    ///
    /// Returns the per-handler failure descriptions when any commit fails, so the
    /// caller can build the fail-closed error with the retained intent path.
    fn commit_all(&self, scope: &EraseScope, vault_id: VaultId) -> std::result::Result<(), Vec<String>> {
        let mut failures = Vec::new();
        for handler in &self.handlers {
            if let Err(error) = handler.commit(scope, vault_id) {
                failures.push(format!(
                    "{}: [{}]: {}",
                    handler.name(),
                    error.code,
                    error.message
                ));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }

    /// Aborts the first `prepared` handlers in reverse order, never panicking.
    /// Returns a human-readable outcome per handler for diagnostics.
    fn abort_prepared(&self, prepared: usize, scope: &EraseScope, vault_id: VaultId) -> Vec<String> {
        let mut outcomes = Vec::new();
        for handler in self.handlers.iter().take(prepared).rev() {
            match handler.abort(scope, vault_id) {
                Ok(()) => outcomes.push(format!("{}: aborted", handler.name())),
                Err(error) => outcomes.push(format!(
                    "{}: abort failed [{}]: {}",
                    handler.name(),
                    error.code,
                    error.message
                )),
            }
        }
        outcomes
    }

    /// Aborts every handler (idempotent cleanup for conflict/stale-intent paths).
    fn abort_all(&self, scope: &EraseScope, vault_id: VaultId) -> Vec<String> {
        self.abort_prepared(self.handlers.len(), scope, vault_id)
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
    fn name(&self) -> &str {
        "noop"
    }

    fn prepare(&self, _scope: &EraseScope, _vault_id: VaultId) -> Result<()> {
        Ok(())
    }

    fn commit(&self, _scope: &EraseScope, _vault_id: VaultId) -> Result<()> {
        Ok(())
    }

    fn abort(&self, _scope: &EraseScope, _vault_id: VaultId) -> Result<()> {
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
            return Ok(EraseDecision::AlreadyTombstoned {
                seq: ts.seq,
                shred,
            });
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
    if selection.real_ledger
        && ledger::existing_tombstone(vault, scope, current_seq)?.is_some()
    {
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
        let ledger_ref = vault.commit_rows_with_ledger_entry_locked(
            commit_rows,
            EntryKind::Erase,
            ledger::tombstone_subject(&tombstone),
            tombstone.as_ledger_payload(),
            tombstone.actor.clone(),
        )?;
        debug_assert_eq!(ledger_ref.seq, tombstone.seq);
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

fn prepare_failed_error(handler: &str, error: &CalyxError, abort_outcomes: &[String]) -> CalyxError {
    CalyxError {
        code: CALYX_ERASE_HANDLER_PREPARE_FAILED,
        message: format!(
            "erase handler {handler} failed to prepare [{}]: {}; aborted prepared handlers [{}]; no core rows were written",
            error.code,
            error.message,
            abort_outcomes.join("; ")
        ),
        remediation: "fix the failing erase handler and re-run erase; the vault core was not modified",
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
