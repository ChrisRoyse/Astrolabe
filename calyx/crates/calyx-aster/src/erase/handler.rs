//! Erase scopes, result, the two-phase handler contract, and the handler
//! registry that drives prepare/commit/abort across derived-data owners.

use calyx_core::{CalyxError, CxId, Result, Ts, VaultId};
use calyx_ledger::SubjectId;
use serde::{Deserialize, Serialize};

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
    pub(super) fn handler_names(&self) -> Vec<String> {
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
    pub(super) fn prepare_all(&self, scope: &EraseScope, vault_id: VaultId) -> Result<()> {
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
    pub(super) fn commit_all(
        &self,
        scope: &EraseScope,
        vault_id: VaultId,
    ) -> std::result::Result<(), Vec<String>> {
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
    fn abort_prepared(
        &self,
        prepared: usize,
        scope: &EraseScope,
        vault_id: VaultId,
    ) -> Vec<String> {
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
    pub(super) fn abort_all(&self, scope: &EraseScope, vault_id: VaultId) -> Vec<String> {
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

fn prepare_failed_error(
    handler: &str,
    error: &CalyxError,
    abort_outcomes: &[String],
) -> CalyxError {
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
