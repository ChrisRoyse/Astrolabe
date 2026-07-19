//! Group-commit hook for adding Ledger rows to a storage write batch.

use calyx_core::{CalyxError, Clock, LedgerRef, Result};

use crate::append::{LedgerAppender, LedgerCfStore, MemoryLedgerStore, PreparedLedgerEntry};
use crate::checkpoint::{CheckpointConfig, CheckpointScheduler, OverlayLedgerStore};
use crate::entry::{ActorId, SubjectId};
use crate::kind::EntryKind;

/// One logical Ledger entry to stage inside a storage transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntryInput {
    pub kind: EntryKind,
    pub subject: SubjectId,
    pub payload: Vec<u8>,
    pub actor: ActorId,
}

impl LedgerEntryInput {
    pub const fn new(
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Self {
        Self {
            kind,
            subject,
            payload,
            actor,
        }
    }
}

/// Storage batch surface required by the Ledger group-commit hook.
pub trait LedgerWriteBatch {
    fn put_ledger_row(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()>;
}

/// Legacy direct hook surface kept crate-private so storage engines cannot
/// advance Ledger state outside their durable staged commit path.
#[allow(dead_code)] // #652: retained only to fail closed if crate-local legacy code calls it.
pub(crate) trait LedgerGroupCommitHook: Send + Sync {
    fn on_commit(
        &mut self,
        batch: &mut dyn LedgerWriteBatch,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<LedgerRef>;
}

/// In-memory batch used by unit tests and adapters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteBatch {
    ledger_rows: Vec<LedgerBatchRow>,
}

impl WriteBatch {
    pub fn ledger_rows(&self) -> &[LedgerBatchRow] {
        &self.ledger_rows
    }
}

impl LedgerWriteBatch for WriteBatch {
    fn put_ledger_row(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.ledger_rows.push(LedgerBatchRow { key, value });
        Ok(())
    }
}

/// One ledger row staged into a group-commit batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerBatchRow {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// One ledger row prepared for a storage batch but not yet committed to the appender tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedLedgerRow {
    key: Vec<u8>,
    value: Vec<u8>,
    ledger_ref: LedgerRef,
    prepared: PreparedLedgerEntry,
    checkpoint_range_end: Option<u64>,
}

impl StagedLedgerRow {
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn ledger_ref(&self) -> LedgerRef {
        self.ledger_ref.clone()
    }

    /// Whether this row is an automatically generated Merkle checkpoint rather
    /// than one of the caller's logical entries.
    pub const fn is_checkpoint(&self) -> bool {
        self.checkpoint_range_end.is_some()
    }
}

/// Default hook backed by a `LedgerAppender`.
#[derive(Debug)]
pub struct DefaultLedgerHook<S = MemoryLedgerStore, C = calyx_core::SystemClock> {
    appender: LedgerAppender<S, C>,
    checkpoint: Option<CheckpointScheduler>,
}

impl<S, C> DefaultLedgerHook<S, C>
where
    S: LedgerCfStore,
    C: Clock,
{
    pub const fn new(appender: LedgerAppender<S, C>) -> Self {
        Self {
            appender,
            checkpoint: None,
        }
    }

    pub fn with_checkpoint_config(
        appender: LedgerAppender<S, C>,
        config: CheckpointConfig,
    ) -> Result<Self> {
        let checkpoint = CheckpointScheduler::recover(config, appender.store())?;
        Ok(Self {
            appender,
            checkpoint: Some(checkpoint),
        })
    }

    pub const fn with_checkpoint_scheduler(
        appender: LedgerAppender<S, C>,
        checkpoint: CheckpointScheduler,
    ) -> Self {
        Self {
            appender,
            checkpoint: Some(checkpoint),
        }
    }

    pub const fn appender(&self) -> &LedgerAppender<S, C> {
        &self.appender
    }

    pub const fn checkpoint(&self) -> Option<&CheckpointScheduler> {
        self.checkpoint.as_ref()
    }

    pub fn stage(
        &self,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<StagedLedgerRow> {
        let prepared = self
            .appender
            .prepare(kind, subject, payload, actor)
            .map_err(group_commit_failed)?;
        Ok(StagedLedgerRow {
            key: ledger_batch_key(prepared.seq()),
            value: prepared.bytes().to_vec(),
            ledger_ref: prepared.ledger_ref(),
            prepared,
            checkpoint_range_end: None,
        })
    }

    pub fn stage_with_checkpoints(
        &self,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<Vec<StagedLedgerRow>> {
        self.stage_many_with_checkpoints([LedgerEntryInput::new(kind, subject, payload, actor)])
    }

    /// Stages several caller entries as one contiguous hash-chain segment,
    /// interleaving any due Merkle checkpoints, without mutating the appender.
    ///
    /// The returned rows are ready to join one storage batch. The caller must
    /// durably commit every row before invoking [`Self::commit_staged`] in
    /// returned order. Empty logical batches are refused.
    pub fn stage_many_with_checkpoints(
        &self,
        entries: impl IntoIterator<Item = LedgerEntryInput>,
    ) -> Result<Vec<StagedLedgerRow>> {
        let entries = entries.into_iter().collect::<Vec<_>>();
        if entries.is_empty() {
            return Err(group_commit_failed(
                "cannot stage an empty logical Ledger entry batch",
            ));
        }
        let mut staged: Vec<StagedLedgerRow> = Vec::new();
        let mut checkpoint_state = self.checkpoint.clone();
        for entry in entries {
            let prepared = match staged.last() {
                Some(predecessor) => self.appender.prepare_after(
                    &predecessor.prepared,
                    entry.kind,
                    entry.subject,
                    entry.payload,
                    entry.actor,
                )?,
                None => {
                    self.appender
                        .prepare(entry.kind, entry.subject, entry.payload, entry.actor)?
                }
            };
            let range_end = prepared
                .seq()
                .checked_add(1)
                .ok_or_else(|| CalyxError::ledger_chain_broken("ledger sequence exhausted"))?;
            staged.push(StagedLedgerRow {
                key: ledger_batch_key(prepared.seq()),
                value: prepared.bytes().to_vec(),
                ledger_ref: prepared.ledger_ref(),
                prepared,
                checkpoint_range_end: None,
            });

            if let Some(checkpoint) = checkpoint_state.as_mut()
                && checkpoint.should_checkpoint(range_end)
            {
                let overlay = OverlayLedgerStore::new(
                    self.appender.store(),
                    staged.iter().map(|row| row.prepared.clone()),
                )?;
                let predecessor = &staged.last().expect("staged data row").prepared;
                let prepared = checkpoint.prepare_checkpoint_after(
                    &self.appender,
                    &overlay,
                    predecessor,
                    range_end,
                )?;
                staged.push(StagedLedgerRow {
                    key: ledger_batch_key(prepared.seq()),
                    value: prepared.bytes().to_vec(),
                    ledger_ref: prepared.ledger_ref(),
                    prepared,
                    checkpoint_range_end: Some(range_end),
                });
                checkpoint.advance_after_checkpoint(range_end)?;
            }
        }
        Ok(staged)
    }

    pub fn commit_staged(&mut self, staged: &StagedLedgerRow) -> Result<LedgerRef> {
        let ledger_ref = self
            .appender
            .commit_prepared(&staged.prepared)
            .map_err(group_commit_failed)?;
        if let (Some(checkpoint), Some(range_end)) =
            (self.checkpoint.as_mut(), staged.checkpoint_range_end)
        {
            checkpoint
                .advance_after_checkpoint(range_end)
                .map_err(group_commit_failed)?;
        }
        Ok(ledger_ref)
    }
}

impl<S, C> LedgerGroupCommitHook for DefaultLedgerHook<S, C>
where
    S: LedgerCfStore + Send + Sync,
    C: Clock + Send + Sync,
{
    fn on_commit(
        &mut self,
        _batch: &mut dyn LedgerWriteBatch,
        _kind: EntryKind,
        _subject: SubjectId,
        _payload: Vec<u8>,
        _actor: ActorId,
    ) -> Result<LedgerRef> {
        Err(group_commit_failed(
            "direct LedgerGroupCommitHook::on_commit is disabled; use \
             stage_with_checkpoints and commit_staged after durable storage commit",
        ))
    }
}

/// Big-endian ledger CF key; must match Aster `ledger_key`.
pub fn ledger_batch_key(seq: u64) -> Vec<u8> {
    seq.to_be_bytes().to_vec()
}

/// Storage operation categories mapped to ledger entry kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOp {
    Ingest,
    VaultAdmin,
    Erase,
}

pub const fn ingest_kind_for(op: WriteOp) -> EntryKind {
    match op {
        WriteOp::Ingest => EntryKind::Ingest,
        WriteOp::VaultAdmin => EntryKind::Admin,
        WriteOp::Erase => EntryKind::Erase,
    }
}

fn group_commit_failed(message: impl ToString) -> CalyxError {
    CalyxError::ledger_group_commit_failed(message.to_string())
}
