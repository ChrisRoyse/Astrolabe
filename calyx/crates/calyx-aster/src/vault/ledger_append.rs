use super::{AsterVault, encode, ledger_hook};
use crate::cf::{ColumnFamily, anchor_key, base_key, ledger_key};
use crate::ledger_view::parse_aster_ledger_seq;
use calyx_core::{Anchor, CalyxError, Clock, CxId, LedgerRef, Result, VaultStore};
use calyx_ledger::{
    ActorId, EntryKind, LedgerAppender, LedgerCfStore, LedgerEntryInput, LedgerHeadAnchor,
    LedgerRow, PreparedLedgerEntry, SubjectId,
};

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Adds an anchor and stamps the stored base row with the same ledger ref.
    ///
    /// Grounding does not consume slot vectors. The read-modify-write therefore
    /// uses the lossless Base record directly, preserving its sealed slot hashes
    /// without opening, decoding, or substituting any slot representation.
    pub fn anchor_with_ledger_entry(
        &self,
        id: CxId,
        anchor: Anchor,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<LedgerRef> {
        let entry = LedgerEntryInput {
            kind,
            subject,
            payload,
            actor,
        };
        anchor.validate_schema()?;
        self.with_durable_commit_lock(|| {
            let latest = self.snapshot();
            let base = self
                .read_cf_at(latest, ColumnFamily::Base, &base_key(id))?
                .ok_or_else(|| CalyxError::stale_derived("constellation missing at snapshot"))?;
            let mut record = encode::BaseRecord::decode_for_key(id, &base)?;
            if record.vault_id() != self.vault_id {
                return Err(CalyxError::vault_access_denied(format!(
                    "Base row for cx {id} belongs to another vault"
                )));
            }
            record.anchors_mut().push(anchor.clone());
            let ungrounded = record.constellation().anchors.is_empty();
            record.flags_mut().ungrounded = ungrounded;
            record.constellation().validate_schema()?;
            let Some(hook) = &self.ledger_hook else {
                return self.anchor_with_raw_ledger_entry(id, &mut record, anchor, entry);
            };
            let mut guard = ledger_hook::lock_hook(hook)?;
            let staged = guard.stage_with_checkpoints(
                entry.kind,
                entry.subject,
                entry.payload,
                entry.actor,
            )?;
            let ledger_ref = staged
                .first()
                .ok_or_else(|| CalyxError::ledger_group_commit_failed("no staged ledger rows"))?
                .ledger_ref();
            record.set_provenance(ledger_ref.clone());
            let mut rows = anchor_rows(id, &record, &anchor)?;
            rows.extend(staged.iter().map(|row| encode::WriteRow {
                cf: ColumnFamily::Ledger,
                key: row.key().to_vec(),
                value: row.value().to_vec(),
            }));
            self.commit_rows_locked(&rows)?;
            for row in &staged {
                guard.commit_staged(row)?;
            }
            Ok(ledger_ref)
        })
    }

    /// Writes a seq-guarded raw CF batch and one provenance Ledger entry in the
    /// same atomic group commit.
    ///
    /// The sequence comparison, the CF rows, and the hash-chained Ledger row all
    /// share one commit: either the complete batch plus its ledger transition is
    /// durable, or nothing is. Used by replace-style workflows (for example the
    /// registry compression generation rewrite) that must never persist state
    /// without its paired ledger entry.
    ///
    /// Fail-closed: a stale `expected_seq` returns
    /// `CALYX_ASTER_SEQUENCE_CONFLICT` and writes nothing.
    pub fn write_cf_batch_with_ledger_entry_if_seq(
        &self,
        expected_seq: calyx_core::Seq,
        rows: impl IntoIterator<Item = (ColumnFamily, Vec<u8>, Vec<u8>)>,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<(calyx_core::Seq, LedgerRef)> {
        let (seq, refs) = self.write_cf_batch_with_ledger_entries_if_seq(
            expected_seq,
            rows,
            [LedgerEntryInput::new(kind, subject, payload, actor)],
        )?;
        Ok((seq, require_single_ledger_ref(refs)?))
    }

    /// Writes a seq-guarded raw CF batch and several ordered provenance Ledger
    /// entries inside one atomic group commit.
    ///
    /// Logical entries form one contiguous hash-chain segment. Any due Merkle
    /// checkpoints are interleaved automatically, and the returned refs contain
    /// only the caller's entries in input order. An empty entry set is refused.
    pub fn write_cf_batch_with_ledger_entries_if_seq(
        &self,
        expected_seq: calyx_core::Seq,
        rows: impl IntoIterator<Item = (ColumnFamily, Vec<u8>, Vec<u8>)>,
        entries: impl IntoIterator<Item = LedgerEntryInput>,
    ) -> Result<(calyx_core::Seq, Vec<LedgerRef>)> {
        let rows = rows
            .into_iter()
            .map(|(cf, key, value)| encode::WriteRow { cf, key, value })
            .collect::<Vec<_>>();
        let entries = entries.into_iter().collect::<Vec<_>>();
        require_ledger_entries(&entries)?;
        if self.durable.is_none() {
            return self.write_volatile_batch_with_ledger_entries_if_seq(
                expected_seq,
                rows,
                entries,
            );
        }
        self.with_durable_commit_lock(|| {
            let current = self.latest_seq();
            if current != expected_seq {
                return Err(sequence_conflict_error(expected_seq, current));
            }
            let ledger_refs = self.commit_rows_with_ledger_entries_locked(rows, entries)?;
            Ok((self.latest_seq(), ledger_refs))
        })
    }

    fn write_volatile_batch_with_ledger_entries_if_seq(
        &self,
        expected_seq: calyx_core::Seq,
        mut rows: Vec<encode::WriteRow>,
        entries: Vec<LedgerEntryInput>,
    ) -> Result<(calyx_core::Seq, Vec<LedgerRef>)> {
        let Some(hook) = &self.ledger_hook else {
            let (ledger_rows, ledger_refs) = self.raw_prepared_ledger_rows(entries)?;
            rows.extend(ledger_rows);
            let seq = self.commit_rows_if_current_volatile(expected_seq, rows)?;
            return Ok((seq, ledger_refs));
        };
        let mut guard = ledger_hook::lock_hook(hook)?;
        let entry_count = entries.len();
        let staged = guard.stage_many_with_checkpoints(entries)?;
        let ledger_refs = logical_ledger_refs(&staged, entry_count)?;
        rows.extend(staged.iter().map(|row| encode::WriteRow {
            cf: ColumnFamily::Ledger,
            key: row.key().to_vec(),
            value: row.value().to_vec(),
        }));
        let seq = self.commit_rows_if_current_volatile(expected_seq, rows)?;
        for row in &staged {
            guard.commit_staged(row)?;
        }
        Ok((seq, ledger_refs))
    }

    /// Appends a provenance Ledger entry through Aster's durable group-commit path.
    pub fn append_ledger_entry(
        &self,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<LedgerRef> {
        self.with_durable_commit_lock(|| {
            let Some(hook) = &self.ledger_hook else {
                return self.append_ledger_entry_without_hook(kind, subject, payload, actor);
            };
            let mut guard = ledger_hook::lock_hook(hook)?;
            let staged = guard.stage_with_checkpoints(kind, subject, payload, actor)?;
            let ledger_ref = staged
                .first()
                .ok_or_else(|| CalyxError::ledger_group_commit_failed("no staged ledger rows"))?
                .ledger_ref();
            let rows = staged
                .iter()
                .map(|row| encode::WriteRow {
                    cf: ColumnFamily::Ledger,
                    key: row.key().to_vec(),
                    value: row.value().to_vec(),
                })
                .collect::<Vec<_>>();
            self.commit_rows_locked(&rows)?;
            for row in &staged {
                guard.commit_staged(row)?;
            }
            Ok(ledger_ref)
        })
    }

    /// Appends one no-hook ledger entry inside the caller's already-held durable
    /// commit lock, as a single crash-consistent group commit.
    ///
    /// The row is prepared through [`Self::raw_prepared_ledger_row`] (which never
    /// mutates the store) and committed by exactly one
    /// [`Self::commit_rows_locked`] group. `commit_rows_locked` ->
    /// `commit_prepared_rows` persists the Ledger CF row and derives+writes the
    /// head anchor (`newest_anchor_from_rows`) inside the same WAL-backed
    /// boundary, so the ledger row and its external witness share one commit.
    ///
    /// This path never reacquires the durable commit lock: the lock is already
    /// held by [`Self::append_ledger_entry`], and `commit_rows_locked` does not
    /// take it. A read-only handle fails closed with `CALYX_VAULT_READ_ONLY`
    /// (via `ensure_writeable`) instead of hanging.
    fn append_ledger_entry_without_hook(
        &self,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<LedgerRef> {
        let (ledger_row, ledger_ref) =
            self.raw_prepared_ledger_row(kind, subject, payload, actor)?;
        self.commit_rows_locked(&[ledger_row])?;
        Ok(ledger_ref)
    }

    /// Prepares the next append-only ledger row without touching the durable
    /// commit boundary or the raw store's mutating surface.
    ///
    /// This is the single no-hook ledger preparation path. It opens a
    /// [`LedgerAppender`] over the read-only [`AsterRawLedgerStore`] (tip
    /// recovery reads `scan`/`head_anchor` only), builds the next chained row
    /// with [`LedgerAppender::prepare`] (pure — it never calls `put_new`), and
    /// runs an append-only readback guard so the returned row can be committed
    /// inside one `commit_rows_locked` group by the caller. No ledger row is ever
    /// persisted through the appender.
    ///
    /// # Errors
    /// - [`CalyxError::ledger_append_only_violation`] if a row already exists at
    ///   the prepared sequence (a concurrent writer advanced the ledger tip
    ///   between tip recovery and this readback); nothing is written.
    fn raw_prepared_ledger_row(
        &self,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<(encode::WriteRow, LedgerRef)> {
        let (mut rows, refs) =
            self.raw_prepared_ledger_rows([LedgerEntryInput::new(kind, subject, payload, actor)])?;
        let row = rows
            .pop()
            .ok_or_else(|| CalyxError::ledger_group_commit_failed("no prepared Ledger row"))?;
        Ok((row, require_single_ledger_ref(refs)?))
    }

    /// Prepares a contiguous hash-chain segment without mutating either Aster
    /// or an appender. Used by no-hook atomic batches.
    pub(super) fn raw_prepared_ledger_rows(
        &self,
        entries: impl IntoIterator<Item = LedgerEntryInput>,
    ) -> Result<(Vec<encode::WriteRow>, Vec<LedgerRef>)> {
        let entries = entries.into_iter().collect::<Vec<_>>();
        require_ledger_entries(&entries)?;
        let store = AsterRawLedgerStore { vault: self };
        let appender = LedgerAppender::open(store, std::sync::Arc::clone(&self.clock))?;
        let mut prepared_entries: Vec<PreparedLedgerEntry> = Vec::with_capacity(entries.len());
        for entry in entries {
            let prepared = match prepared_entries.last() {
                Some(predecessor) => appender.prepare_after(
                    predecessor,
                    entry.kind,
                    entry.subject,
                    entry.payload,
                    entry.actor,
                )?,
                None => appender.prepare(entry.kind, entry.subject, entry.payload, entry.actor)?,
            };
            let seq = prepared.seq();
            let key = ledger_key(seq);
            if self
                .read_cf_at(self.snapshot(), ColumnFamily::Ledger, &key)?
                .is_some()
            {
                return Err(CalyxError::ledger_append_only_violation(format!(
                    "ledger seq {seq} already exists; refusing to overwrite an append-only ledger row"
                )));
            }
            prepared_entries.push(prepared);
        }
        let rows = prepared_entries
            .iter()
            .map(|prepared| encode::WriteRow {
                cf: ColumnFamily::Ledger,
                key: ledger_key(prepared.seq()),
                value: prepared.bytes().to_vec(),
            })
            .collect();
        let refs = prepared_entries
            .iter()
            .map(PreparedLedgerEntry::ledger_ref)
            .collect();
        Ok((rows, refs))
    }

    fn anchor_with_raw_ledger_entry(
        &self,
        id: CxId,
        record: &mut encode::BaseRecord,
        anchor: Anchor,
        entry: LedgerEntryInput,
    ) -> Result<LedgerRef> {
        let (ledger_row, ledger_ref) =
            self.raw_prepared_ledger_row(entry.kind, entry.subject, entry.payload, entry.actor)?;
        record.set_provenance(ledger_ref.clone());
        let mut rows = anchor_rows(id, record, &anchor)?;
        rows.push(ledger_row);
        self.commit_rows_locked(&rows)?;
        Ok(ledger_ref)
    }

    pub(crate) fn has_real_ledger_hook(&self) -> bool {
        self.ledger_hook.is_some()
    }

    pub(crate) fn next_ledger_seq_locked(&self) -> Result<u64> {
        let Some(hook) = &self.ledger_hook else {
            let store = AsterRawLedgerStore { vault: self };
            return Ok(LedgerAppender::open(store, std::sync::Arc::clone(&self.clock))?.next_seq());
        };
        let guard = ledger_hook::lock_hook(hook)?;
        Ok(guard.appender().next_seq())
    }

    pub(crate) fn commit_rows_with_ledger_entry_locked(
        &self,
        rows: Vec<encode::WriteRow>,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<LedgerRef> {
        let refs = self.commit_rows_with_ledger_entries_locked(
            rows,
            [LedgerEntryInput::new(kind, subject, payload, actor)],
        )?;
        require_single_ledger_ref(refs)
    }

    pub(crate) fn commit_rows_with_ledger_entries_locked(
        &self,
        mut rows: Vec<encode::WriteRow>,
        entries: impl IntoIterator<Item = LedgerEntryInput>,
    ) -> Result<Vec<LedgerRef>> {
        let entries = entries.into_iter().collect::<Vec<_>>();
        require_ledger_entries(&entries)?;
        let Some(hook) = &self.ledger_hook else {
            return self.commit_rows_with_raw_ledger_entries(rows, entries);
        };
        let mut guard = ledger_hook::lock_hook(hook)?;
        let entry_count = entries.len();
        let staged = guard.stage_many_with_checkpoints(entries)?;
        let ledger_refs = logical_ledger_refs(&staged, entry_count)?;
        rows.extend(staged.iter().map(|row| encode::WriteRow {
            cf: ColumnFamily::Ledger,
            key: row.key().to_vec(),
            value: row.value().to_vec(),
        }));
        self.commit_rows_locked(&rows)?;
        for row in &staged {
            guard.commit_staged(row)?;
        }
        Ok(ledger_refs)
    }

    fn commit_rows_with_raw_ledger_entries(
        &self,
        mut rows: Vec<encode::WriteRow>,
        entries: Vec<LedgerEntryInput>,
    ) -> Result<Vec<LedgerRef>> {
        let (ledger_rows, ledger_refs) = self.raw_prepared_ledger_rows(entries)?;
        rows.extend(ledger_rows);
        self.commit_rows_locked(&rows)?;
        Ok(ledger_refs)
    }
}

/// Error code returned when the raw ledger adapter's mutating surface is used.
///
/// [`AsterRawLedgerStore`] is read-only tip recovery (`scan`/`head_anchor`).
/// All ledger persistence routes through `prepare` + one `commit_rows_locked`
/// group so the ledger row and its head anchor share a single durable commit
/// boundary (`commit_prepared_rows`). This code fires if any caller reaches the
/// adapter's `put_new`/`put_head_anchor` methods, which would otherwise nest the
/// durable commit lock or split that boundary.
pub const CALYX_ASTER_RAW_LEDGER_COMMIT_BOUNDARY: &str = "CALYX_ASTER_RAW_LEDGER_COMMIT_BOUNDARY";

fn require_ledger_entries(entries: &[LedgerEntryInput]) -> Result<()> {
    if entries.is_empty() {
        return Err(CalyxError::ledger_group_commit_failed(
            "atomic Ledger batch requires at least one logical entry",
        ));
    }
    Ok(())
}

pub(super) fn logical_ledger_refs(
    staged: &[calyx_ledger::StagedLedgerRow],
    expected: usize,
) -> Result<Vec<LedgerRef>> {
    let refs = staged
        .iter()
        .filter(|row| !row.is_checkpoint())
        .map(calyx_ledger::StagedLedgerRow::ledger_ref)
        .collect::<Vec<_>>();
    if refs.len() != expected {
        return Err(CalyxError::ledger_group_commit_failed(format!(
            "staged Ledger batch contains {} logical entries, expected {expected}",
            refs.len()
        )));
    }
    Ok(refs)
}

fn require_single_ledger_ref(mut refs: Vec<LedgerRef>) -> Result<LedgerRef> {
    if refs.len() != 1 {
        return Err(CalyxError::ledger_group_commit_failed(format!(
            "single-entry Ledger commit produced {} logical refs",
            refs.len()
        )));
    }
    Ok(refs.remove(0))
}

fn raw_ledger_commit_boundary_error(operation: String) -> CalyxError {
    CalyxError {
        code: CALYX_ASTER_RAW_LEDGER_COMMIT_BOUNDARY,
        message: format!(
            "raw ledger adapter rejected {operation}: the adapter is read-only tip recovery and must never persist ledger state"
        ),
        remediation: "route ledger persistence through prepare + one commit_rows_locked group; the raw adapter exposes only scan/head_anchor for tip recovery",
    }
}

fn sequence_conflict_error(expected: calyx_core::Seq, current: calyx_core::Seq) -> CalyxError {
    CalyxError {
        code: "CALYX_ASTER_SEQUENCE_CONFLICT",
        message: format!(
            "conditional CF batch with ledger entry expected seq {expected}, current seq is {current}; no rows were written"
        ),
        remediation: "re-read the current snapshot, revalidate the complete replacement, and retry with that exact sequence",
    }
}

fn anchor_rows(
    id: CxId,
    record: &encode::BaseRecord,
    anchor: &Anchor,
) -> Result<Vec<encode::WriteRow>> {
    Ok(vec![
        encode::WriteRow {
            cf: ColumnFamily::Base,
            key: base_key(id),
            value: record.encode()?,
        },
        encode::WriteRow {
            cf: ColumnFamily::Anchors,
            key: anchor_key(id, &anchor.kind),
            value: encode::encode_anchor(anchor)?,
        },
    ])
}

struct AsterRawLedgerStore<'a, C> {
    vault: &'a AsterVault<C>,
}

impl<C> LedgerCfStore for AsterRawLedgerStore<'_, C>
where
    C: Clock,
{
    fn scan(&self) -> Result<Vec<LedgerRow>> {
        let mut rows = Vec::new();
        for (key, bytes) in self
            .vault
            .scan_cf_at(self.vault.snapshot(), ColumnFamily::Ledger)?
        {
            rows.push(LedgerRow {
                seq: parse_aster_ledger_seq(&key)?,
                bytes,
            });
        }
        rows.sort_by_key(|row| row.seq);
        Ok(rows)
    }

    /// Fail-closed: the raw adapter never persists ledger rows.
    ///
    /// A durable no-hook append here would call `vault.write_cf`, which
    /// reacquires `with_durable_commit_lock` on the same non-reentrant file lock
    /// and self-deadlocks, and would also split the ledger row from its head
    /// anchor into a second commit boundary. Ledger persistence goes through
    /// `raw_prepared_ledger_row` + one `commit_rows_locked` group instead
    /// (issue #560).
    fn put_new(&mut self, seq: u64, _bytes: &[u8]) -> Result<()> {
        Err(raw_ledger_commit_boundary_error(format!(
            "put_new(seq={seq})"
        )))
    }

    fn head_anchor(&self) -> Result<Option<LedgerHeadAnchor>> {
        let Some(durable) = &self.vault.durable else {
            return Ok(None);
        };
        let anchor = crate::ledger_head::read_head_anchor(durable.root())?;
        if anchor.is_none() {
            let rows = self.scan()?;
            return crate::ledger_head::require_head_anchor_for_rows(durable.root(), anchor, &rows);
        }
        Ok(anchor)
    }

    /// Fail-closed: the head anchor is derived from the committed Ledger CF row
    /// and persisted by `commit_prepared_rows` inside the group-commit boundary,
    /// never by this adapter (issue #560).
    fn put_head_anchor(&mut self, anchor: &LedgerHeadAnchor) -> Result<()> {
        Err(raw_ledger_commit_boundary_error(format!(
            "put_head_anchor(height={})",
            anchor.height
        )))
    }
}
