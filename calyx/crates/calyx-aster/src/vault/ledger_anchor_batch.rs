use std::collections::{BTreeMap, BTreeSet};

use super::{AsterVault, encode, ledger_hook};
use crate::cf::{ColumnFamily, anchor_key, base_key, ledger_key};
use crate::ledger_view::parse_aster_ledger_seq;
use calyx_core::{Anchor, CalyxError, Clock, CxId, LedgerRef, Result, VaultStore};
use calyx_ledger::{
    ActorId, EntryKind, LedgerAppender, LedgerCfStore, LedgerHeadAnchor, LedgerRow, SubjectId,
    decode as decode_ledger,
};

struct AnchorBatchLedgerInput {
    kind: EntryKind,
    subject: SubjectId,
    payload: Vec<u8>,
    actor: ActorId,
}

impl<C> AsterVault<C>
where
    C: Clock,
{
    /// Adds multiple anchors and stamps the stored base row with one shared ledger ref.
    ///
    /// This is for one semantic grounding event that has more than one anchor axis. The batch is
    /// idempotent only when every requested anchor already exists and the Base provenance points to
    /// the same requested ledger entry. A partial pre-existing batch fails closed so a legacy
    /// unstamped anchor is never silently upgraded. Slot vectors are not grounding inputs, so the
    /// mutation preserves the lossless Base record's sealed slot hashes without hydrating slots.
    pub fn anchors_with_ledger_entry(
        &self,
        id: CxId,
        anchors: Vec<Anchor>,
        kind: EntryKind,
        subject: SubjectId,
        payload: Vec<u8>,
        actor: ActorId,
    ) -> Result<LedgerRef> {
        validate_anchor_batch(&anchors)?;
        let entry = AnchorBatchLedgerInput {
            kind,
            subject,
            payload,
            actor,
        };
        self.with_durable_commit_lock(|| {
            let latest = self.snapshot();
            let base = self
                .read_cf_at(latest, ColumnFamily::Base, &base_key(id))?
                .ok_or_else(|| CalyxError::stale_derived("constellation missing at snapshot"))?;
            let mut record = encode::BaseRecord::decode_for_key(id, &base)?;
            let mut existing_anchors = BTreeMap::<_, Vec<_>>::new();
            for anchor in &record.constellation().anchors {
                existing_anchors
                    .entry(anchor.kind.clone())
                    .or_default()
                    .push(anchor);
            }
            let mut missing = Vec::new();
            let mut existing_count = 0usize;
            for anchor in &anchors {
                match classify_anchor_state(self, latest, id, &existing_anchors, anchor)? {
                    AnchorState::Existing => existing_count += 1,
                    AnchorState::Missing => missing.push(anchor.clone()),
                }
            }
            if existing_count == anchors.len() {
                validate_existing_batch_ledger(
                    self,
                    latest,
                    id,
                    &record.constellation().provenance,
                    &entry,
                )?;
                return Ok(record.constellation().provenance.clone());
            }
            if existing_count != 0 {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "partial anchor batch for {id}: {existing_count} existing anchors and {} \
                     missing anchors",
                    missing.len()
                )));
            }

            let Some(hook) = &self.ledger_hook else {
                let store = AnchorBatchRawLedgerStore { vault: self };
                let appender = LedgerAppender::open(store, std::sync::Arc::clone(&self.clock))?;
                let prepared =
                    appender.prepare(entry.kind, entry.subject, entry.payload, entry.actor)?;
                let ledger_ref = prepared.ledger_ref();
                let mut rows =
                    anchor_batch_rows_with_ledger_ref(id, &mut record, &missing, &ledger_ref)?;
                rows.push(encode::WriteRow {
                    cf: ColumnFamily::Ledger,
                    key: ledger_key(prepared.seq()),
                    value: prepared.bytes().to_vec(),
                });
                self.commit_rows_locked(&rows)?;
                return Ok(ledger_ref);
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
            let mut rows =
                anchor_batch_rows_with_ledger_ref(id, &mut record, &missing, &ledger_ref)?;
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
}

enum AnchorState {
    Existing,
    Missing,
}

fn classify_anchor_state<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: u64,
    id: CxId,
    existing_anchors: &BTreeMap<calyx_core::AnchorKind, Vec<&Anchor>>,
    anchor: &Anchor,
) -> Result<AnchorState> {
    let key = anchor_key(id, &anchor.kind);
    let anchor_bytes = encode::encode_anchor(anchor)?;
    let matching = existing_anchors
        .get(&anchor.kind)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let matching_base_anchor_count = matching.len();
    let exact_base_anchor_count = matching
        .iter()
        .filter(|existing| **existing == anchor)
        .count();
    match vault.read_cf_at(snapshot, ColumnFamily::Anchors, &key)? {
        Some(existing_bytes) => {
            let stored_anchor = encode::decode_anchor(&existing_bytes)?;
            if existing_bytes != anchor_bytes || stored_anchor != *anchor {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "conflicting Anchors CF row for {id} {:?}; existing persisted row does not \
                     match requested anchor",
                    anchor.kind
                )));
            }
            if matching_base_anchor_count != 1 || exact_base_anchor_count != 1 {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "Anchors CF row for {id} {:?} matches request but Base row has {} \
                     matching-kind anchors",
                    anchor.kind, matching_base_anchor_count
                )));
            }
            Ok(AnchorState::Existing)
        }
        None => {
            if matching_base_anchor_count != 0 {
                return Err(CalyxError::aster_corrupt_shard(format!(
                    "Base row for {id} already has {} {:?} anchors but Anchors CF row is missing",
                    matching_base_anchor_count, anchor.kind
                )));
            }
            Ok(AnchorState::Missing)
        }
    }
}

fn validate_existing_batch_ledger<C: Clock>(
    vault: &AsterVault<C>,
    snapshot: u64,
    id: CxId,
    ledger_ref: &LedgerRef,
    entry: &AnchorBatchLedgerInput,
) -> Result<()> {
    let row = vault
        .read_cf_at(snapshot, ColumnFamily::Ledger, &ledger_key(ledger_ref.seq))?
        .ok_or_else(|| {
            CalyxError::aster_corrupt_shard(format!(
                "matching anchor batch for {id} has provenance seq {} but Ledger CF row is missing",
                ledger_ref.seq
            ))
        })?;
    let stored = decode_ledger(&row)?;
    if stored.seq != ledger_ref.seq || stored.entry_hash != ledger_ref.hash {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "matching anchor batch for {id} has provenance ref that does not match Ledger CF row"
        )));
    }
    if stored.kind != entry.kind
        || stored.subject != entry.subject
        || stored.payload != entry.payload
        || stored.actor != entry.actor
    {
        return Err(CalyxError::aster_corrupt_shard(format!(
            "matching anchor batch for {id} is not backed by the requested ledger entry"
        )));
    }
    Ok(())
}

fn anchor_batch_rows_with_ledger_ref(
    id: CxId,
    record: &mut encode::BaseRecord,
    anchors: &[Anchor],
    ledger_ref: &LedgerRef,
) -> Result<Vec<encode::WriteRow>> {
    record.set_provenance(ledger_ref.clone());
    record.anchors_mut().extend_from_slice(anchors);
    record.flags_mut().ungrounded = false;
    record.constellation().validate_schema()?;
    let mut rows = Vec::with_capacity(1 + anchors.len());
    rows.push(encode::WriteRow {
        cf: ColumnFamily::Base,
        key: base_key(id),
        value: record.encode()?,
    });
    for anchor in anchors {
        rows.push(encode::WriteRow {
            cf: ColumnFamily::Anchors,
            key: anchor_key(id, &anchor.kind),
            value: encode::encode_anchor(anchor)?,
        });
    }
    Ok(rows)
}

fn validate_anchor_batch(anchors: &[Anchor]) -> Result<()> {
    if anchors.is_empty() {
        return Err(CalyxError::aster_corrupt_shard(
            "ledger-stamped anchor batch must contain at least one anchor",
        ));
    }
    let mut kinds = BTreeSet::new();
    for anchor in anchors {
        anchor.validate_schema()?;
        if !kinds.insert(anchor.kind.clone()) {
            return Err(CalyxError::aster_corrupt_shard(format!(
                "ledger-stamped anchor batch contains duplicate anchor kind {:?}",
                anchor.kind
            )));
        }
    }
    Ok(())
}

struct AnchorBatchRawLedgerStore<'a, C> {
    vault: &'a AsterVault<C>,
}

impl<C> LedgerCfStore for AnchorBatchRawLedgerStore<'_, C>
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

    fn put_new(&mut self, seq: u64, bytes: &[u8]) -> Result<()> {
        let key = ledger_key(seq);
        if self
            .vault
            .read_cf_at(self.vault.snapshot(), ColumnFamily::Ledger, &key)?
            .is_some()
        {
            return Err(CalyxError::ledger_append_only_violation(format!(
                "ledger seq {seq} already exists"
            )));
        }
        self.vault
            .write_cf(ColumnFamily::Ledger, key, bytes.to_vec())
            .map(|_| ())
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

    fn put_head_anchor(&mut self, anchor: &LedgerHeadAnchor) -> Result<()> {
        if let Some(durable) = &self.vault.durable {
            crate::ledger_head::write_head_anchor(durable.root(), anchor)?;
        }
        Ok(())
    }
}
