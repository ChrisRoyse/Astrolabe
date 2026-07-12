//! Vault-side adapter for the engine-native FSV write-ack witness (#178).
//!
//! [`astrolabe_domain::fsv`] owns the unforgeable [`FsvAck`] and the comparison
//! logic; this module binds that logic to a real [`AsterVault`] so that a
//! mutation is acked **only after its persisted rows and its paired ledger entry
//! are re-read from the committed snapshot**.
//!
//! The write path builds a [`VaultMutationPlan`] naming every column-family row
//! it intends to persist, commits through
//! [`AsterVault::write_cf_batch_with_ledger_entry`], and then calls
//! [`VaultMutationPlan::verify_committed`]. That method re-reads each planned row
//! at the commit snapshot (a *separate* read against the store, never the write
//! set) and the newest ledger entry, and returns an `FsvAck` only if everything
//! matches. On any divergence it fails closed with a structured
//! `{code, message, remediation}` error naming the exact CF and key.

use std::collections::HashMap;

use astrolabe_domain::fsv::{
    FsvAck, FsvLedgerExpectation, FsvLedgerReadback, FsvPlan, FsvRow, FsvSampling, verify_mutation,
};
use calyx_aster::cf::ColumnFamily;
use calyx_aster::vault::AsterVault;
use calyx_core::{Clock, Seq};
use calyx_ledger::{ActorId, EntryKind, SubjectId, decode};

use crate::registry::{IngestError, IngestResult};

/// A planned set of column-family rows plus the ledger entry a single vault
/// mutation is accountable for.
///
/// Rows are added with [`push_content`](Self::push_content) (must read back
/// byte-identical) or [`push_tombstoned`](Self::push_tombstoned) (must not read
/// back live). The plan is then verified against the committed snapshot with
/// [`verify_committed`](Self::verify_committed).
pub struct VaultMutationPlan {
    plan: FsvPlan,
    /// Parallel CF lookup so the readback closure can resolve each planned row's
    /// physical column family from its `(store_name, key)` pair without scanning.
    cf_by_row: HashMap<(String, Vec<u8>), ColumnFamily>,
}

impl VaultMutationPlan {
    /// Starts a plan for `scope`, requiring the paired ledger entry to match
    /// `kind` / `actor` / `subject`. Defaults to full readback.
    pub fn new(
        scope: impl Into<String>,
        kind: EntryKind,
        actor: &ActorId,
        subject: &SubjectId,
    ) -> Self {
        let ledger = FsvLedgerExpectation {
            kind: kind.as_str().to_string(),
            actor: actor_name(actor),
            subject: subject_bytes(subject),
        };
        Self {
            plan: FsvPlan::new(scope, ledger),
            cf_by_row: HashMap::new(),
        }
    }

    /// Sets a registry-declared sampling policy. A sampled verification yields a
    /// `fsv:verified-sampled` ack, never `fsv:verified`.
    #[must_use]
    pub fn with_sampling(mut self, sampling: FsvSampling) -> Self {
        self.plan = self.plan.with_sampling(sampling);
        self
    }

    /// Plans a row that must read back byte-identical to `bytes`.
    pub fn push_content(&mut self, cf: ColumnFamily, key: Vec<u8>, bytes: &[u8]) {
        let store = cf.name();
        self.cf_by_row.insert((store.clone(), key.clone()), cf);
        self.plan.push(FsvRow::content(store, key, bytes));
    }

    /// Plans a row that must read back absent or equal to `tombstone`.
    pub fn push_tombstoned(&mut self, cf: ColumnFamily, key: Vec<u8>, tombstone: &[u8]) {
        let store = cf.name();
        self.cf_by_row.insert((store.clone(), key.clone()), cf);
        self.plan.push(FsvRow::tombstoned(store, key, tombstone));
    }

    /// Returns the number of planned rows.
    pub fn len(&self) -> usize {
        self.plan.rows().len()
    }

    /// Returns true when no rows are planned.
    pub fn is_empty(&self) -> bool {
        self.plan.rows().is_empty()
    }

    /// Re-reads every planned row and the newest ledger entry at the commit
    /// snapshot and returns an [`FsvAck`] only if all bytes match and the ledger
    /// entry is present and correctly paired.
    ///
    /// The `commit_seq` must be the sequence produced by the commit whose rows
    /// this plan describes (typically `vault.latest_seq()` immediately after the
    /// group commit).
    ///
    /// # Errors
    ///
    /// Propagates the fail-closed domain refusals as [`IngestError::Domain`]:
    /// `ASTRO_FSV_READBACK_MISMATCH` (a row's persisted bytes diverge),
    /// `ASTRO_FSV_LEDGER_UNPAIRED` (the mutation has no matching ledger entry),
    /// or `ASTRO_FSV_PLAN_INVALID` (the plan named no rows).
    pub fn verify_committed<C>(
        &self,
        vault: &AsterVault<C>,
        commit_seq: Seq,
    ) -> IngestResult<FsvAck>
    where
        C: Clock,
    {
        let read_error: std::cell::RefCell<Option<IngestError>> = std::cell::RefCell::new(None);
        let ack = verify_mutation(
            &self.plan,
            |row| {
                let cf = match self
                    .cf_by_row
                    .get(&(row.store().to_string(), row.key().to_vec()))
                {
                    Some(cf) => *cf,
                    None => {
                        // The plan builder always registers a CF for every row it
                        // pushed; a missing entry is an internal contract break,
                        // surfaced fail-closed rather than skipped.
                        let err = IngestError::refused(
                            astrolabe_domain::fsv::ASTRO_FSV_PLAN_INVALID,
                            format!(
                                "FSV plan row store={} key len={} has no registered column family",
                                row.store(),
                                row.key().len()
                            ),
                            "This is an internal FSV plan construction bug: every planned row must be pushed through VaultMutationPlan so its column family is recorded.",
                        );
                        *read_error.borrow_mut() = Some(err);
                        return Err(plan_bug());
                    }
                };
                match vault.read_cf_at(commit_seq, cf, row.key()) {
                    Ok(value) => Ok(value),
                    Err(err) => {
                        let err = IngestError::from(err);
                        *read_error.borrow_mut() = Some(err);
                        Err(plan_bug())
                    }
                }
            },
            || match newest_ledger_readback(vault, commit_seq) {
                Ok(entry) => Ok(entry),
                Err(err) => {
                    *read_error.borrow_mut() = Some(err);
                    Err(plan_bug())
                }
            },
        );
        match ack {
            Ok(ack) => Ok(ack),
            Err(domain_err) => {
                if let Some(err) = read_error.take() {
                    return Err(err);
                }
                Err(IngestError::Domain(domain_err))
            }
        }
    }
}

/// Sentinel domain error used to unwind out of the verification closures when a
/// vault read itself fails; the real [`IngestError`] is stashed and re-raised by
/// [`VaultMutationPlan::verify_committed`].
fn plan_bug() -> astrolabe_domain::DomainError {
    astrolabe_domain::DomainError::new(
        astrolabe_domain::fsv::ASTRO_FSV_PLAN_INVALID,
        "vault readback failed during FSV verification",
        "internal: the stashed IngestError carries the real cause",
    )
}

fn newest_ledger_readback<C>(
    vault: &AsterVault<C>,
    commit_seq: Seq,
) -> IngestResult<Option<FsvLedgerReadback>>
where
    C: Clock,
{
    let newest = vault
        .scan_cf_at(commit_seq, ColumnFamily::Ledger)?
        .into_iter()
        .max_by(|left, right| left.0.cmp(&right.0));
    let Some((_key, bytes)) = newest else {
        return Ok(None);
    };
    let entry = decode(&bytes)?;
    Ok(Some(FsvLedgerReadback {
        seq: entry.seq,
        kind: entry.kind.as_str().to_string(),
        actor: actor_name(&entry.actor),
        subject: subject_bytes(&entry.subject),
        entry_hash_hex: hex_lower(&entry.entry_hash),
    }))
}

fn actor_name(actor: &ActorId) -> String {
    match actor {
        ActorId::Agent(name) => format!("agent:{name}"),
        ActorId::Service(name) => format!("service:{name}"),
        ActorId::System => "system".to_string(),
    }
}

/// Canonical, tag-prefixed subject bytes so two subjects of different variants
/// that happen to share inner bytes never falsely pair. The tag byte matches the
/// variant discriminant order of [`SubjectId`].
fn subject_bytes(subject: &SubjectId) -> Vec<u8> {
    let (tag, body): (u8, Vec<u8>) = match subject {
        SubjectId::Cx(id) => (0, id.as_bytes().to_vec()),
        SubjectId::Lens(id) => (1, id.as_bytes().to_vec()),
        SubjectId::Kernel(bytes) => (2, bytes.clone()),
        SubjectId::Guard(bytes) => (3, bytes.clone()),
        SubjectId::Query(bytes) => (4, bytes.clone()),
    };
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(tag);
    out.extend_from_slice(&body);
    out
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
