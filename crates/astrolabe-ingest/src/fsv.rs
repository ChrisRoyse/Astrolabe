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

use astrolabe_domain::fsv::{
    FsvAck, FsvLedgerExpectation, FsvLedgerReadback, FsvPlan, FsvRow, FsvSampling,
};
use calyx_aster::cf::{ColumnFamily, ledger_key};
use calyx_aster::mvcc::OrderedReadbackMetrics;
use calyx_aster::vault::{AsterVault, OrderedCfRead};
use calyx_core::{CalyxError, Clock, LedgerRef, Seq};
use calyx_ledger::{ActorId, EntryKind, SubjectId, decode};

/// A planned set of column-family rows plus the ledger entry a single vault
/// mutation is accountable for.
///
/// Rows are added with [`push_content`](Self::push_content) (must read back
/// byte-identical) or [`push_tombstoned`](Self::push_tombstoned) (must not read
/// back live). The plan is then verified against the committed snapshot with
/// [`verify_committed`](Self::verify_committed).
pub struct VaultMutationPlan {
    plan: FsvPlan,
    /// Compact order-aligned CF identity. The key and diagnostic store name live
    /// only in `plan.rows`; no composite-key map duplicates either allocation.
    cf_by_ordinal: Vec<ColumnFamily>,
}

/// Measured physical shape of one vault mutation readback.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VaultMutationReadbackMetrics {
    /// Persisted rows delivered, including explicit absence/tombstone states.
    pub rows_read_back: u64,
    /// Exact persisted value bytes exposed to verification.
    pub bytes_read_back: u64,
    /// Column-family groups traversed under the pinned snapshot.
    pub read_batches: u64,
    /// Row-table, memtable, and immutable-SST sources consulted.
    pub source_read_operations: u64,
    /// Immutable SST files opened by the complete plan.
    pub sst_files_opened: u64,
    /// Peak bytes retained by the mutation plan and all ordering indexes.
    pub max_plan_bytes: u64,
    /// Largest persisted value borrowed at once by the streaming verifier.
    pub max_readback_batch_bytes: u64,
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
            cf_by_ordinal: Vec::new(),
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
        self.push_content_hash(cf, key, *blake3::hash(bytes).as_bytes());
    }

    /// Plans an exact content readback from a digest computed before ownership
    /// of the value moved into the vault commit.
    pub fn push_content_hash(&mut self, cf: ColumnFamily, key: Vec<u8>, content_hash: [u8; 32]) {
        let store = cf.name();
        self.cf_by_ordinal.push(cf);
        self.plan
            .push(FsvRow::content_hash(store, key, content_hash));
    }

    /// Plans a row that must read back absent or equal to `tombstone`.
    pub fn push_tombstoned(&mut self, cf: ColumnFamily, key: Vec<u8>, tombstone: &[u8]) {
        self.push_tombstoned_hash(cf, key, *blake3::hash(tombstone).as_bytes());
    }

    /// Plans a non-live readback from the tombstone digest computed before the
    /// value allocation moved into the vault commit.
    pub fn push_tombstoned_hash(
        &mut self,
        cf: ColumnFamily,
        key: Vec<u8>,
        tombstone_hash: [u8; 32],
    ) {
        let store = cf.name();
        self.cf_by_ordinal.push(cf);
        self.plan
            .push(FsvRow::tombstoned_hash(store, key, tombstone_hash));
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
    /// Propagates fail-closed refusals as structured [`CalyxError`] values:
    /// `ASTRO_FSV_READBACK_MISMATCH` (a row's persisted bytes diverge),
    /// `ASTRO_FSV_LEDGER_UNPAIRED` (the mutation has no matching ledger entry),
    /// or `ASTRO_FSV_PLAN_INVALID` (the plan named no rows).
    pub fn verify_committed<C>(
        &self,
        vault: &AsterVault<C>,
        commit_seq: Seq,
    ) -> calyx_core::Result<FsvAck>
    where
        C: Clock,
    {
        self.verify_committed_with_reader(vault, commit_seq, || {
            newest_ledger_readback(vault, commit_seq)
        })
    }

    /// Re-reads every planned row and the exact hash-bound Ledger row returned
    /// by the atomic group commit.
    ///
    /// Unlike [`verify_committed`](Self::verify_committed), this path never
    /// scans the Ledger CF: it point-reads `ledger_key(ledger_ref.seq)`, decodes
    /// and canonically verifies the entry, and requires its sequence and hash
    /// to match `ledger_ref` before the normal kind/actor/subject comparison.
    pub fn verify_committed_with_ledger_ref<C>(
        &self,
        vault: &AsterVault<C>,
        commit_seq: Seq,
        ledger_ref: &LedgerRef,
    ) -> calyx_core::Result<FsvAck>
    where
        C: Clock,
    {
        self.verify_committed_with_reader(vault, commit_seq, || {
            exact_ledger_readback(vault, commit_seq, ledger_ref)
        })
    }

    /// Runs the same unforgeable digest verification while exposing each
    /// already-verified persisted row to one semantic observer. The observer is
    /// invoked inside the Calyx storage-local stream; values are borrowed and
    /// cannot accumulate into a second corpus-sized readback cache.
    pub fn verify_committed_with_ledger_ref_observed<C, E, F>(
        &self,
        vault: &AsterVault<C>,
        commit_seq: Seq,
        ledger_ref: &LedgerRef,
        observer: F,
    ) -> std::result::Result<(FsvAck, VaultMutationReadbackMetrics), E>
    where
        C: Clock,
        E: From<CalyxError>,
        F: FnMut(usize, ColumnFamily, &[u8], Option<&[u8]>) -> std::result::Result<(), E>,
    {
        self.verify_committed_with_reader_observed(
            vault,
            commit_seq,
            || exact_ledger_readback(vault, commit_seq, ledger_ref).map_err(E::from),
            observer,
        )
    }

    /// Verifies planned rows against the live snapshot while consuming Ledger
    /// bytes that were independently read from the physical SST/WAL source.
    ///
    /// This is the batch counterpart to
    /// [`verify_committed_with_ledger_ref`](Self::verify_committed_with_ledger_ref):
    /// callers can read many exact Ledger sequences once, then pair each plan to
    /// its hash-bound bytes without reopening the same SST for every logical row.
    pub fn verify_committed_with_ledger_bytes<C>(
        &self,
        vault: &AsterVault<C>,
        commit_seq: Seq,
        ledger_ref: &LedgerRef,
        ledger_bytes: &[u8],
    ) -> calyx_core::Result<FsvAck>
    where
        C: Clock,
    {
        self.verify_committed_with_reader(vault, commit_seq, || {
            exact_ledger_readback_bytes(commit_seq, ledger_ref, ledger_bytes).map(Some)
        })
    }

    fn verify_committed_with_reader<C, L>(
        &self,
        vault: &AsterVault<C>,
        commit_seq: Seq,
        read_ledger: L,
    ) -> calyx_core::Result<FsvAck>
    where
        C: Clock,
        L: FnOnce() -> calyx_core::Result<Option<FsvLedgerReadback>>,
    {
        self.verify_committed_with_reader_observed(vault, commit_seq, read_ledger, |_, _, _, _| {
            Ok(())
        })
        .map(|(ack, _)| ack)
    }

    fn verify_committed_with_reader_observed<C, E, L, F>(
        &self,
        vault: &AsterVault<C>,
        commit_seq: Seq,
        read_ledger: L,
        mut observer: F,
    ) -> std::result::Result<(FsvAck, VaultMutationReadbackMetrics), E>
    where
        C: Clock,
        E: From<CalyxError>,
        L: FnOnce() -> std::result::Result<Option<FsvLedgerReadback>, E>,
        F: FnMut(usize, ColumnFamily, &[u8], Option<&[u8]>) -> std::result::Result<(), E>,
    {
        if self.plan.rows().len() != self.cf_by_ordinal.len() {
            return Err(E::from(CalyxError {
                code: astrolabe_domain::fsv::ASTRO_FSV_PLAN_INVALID,
                message: format!(
                    "FSV plan has {} rows but {} order-aligned column families",
                    self.plan.rows().len(),
                    self.cf_by_ordinal.len()
                ),
                remediation: "This is an internal FSV plan construction bug: append every row and its column family in the same VaultMutationPlan operation.",
            }));
        }
        let mut verification = self
            .plan
            .begin_verification()
            .map_err(domain_as_calyx)
            .map_err(E::from)?;
        let reads = self
            .plan
            .rows()
            .iter()
            .zip(&self.cf_by_ordinal)
            .enumerate()
            .map(|(ordinal, (row, cf))| OrderedCfRead::new(ordinal, *cf, row.key()))
            .collect::<Vec<_>>();
        let physical =
            vault.visit_ordered_cf_plan_at(commit_seq, &reads, |ordinal, cf, key, persisted| {
                if self.plan.selects_ordinal(ordinal) {
                    verification
                        .observe(ordinal, persisted)
                        .map_err(domain_as_calyx)
                        .map_err(E::from)?;
                }
                observer(ordinal, cf, key, persisted)
            })?;
        let ack = verification
            .finish(read_ledger()?)
            .map_err(domain_as_calyx)
            .map_err(E::from)?;
        if self.plan.sampling().is_full()
            && (ack.rows_read_back() != physical.rows_read_back
                || ack.bytes_read_back() != physical.bytes_read_back)
        {
            return Err(E::from(CalyxError {
                code: astrolabe_domain::fsv::ASTRO_FSV_PLAN_INVALID,
                message: format!(
                    "full FSV witness counted rows={} bytes={} but Calyx physical readback counted rows={} bytes={}",
                    ack.rows_read_back(),
                    ack.bytes_read_back(),
                    physical.rows_read_back,
                    physical.bytes_read_back
                ),
                remediation: "Preserve the vault and correct the ordered readback accounting divergence before acknowledging the mutation.",
            }));
        }
        let max_plan_bytes = self
            .plan
            .allocated_bytes()
            .map_err(domain_as_calyx)
            .map_err(E::from)?
            .checked_add(
                u64::try_from(
                    self.cf_by_ordinal
                        .capacity()
                        .checked_mul(std::mem::size_of::<ColumnFamily>())
                        .ok_or_else(|| {
                            E::from(CalyxError {
                                code: astrolabe_domain::fsv::ASTRO_FSV_PLAN_INVALID,
                                message: "FSV CF-plan allocation accounting overflow".to_string(),
                                remediation: "Reduce the mutation batch or correct the platform allocation accounting before retrying.",
                            })
                        })?,
                )
                .map_err(|_| {
                    E::from(CalyxError {
                        code: astrolabe_domain::fsv::ASTRO_FSV_PLAN_INVALID,
                        message: "FSV CF-plan allocation footprint exceeds u64".to_string(),
                        remediation: "Reduce the mutation batch or correct the platform allocation accounting before retrying.",
                    })
                })?,
            )
            .and_then(|bytes| bytes.checked_add(physical.plan_index_bytes))
            .ok_or_else(|| {
                E::from(CalyxError {
                    code: astrolabe_domain::fsv::ASTRO_FSV_PLAN_INVALID,
                    message: "FSV total plan allocation accounting overflow".to_string(),
                    remediation: "Reduce the mutation batch or correct the platform allocation accounting before retrying.",
                })
            })?;
        Ok((ack, vault_metrics(physical, max_plan_bytes)))
    }
}

fn domain_as_calyx(error: astrolabe_domain::DomainError) -> CalyxError {
    CalyxError {
        code: error.code(),
        message: error.message().to_string(),
        remediation: error.remediation(),
    }
}

fn vault_metrics(
    physical: OrderedReadbackMetrics,
    max_plan_bytes: u64,
) -> VaultMutationReadbackMetrics {
    VaultMutationReadbackMetrics {
        rows_read_back: physical.rows_read_back,
        bytes_read_back: physical.bytes_read_back,
        read_batches: physical.read_batches,
        source_read_operations: physical.source_read_operations,
        sst_files_opened: physical.sst_files_opened,
        max_plan_bytes,
        max_readback_batch_bytes: physical.max_readback_batch_bytes,
    }
}

fn newest_ledger_readback<C>(
    vault: &AsterVault<C>,
    commit_seq: Seq,
) -> calyx_core::Result<Option<FsvLedgerReadback>>
where
    C: Clock,
{
    // Newest *pairable* entry: periodic system checkpoints interleave after
    // the commit's own entry at every checkpoint-interval boundary (#495).
    let newest = calyx_aster::ledger_view::newest_pairable_ledger(
        vault.scan_cf_at(commit_seq, ColumnFamily::Ledger)?,
    )?;
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

fn exact_ledger_readback<C>(
    vault: &AsterVault<C>,
    commit_seq: Seq,
    ledger_ref: &LedgerRef,
) -> calyx_core::Result<Option<FsvLedgerReadback>>
where
    C: Clock,
{
    let Some(bytes) = vault.read_cf_at(
        commit_seq,
        ColumnFamily::Ledger,
        &ledger_key(ledger_ref.seq),
    )?
    else {
        return Ok(None);
    };
    Ok(Some(exact_ledger_readback_bytes(
        commit_seq, ledger_ref, &bytes,
    )?))
}

fn exact_ledger_readback_bytes(
    commit_seq: Seq,
    ledger_ref: &LedgerRef,
    bytes: &[u8],
) -> calyx_core::Result<FsvLedgerReadback> {
    let entry = decode(bytes)?;
    if !entry.verify() || entry.seq != ledger_ref.seq || entry.entry_hash != ledger_ref.hash {
        return Err(CalyxError {
            code: astrolabe_domain::fsv::ASTRO_FSV_LEDGER_UNPAIRED,
            message: format!(
                "exact Ledger readback at commit seq {commit_seq} failed canonical verification or returned seq {} hash {} but the atomic receipt requires seq {} hash {}",
                entry.seq,
                hex_lower(&entry.entry_hash),
                ledger_ref.seq,
                hex_lower(&ledger_ref.hash),
            ),
            remediation: "quarantine the vault, run astrolabe verify --deep, and rebuild from source bytes if the Ledger receipt diverges",
        });
    }
    Ok(FsvLedgerReadback {
        seq: entry.seq,
        kind: entry.kind.as_str().to_string(),
        actor: actor_name(&entry.actor),
        subject: subject_bytes(&entry.subject),
        entry_hash_hex: hex_lower(&entry.entry_hash),
    })
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
