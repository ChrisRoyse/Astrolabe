//! Engine-native Full State Verification: the unforgeable write-ack witness (#178).
//!
//! # What makes an ack trustworthy
//!
//! An ack is trustworthy exactly when **the bytes a later independent reader will
//! see have been re-read after the commit and matched against the content the
//! mutation intended, and the ledger entry that authorizes that mutation is
//! itself present on disk.** Anything weaker — a writer return value, a row
//! count, a log line — is a claim about *intent*, not about *state*.
//!
//! # Why this is a type and not a convention
//!
//! A convention ("please call the verifier before you ack") decays: the next
//! caller forgets, the fast path skips it, and the response still says success.
//! So the success value is made **impossible to express without the verification
//! having happened**:
//!
//! * [`FsvAck`] has private fields, no public constructor, and no `Deserialize`
//!   impl. It cannot be built by a struct literal from another crate, and it
//!   cannot be conjured out of a JSON body.
//! * The only paths in the entire workspace that return one are
//!   [`verify_mutation`] and [`FsvVerification::finish`]. Both perform the
//!   comparison themselves: the streaming form accepts persisted bytes by stable
//!   plan ordinal, rejects duplicates and omissions, hashes every selected row,
//!   and verifies the paired ledger entry before it can mint the ack. A caller
//!   cannot hand either path a "yes it matched" boolean.
//!
//! Consequently a downstream crate (including `astrolabe-server`) can only put
//! an `fsv:verified` label in a response envelope if it is holding an `FsvAck`
//! that some verified path produced. There is no other way to obtain one.
//!
//! # Labels are honest about coverage
//!
//! Verification may be sampled (the sampling rate is the registry-declared knob
//! [`crate::knobs::FSV_READBACK_SAMPLE_RATE_PERMILLE_KNOB`]). A sampled ack
//! carries [`FSV_LABEL_SAMPLED`], never [`FSV_LABEL_VERIFIED`]: an unlabeled
//! `fsv:verified` therefore *always* means every mutated row was read back.
//! Sampling is a labeled degradation, not a silent one (standing invariants 1
//! and 3).
//!
//! # Design precedents
//!
//! * RocksDB `paranoid_checks` / `ReadOptions::verify_checksums` — foreground
//!   verification is on by default because correctness outranks availability.
//! * ZFS end-to-end checksums — the checksum lives with the *parent* reference,
//!   not next to the data, so the data and its expectation cannot be corrupted
//!   together. Here the expectation is the planned content hash held by the
//!   writer, and the readback goes through the store.

use std::fmt;

use serde::Serialize;

use crate::DomainError;
use crate::knobs::{
    FSV_MIN_SAMPLE_RATE_PERMILLE, FSV_READBACK_SAMPLE_RATE_PERMILLE_KNOB,
    FSV_SAMPLE_RATE_FULL_PERMILLE, fsv_knob,
};

/// Envelope label for a mutation whose every persisted row was read back and matched.
pub const FSV_LABEL_VERIFIED: &str = "fsv:verified";
/// Envelope label for a mutation verified by a *sample* of its persisted rows.
pub const FSV_LABEL_SAMPLED: &str = "fsv:verified-sampled";

/// Persisted bytes did not match the content the mutation committed.
pub const ASTRO_FSV_READBACK_MISMATCH: &str = "ASTRO_FSV_READBACK_MISMATCH";
/// The mutation's paired ledger entry is missing or names the wrong commit.
pub const ASTRO_FSV_LEDGER_UNPAIRED: &str = "ASTRO_FSV_LEDGER_UNPAIRED";
/// A verification plan was malformed (no rows, or an out-of-bounds sampling rate).
pub const ASTRO_FSV_PLAN_INVALID: &str = "ASTRO_FSV_PLAN_INVALID";

const READBACK_REMEDIATION: &str = "Persisted bytes diverge from the committed content: quarantine the named column family and key, restore or rebuild the vault from source bytes, then rerun astrolabe verify --deep.";
const LEDGER_REMEDIATION: &str = "The mutation is not paired with its ledger entry, so it cannot be acked: quarantine the vault, run astrolabe verify --deep, and rebuild from source bytes if the ledger head is inconsistent.";
const PLAN_REMEDIATION: &str = "Fix the caller: an FSV plan must name at least one persisted row and a sampling rate inside the declared knob bounds.";

/// How much of a mutation's persisted state a verification pass covered.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(tag = "coverage", rename_all = "snake_case")]
pub enum FsvCoverage {
    /// Every row the mutation persisted was re-read and content-hash compared.
    Full,
    /// A deterministic content-addressed sample of the rows was re-read.
    Sampled {
        /// The registry-declared sampling rate this pass ran under.
        rate_permille: u32,
    },
}

impl FsvCoverage {
    /// Returns the envelope label this coverage level is allowed to claim.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Full => FSV_LABEL_VERIFIED,
            Self::Sampled { .. } => FSV_LABEL_SAMPLED,
        }
    }

    /// Returns true only for a full readback of every mutated row.
    pub const fn is_full(&self) -> bool {
        matches!(self, Self::Full)
    }
}

/// The sampling policy a verification pass runs under.
///
/// Built through [`FsvSampling::from_permille`] so an out-of-bounds rate is a
/// fail-closed refusal rather than a silently clamped value.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FsvSampling {
    rate_permille: u32,
}

impl FsvSampling {
    /// Full readback: the registry default.
    pub const FULL: Self = Self {
        rate_permille: FSV_SAMPLE_RATE_FULL_PERMILLE as u32,
    };

    /// Builds a sampling policy, refusing any rate outside the declared knob bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ASTRO_FSV_PLAN_INVALID`] when `rate_permille` is outside the
    /// closed interval declared by the
    /// [`crate::knobs::FSV_READBACK_SAMPLE_RATE_PERMILLE_KNOB`] knob. Rate `0` is
    /// rejected: it would verify nothing while still producing an ack.
    pub fn from_permille(rate_permille: u32) -> Result<Self, DomainError> {
        let knob = fsv_knob(FSV_READBACK_SAMPLE_RATE_PERMILLE_KNOB)
            .expect("fsv sampling knob is declared in the FSV knob registry");
        if !knob.accepts(u64::from(rate_permille)) {
            return Err(DomainError::new(
                ASTRO_FSV_PLAN_INVALID,
                format!(
                    "readback sampling rate {rate_permille} permille is outside the declared knob bounds [{}, {}] for {}",
                    knob.min, knob.max, knob.name
                ),
                PLAN_REMEDIATION,
            ));
        }
        Ok(Self { rate_permille })
    }

    /// Returns the rate in permille.
    pub const fn rate_permille(&self) -> u32 {
        self.rate_permille
    }

    /// Returns true when the policy reads back every row.
    pub const fn is_full(&self) -> bool {
        self.rate_permille as u64 == FSV_SAMPLE_RATE_FULL_PERMILLE
    }

    /// Decides — deterministically, from row content alone — whether `key` is in the sample.
    ///
    /// The decision is a function of the key bytes only, so it is identical
    /// across worker counts, machines, and reruns (standing invariant 5:
    /// determinism is seeded and worker-count-invariant).
    pub fn selects(&self, key: &[u8]) -> bool {
        if self.is_full() {
            return true;
        }
        let digest = blake3::hash(key);
        let draw = u64::from_le_bytes(
            digest.as_bytes()[..8]
                .try_into()
                .expect("blake3 digest is 32 bytes"),
        );
        draw % FSV_SAMPLE_RATE_FULL_PERMILLE < u64::from(self.rate_permille)
    }
}

impl Default for FsvSampling {
    fn default() -> Self {
        Self::FULL
    }
}

/// What a persisted row must read back as after the commit.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FsvExpectation {
    /// The row must exist and its bytes must hash to this BLAKE3 digest.
    ///
    /// The digest — not a copy of the value — is what the plan carries, so
    /// verifying an L-scale batch costs 32 bytes of plan per row instead of a
    /// second full copy of the write set (#101).
    ContentHash([u8; 32]),
    /// The row must not read back as a live value: it must be absent, or equal
    /// to the store's tombstone marker, whose hash is carried here.
    NotLive([u8; 32]),
}

/// One persisted row a mutation is accountable for.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FsvRow {
    store: String,
    key: Vec<u8>,
    expectation: FsvExpectation,
}

impl FsvRow {
    /// Plans a row that must read back byte-identical to `bytes`.
    ///
    /// `store` names the physical location for the refusal message: a column
    /// family name for vault rows, an artifact path for derived files.
    pub fn content(store: impl Into<String>, key: impl Into<Vec<u8>>, bytes: &[u8]) -> Self {
        Self::content_hash(store, key, *blake3::hash(bytes).as_bytes())
    }

    /// Plans a row from an already-computed BLAKE3 content digest.
    ///
    /// This is the ownership-preserving group-commit boundary: the caller may
    /// hash a value before moving its only allocation into durable storage,
    /// while the verification plan retains only the fixed-size expectation.
    pub fn content_hash(
        store: impl Into<String>,
        key: impl Into<Vec<u8>>,
        content_hash: [u8; 32],
    ) -> Self {
        Self {
            store: store.into(),
            key: key.into(),
            expectation: FsvExpectation::ContentHash(content_hash),
        }
    }

    /// Plans a row that must read back as absent or as the given tombstone value.
    pub fn tombstoned(store: impl Into<String>, key: impl Into<Vec<u8>>, tombstone: &[u8]) -> Self {
        Self::tombstoned_hash(store, key, *blake3::hash(tombstone).as_bytes())
    }

    /// Plans a non-live row from the already-computed tombstone BLAKE3 digest.
    pub fn tombstoned_hash(
        store: impl Into<String>,
        key: impl Into<Vec<u8>>,
        tombstone_hash: [u8; 32],
    ) -> Self {
        Self {
            store: store.into(),
            key: key.into(),
            expectation: FsvExpectation::NotLive(tombstone_hash),
        }
    }

    /// Returns the store (column family or artifact) this row lives in.
    pub fn store(&self) -> &str {
        &self.store
    }

    /// Returns the row key.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns what the row must read back as.
    pub fn expectation(&self) -> &FsvExpectation {
        &self.expectation
    }
}

/// The ledger entry a mutation must be paired with for its ack to be legal.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FsvLedgerExpectation {
    /// Ledger `EntryKind` name, e.g. `Ingest`.
    pub kind: String,
    /// Service actor that must own the entry.
    pub actor: String,
    /// Subject bytes the entry must name.
    pub subject: Vec<u8>,
}

/// A ledger entry as it was actually read back from the store after the commit.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FsvLedgerReadback {
    /// Ledger sequence of the entry.
    pub seq: u64,
    /// Ledger `EntryKind` name of the persisted entry.
    pub kind: String,
    /// Service actor named by the persisted entry.
    pub actor: String,
    /// Subject bytes named by the persisted entry.
    pub subject: Vec<u8>,
    /// Lower-hex entry hash of the persisted entry.
    pub entry_hash_hex: String,
}

/// The set of persisted rows and the ledger entry one mutation must answer for.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FsvPlan {
    scope: String,
    rows: Vec<FsvRow>,
    ledger: FsvLedgerExpectation,
    sampling: FsvSampling,
}

impl FsvPlan {
    /// Starts a plan for `scope` (the mutation path name that appears in refusals).
    pub fn new(scope: impl Into<String>, ledger: FsvLedgerExpectation) -> Self {
        Self {
            scope: scope.into(),
            rows: Vec::new(),
            ledger,
            sampling: FsvSampling::FULL,
        }
    }

    /// Sets the sampling policy. Defaults to full readback.
    #[must_use]
    pub fn with_sampling(mut self, sampling: FsvSampling) -> Self {
        self.sampling = sampling;
        self
    }

    /// Adds a persisted row the mutation must answer for.
    pub fn push(&mut self, row: FsvRow) {
        self.rows.push(row);
    }

    /// Returns the planned rows.
    pub fn rows(&self) -> &[FsvRow] {
        &self.rows
    }

    /// Returns the scope name.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Returns the sampling policy.
    pub const fn sampling(&self) -> FsvSampling {
        self.sampling
    }

    /// Starts an ordinal-aware streaming verification of this plan.
    ///
    /// The returned verifier accepts rows in any physical order, which lets a
    /// store group reads by column family and immutable SST without retaining
    /// the values. It still requires every selected ordinal exactly once before
    /// [`FsvVerification::finish`] can mint an [`FsvAck`].
    pub fn begin_verification(&self) -> Result<FsvVerification<'_>, DomainError> {
        FsvVerification::new(self)
    }

    /// Returns whether `ordinal` belongs to the configured deterministic sample.
    /// An out-of-range ordinal is never selected.
    pub fn selects_ordinal(&self, ordinal: usize) -> bool {
        self.rows
            .get(ordinal)
            .is_some_and(|row| self.sampling.selects(&row.key))
    }

    /// Returns the plan-owned allocation footprint used for readback-memory
    /// telemetry. Persisted values are deliberately absent; this counts the
    /// row vector, owned store/key buffers, and ledger expectation buffers.
    pub fn allocated_bytes(&self) -> Result<u64, DomainError> {
        let mut bytes = self
            .rows
            .capacity()
            .checked_mul(std::mem::size_of::<FsvRow>())
            .and_then(|value| value.checked_add(self.scope.capacity()))
            .and_then(|value| value.checked_add(self.ledger.kind.capacity()))
            .and_then(|value| value.checked_add(self.ledger.actor.capacity()))
            .and_then(|value| value.checked_add(self.ledger.subject.capacity()))
            .ok_or_else(|| {
                DomainError::new(
                    ASTRO_FSV_PLAN_INVALID,
                    format!("FSV plan allocation accounting overflow for {}", self.scope),
                    PLAN_REMEDIATION,
                )
            })?;
        for row in &self.rows {
            bytes = bytes
                .checked_add(row.store.capacity())
                .and_then(|value| value.checked_add(row.key.capacity()))
                .ok_or_else(|| {
                    DomainError::new(
                        ASTRO_FSV_PLAN_INVALID,
                        format!("FSV row allocation accounting overflow for {}", self.scope),
                        PLAN_REMEDIATION,
                    )
                })?;
        }
        u64::try_from(bytes).map_err(|_| {
            DomainError::new(
                ASTRO_FSV_PLAN_INVALID,
                format!(
                    "FSV plan allocation footprint for {} exceeds u64",
                    self.scope
                ),
                PLAN_REMEDIATION,
            )
        })
    }
}

/// Incremental, ordinal-aware full-state verifier.
///
/// This is the engine seam for storage-local readback. Persisted rows may arrive
/// in any order, but every selected plan ordinal must arrive exactly once. The
/// verifier owns no persisted value buffers: each borrowed byte slice is hashed
/// and discarded before the next row is observed.
pub struct FsvVerification<'a> {
    plan: &'a FsvPlan,
    seen: Vec<bool>,
    rows_read_back: u64,
    bytes_read_back: u64,
}

impl<'a> FsvVerification<'a> {
    fn new(plan: &'a FsvPlan) -> Result<Self, DomainError> {
        if plan.rows.is_empty() {
            return Err(DomainError::new(
                ASTRO_FSV_PLAN_INVALID,
                format!(
                    "FSV plan for {} named no persisted rows; a mutation that persisted nothing must not be acked as verified",
                    plan.scope
                ),
                PLAN_REMEDIATION,
            ));
        }
        Ok(Self {
            plan,
            seen: vec![false; plan.rows.len()],
            rows_read_back: 0,
            bytes_read_back: 0,
        })
    }

    /// Hashes and compares one independently read persisted row.
    ///
    /// `ordinal` is the stable index in [`FsvPlan::rows`]. Duplicate,
    /// out-of-range, or non-selected observations are plan violations rather
    /// than silently ignored work.
    pub fn observe(&mut self, ordinal: usize, persisted: Option<&[u8]>) -> Result<(), DomainError> {
        let row = self.plan.rows.get(ordinal).ok_or_else(|| {
            DomainError::new(
                ASTRO_FSV_PLAN_INVALID,
                format!(
                    "FSV plan for {} received out-of-range row ordinal {ordinal}; row count is {}",
                    self.plan.scope,
                    self.plan.rows.len()
                ),
                PLAN_REMEDIATION,
            )
        })?;
        if !self.plan.sampling.selects(&row.key) {
            return Err(DomainError::new(
                ASTRO_FSV_PLAN_INVALID,
                format!(
                    "FSV plan for {} received unselected row ordinal {ordinal}",
                    self.plan.scope
                ),
                PLAN_REMEDIATION,
            ));
        }
        if self.seen[ordinal] {
            return Err(DomainError::new(
                ASTRO_FSV_PLAN_INVALID,
                format!(
                    "FSV plan for {} received duplicate row ordinal {ordinal}",
                    self.plan.scope
                ),
                PLAN_REMEDIATION,
            ));
        }

        match (&row.expectation, persisted) {
            (FsvExpectation::ContentHash(expected), Some(bytes)) => {
                let found = blake3::hash(bytes);
                if found.as_bytes() != expected {
                    return Err(readback_mismatch(
                        self.plan,
                        row,
                        &format!(
                            "persisted bytes hash to {} but the commit wrote content hashing to {}",
                            hex_lower(found.as_bytes()),
                            hex_lower(expected)
                        ),
                    ));
                }
                self.bytes_read_back = self
                    .bytes_read_back
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| {
                        DomainError::new(
                            ASTRO_FSV_PLAN_INVALID,
                            format!("FSV byte counter overflow for {}", self.plan.scope),
                            PLAN_REMEDIATION,
                        )
                    })?;
            }
            (FsvExpectation::ContentHash(_), None) => {
                return Err(readback_mismatch(
                    self.plan,
                    row,
                    "row is absent at the commit snapshot after the commit reported success",
                ));
            }
            (FsvExpectation::NotLive(tombstone), Some(bytes)) => {
                let found = blake3::hash(bytes);
                if found.as_bytes() != tombstone {
                    return Err(readback_mismatch(
                        self.plan,
                        row,
                        "tombstoned row still reads back as a live value",
                    ));
                }
                self.bytes_read_back = self
                    .bytes_read_back
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| {
                        DomainError::new(
                            ASTRO_FSV_PLAN_INVALID,
                            format!("FSV byte counter overflow for {}", self.plan.scope),
                            PLAN_REMEDIATION,
                        )
                    })?;
            }
            (FsvExpectation::NotLive(_), None) => {}
        }
        self.seen[ordinal] = true;
        self.rows_read_back = self.rows_read_back.checked_add(1).ok_or_else(|| {
            DomainError::new(
                ASTRO_FSV_PLAN_INVALID,
                format!("FSV row counter overflow for {}", self.plan.scope),
                PLAN_REMEDIATION,
            )
        })?;
        Ok(())
    }

    /// Verifies completeness and the independently read ledger row, then mints
    /// the unforgeable acknowledgment.
    pub fn finish(self, entry: Option<FsvLedgerReadback>) -> Result<FsvAck, DomainError> {
        if let Some((ordinal, row)) = self
            .plan
            .rows
            .iter()
            .enumerate()
            .find(|(ordinal, row)| self.plan.sampling.selects(&row.key) && !self.seen[*ordinal])
        {
            return Err(DomainError::new(
                ASTRO_FSV_PLAN_INVALID,
                format!(
                    "FSV plan for {} did not receive selected row ordinal {ordinal} store={} key={}",
                    self.plan.scope,
                    row.store,
                    hex_lower(&row.key)
                ),
                PLAN_REMEDIATION,
            ));
        }
        finish_verification(self.plan, self.rows_read_back, self.bytes_read_back, entry)
    }
}

/// Proof that a mutation's persisted state was re-read and matched, and that its
/// ledger entry exists.
///
/// This type is the whole point of the module: it has private fields, no public
/// constructor, and no `Deserialize` impl, so the *only* way any crate can hold
/// one is to have completed [`verify_mutation`] or an ordinal-aware
/// [`FsvVerification`] and had the readback succeed. A response envelope that
/// carries [`FsvAck::label`] is therefore always backed by a real readback of
/// real persisted bytes.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct FsvAck {
    label: &'static str,
    scope: String,
    #[serde(flatten)]
    coverage: FsvCoverage,
    rows_planned: u64,
    rows_read_back: u64,
    bytes_read_back: u64,
    ledger_seq: u64,
    ledger_entry_hash: String,
}

impl FsvAck {
    /// Returns the envelope label: `fsv:verified` or `fsv:verified-sampled`.
    ///
    /// An `fsv:verified` label means every persisted row of the mutation was
    /// read back and content-hash matched. Never present a sampled ack under the
    /// unqualified label.
    pub const fn label(&self) -> &'static str {
        self.label
    }

    /// Returns the mutation path this ack belongs to.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Returns the coverage this ack was earned under.
    pub const fn coverage(&self) -> FsvCoverage {
        self.coverage
    }

    /// Returns true only when every mutated row was read back.
    pub const fn is_full_readback(&self) -> bool {
        self.coverage.is_full()
    }

    /// Returns the number of persisted rows the mutation was accountable for.
    pub const fn rows_planned(&self) -> u64 {
        self.rows_planned
    }

    /// Returns the number of persisted rows actually re-read from the store.
    pub const fn rows_read_back(&self) -> u64 {
        self.rows_read_back
    }

    /// Returns the number of persisted bytes actually re-read from the store.
    pub const fn bytes_read_back(&self) -> u64 {
        self.bytes_read_back
    }

    /// Returns the ledger sequence of the paired entry.
    pub const fn ledger_seq(&self) -> u64 {
        self.ledger_seq
    }

    /// Returns the lower-hex entry hash of the paired ledger entry.
    pub fn ledger_entry_hash(&self) -> &str {
        &self.ledger_entry_hash
    }
}

impl fmt::Display for FsvAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} scope={} rows={}/{} bytes={} ledger_seq={}",
            self.label,
            self.scope,
            self.rows_read_back,
            self.rows_planned,
            self.bytes_read_back,
            self.ledger_seq
        )
    }
}

/// Re-reads a mutation's persisted rows and its paired ledger entry, and — only
/// if everything matches — mints the [`FsvAck`] that authorizes an ack.
///
/// `read_row` must perform a *real read against the store*, not return a cached
/// copy of what was written; `read_ledger` must return the entry the commit
/// actually persisted. This function does the hashing and the comparing itself,
/// so a caller cannot assert success — it can only supply bytes and be judged.
///
/// # Errors
///
/// * [`ASTRO_FSV_PLAN_INVALID`] — the plan named no rows.
/// * [`ASTRO_FSV_READBACK_MISMATCH`] — a row is missing, a row's persisted bytes
///   do not hash to the committed content, or a tombstoned key still reads back
///   live. The refusal names the exact store and key.
/// * [`ASTRO_FSV_LEDGER_UNPAIRED`] — no ledger entry was persisted for the
///   commit, or the persisted entry names a different kind, actor, or subject.
pub fn verify_mutation<R, L>(
    plan: &FsvPlan,
    mut read_row: R,
    read_ledger: L,
) -> Result<FsvAck, DomainError>
where
    R: FnMut(&FsvRow) -> Result<Option<Vec<u8>>, DomainError>,
    L: FnOnce() -> Result<Option<FsvLedgerReadback>, DomainError>,
{
    let mut verification = plan.begin_verification()?;
    for (ordinal, row) in plan.rows.iter().enumerate() {
        if !plan.selects_ordinal(ordinal) {
            continue;
        }
        let persisted = read_row(row)?;
        verification.observe(ordinal, persisted.as_deref())?;
    }
    verification.finish(read_ledger()?)
}

fn finish_verification(
    plan: &FsvPlan,
    rows_read_back: u64,
    bytes_read_back: u64,
    entry: Option<FsvLedgerReadback>,
) -> Result<FsvAck, DomainError> {
    let Some(entry) = entry else {
        return Err(DomainError::new(
            ASTRO_FSV_LEDGER_UNPAIRED,
            format!(
                "{}: the commit persisted {} row(s) but no paired ledger entry was found at the commit snapshot",
                plan.scope,
                plan.rows.len()
            ),
            LEDGER_REMEDIATION,
        ));
    };
    if entry.kind != plan.ledger.kind
        || entry.actor != plan.ledger.actor
        || entry.subject != plan.ledger.subject
    {
        return Err(DomainError::new(
            ASTRO_FSV_LEDGER_UNPAIRED,
            format!(
                "{}: ledger entry at seq {} is kind={} actor={} but the commit requires kind={} actor={} (subject match: {})",
                plan.scope,
                entry.seq,
                entry.kind,
                entry.actor,
                plan.ledger.kind,
                plan.ledger.actor,
                entry.subject == plan.ledger.subject
            ),
            LEDGER_REMEDIATION,
        ));
    }

    let coverage = if plan.sampling.is_full() {
        FsvCoverage::Full
    } else {
        FsvCoverage::Sampled {
            rate_permille: plan.sampling.rate_permille(),
        }
    };

    Ok(FsvAck {
        label: coverage.label(),
        scope: plan.scope.clone(),
        coverage,
        rows_planned: plan.rows.len() as u64,
        rows_read_back,
        bytes_read_back,
        ledger_seq: entry.seq,
        ledger_entry_hash: entry.entry_hash_hex,
    })
}

fn readback_mismatch(plan: &FsvPlan, row: &FsvRow, detail: &str) -> DomainError {
    DomainError::new(
        ASTRO_FSV_READBACK_MISMATCH,
        format!(
            "{}: readback of store={} key={} failed: {detail}",
            plan.scope,
            row.store,
            hex_lower(&row.key)
        ),
        READBACK_REMEDIATION,
    )
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

/// Returns the minimum legal sampling rate, for callers validating operator config.
pub const fn min_sample_rate_permille() -> u32 {
    FSV_MIN_SAMPLE_RATE_PERMILLE as u32
}
