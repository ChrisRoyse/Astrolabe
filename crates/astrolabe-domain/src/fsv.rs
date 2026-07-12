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
//! * The only function in the entire workspace that returns one is
//!   [`verify_mutation`], and that function *performs the comparison itself* —
//!   it re-reads every planned row through the caller's reader, hashes the bytes
//!   it got back, compares them to the planned content hash, and reads back the
//!   paired ledger entry. A caller cannot hand it a "yes it matched" boolean.
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
        Self {
            store: store.into(),
            key: key.into(),
            expectation: FsvExpectation::ContentHash(*blake3::hash(bytes).as_bytes()),
        }
    }

    /// Plans a row that must read back as absent or as the given tombstone value.
    pub fn tombstoned(store: impl Into<String>, key: impl Into<Vec<u8>>, tombstone: &[u8]) -> Self {
        Self {
            store: store.into(),
            key: key.into(),
            expectation: FsvExpectation::NotLive(*blake3::hash(tombstone).as_bytes()),
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
}

/// Proof that a mutation's persisted state was re-read and matched, and that its
/// ledger entry exists.
///
/// This type is the whole point of the module: it has private fields, no public
/// constructor, and no `Deserialize` impl, so the *only* way any crate can hold
/// one is to have called [`verify_mutation`] and had the readback succeed. A
/// response envelope that carries [`FsvAck::label`] is therefore always backed by
/// a real readback of real persisted bytes.
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

    let mut rows_read_back = 0_u64;
    let mut bytes_read_back = 0_u64;
    for row in &plan.rows {
        if !plan.sampling.selects(&row.key) {
            continue;
        }
        let persisted = read_row(row)?;
        match (&row.expectation, persisted) {
            (FsvExpectation::ContentHash(expected), Some(bytes)) => {
                let found = blake3::hash(&bytes);
                if found.as_bytes() != expected {
                    return Err(readback_mismatch(
                        plan,
                        row,
                        &format!(
                            "persisted bytes hash to {} but the commit wrote content hashing to {}",
                            hex_lower(found.as_bytes()),
                            hex_lower(expected)
                        ),
                    ));
                }
                bytes_read_back = bytes_read_back.saturating_add(bytes.len() as u64);
            }
            (FsvExpectation::ContentHash(_), None) => {
                return Err(readback_mismatch(
                    plan,
                    row,
                    "row is absent at the commit snapshot after the commit reported success",
                ));
            }
            (FsvExpectation::NotLive(tombstone), Some(bytes)) => {
                let found = blake3::hash(&bytes);
                if found.as_bytes() != tombstone {
                    return Err(readback_mismatch(
                        plan,
                        row,
                        "tombstoned row still reads back as a live value",
                    ));
                }
                bytes_read_back = bytes_read_back.saturating_add(bytes.len() as u64);
            }
            (FsvExpectation::NotLive(_), None) => {}
        }
        rows_read_back = rows_read_back.saturating_add(1);
    }

    let Some(entry) = read_ledger()? else {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger_expect() -> FsvLedgerExpectation {
        FsvLedgerExpectation {
            kind: "Ingest".to_string(),
            actor: "astrolabe-test".to_string(),
            subject: b"subject".to_vec(),
        }
    }

    fn ledger_readback() -> FsvLedgerReadback {
        FsvLedgerReadback {
            seq: 7,
            kind: "Ingest".to_string(),
            actor: "astrolabe-test".to_string(),
            subject: b"subject".to_vec(),
            entry_hash_hex: "ab".repeat(32),
        }
    }

    fn plan_with(rows: Vec<(&'static str, Vec<u8>)>) -> FsvPlan {
        let mut plan = FsvPlan::new("test-scope", ledger_expect());
        for (key, bytes) in rows {
            plan.push(FsvRow::content("Kv", key.as_bytes().to_vec(), &bytes));
        }
        plan
    }

    #[test]
    fn full_readback_of_matching_bytes_mints_the_verified_label() {
        let plan = plan_with(vec![("a", b"alpha".to_vec()), ("b", b"beta".to_vec())]);
        let ack = verify_mutation(
            &plan,
            |row| {
                Ok(Some(match row.key() {
                    b"a" => b"alpha".to_vec(),
                    b"b" => b"beta".to_vec(),
                    other => panic!("unexpected key {other:?}"),
                }))
            },
            || Ok(Some(ledger_readback())),
        )
        .expect("clean readback");
        assert_eq!(ack.label(), FSV_LABEL_VERIFIED);
        assert!(ack.is_full_readback());
        assert_eq!(ack.rows_planned(), 2);
        assert_eq!(ack.rows_read_back(), 2);
        assert_eq!(ack.bytes_read_back(), 9);
        assert_eq!(ack.ledger_seq(), 7);
    }

    #[test]
    fn one_flipped_byte_fails_closed_and_names_the_row() {
        let plan = plan_with(vec![("a", b"alpha".to_vec())]);
        let err = verify_mutation(
            &plan,
            |_row| Ok(Some(b"alphb".to_vec())),
            || Ok(Some(ledger_readback())),
        )
        .expect_err("tampered bytes must refuse");
        assert_eq!(err.code(), ASTRO_FSV_READBACK_MISMATCH);
        assert!(err.message().contains("store=Kv"), "{err}");
        assert!(err.message().contains(&hex_lower(b"a")), "{err}");
        assert!(!err.remediation().is_empty());
    }

    #[test]
    fn missing_ledger_entry_cannot_ack() {
        let plan = plan_with(vec![("a", b"alpha".to_vec())]);
        let err = verify_mutation(&plan, |_row| Ok(Some(b"alpha".to_vec())), || Ok(None))
            .expect_err("unpaired mutation must refuse");
        assert_eq!(err.code(), ASTRO_FSV_LEDGER_UNPAIRED);
    }

    #[test]
    fn wrong_actor_on_the_paired_entry_cannot_ack() {
        let plan = plan_with(vec![("a", b"alpha".to_vec())]);
        let err = verify_mutation(
            &plan,
            |_row| Ok(Some(b"alpha".to_vec())),
            || {
                Ok(Some(FsvLedgerReadback {
                    actor: "someone-else".to_string(),
                    ..ledger_readback()
                }))
            },
        )
        .expect_err("wrong actor must refuse");
        assert_eq!(err.code(), ASTRO_FSV_LEDGER_UNPAIRED);
    }

    #[test]
    fn sampled_ack_is_labeled_sampled_and_never_verified() {
        let sampling = FsvSampling::from_permille(500).expect("in bounds");
        let rows = (0..64_u32)
            .map(|index| (index.to_le_bytes().to_vec(), format!("value-{index}")))
            .collect::<Vec<_>>();
        let mut plan = FsvPlan::new("sampled-scope", ledger_expect()).with_sampling(sampling);
        for (key, value) in &rows {
            plan.push(FsvRow::content("Kv", key.clone(), value.as_bytes()));
        }
        let mut reads = 0_u64;
        let ack = verify_mutation(
            &plan,
            |row| {
                reads += 1;
                let index = u32::from_le_bytes(row.key().try_into().expect("key"));
                Ok(Some(format!("value-{index}").into_bytes()))
            },
            || Ok(Some(ledger_readback())),
        )
        .expect("sampled readback");
        assert_eq!(ack.label(), FSV_LABEL_SAMPLED);
        assert!(!ack.is_full_readback());
        assert_eq!(ack.rows_planned(), 64);
        assert!(ack.rows_read_back() < 64, "sample must be a strict subset");
        assert_eq!(ack.rows_read_back(), reads);
        assert_eq!(ack.coverage(), FsvCoverage::Sampled { rate_permille: 500 });
    }

    #[test]
    fn sampling_selection_is_deterministic_across_runs() {
        let sampling = FsvSampling::from_permille(250).expect("in bounds");
        let first = (0..256_u32)
            .filter(|index| sampling.selects(&index.to_le_bytes()))
            .collect::<Vec<_>>();
        let second = (0..256_u32)
            .filter(|index| sampling.selects(&index.to_le_bytes()))
            .collect::<Vec<_>>();
        assert_eq!(first, second);
        assert!(!first.is_empty() && first.len() < 256);
    }

    #[test]
    fn zero_and_over_max_sampling_rates_are_refused() {
        let zero = FsvSampling::from_permille(0).expect_err("zero rate must refuse");
        assert_eq!(zero.code(), ASTRO_FSV_PLAN_INVALID);
        let over = FsvSampling::from_permille(1_001).expect_err("over-max rate must refuse");
        assert_eq!(over.code(), ASTRO_FSV_PLAN_INVALID);
        assert!(FsvSampling::from_permille(1).is_ok());
        assert!(FsvSampling::from_permille(1_000).expect("max").is_full());
    }

    #[test]
    fn empty_plan_cannot_ack() {
        let plan = FsvPlan::new("empty-scope", ledger_expect());
        let err = verify_mutation(
            &plan,
            |_row| Ok(Some(Vec::new())),
            || Ok(Some(ledger_readback())),
        )
        .expect_err("empty plan must refuse");
        assert_eq!(err.code(), ASTRO_FSV_PLAN_INVALID);
    }

    #[test]
    fn tombstoned_row_reading_back_live_fails_closed() {
        let mut plan = FsvPlan::new("tombstone-scope", ledger_expect());
        plan.push(FsvRow::tombstoned("Kernel", b"gone".to_vec(), b""));
        let err = verify_mutation(
            &plan,
            |_row| Ok(Some(b"still-here".to_vec())),
            || Ok(Some(ledger_readback())),
        )
        .expect_err("live tombstone must refuse");
        assert_eq!(err.code(), ASTRO_FSV_READBACK_MISMATCH);

        let ack = verify_mutation(&plan, |_row| Ok(None), || Ok(Some(ledger_readback())))
            .expect("absent tombstoned row verifies");
        assert_eq!(ack.label(), FSV_LABEL_VERIFIED);
    }
}
