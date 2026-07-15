//! Append-only, hash-chained ledger of P5.3 differentiation cards, with
//! independent read-back verification (FSV) (08_ASSAY §8).
//!
//! Every differentiation card (redundancy, synergy, causality, periodicity,
//! change-point, drift) is ledgered as a chained entry that records the card seed
//! and a content fingerprint of the card, so a reader can verify the log has not
//! been rewritten and can independently re-read the persisted card bytes. Each
//! append is proven by re-reading and re-chain-verifying the file, never by
//! trusting the write's return value.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::changepoint::ChangePointCard;
use crate::drift::DriftCard;
use crate::error::{
    ASTRO_ASSAY_READBACK_MISMATCH, ASTRO_ASSAY_STORE_CORRUPT, ASTRO_ASSAY_STORE_IO, AssayError,
    Result,
};
use crate::periodicity::PeriodicityCard;
use crate::redundancy::RedundancyCard;
use crate::synergy::SynergyCard;
use crate::transfer_entropy::CausalityCard;

/// Domain-separation tag for the differentiation ledger entry hash.
pub const ASSAY_DIFF_LEDGER_TAG: &str = "astro-assay-diff-ledger-v1";

/// The hex hash that seeds an empty chain (the genesis previous-hash).
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// One of the six P5.3 differentiation cards.
///
/// Externally tagged (`{"redundancy": {…}}`) so the serialized form round-trips
/// byte-for-byte: the ledger entry hash is recomputed from the re-serialized card
/// on every read, so serialization must be idempotent under a parse round-trip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferentiationCard {
    /// A redundancy (TC / n_eff / gate) card.
    Redundancy(RedundancyCard),
    /// A synergy (interaction-information) card.
    Synergy(SynergyCard),
    /// A causality (transfer-entropy DRIVES) card.
    Causality(CausalityCard),
    /// A periodicity (Lomb–Scargle / FAP) card.
    Periodicity(PeriodicityCard),
    /// A change-point (CUSUM) card.
    ChangePoint(ChangePointCard),
    /// A drift (MMD two-sample) card.
    Drift(DriftCard),
}

/// One ledgered differentiation-card entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffCardEntry {
    /// Zero-based sequence number in the chain.
    pub seq: u64,
    /// Hex hash of the previous entry (genesis constant for the first entry).
    pub prev_hash: String,
    /// Hex hash of this entry's canonical payload.
    pub entry_hash: String,
    /// Seed that drove the card's stochastic steps.
    pub seed: u64,
    /// The ledgered card.
    pub card: DifferentiationCard,
}

fn entry_hash(seq: u64, prev_hash: &str, seed: u64, card_json: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ASSAY_DIFF_LEDGER_TAG.as_bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(&seed.to_le_bytes());
    hasher.update(card_json);
    hasher.finalize().to_hex().to_string()
}

/// A filesystem-backed, append-only differentiation-card ledger.
#[derive(Debug, Clone)]
pub struct DiffLedger {
    path: PathBuf,
}

impl DiffLedger {
    /// Opens (creating the parent directory if needed) a ledger at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!("could not create ledger dir {}: {error}", parent.display()),
                    "ensure the ledger root is writable before appending cards",
                )
            })?;
        }
        Ok(Self { path })
    }

    /// Reads and chain-verifies every ledgered entry, in sequence order.
    pub fn read_all(&self) -> Result<Vec<DiffCardEntry>> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!("could not read ledger {}: {error}", self.path.display()),
                    "check the ledger filesystem before retrying",
                ));
            }
        };
        let text = String::from_utf8(bytes).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("ledger {} is not utf-8: {error}", self.path.display()),
                "quarantine the corrupt ledger and rebuild it",
            )
        })?;
        let mut entries = Vec::new();
        let mut prev = GENESIS_PREV_HASH.to_string();
        for (line_no, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let entry: DiffCardEntry = serde_json::from_str(line).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!(
                        "{}:{} did not parse: {error}",
                        self.path.display(),
                        line_no + 1
                    ),
                    "quarantine the corrupt ledger and rebuild it",
                )
            })?;
            if entry.seq != entries.len() as u64 {
                return Err(AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!(
                        "ledger sequence gap at line {}: expected {} got {}",
                        line_no + 1,
                        entries.len(),
                        entry.seq
                    ),
                    "quarantine the corrupt ledger and rebuild it",
                ));
            }
            if entry.prev_hash != prev {
                return Err(AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!(
                        "ledger chain break at seq {}: prev_hash does not match",
                        entry.seq
                    ),
                    "quarantine the corrupt ledger and rebuild it",
                ));
            }
            let card_json = serde_json::to_vec(&entry.card).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!("could not re-serialize card at seq {}: {error}", entry.seq),
                    "quarantine the corrupt ledger and rebuild it",
                )
            })?;
            let recomputed = entry_hash(entry.seq, &entry.prev_hash, entry.seed, &card_json);
            if recomputed != entry.entry_hash {
                return Err(AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!("ledger entry hash mismatch at seq {}", entry.seq),
                    "quarantine the corrupt ledger and rebuild it",
                ));
            }
            prev = entry.entry_hash.clone();
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Appends a card to the ledger and proves the write by reading it back.
    pub fn append(&self, card: &DifferentiationCard, seed: u64) -> Result<DiffCardEntry> {
        let existing = self.read_all()?;
        let seq = existing.len() as u64;
        let prev_hash = existing
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
        let card_json = serde_json::to_vec(card).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("could not serialize card: {error}"),
                "this is an internal serialization fault; report it",
            )
        })?;
        let hash = entry_hash(seq, &prev_hash, seed, &card_json);
        let entry = DiffCardEntry {
            seq,
            prev_hash,
            entry_hash: hash,
            seed,
            card: card.clone(),
        };
        let mut line = serde_json::to_vec(&entry).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("could not serialize ledger entry: {error}"),
                "this is an internal serialization fault; report it",
            )
        })?;
        line.push(b'\n');

        let mut all = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                return Err(AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!(
                        "could not read ledger {} before append: {error}",
                        self.path.display()
                    ),
                    "check the ledger filesystem before retrying",
                ));
            }
        };
        all.extend_from_slice(&line);
        fs::write(&self.path, &all).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_IO,
                format!("could not write ledger {}: {error}", self.path.display()),
                "ensure the ledger root is writable before appending cards",
            )
        })?;
        // FSV: re-read and re-chain-verify; the freshly appended entry must be the
        // last one and must parse back to exactly what we intended to write.
        let readback = self.read_all()?;
        match readback.last() {
            Some(last) if *last == entry => Ok(entry),
            _ => Err(AssayError::new(
                ASTRO_ASSAY_READBACK_MISMATCH,
                "appended ledger entry did not read back as written",
                "the persisted ledger diverges from the committed entry; quarantine the ledger root",
            )),
        }
    }
}
