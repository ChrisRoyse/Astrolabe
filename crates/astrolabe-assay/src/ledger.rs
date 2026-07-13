//! Append-only, hash-chained ledger of assay cards, with reproduce (08 §8).
//!
//! Every card the bits pipeline emits is ledgered as an entry that records the
//! *exact* inputs needed to re-derive it: the card seed, a content fingerprint of
//! the slot/axis observations, and the card itself with its per-slot estimator,
//! `n`, interval, and trust. Entries are chained — each carries the previous
//! entry's hash — so a reader can verify the log has not been rewritten, and each
//! write is proven by reading the bytes back (FSV). `reproduce` re-runs the
//! measurement from the recorded seed and inputs and asserts the result matches
//! the ledgered card bit-for-bit, which is exactly the reproducibility contract
//! the blueprint requires (`reproduce` re-derives within tolerance).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::bits::{
    AxisValues, BitsConfig, SignalRankingCard, SlotObservations, build_signal_ranking,
};
use crate::error::{
    ASTRO_ASSAY_READBACK_MISMATCH, ASTRO_ASSAY_REPRODUCE_MISMATCH, ASTRO_ASSAY_STORE_CORRUPT,
    ASTRO_ASSAY_STORE_IO, AssayError, Result,
};

/// Domain-separation tag for the ledger entry hash.
pub const ASSAY_LEDGER_TAG: &str = "astro-assay-card-ledger-v1";

/// The hex hash that seeds an empty chain (the genesis previous-hash).
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// One ledgered assay card entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssayCardEntry {
    /// Zero-based sequence number in the chain.
    pub seq: u64,
    /// Hex hash of the previous entry (genesis constant for the first entry).
    pub prev_hash: String,
    /// Hex hash of this entry's canonical payload.
    pub entry_hash: String,
    /// Seed that drove the card's stochastic steps.
    pub seed: u64,
    /// Hex blake3 fingerprint of the exact `(slots, axis)` inputs.
    pub input_fingerprint: String,
    /// The ledgered card.
    pub card: SignalRankingCard,
}

/// Computes the content fingerprint of a slot/axis input set.
///
/// Canonical JSON of the ordered inputs is hashed, so two callers that assemble
/// the same observations produce the same fingerprint. Fails closed if the inputs
/// cannot be serialized.
pub fn input_fingerprint(slots: &[SlotObservations], axis: &AxisValues) -> Result<String> {
    let bytes = serde_json::to_vec(&(slots, axis)).map_err(|error| {
        AssayError::new(
            ASTRO_ASSAY_STORE_CORRUPT,
            format!("could not serialize measurement inputs: {error}"),
            "this is an internal serialization fault; report it with the failing inputs",
        )
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(ASSAY_LEDGER_TAG.as_bytes());
    hasher.update(b"inputs");
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn entry_hash(
    seq: u64,
    prev_hash: &str,
    seed: u64,
    input_fingerprint: &str,
    card_json: &[u8],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ASSAY_LEDGER_TAG.as_bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(&seed.to_le_bytes());
    hasher.update(input_fingerprint.as_bytes());
    hasher.update(card_json);
    hasher.finalize().to_hex().to_string()
}

/// A filesystem-backed, append-only assay card ledger.
#[derive(Debug, Clone)]
pub struct CardLedger {
    path: PathBuf,
}

impl CardLedger {
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
    ///
    /// A broken chain (a `prev_hash` that does not match the prior entry's
    /// `entry_hash`, a recomputed hash that does not match, or a sequence gap)
    /// fails closed rather than being served.
    pub fn read_all(&self) -> Result<Vec<AssayCardEntry>> {
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
            let entry: AssayCardEntry = serde_json::from_str(line).map_err(|error| {
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
            let recomputed = entry_hash(
                entry.seq,
                &entry.prev_hash,
                entry.seed,
                &entry.input_fingerprint,
                &card_json,
            );
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
    ///
    /// Records the card seed and the input fingerprint alongside the card so the
    /// entry is self-sufficient for [`CardLedger::reproduce`]. The written line is
    /// re-read and re-parsed (FSV) before returning.
    pub fn append(
        &self,
        card: &SignalRankingCard,
        seed: u64,
        input_fingerprint: &str,
    ) -> Result<AssayCardEntry> {
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
        let hash = entry_hash(seq, &prev_hash, seed, input_fingerprint, &card_json);
        let entry = AssayCardEntry {
            seq,
            prev_hash,
            entry_hash: hash,
            seed,
            input_fingerprint: input_fingerprint.to_string(),
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

    /// Re-derives the card at `seq` from its recorded seed and the supplied inputs
    /// and asserts the result matches the ledgered card bit-for-bit.
    ///
    /// The supplied inputs must fingerprint to the value recorded in the entry
    /// (so the same observations are being reproduced), and the re-derived card
    /// must equal the ledgered one. Because every stochastic step is seeded, the
    /// match is exact, not merely within tolerance. Returns the re-derived card.
    pub fn reproduce(
        &self,
        seq: u64,
        slots: &[SlotObservations],
        axis: &AxisValues,
        cfg: &BitsConfig,
    ) -> Result<SignalRankingCard> {
        let entries = self.read_all()?;
        let entry = entries.get(seq as usize).ok_or_else(|| {
            AssayError::new(
                ASTRO_ASSAY_REPRODUCE_MISMATCH,
                format!("no ledger entry at seq {seq}"),
                "reproduce an entry that exists in the ledger",
            )
        })?;
        let fp = input_fingerprint(slots, axis)?;
        if fp != entry.input_fingerprint {
            return Err(AssayError::new(
                ASTRO_ASSAY_REPRODUCE_MISMATCH,
                format!(
                    "reproduce inputs fingerprint {fp} does not match ledgered {}",
                    entry.input_fingerprint
                ),
                "reproduce with the exact observations the card was measured over",
            ));
        }
        let rederived =
            build_signal_ranking(entry.card.axis.clone(), slots, axis, entry.seed, cfg)?;
        if rederived != entry.card {
            return Err(AssayError::new(
                ASTRO_ASSAY_REPRODUCE_MISMATCH,
                format!("re-derived card at seq {seq} did not match the ledgered card"),
                "the measurement is not reproducible from its recorded seed and inputs; investigate non-determinism",
            ));
        }
        Ok(rederived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bits::{SlotValues, build_signal_ranking};
    use crate::rng::DeterministicRng;

    fn fixture() -> (Vec<SlotObservations>, AxisValues, BitsConfig) {
        let cfg = BitsConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(1, "fixture");
        let n = 120;
        let mut scalar = Vec::new();
        let mut axis = Vec::new();
        for _ in 0..n {
            let z = rng.next_standard_normal();
            scalar.push(z);
            axis.push(if z + 0.3 * rng.next_standard_normal() > 0.0 {
                1
            } else {
                0
            });
        }
        let slots = vec![SlotObservations {
            slot: "scalar".into(),
            values: SlotValues::Scalar(scalar),
        }];
        (slots, AxisValues::Discrete(axis), cfg)
    }

    #[test]
    fn append_reads_back_and_reproduces() {
        let dir = std::env::temp_dir().join(format!("astro-assay-ledger-{}", std::process::id()));
        let path = dir.join("cards.ndjson");
        let _ = fs::remove_file(&path);
        let ledger = CardLedger::open(&path).unwrap();
        let (slots, axis, cfg) = fixture();
        let seed = 7;
        let card = build_signal_ranking("defect", &slots, &axis, seed, &cfg).unwrap();
        let fp = input_fingerprint(&slots, &axis).unwrap();
        let entry = ledger.append(&card, seed, &fp).unwrap();
        assert_eq!(entry.seq, 0);
        assert_eq!(entry.prev_hash, GENESIS_PREV_HASH);
        // Reproduce re-derives the same card exactly.
        let re = ledger.reproduce(0, &slots, &axis, &cfg).unwrap();
        assert_eq!(re, card);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reproduce_rejects_mismatched_inputs() {
        let dir = std::env::temp_dir().join(format!("astro-assay-ledger2-{}", std::process::id()));
        let path = dir.join("cards.ndjson");
        let _ = fs::remove_file(&path);
        let ledger = CardLedger::open(&path).unwrap();
        let (slots, axis, cfg) = fixture();
        let card = build_signal_ranking("defect", &slots, &axis, 7, &cfg).unwrap();
        let fp = input_fingerprint(&slots, &axis).unwrap();
        ledger.append(&card, 7, &fp).unwrap();
        // Perturb one input value; reproduce must refuse on fingerprint mismatch.
        let mut other = slots.clone();
        if let SlotValues::Scalar(v) = &mut other[0].values {
            v[0] += 1.0;
        }
        let err = ledger.reproduce(0, &other, &axis, &cfg).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_REPRODUCE_MISMATCH);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_detects_tamper() {
        let dir = std::env::temp_dir().join(format!("astro-assay-ledger3-{}", std::process::id()));
        let path = dir.join("cards.ndjson");
        let _ = fs::remove_file(&path);
        let ledger = CardLedger::open(&path).unwrap();
        let (slots, axis, cfg) = fixture();
        let card = build_signal_ranking("defect", &slots, &axis, 7, &cfg).unwrap();
        let fp = input_fingerprint(&slots, &axis).unwrap();
        ledger.append(&card, 7, &fp).unwrap();
        // Tamper: rewrite the file with a flipped seed but stale hash.
        let mut entries = ledger.read_all().unwrap();
        entries[0].seed = 999;
        let mut line = serde_json::to_vec(&entries[0]).unwrap();
        line.push(b'\n');
        fs::write(&path, &line).unwrap();
        let err = ledger.read_all().unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_STORE_CORRUPT);
        let _ = fs::remove_dir_all(&dir);
    }
}
