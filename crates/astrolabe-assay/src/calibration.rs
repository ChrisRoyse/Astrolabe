//! Edge-strategy calibration: CBM's fixed resolution-strategy confidences become
//! per-repo *measured* precisions with confidence intervals (blueprint 08_ASSAY
//! §5, deliverable card 6).
//!
//! CBM resolves a call/reference edge with one of a fixed set of strategies —
//! `import_map` (prior 0.95), `same_module` (0.90), `unique` (0.75), `suffix`
//! (0.55), `service_pattern` (0.50), `lsp` (0.60–0.95) — each carrying a *guessed*
//! confidence baked into the source. This module replaces each guess with the
//! strategy's **empirical precision** measured against ground truth: the fraction
//! of that strategy's edges that an LSP-confirmed or trace-confirmed resolution
//! agrees with, in *this* repo. The measured precision becomes the edge-weight
//! prior, carried with a Wilson score interval.
//!
//! The honesty discipline is explicit and asserted:
//!
//! * **Measured supersedes prior.** Once a strategy has at least the declared
//!   minimum ground-truth samples ([`crate::knobs::ASSAY_CALIBRATION_MIN_SAMPLES_KNOB`]),
//!   its measured precision replaces the prior as the effective confidence, with
//!   a [Wilson interval](crate::stats::wilson_interval) attached. It is tagged
//!   `Trusted` (measured against resolved ground truth).
//! * **Prior retained as fallback where unmeasured.** A strategy with too few
//!   ground-truth samples keeps its CBM prior as the effective confidence, tagged
//!   `Provisional` and labeled `prior_fallback`, so an unmeasured strategy is
//!   never silently presented as measured.
//!
//! The card is deterministic — a pure function of `(observations, config)` — so
//! it reproduces bit-for-bit through the [`CalibrationLedger`], which chains and
//! read-back-verifies every entry exactly as [`crate::ledger::CardLedger`] does
//! for signal-ranking cards.

use std::fs;
use std::path::{Path, PathBuf};

use astrolabe_domain::TrustTag;
use serde::{Deserialize, Serialize};

use crate::error::{
    ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, ASTRO_ASSAY_READBACK_MISMATCH,
    ASTRO_ASSAY_REPRODUCE_MISMATCH, ASTRO_ASSAY_STORE_CORRUPT, ASTRO_ASSAY_STORE_IO, AssayError,
    Result,
};
use crate::knobs::{
    ASSAY_CALIBRATION_MIN_SAMPLES_KNOB, ASSAY_CI_CONFIDENCE_PERMILLE_KNOB,
    ASSAY_DEFAULT_CALIBRATION_MIN_SAMPLES, ASSAY_DEFAULT_CI_CONFIDENCE_PERMILLE, assay_bits_knob,
    assay_card_knob,
};
use crate::stats::wilson_interval;

/// One edge strategy's ground-truth observations for a repo.
///
/// `correct` of `total` of this strategy's resolved edges were confirmed by the
/// ground-truth oracle (LSP-confirmed + trace-confirmed). `prior` is CBM's fixed
/// confidence for the strategy, retained as a fallback below quorum.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyObservation {
    /// Stable strategy name (e.g. `import_map`, `service_pattern`, `lsp`).
    pub strategy: String,
    /// CBM's fixed prior confidence for this strategy, in `[0, 1]`.
    pub prior: f64,
    /// Ground-truth-confirmed edges resolved by this strategy.
    pub correct: u64,
    /// Total edges resolved by this strategy that were checked against truth.
    pub total: u64,
}

/// A measured per-strategy precision with its confidence interval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasuredPrecision {
    /// Empirical precision `correct / total`, in `[0, 1]`.
    pub precision: f64,
    /// Wilson score interval lower endpoint.
    pub ci_lo: f64,
    /// Wilson score interval upper endpoint.
    pub ci_hi: f64,
    /// Two-sided interval level, in permille (950 = 95%).
    pub level_permille: u64,
    /// Number of ground-truth samples the precision was measured over.
    pub n: u64,
}

/// Where a strategy's effective confidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationSource {
    /// Measured empirical precision, replacing the prior (at or above quorum).
    Measured,
    /// The CBM prior, retained as a fallback (below quorum / unmeasured).
    PriorFallback,
}

impl CalibrationSource {
    /// Stable response-envelope label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::PriorFallback => "prior_fallback",
        }
    }
}

/// One strategy's calibration: its prior, its measurement (if any), and the
/// effective confidence the edge weight should now use.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyCalibration {
    /// Strategy name.
    pub strategy: String,
    /// CBM's fixed prior confidence.
    pub prior: f64,
    /// The measured precision + interval, present only when at/above quorum.
    pub measured: Option<MeasuredPrecision>,
    /// The confidence the edge weight should use: the measured precision when
    /// measured, otherwise the prior.
    pub effective_confidence: f64,
    /// Whether `effective_confidence` is measured or a prior fallback.
    pub source: CalibrationSource,
    /// `Trusted` when measured against ground truth, else `Provisional`.
    pub trust: TrustTag,
}

/// A calibration card: every edge strategy's measured precision vs its prior.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationCard {
    /// Per-strategy calibrations, ordered by strategy name.
    pub strategies: Vec<StrategyCalibration>,
    /// The quorum used: strategies with `total` below it keep their prior.
    pub min_samples: u64,
    /// The interval level applied to every measured precision, in permille.
    pub ci_level_permille: u64,
}

/// Resolved configuration for the calibration card, drawn from the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibrationConfig {
    /// Minimum ground-truth samples before a measured precision supersedes the prior.
    pub min_samples: u64,
    /// Two-sided Wilson interval level, in permille.
    pub ci_level_permille: u64,
}

impl CalibrationConfig {
    /// Builds the config from the declared knob defaults, failing closed if a
    /// declared default is out of its own bounds.
    pub fn from_defaults() -> Result<Self> {
        let min_samples = checked_card(
            ASSAY_CALIBRATION_MIN_SAMPLES_KNOB,
            ASSAY_DEFAULT_CALIBRATION_MIN_SAMPLES,
        )?;
        let ci_level_permille = checked_bits(
            ASSAY_CI_CONFIDENCE_PERMILLE_KNOB,
            ASSAY_DEFAULT_CI_CONFIDENCE_PERMILLE,
        )?;
        Ok(Self {
            min_samples,
            ci_level_permille,
        })
    }
}

fn checked_card(name: &str, value: u64) -> Result<u64> {
    let knob = assay_card_knob(name).ok_or_else(|| {
        AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("card knob {name} is not declared"),
            "declare the knob in ASSAY_CARD_KNOBS before using it",
        )
    })?;
    if !knob.accepts(value) {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("card knob {name} default {value} is outside its declared bounds"),
            "correct the knob default so it lies within [min, max]",
        ));
    }
    Ok(value)
}

fn checked_bits(name: &str, value: u64) -> Result<u64> {
    let knob = assay_bits_knob(name).ok_or_else(|| {
        AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("bits knob {name} is not declared"),
            "declare the knob in ASSAY_BITS_KNOBS before using it",
        )
    })?;
    if !knob.accepts(value) {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("bits knob {name} default {value} is outside its declared bounds"),
            "correct the knob default so it lies within [min, max]",
        ));
    }
    Ok(value)
}

/// Builds a calibration card from per-strategy ground-truth observations.
///
/// For each strategy: a `total` at or above `cfg.min_samples` yields a measured
/// precision `correct/total` with a Wilson interval, replacing the prior as the
/// effective confidence and tagging the entry `Trusted`/`measured`. Below quorum
/// the prior is retained as the effective confidence, tagged
/// `Provisional`/`prior_fallback`. Strategies are ordered by name so the card is
/// a pure function of the observation set.
///
/// Fails closed on a non-finite or out-of-range prior, `correct > total`, an
/// empty strategy name, or a duplicate strategy (ambiguous ground truth).
pub fn build_calibration_card(
    observations: &[StrategyObservation],
    cfg: &CalibrationConfig,
) -> Result<CalibrationCard> {
    let mut seen = std::collections::BTreeSet::new();
    let mut strategies = Vec::with_capacity(observations.len());
    for obs in observations {
        if obs.strategy.trim().is_empty() {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                "a strategy observation carries an empty strategy name",
                "name every calibration strategy with a stable non-empty identifier",
            ));
        }
        if !seen.insert(obs.strategy.clone()) {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!("strategy {} appears more than once", obs.strategy),
                "supply exactly one aggregated observation per strategy",
            ));
        }
        if !obs.prior.is_finite() || !(0.0..=1.0).contains(&obs.prior) {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!(
                    "strategy {} prior {} is not a finite confidence in [0, 1]",
                    obs.strategy, obs.prior
                ),
                "supply each strategy's CBM prior as a finite confidence in [0, 1]",
            ));
        }
        if obs.correct > obs.total {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!(
                    "strategy {} has {} correct of {} total (correct exceeds total)",
                    obs.strategy, obs.correct, obs.total
                ),
                "correct-confirmed edges cannot exceed the total checked against ground truth",
            ));
        }

        let calibration = if obs.total >= cfg.min_samples {
            let level = cfg.ci_level_permille as f64 / 1000.0;
            let (ci_lo, ci_hi) = wilson_interval(obs.correct, obs.total, level);
            let precision = obs.correct as f64 / obs.total as f64;
            StrategyCalibration {
                strategy: obs.strategy.clone(),
                prior: obs.prior,
                measured: Some(MeasuredPrecision {
                    precision,
                    ci_lo,
                    ci_hi,
                    level_permille: cfg.ci_level_permille,
                    n: obs.total,
                }),
                effective_confidence: precision,
                source: CalibrationSource::Measured,
                trust: TrustTag::Trusted,
            }
        } else {
            StrategyCalibration {
                strategy: obs.strategy.clone(),
                prior: obs.prior,
                measured: None,
                effective_confidence: obs.prior,
                source: CalibrationSource::PriorFallback,
                trust: TrustTag::Provisional,
            }
        };
        strategies.push(calibration);
    }
    strategies.sort_by(|a, b| a.strategy.cmp(&b.strategy));
    Ok(CalibrationCard {
        strategies,
        min_samples: cfg.min_samples,
        ci_level_permille: cfg.ci_level_permille,
    })
}

/// Domain-separation tag for the calibration ledger entry hash.
pub const CALIBRATION_LEDGER_TAG: &str = "astro-assay-calibration-ledger-v1";

/// The hex hash that seeds an empty calibration chain.
pub const CALIBRATION_GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// One ledgered calibration card entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationLedgerEntry {
    /// Zero-based sequence number in the chain.
    pub seq: u64,
    /// Hex hash of the previous entry (genesis constant for the first entry).
    pub prev_hash: String,
    /// Hex hash of this entry's canonical payload.
    pub entry_hash: String,
    /// Hex blake3 fingerprint of the exact observation set.
    pub input_fingerprint: String,
    /// The ledgered calibration card.
    pub card: CalibrationCard,
}

/// Computes the content fingerprint of a calibration observation set.
pub fn calibration_input_fingerprint(observations: &[StrategyObservation]) -> Result<String> {
    let bytes = serde_json::to_vec(observations).map_err(|error| {
        AssayError::new(
            ASTRO_ASSAY_STORE_CORRUPT,
            format!("could not serialize calibration observations: {error}"),
            "this is an internal serialization fault; report it with the failing inputs",
        )
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(CALIBRATION_LEDGER_TAG.as_bytes());
    hasher.update(b"inputs");
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn calibration_entry_hash(
    seq: u64,
    prev_hash: &str,
    input_fingerprint: &str,
    card_json: &[u8],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CALIBRATION_LEDGER_TAG.as_bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(input_fingerprint.as_bytes());
    hasher.update(card_json);
    hasher.finalize().to_hex().to_string()
}

/// A filesystem-backed, append-only calibration card ledger.
#[derive(Debug, Clone)]
pub struct CalibrationLedger {
    path: PathBuf,
}

impl CalibrationLedger {
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
    pub fn read_all(&self) -> Result<Vec<CalibrationLedgerEntry>> {
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
        let mut prev = CALIBRATION_GENESIS_PREV_HASH.to_string();
        for (line_no, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let entry: CalibrationLedgerEntry = serde_json::from_str(line).map_err(|error| {
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
            let recomputed = calibration_entry_hash(
                entry.seq,
                &entry.prev_hash,
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

    /// Appends a calibration card, proving the write by reading it back (FSV).
    pub fn append(
        &self,
        card: &CalibrationCard,
        input_fingerprint: &str,
    ) -> Result<CalibrationLedgerEntry> {
        let existing = self.read_all()?;
        let seq = existing.len() as u64;
        let prev_hash = existing
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| CALIBRATION_GENESIS_PREV_HASH.to_string());
        let card_json = serde_json::to_vec(card).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("could not serialize card: {error}"),
                "this is an internal serialization fault; report it",
            )
        })?;
        let hash = calibration_entry_hash(seq, &prev_hash, input_fingerprint, &card_json);
        let entry = CalibrationLedgerEntry {
            seq,
            prev_hash,
            entry_hash: hash,
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
                "appended calibration ledger entry did not read back as written",
                "the persisted ledger diverges from the committed entry; quarantine the ledger root",
            )),
        }
    }

    /// Re-derives the card at `seq` from the supplied observations and asserts it
    /// matches the ledgered card bit-for-bit (deterministic, exact).
    pub fn reproduce(
        &self,
        seq: u64,
        observations: &[StrategyObservation],
        cfg: &CalibrationConfig,
    ) -> Result<CalibrationCard> {
        let entries = self.read_all()?;
        let entry = entries.get(seq as usize).ok_or_else(|| {
            AssayError::new(
                ASTRO_ASSAY_REPRODUCE_MISMATCH,
                format!("no calibration ledger entry at seq {seq}"),
                "reproduce an entry that exists in the ledger",
            )
        })?;
        let fp = calibration_input_fingerprint(observations)?;
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
        let rederived = build_calibration_card(observations, cfg)?;
        if rederived != entry.card {
            return Err(AssayError::new(
                ASTRO_ASSAY_REPRODUCE_MISMATCH,
                format!("re-derived calibration card at seq {seq} did not match the ledgered card"),
                "the calibration is not reproducible from its recorded inputs; investigate non-determinism",
            ));
        }
        Ok(rederived)
    }
}
