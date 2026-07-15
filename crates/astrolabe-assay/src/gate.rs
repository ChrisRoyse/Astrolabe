//! Per-repo lens capability gate — Admit / Park / Retire, ledgered and reversible
//! (P5.5, blueprint `05_LENS_PANEL.md` §6 capabilities 1.8 / 4.8).
//!
//! A repo's steady state is 12–18 active lenses out of the frozen 22, *measured*
//! not guessed and different per repo. This module turns each candidate lens's
//! measured profile into an Admit / Park / Retire verdict, records every verdict
//! as an entry in an append-only, hash-chained journal, and makes the verdict
//! **reversible** — appending a ledgered reversal restores the prior serving
//! state byte-for-byte. Nothing here mutates the frozen roster: parking a lens is
//! a per-repo serving overlay, never a roster edit, so the panel-version roster
//! contract ([`crate`]-external `slots_for_version`) is untouched.
//!
//! # Decision (the four branches)
//!
//! Given the candidate's [`LensCapabilityCard`], the maximum pairwise correlation
//! of its activation with an already-admitted lens, and whether it is the sole
//! carrier of a rare-but-critical stratum:
//!
//! * **Retire** when the max admitted correlation *exceeds* the registry
//!   threshold (0.6): the lens is redundant with an admitted one.
//! * **Park** when it clears the correlation gate but carries under the
//!   registry min-signal floor (0.05 bits) about *every* anchor axis — and it is
//!   not the sole carrier of any critical stratum.
//! * **Admit (stratified override)** when a globally-weak lens *is* the sole
//!   carrier of a rare-but-critical stratum: it is kept despite failing the
//!   global signal floor.
//! * **Admit** otherwise: the lens clears the correlation gate and carries real
//!   signal.
//!
//! Both comparisons are strict, so the boundary values are pinned: a lens at
//! exactly 0.60 correlation is *not* retired, and a lens at exactly 0.05 bits is
//! *not* parked.
//!
//! Every threshold is a registry-declared knob ([`crate::knobs`]); the correlation
//! ceiling is the gate registry's `assay_gate_retire_correlation_permille`, and
//! the signal floor reuses the bits registry's `assay_min_slot_signal_millibits`
//! (blueprint capability 10.3, the same 0.05-bit lens-admission gate).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::bits::BitsConfig;
use crate::error::{
    ASTRO_ASSAY_GATE_INPUT_INVALID, ASTRO_ASSAY_GATE_REVERT_INVALID, ASTRO_ASSAY_READBACK_MISMATCH,
    ASTRO_ASSAY_STORE_CORRUPT, ASTRO_ASSAY_STORE_IO, AssayError, Result,
};
use crate::knobs::{
    ASSAY_DEFAULT_GATE_RETIRE_CORRELATION_PERMILLE, ASSAY_GATE_RETIRE_CORRELATION_PERMILLE_KNOB,
    assay_gate_knob,
};

/// Domain-separation tag framed into the capability-card content hash.
pub const ASSAY_GATE_CARD_TAG: &str = "astro-assay-gate-card-v1";
/// Domain-separation tag framed into every gate journal entry hash.
pub const ASSAY_GATE_LEDGER_TAG: &str = "astro-assay-gate-ledger-v1";
/// The hex hash that seeds an empty gate journal chain (genesis previous-hash).
pub const GATE_GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Reason recorded on a Retire verdict: redundant with an admitted lens.
pub const GATE_REASON_RETIRE_REDUNDANT: &str = "retire_redundant_correlation";
/// Reason recorded on a Park verdict: no grounded signal about any anchor axis.
pub const GATE_REASON_PARK_NO_SIGNAL: &str = "park_no_grounded_signal";
/// Reason recorded on an Admit verdict produced by the stratified override.
pub const GATE_REASON_ADMIT_OVERRIDE: &str = "admit_stratified_override";
/// Reason recorded on an ordinary Admit verdict: carries real signal.
pub const GATE_REASON_ADMIT_SIGNAL: &str = "admit_signal";

/// Resolved thresholds for the capability gate, drawn from the registry knobs.
///
/// Built from the declared defaults with [`GateConfig::from_defaults`], which
/// asserts each default lies inside its knob's declared bounds so a mis-declared
/// default fails closed at construction rather than silently mis-gating.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GateConfig {
    /// Retire when max admitted correlation strictly exceeds this (0.0..=1.0).
    pub retire_correlation: f64,
    /// Park (absent an override) when signal is strictly below this, in bits.
    pub min_signal_bits: f64,
}

impl GateConfig {
    /// Builds the config from the registry knob defaults.
    ///
    /// The retire-correlation ceiling reads the gate registry; the min-signal
    /// floor reuses the bits registry's per-slot signal knob (the same 0.05-bit
    /// lens-admission gate, blueprint capability 10.3), routed through
    /// [`BitsConfig`] so the two stay a single source of truth.
    pub fn from_defaults() -> Result<Self> {
        let knob =
            assay_gate_knob(ASSAY_GATE_RETIRE_CORRELATION_PERMILLE_KNOB).ok_or_else(|| {
                AssayError::new(
                    ASTRO_ASSAY_GATE_INPUT_INVALID,
                    format!(
                        "gate knob {ASSAY_GATE_RETIRE_CORRELATION_PERMILLE_KNOB} is not declared"
                    ),
                    "declare the knob in ASSAY_GATE_KNOBS before using it",
                )
            })?;
        if !knob.accepts(ASSAY_DEFAULT_GATE_RETIRE_CORRELATION_PERMILLE) {
            return Err(AssayError::new(
                ASTRO_ASSAY_GATE_INPUT_INVALID,
                format!(
                    "gate correlation default {ASSAY_DEFAULT_GATE_RETIRE_CORRELATION_PERMILLE} is outside its declared bounds"
                ),
                "correct the knob default so it lies within [min, max]",
            ));
        }
        let bits = BitsConfig::from_defaults()?;
        Ok(Self {
            retire_correlation: ASSAY_DEFAULT_GATE_RETIRE_CORRELATION_PERMILLE as f64 / 1000.0,
            min_signal_bits: bits.min_slot_signal_bits,
        })
    }
}

/// A candidate lens's measured capability profile (blueprint 05 §6: signal /
/// spread / separation / cost / coverage).
///
/// Every field is a measurement over the aligned assay sample, never a guess. The
/// card is the input the gate hashes into its ledger entry, so a reader can pair
/// each recorded verdict with the exact profile that produced it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LensCapabilityCard {
    /// Stable lens name (the gate/serving key).
    pub lens: String,
    /// Measured bits about each anchor axis (finite, non-negative).
    pub axis_bits: BTreeMap<String, f64>,
    /// Best grounded signal: the maximum over `axis_bits` (0.0 when empty).
    pub signal_bits: f64,
    /// Fraction of sampled subjects where the lens fires (present), in `0.0..=1.0`.
    pub coverage: f64,
    /// Dynamic range: population standard deviation of the lens activation.
    pub spread: f64,
    /// Discriminability across strata: the between-stratum share of activation
    /// variance (eta-squared), in `0.0..=1.0`. Zero when the lens is constant.
    pub separation: f64,
    /// Measured encode/serve cost of the lens, in cost-units (finite, non-negative).
    pub cost_units: f64,
    /// Number of sampled subjects the card was measured over.
    pub n: usize,
}

impl LensCapabilityCard {
    /// Returns the content hash of the card's measured fields.
    ///
    /// Canonical JSON of the card is hashed under a domain-separation tag, so two
    /// callers that assemble the same profile produce the same hash. This is the
    /// value the gate ledger records to pair a verdict with its input card.
    pub fn card_hash(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("could not serialize capability card: {error}"),
                "this is an internal serialization fault; report it with the failing card",
            )
        })?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(ASSAY_GATE_CARD_TAG.as_bytes());
        hasher.update(&bytes);
        Ok(hasher.finalize().to_hex().to_string())
    }
}

fn check_finite(values: &[f64], what: &str) -> Result<()> {
    if values.iter().any(|v| !v.is_finite()) {
        return Err(AssayError::new(
            ASTRO_ASSAY_GATE_INPUT_INVALID,
            format!("{what} carries a non-finite value"),
            "supply only finite measured values to the capability gate",
        ));
    }
    Ok(())
}

/// Builds a measured capability card for one candidate lens.
///
/// `activation` is the per-subject scalar reduction of the lens output (e.g. the
/// L2 norm of its slot vector, or a scalar lens value), `present` marks the
/// subjects where the lens fired, `strata` labels each subject's stratum, and
/// `axis_bits` is the measured mutual information about each anchor axis (from the
/// bits pipeline, #32). All three per-subject vectors must have the same non-zero
/// length; a length disagreement or a non-finite value fails closed.
pub fn build_capability_card(
    lens: impl Into<String>,
    activation: &[f64],
    present: &[bool],
    strata: &[String],
    axis_bits: BTreeMap<String, f64>,
    cost_units: f64,
) -> Result<LensCapabilityCard> {
    let lens = lens.into();
    let n = activation.len();
    if n == 0 {
        return Err(AssayError::new(
            ASTRO_ASSAY_GATE_INPUT_INVALID,
            format!("lens {lens} carries no sampled activations"),
            "measure a non-empty assay sample before building a capability card",
        ));
    }
    if present.len() != n || strata.len() != n {
        return Err(AssayError::new(
            ASTRO_ASSAY_GATE_INPUT_INVALID,
            format!(
                "lens {lens} activation/present/strata lengths disagree ({n}, {}, {})",
                present.len(),
                strata.len()
            ),
            "align activation, presence, and stratum vectors to one sample set",
        ));
    }
    check_finite(activation, "activation")?;
    if !cost_units.is_finite() || cost_units < 0.0 {
        return Err(AssayError::new(
            ASTRO_ASSAY_GATE_INPUT_INVALID,
            format!("lens {lens} cost {cost_units} is not finite non-negative"),
            "supply a finite non-negative measured encode cost",
        ));
    }
    for (axis, bits) in &axis_bits {
        if !bits.is_finite() || *bits < 0.0 {
            return Err(AssayError::new(
                ASTRO_ASSAY_GATE_INPUT_INVALID,
                format!("lens {lens} bits about axis {axis} ({bits}) is not finite non-negative"),
                "supply finite non-negative measured bits per anchor axis",
            ));
        }
    }

    let signal_bits = axis_bits
        .values()
        .copied()
        .fold(0.0_f64, |acc, b| if b > acc { b } else { acc });
    let present_count = present.iter().filter(|&&p| p).count();
    let coverage = present_count as f64 / n as f64;
    let spread = population_std(activation);
    let separation = eta_squared(activation, strata);

    Ok(LensCapabilityCard {
        lens,
        axis_bits,
        signal_bits,
        coverage,
        spread,
        separation,
        cost_units,
        n,
    })
}

fn population_std(values: &[f64]) -> f64 {
    let n = values.len();
    if n == 0 {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / n as f64;
    let var = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n as f64;
    var.max(0.0).sqrt()
}

/// Between-stratum share of activation variance (eta-squared), in `0.0..=1.0`.
fn eta_squared(activation: &[f64], strata: &[String]) -> f64 {
    let n = activation.len();
    if n == 0 {
        return 0.0;
    }
    let grand_mean = activation.iter().sum::<f64>() / n as f64;
    let ss_total: f64 = activation.iter().map(|v| (v - grand_mean).powi(2)).sum();
    if ss_total <= 0.0 {
        return 0.0;
    }
    let mut group_sum: BTreeMap<&str, (f64, usize)> = BTreeMap::new();
    for (v, s) in activation.iter().zip(strata.iter()) {
        let entry = group_sum.entry(s.as_str()).or_insert((0.0, 0));
        entry.0 += *v;
        entry.1 += 1;
    }
    let ss_between: f64 = group_sum
        .values()
        .map(|&(sum, count)| {
            let group_mean = sum / count as f64;
            count as f64 * (group_mean - grand_mean).powi(2)
        })
        .sum();
    (ss_between / ss_total).clamp(0.0, 1.0)
}

/// Absolute Pearson correlation between two aligned per-subject activation
/// vectors, in `0.0..=1.0`.
///
/// Returns `0.0` when either vector has zero variance: a constant lens has no
/// linear relationship to measure, so it is treated as uncorrelated (it is
/// caught by the signal floor, not the redundancy gate). Fails closed on a length
/// disagreement or a non-finite value.
pub fn pearson_correlation(a: &[f64], b: &[f64]) -> Result<f64> {
    if a.len() != b.len() {
        return Err(AssayError::new(
            ASTRO_ASSAY_GATE_INPUT_INVALID,
            format!(
                "correlation inputs have lengths {} and {}",
                a.len(),
                b.len()
            ),
            "align the two activation vectors to the same sample set",
        ));
    }
    if a.is_empty() {
        return Err(AssayError::new(
            ASTRO_ASSAY_GATE_INPUT_INVALID,
            "correlation inputs are empty",
            "supply a non-empty aligned activation pair",
        ));
    }
    check_finite(a, "correlation input a")?;
    check_finite(b, "correlation input b")?;
    let n = a.len() as f64;
    let mean_a = a.iter().sum::<f64>() / n;
    let mean_b = b.iter().sum::<f64>() / n;
    let mut cov = 0.0;
    let mut var_a = 0.0;
    let mut var_b = 0.0;
    for (x, y) in a.iter().zip(b.iter()) {
        let da = x - mean_a;
        let db = y - mean_b;
        cov += da * db;
        var_a += da * da;
        var_b += db * db;
    }
    if var_a <= 0.0 || var_b <= 0.0 {
        return Ok(0.0);
    }
    Ok((cov / (var_a.sqrt() * var_b.sqrt())).abs().clamp(0.0, 1.0))
}

/// The maximum absolute correlation of a candidate lens's activation with any of
/// the already-admitted lenses' activations.
///
/// Returns `0.0` when there are no admitted lenses (nothing to be redundant
/// with). Each pairwise correlation is measured with [`pearson_correlation`].
pub fn max_admitted_correlation(
    candidate_activation: &[f64],
    admitted_activations: &[Vec<f64>],
) -> Result<f64> {
    let mut max = 0.0_f64;
    for admitted in admitted_activations {
        let corr = pearson_correlation(candidate_activation, admitted)?;
        if corr > max {
            max = corr;
        }
    }
    Ok(max)
}

/// The verdict the gate reaches for one lens in one repo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// Keep the lens on the serving path for this repo.
    Admit,
    /// Suspend the lens from serving (non-destructively) — recoverable.
    Park,
    /// Retire the lens for this repo — redundant with an admitted lens.
    Retire,
}

impl GateVerdict {
    /// The stable snake_case label for this verdict.
    pub const fn as_str(self) -> &'static str {
        match self {
            GateVerdict::Admit => "admit",
            GateVerdict::Park => "park",
            GateVerdict::Retire => "retire",
        }
    }
}

/// A gate verdict for one lens, with the reason and the input card hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecision {
    /// The lens the verdict is about.
    pub lens: String,
    /// Admit / Park / Retire.
    pub verdict: GateVerdict,
    /// Stable reason code (one of the `GATE_REASON_*` constants).
    pub reason_code: String,
    /// Content hash of the [`LensCapabilityCard`] that produced this verdict.
    pub card_hash: String,
}

/// The measured inputs a single-lens gate evaluation consumes.
#[derive(Debug, Clone)]
pub struct GateEvaluation<'a> {
    /// The candidate's measured capability card.
    pub card: &'a LensCapabilityCard,
    /// Max absolute correlation of the candidate with any admitted lens (0..=1).
    pub max_admitted_correlation: f64,
    /// Whether the candidate is the sole carrier of a rare-but-critical stratum.
    pub sole_critical_carrier: bool,
}

/// Gates one candidate lens into an Admit / Park / Retire verdict.
///
/// See the module docs for the four branches and the pinned boundary semantics
/// (correlation `> 0.6`, signal `< 0.05` bits, both strict).
pub fn gate_lens(eval: &GateEvaluation<'_>, cfg: &GateConfig) -> Result<GateDecision> {
    let corr = eval.max_admitted_correlation;
    if !corr.is_finite() || !(0.0..=1.0).contains(&corr) {
        return Err(AssayError::new(
            ASTRO_ASSAY_GATE_INPUT_INVALID,
            format!("max admitted correlation {corr} is not a finite value in 0.0..=1.0"),
            "supply an absolute correlation measured with pearson_correlation",
        ));
    }
    let card_hash = eval.card.card_hash()?;
    let (verdict, reason_code) = if corr > cfg.retire_correlation {
        (GateVerdict::Retire, GATE_REASON_RETIRE_REDUNDANT)
    } else if eval.card.signal_bits < cfg.min_signal_bits {
        if eval.sole_critical_carrier {
            (GateVerdict::Admit, GATE_REASON_ADMIT_OVERRIDE)
        } else {
            (GateVerdict::Park, GATE_REASON_PARK_NO_SIGNAL)
        }
    } else {
        (GateVerdict::Admit, GATE_REASON_ADMIT_SIGNAL)
    };
    Ok(GateDecision {
        lens: eval.card.lens.clone(),
        verdict,
        reason_code: reason_code.to_string(),
        card_hash,
    })
}

/// Returns true when `lens` is the sole carrier of at least one critical stratum.
///
/// `critical_carriers` maps each rare-but-critical stratum to the lenses that
/// carry usable signal there. The lens qualifies for the stratified override when
/// some stratum's carrier list contains exactly that lens and no other — planting
/// a second carrier in every stratum removes the override.
pub fn is_sole_critical_carrier(
    lens: &str,
    critical_carriers: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    critical_carriers
        .values()
        .any(|carriers| carriers.len() == 1 && carriers.contains(lens))
}

/// One entry in the append-only, hash-chained gate journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateJournalEntry {
    /// Zero-based sequence number in the chain.
    pub seq: u64,
    /// Hex hash of the previous entry (genesis constant for the first entry).
    pub prev_hash: String,
    /// Hex hash of this entry's canonical payload.
    pub entry_hash: String,
    /// Repo the entry is scoped to (the gate is per-repo).
    pub repo: String,
    /// Lens the entry is about.
    pub lens: String,
    /// The recorded action (a decision or a reversal).
    pub action: GateAction,
}

/// A gate journal action: either a fresh decision or a reversal of a prior one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GateAction {
    /// A gate verdict for the entry's `(repo, lens)`.
    Decide {
        /// Admit / Park / Retire.
        verdict: GateVerdict,
        /// Stable reason code.
        reason_code: String,
        /// Content hash of the input capability card.
        card_hash: String,
    },
    /// A reversal that neutralizes the decision at `reverts_seq`.
    Revert {
        /// Sequence number of the decision this reversal neutralizes.
        reverts_seq: u64,
    },
}

fn gate_entry_hash(
    seq: u64,
    prev_hash: &str,
    repo: &str,
    lens: &str,
    action_json: &[u8],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ASSAY_GATE_LEDGER_TAG.as_bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(repo.as_bytes());
    hasher.update(b"\x00");
    hasher.update(lens.as_bytes());
    hasher.update(b"\x00");
    hasher.update(action_json);
    hasher.finalize().to_hex().to_string()
}

/// The per-repo serving admission state folded from the journal.
///
/// Each lens appears in exactly one bucket, determined by its latest *active*
/// (not reverted) decision; a lens with no active decision does not appear. The
/// bucket vectors are sorted, so the serialized state is a deterministic,
/// byte-comparable snapshot — the evidence the reversibility check reads back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServingAdmission {
    /// Repo this admission state is scoped to.
    pub repo: String,
    /// Lenses whose latest active verdict is Admit (the serving set), sorted.
    pub admitted: Vec<String>,
    /// Lenses whose latest active verdict is Park, sorted.
    pub parked: Vec<String>,
    /// Lenses whose latest active verdict is Retire, sorted.
    pub retired: Vec<String>,
}

impl ServingAdmission {
    /// Canonical JSON bytes of the state — the byte-comparable serving snapshot.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("could not serialize serving admission: {error}"),
                "this is an internal serialization fault; report it",
            )
        })
    }
}

/// A filesystem-backed, append-only, hash-chained per-repo gate journal.
#[derive(Debug, Clone)]
pub struct GateJournal {
    path: PathBuf,
}

impl GateJournal {
    /// Opens (creating the parent directory if needed) a journal at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!(
                        "could not create gate journal dir {}: {error}",
                        parent.display()
                    ),
                    "ensure the journal root is writable before appending decisions",
                )
            })?;
        }
        Ok(Self { path })
    }

    /// Reads and chain-verifies every journal entry, in sequence order.
    ///
    /// A sequence gap, a `prev_hash` that does not match the prior entry's
    /// `entry_hash`, or a recomputed hash mismatch fails closed rather than being
    /// served.
    pub fn read_all(&self) -> Result<Vec<GateJournalEntry>> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!(
                        "could not read gate journal {}: {error}",
                        self.path.display()
                    ),
                    "check the journal filesystem before retrying",
                ));
            }
        };
        let text = String::from_utf8(bytes).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("gate journal {} is not utf-8: {error}", self.path.display()),
                "quarantine the corrupt journal and rebuild it",
            )
        })?;
        let mut entries: Vec<GateJournalEntry> = Vec::new();
        let mut prev = GATE_GENESIS_PREV_HASH.to_string();
        for (line_no, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let entry: GateJournalEntry = serde_json::from_str(line).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!(
                        "{}:{} did not parse: {error}",
                        self.path.display(),
                        line_no + 1
                    ),
                    "quarantine the corrupt journal and rebuild it",
                )
            })?;
            if entry.seq != entries.len() as u64 {
                return Err(AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!(
                        "gate journal sequence gap at line {}: expected {} got {}",
                        line_no + 1,
                        entries.len(),
                        entry.seq
                    ),
                    "quarantine the corrupt journal and rebuild it",
                ));
            }
            if entry.prev_hash != prev {
                return Err(AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!(
                        "gate journal chain break at seq {}: prev_hash mismatch",
                        entry.seq
                    ),
                    "quarantine the corrupt journal and rebuild it",
                ));
            }
            let action_json = serde_json::to_vec(&entry.action).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!(
                        "could not re-serialize action at seq {}: {error}",
                        entry.seq
                    ),
                    "quarantine the corrupt journal and rebuild it",
                )
            })?;
            let recomputed = gate_entry_hash(
                entry.seq,
                &entry.prev_hash,
                &entry.repo,
                &entry.lens,
                &action_json,
            );
            if recomputed != entry.entry_hash {
                return Err(AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!("gate journal entry hash mismatch at seq {}", entry.seq),
                    "quarantine the corrupt journal and rebuild it",
                ));
            }
            prev = entry.entry_hash.clone();
            entries.push(entry);
        }
        Ok(entries)
    }

    fn append_entry(&self, repo: &str, lens: &str, action: GateAction) -> Result<GateJournalEntry> {
        let existing = self.read_all()?;
        let seq = existing.len() as u64;
        let prev_hash = existing
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| GATE_GENESIS_PREV_HASH.to_string());
        let action_json = serde_json::to_vec(&action).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("could not serialize gate action: {error}"),
                "this is an internal serialization fault; report it",
            )
        })?;
        let entry_hash = gate_entry_hash(seq, &prev_hash, repo, lens, &action_json);
        let entry = GateJournalEntry {
            seq,
            prev_hash,
            entry_hash,
            repo: repo.to_string(),
            lens: lens.to_string(),
            action,
        };
        let mut line = serde_json::to_vec(&entry).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("could not serialize gate journal entry: {error}"),
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
                        "could not read gate journal {} before append: {error}",
                        self.path.display()
                    ),
                    "check the journal filesystem before retrying",
                ));
            }
        };
        all.extend_from_slice(&line);
        fs::write(&self.path, &all).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_IO,
                format!(
                    "could not write gate journal {}: {error}",
                    self.path.display()
                ),
                "ensure the journal root is writable before appending decisions",
            )
        })?;
        // FSV: re-read and re-chain-verify; the appended entry must read back as written.
        let readback = self.read_all()?;
        match readback.last() {
            Some(last) if *last == entry => Ok(entry),
            _ => Err(AssayError::new(
                ASTRO_ASSAY_READBACK_MISMATCH,
                "appended gate journal entry did not read back as written",
                "the persisted journal diverges from the committed entry; quarantine the journal root",
            )),
        }
    }

    /// Appends a gate decision for `(repo, lens)` and proves the write by readback.
    pub fn append_decision(&self, repo: &str, decision: &GateDecision) -> Result<GateJournalEntry> {
        let action = GateAction::Decide {
            verdict: decision.verdict,
            reason_code: decision.reason_code.clone(),
            card_hash: decision.card_hash.clone(),
        };
        self.append_entry(repo, &decision.lens, action)
    }

    /// Appends a reversal that neutralizes the decision at `reverts_seq`.
    ///
    /// The target must exist, be a `Decide` (not itself a reversal), and not
    /// already be reverted — otherwise the reversal is rejected fail-closed. The
    /// reversal copies the target's `(repo, lens)` so the fold restores the prior
    /// serving state for exactly that lens.
    pub fn revert(&self, reverts_seq: u64) -> Result<GateJournalEntry> {
        let entries = self.read_all()?;
        let target = entries.get(reverts_seq as usize).ok_or_else(|| {
            AssayError::new(
                ASTRO_ASSAY_GATE_REVERT_INVALID,
                format!("no gate journal entry at seq {reverts_seq}"),
                "revert a decision sequence that exists in the journal",
            )
        })?;
        if !matches!(target.action, GateAction::Decide { .. }) {
            return Err(AssayError::new(
                ASTRO_ASSAY_GATE_REVERT_INVALID,
                format!("seq {reverts_seq} is not a decision and cannot be reverted"),
                "revert a Decide entry, not a Revert entry",
            ));
        }
        if entries
            .iter()
            .any(|e| matches!(e.action, GateAction::Revert { reverts_seq: r } if r == reverts_seq))
        {
            return Err(AssayError::new(
                ASTRO_ASSAY_GATE_REVERT_INVALID,
                format!("seq {reverts_seq} is already reverted"),
                "a decision may be reverted at most once; issue a fresh decision instead",
            ));
        }
        let repo = target.repo.clone();
        let lens = target.lens.clone();
        self.append_entry(&repo, &lens, GateAction::Revert { reverts_seq })
    }

    /// Folds the journal into the per-repo serving admission state.
    ///
    /// A decision is *active* unless a later `Revert` names its sequence. For each
    /// lens the latest active decision determines its bucket; a lens with no
    /// active decision does not appear. This fold is what makes a reversal restore
    /// the prior state exactly: neutralizing the latest decision re-exposes the
    /// one before it (or none), byte-for-byte.
    pub fn serving_admission(&self, repo: &str) -> Result<ServingAdmission> {
        let entries = self.read_all()?;
        let reverted: BTreeSet<u64> = entries
            .iter()
            .filter_map(|e| match e.action {
                GateAction::Revert { reverts_seq } => Some(reverts_seq),
                GateAction::Decide { .. } => None,
            })
            .collect();
        // Latest active verdict per lens (entries are in ascending seq order).
        let mut latest: BTreeMap<String, GateVerdict> = BTreeMap::new();
        for entry in &entries {
            if entry.repo != repo {
                continue;
            }
            if let GateAction::Decide { verdict, .. } = &entry.action
                && !reverted.contains(&entry.seq)
            {
                latest.insert(entry.lens.clone(), *verdict);
            }
        }
        let mut admitted = Vec::new();
        let mut parked = Vec::new();
        let mut retired = Vec::new();
        for (lens, verdict) in latest {
            match verdict {
                GateVerdict::Admit => admitted.push(lens),
                GateVerdict::Park => parked.push(lens),
                GateVerdict::Retire => retired.push(lens),
            }
        }
        admitted.sort();
        parked.sort();
        retired.sort();
        Ok(ServingAdmission {
            repo: repo.to_string(),
            admitted,
            parked,
            retired,
        })
    }

    /// Canonical serving-state bytes for `repo` — the reversibility read-back.
    pub fn serving_state_bytes(&self, repo: &str) -> Result<Vec<u8>> {
        self.serving_admission(repo)?.to_bytes()
    }
}
