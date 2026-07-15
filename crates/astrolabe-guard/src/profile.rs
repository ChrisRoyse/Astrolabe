//! Guard profiles + split-conformal calibration (P7.2, blueprint `10_GUARD.md`
//! §1, R16; consumer contract `astrolabe.optimizer_guard_health.v1`).
//!
//! A [`GuardProfile`] is the per-domain (language × scope-class) calibration
//! artifact the guard consults on every `guard_check`: a fixed set of guard
//! slots, each with a conformally calibrated per-slot threshold `tau`, its
//! measured false-accept rate (FAR) on a held-out bad population, false-reject
//! rate (FRR) on the good population, and a drift bound. The doctrine
//! (blueprint §0) is enforced structurally here:
//!
//! - **per-slot, never averaged (A3):** [`combine_verdicts`] routes on the
//!   individual [`SlotVerdict`]s and their [`SlotKind`]; it never computes a
//!   mean cosine. A single identity-slot breach refuses even when every other
//!   slot passes with a wide margin.
//! - **fail closed:** calibration that cannot meet its finite-sample bound is a
//!   [`CalibrationError`], never a thinned profile.
//! - **provisional until calibrated:** an uncalibrated profile is cold-start
//!   `tau = 0.7` with `provisional = true`; [`validate_high_stakes_profile`]
//!   refuses any provisional slot in high-stakes mode (Ward
//!   `validate_high_stakes_profile`).
//! - **raw storage:** guard slots are serialized as raw IEEE-754 `f32` bits, no
//!   quantization ([`GuardProfile::raw_slot_bytes`] /
//!   [`slot_calibration_from_raw_bytes`]); the byte round-trip is bit-exact.
//!
//! Calibration is **split (inductive) conformal**: the bad population is split
//! deterministically into a calibration half (which sets `tau` via the
//! binomial-bounded [`conformal_tau`] estimator) and a held-out validation half
//! (which *measures* the achieved FAR). Under exchangeability the held-out FAR
//! concentrates on the target within the split-conformal finite-sample gap
//! `1/(n_val + 1)` plus binomial sampling noise; [`finite_sample_far_bound`]
//! makes that ceiling explicit and every calibration checks its own held-out
//! FAR against it, refusing (`ASTRO_GUARD_FAR_BOUND_EXCEEDED`) rather than
//! shipping an over-accepting slot.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::calibration::{
    BadCaseScorer, CalibrationCorpus, CalibrationDomain, CalibrationError, TAU_COLD_START,
    conformal_tau, false_accept_rate, false_reject_rate,
};

/// Registry version for the guard-profile knob set (invariant #4: no bare
/// constant that could be a measurement — the targets, alpha, quarantine band,
/// and drift multiplier are all declared here).
pub const GUARD_PROFILE_KNOB_REGISTRY_VERSION: &str = "astro.guard.profile_knobs.v1";

/// Canonical guard-profile serialization schema, hashed into `profile_hash`
/// (the value pinned into the ledger `CalibrationMeta` payload).
pub const GUARD_PROFILE_SCHEMA: &str = "astro.guard.profile.v1";

/// Consumer contract the `guard_calibrate` server tool persists and
/// `optimizer_status`/`get_readiness` read (already live/validated, see
/// `astrolabe-server` `optimizer_guard_health_config_json`).
pub const OPTIMIZER_GUARD_HEALTH_SCHEMA: &str = "astrolabe.optimizer_guard_health.v1";

// --- Registry-declared knobs (invariant #4) --------------------------------

/// Identity-locked slot target false-accept rate (breaking-change protection on
/// exported APIs). Blueprint §1 table.
pub const IDENTITY_TARGET_FAR: f32 = 0.01;
/// Content slot target false-accept rate (semantic / structural / API misuse).
pub const CONTENT_TARGET_FAR: f32 = 0.03;
/// Stylistic slot target false-accept rate (naming / complexity drift).
pub const STYLISTIC_TARGET_FAR: f32 = 0.05;

/// Binomial confidence level for the [`conformal_tau`] bound: the probability
/// the true FAR exceeds target given the calibration accepts is `<= alpha`.
pub const CONFORMAL_ALPHA: f32 = 0.05;

/// Near-miss band for identity slots: a failing identity slot whose cosine is
/// within this margin of `tau` is *quarantined* (held for review) rather than
/// hard-refused. Outside the band it is an outright identity breach.
pub const IDENTITY_QUARANTINE_MARGIN: f32 = 0.05;

/// Drift multiplier (Ward drift monitor): a rolling rejection rate above
/// `multiplier × calibrated FAR` signals the domain distribution shifted and
/// recalibration is due. Recorded per slot as its `drift` bound.
pub const DRIFT_ALARM_MULTIPLIER: f32 = 1.5;

/// Rolling window (number of most-recent per-slot `guard_check` outcomes) over
/// which a slot's rejection rate is measured for drift monitoring (blueprint
/// `10_GUARD.md` §4). A rejection rate over the slot's `drift_bound`
/// (`DRIFT_ALARM_MULTIPLIER × achieved_far`) across this window fires a
/// recalibration proposal exactly once per crossing (see [`crate::drift`]).
pub const DRIFT_REJECTION_WINDOW: usize = 500;

/// Advisory `PostToolUse` hook wall-clock budget in milliseconds (blueprint
/// `10_GUARD.md` §5, CBM `hook_augment` contract). The advisory quick check
/// must return an advisory or go silent within this budget; it never blocks the
/// agent flow (see [`crate::hook`]).
pub const ADVISORY_HOOK_BUDGET_MS: u64 = 300;

// ---------------------------------------------------------------------------
// Slot taxonomy
// ---------------------------------------------------------------------------

/// The strictness class of a guard slot, which fixes its default target FAR and
/// its role in verdict combination.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SlotKind {
    /// Identity-locked (exported/public API): `AllRequired`, FAR 0.01.
    Identity,
    /// Content (semantic/structural/API/error): `KofN` advisory, FAR 0.03.
    Content,
    /// Stylistic (naming/complexity): advisory, FAR 0.05; a miss routes to
    /// `new-region`, never refusal.
    Stylistic,
}

impl SlotKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Content => "content",
            Self::Stylistic => "stylistic",
        }
    }

    /// The registry-declared default target FAR for this kind.
    pub const fn default_target_far(self) -> f32 {
        match self {
            Self::Identity => IDENTITY_TARGET_FAR,
            Self::Content => CONTENT_TARGET_FAR,
            Self::Stylistic => STYLISTIC_TARGET_FAR,
        }
    }
}

/// The fixed guard slots (blueprint §1 table). The discriminant order is frozen:
/// it participates in the canonical profile serialization.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum GuardSlot {
    /// S18 semantic embedding — semantically alien code for this area.
    CodeSemantic,
    /// S1 structural trigrams — structurally alien constructs.
    StructTrigrams,
    /// S4 API callees — API misuse / calling things this area never calls.
    ApiCallees,
    /// S20 name semantics — naming-convention drift.
    NameSemantic,
    /// S2 complexity profile — complexity regime violations.
    ComplexityProfile,
    /// S15 error surface — novel/incorrect error-handling patterns.
    ErrorSurface,
    /// S5+S17 on exported symbols — breaking-change drift on locked APIs.
    PublicApiSignature,
}

impl GuardSlot {
    /// Every guard slot, in canonical order.
    pub const ALL: [GuardSlot; 7] = [
        Self::CodeSemantic,
        Self::StructTrigrams,
        Self::ApiCallees,
        Self::NameSemantic,
        Self::ComplexityProfile,
        Self::ErrorSurface,
        Self::PublicApiSignature,
    ];

    /// Stable wire label (the `slot` field of the consumer contract).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CodeSemantic => "code_semantic",
            Self::StructTrigrams => "struct_trigrams",
            Self::ApiCallees => "api_callees",
            Self::NameSemantic => "name_semantic",
            Self::ComplexityProfile => "complexity_profile",
            Self::ErrorSurface => "error_surface",
            Self::PublicApiSignature => "public_api_signature",
        }
    }

    /// The panel lens source this slot measures.
    pub const fn panel_source(self) -> &'static str {
        match self {
            Self::CodeSemantic => "S18",
            Self::StructTrigrams => "S1",
            Self::ApiCallees => "S4",
            Self::NameSemantic => "S20",
            Self::ComplexityProfile => "S2",
            Self::ErrorSurface => "S15",
            Self::PublicApiSignature => "S5+S17",
        }
    }

    pub const fn kind(self) -> SlotKind {
        match self {
            Self::CodeSemantic | Self::StructTrigrams | Self::ApiCallees | Self::ErrorSurface => {
                SlotKind::Content
            }
            Self::NameSemantic | Self::ComplexityProfile => SlotKind::Stylistic,
            Self::PublicApiSignature => SlotKind::Identity,
        }
    }

    /// Default target FAR (from the slot's kind).
    pub const fn default_target_far(self) -> f32 {
        self.kind().default_target_far()
    }

    const fn ordinal(self) -> u8 {
        match self {
            Self::CodeSemantic => 0,
            Self::StructTrigrams => 1,
            Self::ApiCallees => 2,
            Self::NameSemantic => 3,
            Self::ComplexityProfile => 4,
            Self::ErrorSurface => 5,
            Self::PublicApiSignature => 6,
        }
    }
}

impl fmt::Display for GuardSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Combination policy
// ---------------------------------------------------------------------------

/// How the per-slot pass/fail outcomes combine into an overall verdict. This is
/// intentionally *not* a numeric aggregation — it consumes the per-slot boolean
/// outcomes only (A3 no-flatten).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CombinationPolicy {
    /// Every slot of this class must pass (identity-locked checks).
    AllRequired,
    /// At least `k` of `n` slots of this class must pass (advisory checks,
    /// default `k = n - 1`).
    KofN { k: usize, n: usize },
}

// ---------------------------------------------------------------------------
// Per-slot calibration
// ---------------------------------------------------------------------------

/// A calibrated (or cold-start) threshold for one guard slot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlotCalibration {
    pub slot: GuardSlot,
    /// The per-slot accept threshold: a candidate cosine `>= tau` passes.
    pub tau: f32,
    /// The FAR target this slot was calibrated against.
    pub target_far: f32,
    /// Achieved FAR measured on the held-out bad validation split (cold-start:
    /// unmeasured, recorded as the cold-start `NaN`-free sentinel `1.0`).
    pub achieved_far: f32,
    /// Achieved FRR measured on the good population.
    pub achieved_frr: f32,
    /// Drift bound = `DRIFT_ALARM_MULTIPLIER × achieved_far`; a rolling rejection
    /// rate above this signals recalibration is due.
    pub drift_bound: f32,
    /// Bad-calibration split size.
    pub n_bad_calibration: usize,
    /// Bad-validation (held-out) split size.
    pub n_bad_validation: usize,
    /// Good population size.
    pub n_good: usize,
    /// `true` until this slot has a measured calibration (cold-start).
    pub provisional: bool,
}

impl SlotCalibration {
    /// Cold-start slot: `tau = 0.7`, provisional, no measured rates.
    pub fn cold_start(slot: GuardSlot) -> Self {
        Self {
            slot,
            tau: TAU_COLD_START,
            target_far: slot.default_target_far(),
            achieved_far: 1.0,
            achieved_frr: 1.0,
            drift_bound: 1.0,
            n_bad_calibration: 0,
            n_bad_validation: 0,
            n_good: 0,
            provisional: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Guard profile
// ---------------------------------------------------------------------------

/// A per-domain guard profile: the full slot set with calibrated thresholds and
/// its content-check `KofN` policy. Persisted (raw) and ledgered by
/// `guard_calibrate`.
#[derive(Debug, Clone, PartialEq)]
pub struct GuardProfile {
    pub domain: CalibrationDomain,
    pub slots: Vec<SlotCalibration>,
    /// `KofN` policy applied to the *content* slots (identity slots are always
    /// `AllRequired`, stylistic slots are advisory).
    pub content_policy: CombinationPolicy,
    /// `true` while any slot is provisional (cold-start / uncalibrated).
    pub provisional: bool,
    /// SHA-256 over the corpus this profile was calibrated on (from
    /// [`CalibrationCorpus::corpus_hash`]); all-zero for a cold-start profile.
    pub corpus_hash: [u8; 32],
    /// Ledger seq of the `guard_calibrate` run that produced this profile;
    /// `None` for an uncalibrated cold-start profile.
    pub calibrated_ledger_seq: Option<u64>,
}

impl GuardProfile {
    /// A cold-start profile for `domain`: every slot at `tau = 0.7`, provisional.
    /// Verdicts against it are labeled provisional; high-stakes mode refuses.
    pub fn cold_start(domain: CalibrationDomain) -> Self {
        let slots: Vec<SlotCalibration> = GuardSlot::ALL
            .iter()
            .map(|slot| SlotCalibration::cold_start(*slot))
            .collect();
        Self {
            domain,
            slots,
            content_policy: default_content_policy(),
            provisional: true,
            corpus_hash: [0u8; 32],
            calibrated_ledger_seq: None,
        }
    }

    pub fn slot(&self, slot: GuardSlot) -> Option<&SlotCalibration> {
        self.slots
            .iter()
            .find(|calibration| calibration.slot == slot)
    }

    /// Lowercase hex of the corpus hash.
    pub fn corpus_hash_hex(&self) -> String {
        self.corpus_hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Lowercase hex of the canonical profile hash (`profile_hash`), the value
    /// pinned into the ledger `CalibrationMeta` payload.
    pub fn profile_hash_hex(&self) -> String {
        self.canonical_profile_hash()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// SHA-256 over the canonical profile bytes.
    pub fn canonical_profile_hash(&self) -> [u8; 32] {
        let bytes = self.canonical_profile_bytes();
        let digest = Sha256::digest(&bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Canonical, deterministic byte serialization of the profile (slots in
    /// canonical `GuardSlot` order). Every `f32` is emitted as raw big-endian
    /// IEEE-754 bits — **no quantization** — so the byte round-trip is bit-exact
    /// (proven by [`slot_calibration_from_raw_bytes`] readback tests).
    pub fn canonical_profile_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(GUARD_PROFILE_SCHEMA.as_bytes());
        out.push(0);
        out.push(self.domain.language.ordinal_public());
        out.extend_from_slice(self.domain.scope_class.as_bytes());
        out.push(0);
        out.push(match self.content_policy {
            CombinationPolicy::AllRequired => 0,
            CombinationPolicy::KofN { .. } => 1,
        });
        if let CombinationPolicy::KofN { k, n } = self.content_policy {
            out.extend_from_slice(&(k as u32).to_be_bytes());
            out.extend_from_slice(&(n as u32).to_be_bytes());
        } else {
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        out.push(self.provisional as u8);
        out.extend_from_slice(&self.corpus_hash);
        out.extend_from_slice(&self.calibrated_ledger_seq.unwrap_or(u64::MAX).to_be_bytes());
        // Slots, always in canonical order.
        let mut ordered: Vec<&SlotCalibration> = self.slots.iter().collect();
        ordered.sort_by_key(|calibration| calibration.slot.ordinal());
        out.extend_from_slice(&(ordered.len() as u32).to_be_bytes());
        for calibration in ordered {
            out.extend_from_slice(&self.raw_slot_bytes(calibration));
        }
        out
    }

    /// Raw (unquantized) byte encoding of one slot's calibration: slot ordinal,
    /// provisional flag, then five raw `f32` fields as big-endian IEEE-754 bits,
    /// then three `u32` counts. Exactly the bytes a CF byte-read reproduces.
    pub fn raw_slot_bytes(&self, calibration: &SlotCalibration) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 1 + 5 * 4 + 3 * 4);
        out.push(calibration.slot.ordinal());
        out.push(calibration.provisional as u8);
        for value in [
            calibration.tau,
            calibration.target_far,
            calibration.achieved_far,
            calibration.achieved_frr,
            calibration.drift_bound,
        ] {
            out.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        for count in [
            calibration.n_bad_calibration,
            calibration.n_bad_validation,
            calibration.n_good,
        ] {
            out.extend_from_slice(&(count as u32).to_be_bytes());
        }
        out
    }
}

/// Default content-slot combination policy: `KofN` with `k = n - 1` over the
/// four content slots (allow at most one content dimension to miss before the
/// candidate is out-of-distribution).
pub fn default_content_policy() -> CombinationPolicy {
    let n = GuardSlot::ALL
        .iter()
        .filter(|slot| slot.kind() == SlotKind::Content)
        .count();
    CombinationPolicy::KofN {
        k: n.saturating_sub(1),
        n,
    }
}

/// Reconstruct a [`SlotCalibration`] from its raw byte encoding (the CF
/// byte-read verifier). Fails closed on a truncated or malformed record.
pub fn slot_calibration_from_raw_bytes(bytes: &[u8]) -> Result<SlotCalibration, CalibrationError> {
    const LEN: usize = 1 + 1 + 5 * 4 + 3 * 4;
    if bytes.len() != LEN {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_RAW_SLOT_MALFORMED",
            format!(
                "raw slot record is {} bytes; expected exactly {LEN}",
                bytes.len()
            ),
            "Re-read the full fixed-width raw slot record before decoding.",
        ));
    }
    let slot = guard_slot_from_ordinal(bytes[0])?;
    let provisional = bytes[1] != 0;
    let mut cursor = 2usize;
    let mut read_f32 = || {
        let word = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        cursor += 4;
        f32::from_bits(word)
    };
    let tau = read_f32();
    let target_far = read_f32();
    let achieved_far = read_f32();
    let achieved_frr = read_f32();
    let drift_bound = read_f32();
    let mut read_u32 = || {
        let word = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        cursor += 4;
        word as usize
    };
    let n_bad_calibration = read_u32();
    let n_bad_validation = read_u32();
    let n_good = read_u32();
    Ok(SlotCalibration {
        slot,
        tau,
        target_far,
        achieved_far,
        achieved_frr,
        drift_bound,
        n_bad_calibration,
        n_bad_validation,
        n_good,
        provisional,
    })
}

fn guard_slot_from_ordinal(ordinal: u8) -> Result<GuardSlot, CalibrationError> {
    GuardSlot::ALL
        .iter()
        .copied()
        .find(|slot| slot.ordinal() == ordinal)
        .ok_or_else(|| {
            CalibrationError::new(
                "ASTRO_GUARD_RAW_SLOT_MALFORMED",
                format!("raw slot ordinal {ordinal} is out of range"),
                "Re-read the raw slot record; the ordinal byte is corrupt.",
            )
        })
}

// ---------------------------------------------------------------------------
// Split-conformal calibration
// ---------------------------------------------------------------------------

/// The finite-sample ceiling the held-out FAR must respect: the split-conformal
/// coverage gap `1/(n_val + 1)` plus the one-sided binomial Wald slack at level
/// `alpha` for `n_val` held-out draws. A held-out FAR above this ceiling means
/// the calibration did not generalize and the slot is refused.
pub fn finite_sample_far_bound(target_far: f32, n_val: usize, alpha: f32) -> f32 {
    if n_val == 0 {
        return 1.0;
    }
    let split_gap = 1.0 / (n_val as f32 + 1.0);
    // One-sided normal quantile approximations for the common alpha values; a
    // conservative default otherwise. (No hidden magic: these are the standard
    // z-scores, selected by the declared alpha knob.)
    let z = if alpha <= 0.01 {
        2.326
    } else if alpha <= 0.05 {
        1.645
    } else if alpha <= 0.10 {
        1.282
    } else {
        1.036
    };
    let p = target_far.clamp(0.0, 1.0);
    let wald = z * ((p * (1.0 - p)) / n_val as f32).sqrt();
    (p + split_gap + wald).min(1.0)
}

/// A per-slot scorer over the corpus: given a candidate, the guard scores its
/// per-slot cosine to the trusted region. In calibration we score every
/// good/bad case through the same instrument. The real scorer measures code
/// through the panel/lens; the trait keeps calibration scorer-agnostic (driven
/// by that real scorer or by a deterministic fixture for the committed proof).
pub trait SlotScorer {
    fn score_bad(&self, slot: GuardSlot, case: &crate::calibration::BadCase) -> f32;
    fn score_good(&self, slot: GuardSlot, case: &crate::calibration::GoodCase) -> f32;
}

/// Adapt a whole-candidate [`BadCaseScorer`] into a per-slot [`SlotScorer`] that
/// ignores the slot (all slots share one distance). Used where a single cosine
/// stands in for every slot (e.g. the ablation fixture scorer).
pub struct UniformSlotScorer<S>(pub S);

impl<S: BadCaseScorer> SlotScorer for UniformSlotScorer<S> {
    fn score_bad(&self, _slot: GuardSlot, case: &crate::calibration::BadCase) -> f32 {
        self.0.score_bad(case)
    }
    fn score_good(&self, _slot: GuardSlot, case: &crate::calibration::GoodCase) -> f32 {
        self.0.score_good(case)
    }
}

/// Split a bad-score population deterministically into (calibration, validation)
/// halves by stable index parity — no RNG, so the split is reproducible from the
/// corpus order alone.
fn split_bad_scores(scores: &[f32]) -> (Vec<f32>, Vec<f32>) {
    let mut calibration = Vec::new();
    let mut validation = Vec::new();
    for (index, score) in scores.iter().enumerate() {
        if index % 2 == 0 {
            calibration.push(*score);
        } else {
            validation.push(*score);
        }
    }
    (calibration, validation)
}

/// Calibrate one slot by split conformal prediction. `tau` is set on the
/// calibration split via the binomial-bounded [`conformal_tau`]; the achieved
/// FAR is *measured* on the held-out validation split and checked against
/// [`finite_sample_far_bound`]. Fails closed if the held-out FAR exceeds that
/// ceiling or the population is too thin to split.
pub fn calibrate_slot(
    slot: GuardSlot,
    good_scores: &[f32],
    bad_scores: &[f32],
    target_far: f32,
    alpha: f32,
) -> Result<SlotCalibration, CalibrationError> {
    if !(0.0..=1.0).contains(&target_far) || !(0.0..=1.0).contains(&alpha) {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_CALIBRATE_PARAMS",
            "target_far and alpha must be in [0,1]",
            "Pass a target FAR and alpha within [0,1].",
        ));
    }
    if bad_scores.len() < 2 {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_SLOT_UNSPLITTABLE",
            format!(
                "slot {} has {} bad scores; split conformal needs >= 2 to hold out a validation \
                 set. Calibration refused.",
                slot.as_str(),
                bad_scores.len()
            ),
            "Widen the bad population for this slot before calibrating; never calibrate on a \
             single held-in point.",
        ));
    }
    let (calibration_bad, validation_bad) = split_bad_scores(bad_scores);
    let tau = conformal_tau(&calibration_bad, target_far, alpha);
    let achieved_far = false_accept_rate(&validation_bad, tau);
    let bound = finite_sample_far_bound(target_far, validation_bad.len(), alpha);
    if achieved_far > bound + f32::EPSILON {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_FAR_BOUND_EXCEEDED",
            format!(
                "slot {} held-out FAR {achieved_far:.4} exceeds the finite-sample ceiling \
                 {bound:.4} (target {target_far}); the calibration did not generalize.",
                slot.as_str()
            ),
            "Enlarge or rebalance the bad population, or relax the target FAR; do not ship an \
             over-accepting slot.",
        ));
    }
    let achieved_frr = false_reject_rate(good_scores, tau);
    Ok(SlotCalibration {
        slot,
        tau,
        target_far,
        achieved_far,
        achieved_frr,
        drift_bound: DRIFT_ALARM_MULTIPLIER * achieved_far,
        n_bad_calibration: calibration_bad.len(),
        n_bad_validation: validation_bad.len(),
        n_good: good_scores.len(),
        provisional: false,
    })
}

/// Calibrate a full [`GuardProfile`] for `corpus.domain` from a per-slot scorer.
/// Every slot is calibrated by [`calibrate_slot`] against its default target
/// FAR. Fails closed if any slot fails to calibrate.
pub fn calibrate_profile<S: SlotScorer>(
    corpus: &CalibrationCorpus,
    scorer: &S,
    alpha: f32,
) -> Result<GuardProfile, CalibrationError> {
    let mut slots = Vec::with_capacity(GuardSlot::ALL.len());
    for slot in GuardSlot::ALL {
        let good_scores: Vec<f32> = corpus
            .good_cases
            .iter()
            .map(|case| scorer.score_good(slot, case))
            .collect();
        let bad_scores: Vec<f32> = corpus
            .bad_cases
            .iter()
            .map(|case| scorer.score_bad(slot, case))
            .collect();
        slots.push(calibrate_slot(
            slot,
            &good_scores,
            &bad_scores,
            slot.default_target_far(),
            alpha,
        )?);
    }
    Ok(GuardProfile {
        domain: corpus.domain.clone(),
        slots,
        content_policy: default_content_policy(),
        provisional: false,
        corpus_hash: corpus.corpus_hash,
        calibrated_ledger_seq: None,
    })
}

/// High-stakes gate (Ward `validate_high_stakes_profile`): refuse any profile
/// with a provisional (uncalibrated) slot. In high-stakes mode a cold-start
/// profile cannot be used — the guard fails closed rather than admitting code
/// on a `tau = 0.7` guess.
pub fn validate_high_stakes_profile(profile: &GuardProfile) -> Result<(), CalibrationError> {
    if profile.provisional || profile.slots.iter().any(|slot| slot.provisional) {
        let provisional_slots: Vec<&str> = profile
            .slots
            .iter()
            .filter(|slot| slot.provisional)
            .map(|slot| slot.slot.as_str())
            .collect();
        return Err(CalibrationError::new(
            "ASTRO_GUARD_HIGH_STAKES_UNCALIBRATED",
            format!(
                "domain {} has provisional (uncalibrated) slots {:?}; high-stakes mode refuses \
                 on uncalibrated profiles.",
                profile.domain.label(),
                provisional_slots
            ),
            "Run guard_calibrate for this domain and retry, or drop high_stakes to accept \
             provisional cold-start verdicts.",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-slot verdict + no-flatten combination (A3)
// ---------------------------------------------------------------------------

/// One slot's check outcome: measured cosine vs. calibrated `tau`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlotVerdict {
    pub slot: GuardSlot,
    pub cos: f32,
    pub tau: f32,
}

impl SlotVerdict {
    /// A candidate passes a slot iff its cosine meets or exceeds `tau`.
    pub fn pass(&self) -> bool {
        self.cos >= self.tau
    }
    /// Signed margin (cos − tau); negative = below threshold.
    pub fn margin(&self) -> f32 {
        self.cos - self.tau
    }
}

/// The overall guard routing outcome (blueprint §3.5). Ordered by severity so a
/// more-severe class dominates during combination.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum GuardVerdict {
    /// Every slot passes: safe to auto-apply (subject to autonomy policy).
    Accept,
    /// Novel-but-plausible: recorded `AwaitingGrounding`, surfaced for human ack.
    NewRegion,
    /// Held for review (e.g. an identity-slot near-miss).
    Quarantine,
    /// Out-of-distribution: refused with the per-slot breakdown.
    Refuse,
}

impl GuardVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::NewRegion => "new_region",
            Self::Quarantine => "quarantine",
            Self::Refuse => "refuse",
        }
    }
}

/// The combined outcome of a guard check, carrying the per-slot detail (never
/// discarded) and the provisional flag.
#[derive(Debug, Clone, PartialEq)]
pub struct CombinedVerdict {
    pub verdict: GuardVerdict,
    pub per_slot: Vec<SlotVerdict>,
    /// `true` when the driving profile is uncalibrated (cold-start).
    pub provisional: bool,
    /// The most severe reason contributing to the verdict (for remediation).
    pub reason: String,
}

/// Combine per-slot verdicts into an overall routing decision **per-slot, never
/// averaged (A3)**. The decision reads the individual slot pass/fail outcomes
/// and their [`SlotKind`]; it never computes a mean cosine, so a single
/// identity breach refuses even when every other slot passes with a wide
/// margin (asserted in tests). Precedence: Refuse > Quarantine > NewRegion >
/// Accept.
///
/// Identity-locked semantics: the identity slot ([`GuardSlot::PublicApiSignature`])
/// is always treated as identity-locked here. Callers that hold a per-target
/// lock decision use [`combine_verdicts_with_lock`] to downgrade the identity
/// slot to content-class handling for non-exported (unlocked) symbols.
pub fn combine_verdicts(
    per_slot: &[SlotVerdict],
    content_policy: CombinationPolicy,
    provisional: bool,
) -> CombinedVerdict {
    combine_verdicts_with_lock(per_slot, content_policy, provisional, true)
}

/// Combine per-slot verdicts with an explicit **identity-lock** decision for the
/// candidate's target symbol (P7.4, blueprint `10_GUARD.md` §4). Exported/public
/// API symbols are identity-locked: their public-API-signature slot is enforced
/// `AllRequired` at the identity FAR (a breach refuses, a near-miss quarantines).
///
/// A **non-exported** symbol (`identity_locked = false`) is not breaking-change
/// protected: the same public-API-signature drift is folded into the content
/// `KofN` set and handled as content-class (one tolerated miss routes to
/// `new_region`, not an identity refuse). Everything else is unchanged, and the
/// per-slot detail is preserved (never flattened, A3).
pub fn combine_verdicts_with_lock(
    per_slot: &[SlotVerdict],
    content_policy: CombinationPolicy,
    provisional: bool,
    identity_locked: bool,
) -> CombinedVerdict {
    // Effective kind: an unlocked (non-exported) symbol's identity slot is
    // handled as content, never as a breaking-change identity lock.
    let effective_kind = |slot: GuardSlot| -> SlotKind {
        match slot.kind() {
            SlotKind::Identity if !identity_locked => SlotKind::Content,
            other => other,
        }
    };

    let mut verdict = GuardVerdict::Accept;
    let mut reason = String::from("all slots within their calibrated trusted region");

    let escalate =
        |candidate: GuardVerdict, why: String, verdict: &mut GuardVerdict, reason: &mut String| {
            if candidate > *verdict {
                *verdict = candidate;
                *reason = why;
            }
        };

    // 1. Identity slots (AllRequired). A failing identity slot dominates. Only
    //    identity-locked (exported/public) symbols enter this branch.
    for slot_verdict in per_slot
        .iter()
        .filter(|sv| effective_kind(sv.slot) == SlotKind::Identity)
    {
        if !slot_verdict.pass() {
            let within_band = slot_verdict.margin() >= -IDENTITY_QUARANTINE_MARGIN;
            if within_band {
                escalate(
                    GuardVerdict::Quarantine,
                    format!(
                        "identity slot {} near-miss (cos {:.3} < tau {:.3}, within quarantine \
                         band): held for review",
                        slot_verdict.slot.as_str(),
                        slot_verdict.cos,
                        slot_verdict.tau
                    ),
                    &mut verdict,
                    &mut reason,
                );
            } else {
                escalate(
                    GuardVerdict::Refuse,
                    format!(
                        "identity slot {} breach (cos {:.3} < tau {:.3}): breaking-change drift \
                         on a locked API",
                        slot_verdict.slot.as_str(),
                        slot_verdict.cos,
                        slot_verdict.tau
                    ),
                    &mut verdict,
                    &mut reason,
                );
            }
        }
    }

    // 2. Content slots (KofN). Too many content misses => OOD refusal; exactly
    //    the tolerated single miss => novel-but-plausible new-region. For an
    //    unlocked target the identity slot joins this set (content-class).
    let content: Vec<&SlotVerdict> = per_slot
        .iter()
        .filter(|sv| effective_kind(sv.slot) == SlotKind::Content)
        .collect();
    if !content.is_empty() {
        let passes = content.iter().filter(|sv| sv.pass()).count();
        // Preserve the policy's tolerance (allowed misses) across the effective
        // content set size, so folding the identity slot in does not change how
        // many misses are tolerated before OOD refusal.
        let allowed_misses = match content_policy {
            CombinationPolicy::AllRequired => 0,
            CombinationPolicy::KofN { k, n } => n.saturating_sub(k),
        };
        let required_k = content.len().saturating_sub(allowed_misses);
        if passes < required_k {
            let failed: Vec<&str> = content
                .iter()
                .filter(|sv| !sv.pass())
                .map(|sv| sv.slot.as_str())
                .collect();
            escalate(
                GuardVerdict::Refuse,
                format!(
                    "content slots {failed:?} below tau ({passes}/{} passed, need {required_k}): \
                     out-of-distribution for this area",
                    content.len()
                ),
                &mut verdict,
                &mut reason,
            );
        } else if passes < content.len() {
            let failed: Vec<&str> = content
                .iter()
                .filter(|sv| !sv.pass())
                .map(|sv| sv.slot.as_str())
                .collect();
            escalate(
                GuardVerdict::NewRegion,
                format!(
                    "content slots {failed:?} below tau but within the KofN tolerance: \
                     novel-but-plausible, recorded awaiting grounding"
                ),
                &mut verdict,
                &mut reason,
            );
        }
    }

    // 3. Stylistic slots (advisory). A miss routes to new-region, never refusal.
    let stylistic_miss: Vec<&str> = per_slot
        .iter()
        .filter(|sv| sv.slot.kind() == SlotKind::Stylistic && !sv.pass())
        .map(|sv| sv.slot.as_str())
        .collect();
    if !stylistic_miss.is_empty() {
        escalate(
            GuardVerdict::NewRegion,
            format!(
                "stylistic slots {stylistic_miss:?} drift from convention: advisory new-region"
            ),
            &mut verdict,
            &mut reason,
        );
    }

    CombinedVerdict {
        verdict,
        per_slot: per_slot.to_vec(),
        provisional,
        reason,
    }
}

// ---------------------------------------------------------------------------
// Ledger CalibrationMeta payload
// ---------------------------------------------------------------------------

/// The canonical ledger payload for a `guard_calibrate` run: schema-tagged,
/// carrying the domain, profile hash, corpus hash, and per-slot tau/FAR/FRR.
/// The server tool appends this (subject = `SubjectId::Guard`) so every
/// calibration is auditably paired with its ledger entry (blueprint §5, R16).
///
/// The entry's own ledger seq is not embedded — the ledger position *is* the
/// seq, and the config projection (`last_calibrated_ledger_seq`) references it.
///
/// Returned as canonical UTF-8 JSON bytes so the server can both hash it and
/// read it back byte-for-byte in the FSV.
pub fn calibration_meta_payload_bytes(profile: &GuardProfile) -> Vec<u8> {
    // Hand-built canonical JSON (stable key order, no float locale surprises):
    // the server re-parses and re-hashes it, so byte stability matters.
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"schema\":\"{}\",", GUARD_PROFILE_SCHEMA));
    out.push_str(&format!(
        "\"knob_registry\":\"{}\",",
        GUARD_PROFILE_KNOB_REGISTRY_VERSION
    ));
    out.push_str(&format!("\"domain\":\"{}\",", profile.domain.label()));
    out.push_str(&format!(
        "\"profile_hash\":\"{}\",",
        profile.profile_hash_hex()
    ));
    out.push_str(&format!(
        "\"corpus_hash\":\"{}\",",
        profile.corpus_hash_hex()
    ));
    out.push_str("\"slots\":[");
    let mut ordered: Vec<&SlotCalibration> = profile.slots.iter().collect();
    ordered.sort_by_key(|calibration| calibration.slot.ordinal());
    for (index, calibration) in ordered.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"slot\":\"{}\",\"panel_source\":\"{}\",\"kind\":\"{}\",\"tau\":{},\
             \"target_far\":{},\"far\":{},\"frr\":{},\"drift\":{},\"provisional\":{}}}",
            calibration.slot.as_str(),
            calibration.slot.panel_source(),
            calibration.slot.kind().as_str(),
            json_f32(calibration.tau),
            json_f32(calibration.target_far),
            json_f32(calibration.achieved_far),
            json_f32(calibration.achieved_frr),
            json_f32(calibration.drift_bound),
            calibration.provisional,
        ));
    }
    out.push_str("]}");
    out.into_bytes()
}

/// Emit an `f32` as a finite JSON number (never `NaN`/`Infinity`, which are not
/// valid JSON). Non-finite values are clamped to their sign's finite extreme.
fn json_f32(value: f32) -> String {
    if value.is_nan() {
        "0".to_string()
    } else if value.is_infinite() {
        if value > 0.0 {
            "1e38".to_string()
        } else {
            "-1e38".to_string()
        }
    } else {
        // Use the shortest round-trippable representation.
        let text = format!("{value}");
        if text.contains('.') || text.contains('e') || text.contains('E') {
            text
        } else {
            format!("{text}.0")
        }
    }
}
