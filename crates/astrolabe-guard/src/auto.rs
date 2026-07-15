//! Guard `guard_calibrate` **auto** path (blueprint `10_GUARD.md` §1/§3, #326).
//!
//! The wave-9 calibration core (#46) consumes operator-supplied per-slot cosine
//! populations. The blueprint contract additionally specifies an *auto* path: given
//! `sources`, score them through the real panel/lens stack
//! (S18/S1/S4/S20/S2/S15/S5+S17) to derive the good/bad cosine populations itself,
//! then feed the existing split-conformal `calibrate_slot` machinery unchanged.
//!
//! This module owns the panel→guard bridge that is *pure* (no libcbm, no vault): the
//! guard-slot → panel-slot mapping, and [`calibrate_auto`], which measures each
//! source's per-slot cosine to a trusted-region centroid and calibrates every guard
//! slot. The server handler supplies the [`MeasuredSymbol`]s (panel readouts over the
//! real indexed corpus) and pairs the result with its ledger entry.
//!
//! Doctrine held here (standing invariants):
//! - **No silent fallback (#3):** a panel that lacks a required slot for the whole
//!   trusted set is a fail-closed deficit card ([`ASTRO_GUARD_AUTO_SLOT_UNMEASURED`]),
//!   never a silently dropped slot or a revert to supplied scores.
//! - **Refusal over guessing (#2):** an empty trusted set, a thin bad population, or a
//!   held-out FAR over its finite-sample bound all refuse with a coded deficit.
//! - **Fail-closed roster (#310):** the panel version is validated up front against the
//!   frozen roster; an unknown version refuses rather than measuring the wrong panel.

use std::collections::BTreeMap;

use astrolabe_panel::{slot_centroid, slot_vector_cosine};
use calyx_core::SlotVector;

use crate::calibration::{BadCase, CalibrationCorpus, CalibrationDomain, CalibrationError};
use crate::profile::{
    GuardProfile, GuardSlot, SlotCalibration, calibrate_slot, default_content_policy,
};

/// Deficit code: the panel produced no measurement of a guard slot's panel source
/// across the entire trusted (good) set, so no trusted-region centroid can be formed.
pub const ASTRO_GUARD_AUTO_SLOT_UNMEASURED: &str = "ASTRO_GUARD_AUTO_SLOT_UNMEASURED";
/// Deficit code: the trusted (good) source set is empty — there is nothing to build a
/// trusted region from.
pub const ASTRO_GUARD_AUTO_NO_TRUSTED: &str = "ASTRO_GUARD_AUTO_NO_TRUSTED";
/// Deficit code: the requested panel roster version has no frozen slot roster.
pub const ASTRO_GUARD_AUTO_PANEL_VERSION: &str = "ASTRO_GUARD_AUTO_PANEL_VERSION";
/// Deficit code: a panel cosine/centroid computation failed (shape/dim contract
/// violation) while deriving a slot's cosine population.
pub const ASTRO_GUARD_AUTO_PANEL_ERROR: &str = "ASTRO_GUARD_AUTO_PANEL_ERROR";
/// Deficit code: an auto-generated bad corpus produced no bad cases, so the guard
/// has nothing out-of-distribution to calibrate the conformal tau against.
pub const ASTRO_GUARD_AUTO_CORPUS_EMPTY: &str = "ASTRO_GUARD_AUTO_CORPUS_EMPTY";

/// The panel slot id(s) each guard slot measures (blueprint `10_GUARD.md` §1 table).
///
/// A guard slot with two panel sources (`PublicApiSignature` = S5 type-surface + S17
/// route-surface) measures a symbol against *both* trusted-region centroids and
/// combines the per-source cosines with a uniform mean (an assumption-free structural
/// combiner, not a tunable weight).
pub const fn guard_slot_panel_sources(slot: GuardSlot) -> &'static [u16] {
    match slot {
        GuardSlot::CodeSemantic => &[18],
        GuardSlot::StructTrigrams => &[1],
        GuardSlot::ApiCallees => &[4],
        GuardSlot::NameSemantic => &[20],
        GuardSlot::ComplexityProfile => &[2],
        GuardSlot::ErrorSurface => &[15],
        GuardSlot::PublicApiSignature => &[5, 17],
    }
}

/// One measured symbol: its panel slot vectors, keyed by panel slot id. Only the
/// guard-relevant panel source slots need be present; a slot absent from the map (or
/// present as [`SlotVector::Absent`]) is treated as unmeasured for that symbol.
#[derive(Debug, Clone, PartialEq)]
pub struct MeasuredSymbol {
    /// Panel slot id → measured vector for this symbol.
    pub slots: BTreeMap<u16, SlotVector>,
}

impl MeasuredSymbol {
    /// Builds a measured symbol from `(panel_slot_id, vector)` pairs.
    pub fn new(slots: impl IntoIterator<Item = (u16, SlotVector)>) -> Self {
        Self {
            slots: slots.into_iter().collect(),
        }
    }

    /// The measured vector for a panel slot, treating an explicit absence as no
    /// measurement.
    fn measured(&self, panel_slot: u16) -> Option<&SlotVector> {
        self.slots
            .get(&panel_slot)
            .filter(|vector| !vector.is_absent())
    }
}

/// Auto-derive per-slot good/bad cosine populations by scoring sources through the
/// panel, then calibrate every guard slot with the existing split-conformal machinery.
///
/// For each guard slot, the trusted-region centroid is the mean direction over the
/// `good` measurements of the slot's panel source(s); every good/bad symbol is scored
/// as its cosine to that centroid (per-source cosines uniformly averaged for a
/// multi-source slot). Those populations feed [`calibrate_slot`] against the slot's
/// registry-declared target FAR.
///
/// Fails closed (never a partial or over-accepting profile) when:
/// - `good` is empty ([`ASTRO_GUARD_AUTO_NO_TRUSTED`]);
/// - a required panel source has no trusted measurement at all
///   ([`ASTRO_GUARD_AUTO_SLOT_UNMEASURED`] — the deficit card);
/// - the panel version is not a frozen roster ([`ASTRO_GUARD_AUTO_PANEL_VERSION`]);
/// - a cosine/centroid contract is violated ([`ASTRO_GUARD_AUTO_PANEL_ERROR`]);
/// - any slot's bad population is too thin to split, or its held-out FAR breaches its
///   finite-sample ceiling (surfaced verbatim from [`calibrate_slot`]).
pub fn calibrate_auto(
    domain: CalibrationDomain,
    panel_version: u32,
    good: &[MeasuredSymbol],
    bad: &[MeasuredSymbol],
    corpus_hash: [u8; 32],
    alpha: f32,
) -> Result<GuardProfile, CalibrationError> {
    // Fail-closed roster selector (#310): reject an unknown panel version before
    // measuring anything, rather than silently scoring the wrong panel.
    astrolabe_panel::slots_for_version(panel_version).map_err(|err| {
        CalibrationError::new(
            ASTRO_GUARD_AUTO_PANEL_VERSION,
            format!(
                "panel version {panel_version} has no frozen slot roster: {}",
                err.message()
            ),
            "Calibrate with panel version 1 (S0-S22) or 2 (S0-S23).",
        )
    })?;

    if good.is_empty() {
        return Err(CalibrationError::new(
            ASTRO_GUARD_AUTO_NO_TRUSTED,
            "auto calibration has no trusted (good) sources; a trusted region cannot be formed",
            "Supply at least one in-distribution source symbol for the domain before calibrating.",
        ));
    }

    let mut slots = Vec::with_capacity(GuardSlot::ALL.len());
    for slot in GuardSlot::ALL {
        let calibration = calibrate_auto_slot(slot, good, bad, alpha)?;
        slots.push(calibration);
    }

    Ok(GuardProfile {
        domain,
        slots,
        content_policy: default_content_policy(),
        provisional: false,
        corpus_hash,
        calibrated_ledger_seq: None,
    })
}

/// Measures one auto-generated [`BadCase`] (a real source transformation — mutant,
/// alien symbol, reverted code, or vulnerability snippet) into its guard panel-source
/// slot vectors *through the real panel*.
///
/// This is the seam the blueprint's fuller AUTO path needs (#334): the bad calibration
/// population is *generated* from the indexed corpus (mutation operators + alien
/// constellations via [`crate::calibration::build_corpus`]) and each bad case is
/// re-measured through the panel — never a caller-supplied `class` tag. The concrete
/// implementor drives the real libcbm re-parse + panel encoders (the server's
/// `ShadowSlotRuntime`); the guard crate stays panel-runtime-agnostic and only
/// orchestrates, so a panel measurement failure surfaces as a fail-closed refusal
/// (standing invariant #3 — never a silent skip or a revert to the class-tag path).
pub trait CorpusPanelMeasurer {
    /// Measure a generated bad case into its guard panel-source slot vectors. A
    /// measurement fault must be returned as a coded [`CalibrationError`], never
    /// swallowed into an absent/empty measurement.
    fn measure_bad_case(&self, case: &BadCase) -> Result<MeasuredSymbol, CalibrationError>;
}

/// Auto-generate-and-calibrate: measure every bad case in a *generated* corpus through
/// the real panel and calibrate every guard slot against those measured populations.
///
/// `good` is the trusted (in-distribution) population, already measured through the
/// same panel (the server measures the indexed good symbols). `corpus` is the
/// stratified bad-case corpus produced by [`crate::calibration::build_corpus`]
/// (mutation + revert + alien + vulnerability, mix-policy enforced). Each bad case is
/// re-measured through `measurer`, then the good/bad measured populations feed
/// [`calibrate_auto`] unchanged, pinning the corpus's `corpus_hash` into the profile.
///
/// Fails closed (never a partial or over-accepting profile) when:
/// - the generated corpus has no bad cases ([`ASTRO_GUARD_AUTO_CORPUS_EMPTY`]);
/// - measuring any bad case through the panel fails (the measurer's coded error is
///   surfaced verbatim — the auto path never falls back to caller tags on a fault);
/// - any condition [`calibrate_auto`] itself refuses (empty trusted set, unmeasured
///   required slot, invalid panel version, thin/over-accepting slot population).
pub fn calibrate_auto_from_corpus<M: CorpusPanelMeasurer>(
    domain: CalibrationDomain,
    panel_version: u32,
    good: &[MeasuredSymbol],
    corpus: &CalibrationCorpus,
    measurer: &M,
    alpha: f32,
) -> Result<GuardProfile, CalibrationError> {
    if corpus.bad_cases.is_empty() {
        return Err(CalibrationError::new(
            ASTRO_GUARD_AUTO_CORPUS_EMPTY,
            "the auto-generated calibration corpus produced no bad cases; there is nothing \
             out-of-distribution to calibrate the conformal tau against",
            "Widen the mutation source set or supply alien/revert records so build_corpus yields \
             a stratified bad population before auto-calibrating.",
        ));
    }

    let mut bad: Vec<MeasuredSymbol> = Vec::with_capacity(corpus.bad_cases.len());
    for case in &corpus.bad_cases {
        // Fail-closed: a panel fault on any generated bad case refuses the whole run;
        // it never silently drops the case or reverts to caller-supplied populations.
        bad.push(measurer.measure_bad_case(case)?);
    }

    calibrate_auto(domain, panel_version, good, &bad, corpus.corpus_hash, alpha)
}

fn calibrate_auto_slot(
    slot: GuardSlot,
    good: &[MeasuredSymbol],
    bad: &[MeasuredSymbol],
    alpha: f32,
) -> Result<SlotCalibration, CalibrationError> {
    let sources = guard_slot_panel_sources(slot);

    // Build a trusted-region centroid per panel source from the good measurements.
    // A source with no trusted measurement at all is a fail-closed deficit card.
    let mut centroids: Vec<(u16, SlotVector)> = Vec::with_capacity(sources.len());
    for &panel_slot in sources {
        let measured: Vec<&SlotVector> = good
            .iter()
            .filter_map(|symbol| symbol.measured(panel_slot))
            .collect();
        let centroid =
            slot_centroid(&measured).map_err(|err| panel_error(slot, panel_slot, &err))?;
        match centroid {
            Some(centroid) => centroids.push((panel_slot, centroid)),
            None => {
                return Err(CalibrationError::new(
                    ASTRO_GUARD_AUTO_SLOT_UNMEASURED,
                    format!(
                        "guard slot `{}` (panel source S{panel_slot}) has no trusted measurement \
                         across the good set; the panel lacks this required slot",
                        slot.as_str()
                    ),
                    "Index sources that exercise this slot, or exclude the domain from auto \
                     calibration until the panel measures it — never calibrate a slot the panel \
                     cannot see.",
                ));
            }
        }
    }

    let good_scores = population_scores(slot, good, &centroids)?;
    let bad_scores = population_scores(slot, bad, &centroids)?;

    calibrate_slot(
        slot,
        &good_scores,
        &bad_scores,
        slot.default_target_far(),
        alpha,
    )
}

/// Scores every symbol in `population` against the slot's trusted centroid(s): the
/// per-source cosines are uniformly averaged, and a symbol with no measured source is
/// dropped from the population (its gap is real, not a fabricated score).
fn population_scores(
    slot: GuardSlot,
    population: &[MeasuredSymbol],
    centroids: &[(u16, SlotVector)],
) -> Result<Vec<f32>, CalibrationError> {
    let mut scores = Vec::with_capacity(population.len());
    for symbol in population {
        let mut sum = 0.0f32;
        let mut count = 0u32;
        for (panel_slot, centroid) in centroids {
            let Some(vector) = symbol.measured(*panel_slot) else {
                continue;
            };
            let cos = slot_vector_cosine(vector, centroid)
                .map_err(|err| panel_error(slot, *panel_slot, &err))?;
            if let Some(cos) = cos {
                sum += cos;
                count += 1;
            }
        }
        if count > 0 {
            scores.push(sum / count as f32);
        }
    }
    Ok(scores)
}

fn panel_error(
    slot: GuardSlot,
    panel_slot: u16,
    err: &astrolabe_panel::PanelError,
) -> CalibrationError {
    CalibrationError::new(
        ASTRO_GUARD_AUTO_PANEL_ERROR,
        format!(
            "guard slot `{}` panel source S{panel_slot} scoring failed: {} ({})",
            slot.as_str(),
            err.message(),
            err.code()
        ),
        "Re-measure the sources through the panel; a slot-vector shape/dim contract was violated.",
    )
}
