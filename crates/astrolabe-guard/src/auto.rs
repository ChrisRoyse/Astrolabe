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

use crate::calibration::{CalibrationDomain, CalibrationError};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibration::CalibrationLanguage;
    use crate::profile::validate_high_stakes_profile;
    use astrolabe_panel::{EncoderLensInput, StructuralTrigram, encode_slot};
    use calyx_core::SlotId;

    fn domain() -> CalibrationDomain {
        CalibrationDomain::new(CalibrationLanguage::Rust, "core").expect("valid domain")
    }

    fn empty_encoder_input() -> EncoderLensInput {
        EncoderLensInput {
            ast_profile: None,
            struct_trigrams: None,
            complexity: None,
            api_calls: None,
            type_surface: None,
            decorators: None,
            identifiers: None,
            graph_position: None,
            path_hierarchy: None,
            churn_profile: None,
            recency: None,
            role_flags: None,
            lang_label: None,
            test_topology: None,
            error_surface: None,
            config_env_surface: None,
            route_surface: None,
            record_vec: None,
        }
    }

    /// A real S1 struct-trigram vector for a set of trigrams (exercises the real
    /// panel encoder, not a hand-built vector).
    fn s1_vector(tris: &[(&str, &str, &str)]) -> SlotVector {
        let struct_trigrams = tris
            .iter()
            .map(|(a, b, c)| StructuralTrigram {
                a: (*a).to_string(),
                b: (*b).to_string(),
                c: (*c).to_string(),
                weight: 1.0,
            })
            .collect();
        let input = EncoderLensInput {
            struct_trigrams: Some(struct_trigrams),
            ..empty_encoder_input()
        };
        encode_slot(SlotId::new(1), &input).expect("S1 encodes")
    }

    /// A dense unit-ish vector for the embedding/dense slots (S18/S20/S2/S4/S5/S15),
    /// built so trusted symbols cluster and alien symbols separate. `axis` selects the
    /// dominant direction; `dim` the slot's dimension.
    fn dense_axis(dim: u32, axis: usize, jitter: f32) -> SlotVector {
        let mut data = vec![0.0f32; dim as usize];
        data[axis % dim as usize] = 1.0;
        // A little off-axis jitter so cosines are not degenerate 1.0/0.0.
        data[(axis + 1) % dim as usize] = jitter;
        SlotVector::Dense { dim, data }
    }

    /// Build a measured symbol whose every guard panel source is present, dominated by
    /// `axis` (trusted vs alien differ by axis). Uses the real S1 encoder for the
    /// struct-trigram slot and dense axis vectors for the remaining slots.
    fn symbol(axis: usize, jitter: f32, trusted_struct: bool) -> MeasuredSymbol {
        let s1 = if trusted_struct {
            s1_vector(&[
                ("function_definition", "parameters", "identifier"),
                ("if_statement", "comparison_operator", "identifier"),
                ("return_statement", "binary_expression", "identifier"),
            ])
        } else {
            s1_vector(&[
                ("class_definition", "block", "method"),
                ("for_statement", "call_expression", "argument_list"),
                ("try_statement", "except_clause", "raise_statement"),
            ])
        };
        MeasuredSymbol::new([
            (1u16, s1),
            (2, dense_axis(8, axis, jitter)),
            (4, dense_axis(64, axis, jitter)),
            (5, dense_axis(64, axis, jitter)),
            (15, dense_axis(64, axis, jitter)),
            (17, dense_axis(64, axis, jitter)),
            (18, dense_axis(768, axis, jitter)),
            (20, dense_axis(768, axis, jitter)),
        ])
    }

    fn trusted_set() -> Vec<MeasuredSymbol> {
        // Tight trusted cluster around axis 0 with small jitter.
        (0..30)
            .map(|i| symbol(0, 0.02 + (i % 5) as f32 * 0.005, true))
            .collect()
    }

    fn alien_set() -> Vec<MeasuredSymbol> {
        // Separated bad cluster around a different axis, and structurally alien.
        (0..30).map(|i| symbol(3 + i % 4, 0.01, false)).collect()
    }

    #[test]
    fn auto_calibration_produces_measured_slots_that_separate_good_from_bad() {
        let profile = calibrate_auto(domain(), 1, &trusted_set(), &alien_set(), [7u8; 32], 0.05)
            .expect("auto calibrates");
        assert!(
            !profile.provisional,
            "auto profile must be measured, not cold-start"
        );
        assert_eq!(profile.corpus_hash, [7u8; 32]);
        assert_eq!(profile.slots.len(), GuardSlot::ALL.len());
        for slot in &profile.slots {
            assert!(
                !slot.provisional,
                "slot {} still provisional",
                slot.slot.as_str()
            );
            // tau sits below the trusted cosines (~1) and excludes the alien band.
            assert!(
                slot.tau <= 1.0 + f32::EPSILON,
                "slot {} tau {}",
                slot.slot.as_str(),
                slot.tau
            );
            assert!(
                slot.n_bad_validation >= 1,
                "slot {} held out no bad",
                slot.slot.as_str()
            );
        }
        // A fully-measured auto profile passes the high-stakes gate.
        validate_high_stakes_profile(&profile)
            .expect("calibrated auto profile is high-stakes ready");
    }

    #[test]
    fn empty_trusted_set_is_refused_with_deficit() {
        let err = calibrate_auto(domain(), 1, &[], &alien_set(), [0u8; 32], 0.05)
            .expect_err("empty trusted set must refuse");
        assert_eq!(err.code(), ASTRO_GUARD_AUTO_NO_TRUSTED);
        assert!(!err.remediation().is_empty());
    }

    #[test]
    fn thin_bad_population_is_refused_not_thinned() {
        // A single bad symbol cannot be split into calibration + validation halves.
        let one_bad = vec![symbol(3, 0.01, false)];
        let err = calibrate_auto(domain(), 1, &trusted_set(), &one_bad, [0u8; 32], 0.05)
            .expect_err("single bad case cannot be split");
        assert_eq!(err.code(), "ASTRO_GUARD_SLOT_UNSPLITTABLE");
    }

    #[test]
    fn panel_lacking_a_required_slot_is_a_fail_closed_deficit_card() {
        // Every trusted symbol is missing panel source S4 (api_callees): the good set
        // has no measurement of that slot, so no trusted centroid can be formed.
        let mut good = trusted_set();
        for symbol in good.iter_mut() {
            symbol.slots.remove(&4);
        }
        let err = calibrate_auto(domain(), 1, &good, &alien_set(), [0u8; 32], 0.05)
            .expect_err("unmeasured required slot must refuse");
        assert_eq!(err.code(), ASTRO_GUARD_AUTO_SLOT_UNMEASURED);
        assert!(err.message().contains("api_callees"));
        assert!(err.message().contains("S4"));
    }

    #[test]
    fn invalid_panel_version_is_refused() {
        for bad_version in [0u32, 3, 99] {
            let err = calibrate_auto(
                domain(),
                bad_version,
                &trusted_set(),
                &alien_set(),
                [0u8; 32],
                0.05,
            )
            .expect_err("unknown panel version must refuse");
            assert_eq!(err.code(), ASTRO_GUARD_AUTO_PANEL_VERSION);
        }
        // Both frozen rosters are accepted (guard sources are all S0-S22).
        for good_version in [1u32, 2] {
            calibrate_auto(
                domain(),
                good_version,
                &trusted_set(),
                &alien_set(),
                [0u8; 32],
                0.05,
            )
            .unwrap_or_else(|err| panic!("version {good_version} should calibrate: {err}"));
        }
    }

    #[test]
    fn shape_mismatch_in_a_source_fails_closed() {
        // Corrupt one trusted S18 vector to the wrong dim: the centroid build detects
        // the shape contract violation and refuses (never a silent zero score).
        let mut good = trusted_set();
        good[0].slots.insert(
            18,
            SlotVector::Dense {
                dim: 4,
                data: vec![1.0, 0.0, 0.0, 0.0],
            },
        );
        let err = calibrate_auto(domain(), 1, &good, &alien_set(), [0u8; 32], 0.05)
            .expect_err("dim mismatch must fail closed");
        assert_eq!(err.code(), ASTRO_GUARD_AUTO_PANEL_ERROR);
    }

    #[test]
    fn panel_source_mapping_covers_every_guard_slot() {
        for slot in GuardSlot::ALL {
            let sources = guard_slot_panel_sources(slot);
            assert!(
                !sources.is_empty(),
                "slot {} has no panel source",
                slot.as_str()
            );
        }
        assert_eq!(
            guard_slot_panel_sources(GuardSlot::PublicApiSignature),
            &[5, 17]
        );
        assert_eq!(guard_slot_panel_sources(GuardSlot::CodeSemantic), &[18]);
    }

    #[test]
    fn same_inputs_calibrate_deterministically() {
        let a = calibrate_auto(domain(), 1, &trusted_set(), &alien_set(), [9u8; 32], 0.05).unwrap();
        let b = calibrate_auto(domain(), 1, &trusted_set(), &alien_set(), [9u8; 32], 0.05).unwrap();
        assert_eq!(a.canonical_profile_hash(), b.canonical_profile_hash());
    }
}
