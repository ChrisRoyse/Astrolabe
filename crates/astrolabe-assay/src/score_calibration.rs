//! Per-pair calibrated severity thresholds derived from a repo's own score
//! distribution (P5.6 blind-spot sweep calibration substrate, #36).
//!
//! The blind-spot sweep in `astrolabe-weave` produces, for one lens pair, a
//! per-symbol *gap* score in `[0, 1000]` millipoints (how far a symbol's
//! confident-lens neighborhood disagrees with its neighbor-lens agreement).
//! Turning those raw scores into severity tiers requires a threshold — and a
//! fixed constant is exactly the anti-pattern standing invariant 4 forbids: a
//! corpus with a tight score distribution and one with a wide one must not share
//! a threshold. This module *measures* the threshold from the repo's own score
//! distribution instead.
//!
//! The estimator is the classic upper-tail rule `threshold = mean + z·stddev`
//! over the observed scores: a symbol is anomalous when its gap sits `z` standard
//! deviations above the corpus mean. The multiplier `z` is a registry-declared
//! knob (a deliberate operator choice of tail strictness), while the threshold
//! *value* is measured per repo, so two corpora with different spreads yield
//! different thresholds. The whole computation is a pure, deterministic function
//! of the input slice — no randomness, no threading — so it is worker-count
//! invariant and reproduces bit-for-bit.
//!
//! Two conditions **refuse with a labeled deficit** rather than fabricate a
//! threshold (standing invariants 2 and 3):
//!
//! * **Below floor** — fewer than the floor number of observations. A handful of
//!   scores cannot pin a distribution, so the calibrator refuses instead of
//!   emitting a threshold no reader should trust.
//! * **Degenerate (zero spread)** — every observation is identical, so the
//!   standard deviation is zero and there is no distributional signal to separate
//!   an anomaly from the bulk. A zero-spread corpus is the zero-signal negative
//!   control: the calibrator refuses, and the sweep flags nothing.

use serde::{Deserialize, Serialize};

use astrolabe_domain::knobs::U64KnobDeclaration;

use crate::error::{
    ASTRO_ASSAY_CALIBRATION_BELOW_FLOOR, ASTRO_ASSAY_CALIBRATION_DEGENERATE,
    ASTRO_ASSAY_CALIBRATION_INPUT_INVALID, AssayError, Result,
};

/// Registry version tag for the per-pair calibration knobs (#36).
pub const ASSAY_CALIBRATION_KNOB_REGISTRY_VERSION: &str = "astrolabe-assay-calibration-knobs-v1";

/// Largest legal per-symbol score, in millipoints (a unit interval mapped onto
/// `[0, 1000]`). A score above this cannot be a valid similarity-gap millipoint
/// value and is rejected as malformed input rather than silently clamped.
pub const ASSAY_CALIBRATION_MAX_SCORE_MILLIPOINTS: u64 = 1_000;

/// Name of the calibration floor-sample-size knob.
pub const ASSAY_CALIBRATION_FLOOR_SAMPLE_SIZE_KNOB: &str = "assay_calibration_floor_sample_size";
/// Name of the medium-tier standard-deviation multiplier knob (permille of σ).
pub const ASSAY_CALIBRATION_MEDIUM_Z_PERMILLE_KNOB: &str = "assay_calibration_medium_z_permille";
/// Name of the high-tier standard-deviation multiplier knob (permille of σ).
pub const ASSAY_CALIBRATION_HIGH_Z_PERMILLE_KNOB: &str = "assay_calibration_high_z_permille";

/// Default minimum observation count below which calibration refuses.
///
/// Below roughly eight observations the sample mean and (especially) the sample
/// standard deviation are dominated by sampling noise, so a `mean + z·σ`
/// threshold derived from them is not a measurement of the repo's distribution —
/// it is a measurement of the noise. Eight is a deliberately conservative floor
/// for a per-repo, per-pair distribution; replace it with a measured
/// stderr-of-σ target once the sweep's score distributions are benchmarked.
pub const ASSAY_DEFAULT_CALIBRATION_FLOOR_SAMPLE_SIZE: u64 = 8;
/// Smallest legal floor: at least two observations are needed to define a spread.
pub const ASSAY_MIN_CALIBRATION_FLOOR_SAMPLE_SIZE: u64 = 2;
/// Largest legal floor. An upper bound keeps the refusal regime bounded.
pub const ASSAY_MAX_CALIBRATION_FLOOR_SAMPLE_SIZE: u64 = 1_000_000;

/// Default medium-tier multiplier, in permille of σ: 1000 = 1.0·σ.
///
/// One standard deviation above the mean is the conventional first upper-tail
/// cut for a bell-shaped statistic; under a normal model it flags the top ~16%
/// of scores as at-least-medium. It is a deliberate strictness choice, not a
/// measurement, hence a declared knob.
pub const ASSAY_DEFAULT_CALIBRATION_MEDIUM_Z_PERMILLE: u64 = 1_000;
/// Default high-tier multiplier, in permille of σ: 2000 = 2.0·σ.
///
/// Two standard deviations above the mean is the conventional strong-outlier cut
/// (top ~2.3% under a normal model), one tier stricter than the medium cut.
pub const ASSAY_DEFAULT_CALIBRATION_HIGH_Z_PERMILLE: u64 = 2_000;
/// Smallest legal σ-multiplier (permille): 1 keeps a sliver of a tail rule.
pub const ASSAY_MIN_CALIBRATION_Z_PERMILLE: u64 = 1;
/// Largest legal σ-multiplier (permille): 100000 = 100·σ, past which the
/// threshold saturates the score ceiling for any realistic spread.
pub const ASSAY_MAX_CALIBRATION_Z_PERMILLE: u64 = 100_000;

/// The per-pair calibration knob registry (#36).
pub const ASSAY_CALIBRATION_KNOBS: &[U64KnobDeclaration] = &[
    U64KnobDeclaration {
        registry_version: ASSAY_CALIBRATION_KNOB_REGISTRY_VERSION,
        name: ASSAY_CALIBRATION_FLOOR_SAMPLE_SIZE_KNOB,
        default: ASSAY_DEFAULT_CALIBRATION_FLOOR_SAMPLE_SIZE,
        min: ASSAY_MIN_CALIBRATION_FLOOR_SAMPLE_SIZE,
        max: ASSAY_MAX_CALIBRATION_FLOOR_SAMPLE_SIZE,
        unit: "observations",
        source: "ASTROLABE #36 (per-lens-pair blind-spot calibration); small-sample instability of the sample standard deviation (Cochran, Sampling Techniques 3rd ed.)",
        rationale: "minimum score count below which a mean+z·σ threshold reflects sampling noise rather than the repo distribution, so calibration refuses with a labeled deficit; replace with a measured stderr-of-σ target once sweep score distributions are benchmarked",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_CALIBRATION_KNOB_REGISTRY_VERSION,
        name: ASSAY_CALIBRATION_MEDIUM_Z_PERMILLE_KNOB,
        default: ASSAY_DEFAULT_CALIBRATION_MEDIUM_Z_PERMILLE,
        min: ASSAY_MIN_CALIBRATION_Z_PERMILLE,
        max: ASSAY_MAX_CALIBRATION_Z_PERMILLE,
        unit: "permille",
        source: "conventional one-sigma upper-tail cut for a bell-shaped statistic (Cover & Thomas / standard z-score outlier rule)",
        rationale: "standard-deviation multiplier for the medium severity tier; 1000 permille = 1.0·σ flags the upper ~16% under a normal model; the threshold VALUE is measured per repo, the multiplier is a deliberate strictness choice",
    },
    U64KnobDeclaration {
        registry_version: ASSAY_CALIBRATION_KNOB_REGISTRY_VERSION,
        name: ASSAY_CALIBRATION_HIGH_Z_PERMILLE_KNOB,
        default: ASSAY_DEFAULT_CALIBRATION_HIGH_Z_PERMILLE,
        min: ASSAY_MIN_CALIBRATION_Z_PERMILLE,
        max: ASSAY_MAX_CALIBRATION_Z_PERMILLE,
        unit: "permille",
        source: "conventional two-sigma strong-outlier cut for a bell-shaped statistic (standard z-score outlier rule)",
        rationale: "standard-deviation multiplier for the high severity tier; 2000 permille = 2.0·σ flags the upper ~2.3% under a normal model, one tier stricter than medium; the threshold VALUE is measured per repo",
    },
];

/// Returns the calibration declaration for `name`, or `None` when undeclared.
pub fn assay_calibration_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    ASSAY_CALIBRATION_KNOBS
        .iter()
        .find(|knob| knob.name == name)
}

/// Configuration for [`calibrate_score_distribution`], every field a
/// registry-declared knob value.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CalibrationConfig {
    /// Minimum observation count below which calibration refuses with a deficit.
    pub floor_sample_size: u64,
    /// Medium-tier σ multiplier, in permille (1000 = 1.0·σ).
    pub medium_z_permille: u64,
    /// High-tier σ multiplier, in permille (2000 = 2.0·σ).
    pub high_z_permille: u64,
}

impl Default for CalibrationConfig {
    fn default() -> Self {
        Self {
            floor_sample_size: ASSAY_DEFAULT_CALIBRATION_FLOOR_SAMPLE_SIZE,
            medium_z_permille: ASSAY_DEFAULT_CALIBRATION_MEDIUM_Z_PERMILLE,
            high_z_permille: ASSAY_DEFAULT_CALIBRATION_HIGH_Z_PERMILLE,
        }
    }
}

impl CalibrationConfig {
    /// Validates every field against its registry-declared bounds, failing closed
    /// on the first out-of-bounds knob.
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            (
                ASSAY_CALIBRATION_FLOOR_SAMPLE_SIZE_KNOB,
                self.floor_sample_size,
            ),
            (
                ASSAY_CALIBRATION_MEDIUM_Z_PERMILLE_KNOB,
                self.medium_z_permille,
            ),
            (ASSAY_CALIBRATION_HIGH_Z_PERMILLE_KNOB, self.high_z_permille),
        ] {
            let knob = assay_calibration_knob(name).expect("declared calibration knob");
            if !knob.accepts(value) {
                return Err(AssayError::new(
                    ASTRO_ASSAY_CALIBRATION_INPUT_INVALID,
                    format!(
                        "calibration knob {name} = {value} is outside [{}, {}]",
                        knob.min, knob.max
                    ),
                    "set the calibration knob to a value inside its declared closed interval",
                ));
            }
        }
        Ok(())
    }
}

/// A per-pair severity calibration measured from one repo's score distribution.
///
/// The two threshold fields are the medium/high severity cut points, in
/// millipoints, that a detector compares a symbol's gap score against. Every
/// field is exact (integer millipoints) so the value is hashable, `Eq`, and
/// reproduces bit-for-bit; the JSON dump ([`calibration_dump_bytes`]) round-trips
/// it for persisted-state readback.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DistributionCalibration {
    /// Opaque key identifying the calibrated lens pair / repo scope (echoed into
    /// provenance so a reader can trace which distribution produced the threshold).
    pub pair_key: String,
    /// Number of scores in the calibrating sample.
    pub sample_size: u64,
    /// Effective sample size actually used (finite in-range observations). Equal
    /// to `sample_size` here because malformed scores are rejected up front, but
    /// reported explicitly so a downstream reader never has to assume it.
    pub n_eff: u64,
    /// Measured sample mean of the scores, in millipoints (rounded).
    pub mean_millipoints: u64,
    /// Measured population standard deviation of the scores, in millipoints
    /// (rounded). Strictly positive — a zero-spread sample refuses calibration.
    pub std_dev_millipoints: u64,
    /// Medium severity threshold `round(mean + z_medium·σ)`, clamped to the score
    /// ceiling, in millipoints.
    pub medium_min_score_millipoints: u64,
    /// High severity threshold `round(mean + z_high·σ)`, clamped to the score
    /// ceiling and never below the medium threshold, in millipoints.
    pub high_min_score_millipoints: u64,
    /// Medium-tier σ multiplier used, in permille.
    pub medium_z_permille: u64,
    /// High-tier σ multiplier used, in permille.
    pub high_z_permille: u64,
    /// Auditable provenance string encoding the registry version, pair key, and
    /// measured moments that produced these thresholds.
    pub provenance_ref: String,
}

/// Derives per-pair severity thresholds from an observed score distribution.
///
/// `scores_millipoints` is the raw per-symbol score set (each in
/// `[0, ASSAY_CALIBRATION_MAX_SCORE_MILLIPOINTS]`). The result's thresholds are
/// `round(mean + z·σ)` for the medium and high `z` knobs, clamped to the score
/// ceiling. The function is a pure, deterministic function of its inputs
/// (worker-count invariant, no randomness).
///
/// # Errors
/// * [`ASTRO_ASSAY_CALIBRATION_INPUT_INVALID`] — a config knob is out of bounds
///   or a score exceeds the ceiling.
/// * [`ASTRO_ASSAY_CALIBRATION_BELOW_FLOOR`] — fewer than `floor_sample_size`
///   observations (refuse with deficit).
/// * [`ASTRO_ASSAY_CALIBRATION_DEGENERATE`] — zero spread (every score equal), so
///   no distributional signal exists to calibrate against.
pub fn calibrate_score_distribution(
    pair_key: &str,
    scores_millipoints: &[u64],
    config: &CalibrationConfig,
) -> Result<DistributionCalibration> {
    config.validate()?;

    for &score in scores_millipoints {
        if score > ASSAY_CALIBRATION_MAX_SCORE_MILLIPOINTS {
            return Err(AssayError::new(
                ASTRO_ASSAY_CALIBRATION_INPUT_INVALID,
                format!(
                    "calibration score {score} exceeds the {ASSAY_CALIBRATION_MAX_SCORE_MILLIPOINTS} millipoint ceiling"
                ),
                "map every per-symbol score into [0, 1000] millipoints before calibrating",
            ));
        }
    }

    let n = scores_millipoints.len() as u64;
    if n < config.floor_sample_size {
        return Err(AssayError::new(
            ASTRO_ASSAY_CALIBRATION_BELOW_FLOOR,
            format!(
                "calibration sample size {n} is below the floor {} for pair {pair_key}",
                config.floor_sample_size
            ),
            "collect at least the floor number of scored symbols before calibrating, or report the finding set as provisional/uncalibrated",
        ));
    }

    let n_f = n as f64;
    let sum: f64 = scores_millipoints.iter().map(|&s| s as f64).sum();
    let mean = sum / n_f;
    // Population variance: the sample IS the repo's score population for this
    // pair, not a draw from a larger one, so the population (÷n) form is the exact
    // second moment of the observed distribution.
    let variance = scores_millipoints
        .iter()
        .map(|&s| s as f64)
        .map(|s| (s - mean) * (s - mean))
        .sum::<f64>()
        / n_f;
    let std_dev = variance.sqrt();

    let std_dev_millipoints = std_dev.round() as u64;
    if std_dev_millipoints == 0 {
        return Err(AssayError::new(
            ASTRO_ASSAY_CALIBRATION_DEGENERATE,
            format!(
                "calibration distribution for pair {pair_key} has zero spread ({n} identical scores); no threshold can separate an anomaly from the bulk"
            ),
            "calibrate against a distribution with real spread, or treat a zero-spread corpus as a zero-signal negative control that flags nothing",
        ));
    }

    let mean_millipoints = mean.round() as u64;
    let ceiling = ASSAY_CALIBRATION_MAX_SCORE_MILLIPOINTS as f64;
    let medium_f =
        (mean + (config.medium_z_permille as f64 / 1_000.0) * std_dev).clamp(0.0, ceiling);
    let high_f = (mean + (config.high_z_permille as f64 / 1_000.0) * std_dev).clamp(0.0, ceiling);
    let medium = medium_f.round() as u64;
    // The high tier is never below the medium tier even if an operator inverts the
    // z knobs; detectors rely on medium <= high to order the tiers.
    let high = (high_f.round() as u64).max(medium);

    let provenance_ref = format!(
        "{ASSAY_CALIBRATION_KNOB_REGISTRY_VERSION}:{pair_key}:n{n}:mean{mean_millipoints}:std{std_dev_millipoints}:zm{}:zh{}:med{medium}:high{high}",
        config.medium_z_permille, config.high_z_permille
    );

    Ok(DistributionCalibration {
        pair_key: pair_key.to_string(),
        sample_size: n,
        n_eff: n,
        mean_millipoints,
        std_dev_millipoints,
        medium_min_score_millipoints: medium,
        high_min_score_millipoints: high,
        medium_z_permille: config.medium_z_permille,
        high_z_permille: config.high_z_permille,
        provenance_ref,
    })
}

/// Serializes a calibration to canonical JSON bytes for persisted-state readback.
///
/// Field order is fixed by the struct declaration, so two calibrations serialize
/// byte-identically exactly when they are equal; [`read_calibration_bytes`]
/// parses the bytes back for an FSV round-trip.
pub fn calibration_dump_bytes(calibration: &DistributionCalibration) -> Vec<u8> {
    serde_json::to_vec(calibration).expect("DistributionCalibration is always serializable")
}

/// Parses calibration bytes written by [`calibration_dump_bytes`] back into a
/// value, failing closed on corrupt bytes.
pub fn read_calibration_bytes(bytes: &[u8]) -> Result<DistributionCalibration> {
    serde_json::from_slice(bytes).map_err(|error| {
        AssayError::new(
            ASTRO_ASSAY_CALIBRATION_INPUT_INVALID,
            format!("persisted calibration bytes did not parse: {error}"),
            "regenerate the calibration from its score distribution",
        )
    })
}
