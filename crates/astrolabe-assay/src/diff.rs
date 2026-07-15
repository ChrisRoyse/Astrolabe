//! Shared configuration and input-reduction helpers for the P5.3 differentiation
//! cards (redundancy, synergy, transfer entropy, periodicity, CUSUM, MMD).
//!
//! [`DiffConfig`] resolves the differentiation knob registry
//! ([`crate::knobs::ASSAY_DIFF_KNOBS`]) into typed fields exactly as
//! [`crate::bits::BitsConfig`] resolves the bits registry — every field is a
//! declared knob, validated against its bounds at construction, never a bare
//! constant. The reduction helpers turn a heterogeneous [`SlotObservations`] into
//! the aligned integer column the discrete plug-in estimators consume.

use crate::bits::{SlotObservations, SlotValues};
use crate::error::{ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, AssayError, Result};
use crate::knobs::{
    ASSAY_CUSUM_MIN_SEGMENT_KNOB, ASSAY_CUSUM_PERMUTATIONS_KNOB,
    ASSAY_DEFAULT_CI_CONFIDENCE_PERMILLE, ASSAY_DEFAULT_CUSUM_MIN_SEGMENT,
    ASSAY_DEFAULT_CUSUM_PERMUTATIONS, ASSAY_DEFAULT_DIFF_DISCRETIZATION_BINS,
    ASSAY_DEFAULT_FAP_THRESHOLD_PERMILLE, ASSAY_DEFAULT_MMD_PERMUTATIONS,
    ASSAY_DEFAULT_PERIODICITY_OVERSAMPLE, ASSAY_DEFAULT_PERIODICITY_PERMUTATIONS,
    ASSAY_DEFAULT_REDUNDANCY_QUORUM, ASSAY_DEFAULT_REDUNDANCY_RETIRE_NMI_PERMILLE,
    ASSAY_DEFAULT_SIGNIFICANCE_PERMILLE, ASSAY_DEFAULT_SYNERGY_MIN_EFFECT_MILLIBITS,
    ASSAY_DEFAULT_SYNERGY_QUORUM, ASSAY_DEFAULT_SYNERGY_RESAMPLES, ASSAY_DEFAULT_TE_MAX_LAG,
    ASSAY_DEFAULT_TE_MIN_LAG, ASSAY_DEFAULT_TE_PERMUTATIONS, ASSAY_DEFAULT_TE_QUORUM,
    ASSAY_DIFF_DISCRETIZATION_BINS_KNOB, ASSAY_FAP_THRESHOLD_PERMILLE_KNOB,
    ASSAY_MMD_PERMUTATIONS_KNOB, ASSAY_PERIODICITY_OVERSAMPLE_KNOB,
    ASSAY_PERIODICITY_PERMUTATIONS_KNOB, ASSAY_REDUNDANCY_QUORUM_KNOB,
    ASSAY_REDUNDANCY_RETIRE_NMI_PERMILLE_KNOB, ASSAY_SIGNIFICANCE_PERMILLE_KNOB,
    ASSAY_SYNERGY_MIN_EFFECT_MILLIBITS_KNOB, ASSAY_SYNERGY_QUORUM_KNOB,
    ASSAY_SYNERGY_RESAMPLES_KNOB, ASSAY_TE_MAX_LAG_KNOB, ASSAY_TE_MIN_LAG_KNOB,
    ASSAY_TE_PERMUTATIONS_KNOB, ASSAY_TE_QUORUM_KNOB, assay_diff_knob,
};
use crate::multivariate::{compact_labels, quantile_bins};
use crate::projection::random_projection;

/// Resolved configuration for the differentiation pipeline, drawn from the
/// registry knobs and validated against their bounds.
#[derive(Debug, Clone, PartialEq)]
pub struct DiffConfig {
    /// Equal-frequency bins for continuous discretization.
    pub diff_bins: usize,
    /// Redundancy per-slot sample quorum.
    pub redundancy_quorum: usize,
    /// Redundancy retire-gate NMI threshold, in `[0,1]`.
    pub redundancy_retire_nmi: f64,
    /// Synergy per-triple sample quorum.
    pub synergy_quorum: usize,
    /// Synergy classification resample count.
    pub synergy_resamples: usize,
    /// Synergy minimum effect magnitude, in bits.
    pub synergy_min_effect_bits: f64,
    /// Smallest lag in the dyadic transfer-entropy sweep.
    pub te_min_lag: usize,
    /// Largest lag in the dyadic transfer-entropy sweep.
    pub te_max_lag: usize,
    /// Transfer-entropy permutation count.
    pub te_permutations: usize,
    /// Transfer-entropy effective-sample quorum.
    pub te_quorum: usize,
    /// Periodicity permutation count.
    pub periodicity_permutations: usize,
    /// Lomb–Scargle frequency-grid oversampling factor.
    pub periodicity_oversample: usize,
    /// Periodicity false-alarm-probability threshold, in `[0,1]`.
    pub fap_threshold: f64,
    /// CUSUM minimum segment length before a reported change.
    pub cusum_min_segment: usize,
    /// CUSUM bootstrap permutation count.
    pub cusum_permutations: usize,
    /// MMD permutation count.
    pub mmd_permutations: usize,
    /// Two-sample significance level, in `[0,1]` (fraction of the null to exceed).
    pub significance: f64,
    /// Two-sided interval level for synergy classification, in permille.
    pub ci_confidence_permille: u64,
}

impl DiffConfig {
    /// Builds the config from the registry knob defaults, failing closed if any
    /// declared default falls outside its own bounds.
    pub fn from_defaults() -> Result<Self> {
        fn checked(name: &str, value: u64) -> Result<u64> {
            let knob = assay_diff_knob(name).ok_or_else(|| {
                AssayError::new(
                    ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                    format!("diff knob {name} is not declared"),
                    "declare the knob in ASSAY_DIFF_KNOBS before using it",
                )
            })?;
            if !knob.accepts(value) {
                return Err(AssayError::new(
                    ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                    format!("diff knob {name} default {value} is outside its declared bounds"),
                    "correct the knob default so it lies within [min, max]",
                ));
            }
            Ok(value)
        }
        let te_min_lag = checked(ASSAY_TE_MIN_LAG_KNOB, ASSAY_DEFAULT_TE_MIN_LAG)? as usize;
        let te_max_lag = checked(ASSAY_TE_MAX_LAG_KNOB, ASSAY_DEFAULT_TE_MAX_LAG)? as usize;
        if te_min_lag > te_max_lag {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!("transfer-entropy min lag {te_min_lag} exceeds max lag {te_max_lag}"),
                "set te_min_lag ≤ te_max_lag so the dyadic sweep is non-empty",
            ));
        }
        Ok(Self {
            diff_bins: checked(
                ASSAY_DIFF_DISCRETIZATION_BINS_KNOB,
                ASSAY_DEFAULT_DIFF_DISCRETIZATION_BINS,
            )? as usize,
            redundancy_quorum: checked(
                ASSAY_REDUNDANCY_QUORUM_KNOB,
                ASSAY_DEFAULT_REDUNDANCY_QUORUM,
            )? as usize,
            redundancy_retire_nmi: checked(
                ASSAY_REDUNDANCY_RETIRE_NMI_PERMILLE_KNOB,
                ASSAY_DEFAULT_REDUNDANCY_RETIRE_NMI_PERMILLE,
            )? as f64
                / 1000.0,
            synergy_quorum: checked(ASSAY_SYNERGY_QUORUM_KNOB, ASSAY_DEFAULT_SYNERGY_QUORUM)?
                as usize,
            synergy_resamples: checked(
                ASSAY_SYNERGY_RESAMPLES_KNOB,
                ASSAY_DEFAULT_SYNERGY_RESAMPLES,
            )? as usize,
            synergy_min_effect_bits: checked(
                ASSAY_SYNERGY_MIN_EFFECT_MILLIBITS_KNOB,
                ASSAY_DEFAULT_SYNERGY_MIN_EFFECT_MILLIBITS,
            )? as f64
                / 1000.0,
            te_min_lag,
            te_max_lag,
            te_permutations: checked(ASSAY_TE_PERMUTATIONS_KNOB, ASSAY_DEFAULT_TE_PERMUTATIONS)?
                as usize,
            te_quorum: checked(ASSAY_TE_QUORUM_KNOB, ASSAY_DEFAULT_TE_QUORUM)? as usize,
            periodicity_permutations: checked(
                ASSAY_PERIODICITY_PERMUTATIONS_KNOB,
                ASSAY_DEFAULT_PERIODICITY_PERMUTATIONS,
            )? as usize,
            periodicity_oversample: checked(
                ASSAY_PERIODICITY_OVERSAMPLE_KNOB,
                ASSAY_DEFAULT_PERIODICITY_OVERSAMPLE,
            )? as usize,
            fap_threshold: checked(
                ASSAY_FAP_THRESHOLD_PERMILLE_KNOB,
                ASSAY_DEFAULT_FAP_THRESHOLD_PERMILLE,
            )? as f64
                / 1000.0,
            cusum_min_segment: checked(
                ASSAY_CUSUM_MIN_SEGMENT_KNOB,
                ASSAY_DEFAULT_CUSUM_MIN_SEGMENT,
            )? as usize,
            cusum_permutations: checked(
                ASSAY_CUSUM_PERMUTATIONS_KNOB,
                ASSAY_DEFAULT_CUSUM_PERMUTATIONS,
            )? as usize,
            mmd_permutations: checked(ASSAY_MMD_PERMUTATIONS_KNOB, ASSAY_DEFAULT_MMD_PERMUTATIONS)?
                as usize,
            significance: checked(
                ASSAY_SIGNIFICANCE_PERMILLE_KNOB,
                ASSAY_DEFAULT_SIGNIFICANCE_PERMILLE,
            )? as f64
                / 1000.0,
            ci_confidence_permille: ASSAY_DEFAULT_CI_CONFIDENCE_PERMILLE,
        })
    }

    /// The dyadic transfer-entropy lag sweep: the powers of two in
    /// `[te_min_lag, te_max_lag]`. At the defaults this is `{1, 2, 4, 8}`.
    pub fn te_lags(&self) -> Vec<usize> {
        let mut lags = Vec::new();
        let mut lag = 1usize;
        while lag <= self.te_max_lag {
            if lag >= self.te_min_lag {
                lags.push(lag);
            }
            lag = match lag.checked_mul(2) {
                Some(next) => next,
                None => break,
            };
        }
        // If min_lag is not itself a power of two, still guarantee at least the
        // smallest admissible dyadic lag is present.
        if lags.is_empty() && self.te_min_lag <= self.te_max_lag {
            lags.push(self.te_min_lag);
        }
        lags
    }
}

/// Reduces a slot to an aligned discrete integer column for the plug-in
/// estimators: scalars are equal-frequency binned, labels compacted, and
/// embeddings deterministically projected to one axis then binned.
///
/// Fails closed on an empty slot or a non-finite value, mirroring the bits
/// pipeline's input contract.
pub fn discretize_slot(slot: &SlotObservations, seed: u64, cfg: &DiffConfig) -> Result<Vec<i64>> {
    if slot.values.is_empty() {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("slot {} carries no samples", slot.slot),
            "supply a non-empty slot before differentiating",
        ));
    }
    match &slot.values {
        SlotValues::Scalar(v) => {
            if v.iter().any(|x| !x.is_finite()) {
                return Err(non_finite(&slot.slot));
            }
            Ok(quantile_bins(v, cfg.diff_bins))
        }
        SlotValues::Label(v) => Ok(compact_labels(v).0),
        SlotValues::Embedding { dim, rows } => {
            for row in rows {
                if row.len() != *dim {
                    return Err(AssayError::new(
                        ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                        format!(
                            "embedding slot {} has a row of width {} but dim is {dim}",
                            slot.slot,
                            row.len()
                        ),
                        "give every embedding row the declared dim width",
                    ));
                }
                if row.iter().any(|x| !x.is_finite()) {
                    return Err(non_finite(&slot.slot));
                }
            }
            // Reduce the embedding to one JL-projected axis, then bin it: enough to
            // expose redundancy between two embedding lenses without an O(n²) k-NN.
            let projected = random_projection(rows, *dim, 1, seed);
            let axis: Vec<f64> = projected
                .iter()
                .map(|r| r.first().copied().unwrap_or(0.0))
                .collect();
            Ok(quantile_bins(&axis, cfg.diff_bins))
        }
    }
}

fn non_finite(slot: &str) -> AssayError {
    AssayError::new(
        ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
        format!("slot {slot} carries a non-finite value"),
        "supply only finite measured values to the differentiation estimators",
    )
}
