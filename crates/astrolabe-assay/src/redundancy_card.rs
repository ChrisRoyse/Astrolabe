//! Redundancy & effective rank: total correlation and `n_eff` over the panel's
//! discrete lens columns (blueprint 08_ASSAY §3, deliverable card 3).
//!
//! Given the panel's per-slot values discretized to labels (continuous slots are
//! quantile-binned by the caller before they reach here), this card measures how
//! much the lenses *repeat each other*:
//!
//! * **Total correlation** `TC = Σ H(slotₖ) − H(Φ)` — the bits by which the slots
//!   jointly carry less entropy than the sum of their marginals, i.e. the shared
//!   information. Zero when the slots are independent; maximal when they are
//!   copies.
//! * **Effective rank** `n_eff = k · (1 − TC / ΣH)` for `k` slots — "you have 24
//!   lenses but only 9 independent ones." Independent slots give `n_eff = k`;
//!   `k` identical slots collapse to `n_eff = 1`.
//!
//! It also reports every pairwise slot MI (the redundancy map that feeds the
//! agreement graph and the capability gate), ordered by descending shared bits.
//! Everything is the plug-in discrete estimate over the observed columns, so the
//! card is an exact, deterministic function of its inputs.

use astrolabe_domain::TrustTag;
use serde::{Deserialize, Serialize};

use crate::error::{ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, AssayError, Result};
use crate::estimators::{entropy_bits, mi_discrete};
use crate::knobs::{
    ASSAY_DEFAULT_REDUNDANCY_QUORUM, ASSAY_REDUNDANCY_QUORUM_KNOB, assay_card_knob,
};

/// One panel slot's discrete values across the aligned sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlotColumn {
    /// Stable slot name.
    pub slot: String,
    /// One discrete label per sample; every column must be the same length.
    pub values: Vec<i64>,
}

/// One slot pair's shared information, in bits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedundantPair {
    /// First slot name (lexically smaller of the pair).
    pub a: String,
    /// Second slot name.
    pub b: String,
    /// Pairwise mutual information, in bits.
    pub mi_bits: f64,
}

/// A redundancy card: total correlation, effective rank, and the pairwise map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedundancyCard {
    /// Number of aligned samples every column carries.
    pub n_samples: usize,
    /// Number of slots (lenses) in the panel.
    pub n_slots: usize,
    /// Sum of the per-slot marginal entropies, in bits.
    pub sum_marginal_entropy_bits: f64,
    /// Joint entropy of the whole panel `H(Φ)`, in bits.
    pub joint_entropy_bits: f64,
    /// Total correlation `Σ H(slotₖ) − H(Φ)`, in bits.
    pub total_correlation_bits: f64,
    /// Effective rank `k · (1 − TC / ΣH)`; the count of independent lenses.
    pub n_eff: f64,
    /// Pairwise slot MI, ordered by descending shared bits then slot names.
    pub redundant_pairs: Vec<RedundantPair>,
    /// The per-slot sample quorum applied.
    pub quorum: u64,
    /// Whether the sample is below quorum (card reported but provisional).
    pub below_quorum: bool,
    /// `Trusted` at or above quorum, else `Provisional`.
    pub trust: TrustTag,
}

/// Resolved configuration for the redundancy card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedundancyConfig {
    /// Minimum samples per slot before the card is trusted.
    pub quorum: u64,
}

impl RedundancyConfig {
    /// Builds the config from the declared knob default.
    pub fn from_defaults() -> Result<Self> {
        Ok(Self {
            quorum: card_knob_default(
                ASSAY_REDUNDANCY_QUORUM_KNOB,
                ASSAY_DEFAULT_REDUNDANCY_QUORUM,
            )?,
        })
    }
}

pub(crate) fn card_knob_default(name: &str, value: u64) -> Result<u64> {
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

/// Joint entropy in bits over the tuple of all slot columns.
///
/// Each sample's cross-slot tuple is assigned a compact id via an exact map, so
/// the joint distribution is the true observed one (no hash collisions).
fn joint_entropy_bits(slots: &[SlotColumn], n: usize) -> f64 {
    use std::collections::BTreeMap;
    let mut ids: BTreeMap<Vec<i64>, i64> = BTreeMap::new();
    let mut next = 0i64;
    let mut joint = Vec::with_capacity(n);
    for i in 0..n {
        let tuple: Vec<i64> = slots.iter().map(|s| s.values[i]).collect();
        let id = *ids.entry(tuple).or_insert_with(|| {
            let id = next;
            next += 1;
            id
        });
        joint.push(id);
    }
    entropy_bits(&joint)
}

/// Builds a redundancy card from the panel's discrete slot columns.
///
/// Fails closed on an empty panel, an empty sample, or ragged columns (a column
/// whose length disagrees with the first).
pub fn build_redundancy_card(
    slots: &[SlotColumn],
    cfg: &RedundancyConfig,
) -> Result<RedundancyCard> {
    if slots.is_empty() {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            "redundancy card needs at least one slot column",
            "supply the panel's per-slot discrete columns before measuring redundancy",
        ));
    }
    let n = slots[0].values.len();
    if n == 0 {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            "redundancy card needs a non-empty sample",
            "measure a non-empty aligned sample before requesting redundancy",
        ));
    }
    for s in slots {
        if s.values.len() != n {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!(
                    "slot {} has {} samples but the panel is aligned to {n}",
                    s.slot,
                    s.values.len()
                ),
                "align every slot column to the same sample set before measuring",
            ));
        }
    }

    let marginal: Vec<f64> = slots.iter().map(|s| entropy_bits(&s.values)).collect();
    let sum_marginal: f64 = marginal.iter().sum();
    let joint = joint_entropy_bits(slots, n);
    let tc = (sum_marginal - joint).max(0.0);
    let k = slots.len() as f64;
    let n_eff = if sum_marginal > 0.0 {
        (k * (1.0 - tc / sum_marginal)).clamp(0.0, k)
    } else {
        // No slot carries any entropy: there are zero informative independent lenses.
        0.0
    };

    let mut pairs = Vec::new();
    for i in 0..slots.len() {
        for j in (i + 1)..slots.len() {
            let mi = mi_discrete(&slots[i].values, &slots[j].values);
            let (a, b) = if slots[i].slot <= slots[j].slot {
                (slots[i].slot.clone(), slots[j].slot.clone())
            } else {
                (slots[j].slot.clone(), slots[i].slot.clone())
            };
            pairs.push(RedundantPair { a, b, mi_bits: mi });
        }
    }
    pairs.sort_by(|x, y| {
        y.mi_bits
            .partial_cmp(&x.mi_bits)
            .unwrap()
            .then_with(|| x.a.cmp(&y.a))
            .then_with(|| x.b.cmp(&y.b))
    });

    let below_quorum = (n as u64) < cfg.quorum;
    let trust = if below_quorum {
        TrustTag::Provisional
    } else {
        TrustTag::Trusted
    };
    Ok(RedundancyCard {
        n_samples: n,
        n_slots: slots.len(),
        sum_marginal_entropy_bits: sum_marginal,
        joint_entropy_bits: joint,
        total_correlation_bits: tc,
        n_eff,
        redundant_pairs: pairs,
        quorum: cfg.quorum,
        below_quorum,
        trust,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RedundancyConfig {
        RedundancyConfig::from_defaults().unwrap()
    }

    fn col(name: &str, v: Vec<i64>) -> SlotColumn {
        SlotColumn {
            slot: name.into(),
            values: v,
        }
    }

    #[test]
    fn independent_slots_have_full_effective_rank() {
        // Two independent fair binaries: (i%2) and (i//2 %2) over a long run.
        let n = 400;
        let a: Vec<i64> = (0..n).map(|i| (i % 2) as i64).collect();
        let b: Vec<i64> = (0..n).map(|i| ((i / 2) % 2) as i64).collect();
        let card = build_redundancy_card(&[col("a", a), col("b", b)], &cfg()).unwrap();
        assert!(
            card.total_correlation_bits < 1e-9,
            "TC={}",
            card.total_correlation_bits
        );
        assert!((card.n_eff - 2.0).abs() < 1e-6, "n_eff={}", card.n_eff);
        assert_eq!(card.trust, TrustTag::Trusted);
    }

    #[test]
    fn identical_slots_collapse_to_one_effective_lens() {
        // Two copies of the same fair-binary column: TC = H = 1 bit, n_eff = 1.
        let n = 400;
        let a: Vec<i64> = (0..n).map(|i| (i % 2) as i64).collect();
        let card = build_redundancy_card(&[col("a", a.clone()), col("b", a)], &cfg()).unwrap();
        assert!(
            (card.total_correlation_bits - 1.0).abs() < 1e-9,
            "TC={}",
            card.total_correlation_bits
        );
        assert!((card.n_eff - 1.0).abs() < 1e-6, "n_eff={}", card.n_eff);
        // The identical pair is the top of the redundancy map at 1 bit shared.
        assert!((card.redundant_pairs[0].mi_bits - 1.0).abs() < 1e-9);
    }

    #[test]
    fn ragged_and_empty_inputs_fail_closed() {
        let e = build_redundancy_card(&[], &cfg()).unwrap_err();
        assert_eq!(e.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
        let e = build_redundancy_card(&[col("a", vec![0, 1, 0]), col("b", vec![0, 1])], &cfg())
            .unwrap_err();
        assert_eq!(e.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }

    #[test]
    fn small_sample_is_flagged_below_quorum() {
        let card = build_redundancy_card(
            &[col("a", vec![0, 1, 0, 1]), col("b", vec![1, 0, 1, 0])],
            &cfg(),
        )
        .unwrap();
        assert!(card.below_quorum);
        assert_eq!(card.trust, TrustTag::Provisional);
    }
}
