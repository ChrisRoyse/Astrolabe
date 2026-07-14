//! Synergy: three-way interaction information over designed triples, with a
//! sign-and-interval classifier that promotes synergistic pairs' cross-terms
//! (08_ASSAY §4, capability 4.5).
//!
//! For a triple `(X, Y, outcome)` the co-information
//! `I(X;Y;outcome) = I(X;Y) − I(X;Y|outcome)` classifies the pair:
//!
//! * **negative** → *synergistic*: `X` and `Y` predict the outcome together beyond
//!   what either predicts alone (the XOR case is exactly `−1` bit). The pair's
//!   interaction cross-term is promoted to eager (07 §4).
//! * **positive** → *redundant*: the pair explains the outcome through shared
//!   information.
//! * **interval within the effect band** → *unclear*: not enough evidence to
//!   classify (`BUILDING_ON_CALYX` §4 — classify by whether the interval straddles
//!   zero, widened to a `±min_effect` band so finite-sample plug-in bias on
//!   independent variables is not mistaken for synergy).
//!
//! The interval is a seeded without-replacement subsample percentile interval, so
//! the classification is a pure function of `(inputs, seed, config)`.

use astrolabe_domain::TrustTag;
use serde::{Deserialize, Serialize};

use crate::bits::{BitsInterval, SlotObservations};
use crate::diff::{DiffConfig, discretize_slot};
use crate::error::{ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, AssayError, Result};
use crate::multivariate::{interaction_information_bits, percentile_interval};
use crate::rng::DeterministicRng;

/// The three aligned slots of one designed synergy triple.
#[derive(Debug, Clone, PartialEq)]
pub struct SynergyTripleInput {
    /// First predictor slot.
    pub x: SlotObservations,
    /// Second predictor slot.
    pub y: SlotObservations,
    /// The outcome slot the pair is tested against.
    pub outcome: SlotObservations,
}

/// The synergy classification of a triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynergyClass {
    /// Interaction information whose whole interval stays below the negative
    /// effect band: a confident synergy.
    Synergistic,
    /// Interaction information whose whole interval stays above the positive
    /// effect band: a confident redundancy.
    Redundant,
    /// The interval lies within the effect band: no confident classification.
    Unclear,
}

/// One triple's measured interaction information and classification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SynergyTriple {
    /// First predictor slot name.
    pub x: String,
    /// Second predictor slot name.
    pub y: String,
    /// Outcome slot name.
    pub outcome: String,
    /// Co-information `I(X;Y;outcome)`, in bits (negative = synergy).
    pub interaction_information_bits: f64,
    /// Interval around the interaction information.
    pub interval: BitsInterval,
    /// The classification derived from the interval's position relative to the
    /// effect band around zero.
    pub classification: SynergyClass,
    /// Whether the pair's interaction cross-term is promoted to eager.
    pub promote_cross_term: bool,
    /// Aligned sample count.
    pub n: usize,
    /// `Trusted` above the synergy quorum, else `Provisional`.
    pub trust: TrustTag,
}

/// A synergy card: one entry per designed triple.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SynergyCard {
    /// Per-triple synergy findings.
    pub triples: Vec<SynergyTriple>,
    /// `Provisional` if any triple is below the synergy quorum.
    pub trust: TrustTag,
}

/// The three discretized columns of a triple plus the aligned sample count.
type TripleColumns = (Vec<i64>, Vec<i64>, Vec<i64>, usize);

fn aligned_columns(
    triple: &SynergyTripleInput,
    seed: u64,
    cfg: &DiffConfig,
) -> Result<TripleColumns> {
    let n = triple.x.values.len();
    if triple.y.values.len() != n || triple.outcome.values.len() != n {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!(
                "synergy triple ({}, {}, {}) has misaligned lengths {}/{}/{}",
                triple.x.slot,
                triple.y.slot,
                triple.outcome.slot,
                n,
                triple.y.values.len(),
                triple.outcome.values.len()
            ),
            "align x, y and outcome to the same sample set before differentiating",
        ));
    }
    let x = discretize_slot(&triple.x, seed, cfg)?;
    let y = discretize_slot(&triple.y, seed, cfg)?;
    let o = discretize_slot(&triple.outcome, seed, cfg)?;
    Ok((x, y, o, n))
}

/// Measures the interaction information of one triple and classifies it.
pub fn measure_synergy_triple(
    triple: &SynergyTripleInput,
    seed: u64,
    cfg: &DiffConfig,
) -> Result<SynergyTriple> {
    let (x, y, o, n) = aligned_columns(triple, seed, cfg)?;
    if n == 0 {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            "synergy triple carries no samples",
            "supply a non-empty aligned triple",
        ));
    }
    let point = interaction_information_bits(&x, &y, &o);

    // Seeded without-replacement subsample interval. Discrete plug-in II tolerates
    // repeated values, but a without-replacement subsample keeps the resample a
    // genuine subset of the data rather than an inflated duplicate draw.
    let m = ((800u128 * n as u128) / 1000) as usize;
    let m = m.clamp(2.min(n), n.saturating_sub(1).max(1));
    let mut rng = DeterministicRng::from_u64_labeled(seed, "synergy-subsample");
    let mut idx: Vec<usize> = (0..n).collect();
    let mut stats = Vec::with_capacity(cfg.synergy_resamples);
    for _ in 0..cfg.synergy_resamples {
        for i in 0..m {
            let j = i + (rng.next_u64() % (n - i) as u64) as usize;
            idx.swap(i, j);
        }
        let xs: Vec<i64> = idx[..m].iter().map(|&i| x[i]).collect();
        let ys: Vec<i64> = idx[..m].iter().map(|&i| y[i]).collect();
        let os: Vec<i64> = idx[..m].iter().map(|&i| o[i]).collect();
        stats.push(interaction_information_bits(&xs, &ys, &os));
    }
    let (lo, hi) = percentile_interval(&stats, cfg.ci_confidence_permille);
    let interval = BitsInterval {
        lo,
        hi,
        level_permille: cfg.ci_confidence_permille,
        method: "subsample-percentile".to_string(),
    };

    // Classify by where the interval sits relative to a symmetric effect band
    // around zero. Requiring the whole interval to clear ±min_effect (not merely
    // zero) keeps finite-sample plug-in bias — which pushes the interaction
    // information of truly independent variables slightly, confidently negative —
    // from masquerading as synergy.
    let effect = cfg.synergy_min_effect_bits;
    let classification = if hi < -effect {
        SynergyClass::Synergistic
    } else if lo > effect {
        SynergyClass::Redundant
    } else {
        SynergyClass::Unclear
    };
    let promote_cross_term = classification == SynergyClass::Synergistic;
    let trust = if n >= cfg.synergy_quorum {
        TrustTag::Trusted
    } else {
        TrustTag::Provisional
    };

    Ok(SynergyTriple {
        x: triple.x.slot.clone(),
        y: triple.y.slot.clone(),
        outcome: triple.outcome.slot.clone(),
        interaction_information_bits: point,
        interval,
        classification,
        promote_cross_term,
        n,
        trust,
    })
}

/// Measures a synergy card over a list of designed triples.
pub fn measure_synergy(
    triples: &[SynergyTripleInput],
    seed: u64,
    cfg: &DiffConfig,
) -> Result<SynergyCard> {
    let mut out = Vec::with_capacity(triples.len());
    for triple in triples {
        out.push(measure_synergy_triple(triple, seed, cfg)?);
    }
    let trust = if out.iter().all(|t| t.trust == TrustTag::Trusted) && !out.is_empty() {
        TrustTag::Trusted
    } else {
        TrustTag::Provisional
    };
    Ok(SynergyCard {
        triples: out,
        trust,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bits::SlotValues;
    use crate::rng::DeterministicRng;

    fn label(name: &str, values: Vec<i64>) -> SlotObservations {
        SlotObservations {
            slot: name.into(),
            values: SlotValues::Label(values),
        }
    }

    #[test]
    fn xor_pair_is_synergistic_and_promotes_cross_term() {
        // X, Y independent fair bits; outcome = X XOR Y. Neither predicts alone,
        // the pair predicts perfectly: interaction information ≈ −1 bit.
        let cfg = DiffConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(11, "xor");
        let n = 4000;
        let mut x = Vec::with_capacity(n);
        let mut y = Vec::with_capacity(n);
        let mut o = Vec::with_capacity(n);
        for _ in 0..n {
            let xv = (rng.next_u64() & 1) as i64;
            let yv = (rng.next_u64() & 1) as i64;
            x.push(xv);
            y.push(yv);
            o.push(xv ^ yv);
        }
        let triple = SynergyTripleInput {
            x: label("x", x),
            y: label("y", y),
            outcome: label("defect", o),
        };
        let res = measure_synergy_triple(&triple, 1, &cfg).unwrap();
        assert!(
            (res.interaction_information_bits + 1.0).abs() < 0.05,
            "ii={}",
            res.interaction_information_bits
        );
        assert_eq!(res.classification, SynergyClass::Synergistic);
        assert!(res.promote_cross_term);
        // The whole interval is below zero.
        assert!(res.interval.hi < 0.0, "hi={}", res.interval.hi);
        assert_eq!(res.trust, TrustTag::Trusted);
    }

    #[test]
    fn common_cause_triple_is_redundant() {
        // outcome = X = Y (all the same variable): interaction information > 0.
        let cfg = DiffConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(12, "common");
        let base: Vec<i64> = (0..3000).map(|_| (rng.next_u64() % 3) as i64).collect();
        let triple = SynergyTripleInput {
            x: label("x", base.clone()),
            y: label("y", base.clone()),
            outcome: label("z", base.clone()),
        };
        let res = measure_synergy_triple(&triple, 1, &cfg).unwrap();
        assert!(
            res.interaction_information_bits > 0.5,
            "ii={}",
            res.interaction_information_bits
        );
        assert_eq!(res.classification, SynergyClass::Redundant);
        assert!(!res.promote_cross_term);
        assert!(res.interval.lo > 0.0, "lo={}", res.interval.lo);
    }

    #[test]
    fn independent_triple_is_unclear() {
        // X, Y, outcome all mutually independent: interaction information ≈ 0, the
        // interval straddles zero → Unclear (not promoted).
        let cfg = DiffConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(13, "indep");
        let n = 2000;
        let x: Vec<i64> = (0..n).map(|_| (rng.next_u64() & 1) as i64).collect();
        let y: Vec<i64> = (0..n).map(|_| (rng.next_u64() & 1) as i64).collect();
        let o: Vec<i64> = (0..n).map(|_| (rng.next_u64() & 1) as i64).collect();
        let triple = SynergyTripleInput {
            x: label("x", x),
            y: label("y", y),
            outcome: label("o", o),
        };
        let res = measure_synergy_triple(&triple, 1, &cfg).unwrap();
        assert_eq!(res.classification, SynergyClass::Unclear);
        assert!(!res.promote_cross_term);
        // The interaction information sits inside the ±min-effect band (no
        // classifiable signal above finite-sample bias).
        assert!(
            res.interaction_information_bits.abs() < cfg.synergy_min_effect_bits,
            "ii={}",
            res.interaction_information_bits
        );
    }

    #[test]
    fn below_quorum_is_provisional() {
        let cfg = DiffConfig::from_defaults().unwrap();
        // 20 samples < synergy quorum 150.
        let triple = SynergyTripleInput {
            x: label("x", (0..20).map(|i| (i % 2) as i64).collect()),
            y: label("y", (0..20).map(|i| (i / 2 % 2) as i64).collect()),
            outcome: label(
                "o",
                (0..20).map(|i| ((i % 2) ^ (i / 2 % 2)) as i64).collect(),
            ),
        };
        let res = measure_synergy_triple(&triple, 1, &cfg).unwrap();
        assert_eq!(res.trust, TrustTag::Provisional);
    }

    #[test]
    fn misaligned_triple_is_rejected() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let triple = SynergyTripleInput {
            x: label("x", vec![0, 1, 0]),
            y: label("y", vec![0, 1]),
            outcome: label("o", vec![0, 1, 0]),
        };
        let err = measure_synergy_triple(&triple, 1, &cfg).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }

    #[test]
    fn deterministic_under_fixed_seed() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(5, "det");
        let n = 500;
        let x: Vec<i64> = (0..n).map(|_| (rng.next_u64() & 1) as i64).collect();
        let y: Vec<i64> = (0..n).map(|_| (rng.next_u64() & 1) as i64).collect();
        let o: Vec<i64> = x.iter().zip(&y).map(|(a, b)| a ^ b).collect();
        let triple = SynergyTripleInput {
            x: label("x", x),
            y: label("y", y),
            outcome: label("o", o),
        };
        let a = measure_synergy_triple(&triple, 42, &cfg).unwrap();
        let b = measure_synergy_triple(&triple, 42, &cfg).unwrap();
        assert_eq!(a, b);
    }
}
