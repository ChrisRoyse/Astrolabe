//! MMD two-sample drift per slot (08_ASSAY §6, capability 4.11).
//!
//! The maximum mean discrepancy (MMD) is a kernel two-sample test: it measures how
//! far apart two samples are in the reproducing-kernel Hilbert space of an RBF
//! kernel, and its permutation p-value says whether that distance is more than
//! label noise. Per slot, the reference corpus is compared against the new symbols;
//! a small p-value is a **drift alarm** that feeds guard recalibration (10 §6).
//!
//! The kernel bandwidth is the **median heuristic** — the median pairwise distance
//! of the pooled sample, a measured value rather than a fixed constant (Gretton et
//! al. 2012, §5). Because the pooled point set is invariant under label
//! permutation, the Gram matrix and bandwidth are computed once and every
//! permutation is a cheap re-partition, keeping the seeded null a pure function of
//! `(inputs, seed, config)`.

use astrolabe_domain::TrustTag;
use serde::{Deserialize, Serialize};

use crate::diff::DiffConfig;
use crate::error::{ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, AssayError, Result};
use crate::multivariate::quantile_sorted;
use crate::rng::DeterministicRng;

/// A drift card comparing a reference sample against a new sample for one slot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriftCard {
    /// Slot name.
    pub slot: String,
    /// Unbiased MMD² statistic.
    pub mmd_squared: f64,
    /// Permutation p-value, in permille.
    pub p_value_permille: u64,
    /// Whether the drift cleared the significance level (an alarm).
    pub drift_detected: bool,
    /// RBF bandwidth from the median heuristic (a measured value).
    pub bandwidth: f64,
    /// Reference sample size.
    pub n_reference: usize,
    /// New sample size.
    pub n_sample: usize,
    /// `Trusted` when both samples clear the redundancy quorum, else `Provisional`.
    pub trust: TrustTag,
}

/// Squared Euclidean distance between two equal-length points.
fn sq_dist(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y) * (x - y)).sum()
}

/// Unbiased MMD² given the pooled Gram matrix `k` (size `n×n`, row-major) and the
/// index partition `a` (first sample) / `b` (second sample).
fn mmd_squared_from_gram(k: &[f64], n: usize, a: &[usize], b: &[usize]) -> f64 {
    let m = a.len();
    let l = b.len();
    let mut sum_aa = 0.0;
    for &i in a {
        for &j in a {
            if i != j {
                sum_aa += k[i * n + j];
            }
        }
    }
    let mut sum_bb = 0.0;
    for &i in b {
        for &j in b {
            if i != j {
                sum_bb += k[i * n + j];
            }
        }
    }
    let mut sum_ab = 0.0;
    for &i in a {
        for &j in b {
            sum_ab += k[i * n + j];
        }
    }
    sum_aa / (m * (m - 1)) as f64 + sum_bb / (l * (l - 1)) as f64 - 2.0 * sum_ab / (m * l) as f64
}

/// Measures the drift card for a slot's reference vs new sample.
///
/// Each sample is a set of equal-dimension points (a scalar slot is a set of
/// 1-vectors). Fails closed on fewer than two points per side, a dimension
/// mismatch, or a non-finite value.
pub fn measure_drift(
    slot_name: impl Into<String>,
    reference: &[Vec<f64>],
    sample: &[Vec<f64>],
    seed: u64,
    cfg: &DiffConfig,
) -> Result<DriftCard> {
    let slot = slot_name.into();
    if reference.len() < 2 || sample.len() < 2 {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!(
                "drift needs at least two points per side, got {}/{}",
                reference.len(),
                sample.len()
            ),
            "supply at least two points in each of the reference and new samples",
        ));
    }
    let dim = reference[0].len();
    if dim == 0 {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            "drift points have zero dimension",
            "supply points of at least one dimension",
        ));
    }
    for point in reference.iter().chain(sample.iter()) {
        if point.len() != dim {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!(
                    "drift point has width {} but the slot dim is {dim}",
                    point.len()
                ),
                "give every reference and new point the same dimension",
            ));
        }
        if point.iter().any(|v| !v.is_finite()) {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                "drift sample carries a non-finite value",
                "supply only finite measured values",
            ));
        }
    }

    // Pool the two samples; the first `m` indices are the reference.
    let m = reference.len();
    let l = sample.len();
    let n = m + l;
    let mut pooled: Vec<&[f64]> = Vec::with_capacity(n);
    pooled.extend(reference.iter().map(|v| v.as_slice()));
    pooled.extend(sample.iter().map(|v| v.as_slice()));

    // Median-heuristic bandwidth from pooled pairwise distances.
    let mut dists = Vec::with_capacity(n * (n - 1) / 2);
    let mut sq = vec![0.0_f64; n * n];
    for i in 0..n {
        for j in (i + 1)..n {
            let d2 = sq_dist(pooled[i], pooled[j]);
            sq[i * n + j] = d2;
            sq[j * n + i] = d2;
            dists.push(d2.sqrt());
        }
    }
    dists.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = quantile_sorted(&dists, 0.5);
    // Degenerate pool (all identical): no measurable discrepancy.
    if median <= 0.0 {
        return Ok(DriftCard {
            slot,
            mmd_squared: 0.0,
            p_value_permille: 1000,
            drift_detected: false,
            bandwidth: 0.0,
            n_reference: m,
            n_sample: l,
            trust: trust_of(m, l, cfg),
        });
    }
    let bandwidth = median;
    let gamma = 1.0 / (2.0 * bandwidth * bandwidth);

    // Gram matrix K_ij = exp(-γ ||i-j||²); diagonal is 1 but never used (i≠j).
    let mut k = vec![0.0_f64; n * n];
    for i in 0..n {
        for j in 0..n {
            k[i * n + j] = (-gamma * sq[i * n + j]).exp();
        }
    }

    let a: Vec<usize> = (0..m).collect();
    let b: Vec<usize> = (m..n).collect();
    let observed = mmd_squared_from_gram(&k, n, &a, &b);

    // Permutation null: re-partition the pooled indices into sizes m and l.
    let mut rng = DeterministicRng::from_u64_labeled(seed, "mmd-perm");
    let mut idx: Vec<usize> = (0..n).collect();
    let mut ge = 0usize;
    for _ in 0..cfg.mmd_permutations {
        for i in (1..n).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            idx.swap(i, j);
        }
        let stat = mmd_squared_from_gram(&k, n, &idx[..m], &idx[m..]);
        if stat >= observed {
            ge += 1;
        }
    }
    let num = (1 + ge) as u128 * 1000;
    let den = (1 + cfg.mmd_permutations) as u128;
    let p_value_permille = num.div_ceil(den) as u64;
    let p_gate_permille = (1000.0 * (1.0 - cfg.significance)).round() as u64;
    let drift_detected = p_value_permille <= p_gate_permille;

    Ok(DriftCard {
        slot,
        mmd_squared: observed,
        p_value_permille,
        drift_detected,
        bandwidth,
        n_reference: m,
        n_sample: l,
        trust: trust_of(m, l, cfg),
    })
}

fn trust_of(m: usize, l: usize, cfg: &DiffConfig) -> TrustTag {
    if m >= cfg.redundancy_quorum && l >= cfg.redundancy_quorum {
        TrustTag::Trusted
    } else {
        TrustTag::Provisional
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalars(rng: &mut DeterministicRng, n: usize, mean: f64) -> Vec<Vec<f64>> {
        (0..n)
            .map(|_| vec![mean + rng.next_standard_normal()])
            .collect()
    }

    #[test]
    fn planted_distribution_shift_is_flagged() {
        // Reference N(0,1) vs new N(3,1): a clear mean shift → drift alarm.
        let cfg = DiffConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(1, "shift");
        let reference = scalars(&mut rng, 80, 0.0);
        let sample = scalars(&mut rng, 80, 3.0);
        let card = measure_drift("embedding", &reference, &sample, 5, &cfg).unwrap();
        assert!(card.drift_detected, "p={}", card.p_value_permille);
        assert!(card.mmd_squared > 0.1, "mmd²={}", card.mmd_squared);
        assert!(card.bandwidth > 0.0);
        assert_eq!(card.trust, TrustTag::Trusted);
    }

    #[test]
    fn identical_distributions_hold_the_false_positive_rate() {
        // Repeated trials: reference and new drawn from the SAME N(0,1). The
        // fraction of trials that raise a (false) alarm must stay near the 0.05
        // level the significance knob calibrates.
        let cfg = DiffConfig::from_defaults().unwrap();
        let trials = 40;
        let mut alarms = 0;
        for t in 0..trials {
            let mut rng = DeterministicRng::from_u64_labeled(1000 + t, "null");
            let reference = scalars(&mut rng, 50, 0.0);
            let sample = scalars(&mut rng, 50, 0.0);
            let card = measure_drift("s", &reference, &sample, t, &cfg).unwrap();
            if card.drift_detected {
                alarms += 1;
            }
        }
        let fpr = alarms as f64 / trials as f64;
        // Level is 0.05; allow generous slack for 40 trials of Monte-Carlo noise.
        assert!(
            fpr < 0.2,
            "false-positive rate {fpr} too high ({alarms}/{trials})"
        );
    }

    #[test]
    fn constant_pool_reports_no_drift() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let reference = vec![vec![2.0]; 10];
        let sample = vec![vec![2.0]; 10];
        let card = measure_drift("flat", &reference, &sample, 1, &cfg).unwrap();
        assert!(!card.drift_detected);
        assert_eq!(card.mmd_squared, 0.0);
        assert_eq!(card.bandwidth, 0.0);
    }

    #[test]
    fn too_few_points_rejected() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let err = measure_drift("s", &[vec![1.0]], &[vec![2.0], vec![3.0]], 1, &cfg).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }

    #[test]
    fn dimension_mismatch_rejected() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let reference = vec![vec![1.0, 2.0], vec![3.0, 4.0]];
        let sample = vec![vec![1.0], vec![2.0]];
        let err = measure_drift("s", &reference, &sample, 1, &cfg).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }

    #[test]
    fn deterministic_under_fixed_seed() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(2, "det");
        let reference = scalars(&mut rng, 30, 0.0);
        let sample = scalars(&mut rng, 30, 1.0);
        let a = measure_drift("s", &reference, &sample, 9, &cfg).unwrap();
        let b = measure_drift("s", &reference, &sample, 9, &cfg).unwrap();
        assert_eq!(a, b);
    }
}
