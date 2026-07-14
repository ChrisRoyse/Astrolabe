//! Multivariate discrete information-theoretic estimators shared by the P5.3
//! differentiation cards (redundancy, synergy, transfer entropy).
//!
//! Everything here is **base-2** (bits) plug-in estimation over aligned integer
//! columns: a column is a per-sample discrete label (a categorical lens, a binary
//! event, or a continuous value already reduced to an equal-frequency bin index by
//! [`quantile_bins`]). The estimators are pure, deterministic functions of their
//! input arrays — no randomness, no threading — so a given sample always yields
//! the same value regardless of worker count.
//!
//! The quantities layered on top of the plug-in entropy are exactly the ones the
//! blueprint's differentiation layer names (08_ASSAY §3–4, §6, and
//! `BUILDING_ON_CALYX` §4):
//!
//! * [`joint_entropy_bits`] — `H(X₁,…,X_m)` over the observed tuples.
//! * [`conditional_mi_bits`] — `I(X;Y|Z)` via the four-entropy decomposition.
//! * [`interaction_information_bits`] — three-way co-information; its sign
//!   classifies redundant (positive) vs synergistic (negative).
//! * [`transfer_entropy_bits`] — `T(A→B) = I(B_future; A_past | B_past)`.
//! * [`normalized_mi_bits`] — `I(A;B)/√(H(A)·H(B))` in `[0,1]` for the agreement
//!   graph and the redundancy retire gate.

use std::collections::HashMap;

use crate::estimators::entropy_bits;

/// Equal-frequency (quantile) bin indices for a continuous vector, in `0..bins`.
///
/// Ranks are assigned by a stable sort (ties keep input order), then mapped to
/// bins by rank so the binning is deterministic and each bin holds as close to an
/// equal share of the sample as ties allow. An empty input yields an empty vector;
/// `bins` is treated as at least one.
pub fn quantile_bins(values: &[f64], bins: usize) -> Vec<i64> {
    let n = values.len();
    let bins = bins.max(1);
    if n == 0 {
        return Vec::new();
    }
    let mut idx: Vec<usize> = (0..n).collect();
    idx.sort_by(|&a, &b| {
        values[a]
            .partial_cmp(&values[b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut out = vec![0i64; n];
    for (rank, &i) in idx.iter().enumerate() {
        out[i] = ((rank * bins) / n).min(bins - 1) as i64;
    }
    out
}

/// Joint entropy `H(X₁,…,X_m)` of several aligned discrete columns, in bits.
///
/// The plug-in estimate over the observed distinct tuples: `-Σ p·log2 p` where `p`
/// is the empirical frequency of each distinct row-tuple. Zero columns or zero
/// rows carry zero entropy. Columns of unequal length are truncated to the
/// shortest, so a caller that aligns its inputs gets the exact joint entropy.
pub fn joint_entropy_bits(columns: &[&[i64]]) -> f64 {
    if columns.is_empty() {
        return 0.0;
    }
    let n = columns.iter().map(|c| c.len()).min().unwrap_or(0);
    if n == 0 {
        return 0.0;
    }
    let mut counts: HashMap<Vec<i64>, usize> = HashMap::new();
    for i in 0..n {
        let tuple: Vec<i64> = columns.iter().map(|c| c[i]).collect();
        *counts.entry(tuple).or_insert(0) += 1;
    }
    // Deterministic summation order: `HashMap` iteration order is per-instance
    // random and floating-point addition is not associative, so summing the tuple
    // frequencies in an unordered pass would differ in the last ULP between two
    // identical calls and break bit-exact reproducibility (invariant 5).
    let mut freqs: Vec<usize> = counts.into_values().collect();
    freqs.sort_unstable();
    let n_f = n as f64;
    let mut h = 0.0;
    for c in freqs {
        let p = c as f64 / n_f;
        h -= p * p.log2();
    }
    h.max(0.0)
}

/// Conditional mutual information `I(X;Y|Z)` in bits, over aligned discrete
/// columns.
///
/// Uses the entropy decomposition
/// `I(X;Y|Z) = H(X,Z) + H(Y,Z) − H(X,Y,Z) − H(Z)`, which is non-negative in the
/// population and clamped at zero here to absorb plug-in noise.
pub fn conditional_mi_bits(x: &[i64], y: &[i64], z: &[i64]) -> f64 {
    let h_xz = joint_entropy_bits(&[x, z]);
    let h_yz = joint_entropy_bits(&[y, z]);
    let h_xyz = joint_entropy_bits(&[x, y, z]);
    let h_z = entropy_bits(z);
    (h_xz + h_yz - h_xyz - h_z).max(0.0)
}

/// Three-way interaction information (co-information) `I(X;Y;Z)` in bits.
///
/// `I(X;Y;Z) = H(X)+H(Y)+H(Z) − H(X,Y) − H(X,Z) − H(Y,Z) + H(X,Y,Z)`, equal to
/// `I(X;Y) − I(X;Y|Z)`. The sign is the classifier the synergy card reads:
/// **positive** means the third variable is explained redundantly by the pair,
/// **negative** means the pair is *synergistic* about the third (the XOR case is
/// exactly `−1` bit). This value is not clamped — its sign is load-bearing.
pub fn interaction_information_bits(x: &[i64], y: &[i64], z: &[i64]) -> f64 {
    let h_x = entropy_bits(x);
    let h_y = entropy_bits(y);
    let h_z = entropy_bits(z);
    let h_xy = joint_entropy_bits(&[x, y]);
    let h_xz = joint_entropy_bits(&[x, z]);
    let h_yz = joint_entropy_bits(&[y, z]);
    let h_xyz = joint_entropy_bits(&[x, y, z]);
    h_x + h_y + h_z - h_xy - h_xz - h_yz + h_xyz
}

/// Transfer entropy `T(source→target)` at `lag`, in bits.
///
/// `T(A→B) = I(B_t; A_{t−lag} | B_{t−lag})`, the reduction in uncertainty about
/// `B`'s present that `A`'s lagged past adds over `B`'s own lagged past. Built from
/// the three aligned windows `B_future = B[lag..]`, `B_past = B[..n−lag]`,
/// `A_past = A[..n−lag]` and evaluated through [`conditional_mi_bits`]. Returns
/// `0.0` when `lag == 0` or the series is too short to form a lagged window.
pub fn transfer_entropy_bits(source: &[i64], target: &[i64], lag: usize) -> f64 {
    let n = source.len().min(target.len());
    if lag == 0 || n <= lag {
        return 0.0;
    }
    let b_future = &target[lag..n];
    let b_past = &target[..n - lag];
    let a_past = &source[..n - lag];
    conditional_mi_bits(b_future, a_past, b_past)
}

/// Normalized mutual information `I(A;B)/√(H(A)·H(B))` in `[0,1]`.
///
/// The symmetric-uncertainty-style normalization used for the agreement graph and
/// the redundancy retire gate: identical non-constant columns give `1.0`; a
/// constant column shares no information, so any pair involving one gives `0.0`.
pub fn normalized_mi_bits(a: &[i64], b: &[i64]) -> f64 {
    let h_a = entropy_bits(a);
    let h_b = entropy_bits(b);
    if h_a <= 0.0 || h_b <= 0.0 {
        return 0.0;
    }
    let h_ab = joint_entropy_bits(&[a, b]);
    let mi = (h_a + h_b - h_ab).max(0.0);
    (mi / (h_a * h_b).sqrt()).clamp(0.0, 1.0)
}

/// Linear-interpolated quantile of an already-sorted, finite slice.
///
/// Returns `0.0` for an empty slice and the sole element for a singleton; `q` is
/// clamped to `[0,1]`.
pub fn quantile_sorted(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let pos = q.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    let frac = pos - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

/// Two-sided percentile endpoints of `values` at a permille level (950 = 95%).
///
/// Sorts a copy and returns `(lo, hi)` at the `α/2` and `1−α/2` quantiles. An
/// empty input yields `(0, 0)`.
pub fn percentile_interval(values: &[f64], level_permille: u64) -> (f64, f64) {
    let mut sorted: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let alpha = 1.0 - level_permille as f64 / 1000.0;
    (
        quantile_sorted(&sorted, alpha / 2.0),
        quantile_sorted(&sorted, 1.0 - alpha / 2.0),
    )
}

/// Maps arbitrary integer labels to compact `0..classes` indices, returning the
/// remapped vector and the class count. Deterministic in first-appearance order.
pub fn compact_labels(labels: &[i64]) -> (Vec<i64>, usize) {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<i64, i64> = BTreeMap::new();
    let mut next = 0i64;
    let mut out = Vec::with_capacity(labels.len());
    for &l in labels {
        let id = *map.entry(l).or_insert_with(|| {
            let id = next;
            next += 1;
            id
        });
        out.push(id);
    }
    (out, next as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joint_entropy_of_two_independent_fair_bits_is_two() {
        // (i%2, i%3) over a full period are independent → H = 1 + log2(3)? no:
        // use genuinely independent fair bits so the joint entropy is 2 bits.
        let a: Vec<i64> = (0..1000).map(|i| (i % 2) as i64).collect();
        let b: Vec<i64> = (0..1000).map(|i| ((i / 2) % 2) as i64).collect();
        let h = joint_entropy_bits(&[&a, &b]);
        assert!((h - 2.0).abs() < 1e-9, "h={h}");
    }

    #[test]
    fn joint_entropy_of_duplicate_column_equals_marginal() {
        let a: Vec<i64> = (0..600).map(|i| (i % 3) as i64).collect();
        let single = entropy_bits(&a);
        let joint = joint_entropy_bits(&[&a, &a]);
        assert!(
            (single - joint).abs() < 1e-9,
            "single={single} joint={joint}"
        );
    }

    #[test]
    fn interaction_information_of_xor_is_minus_one_bit() {
        // X, Y independent fair bits; Z = X XOR Y. Co-information = -1 bit (synergy).
        let n = 4000;
        let mut x = Vec::with_capacity(n);
        let mut y = Vec::with_capacity(n);
        let mut z = Vec::with_capacity(n);
        for i in 0..n {
            let xv = (i % 2) as i64;
            let yv = ((i / 2) % 2) as i64;
            x.push(xv);
            y.push(yv);
            z.push(xv ^ yv);
        }
        let ii = interaction_information_bits(&x, &y, &z);
        assert!((ii + 1.0).abs() < 1e-9, "ii={ii}");
    }

    #[test]
    fn interaction_information_of_common_cause_is_positive() {
        // Z drives both X and Y (X=Y=Z): redundant, co-information = +H(Z) > 0.
        let z: Vec<i64> = (0..600).map(|i| (i % 3) as i64).collect();
        let ii = interaction_information_bits(&z, &z, &z);
        assert!(ii > 0.5, "ii={ii}");
    }

    #[test]
    fn transfer_entropy_of_lagged_copy_is_directional() {
        // B[t] = A[t-1]; A iid fair bits. T(A→B) at lag 1 ≈ 1 bit; T(B→A) ≈ 0.
        let n = 4000;
        let mut a = Vec::with_capacity(n);
        let mut seed = 0x9E3779B97F4A7C15u64;
        for _ in 0..n {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            a.push((seed & 1) as i64);
        }
        let mut b = vec![0i64; n];
        b[1..n].copy_from_slice(&a[..n - 1]);
        let te_ab = transfer_entropy_bits(&a, &b, 1);
        let te_ba = transfer_entropy_bits(&b, &a, 1);
        assert!(te_ab > 0.8, "te_ab={te_ab}");
        assert!(te_ba < 0.15, "te_ba={te_ba}");
    }

    #[test]
    fn normalized_mi_of_identical_is_one_and_constant_is_zero() {
        let a: Vec<i64> = (0..600).map(|i| (i % 4) as i64).collect();
        assert!((normalized_mi_bits(&a, &a) - 1.0).abs() < 1e-9);
        let c = vec![7i64; 600];
        assert_eq!(normalized_mi_bits(&a, &c), 0.0);
    }

    #[test]
    fn quantile_bins_are_balanced() {
        let values: Vec<f64> = (0..100).map(|i| i as f64).collect();
        let bins = quantile_bins(&values, 4);
        for b in 0..4 {
            let count = bins.iter().filter(|&&x| x == b as i64).count();
            assert_eq!(count, 25, "bin {b} count");
        }
    }
}
