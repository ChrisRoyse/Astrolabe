//! Categorical association — how strongly a discrete label (market category,
//! region, resolution source) is associated with a discrete outcome, and in
//! which direction (#65).
//!
//! From one contingency table this reports the full family:
//! - **Pearson χ²** `Σ (O−E)²/E` and the **likelihood-ratio G-test**
//!   `2·Σ O·ln(O/E)`, both on `(r−1)(c−1)` degrees of freedom, with p-values
//!   from the χ² survival function (the regularised upper incomplete gamma in
//!   [`special_fn`](crate::special_fn) — no external stats crate).
//! - **φ (mean-square contingency)** `√(χ²/N)` and **Cramér's V**
//!   `√(χ²/(N·min(r−1,c−1)))` — symmetric effect sizes in `[0,1]` (φ = V for a
//!   2×2 table).
//! - **Theil's U (uncertainty coefficient)**, the *directional* member:
//!   `U(Y|X) = I(X;Y)/H(Y)` is the fraction of the outcome's entropy explained
//!   by the label, and `U(X|Y) = I(X;Y)/H(X)` the reverse. `U(Y|X) ≠ U(X|Y)` in
//!   general, so it distinguishes "the source pins the outcome" from "the
//!   outcome pins the source" — the categorical analogue of Granger direction.
//! - **Mutual information** `I(X;Y)` in bits, the common core of Theil's U.
//!
//! [`point_biserial`] handles the mixed continuous-vs-binary case (a slot score
//! against a Pass/Fail anchor): it is exactly the Pearson correlation of the
//! score with the 0/1 indicator, with the same exact-t inference.
//!
//! Everything fails closed: length mismatch, an empty sample, or a constant
//! (single-category) column — for which association is undefined — returns a
//! structured `CalyxError`, never a silent `NaN`.

use std::collections::BTreeMap;

use calyx_core::{CalyxError, Result};
use serde::{Deserialize, Serialize};

use crate::partial_correlation::{PearsonReport, pearson};
use crate::special_fn::gammq;

/// Minimum paired observations for a defined categorical association test.
pub const MIN_CATEGORICAL_SAMPLES: usize = 4;

/// Full categorical-association report from a single contingency table.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct CategoricalReport {
    pub chi_square: f32,
    pub g_statistic: f32,
    /// Degrees of freedom `(r−1)(c−1)`.
    pub dof: usize,
    /// χ² survival p-value on `dof`.
    pub chi_square_p: f32,
    /// G-test survival p-value on `dof` (same asymptotic χ² reference).
    pub g_p: f32,
    /// φ = √(χ²/N) — the mean-square contingency coefficient.
    pub phi: f32,
    /// Cramér's V = √(χ²/(N·min(r−1,c−1))).
    pub cramers_v: f32,
    /// Theil's U(Y|X): fraction of the outcome (`y`) entropy explained by `x`.
    pub theil_u_y_given_x: f32,
    /// Theil's U(X|Y): fraction of the `x` entropy explained by `y`.
    pub theil_u_x_given_y: f32,
    /// Mutual information I(X;Y) in bits.
    pub mutual_information_bits: f32,
    pub n_rows: usize,
    pub n_cols: usize,
    pub n_samples: usize,
}

/// Categorical association between two discrete label series `x` and `y`.
pub fn categorical_association(x: &[u32], y: &[u32]) -> Result<CategoricalReport> {
    if x.len() != y.len() {
        return Err(CalyxError::assay_insufficient_samples(format!(
            "categorical association requires paired labels: x={} y={}",
            x.len(),
            y.len()
        )));
    }
    let n = x.len();
    if n < MIN_CATEGORICAL_SAMPLES {
        return Err(CalyxError::assay_insufficient_samples(format!(
            "categorical association requires at least {MIN_CATEGORICAL_SAMPLES} samples; got {n}"
        )));
    }

    // Dense contingency table over the observed category codes.
    let x_levels = index_levels(x);
    let y_levels = index_levels(y);
    let r = x_levels.len();
    let c = y_levels.len();
    if r < 2 || c < 2 {
        return Err(CalyxError::assay_degenerate_input(format!(
            "categorical association undefined: a variable has a single category (r={r}, c={c})"
        )));
    }
    let mut table = vec![0u64; r * c];
    for (&xi, &yi) in x.iter().zip(y) {
        let ri = x_levels[&xi];
        let ci = y_levels[&yi];
        table[ri * c + ci] += 1;
    }

    let nf = n as f64;
    let row_sums: Vec<f64> = (0..r)
        .map(|i| (0..c).map(|j| table[i * c + j] as f64).sum())
        .collect();
    let col_sums: Vec<f64> = (0..c)
        .map(|j| (0..r).map(|i| table[i * c + j] as f64).sum())
        .collect();

    // χ² and G statistics.
    let mut chi_square = 0.0f64;
    let mut g_statistic = 0.0f64;
    for i in 0..r {
        for j in 0..c {
            let o = table[i * c + j] as f64;
            let e = row_sums[i] * col_sums[j] / nf; // > 0: margins are all > 0
            let d = o - e;
            chi_square += d * d / e;
            if o > 0.0 {
                g_statistic += 2.0 * o * (o / e).ln();
            }
        }
    }
    let dof = (r - 1) * (c - 1);
    let half_dof = dof as f64 / 2.0;
    let chi_square_p = gammq(half_dof, chi_square / 2.0)?;
    let g_p = gammq(half_dof, g_statistic.max(0.0) / 2.0)?;

    // φ and Cramér's V.
    let phi = (chi_square / nf).sqrt();
    let k = (r.min(c) - 1) as f64;
    let cramers_v = (chi_square / (nf * k)).sqrt().clamp(0.0, 1.0);

    // Entropies (bits) and mutual information for Theil's U.
    let h_x = entropy_bits(&row_sums, nf);
    let h_y = entropy_bits(&col_sums, nf);
    let mut h_joint = 0.0f64;
    for &cell in &table {
        if cell > 0 {
            let p = cell as f64 / nf;
            h_joint -= p * p.log2();
        }
    }
    // I(X;Y) = H(X) + H(Y) − H(X,Y) ≥ 0; clamp float noise.
    let mi = (h_x + h_y - h_joint).max(0.0);
    let theil_u_y_given_x = if h_y > 0.0 {
        (mi / h_y).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let theil_u_x_given_y = if h_x > 0.0 {
        (mi / h_x).clamp(0.0, 1.0)
    } else {
        0.0
    };

    Ok(CategoricalReport {
        chi_square: chi_square as f32,
        g_statistic: g_statistic.max(0.0) as f32,
        dof,
        chi_square_p: chi_square_p as f32,
        g_p: g_p as f32,
        phi: phi as f32,
        cramers_v: cramers_v as f32,
        theil_u_y_given_x: theil_u_y_given_x as f32,
        theil_u_x_given_y: theil_u_x_given_y as f32,
        mutual_information_bits: mi as f32,
        n_rows: r,
        n_cols: c,
        n_samples: n,
    })
}

/// Point-biserial correlation of a continuous `score` against a `binary`
/// (0/1) label — e.g. a slot score against a Pass/Fail anchor. This is exactly
/// the Pearson correlation of `score` with the indicator, carrying the same
/// exact-t significance and Fisher-z CI. Fails closed if `binary` is not all in
/// `{0, 1}` or if either class is absent (a constant indicator).
pub fn point_biserial(score: &[f32], binary: &[u32]) -> Result<PearsonReport> {
    if score.len() != binary.len() {
        return Err(CalyxError::assay_insufficient_samples(format!(
            "point-biserial requires paired samples: score={} binary={}",
            score.len(),
            binary.len()
        )));
    }
    let mut indicator = Vec::with_capacity(binary.len());
    let mut ones = 0usize;
    for (idx, &b) in binary.iter().enumerate() {
        match b {
            0 => indicator.push(0.0f32),
            1 => {
                indicator.push(1.0f32);
                ones += 1;
            }
            other => {
                return Err(CalyxError::assay_insufficient_samples(format!(
                    "point-biserial requires a binary label in {{0,1}}; binary[{idx}] = {other}"
                )));
            }
        }
    }
    if ones == 0 || ones == binary.len() {
        return Err(CalyxError::assay_degenerate_input(
            "point-biserial undefined: the binary label is constant (only one class present)",
        ));
    }
    // Pearson of the score against the 0/1 indicator == point-biserial r.
    pearson(score, &indicator)
}

// ----- numerics --------------------------------------------------------------

/// Map the observed category codes to dense contiguous indices (sorted order for
/// determinism). Returns a code→index table.
fn index_levels(labels: &[u32]) -> BTreeMap<u32, usize> {
    let mut levels: BTreeMap<u32, usize> = BTreeMap::new();
    for &l in labels {
        let next = levels.len();
        levels.entry(l).or_insert(next);
    }
    // `entry` inserted in first-seen order; re-index in sorted-key order so the
    // table layout is deterministic regardless of input ordering.
    for (i, (_k, v)) in levels.iter_mut().enumerate() {
        *v = i;
    }
    levels
}

/// Shannon entropy (bits) of a category-count vector with total `n`.
fn entropy_bits(counts: &[f64], n: f64) -> f64 {
    let mut h = 0.0f64;
    for &cnt in counts {
        if cnt > 0.0 {
            let p = cnt / n;
            h -= p * p.log2();
        }
    }
    h
}
