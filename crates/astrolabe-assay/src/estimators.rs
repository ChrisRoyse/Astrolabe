//! KSG k-nearest-neighbour mutual-information estimators and the plug-in
//! information quantities the assay cards are built from.
//!
//! Everything here is **base-2** (bits) at the boundary: the k-NN estimators are
//! naturally derived in nats and converted once, at the end, by dividing by
//! `ln 2`. The estimators are pure, deterministic functions of their input
//! arrays — no randomness, no threading — so a given sample always yields the
//! same point estimate regardless of worker count.
//!
//! Three routes cover the measurement matrix (08 §1):
//!
//! * [`mi_continuous_ksg`] — continuous↔continuous, the Kraskov–Stögbauer–
//!   Grassberger (2004) algorithm 1 with the Chebyshev (max) norm. This is the
//!   route for scalar-vs-scalar and (projected) embedding-vs-scalar.
//! * [`mi_mixed_ross`] — continuous↔discrete, the Ross (2014) estimator for a
//!   continuous variable against a discrete label. This is the route for a slot
//!   against a discrete outcome axis and (via role-swap) for a label slot against
//!   a continuous axis.
//! * [`mi_discrete`] / [`entropy_bits`] — the plug-in discrete quantities for
//!   label-vs-label mutual information and for the outcome axis entropy `H(axis)`
//!   the sufficiency check compares the panel against.

/// Natural-log-to-base-2 conversion factor: `1 / ln 2`.
pub const NATS_TO_BITS: f64 = std::f64::consts::LOG2_E;

/// The digamma function ψ(x) for `x > 0`.
///
/// Uses the standard recurrence to push the argument above 6, then the
/// asymptotic Bernoulli series. Accurate to well under `1e-8` across the range
/// the estimators use (small positive integers and their neighbourhoods), which
/// is far tighter than the sampling noise of any k-NN estimate.
pub fn digamma(mut x: f64) -> f64 {
    debug_assert!(x > 0.0, "digamma domain is x > 0");
    let mut result = 0.0;
    // Recurrence ψ(x) = ψ(x+1) - 1/x lifts x into the asymptotic regime.
    while x < 6.0 {
        result -= 1.0 / x;
        x += 1.0;
    }
    let inv = 1.0 / x;
    let inv2 = inv * inv;
    // Asymptotic expansion: ψ(x) ≈ ln x - 1/(2x) - Σ B_2n/(2n x^2n).
    result + x.ln()
        - 0.5 * inv
        - inv2 * (1.0 / 12.0 - inv2 * (1.0 / 120.0 - inv2 * (1.0 / 252.0 - inv2 * (1.0 / 240.0))))
}

/// Chebyshev (max-coordinate) distance between two equal-length points.
fn chebyshev(a: &[f64], b: &[f64]) -> f64 {
    debug_assert_eq!(a.len(), b.len());
    let mut max = 0.0_f64;
    for (x, y) in a.iter().zip(b.iter()) {
        let d = (x - y).abs();
        if d > max {
            max = d;
        }
    }
    max
}

/// Continuous↔continuous mutual information in **bits** via the KSG (2004)
/// algorithm 1 with the Chebyshev norm and `k` neighbours.
///
/// `x` and `y` are row-aligned: `x[i]` and `y[i]` are the two observations of
/// sample `i`. Each may be multi-dimensional (e.g. a projected embedding on one
/// side, a scalar on the other). The estimate is clamped at zero because MI is
/// non-negative and the estimator's variance can push a true-zero estimate very
/// slightly negative.
///
/// Returns `0.0` when there are fewer than `k + 1` samples (too few to form a
/// k-th neighbour) — a caller that needs a labelled refusal for tiny `n` gets it
/// from the floor path, not here.
pub fn mi_continuous_ksg(x: &[Vec<f64>], y: &[Vec<f64>], k: usize) -> f64 {
    let n = x.len();
    debug_assert_eq!(n, y.len());
    if k == 0 || n < k + 1 {
        return 0.0;
    }
    // Joint point i is the concatenation (x[i], y[i]); its Chebyshev distance to
    // point j is the max of the x-block and y-block Chebyshev distances.
    let mut sum = 0.0;
    let mut dist_x = vec![0.0_f64; n];
    let mut dist_y = vec![0.0_f64; n];
    for i in 0..n {
        for j in 0..n {
            dist_x[j] = chebyshev(&x[i], &x[j]);
            dist_y[j] = chebyshev(&y[i], &y[j]);
        }
        // eps_i = distance to the k-th nearest neighbour in joint (max) space,
        // excluding the point itself.
        let mut joint: Vec<f64> = (0..n)
            .filter(|&j| j != i)
            .map(|j| dist_x[j].max(dist_y[j]))
            .collect();
        joint.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let eps = joint[k - 1];
        // Count neighbours strictly inside eps in each marginal (KSG algorithm 1).
        let mut nx = 0usize;
        let mut ny = 0usize;
        for j in 0..n {
            if j == i {
                continue;
            }
            if dist_x[j] < eps {
                nx += 1;
            }
            if dist_y[j] < eps {
                ny += 1;
            }
        }
        sum += digamma((nx + 1) as f64) + digamma((ny + 1) as f64);
    }
    // I = ψ(k) + ψ(N) - <ψ(nx+1) + ψ(ny+1)>   (nats)
    let mi_nats = digamma(k as f64) + digamma(n as f64) - sum / n as f64;
    (mi_nats * NATS_TO_BITS).max(0.0)
}

/// Continuous↔discrete mutual information in **bits** via the Ross (2014)
/// estimator with `k` neighbours.
///
/// `cont[i]` is the (possibly multi-dimensional) continuous observation of
/// sample `i` and `labels[i]` its discrete class. For each point the estimator
/// finds its k-th nearest same-class neighbour at distance `d`, counts how many
/// points of *any* class lie within `d`, and combines the digamma terms. When a
/// class has `<= k` members the per-point neighbour count is capped to that
/// class's size minus one (Ross's small-class rule), so a rare class never
/// crashes the estimate. Clamped at zero for the same reason as the continuous
/// route.
pub fn mi_mixed_ross(cont: &[Vec<f64>], labels: &[i64], k: usize) -> f64 {
    let n = cont.len();
    debug_assert_eq!(n, labels.len());
    if k == 0 || n < 2 {
        return 0.0;
    }
    // Per-class membership counts.
    use std::collections::HashMap;
    let mut class_size: HashMap<i64, usize> = HashMap::new();
    for &l in labels {
        *class_size.entry(l).or_insert(0) += 1;
    }
    let mut acc = 0.0;
    let mut dist = vec![0.0_f64; n];
    for i in 0..n {
        let label = labels[i];
        let nx = *class_size.get(&label).unwrap();
        // A singleton class carries no within-class neighbour; contributes nothing
        // measurable and is skipped from the average denominator implicitly by
        // adding a zero-information term (ψ(1) - ψ(1) style) — but Ross defines the
        // average over all points, so we still add its digamma(nx) term.
        for j in 0..n {
            dist[j] = chebyshev(&cont[i], &cont[j]);
        }
        // k_i is capped at nx - 1 (cannot have more same-class neighbours).
        let k_i = k.min(nx.saturating_sub(1));
        if k_i == 0 {
            // No usable within-class neighbour: the point still enters the ψ(N) and
            // ψ(N_x) terms; use m = N - 1 (all others within an infinite radius) and
            // treat its k contribution as ψ(1) so it neither adds nor removes signal.
            acc += digamma(n as f64) - digamma(nx as f64) + digamma(1.0)
                - digamma((n - 1).max(1) as f64);
            continue;
        }
        // d = distance to the k_i-th nearest same-class neighbour (excluding self).
        let mut same: Vec<f64> = (0..n)
            .filter(|&j| j != i && labels[j] == label)
            .map(|j| dist[j])
            .collect();
        same.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let d = same[k_i - 1];
        // m = number of points of any class within distance d (excluding self).
        let m = dist
            .iter()
            .enumerate()
            .filter(|&(j, &dj)| j != i && dj <= d)
            .count()
            .max(1);
        acc += digamma(n as f64) - digamma(nx as f64) + digamma(k_i as f64) - digamma(m as f64);
    }
    let mi_nats = acc / n as f64;
    (mi_nats * NATS_TO_BITS).max(0.0)
}

/// Shannon entropy `H` of a discrete label sequence, in **bits**.
///
/// The plug-in (maximum-likelihood) estimate `-Σ p log2 p` over the observed
/// class frequencies. Empty input has zero entropy.
pub fn entropy_bits(labels: &[i64]) -> f64 {
    let n = labels.len();
    if n == 0 {
        return 0.0;
    }
    use std::collections::HashMap;
    let mut counts: HashMap<i64, usize> = HashMap::new();
    for &l in labels {
        *counts.entry(l).or_insert(0) += 1;
    }
    // Sum in a deterministic order (ascending count): a `HashMap` iterates in a
    // per-instance random order, and floating-point addition is not associative, so
    // an unordered sum would differ in the last ULP between two otherwise-identical
    // calls and break the bit-exact reproducibility contract (invariant 5).
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

/// Plug-in discrete↔discrete mutual information, in **bits**.
///
/// `I(A;B) = H(A) + H(B) - H(A,B)` over the observed joint frequencies. Used for
/// a label slot against a discrete outcome axis. Row-aligned inputs; empty input
/// is zero.
pub fn mi_discrete(a: &[i64], b: &[i64]) -> f64 {
    let n = a.len();
    debug_assert_eq!(n, b.len());
    if n == 0 {
        return 0.0;
    }
    let joint: Vec<i64> = a
        .iter()
        .zip(b.iter())
        // Pack the two labels into one key via a reversible pairing so the joint
        // entropy is computed over the observed (a,b) cells. Cantor pairing on the
        // zig-zag-encoded values keeps distinct pairs distinct.
        .map(|(&x, &y)| cantor(zigzag(x), zigzag(y)) as i64)
        .collect();
    (entropy_bits(a) + entropy_bits(b) - entropy_bits(&joint)).max(0.0)
}

/// Plug-in mutual information in **bits** between two aligned integer sequences
/// already interpreted as bin indices, via `H(a)+H(b)-H(a,b)`.
///
/// This is the discrete kernel the small-sample posterior draws call once per
/// sampled contingency table.
pub fn mi_from_bins(a: &[i64], b: &[i64]) -> f64 {
    mi_discrete(a, b)
}

/// Plug-in mutual information of a joint probability table, in **bits**.
///
/// `p` is a `rows x cols` row-major joint distribution that sums to one. Used by
/// the posterior draws, which sample a joint table from a Dirichlet and evaluate
/// its MI directly (no re-binning). Cells at probability zero contribute zero.
pub fn mi_from_joint(p: &[f64], rows: usize, cols: usize) -> f64 {
    debug_assert_eq!(p.len(), rows * cols);
    let mut row_marg = vec![0.0_f64; rows];
    let mut col_marg = vec![0.0_f64; cols];
    for r in 0..rows {
        for c in 0..cols {
            let v = p[r * cols + c];
            row_marg[r] += v;
            col_marg[c] += v;
        }
    }
    let mut mi = 0.0;
    for r in 0..rows {
        for c in 0..cols {
            let v = p[r * cols + c];
            if v > 0.0 && row_marg[r] > 0.0 && col_marg[c] > 0.0 {
                mi += v * (v / (row_marg[r] * col_marg[c])).log2();
            }
        }
    }
    mi.max(0.0)
}

/// Zig-zag encodes a signed integer into a non-negative one so the pairing
/// function stays in the non-negative domain.
fn zigzag(x: i64) -> u64 {
    ((x << 1) ^ (x >> 63)) as u64
}

/// Cantor pairing of two non-negative integers into a single one.
fn cantor(a: u64, b: u64) -> u64 {
    // Uses wrapping arithmetic: the result only has to be an injective-enough key
    // for the observed pairs in one sample, not a globally perfect pairing.
    let s = a.wrapping_add(b);
    (s.wrapping_mul(s.wrapping_add(1)) / 2).wrapping_add(b)
}
