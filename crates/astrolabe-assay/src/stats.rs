//! Small deterministic statistics helpers the calibration card depends on.
//!
//! Two pure functions, both exact functions of their inputs (no randomness, no
//! threading), so a card built from them reproduces bit-for-bit regardless of
//! worker count:
//!
//! * [`inverse_standard_normal_cdf`] — the standard-normal quantile `Φ⁻¹(p)`,
//!   via Acklam's rational approximation. It turns a registry-declared confidence
//!   level (e.g. 950 permille) into its two-sided `z` multiplier, so the `z` a
//!   confidence interval uses is *derived from the knob* rather than a hardcoded
//!   1.96 — a mathematical quantile, not a tuned constant.
//! * [`wilson_interval`] — the Wilson score interval for a binomial proportion.
//!   It is the interval the edge-strategy calibration card attaches to a measured
//!   per-strategy precision `x/n`; Wilson is used rather than the Wald interval
//!   because Wald degenerates (zero width, or endpoints outside `[0, 1]`) exactly
//!   at the near-0/near-1 precisions resolution strategies routinely produce.

/// The standard-normal quantile `Φ⁻¹(p)` for `p` in `(0, 1)`.
///
/// Peter Acklam's rational-approximation algorithm: a pair of rational functions
/// (a lower/upper tail region and a central region) whose relative error is below
/// `1.15e-9` across the whole open interval — far tighter than any sampling noise
/// the interval is reported against. The two-sided `z` for a confidence level
/// `c` is `Φ⁻¹((1 + c) / 2)` (e.g. `c = 0.95 → Φ⁻¹(0.975) = 1.959964`).
///
/// Returns `-∞`/`+∞` at `p = 0`/`p = 1` and `NaN` outside `[0, 1]`; callers pass
/// a level strictly inside `(0, 1)`.
pub fn inverse_standard_normal_cdf(p: f64) -> f64 {
    if !(0.0..=1.0).contains(&p) {
        return f64::NAN;
    }
    if p == 0.0 {
        return f64::NEG_INFINITY;
    }
    if p == 1.0 {
        return f64::INFINITY;
    }
    // Acklam coefficients.
    const A: [f64; 6] = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_69e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239e0,
    ];
    const B: [f64; 5] = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    const C: [f64; 6] = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838e0,
        -2.549_732_539_343_734e0,
        4.374_664_141_464_968e0,
        2.938_163_982_698_783e0,
    ];
    const D: [f64; 4] = [
        7.784_695_709_041_462e-3,
        3.224_671_290_700_398e-1,
        2.445_134_137_142_996e0,
        3.754_408_661_907_416e0,
    ];
    // Break-points between the tail and central rational regions.
    const P_LOW: f64 = 0.024_25;
    const P_HIGH: f64 = 1.0 - P_LOW;
    if p < P_LOW {
        let q = (-2.0 * p.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if p <= P_HIGH {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    }
}

/// The two-sided Wilson score interval for a binomial proportion.
///
/// `successes` out of `trials` at two-sided confidence level `level` (a fraction
/// in `(0, 1)`). Returns `(lo, hi)`, each clamped into `[0, 1]`. `z` is obtained
/// from [`inverse_standard_normal_cdf`] so the interval width tracks the declared
/// level rather than a fixed multiplier. `trials == 0` is a degenerate input the
/// caller filters out before measuring; it returns the whole `[0, 1]` range.
pub fn wilson_interval(successes: u64, trials: u64, level: f64) -> (f64, f64) {
    if trials == 0 {
        return (0.0, 1.0);
    }
    let n = trials as f64;
    let p_hat = successes as f64 / n;
    let z = inverse_standard_normal_cdf((1.0 + level) / 2.0);
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let center = (p_hat + z2 / (2.0 * n)) / denom;
    let margin = (z / denom) * (p_hat * (1.0 - p_hat) / n + z2 / (4.0 * n * n)).sqrt();
    (
        (center - margin).clamp(0.0, 1.0),
        (center + margin).clamp(0.0, 1.0),
    )
}
