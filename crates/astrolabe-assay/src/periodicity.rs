//! Periodicity: Lomb–Scargle periodogram, index autocorrelation, and a
//! permutation false-alarm probability on event series (08_ASSAY §6,
//! capability 4.9).
//!
//! Given an event series `(t_i, y_i)` this finds the dominant period by the
//! Lomb–Scargle periodogram (which, unlike a plain FFT, handles the uneven
//! sampling of real event series), corroborates it with the index autocorrelation
//! peak, and tests the periodogram peak against a **value-shuffle permutation
//! null**: the values are repeatedly shuffled and the peak power recomputed,
//! giving a false-alarm probability (FAP). A period is *detected* only when its
//! FAP clears the declared threshold. A white-noise series has a high FAP and is
//! not flagged — the negative control the DoD requires.
//!
//! The permutation stream is a seeded [`DeterministicRng`], so the FAP and the
//! detection verdict are a pure function of `(inputs, seed, config)`.

use astrolabe_domain::TrustTag;
use serde::{Deserialize, Serialize};

use crate::diff::DiffConfig;
use crate::error::{ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, AssayError, Result};
use crate::rng::DeterministicRng;

/// A periodicity card for one event series.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeriodicityCard {
    /// Series name.
    pub series: String,
    /// The period of the strongest periodogram peak (in the time units of `t`).
    pub peak_period: f64,
    /// Normalized Lomb–Scargle power at the peak.
    pub peak_power: f64,
    /// Permutation false-alarm probability, in permille.
    pub fap_permille: u64,
    /// Whether the peak cleared the FAP threshold (a real detected period).
    pub detected: bool,
    /// Index-autocorrelation peak lag (corroborating evidence).
    pub autocorr_peak_lag: usize,
    /// Autocorrelation value at that lag, in `[-1,1]`.
    pub autocorr_peak: f64,
    /// Sample count.
    pub n: usize,
    /// `Trusted` above the redundancy quorum sample count, else `Provisional`.
    pub trust: TrustTag,
}

/// Normalized Lomb–Scargle power at angular frequency `omega` for a
/// mean-subtracted series with variance `var`.
fn ls_power(times: &[f64], y_centered: &[f64], var: f64, omega: f64) -> f64 {
    if var <= 0.0 {
        return 0.0;
    }
    // τ removes the phase so the estimator is time-shift invariant.
    let mut s2 = 0.0;
    let mut c2 = 0.0;
    for &t in times {
        s2 += (2.0 * omega * t).sin();
        c2 += (2.0 * omega * t).cos();
    }
    let tau = 0.5 * s2.atan2(c2) / omega;
    let (mut num_c, mut den_c, mut num_s, mut den_s) = (0.0, 0.0, 0.0, 0.0);
    for (&t, &y) in times.iter().zip(y_centered.iter()) {
        let arg = omega * (t - tau);
        let (sin, cos) = arg.sin_cos();
        num_c += y * cos;
        den_c += cos * cos;
        num_s += y * sin;
        den_s += sin * sin;
    }
    let term_c = if den_c > 0.0 {
        num_c * num_c / den_c
    } else {
        0.0
    };
    let term_s = if den_s > 0.0 {
        num_s * num_s / den_s
    } else {
        0.0
    };
    0.5 * (term_c + term_s) / var
}

/// The angular-frequency grid `[f_min, f_max]` derived from the sampling.
fn frequency_grid(times: &[f64], oversample: usize) -> Vec<f64> {
    let n = times.len();
    let span = times[n - 1] - times[0];
    if span <= 0.0 {
        return Vec::new();
    }
    // Smallest positive gap sets the Nyquist-like upper frequency.
    let mut min_dt = f64::INFINITY;
    for w in times.windows(2) {
        let dt = w[1] - w[0];
        if dt > 0.0 && dt < min_dt {
            min_dt = dt;
        }
    }
    if !min_dt.is_finite() {
        return Vec::new();
    }
    let f_min = 1.0 / span;
    let f_max = 0.5 / min_dt;
    let df = 1.0 / (oversample.max(1) as f64 * span);
    let mut freqs = Vec::new();
    let mut f = f_min;
    while f <= f_max {
        freqs.push(2.0 * std::f64::consts::PI * f);
        f += df;
    }
    freqs
}

/// Peak (angular frequency, power) over the grid.
fn peak_over_grid(times: &[f64], y_centered: &[f64], var: f64, grid: &[f64]) -> (f64, f64) {
    let mut best_omega = 0.0;
    let mut best_power = 0.0;
    for &omega in grid {
        let p = ls_power(times, y_centered, var, omega);
        if p > best_power {
            best_power = p;
            best_omega = omega;
        }
    }
    (best_omega, best_power)
}

/// Index autocorrelation of a mean-subtracted series at integer lags; returns the
/// lag in `1..=max_lag` of largest positive correlation and its value.
fn autocorr_peak(y_centered: &[f64], var: f64, max_lag: usize) -> (usize, f64) {
    let n = y_centered.len();
    if var <= 0.0 || n < 2 {
        return (0, 0.0);
    }
    let denom = var * n as f64;
    let mut best_lag = 0;
    let mut best = 0.0;
    for lag in 1..=max_lag.min(n - 1) {
        let mut acc = 0.0;
        for i in 0..(n - lag) {
            acc += y_centered[i] * y_centered[i + lag];
        }
        let r = acc / denom;
        if r > best {
            best = r;
            best_lag = lag;
        }
    }
    (best_lag, best)
}

/// Measures the periodicity card for an event series `(times, values)`.
///
/// Fails closed on fewer than four points, mismatched lengths, non-finite values,
/// or a non-increasing time axis.
pub fn measure_periodicity(
    series_name: impl Into<String>,
    times: &[f64],
    values: &[f64],
    seed: u64,
    cfg: &DiffConfig,
) -> Result<PeriodicityCard> {
    let n = values.len();
    if n < 4 {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("periodicity needs at least four points, got {n}"),
            "supply a longer event series",
        ));
    }
    if times.len() != n {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("times has {} points but values has {n}", times.len()),
            "align the time axis and values to the same length",
        ));
    }
    if times.iter().chain(values.iter()).any(|v| !v.is_finite()) {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            "periodicity input carries a non-finite value",
            "supply only finite times and values",
        ));
    }
    for w in times.windows(2) {
        if w[1] <= w[0] {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                "periodicity time axis is not strictly increasing",
                "supply a strictly increasing time axis",
            ));
        }
    }

    let mean: f64 = values.iter().sum::<f64>() / n as f64;
    let y_centered: Vec<f64> = values.iter().map(|&y| y - mean).collect();
    let var: f64 = y_centered.iter().map(|y| y * y).sum::<f64>() / n as f64;

    let grid = frequency_grid(times, cfg.periodicity_oversample);
    let (peak_omega, peak_power) = if grid.is_empty() || var <= 0.0 {
        (0.0, 0.0)
    } else {
        peak_over_grid(times, &y_centered, var, &grid)
    };
    let peak_period = if peak_omega > 0.0 {
        2.0 * std::f64::consts::PI / peak_omega
    } else {
        0.0
    };

    // Permutation FAP: shuffle values, recompute the peak power, count how often
    // the null peak reaches the observed peak. Add-one so FAP is never zero.
    let fap_permille = if grid.is_empty() || var <= 0.0 {
        1000
    } else {
        let mut rng = DeterministicRng::from_u64_labeled(seed, "periodicity-perm");
        let mut shuffled = y_centered.clone();
        let mut ge = 0usize;
        for _ in 0..cfg.periodicity_permutations {
            for i in (1..n).rev() {
                let j = (rng.next_u64() % (i as u64 + 1)) as usize;
                shuffled.swap(i, j);
            }
            // Variance is invariant under permutation, so reuse `var`.
            let (_, p) = peak_over_grid(times, &shuffled, var, &grid);
            if p >= peak_power {
                ge += 1;
            }
        }
        let num = (1 + ge) as u128 * 1000;
        let den = (1 + cfg.periodicity_permutations) as u128;
        num.div_ceil(den) as u64
    };

    let detected =
        !grid.is_empty() && peak_power > 0.0 && (fap_permille as f64 / 1000.0) < cfg.fap_threshold;

    let (autocorr_peak_lag, autocorr_peak) = autocorr_peak(&y_centered, var, n / 2);

    let trust = if n >= cfg.redundancy_quorum {
        TrustTag::Trusted
    } else {
        TrustTag::Provisional
    };

    Ok(PeriodicityCard {
        series: series_name.into(),
        peak_period,
        peak_power,
        fap_permille,
        detected,
        autocorr_peak_lag,
        autocorr_peak,
        n,
        trust,
    })
}
