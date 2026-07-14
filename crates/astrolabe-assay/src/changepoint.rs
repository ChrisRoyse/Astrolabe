//! CUSUM change-point detection on churn/complexity streams (08_ASSAY §6,
//! capability 4.10).
//!
//! This is Taylor's change-point analysis: form the cumulative sum of deviations
//! from the mean `S_k = Σ_{i≤k} (x_i − x̄)` (the CUSUM chart), whose range
//! `S_diff = max S − min S` measures how much a single mean shift explains the
//! stream, and whose extremum locates the shift (`argmax_k |S_k|`). The range is
//! tested against a **value-shuffle bootstrap null**: under no change the order is
//! exchangeable, so a large observed range relative to the shuffled null is
//! evidence of a real regime change. A confident change is reported with its index
//! and signed magnitude; a stationary stream produces no change point.
//!
//! The bootstrap stream is a seeded [`DeterministicRng`], so the verdict, index,
//! and confidence are a pure function of `(inputs, seed, config)`.

use astrolabe_domain::TrustTag;
use serde::{Deserialize, Serialize};

use crate::diff::DiffConfig;
use crate::error::{ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, AssayError, Result};
use crate::rng::DeterministicRng;

/// A change-point card for one stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangePointCard {
    /// Stream name.
    pub stream: String,
    /// Whether a confident change point was found.
    pub change_detected: bool,
    /// The estimated change index (the last index of the pre-change segment), when
    /// detected.
    pub change_index: Option<usize>,
    /// Signed magnitude of the shift (mean after − mean before), when detected.
    pub magnitude: f64,
    /// Bootstrap confidence that a change exists, in permille.
    pub confidence_permille: u64,
    /// Range of the CUSUM chart `max S − min S`.
    pub cusum_range: f64,
    /// Sample count.
    pub n: usize,
    /// `Trusted` above the redundancy quorum sample count, else `Provisional`.
    pub trust: TrustTag,
}

/// The CUSUM chart `S_k` (with `S_0 = 0`), its range, and the `argmax|S_k|` index.
fn cusum(values: &[f64]) -> (Vec<f64>, f64, usize) {
    let n = values.len();
    let mean = values.iter().sum::<f64>() / n as f64;
    let mut s = vec![0.0_f64; n + 1];
    for i in 0..n {
        s[i + 1] = s[i] + (values[i] - mean);
    }
    let mut smin = 0.0;
    let mut smax = 0.0;
    let mut arg = 0usize;
    let mut arg_abs = 0.0;
    for (k, &sk) in s.iter().enumerate() {
        if sk < smin {
            smin = sk;
        }
        if sk > smax {
            smax = sk;
        }
        if sk.abs() > arg_abs {
            arg_abs = sk.abs();
            arg = k;
        }
    }
    (s, smax - smin, arg)
}

/// Just the CUSUM range (used inside the bootstrap loop).
fn cusum_range(values: &[f64]) -> f64 {
    let n = values.len();
    let mean = values.iter().sum::<f64>() / n as f64;
    let mut acc = 0.0;
    let mut smin = 0.0;
    let mut smax = 0.0;
    for &v in values {
        acc += v - mean;
        if acc < smin {
            smin = acc;
        }
        if acc > smax {
            smax = acc;
        }
    }
    smax - smin
}

/// Measures the change-point card for a stream.
///
/// Fails closed on a stream shorter than twice the minimum segment or carrying a
/// non-finite value. A stationary or constant stream yields no change point.
pub fn measure_change_point(
    stream_name: impl Into<String>,
    values: &[f64],
    seed: u64,
    cfg: &DiffConfig,
) -> Result<ChangePointCard> {
    let n = values.len();
    let stream = stream_name.into();
    if n < 2 * cfg.cusum_min_segment {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!(
                "change-point stream has {n} samples, below twice the minimum segment {}",
                cfg.cusum_min_segment
            ),
            "supply a stream at least twice the minimum-segment length",
        ));
    }
    if values.iter().any(|v| !v.is_finite()) {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            "change-point stream carries a non-finite value",
            "supply only finite stream values",
        ));
    }

    let trust = if n >= cfg.redundancy_quorum {
        TrustTag::Trusted
    } else {
        TrustTag::Provisional
    };

    let (_s, observed_range, arg) = cusum(values);

    // A perfectly flat stream has zero range: no change.
    if observed_range <= 0.0 {
        return Ok(ChangePointCard {
            stream,
            change_detected: false,
            change_index: None,
            magnitude: 0.0,
            confidence_permille: 0,
            cusum_range: 0.0,
            n,
            trust,
        });
    }

    // Bootstrap: shuffle the values (order-exchangeable under the no-change null)
    // and count how often the shuffled range stays below the observed range.
    let mut rng = DeterministicRng::from_u64_labeled(seed, "cusum-bootstrap");
    let mut shuffled = values.to_vec();
    let mut below = 0usize;
    for _ in 0..cfg.cusum_permutations {
        for i in (1..n).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            shuffled.swap(i, j);
        }
        if cusum_range(&shuffled) < observed_range {
            below += 1;
        }
    }
    let confidence_permille = ((below as u128 * 1000) / cfg.cusum_permutations as u128) as u64;

    // The estimated change index is argmax|S_k|. S has n+1 entries (0..=n); the
    // change falls between samples, and `arg` is the count of pre-change samples,
    // i.e. the last index of the pre-change segment.
    let change_index = arg;
    let significant = confidence_permille as f64 / 1000.0 >= cfg.significance
        && change_index >= cfg.cusum_min_segment
        && change_index <= n - cfg.cusum_min_segment;

    if !significant {
        return Ok(ChangePointCard {
            stream,
            change_detected: false,
            change_index: None,
            magnitude: 0.0,
            confidence_permille,
            cusum_range: observed_range,
            n,
            trust,
        });
    }

    let before = &values[..change_index];
    let after = &values[change_index..];
    let mean_before = before.iter().sum::<f64>() / before.len() as f64;
    let mean_after = after.iter().sum::<f64>() / after.len() as f64;

    Ok(ChangePointCard {
        stream,
        change_detected: true,
        change_index: Some(change_index),
        magnitude: mean_after - mean_before,
        confidence_permille,
        cusum_range: observed_range,
        n,
        trust,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planted_mean_shift_is_recovered() {
        // 0-mean noise for 500 samples, then a +3 shift for 500: change at 500.
        let cfg = DiffConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(1, "shift");
        let n = 1000;
        let shift_at = 500;
        let values: Vec<f64> = (0..n)
            .map(|i| {
                let base = if i < shift_at { 0.0 } else { 3.0 };
                base + rng.next_standard_normal()
            })
            .collect();
        let card = measure_change_point("churn", &values, 7, &cfg).unwrap();
        assert!(card.change_detected, "conf={}", card.confidence_permille);
        let idx = card.change_index.unwrap();
        assert!(
            (idx as i64 - shift_at as i64).abs() <= 20,
            "change index {idx} not within 20 of {shift_at}"
        );
        assert!(card.magnitude > 2.5, "magnitude={}", card.magnitude);
        assert_eq!(card.trust, TrustTag::Trusted);
    }

    #[test]
    fn stationary_stream_has_no_change() {
        // Pure noise, no shift: no confident change point.
        let cfg = DiffConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(2, "stationary");
        let values: Vec<f64> = (0..1000).map(|_| rng.next_standard_normal()).collect();
        let card = measure_change_point("stable", &values, 3, &cfg).unwrap();
        assert!(!card.change_detected, "conf={}", card.confidence_permille);
        assert!(card.change_index.is_none());
    }

    #[test]
    fn constant_stream_has_no_change() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let values = vec![5.0_f64; 100];
        let card = measure_change_point("flat", &values, 1, &cfg).unwrap();
        assert!(!card.change_detected);
        assert_eq!(card.cusum_range, 0.0);
    }

    #[test]
    fn short_stream_is_rejected() {
        let cfg = DiffConfig::from_defaults().unwrap();
        // n = 15 < 2 * min_segment (20).
        let values: Vec<f64> = (0..15).map(|i| i as f64).collect();
        let err = measure_change_point("s", &values, 1, &cfg).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }

    #[test]
    fn deterministic_under_fixed_seed() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(4, "det");
        let values: Vec<f64> = (0..400)
            .map(|i| if i < 200 { 0.0 } else { 2.0 } + rng.next_standard_normal())
            .collect();
        let a = measure_change_point("s", &values, 9, &cfg).unwrap();
        let b = measure_change_point("s", &values, 9, &cfg).unwrap();
        assert_eq!(a, b);
    }
}
