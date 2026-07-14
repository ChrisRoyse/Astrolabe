//! Transfer entropy over change/failure series pairs, with a dyadic lag sweep and
//! a permutation significance gate that emits directed `DRIVES` edges
//! (08_ASSAY §6, capability 4.6).
//!
//! For an ordered pair of aligned discrete series `A`, `B` this computes
//! `T(A→B) = I(B_t; A_{t−lag} | B_{t−lag})` at each lag in the dyadic sweep
//! `{1,2,4,8}` (registry-derived), keeps the lag of largest transfer, and tests it
//! against a **source-shuffle permutation null**: the source series is repeatedly
//! shuffled (destroying its temporal relation to the target) and the transfer
//! recomputed, giving a p-value. The direction of the pair is the larger of
//! `T(A→B)` and `T(B→A)`; a `DRIVES{lag, te_bits}` edge is emitted only when that
//! larger transfer clears the significance level. An independent pair produces no
//! edge — the negative control the DoD requires.
//!
//! Every permutation stream is a seeded [`DeterministicRng`], so the card is a pure
//! function of `(inputs, seed, config)` and reproduces bit-for-bit.

use astrolabe_domain::TrustTag;
use serde::{Deserialize, Serialize};

use crate::diff::DiffConfig;
use crate::error::{ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, AssayError, Result};
use crate::multivariate::{compact_labels, transfer_entropy_bits};
use crate::rng::DeterministicRng;

/// A named discrete event/state series aligned on a common time index.
#[derive(Debug, Clone, PartialEq)]
pub struct NamedSeries {
    /// Stable series name (used as the edge endpoint).
    pub name: String,
    /// The discrete per-step values; compacted internally.
    pub values: Vec<i64>,
}

/// The evaluation of one ordered direction of a pair at its best lag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectionEval {
    /// Source series name.
    pub from: String,
    /// Target series name.
    pub to: String,
    /// Lag of largest transfer in the sweep.
    pub best_lag: usize,
    /// Transfer entropy at the best lag, in bits.
    pub te_bits: f64,
    /// Permutation p-value at the best lag, in permille.
    pub p_value_permille: u64,
    /// Whether the transfer cleared the significance level.
    pub significant: bool,
}

/// A directed causal edge above significance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DrivesEdge {
    /// Driving series name.
    pub from: String,
    /// Driven series name.
    pub to: String,
    /// Lag at which the drive is strongest.
    pub lag: usize,
    /// Transfer entropy at that lag, in bits.
    pub te_bits: f64,
    /// Permutation p-value, in permille.
    pub p_value_permille: u64,
}

/// A causality card: significant `DRIVES` edges plus every direction evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalityCard {
    /// The emitted `DRIVES` edges (one per significant, dominant-direction pair).
    pub edges: Vec<DrivesEdge>,
    /// Every ordered-direction evaluation (both directions of every pair).
    pub evaluations: Vec<DirectionEval>,
    /// `Provisional` if the effective sample count is below the TE quorum.
    pub trust: TrustTag,
}

/// The best lag (largest transfer) for a source→target direction, and its TE.
fn best_direction(source: &[i64], target: &[i64], cfg: &DiffConfig) -> (usize, f64) {
    let mut best_lag = cfg.te_lags().first().copied().unwrap_or(1);
    let mut best_te = f64::NEG_INFINITY;
    for lag in cfg.te_lags() {
        let te = transfer_entropy_bits(source, target, lag);
        if te > best_te {
            best_te = te;
            best_lag = lag;
        }
    }
    (best_lag, best_te.max(0.0))
}

/// Permutation p-value (permille) for the observed transfer at `lag`: the fraction
/// of source-shuffle permutations whose transfer is at least the observed, with
/// the add-one correction so the p-value is never exactly zero.
fn permutation_p_permille(
    source: &[i64],
    target: &[i64],
    lag: usize,
    observed: f64,
    label: &str,
    seed: u64,
    cfg: &DiffConfig,
) -> u64 {
    let mut rng = DeterministicRng::from_u64_labeled(seed, label);
    let mut shuffled = source.to_vec();
    let n = shuffled.len();
    let mut ge = 0usize;
    for _ in 0..cfg.te_permutations {
        // Full Fisher–Yates shuffle destroys the temporal relation to the target.
        for i in (1..n).rev() {
            let j = (rng.next_u64() % (i as u64 + 1)) as usize;
            shuffled.swap(i, j);
        }
        let te = transfer_entropy_bits(&shuffled, target, lag);
        if te >= observed {
            ge += 1;
        }
    }
    // (1 + ge) / (1 + permutations), scaled to permille and rounded up so a
    // borderline p-value is reported conservatively.
    let num = (1 + ge) as u128 * 1000;
    let den = (1 + cfg.te_permutations) as u128;
    num.div_ceil(den) as u64
}

/// Measures a causality card over a set of aligned discrete series.
///
/// Fails closed on fewer than two series or series of unequal length. The pair
/// direction with the larger transfer is emitted as a `DRIVES` edge when it clears
/// the significance level.
pub fn measure_transfer_entropy(
    series: &[NamedSeries],
    seed: u64,
    cfg: &DiffConfig,
) -> Result<CausalityCard> {
    if series.len() < 2 {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!(
                "transfer entropy needs at least two series, got {}",
                series.len()
            ),
            "supply two or more aligned series",
        ));
    }
    let n = series[0].values.len();
    if n == 0 {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            "transfer-entropy series carry no samples",
            "supply non-empty aligned series",
        ));
    }
    for s in series {
        if s.values.len() != n {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!(
                    "series {} has {} samples but the set has {n}",
                    s.name,
                    s.values.len()
                ),
                "align every series to the same time index before differentiating",
            ));
        }
    }

    // Compact every series once.
    let cols: Vec<Vec<i64>> = series.iter().map(|s| compact_labels(&s.values).0).collect();
    // p ≤ 1 − significance (e.g. 0.05) to clear the gate.
    let p_gate_permille = (1000.0 * (1.0 - cfg.significance)).round() as u64;
    let max_lag = cfg.te_lags().into_iter().max().unwrap_or(1);
    let effective_n = n.saturating_sub(max_lag);

    let mut edges = Vec::new();
    let mut evaluations = Vec::new();
    for i in 0..series.len() {
        for j in (i + 1)..series.len() {
            // A → B
            let (lag_ab, te_ab) = best_direction(&cols[i], &cols[j], cfg);
            let label_ab = format!("te-{}->{}", series[i].name, series[j].name);
            let p_ab =
                permutation_p_permille(&cols[i], &cols[j], lag_ab, te_ab, &label_ab, seed, cfg);
            let sig_ab = p_ab <= p_gate_permille;
            evaluations.push(DirectionEval {
                from: series[i].name.clone(),
                to: series[j].name.clone(),
                best_lag: lag_ab,
                te_bits: te_ab,
                p_value_permille: p_ab,
                significant: sig_ab,
            });
            // B → A
            let (lag_ba, te_ba) = best_direction(&cols[j], &cols[i], cfg);
            let label_ba = format!("te-{}->{}", series[j].name, series[i].name);
            let p_ba =
                permutation_p_permille(&cols[j], &cols[i], lag_ba, te_ba, &label_ba, seed, cfg);
            let sig_ba = p_ba <= p_gate_permille;
            evaluations.push(DirectionEval {
                from: series[j].name.clone(),
                to: series[i].name.clone(),
                best_lag: lag_ba,
                te_bits: te_ba,
                p_value_permille: p_ba,
                significant: sig_ba,
            });

            // Direction = the larger transfer; emit only if it is significant.
            if te_ab >= te_ba {
                if sig_ab {
                    edges.push(DrivesEdge {
                        from: series[i].name.clone(),
                        to: series[j].name.clone(),
                        lag: lag_ab,
                        te_bits: te_ab,
                        p_value_permille: p_ab,
                    });
                }
            } else if sig_ba {
                edges.push(DrivesEdge {
                    from: series[j].name.clone(),
                    to: series[i].name.clone(),
                    lag: lag_ba,
                    te_bits: te_ba,
                    p_value_permille: p_ba,
                });
            }
        }
    }

    let trust = if effective_n >= cfg.te_quorum {
        TrustTag::Trusted
    } else {
        TrustTag::Provisional
    };

    Ok(CausalityCard {
        edges,
        evaluations,
        trust,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic binary series from a xorshift stream.
    fn binary_series(n: usize, seed: u64) -> Vec<i64> {
        let mut s = seed | 1;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            out.push((s & 1) as i64);
        }
        out
    }

    #[test]
    fn lagged_copy_emits_correct_direction_and_lag() {
        // B[t] = A[t−1]: A drives B at lag 1; reverse carries no transfer.
        let cfg = DiffConfig::from_defaults().unwrap();
        let n = 3000;
        let a = binary_series(n, 0xABCDEF);
        let mut b = vec![0i64; n];
        b[1..n].copy_from_slice(&a[..n - 1]);
        let series = vec![
            NamedSeries {
                name: "A".into(),
                values: a,
            },
            NamedSeries {
                name: "B".into(),
                values: b,
            },
        ];
        let card = measure_transfer_entropy(&series, 1, &cfg).unwrap();
        assert_eq!(card.edges.len(), 1, "exactly one directed edge");
        let edge = &card.edges[0];
        assert_eq!(edge.from, "A");
        assert_eq!(edge.to, "B");
        assert_eq!(edge.lag, 1);
        assert!(edge.te_bits > 0.8, "te={}", edge.te_bits);
        assert_eq!(card.trust, TrustTag::Trusted);
    }

    #[test]
    fn reversed_construction_flips_the_edge() {
        // A[t] = B[t−1]: now B drives A.
        let cfg = DiffConfig::from_defaults().unwrap();
        let n = 3000;
        let b = binary_series(n, 0x123456);
        let mut a = vec![0i64; n];
        a[1..n].copy_from_slice(&b[..n - 1]);
        let series = vec![
            NamedSeries {
                name: "A".into(),
                values: a,
            },
            NamedSeries {
                name: "B".into(),
                values: b,
            },
        ];
        let card = measure_transfer_entropy(&series, 1, &cfg).unwrap();
        assert_eq!(card.edges.len(), 1);
        assert_eq!(card.edges[0].from, "B");
        assert_eq!(card.edges[0].to, "A");
    }

    #[test]
    fn independent_series_emit_no_edge() {
        // Negative control: two independent binary series → no DRIVES edge.
        let cfg = DiffConfig::from_defaults().unwrap();
        let n = 3000;
        let series = vec![
            NamedSeries {
                name: "A".into(),
                values: binary_series(n, 0x1111),
            },
            NamedSeries {
                name: "B".into(),
                values: binary_series(n, 0x9999),
            },
        ];
        let card = measure_transfer_entropy(&series, 1, &cfg).unwrap();
        assert!(card.edges.is_empty(), "unexpected edges: {:?}", card.edges);
        // Both directions evaluated and both non-significant.
        assert_eq!(card.evaluations.len(), 2);
        assert!(card.evaluations.iter().all(|e| !e.significant));
    }

    #[test]
    fn deterministic_under_fixed_seed() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let n = 800;
        let a = binary_series(n, 0x5555);
        let mut b = vec![0i64; n];
        b[1..n].copy_from_slice(&a[..n - 1]);
        let series = vec![
            NamedSeries {
                name: "A".into(),
                values: a,
            },
            NamedSeries {
                name: "B".into(),
                values: b,
            },
        ];
        let x = measure_transfer_entropy(&series, 7, &cfg).unwrap();
        let y = measure_transfer_entropy(&series, 7, &cfg).unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn too_few_series_rejected() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let series = vec![NamedSeries {
            name: "A".into(),
            values: vec![0, 1, 0, 1],
        }];
        let err = measure_transfer_entropy(&series, 1, &cfg).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }

    #[test]
    fn short_series_below_quorum_is_provisional() {
        let cfg = DiffConfig::from_defaults().unwrap();
        // 20 samples − max lag 8 = 12 effective < quorum 50.
        let a = binary_series(20, 0x2222);
        let mut b = vec![0i64; 20];
        b[1..20].copy_from_slice(&a[..19]);
        let series = vec![
            NamedSeries {
                name: "A".into(),
                values: a,
            },
            NamedSeries {
                name: "B".into(),
                values: b,
            },
        ];
        let card = measure_transfer_entropy(&series, 1, &cfg).unwrap();
        assert_eq!(card.trust, TrustTag::Provisional);
    }
}
