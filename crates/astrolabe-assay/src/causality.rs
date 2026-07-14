//! Causality: transfer entropy over change/failure series with a lag sweep
//! (blueprint 08_ASSAY §6, deliverable card 5).
//!
//! For two aligned discrete series — a candidate **driver** `A` and a **target**
//! `B` — the transfer entropy at lag `L`
//!
//! ```text
//! TE(A → B; L) = H(B_f | B_p) − H(B_f | B_p, A_p)
//!              = I(B_f ; A_p | B_p)
//! ```
//!
//! (with `B_f = B[t]`, `B_p = B[t−L]`, `A_p = A[t−L]`) measures how much the
//! driver's past reduces uncertainty about the target's future *beyond* what the
//! target's own past already explains — turning correlation into an arrow. The
//! card sweeps the blueprint's power-of-two lags `{1, 2, 4, 8}` (capped by the
//! declared max-lag knob) and reports the dominant lag (largest TE) as the edge
//! direction.
//!
//! Every conditional entropy is the plug-in discrete estimate over the
//! constructed lagged triples, so the card is exact and deterministic.

use std::collections::BTreeMap;

use astrolabe_domain::TrustTag;
use serde::{Deserialize, Serialize};

use crate::error::{ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, AssayError, Result};
use crate::estimators::entropy_bits;
use crate::knobs::{
    ASSAY_CAUSALITY_MAX_LAG_KNOB, ASSAY_CAUSALITY_MIN_SERIES_KNOB, ASSAY_DEFAULT_CAUSALITY_MAX_LAG,
    ASSAY_DEFAULT_CAUSALITY_MIN_SERIES,
};
use crate::redundancy_card::card_knob_default;

/// A candidate directed edge to test: driver series `A` against target `B`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalityEdgeInput {
    /// Driver (source) series name.
    pub driver_slot: String,
    /// Driver's discrete series values.
    pub driver: Vec<i64>,
    /// Target series name.
    pub target_slot: String,
    /// Target's discrete series values, aligned with the driver.
    pub target: Vec<i64>,
}

/// Transfer entropy measured at one lag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalityLag {
    /// The lag, in series steps.
    pub lag: u64,
    /// Transfer entropy `TE(A → B; lag)`, in bits.
    pub te_bits: f64,
    /// Number of lagged triples the estimate was computed over.
    pub n_triples: usize,
}

/// One directed edge's transfer-entropy sweep.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalityEdge {
    /// Driver (source) series name.
    pub driver_slot: String,
    /// Target series name.
    pub target_slot: String,
    /// Per-lag transfer entropy across the swept lags.
    pub lags: Vec<CausalityLag>,
    /// The lag with the largest transfer entropy (the reported direction/window).
    pub best_lag: u64,
    /// The transfer entropy at `best_lag`, in bits.
    pub best_te_bits: f64,
    /// The series length.
    pub n: usize,
    /// Whether the series is below the minimum-length quorum.
    pub below_quorum: bool,
    /// `Trusted` at or above quorum, else `Provisional`.
    pub trust: TrustTag,
}

/// A causality card: transfer-entropy sweeps over the candidate edges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalityCard {
    /// Measured edges, ordered by descending best transfer entropy.
    pub edges: Vec<CausalityEdge>,
    /// The swept lags (powers of two up to the max-lag knob).
    pub swept_lags: Vec<u64>,
    /// The minimum-series-length quorum applied.
    pub min_series: u64,
}

/// Resolved configuration for the causality card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CausalityConfig {
    /// Minimum series length before an edge is trusted.
    pub min_series: u64,
    /// Largest lag in the power-of-two sweep.
    pub max_lag: u64,
}

impl CausalityConfig {
    /// Builds the config from the declared knob defaults.
    pub fn from_defaults() -> Result<Self> {
        Ok(Self {
            min_series: card_knob_default(
                ASSAY_CAUSALITY_MIN_SERIES_KNOB,
                ASSAY_DEFAULT_CAUSALITY_MIN_SERIES,
            )?,
            max_lag: card_knob_default(
                ASSAY_CAUSALITY_MAX_LAG_KNOB,
                ASSAY_DEFAULT_CAUSALITY_MAX_LAG,
            )?,
        })
    }

    /// The power-of-two lag sweep `{1, 2, 4, 8, …}` capped at `max_lag`.
    pub fn swept_lags(&self) -> Vec<u64> {
        let mut lags = Vec::new();
        let mut lag = 1u64;
        while lag <= self.max_lag {
            lags.push(lag);
            lag *= 2;
        }
        lags
    }
}

/// Joint entropy in bits over a set of aligned columns (exact tuple compaction).
fn joint_entropy(cols: &[&[i64]]) -> f64 {
    let n = cols[0].len();
    let mut ids: BTreeMap<Vec<i64>, i64> = BTreeMap::new();
    let mut next = 0i64;
    let mut joint = Vec::with_capacity(n);
    for i in 0..n {
        let tuple: Vec<i64> = cols.iter().map(|c| c[i]).collect();
        let id = *ids.entry(tuple).or_insert_with(|| {
            let id = next;
            next += 1;
            id
        });
        joint.push(id);
    }
    entropy_bits(&joint)
}

/// Transfer entropy `TE(A → B; lag)` in bits over the lagged triples.
///
/// Returns `None` when the series is too short to form a single lagged triple at
/// this lag. The estimate is clamped at zero (TE is non-negative; the plug-in
/// conditional-entropy difference can dip slightly negative on finite samples).
fn transfer_entropy(driver: &[i64], target: &[i64], lag: usize) -> Option<(f64, usize)> {
    let n = target.len();
    if n <= lag {
        return None;
    }
    let m = n - lag;
    let mut bf = Vec::with_capacity(m); // B[t]
    let mut bp = Vec::with_capacity(m); // B[t-lag]
    let mut ap = Vec::with_capacity(m); // A[t-lag]
    for k in 0..m {
        bf.push(target[lag + k]);
        bp.push(target[k]);
        ap.push(driver[k]);
    }
    // TE = H(Bf,Bp) - H(Bp) - H(Bf,Bp,Ap) + H(Bp,Ap).
    let h_bf_bp = joint_entropy(&[&bf, &bp]);
    let h_bp = joint_entropy(&[&bp]);
    let h_bf_bp_ap = joint_entropy(&[&bf, &bp, &ap]);
    let h_bp_ap = joint_entropy(&[&bp, &ap]);
    let te = (h_bf_bp - h_bp - h_bf_bp_ap + h_bp_ap).max(0.0);
    Some((te, m))
}

/// Builds a causality card from candidate directed edges.
///
/// Fails closed on an empty target series or a driver/target length mismatch.
pub fn build_causality_card(
    edges: &[CausalityEdgeInput],
    cfg: &CausalityConfig,
) -> Result<CausalityCard> {
    let swept = cfg.swept_lags();
    let mut out = Vec::with_capacity(edges.len());
    for e in edges {
        let n = e.target.len();
        if n == 0 {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!(
                    "edge {} -> {} carries no samples",
                    e.driver_slot, e.target_slot
                ),
                "measure a non-empty aligned series before requesting causality",
            ));
        }
        if e.driver.len() != n {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!(
                    "edge {} -> {} is ragged: driver={} target={n}",
                    e.driver_slot,
                    e.target_slot,
                    e.driver.len()
                ),
                "align the driver and target series to the same steps before measuring",
            ));
        }
        let mut lags = Vec::new();
        let mut best_lag = 0u64;
        let mut best_te = -1.0f64;
        for &lag in &swept {
            if let Some((te, m)) = transfer_entropy(&e.driver, &e.target, lag as usize) {
                if te > best_te {
                    best_te = te;
                    best_lag = lag;
                }
                lags.push(CausalityLag {
                    lag,
                    te_bits: te,
                    n_triples: m,
                });
            }
        }
        // A series shorter than the smallest lag+1 yields no measurable lag.
        let (best_lag, best_te) = if lags.is_empty() {
            (0, 0.0)
        } else {
            (best_lag, best_te.max(0.0))
        };
        let below_quorum = (n as u64) < cfg.min_series || lags.is_empty();
        let trust = if below_quorum {
            TrustTag::Provisional
        } else {
            TrustTag::Trusted
        };
        out.push(CausalityEdge {
            driver_slot: e.driver_slot.clone(),
            target_slot: e.target_slot.clone(),
            lags,
            best_lag,
            best_te_bits: best_te,
            n,
            below_quorum,
            trust,
        });
    }
    out.sort_by(|x, y| {
        y.best_te_bits
            .partial_cmp(&x.best_te_bits)
            .unwrap()
            .then_with(|| x.driver_slot.cmp(&y.driver_slot))
            .then_with(|| x.target_slot.cmp(&y.target_slot))
    });
    Ok(CausalityCard {
        edges: out,
        swept_lags: swept,
        min_series: cfg.min_series,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::DeterministicRng;

    fn cfg() -> CausalityConfig {
        CausalityConfig::from_defaults().unwrap()
    }

    fn random_bits(n: usize, seed: u64) -> Vec<i64> {
        let mut rng = DeterministicRng::from_u64_labeled(seed, "bits");
        (0..n).map(|_| (rng.next_u64() & 1) as i64).collect()
    }

    #[test]
    fn driver_that_sets_target_next_step_has_positive_te_at_lag_one() {
        // B[t] = A[t-1]: A's past fully determines B's future one step later, and
        // B's own past is uninformative, so TE(A->B; 1) -> 1 bit.
        let n = 500;
        let a = random_bits(n, 11);
        let mut b = vec![0i64; n];
        b[1..n].copy_from_slice(&a[..(n - 1)]);
        let card = build_causality_card(
            &[CausalityEdgeInput {
                driver_slot: "a".into(),
                driver: a,
                target_slot: "b".into(),
                target: b,
            }],
            &cfg(),
        )
        .unwrap();
        let e = &card.edges[0];
        assert_eq!(e.best_lag, 1, "best_lag={}", e.best_lag);
        assert!(e.best_te_bits > 0.8, "best_te={}", e.best_te_bits);
        assert_eq!(e.trust, TrustTag::Trusted);
    }

    #[test]
    fn reverse_direction_carries_no_transfer_entropy() {
        // With B[t]=A[t-1], the reverse edge B->A carries ~0 TE: A is i.i.d. and
        // B's past does not predict A's future.
        let n = 500;
        let a = random_bits(n, 12);
        let mut b = vec![0i64; n];
        b[1..n].copy_from_slice(&a[..(n - 1)]);
        let card = build_causality_card(
            &[CausalityEdgeInput {
                driver_slot: "b".into(),
                driver: b,
                target_slot: "a".into(),
                target: a,
            }],
            &cfg(),
        )
        .unwrap();
        let e = &card.edges[0];
        assert!(e.best_te_bits < 0.1, "reverse te={}", e.best_te_bits);
    }

    #[test]
    fn ragged_edge_fails_closed() {
        let e = build_causality_card(
            &[CausalityEdgeInput {
                driver_slot: "a".into(),
                driver: vec![0, 1, 0],
                target_slot: "b".into(),
                target: vec![0, 1],
            }],
            &cfg(),
        )
        .unwrap_err();
        assert_eq!(e.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }
}
