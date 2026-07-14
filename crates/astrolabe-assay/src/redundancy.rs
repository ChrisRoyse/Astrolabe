//! Redundancy: pairwise NMI agreement graph, total correlation, effective rank
//! `n_eff`, and the capability-gate retire recommendation (08_ASSAY §3,
//! capability 4.4).
//!
//! Given a panel of aligned lens slots, this measures how much the lenses
//! duplicate each other:
//!
//! * a **pairwise normalized-MI matrix** — the agreement graph edges (07 §4);
//! * the **total correlation** `TC = Σ H(slotₖ) − H(Φ)`, the multi-information the
//!   panel's joint distribution carries above independence;
//! * the **effective rank** `n_eff = n_slots · (1 − TC/Σ H)` — "you have N lenses
//!   but only n_eff independent ones";
//! * a per-lens **retire recommendation**: a lens whose NMI to an earlier kept
//!   lens exceeds the declared threshold is redundant and recommended for
//!   retirement (05 §6). A duplicated lens sits at NMI 1.0 and is always caught.
//!
//! Every lens is reduced to an aligned discrete column ([`crate::diff`]) and the
//! quantities are plug-in estimates over those columns — pure, deterministic
//! functions of the inputs, so the card reproduces bit-for-bit.

use astrolabe_domain::TrustTag;
use serde::{Deserialize, Serialize};

use crate::bits::SlotObservations;
use crate::diff::{DiffConfig, discretize_slot};
use crate::error::{ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, AssayError, Result};
use crate::estimators::entropy_bits;
use crate::multivariate::{joint_entropy_bits, normalized_mi_bits};

/// One off-diagonal entry of the pairwise NMI agreement matrix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairwiseNmi {
    /// First lens name (lexically the earlier of the pair as listed).
    pub a: String,
    /// Second lens name.
    pub b: String,
    /// Normalized mutual information in `[0,1]`.
    pub nmi: f64,
}

/// The capability-gate recommendation for a lens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedundancyGate {
    /// The lens carries independent signal and is kept.
    Keep,
    /// The lens duplicates an earlier kept lens and is recommended for retirement.
    Retire,
}

/// One lens's gate decision and the evidence behind it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateDecision {
    /// Lens name.
    pub lens: String,
    /// Keep or Retire.
    pub decision: RedundancyGate,
    /// Maximum NMI this lens shares with any earlier kept lens.
    pub max_nmi_to_kept: f64,
    /// The earlier kept lens it most duplicates, when retired.
    pub redundant_with: Option<String>,
}

/// A redundancy card for a panel: agreement graph, TC, n_eff, gate decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedundancyCard {
    /// Number of lenses in the panel.
    pub n_slots: usize,
    /// Aligned sample count.
    pub n_samples: usize,
    /// Total correlation `Σ H(slotₖ) − H(Φ)`, in bits.
    pub total_correlation_bits: f64,
    /// Sum of the per-lens marginal entropies, in bits.
    pub sum_marginal_entropy_bits: f64,
    /// Effective rank `n_slots · (1 − TC/Σ H)`.
    pub n_eff: f64,
    /// Upper-triangle pairwise NMI entries.
    pub pairwise_nmi: Vec<PairwiseNmi>,
    /// Per-lens retire/keep decisions.
    pub gate_decisions: Vec<GateDecision>,
    /// `Trusted` above the per-slot quorum, else `Provisional`.
    pub trust: TrustTag,
}

/// Measures the redundancy card for a panel of aligned lens slots.
///
/// Fails closed on an empty panel, a single lens (no pair to compare), or slots of
/// unequal length. Below the per-slot quorum the card is still produced but tagged
/// `Provisional`.
pub fn measure_redundancy(
    slots: &[SlotObservations],
    seed: u64,
    cfg: &DiffConfig,
) -> Result<RedundancyCard> {
    if slots.len() < 2 {
        return Err(AssayError::new(
            ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
            format!("redundancy needs at least two lenses, got {}", slots.len()),
            "supply a panel of two or more aligned lenses",
        ));
    }
    let n_samples = slots[0].values.len();
    for slot in slots {
        if slot.values.len() != n_samples {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!(
                    "lens {} has {} samples but the panel has {n_samples}",
                    slot.slot,
                    slot.values.len()
                ),
                "align every lens to the same sample set before differentiating",
            ));
        }
    }

    // Reduce every lens to a discrete column once.
    let columns: Vec<Vec<i64>> = slots
        .iter()
        .map(|slot| discretize_slot(slot, seed, cfg))
        .collect::<Result<_>>()?;

    // Marginal entropies and their sum.
    let marginals: Vec<f64> = columns.iter().map(|c| entropy_bits(c)).collect();
    let sum_marginal_entropy_bits: f64 = marginals.iter().sum();

    // Joint entropy of the whole panel.
    let col_refs: Vec<&[i64]> = columns.iter().map(|c| c.as_slice()).collect();
    let joint = joint_entropy_bits(&col_refs);
    let total_correlation_bits = (sum_marginal_entropy_bits - joint).max(0.0);

    // n_eff = n_slots · (1 − TC/ΣH). ΣH == 0 means every lens is constant: no
    // independent signal at all, so n_eff collapses to zero.
    let n_slots = slots.len();
    let n_eff = if sum_marginal_entropy_bits > 0.0 {
        (n_slots as f64) * (1.0 - total_correlation_bits / sum_marginal_entropy_bits)
    } else {
        0.0
    };

    // Pairwise NMI upper triangle.
    let mut pairwise_nmi = Vec::with_capacity(n_slots * (n_slots - 1) / 2);
    for i in 0..n_slots {
        for j in (i + 1)..n_slots {
            pairwise_nmi.push(PairwiseNmi {
                a: slots[i].slot.clone(),
                b: slots[j].slot.clone(),
                nmi: normalized_mi_bits(&columns[i], &columns[j]),
            });
        }
    }

    // Retire gate: walk the lenses in order; a lens is retired if its NMI to any
    // earlier KEPT lens exceeds the threshold. The first of a duplicate pair is
    // kept, the second retired.
    let mut gate_decisions = Vec::with_capacity(n_slots);
    let mut kept: Vec<usize> = Vec::new();
    for i in 0..n_slots {
        let mut max_nmi = 0.0_f64;
        let mut most_like: Option<usize> = None;
        for &k in &kept {
            let nmi = normalized_mi_bits(&columns[i], &columns[k]);
            if nmi > max_nmi {
                max_nmi = nmi;
                most_like = Some(k);
            }
        }
        let retire = max_nmi > cfg.redundancy_retire_nmi;
        if retire {
            gate_decisions.push(GateDecision {
                lens: slots[i].slot.clone(),
                decision: RedundancyGate::Retire,
                max_nmi_to_kept: max_nmi,
                redundant_with: most_like.map(|k| slots[k].slot.clone()),
            });
        } else {
            kept.push(i);
            gate_decisions.push(GateDecision {
                lens: slots[i].slot.clone(),
                decision: RedundancyGate::Keep,
                max_nmi_to_kept: max_nmi,
                redundant_with: None,
            });
        }
    }

    let trust = if n_samples >= cfg.redundancy_quorum {
        TrustTag::Trusted
    } else {
        TrustTag::Provisional
    };

    Ok(RedundancyCard {
        n_slots,
        n_samples,
        total_correlation_bits,
        sum_marginal_entropy_bits,
        n_eff,
        pairwise_nmi,
        gate_decisions,
        trust,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bits::SlotValues;
    use crate::rng::DeterministicRng;

    fn label_slot(name: &str, values: Vec<i64>) -> SlotObservations {
        SlotObservations {
            slot: name.into(),
            values: SlotValues::Label(values),
        }
    }

    /// Four independent fair-4-ary lenses plus an exact copy of the first.
    fn panel_with_duplicate(n: usize) -> Vec<SlotObservations> {
        let mut rng = DeterministicRng::from_u64_labeled(7, "redundancy");
        let mut cols: Vec<Vec<i64>> = (0..4)
            .map(|_| (0..n).map(|_| (rng.next_u64() % 4) as i64).collect())
            .collect();
        // Duplicate lens = exact copy of lens 0.
        let dup = cols[0].clone();
        cols.push(dup);
        vec![
            label_slot("a", cols[0].clone()),
            label_slot("b", cols[1].clone()),
            label_slot("c", cols[2].clone()),
            label_slot("d", cols[3].clone()),
            label_slot("a_copy", cols[4].clone()),
        ]
    }

    #[test]
    fn duplicated_lens_is_detected_and_drops_n_eff_by_one() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let slots = panel_with_duplicate(4000);
        let card = measure_redundancy(&slots, 1, &cfg).unwrap();

        // The duplicate pair has NMI ≈ 1.
        let dup_pair = card
            .pairwise_nmi
            .iter()
            .find(|p| (p.a == "a" && p.b == "a_copy") || (p.a == "a_copy" && p.b == "a"))
            .expect("duplicate pair present");
        assert!(dup_pair.nmi > 0.99, "dup nmi={}", dup_pair.nmi);

        // n_eff drops from 5 lenses to ≈ 4 (one redundant).
        assert!(
            (card.n_eff - 4.0).abs() < 0.1,
            "n_eff={} (expected ≈4)",
            card.n_eff
        );

        // The copy is recommended for retirement, pointing back at lens `a`.
        let copy_decision = card
            .gate_decisions
            .iter()
            .find(|d| d.lens == "a_copy")
            .unwrap();
        assert_eq!(copy_decision.decision, RedundancyGate::Retire);
        assert_eq!(copy_decision.redundant_with.as_deref(), Some("a"));
        // The four independent lenses are kept.
        for name in ["a", "b", "c", "d"] {
            let d = card.gate_decisions.iter().find(|d| d.lens == name).unwrap();
            assert_eq!(d.decision, RedundancyGate::Keep, "{name} kept");
        }
        assert_eq!(card.trust, TrustTag::Trusted);
    }

    #[test]
    fn total_correlation_of_k_duplicates_is_k_minus_one_times_entropy() {
        // k identical copies of one variable: TC = (k−1)·H, n_eff = 1.
        let cfg = DiffConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(3, "dup");
        let base: Vec<i64> = (0..3000).map(|_| (rng.next_u64() % 4) as i64).collect();
        let h = entropy_bits(&base);
        let k = 3;
        let slots: Vec<SlotObservations> = (0..k)
            .map(|i| label_slot(&format!("copy{i}"), base.clone()))
            .collect();
        let card = measure_redundancy(&slots, 1, &cfg).unwrap();
        assert!(
            (card.total_correlation_bits - (k as f64 - 1.0) * h).abs() < 1e-6,
            "tc={} expected={}",
            card.total_correlation_bits,
            (k as f64 - 1.0) * h
        );
        assert!((card.n_eff - 1.0).abs() < 1e-6, "n_eff={}", card.n_eff);
    }

    #[test]
    fn independent_lenses_have_n_eff_near_slot_count() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let mut rng = DeterministicRng::from_u64_labeled(9, "indep");
        let slots: Vec<SlotObservations> = (0..4)
            .map(|i| {
                label_slot(
                    &format!("l{i}"),
                    (0..4000).map(|_| (rng.next_u64() % 4) as i64).collect(),
                )
            })
            .collect();
        let card = measure_redundancy(&slots, 1, &cfg).unwrap();
        // Independent → TC ≈ 0, n_eff ≈ 4.
        assert!(
            card.total_correlation_bits < 0.05,
            "tc={}",
            card.total_correlation_bits
        );
        assert!((card.n_eff - 4.0).abs() < 0.2, "n_eff={}", card.n_eff);
        assert!(
            card.gate_decisions
                .iter()
                .all(|d| d.decision == RedundancyGate::Keep)
        );
    }

    #[test]
    fn single_lens_is_rejected() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let slots = vec![label_slot("only", vec![0, 1, 0, 1])];
        let err = measure_redundancy(&slots, 1, &cfg).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }

    #[test]
    fn constant_lenses_have_zero_n_eff() {
        // Every lens constant: ΣH = 0, no independent signal.
        let cfg = DiffConfig::from_defaults().unwrap();
        let slots = vec![
            label_slot("c1", vec![5; 100]),
            label_slot("c2", vec![7; 100]),
        ];
        let card = measure_redundancy(&slots, 1, &cfg).unwrap();
        assert_eq!(card.sum_marginal_entropy_bits, 0.0);
        assert_eq!(card.n_eff, 0.0);
        assert_eq!(card.total_correlation_bits, 0.0);
    }

    #[test]
    fn below_quorum_is_provisional() {
        let cfg = DiffConfig::from_defaults().unwrap();
        // 10 samples < quorum 50.
        let slots = vec![
            label_slot("a", vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1]),
            label_slot("b", vec![3, 2, 1, 0, 3, 2, 1, 0, 3, 2]),
        ];
        let card = measure_redundancy(&slots, 1, &cfg).unwrap();
        assert_eq!(card.trust, TrustTag::Provisional);
        assert_eq!(card.n_samples, 10);
    }

    #[test]
    fn mismatched_lengths_are_rejected() {
        let cfg = DiffConfig::from_defaults().unwrap();
        let slots = vec![label_slot("a", vec![0, 1, 2]), label_slot("b", vec![0, 1])];
        let err = measure_redundancy(&slots, 1, &cfg).unwrap_err();
        assert_eq!(err.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }
}
