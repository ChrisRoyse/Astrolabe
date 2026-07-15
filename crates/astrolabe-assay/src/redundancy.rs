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
