//! Synergy: three-way interaction information over designed triples (blueprint
//! 08_ASSAY §4, deliverable card 4).
//!
//! For a designed triple of two lens columns `A`, `B` and an outcome axis `C`,
//! the **interaction information**
//!
//! ```text
//! II(A; B; C) = I({A, B}; C) − I(A; C) − I(B; C)
//! ```
//!
//! measures whether the pair *together* tells more about the outcome than the
//! sum of what each tells alone. Its sign classifies the triple (blueprint §4):
//! positive → **synergistic** (the joint carries extra bits — e.g. an XOR-like
//! relationship neither part reveals), negative → **redundant** (the parts
//! overlap), zero → independent. Synergistic pairs get their interaction
//! cross-term promoted to eager and become named features in reports.
//!
//! Every quantity is the plug-in discrete estimate, so the card is an exact,
//! deterministic function of its inputs.

use std::collections::BTreeMap;

use astrolabe_domain::TrustTag;
use serde::{Deserialize, Serialize};

use crate::error::{ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID, AssayError, Result};
use crate::estimators::mi_discrete;
use crate::knobs::{ASSAY_DEFAULT_SYNERGY_QUORUM, ASSAY_SYNERGY_QUORUM_KNOB};
use crate::redundancy::card_knob_default;

/// A designed triple to measure: two lens columns against one outcome axis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SynergyTripleInput {
    /// First lens slot name.
    pub a_slot: String,
    /// First lens's discrete values.
    pub a: Vec<i64>,
    /// Second lens slot name.
    pub b_slot: String,
    /// Second lens's discrete values.
    pub b: Vec<i64>,
    /// Outcome axis name.
    pub axis: String,
    /// Outcome axis's discrete values.
    pub outcome: Vec<i64>,
}

/// How a triple's interaction information classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynergyClassification {
    /// `II > 0`: the joint carries extra bits about the outcome.
    Synergistic,
    /// `II < 0`: the parts overlap in what they say about the outcome.
    Redundant,
    /// `II == 0`: no interaction.
    Independent,
}

impl SynergyClassification {
    /// Stable response-envelope label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Synergistic => "synergistic",
            Self::Redundant => "redundant",
            Self::Independent => "independent",
        }
    }
}

/// One measured triple.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SynergyTriple {
    /// First lens slot name.
    pub a_slot: String,
    /// Second lens slot name.
    pub b_slot: String,
    /// Outcome axis name.
    pub axis: String,
    /// Interaction information `I({A,B};C) − I(A;C) − I(B;C)`, in bits.
    pub ii_bits: f64,
    /// Joint mutual information `I({A,B};C)`, in bits.
    pub joint_mi_bits: f64,
    /// Marginal `I(A;C)`, in bits.
    pub a_mi_bits: f64,
    /// Marginal `I(B;C)`, in bits.
    pub b_mi_bits: f64,
    /// Sign classification.
    pub classification: SynergyClassification,
    /// Number of aligned samples.
    pub n: usize,
    /// Whether the sample is below quorum.
    pub below_quorum: bool,
    /// `Trusted` at or above quorum, else `Provisional`.
    pub trust: TrustTag,
}

/// A synergy card: interaction information over the designed triples.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SynergyCard {
    /// Measured triples, ordered by descending interaction information.
    pub triples: Vec<SynergyTriple>,
    /// The per-triple sample quorum applied.
    pub quorum: u64,
}

/// Resolved configuration for the synergy card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynergyConfig {
    /// Minimum aligned samples before a triple is trusted.
    pub quorum: u64,
}

impl SynergyConfig {
    /// Builds the config from the declared knob default.
    pub fn from_defaults() -> Result<Self> {
        Ok(Self {
            quorum: card_knob_default(ASSAY_SYNERGY_QUORUM_KNOB, ASSAY_DEFAULT_SYNERGY_QUORUM)?,
        })
    }
}

/// Compacts two aligned columns into one joint label per sample (exact).
fn joint_label(a: &[i64], b: &[i64]) -> Vec<i64> {
    let mut ids: BTreeMap<(i64, i64), i64> = BTreeMap::new();
    let mut next = 0i64;
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| {
            *ids.entry((x, y)).or_insert_with(|| {
                let id = next;
                next += 1;
                id
            })
        })
        .collect()
}

/// Builds a synergy card from designed triples.
///
/// Fails closed on an empty outcome, or a triple whose three columns are not the
/// same length.
pub fn build_synergy_card(
    triples: &[SynergyTripleInput],
    cfg: &SynergyConfig,
) -> Result<SynergyCard> {
    let mut out = Vec::with_capacity(triples.len());
    for t in triples {
        let n = t.outcome.len();
        if n == 0 {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!(
                    "triple ({}, {}) about {} carries no samples",
                    t.a_slot, t.b_slot, t.axis
                ),
                "measure a non-empty aligned sample before requesting synergy",
            ));
        }
        if t.a.len() != n || t.b.len() != n {
            return Err(AssayError::new(
                ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID,
                format!(
                    "triple ({}, {}) about {} is ragged: a={} b={} outcome={n}",
                    t.a_slot,
                    t.b_slot,
                    t.axis,
                    t.a.len(),
                    t.b.len()
                ),
                "align both lenses and the outcome to the same sample set before measuring",
            ));
        }
        let joint = joint_label(&t.a, &t.b);
        let joint_mi = mi_discrete(&joint, &t.outcome);
        let a_mi = mi_discrete(&t.a, &t.outcome);
        let b_mi = mi_discrete(&t.b, &t.outcome);
        let ii = joint_mi - a_mi - b_mi;
        let classification = if ii > 0.0 {
            SynergyClassification::Synergistic
        } else if ii < 0.0 {
            SynergyClassification::Redundant
        } else {
            SynergyClassification::Independent
        };
        let below_quorum = (n as u64) < cfg.quorum;
        let trust = if below_quorum {
            TrustTag::Provisional
        } else {
            TrustTag::Trusted
        };
        out.push(SynergyTriple {
            a_slot: t.a_slot.clone(),
            b_slot: t.b_slot.clone(),
            axis: t.axis.clone(),
            ii_bits: ii,
            joint_mi_bits: joint_mi,
            a_mi_bits: a_mi,
            b_mi_bits: b_mi,
            classification,
            n,
            below_quorum,
            trust,
        });
    }
    out.sort_by(|x, y| {
        y.ii_bits
            .partial_cmp(&x.ii_bits)
            .unwrap()
            .then_with(|| x.a_slot.cmp(&y.a_slot))
            .then_with(|| x.b_slot.cmp(&y.b_slot))
            .then_with(|| x.axis.cmp(&y.axis))
    });
    Ok(SynergyCard {
        triples: out,
        quorum: cfg.quorum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SynergyConfig {
        SynergyConfig::from_defaults().unwrap()
    }

    #[test]
    fn xor_is_pure_synergy() {
        // A, B independent fair bits; C = A xor B. Neither A nor B alone tells
        // anything about C, but the pair determines it: II -> +1 bit.
        let n = 400;
        let a: Vec<i64> = (0..n).map(|i| (i % 2) as i64).collect();
        let b: Vec<i64> = (0..n).map(|i| ((i / 2) % 2) as i64).collect();
        let c: Vec<i64> = a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect();
        let card = build_synergy_card(
            &[SynergyTripleInput {
                a_slot: "a".into(),
                a,
                b_slot: "b".into(),
                b,
                axis: "c".into(),
                outcome: c,
            }],
            &cfg(),
        )
        .unwrap();
        let t = &card.triples[0];
        assert!(t.a_mi_bits < 1e-6, "a_mi={}", t.a_mi_bits);
        assert!(t.b_mi_bits < 1e-6, "b_mi={}", t.b_mi_bits);
        assert!(
            (t.joint_mi_bits - 1.0).abs() < 1e-6,
            "joint={}",
            t.joint_mi_bits
        );
        assert!((t.ii_bits - 1.0).abs() < 1e-6, "ii={}", t.ii_bits);
        assert_eq!(t.classification, SynergyClassification::Synergistic);
    }

    #[test]
    fn duplicated_predictors_are_redundant() {
        // A predicts C; B is a copy of A. The pair says no more than A alone, so
        // the shared marginal is double-counted: II < 0 (redundant).
        let n = 400;
        let a: Vec<i64> = (0..n).map(|i| (i % 2) as i64).collect();
        let c = a.clone();
        let b = a.clone();
        let card = build_synergy_card(
            &[SynergyTripleInput {
                a_slot: "a".into(),
                a,
                b_slot: "b".into(),
                b,
                axis: "c".into(),
                outcome: c,
            }],
            &cfg(),
        )
        .unwrap();
        let t = &card.triples[0];
        assert!(t.ii_bits < 0.0, "ii={}", t.ii_bits);
        assert_eq!(t.classification, SynergyClassification::Redundant);
    }

    #[test]
    fn ragged_triple_fails_closed() {
        let e = build_synergy_card(
            &[SynergyTripleInput {
                a_slot: "a".into(),
                a: vec![0, 1, 0],
                b_slot: "b".into(),
                b: vec![0, 1],
                axis: "c".into(),
                outcome: vec![0, 1, 0],
            }],
            &cfg(),
        )
        .unwrap_err();
        assert_eq!(e.code(), ASTRO_ASSAY_MEASUREMENT_INPUT_INVALID);
    }
}
