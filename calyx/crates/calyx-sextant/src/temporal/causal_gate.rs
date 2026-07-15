use calyx_core::Result;
use serde::{Deserialize, Serialize};

use crate::hit::Hit;

use super::{
    BoostConfig, Clock, TemporalPolicy, TimeWindow, apply_temporal_boost, filter_hits_by_window,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalConfidence {
    High,
    Neutral,
    Low,
    #[default]
    Absent,
}

impl CausalConfidence {
    pub const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct CausalGateEvidence {
    pub confidence: CausalConfidence,
    pub multiplier: f32,
}

#[inline]
pub fn causal_gate_mult(confidence: CausalConfidence, cfg: &BoostConfig) -> f32 {
    match confidence {
        CausalConfidence::High => cfg.causal_high_mult,
        CausalConfidence::Low => cfg.causal_low_mult,
        CausalConfidence::Neutral | CausalConfidence::Absent => 1.0,
    }
}

pub fn derive_causal_confidence(hit: &Hit) -> CausalConfidence {
    if !hit.causal_confidence.is_absent() {
        return hit.causal_confidence;
    }
    let Some(guard) = &hit.guard else {
        return CausalConfidence::Absent;
    };
    if guard.verdict.overall_pass && !guard.verdict.provisional {
        CausalConfidence::High
    } else {
        CausalConfidence::Low
    }
}

pub fn apply_causal_gate(mut hits: Vec<Hit>, cfg: &BoostConfig) -> Result<Vec<Hit>> {
    cfg.validate()?;
    for hit in &mut hits {
        let confidence = derive_causal_confidence(hit);
        let multiplier = causal_gate_mult(confidence, cfg);
        hit.score *= multiplier;
        hit.causal_confidence = confidence;
        hit.causal_gate = Some(CausalGateEvidence {
            confidence,
            multiplier,
        });
    }

    hits.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.rank.cmp(&b.rank))
            .then_with(|| a.cx_id.to_string().cmp(&b.cx_id.to_string()))
    });
    for (index, hit) in hits.iter_mut().enumerate() {
        hit.rank = index + 1;
    }
    Ok(hits)
}

pub fn temporal_search_pipeline(
    hits: Vec<Hit>,
    window: &TimeWindow,
    policy: &TemporalPolicy,
    tz_offset_secs: i32,
    clock: &dyn Clock,
) -> Result<Vec<Hit>> {
    let filtered = filter_hits_by_window(hits, window);
    let boosted = apply_temporal_boost(filtered, policy, clock.now_secs(), tz_offset_secs)?;
    apply_causal_gate(boosted, &policy.boost)
}
