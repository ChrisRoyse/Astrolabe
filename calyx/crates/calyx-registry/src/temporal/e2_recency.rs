use calyx_core::{Input, Lens, LensId, Modality, Result, SlotShape, SlotVector};
use serde::{Deserialize, Serialize};

use super::{TEMPORAL_FLAGS, TemporalLensFlags, clamp01, parse_i64_timestamp, temporal_lens_id};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecayFunction {
    Linear { max_age_secs: i64 },
    Exponential { half_life_secs: i64 },
    Step,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2RecencyConfig {
    pub decay: DecayFunction,
    pub reference_time: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2RecencyLens {
    id: LensId,
    config: E2RecencyConfig,
}

impl E2RecencyLens {
    pub fn new(config: E2RecencyConfig) -> Self {
        let spec = format!("e2:{:?}:{}", config.decay, config.reference_time);
        Self {
            id: temporal_lens_id(&["E2_Temporal_Recent", &spec]),
            config,
        }
    }

    pub const fn config(&self) -> E2RecencyConfig {
        self.config
    }

    pub const fn flags(&self) -> TemporalLensFlags {
        TEMPORAL_FLAGS
    }

    pub fn score(&self, event_timestamp: i64) -> f32 {
        let age = (self.config.reference_time - event_timestamp).max(0);
        match self.config.decay {
            DecayFunction::Linear { max_age_secs } if max_age_secs > 0 => {
                clamp01(1.0 - age as f32 / max_age_secs as f32)
            }
            DecayFunction::Linear { .. } => 0.0,
            DecayFunction::Exponential { half_life_secs } if half_life_secs > 0 => {
                (-age as f32 * std::f32::consts::LN_2 / half_life_secs as f32).exp()
            }
            DecayFunction::Exponential { .. } => 0.0,
            DecayFunction::Step if age < 3_600 => 0.8,
            DecayFunction::Step if age < 86_400 => 0.5,
            DecayFunction::Step => 0.1,
        }
    }
}

impl Lens for E2RecencyLens {
    fn id(&self) -> LensId {
        self.id
    }

    fn shape(&self) -> SlotShape {
        SlotShape::Dense(1)
    }

    fn modality(&self) -> Modality {
        Modality::Structured
    }

    fn measure(&self, input: &Input) -> Result<SlotVector> {
        let timestamp = parse_i64_timestamp(&input.bytes, "E2")?;
        Ok(SlotVector::Dense {
            dim: 1,
            data: vec![self.score(timestamp)],
        })
    }
}
