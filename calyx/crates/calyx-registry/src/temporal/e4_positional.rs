use calyx_core::{Input, Lens, LensId, Modality, Result, SlotShape, SlotVector};
use serde::{Deserialize, Serialize};

use super::{TEMPORAL_FLAGS, TemporalLensFlags, parse_position_total, temporal_lens_id};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SequenceDirection {
    Forward,
    Backward,
    Both,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiAnchorMode {
    First,
    Last,
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceOptions {
    pub direction: SequenceDirection,
    pub multi_anchor: MultiAnchorMode,
}

impl Default for SequenceOptions {
    fn default() -> Self {
        Self {
            direction: SequenceDirection::Both,
            multi_anchor: MultiAnchorMode::All,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct E4PositionalConfig {
    pub options: SequenceOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E4PositionalLens {
    id: LensId,
    config: E4PositionalConfig,
}

impl E4PositionalLens {
    pub fn new(config: E4PositionalConfig) -> Self {
        let spec = format!("{:?}", config.options);
        Self {
            id: temporal_lens_id(&["E4_Temporal_Positional", &spec]),
            config,
        }
    }

    pub const fn flags(&self) -> TemporalLensFlags {
        TEMPORAL_FLAGS
    }

    pub fn encode(&self, position: u64, total: u64) -> [f32; 4] {
        let denominator = total.max(1) as f32;
        let pos_ratio = (position as f32 / denominator).clamp(0.0, 1.0);
        let bwd_ratio = 1.0 - pos_ratio;
        let mut data = [
            (pos_ratio * std::f32::consts::PI).sin(),
            (pos_ratio * std::f32::consts::PI).cos(),
            (bwd_ratio * std::f32::consts::PI).sin(),
            (bwd_ratio * std::f32::consts::PI).cos(),
        ];
        match self.config.options.direction {
            SequenceDirection::Forward => {
                data[2] = 0.0;
                data[3] = 0.0;
            }
            SequenceDirection::Backward => {
                data[0] = 0.0;
                data[1] = 0.0;
            }
            SequenceDirection::Both => {}
        }
        data
    }
}

impl Lens for E4PositionalLens {
    fn id(&self) -> LensId {
        self.id
    }

    fn shape(&self) -> SlotShape {
        SlotShape::Dense(4)
    }

    fn modality(&self) -> Modality {
        Modality::Structured
    }

    fn measure(&self, input: &Input) -> Result<SlotVector> {
        let (position, total) = parse_position_total(&input.bytes, "E4")?;
        Ok(SlotVector::Dense {
            dim: 4,
            data: self.encode(position, total).to_vec(),
        })
    }
}
