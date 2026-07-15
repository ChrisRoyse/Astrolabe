//! Structured verdicts emitted by Ward guard calls.

use calyx_core::SlotId;
use serde::{Deserialize, Serialize};

use crate::profile::{GuardId, NoveltyAction};

/// Per-slot cosine decision for a guarded output.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlotVerdict {
    pub slot: SlotId,
    pub cos: f32,
    pub tau: f32,
    pub pass: bool,
}

/// Aggregate guard decision with the full per-slot decomposition.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GuardVerdict {
    pub guard_id: GuardId,
    pub overall_pass: bool,
    #[serde(default)]
    pub provisional: bool,
    pub per_slot: Vec<SlotVerdict>,
    pub action: Option<NoveltyAction>,
}

impl GuardVerdict {
    /// Returns every slot verdict that failed its per-slot tau.
    pub fn failing_slots(&self) -> Vec<&SlotVerdict> {
        self.per_slot.iter().filter(|slot| !slot.pass).collect()
    }

    /// Returns the full per-slot breakdown for pass and fail outcomes.
    pub fn all_slot_details(&self) -> &[SlotVerdict] {
        &self.per_slot
    }
}
