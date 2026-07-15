use calyx_core::{
    Anchor, AnchorKind, AnchorValue, CalyxError, Constellation, CxId, Result, dense_cosine,
};
use serde::{Deserialize, Serialize};

use super::{DedupAction, DedupPolicy};

pub const ANCHOR_VECTOR_TAU: f32 = 0.70;

const CONTESTED_WITH_KEY_PREFIX: &[u8] = b"dedup:contested_with:";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AnchorConflictResult {
    Compatible,
    Conflicting {
        anchor_type: AnchorKind,
        reason: ConflictReason,
    },
    NoAnchor,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ConflictReason {
    OppositeValue,
    IncompatibleVector { cos: f32 },
    ExclusiveTag,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContestedWith {
    pub contested_with: CxId,
    pub anchor_type: AnchorKind,
    pub reason: ConflictReason,
}

pub fn check_anchor_conflict(
    new_cx: &Constellation,
    existing_cx: &Constellation,
) -> AnchorConflictResult {
    let mut shared_anchor = false;
    for new_anchor in &new_cx.anchors {
        for existing_anchor in existing_cx
            .anchors
            .iter()
            .filter(|anchor| anchor.kind == new_anchor.kind)
        {
            shared_anchor = true;
            if let Some(reason) = conflict_reason(new_anchor, existing_anchor) {
                return AnchorConflictResult::Conflicting {
                    anchor_type: new_anchor.kind.clone(),
                    reason,
                };
            }
        }
    }
    if shared_anchor {
        AnchorConflictResult::Compatible
    } else {
        AnchorConflictResult::NoAnchor
    }
}

pub(crate) fn is_recurrence_series_policy(policy: &DedupPolicy) -> bool {
    matches!(
        policy,
        DedupPolicy::TctCosine(config) if config.action == DedupAction::RecurrenceSeries
    )
}

pub fn contested_with_key(cx_id: CxId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CONTESTED_WITH_KEY_PREFIX.len() + 16);
    key.extend_from_slice(CONTESTED_WITH_KEY_PREFIX);
    key.extend_from_slice(cx_id.as_bytes());
    key
}

pub fn encode_contested_with(value: &ContestedWith) -> Result<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|error| CalyxError::aster_corrupt_shard(format!("encode contested row: {error}")))
}

pub fn decode_contested_with(bytes: &[u8]) -> Result<ContestedWith> {
    serde_json::from_slice(bytes)
        .map_err(|error| CalyxError::aster_corrupt_shard(format!("decode contested row: {error}")))
}

fn conflict_reason(new_anchor: &Anchor, existing_anchor: &Anchor) -> Option<ConflictReason> {
    if new_anchor.value == existing_anchor.value {
        return None;
    }
    match &new_anchor.kind {
        AnchorKind::SpeakerMatch => Some(ConflictReason::OppositeValue),
        AnchorKind::StyleHold => style_conflict_reason(&new_anchor.value, &existing_anchor.value),
        AnchorKind::Label(_) => Some(ConflictReason::ExclusiveTag),
        _ => Some(ConflictReason::ExclusiveTag),
    }
}

fn style_conflict_reason(left: &AnchorValue, right: &AnchorValue) -> Option<ConflictReason> {
    let (AnchorValue::Vector(left), AnchorValue::Vector(right)) = (left, right) else {
        return Some(ConflictReason::ExclusiveTag);
    };
    let cos = dense_cosine(left, right)
        .filter(|cos| cos.is_finite())
        .unwrap_or(-1.0);
    (cos < ANCHOR_VECTOR_TAU).then_some(ConflictReason::IncompatibleVector { cos })
}
