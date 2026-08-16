//! PH55 ASK execution: retrieval grounding.

use calyx_aster::vault::{AsterVault, SlotVectorResolver, StrictRawSlotResolver};
use calyx_core::{Clock, Result, Seq};
use serde::{Deserialize, Serialize};

use crate::error::{CALYX_ANSWER_SYNTHESIS_UNAVAILABLE, CALYX_INVALID_ARGUMENT, sextant_error};

use super::{AskSpec, ProvenancedRow};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AskResult {
    pub answer: String,
    pub grounding: Vec<ProvenancedRow>,
    pub gaps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_conf: Option<f32>,
}

pub fn ask<C>(vault: &AsterVault<C>, spec: &AskSpec, snapshot_seq: Seq) -> Result<AskResult>
where
    C: Clock,
{
    ask_resolved(vault, spec, snapshot_seq, &StrictRawSlotResolver)
}

/// Executes ASK through one explicit slot-interpretation owner.
///
/// Answer synthesis/oracle execution is not commissioned yet, so this surface
/// refuses before opening Base or any slot column. Retrieval whose only
/// possible consumer is an unconditional error would be discarded corpus work.
pub fn ask_resolved<C, R>(
    _vault: &AsterVault<C>,
    spec: &AskSpec,
    _snapshot_seq: Seq,
    _resolver: &R,
) -> Result<AskResult>
where
    C: Clock,
    R: SlotVectorResolver<C> + ?Sized,
{
    if spec.question.trim().is_empty() {
        return Err(sextant_error(
            CALYX_INVALID_ARGUMENT,
            "ASK question must not be empty",
        ));
    }

    Err(sextant_error(
        CALYX_ANSWER_SYNTHESIS_UNAVAILABLE,
        "ASK answer synthesis/oracle execution is not commissioned; refused before Base, slot, or compressed-generation I/O",
    ))
}
