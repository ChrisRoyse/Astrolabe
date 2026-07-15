//! Per-slot search timing extracted from search trace events into the matrix
//! artifact (issue #1102): FSV asserts performance budgets from JSON instead
//! of scraping stderr.

use calyx_search::SearchTraceEvent;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ProbeMatrixSlotSearchDiagnostic {
    pub slot: u16,
    pub hit_count: usize,
    /// Wall-clock spent scoring this slot when the slot-result cache missed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u128>,
    /// The original scoring cost replayed by a slot-result cache hit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_elapsed_ms: Option<u128>,
    pub cache_hit: bool,
}

pub(super) fn slot_search_diagnostics(
    events: &[SearchTraceEvent],
) -> Vec<ProbeMatrixSlotSearchDiagnostic> {
    let mut out = Vec::new();
    for event in events {
        let Some(slot) = event.slot else {
            continue;
        };
        match event.phase {
            "search_slot.done" => out.push(ProbeMatrixSlotSearchDiagnostic {
                slot: slot.get(),
                hit_count: event.count.unwrap_or(0),
                elapsed_ms: detail_u128(event.detail.as_deref(), "slot_elapsed_ms"),
                source_elapsed_ms: None,
                cache_hit: false,
            }),
            "search_slot.cache_hit" => out.push(ProbeMatrixSlotSearchDiagnostic {
                slot: slot.get(),
                hit_count: event.count.unwrap_or(0),
                elapsed_ms: None,
                source_elapsed_ms: detail_u128(event.detail.as_deref(), "source_slot_elapsed_ms"),
                cache_hit: true,
            }),
            _ => {}
        }
    }
    out
}

fn detail_u128(detail: Option<&str>, field: &str) -> Option<u128> {
    detail?
        .split_whitespace()
        .find_map(|part| part.strip_prefix(field)?.strip_prefix('='))
        .and_then(|value| value.parse::<u128>().ok())
}
