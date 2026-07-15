//! Fail-closed search performance budgets for probe-matrix (issue #1102).
//!
//! `--search-miss-budget-ms` bounds every variant whose slot-result cache
//! missed (full scoring ran); `--search-hit-budget-ms` bounds every variant
//! served from the slot-result cache. A breach fails the run with a
//! structured error after the matrix artifact is persisted, so FSV can read
//! the regressing timings from JSON.

use calyx_core::CalyxError;

use super::ProbeMatrixArgs;
use super::diagnostics::ProbeMatrixVariantDiagnostic;
use crate::error::{CliError, CliResult};

pub(super) const PERF_BUDGET_CODE: &str = "CALYX_PROBE_MATRIX_PERF_BUDGET_EXCEEDED";
const PERF_BUDGET_REMEDIATION: &str = "inspect diagnostics.variant_guard_counts[].slot_searches and search_done_elapsed_ms in the persisted matrix artifact to find the regressing slot, then fix the regression or recalibrate the budget flags";

pub(super) fn enforce_search_perf_budgets(
    guards: &[ProbeMatrixVariantDiagnostic],
    args: &ProbeMatrixArgs,
) -> CliResult {
    let miss_budget_ms = args.search_miss_budget_ms;
    let hit_budget_ms = args.search_hit_budget_ms;
    if miss_budget_ms.is_none() && hit_budget_ms.is_none() {
        return Ok(());
    }
    let mut breaches = Vec::new();
    for guard in guards {
        let is_miss = guard.search_cache_miss_count > 0;
        let budget = if is_miss {
            miss_budget_ms
        } else {
            hit_budget_ms
        };
        let Some(budget) = budget else {
            continue;
        };
        let Some(elapsed_ms) = guard.search_done_elapsed_ms else {
            return Err(perf_budget_error(format!(
                "variant {} has no search_done_elapsed_ms in diagnostics; cannot verify the search perf budget",
                guard.variant_id
            )));
        };
        if elapsed_ms > u128::from(budget) {
            breaches.push(format!(
                "variant {} ({}) search_done_elapsed_ms={elapsed_ms} > budget {budget}ms",
                guard.variant_id,
                if is_miss { "cache miss" } else { "cache hit" },
            ));
        }
    }
    if breaches.is_empty() {
        return Ok(());
    }
    Err(perf_budget_error(format!(
        "search perf budget exceeded for {} of {} variants: {}",
        breaches.len(),
        guards.len(),
        breaches.join("; ")
    )))
}

fn perf_budget_error(message: impl Into<String>) -> CliError {
    CalyxError {
        code: PERF_BUDGET_CODE,
        message: message.into(),
        remediation: PERF_BUDGET_REMEDIATION,
    }
    .into()
}
