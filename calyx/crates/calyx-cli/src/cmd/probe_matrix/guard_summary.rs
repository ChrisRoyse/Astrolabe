use std::collections::BTreeSet;

use super::diagnostics::ProbeMatrixVariantDiagnostic;

/// Aggregate evidence that the in-region guard filtered every candidate the
/// search path actually retrieved, across the completed variants. Used to fail
/// closed with a specific diagnosis instead of a generic empty-benchmark error
/// (issue #1088).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GuardFilteredAllSummary {
    pub variant_count: usize,
    pub retrieved_candidate_count: usize,
    pub filtered_candidate_count: usize,
    pub observed_best_cosine_min: Option<String>,
    pub observed_best_cosine_max: Option<String>,
    pub tau: Option<String>,
    pub reasons: BTreeSet<String>,
}

/// Returns `Some` only when at least one completed variant retrieved candidates
/// AND every variant that retrieved candidates had all of them filtered by the
/// in-region guard (prefilter or full cosine). `None` means the guard is not the
/// reason the benchmark lacks accepted hits.
pub(super) fn guard_filtered_all_summary(
    guards: &[ProbeMatrixVariantDiagnostic],
) -> Option<GuardFilteredAllSummary> {
    let mut retrieved_total = 0usize;
    let mut filtered_total = 0usize;
    let mut variants_with_candidates = 0usize;
    let mut reasons = BTreeSet::new();
    let mut cosine_mins = Vec::new();
    let mut cosine_maxes = Vec::new();
    let mut tau = None;
    for guard in guards {
        // Candidates the search path actually retrieved for this variant, before
        // the guard: the prefilter input count is the ground truth.
        let retrieved = guard.guard_prefilter_input_count.unwrap_or(0);
        if retrieved == 0 {
            // No candidates retrieved: this variant's emptiness is not a guard
            // artifact, so it neither triggers nor blocks the diagnosis.
            continue;
        }
        variants_with_candidates += 1;
        // Survivors after the full in-region guard (post-guard hit count),
        // falling back to the prefilter output when the guard stage did not run.
        let survivors = guard
            .post_guard_hit_count
            .or(guard.guard_prefilter_output_count)
            .unwrap_or(0);
        if survivors > 0 {
            // At least one variant kept in-region candidates: the guard is not
            // filtering everything, so this is not the guard-filtered-all case.
            return None;
        }
        retrieved_total += retrieved;
        filtered_total += guard
            .guard_prefilter_filtered_count
            .unwrap_or(retrieved)
            .max(guard.guard_filtered_hit_count.unwrap_or(0));
        if let Some(reason) = &guard.guard_zero_hit_reason {
            reasons.insert(reason.clone());
        }
        if tau.is_none() {
            tau = guard.guard_tau.clone();
        }
        if let Some(min) = &guard.guard_best_cosine_min {
            cosine_mins.push(min.clone());
        }
        if let Some(max) = &guard.guard_best_cosine_max {
            cosine_maxes.push(max.clone());
        }
    }
    if variants_with_candidates == 0 {
        return None;
    }
    Some(GuardFilteredAllSummary {
        variant_count: variants_with_candidates,
        retrieved_candidate_count: retrieved_total,
        filtered_candidate_count: filtered_total,
        observed_best_cosine_min: cosine_mins.into_iter().min(),
        observed_best_cosine_max: cosine_maxes.into_iter().max(),
        tau,
        reasons,
    })
}

