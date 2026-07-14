//! Search A/B non-regression + latency instruments (P6.6, blueprint
//! `12_SEARCH.md`, #42).
//!
//! The deterministic measurement half of the P6 search exit gate. Where
//! [`crate::search`] fuses rankings and [`crate::search_index`] builds the
//! per-slot indexes, this module *scores* a fused ranking against the legacy
//! path and against ground truth, and summarizes query latency — the exact
//! numbers the DoD names: `overlap@10`, `recall@10`, and warm `p99`.
//!
//! Everything here is pure integer/rational math over already-materialized
//! ranked id lists and latency samples. It never *runs* a search: the harness
//! that feeds it real fused hits and real legacy `search_graph` hits lives in
//! the server surface (that wiring is the remaining server-side DoD; this is the
//! reusable, unit-tested core it consumes, split out the same way the fusion
//! core was split from the MCP surface). Because the inputs are already
//! ordered, the metrics are worker-count invariant: identical id lists =>
//! identical scores, on every platform.
//!
//! Honesty posture: this scores *whatever real lists it is given*. It contains
//! no model of the legacy engine — comparing a fused ranking against a Rust
//! re-implementation of CBM would measure the model, not parity, so the legacy
//! list must always come from the real `search_graph` BM25 path (the fixed
//! "first-keyword-sorts" legacy behavior, preserved as a compat mode).

use std::collections::BTreeSet;

use crate::search::SearchError;

/// Registry version for the declared evaluation knobs below.
pub const SEARCH_EVAL_KNOB_REGISTRY_VERSION: &str = "astro.weave.search_eval_knobs.v1";

/// Fail-closed: a metric was asked for with no admissible input (k=0, no ground
/// truth, empty latency sample) — never a fabricated 0.0 or 1.0 score.
pub const ASTRO_SEARCH_EVAL_INPUT: &str = "ASTRO_SEARCH_EVAL_INPUT";
/// Fail-closed: the fused ranking regressed against the legacy path or fell
/// below the declared recall floor (the P6 exit gate refusing to promote).
pub const ASTRO_SEARCH_EVAL_REGRESSION: &str = "ASTRO_SEARCH_EVAL_REGRESSION";

/// Fixed-point scale for ratio metrics (per-mille: 1000 == 1.0). Chosen (not a
/// float) so scores are bit-identical across platforms and hashable into the
/// ledger, consistent with the millis convention in [`crate::search`].
pub const METRIC_SCALE_PERMILLE: u64 = 1_000;

/// Minimum admissible fused `recall@k`, per-mille. Declared knob: the blueprint
/// §12/§14 recall gate is `recall@k >= 0.90`; below it the search change must
/// not promote. A guardrail, not a measurement.
pub const MIN_RECALL_AT_K_PERMILLE: u64 = 900;

/// Non-regression tolerance in per-mille: how far below the legacy path the
/// fused `recall@k` may sit and still count as "no regression". Declared knob;
/// the exit gate is strict (fused must at least match legacy), so this is `0`.
/// The blueprint's 5% anneal hysteresis governs *promotion* of a winner, a
/// different decision than this *non-regression* gate.
pub const NON_REGRESSION_TOLERANCE_PERMILLE: u64 = 0;

/// Warm `p99` latency budget in nanoseconds. Declared knob: the P6.6 DoD fixes
/// the warm M-corpus target at `p99 <= 50ms` (the blueprint's `p99 > 200ms`
/// tripwire is the looser auto-revert bound, not this exit target).
pub const SEARCH_P99_BUDGET_NANOS: u64 = 50_000_000;

/// Set overlap of the top-`k` of two rankings, per-mille of `k`:
/// `|top_k(a) ∩ top_k(b)| * 1000 / k`. This is the A/B "how much did fusion move
/// results" diagnostic — 1000 means fusion returned exactly the legacy top-`k`
/// (as a set), 0 means it fully reshuffled them out of the window.
///
/// The denominator is the requested cutoff `k`, so a ranking that returns fewer
/// than `k` hits is honestly penalized (it genuinely overlaps less), and both
/// sides are always scored the same way. Duplicate ids inside one list are an
/// input error (fail-closed) — a slot ranking must be duplicate-free, and so
/// must a legacy result page.
pub fn overlap_at_k_permille(a: &[String], b: &[String], k: usize) -> Result<u64, SearchError> {
    if k == 0 {
        return Err(SearchError::new(
            ASTRO_SEARCH_EVAL_INPUT,
            "overlap@k requested with k=0".to_string(),
            "Score overlap at a positive cutoff (e.g. k=10).",
        ));
    }
    let set_a = top_k_set(a, k, "overlap@k list A")?;
    let set_b = top_k_set(b, k, "overlap@k list B")?;
    let intersection = set_a.intersection(&set_b).count() as u64;
    Ok(intersection.saturating_mul(METRIC_SCALE_PERMILLE) / k as u64)
}

/// `recall@k`, per-mille: `|top_k(retrieved) ∩ relevant| * 1000 / |relevant|`.
///
/// Fail-closed when `relevant` is empty: recall is undefined with no ground
/// truth, and returning `1000` ("perfect") would be a fabricated pass. The
/// relevant set is deduplicated by construction (a `BTreeSet`), so its size is
/// the true number of distinct targets; capping the intersection at that size
/// keeps recall in `[0, 1000]` even if `retrieved` somehow lists a target twice
/// (which is itself refused below).
pub fn recall_at_k_permille(
    retrieved: &[String],
    relevant: &BTreeSet<String>,
    k: usize,
) -> Result<u64, SearchError> {
    if k == 0 {
        return Err(SearchError::new(
            ASTRO_SEARCH_EVAL_INPUT,
            "recall@k requested with k=0".to_string(),
            "Score recall at a positive cutoff (e.g. k=10).",
        ));
    }
    if relevant.is_empty() {
        return Err(SearchError::new(
            ASTRO_SEARCH_EVAL_INPUT,
            "recall@k requested with an empty relevant (ground-truth) set".to_string(),
            "Supply at least one known-relevant symbol id; recall is undefined without ground \
             truth and must not be reported as a pass.",
        ));
    }
    let top = top_k_set(retrieved, k, "recall@k retrieved list")?;
    let hits = top.intersection(relevant).count() as u64;
    Ok(hits.saturating_mul(METRIC_SCALE_PERMILLE) / relevant.len() as u64)
}

/// Deduplicated top-`k` id set, refusing duplicate ids fail-closed (a ranking
/// with a repeated id is a malformed input, not a silently-collapsed set).
fn top_k_set(ids: &[String], k: usize, what: &str) -> Result<BTreeSet<String>, SearchError> {
    let mut set = BTreeSet::new();
    for id in ids.iter().take(k) {
        if !set.insert(id.clone()) {
            return Err(SearchError::new(
                ASTRO_SEARCH_EVAL_INPUT,
                format!("{what} contains duplicate id {id:?} within the top {k}"),
                "Ranked result lists must be duplicate-free before scoring.",
            ));
        }
    }
    Ok(set)
}

/// The A/B non-regression verdict for one query (or one averaged corpus point):
/// the fused and legacy `recall@k`, their set overlap, and whether the fused
/// path cleared both the legacy floor (no regression) and the absolute recall
/// floor knob.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct NonRegressionVerdict {
    pub k: usize,
    pub fused_recall_permille: u64,
    pub legacy_recall_permille: u64,
    pub overlap_permille: u64,
    /// `true` iff fused recall >= legacy recall - tolerance AND fused recall >=
    /// the declared floor.
    pub non_regression: bool,
    /// `true` iff the fused path strictly beats the legacy path on recall (the
    /// blueprint's "fused search wins A/B on recall@10" success bit).
    pub fused_wins: bool,
}

impl NonRegressionVerdict {
    /// Scores one query: fused and legacy retrieved lists against a shared
    /// ground-truth `relevant` set, at cutoff `k`, under the declared knobs.
    pub fn evaluate(
        fused: &[String],
        legacy: &[String],
        relevant: &BTreeSet<String>,
        k: usize,
    ) -> Result<Self, SearchError> {
        let fused_recall = recall_at_k_permille(fused, relevant, k)?;
        let legacy_recall = recall_at_k_permille(legacy, relevant, k)?;
        let overlap = overlap_at_k_permille(fused, legacy, k)?;
        let floor = legacy_recall.saturating_sub(NON_REGRESSION_TOLERANCE_PERMILLE);
        let non_regression = fused_recall >= floor && fused_recall >= MIN_RECALL_AT_K_PERMILLE;
        Ok(Self {
            k,
            fused_recall_permille: fused_recall,
            legacy_recall_permille: legacy_recall,
            overlap_permille: overlap,
            non_regression,
            fused_wins: fused_recall > legacy_recall,
        })
    }

    /// The exit-gate assertion: turns a regression into a fail-closed refusal
    /// carrying a deficit card, so a promoting caller cannot ignore it.
    pub fn require_non_regression(&self) -> Result<(), SearchError> {
        if self.non_regression {
            return Ok(());
        }
        Err(SearchError::new(
            ASTRO_SEARCH_EVAL_REGRESSION,
            format!(
                "fused recall@{k} = {fused}/1000 regressed against legacy {legacy}/1000 \
                 (tolerance {tol}/1000) or fell below the floor {floor}/1000; overlap@{k} = \
                 {overlap}/1000",
                k = self.k,
                fused = self.fused_recall_permille,
                legacy = self.legacy_recall_permille,
                tol = NON_REGRESSION_TOLERANCE_PERMILLE,
                floor = MIN_RECALL_AT_K_PERMILLE,
                overlap = self.overlap_permille,
            ),
            "Do not promote this search change: raise fused recall to at least the legacy path \
             and the declared floor, or record a tracked exception before the P6 exit gate.",
        ))
    }
}

/// A deterministic latency summary over a set of per-query samples (nanoseconds).
///
/// Percentiles use the nearest-rank method with the exact index convention the
/// Calyx A/B runner already uses (`idx = ceil(n*p/100) - 1`), so a warm-run p99
/// here is directly comparable to the anneal tripwire's p99 — no second
/// percentile definition drifting from the first.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LatencySummary {
    pub sample_count: usize,
    pub p50_nanos: u64,
    pub p95_nanos: u64,
    pub p99_nanos: u64,
    pub max_nanos: u64,
}

impl LatencySummary {
    /// Summarizes latency samples. Fail-closed on an empty sample set: a p99
    /// over zero measurements is not a real number and must not read as `0ns`
    /// "instant".
    pub fn from_samples(samples: &[u64]) -> Result<Self, SearchError> {
        if samples.is_empty() {
            return Err(SearchError::new(
                ASTRO_SEARCH_EVAL_INPUT,
                "latency summary requested over zero samples".to_string(),
                "Measure at least one warm query before summarizing p99.",
            ));
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        Ok(Self {
            sample_count: sorted.len(),
            p50_nanos: percentile_nearest_rank(&sorted, 50),
            p95_nanos: percentile_nearest_rank(&sorted, 95),
            p99_nanos: percentile_nearest_rank(&sorted, 99),
            max_nanos: *sorted.last().expect("non-empty checked above"),
        })
    }

    /// Whether warm p99 is within the declared budget knob.
    pub fn meets_p99_budget(&self, budget_nanos: u64) -> bool {
        self.p99_nanos <= budget_nanos
    }

    /// The p99 exit-gate assertion against a declared budget, fail-closed with a
    /// deficit card naming the observed p99 and the budget.
    pub fn require_p99_within(&self, budget_nanos: u64) -> Result<(), SearchError> {
        if self.meets_p99_budget(budget_nanos) {
            return Ok(());
        }
        Err(SearchError::new(
            ASTRO_SEARCH_EVAL_REGRESSION,
            format!(
                "warm p99 = {}ns over {} samples exceeds the declared budget {}ns",
                self.p99_nanos, self.sample_count, budget_nanos
            ),
            "Reduce per-slot ef/k, shrink the fused slot set, or warm the indexes before the \
             benchmark; do not relax the budget knob without a tracked measurement.",
        ))
    }
}

/// Nearest-rank percentile over a pre-sorted ascending slice: the value at
/// 1-based rank `ceil(n * p / 100)`, returned 0-based. Matches
/// `calyx-anneal`'s A/B p99 index exactly.
fn percentile_nearest_rank(sorted_ascending: &[u64], p: u64) -> u64 {
    debug_assert!(!sorted_ascending.is_empty());
    let n = sorted_ascending.len();
    let idx = (n as u64 * p).div_ceil(100).saturating_sub(1) as usize;
    sorted_ascending[idx.min(n - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn relevant_set(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn overlap_at_k_is_hand_computable_and_symmetric() {
        // top-5 of each; intersection {b,c,e} = 3 of 5 => 600 per-mille.
        let a = ids(&["a", "b", "c", "d", "e"]);
        let b = ids(&["e", "c", "b", "x", "y"]);
        assert_eq!(overlap_at_k_permille(&a, &b, 5).unwrap(), 3 * 1000 / 5);
        // Overlap is symmetric on the set.
        assert_eq!(
            overlap_at_k_permille(&a, &b, 5).unwrap(),
            overlap_at_k_permille(&b, &a, 5).unwrap()
        );
        // Cutoff below the divergence: top-3 of a = {a,b,c}, of b = {e,c,b} =>
        // intersection {b,c} = 2 of 3.
        assert_eq!(overlap_at_k_permille(&a, &b, 3).unwrap(), 2 * 1000 / 3);
        // Identical lists => full overlap.
        assert_eq!(overlap_at_k_permille(&a, &a, 5).unwrap(), 1000);
    }

    #[test]
    fn overlap_penalizes_short_lists_against_the_cutoff() {
        // a returns only 2 hits; even a perfect subset of b overlaps 2/10.
        let a = ids(&["a", "b"]);
        let b = ids(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]);
        assert_eq!(overlap_at_k_permille(&a, &b, 10).unwrap(), 2 * 1000 / 10);
    }

    #[test]
    fn recall_at_k_is_hand_computable_and_fail_closed() {
        let retrieved = ids(&["x", "hit1", "y", "hit2", "z"]);
        let relevant = relevant_set(&["hit1", "hit2", "hit3"]);
        // top-5 retrieves hit1,hit2 of 3 relevant => 666 per-mille (floor).
        assert_eq!(
            recall_at_k_permille(&retrieved, &relevant, 5).unwrap(),
            2 * 1000 / 3
        );
        // Cutoff k=2 only sees {x,hit1} => 1 of 3.
        assert_eq!(
            recall_at_k_permille(&retrieved, &relevant, 2).unwrap(),
            1000 / 3
        );
        // Empty ground truth is refused, never a fabricated perfect score.
        let err = recall_at_k_permille(&retrieved, &BTreeSet::new(), 5).unwrap_err();
        assert_eq!(err.code(), ASTRO_SEARCH_EVAL_INPUT);
        // k=0 refused.
        let err = recall_at_k_permille(&retrieved, &relevant, 0).unwrap_err();
        assert_eq!(err.code(), ASTRO_SEARCH_EVAL_INPUT);
    }

    #[test]
    fn duplicate_ids_in_a_ranking_are_refused() {
        let dup = ids(&["a", "a", "b"]);
        let clean = ids(&["a", "b", "c"]);
        assert_eq!(
            overlap_at_k_permille(&dup, &clean, 3).unwrap_err().code(),
            ASTRO_SEARCH_EVAL_INPUT
        );
        let relevant = relevant_set(&["a"]);
        assert_eq!(
            recall_at_k_permille(&dup, &relevant, 3).unwrap_err().code(),
            ASTRO_SEARCH_EVAL_INPUT
        );
    }

    #[test]
    fn non_regression_verdict_gates_fused_against_legacy_and_floor() {
        let relevant = relevant_set(&["r1", "r2", "r3", "r4", "r5"]);
        // Fused finds 5/5 (1000), legacy finds 4/5 (800): fused wins, passes.
        let fused = ids(&["r1", "r2", "r3", "r4", "r5"]);
        let legacy = ids(&["r1", "r2", "r3", "r4", "z"]);
        let verdict = NonRegressionVerdict::evaluate(&fused, &legacy, &relevant, 5).unwrap();
        assert_eq!(verdict.fused_recall_permille, 1000);
        assert_eq!(verdict.legacy_recall_permille, 800);
        assert!(verdict.non_regression);
        assert!(verdict.fused_wins);
        verdict.require_non_regression().unwrap();

        // Fused regresses to 3/5 (600) below legacy 4/5 and below the 900 floor.
        let fused_bad = ids(&["r1", "r2", "r3", "z1", "z2"]);
        let verdict = NonRegressionVerdict::evaluate(&fused_bad, &legacy, &relevant, 5).unwrap();
        assert_eq!(verdict.fused_recall_permille, 600);
        assert!(!verdict.non_regression);
        assert!(!verdict.fused_wins);
        let err = verdict.require_non_regression().unwrap_err();
        assert_eq!(err.code(), ASTRO_SEARCH_EVAL_REGRESSION);
        assert!(!err.remediation().is_empty());
    }

    #[test]
    fn non_regression_floor_binds_even_when_fused_matches_legacy() {
        // Both paths are weak (2/5 = 400): no regression vs each other, but the
        // absolute recall floor (900) still refuses promotion.
        let relevant = relevant_set(&["r1", "r2", "r3", "r4", "r5"]);
        let fused = ids(&["r1", "r2", "z", "y", "x"]);
        let legacy = ids(&["r1", "r2", "q", "p", "o"]);
        let verdict = NonRegressionVerdict::evaluate(&fused, &legacy, &relevant, 5).unwrap();
        assert_eq!(verdict.fused_recall_permille, 400);
        assert_eq!(verdict.legacy_recall_permille, 400);
        assert!(!verdict.non_regression, "floor must bind");
        assert_eq!(
            verdict.require_non_regression().unwrap_err().code(),
            ASTRO_SEARCH_EVAL_REGRESSION
        );
    }

    #[test]
    fn latency_percentiles_are_hand_computable_nearest_rank() {
        // 100 samples 1..=100 ns. nearest-rank: p50 idx=ceil(50)-1=49 => 50,
        // p95 idx=ceil(95)-1=94 => 95, p99 idx=ceil(99)-1=98 => 99.
        let samples: Vec<u64> = (1..=100).collect();
        let summary = LatencySummary::from_samples(&samples).unwrap();
        assert_eq!(summary.sample_count, 100);
        assert_eq!(summary.p50_nanos, 50);
        assert_eq!(summary.p95_nanos, 95);
        assert_eq!(summary.p99_nanos, 99);
        assert_eq!(summary.max_nanos, 100);
        // Ordering of the input does not change the summary (sorted internally).
        let mut shuffled = samples.clone();
        shuffled.reverse();
        assert_eq!(LatencySummary::from_samples(&shuffled).unwrap(), summary);
    }

    #[test]
    fn latency_single_sample_and_empty_edges() {
        // Single sample: every percentile is that sample.
        let one = LatencySummary::from_samples(&[42]).unwrap();
        assert_eq!(
            (one.p50_nanos, one.p95_nanos, one.p99_nanos, one.max_nanos),
            (42, 42, 42, 42)
        );
        // Empty is refused (no fabricated 0ns p99).
        assert_eq!(
            LatencySummary::from_samples(&[]).unwrap_err().code(),
            ASTRO_SEARCH_EVAL_INPUT
        );
    }

    #[test]
    fn p99_budget_gate_passes_and_fails_closed() {
        // All warm samples well under 50ms => passes.
        let fast: Vec<u64> = (0..1_000).map(|i| 1_000_000 + i).collect(); // ~1ms
        let summary = LatencySummary::from_samples(&fast).unwrap();
        assert!(summary.meets_p99_budget(SEARCH_P99_BUDGET_NANOS));
        summary.require_p99_within(SEARCH_P99_BUDGET_NANOS).unwrap();
        // One slow tail past budget at p99 => refused.
        let mut slow = fast.clone();
        for sample in slow.iter_mut().take(20) {
            *sample = 80_000_000; // 80ms tail, > 1% of samples
        }
        let summary = LatencySummary::from_samples(&slow).unwrap();
        assert!(!summary.meets_p99_budget(SEARCH_P99_BUDGET_NANOS));
        let err = summary
            .require_p99_within(SEARCH_P99_BUDGET_NANOS)
            .unwrap_err();
        assert_eq!(err.code(), ASTRO_SEARCH_EVAL_REGRESSION);
    }

    #[test]
    fn metrics_are_deterministic_across_repeated_scoring() {
        let fused = ids(&["r1", "a", "r2", "b", "r3"]);
        let legacy = ids(&["r1", "r2", "c", "d", "r3"]);
        let relevant = relevant_set(&["r1", "r2", "r3"]);
        let first = NonRegressionVerdict::evaluate(&fused, &legacy, &relevant, 5).unwrap();
        for _ in 0..16 {
            let again = NonRegressionVerdict::evaluate(&fused, &legacy, &relevant, 5).unwrap();
            assert_eq!(first, again, "verdict must be deterministic");
        }
    }
}
