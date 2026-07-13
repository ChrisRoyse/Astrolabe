//! Search unification pure core (P6.6, blueprint `12_SEARCH.md` §1–3, #42).
//!
//! The Sextant-fused engine's deterministic algorithmic spine: intent
//! classification, the fail-closed query planner, RRF fusion with per-lens
//! explain contributions, exact scalar/label filtering, and the bounded
//! temporal boost. Everything here is integer-math, allocation-ordered, and
//! input-deterministic: identical request + identical per-slot rankings =>
//! identical fused output, independent of platform or worker count.
//!
//! Not here (deferred to the index/server layers): per-slot index
//! *construction* (BM25/HNSW/SPANN over real vectors), the `search_graph`
//! MCP-surface backward-compatibility layer, and the A/B + latency benchmark
//! harness — those consume this module.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use calyx_core::SlotId;

/// Plan schema id carried by every produced plan.
pub const SEARCH_PLAN_SCHEMA: &str = "astrolabe.search_plan.v1";
/// Registry version for the declared fusion/planner knobs below.
pub const SEARCH_FUSION_KNOB_REGISTRY_VERSION: &str = "astro.weave.search_fusion_knobs.v1";

/// Fail-closed planner refusal code (named by the P6.6 DoD).
pub const PLAN_COST_EXCEEDED: &str = "PLAN_COST_EXCEEDED";
/// Fail-closed temporal-boost knob refusal.
pub const ASTRO_SEARCH_TEMPORAL_ALPHA_RANGE: &str = "ASTRO_SEARCH_TEMPORAL_ALPHA_RANGE";
/// Fail-closed fusion-input refusal (e.g. weight for a slot missing from the plan).
pub const ASTRO_SEARCH_FUSION_INPUT: &str = "ASTRO_SEARCH_FUSION_INPUT";

/// Declared planner caps (registry knobs, blueprint §2). These are guardrails,
/// not measurements: they bound resource use fail-closed.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SearchCaps {
    /// Maximum requested results.
    pub max_k: u64,
    /// Maximum per-slot search effort (HNSW ef).
    pub max_ef: u64,
    /// Maximum number of slots fused in one query.
    pub max_slots: u64,
    /// Maximum plan cost units (see [`plan_cost_units`]).
    pub max_cost_units: u64,
    /// Maximum query timeout in milliseconds.
    pub max_timeout_ms: u64,
}

impl SearchCaps {
    /// Blueprint §2 defaults: k<=100, ef<=512, slots<=16; the cost cap is the
    /// product of those bounds (the largest legal plan), and timeouts are
    /// bounded at 10s.
    pub const fn default_caps() -> Self {
        Self {
            max_k: 100,
            max_ef: 512,
            max_slots: 16,
            max_cost_units: 100 * 512 * 16,
            max_timeout_ms: 10_000,
        }
    }
}

/// RRF rank constant `K` in `w/(K+rank)` (declared knob; blueprint fixes 60).
pub const RRF_RANK_K: u64 = 60;
/// Fixed-point denominator for slot weights (1000 = weight 1.0).
pub const WEIGHT_SCALE_MILLIS: u64 = 1_000;
/// Numerator scale for integer RRF scores (keeps precision at rank<=max_k).
pub const RRF_SCORE_SCALE: u64 = 1_000_000;
/// Maximum temporal-boost alpha in millis (0.10; declared knob).
pub const MAX_TEMPORAL_ALPHA_MILLIS: u64 = 100;

/// Deterministic query intents; each carries a default per-slot weight profile.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum SearchIntent {
    /// Meaning-of-code questions => semantic slots dominate.
    Semantic,
    /// Structure/shape questions => struct trigram slot dominates.
    Structural,
    /// Call/usage questions => API-callee slot dominates.
    ApiUsage,
    /// Identifier lookups => name-semantic + lexical dominate.
    NameLookup,
    /// No keyword evidence => balanced mixed profile.
    Mixed,
}

impl SearchIntent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Semantic => "semantic",
            Self::Structural => "structural",
            Self::ApiUsage => "api_usage",
            Self::NameLookup => "name_lookup",
            Self::Mixed => "mixed",
        }
    }
}

/// Slots the fusion profiles reference (panel v1 ids).
pub const SLOT_STRUCT_TRIGRAMS: SlotId = SlotId::new(1);
pub const SLOT_API_CALLEES: SlotId = SlotId::new(4);
pub const SLOT_LEXICAL_BM25: SlotId = SlotId::new(7);
pub const SLOT_CODE_SEMANTIC: SlotId = SlotId::new(18);
pub const SLOT_NAME_SEMANTIC: SlotId = SlotId::new(20);

/// Classify a query deterministically from keyword evidence. Ties break by
/// fixed intent order (Semantic < Structural < ApiUsage < NameLookup), and a
/// query with no keyword hits is `Mixed` — the classifier never guesses.
pub fn classify_intent(query: &str) -> SearchIntent {
    const SEMANTIC_KEYWORDS: &[&str] = &["like", "similar", "about", "meaning", "related"];
    const STRUCTURAL_KEYWORDS: &[&str] = &["struct", "structure", "shape", "pattern", "nested"];
    const API_KEYWORDS: &[&str] = &["calls", "called", "uses", "using", "imports", "callers"];
    const NAME_KEYWORDS: &[&str] = &["named", "name", "identifier", "symbol", "exact"];

    let lowered = query.to_ascii_lowercase();
    let tokens: BTreeSet<&str> = lowered
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|token| !token.is_empty())
        .collect();
    let hits = |keywords: &[&str]| keywords.iter().filter(|kw| tokens.contains(**kw)).count();

    let scored = [
        (SearchIntent::Semantic, hits(SEMANTIC_KEYWORDS)),
        (SearchIntent::Structural, hits(STRUCTURAL_KEYWORDS)),
        (SearchIntent::ApiUsage, hits(API_KEYWORDS)),
        (SearchIntent::NameLookup, hits(NAME_KEYWORDS)),
    ];
    let best = scored
        .iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .expect("non-empty intent table");
    if best.1 == 0 {
        SearchIntent::Mixed
    } else {
        best.0
    }
}

/// Default fusion weights (millis) per intent. Declared knob table under
/// [`SEARCH_FUSION_KNOB_REGISTRY_VERSION`]; an explicit override replaces it.
pub fn intent_weights_millis(intent: SearchIntent) -> BTreeMap<SlotId, u64> {
    let table: &[(SlotId, u64)] = match intent {
        SearchIntent::Semantic => &[
            (SLOT_CODE_SEMANTIC, 1_000),
            (SLOT_NAME_SEMANTIC, 500),
            (SLOT_LEXICAL_BM25, 300),
        ],
        SearchIntent::Structural => &[
            (SLOT_STRUCT_TRIGRAMS, 1_000),
            (SLOT_CODE_SEMANTIC, 400),
            (SLOT_LEXICAL_BM25, 200),
        ],
        SearchIntent::ApiUsage => &[
            (SLOT_API_CALLEES, 1_000),
            (SLOT_CODE_SEMANTIC, 400),
            (SLOT_LEXICAL_BM25, 200),
        ],
        SearchIntent::NameLookup => &[
            (SLOT_NAME_SEMANTIC, 1_000),
            (SLOT_LEXICAL_BM25, 800),
            (SLOT_CODE_SEMANTIC, 200),
        ],
        SearchIntent::Mixed => &[
            (SLOT_CODE_SEMANTIC, 600),
            (SLOT_LEXICAL_BM25, 600),
            (SLOT_NAME_SEMANTIC, 400),
            (SLOT_STRUCT_TRIGRAMS, 400),
            (SLOT_API_CALLEES, 400),
        ],
    };
    table.iter().copied().collect()
}

/// A search request as the planner sees it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SearchRequest {
    pub query: String,
    pub k: u64,
    pub ef: u64,
    pub timeout_ms: u64,
    /// Explicit fusion override; `None` => deterministic intent classification.
    pub fusion_override_millis: Option<BTreeMap<SlotId, u64>>,
    /// Temporal boost strength in millis (0 disables; capped at
    /// [`MAX_TEMPORAL_ALPHA_MILLIS`], fail-closed).
    pub temporal_alpha_millis: u64,
}

/// A validated, capped plan. The only way to obtain one is [`plan_search`], so
/// a rejected request can never reach the execution stage.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SearchPlan {
    pub schema: &'static str,
    pub knob_registry_version: &'static str,
    pub intent: SearchIntent,
    /// `true` when weights came from an explicit override, not the classifier.
    pub fusion_overridden: bool,
    pub weights_millis: BTreeMap<SlotId, u64>,
    pub k: u64,
    pub ef: u64,
    pub timeout_ms: u64,
    pub cost_units: u64,
    pub temporal_alpha_millis: u64,
}

/// Monotone plan cost model: `k * ef * slot_count`. Any input growing => cost
/// growing, so the cap can never be dodged by inflating another dimension.
pub fn plan_cost_units(k: u64, ef: u64, slot_count: u64) -> u64 {
    k.saturating_mul(ef).saturating_mul(slot_count)
}

/// Plan a search request against declared caps. Every breach is a fail-closed
/// [`PLAN_COST_EXCEEDED`] refusal naming the cap; no partial or clamped plan is
/// ever produced (clamping would be a silent fallback).
pub fn plan_search(request: &SearchRequest, caps: &SearchCaps) -> Result<SearchPlan, SearchError> {
    let refuse = |what: String| {
        Err(SearchError::new(
            PLAN_COST_EXCEEDED,
            what,
            "Reduce k/ef/slot-count/timeout or raise the declared caps knob; the planner never \
             runs an unbounded scan.",
        ))
    };
    if request.k == 0 {
        return Err(SearchError::new(
            ASTRO_SEARCH_FUSION_INPUT,
            "requested k=0".to_string(),
            "Request at least one result.",
        ));
    }
    if request.k > caps.max_k {
        return refuse(format!("k={} exceeds cap {}", request.k, caps.max_k));
    }
    if request.ef > caps.max_ef {
        return refuse(format!("ef={} exceeds cap {}", request.ef, caps.max_ef));
    }
    if request.timeout_ms > caps.max_timeout_ms {
        return refuse(format!(
            "timeout_ms={} exceeds cap {}",
            request.timeout_ms, caps.max_timeout_ms
        ));
    }
    if request.temporal_alpha_millis > MAX_TEMPORAL_ALPHA_MILLIS {
        return Err(SearchError::new(
            ASTRO_SEARCH_TEMPORAL_ALPHA_RANGE,
            format!(
                "temporal_alpha_millis={} exceeds the declared maximum {}",
                request.temporal_alpha_millis, MAX_TEMPORAL_ALPHA_MILLIS
            ),
            "Use a temporal boost alpha of at most 0.10 (100 millis); larger boosts can reorder \
             results beyond the documented bound.",
        ));
    }

    let (intent, fusion_overridden, weights_millis) = match &request.fusion_override_millis {
        Some(weights) => {
            if weights.is_empty() || weights.values().any(|millis| *millis == 0) {
                return Err(SearchError::new(
                    ASTRO_SEARCH_FUSION_INPUT,
                    "fusion override must be non-empty with strictly positive weights".to_string(),
                    "Supply at least one slot with a positive milli-weight, or omit the override \
                     to use intent classification.",
                ));
            }
            (SearchIntent::Mixed, true, weights.clone())
        }
        None => {
            let intent = classify_intent(&request.query);
            (intent, false, intent_weights_millis(intent))
        }
    };

    let slot_count = weights_millis.len() as u64;
    if slot_count > caps.max_slots {
        return refuse(format!(
            "slot count {} exceeds cap {}",
            slot_count, caps.max_slots
        ));
    }
    let cost_units = plan_cost_units(request.k, request.ef, slot_count);
    if cost_units > caps.max_cost_units {
        return refuse(format!(
            "cost {} (k={} * ef={} * slots={}) exceeds cap {}",
            cost_units, request.k, request.ef, slot_count, caps.max_cost_units
        ));
    }

    Ok(SearchPlan {
        schema: SEARCH_PLAN_SCHEMA,
        knob_registry_version: SEARCH_FUSION_KNOB_REGISTRY_VERSION,
        intent,
        fusion_overridden,
        weights_millis,
        k: request.k,
        ef: request.ef,
        timeout_ms: request.timeout_ms,
        cost_units,
        temporal_alpha_millis: request.temporal_alpha_millis,
    })
}

/// One slot's ranked candidates (rank 0 = best), as the per-slot indexes return
/// them. The fusion stage consumes only the ordering, never raw scores, so
/// heterogeneous slot score scales cannot skew the fusion (that is RRF's point).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SlotRanking {
    pub slot: SlotId,
    /// Symbol ids, best first. Duplicates within one slot are an input error.
    pub ranked_symbol_ids: Vec<String>,
}

/// Per-lens contribution to one fused result (explain mode).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LensContribution {
    pub slot: SlotId,
    pub rank: u64,
    /// `weight_millis * RRF_SCORE_SCALE / (RRF_RANK_K + rank + 1)`.
    pub score_micros: u64,
}

/// One fused result with its full explain breakdown.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FusedResult {
    pub symbol_id: String,
    /// Total RRF score (micros), before any temporal boost.
    pub rrf_score_micros: u64,
    /// Final score after the bounded temporal boost (== rrf when disabled).
    pub final_score_micros: u64,
    pub contributions: Vec<LensContribution>,
}

/// Reciprocal-rank fusion: `sum_slots(w_slot / (K + rank))` with rank starting
/// at 1 (rank index 0 => divisor `K+1`), integer-scaled to micros. Results sort
/// by score descending, then symbol id ascending — fully deterministic.
///
/// Dedup is inherent: a symbol appearing in several slots folds into one result
/// with summed contributions. The *recency* signal is deliberately not a fused
/// slot: it enters only through [`apply_temporal_boost`], so it can neither
/// dedup against content slots nor contribute unbounded score.
pub fn fuse_rrf(
    plan: &SearchPlan,
    rankings: &[SlotRanking],
) -> Result<Vec<FusedResult>, SearchError> {
    let mut accumulator: BTreeMap<String, (u64, Vec<LensContribution>)> = BTreeMap::new();
    for ranking in rankings {
        let Some(weight_millis) = plan.weights_millis.get(&ranking.slot).copied() else {
            return Err(SearchError::new(
                ASTRO_SEARCH_FUSION_INPUT,
                format!(
                    "slot {} supplied a ranking but carries no weight in the plan",
                    ranking.slot.get()
                ),
                "Fuse only the slots the plan selected; rebuild the plan to include this slot.",
            ));
        };
        let mut seen = BTreeSet::new();
        for (index, symbol_id) in ranking.ranked_symbol_ids.iter().enumerate() {
            if !seen.insert(symbol_id.as_str()) {
                return Err(SearchError::new(
                    ASTRO_SEARCH_FUSION_INPUT,
                    format!(
                        "slot {} ranked symbol {symbol_id} more than once",
                        ranking.slot.get()
                    ),
                    "Per-slot rankings must be duplicate-free; fix the slot index output.",
                ));
            }
            let rank = index as u64;
            let score_micros =
                weight_millis.saturating_mul(RRF_SCORE_SCALE) / (RRF_RANK_K + rank + 1);
            let entry = accumulator
                .entry(symbol_id.clone())
                .or_insert_with(|| (0, Vec::new()));
            entry.0 = entry.0.saturating_add(score_micros);
            entry.1.push(LensContribution {
                slot: ranking.slot,
                rank,
                score_micros,
            });
        }
    }

    let mut results: Vec<FusedResult> = accumulator
        .into_iter()
        .map(
            |(symbol_id, (rrf_score_micros, contributions))| FusedResult {
                symbol_id,
                rrf_score_micros,
                final_score_micros: rrf_score_micros,
                contributions,
            },
        )
        .collect();
    results.sort_by(|left, right| {
        right
            .rrf_score_micros
            .cmp(&left.rrf_score_micros)
            .then_with(|| left.symbol_id.cmp(&right.symbol_id))
    });
    results.truncate(plan.k as usize);
    Ok(results)
}

/// Bounded multiplicative temporal boost:
/// `final = rrf * (1000 + alpha_millis * recency_millis / 1000) / 1000`
/// with `recency_millis` in `[0, 1000]`. The boost factor is at most
/// `1 + alpha`, so two results whose RRF scores differ by more than a factor of
/// `1 + alpha` can never reorder — the property test pins this bound. Symbols
/// without a recency value are unboosted (recency 0), which is a labeled
/// contract, not a silent default: absence of evidence earns no boost.
pub fn apply_temporal_boost(
    plan: &SearchPlan,
    results: &mut [FusedResult],
    recency_millis_by_symbol: &BTreeMap<String, u64>,
) -> Result<(), SearchError> {
    if plan.temporal_alpha_millis == 0 {
        return Ok(());
    }
    for (symbol, recency) in recency_millis_by_symbol {
        if *recency > WEIGHT_SCALE_MILLIS {
            return Err(SearchError::new(
                ASTRO_SEARCH_FUSION_INPUT,
                format!("recency for {symbol} is {recency} millis, outside [0,1000]"),
                "Normalize recency to millis in [0,1000] before boosting.",
            ));
        }
    }
    for result in results.iter_mut() {
        let recency = recency_millis_by_symbol
            .get(&result.symbol_id)
            .copied()
            .unwrap_or(0);
        let factor_millis = WEIGHT_SCALE_MILLIS
            + plan.temporal_alpha_millis.saturating_mul(recency) / WEIGHT_SCALE_MILLIS;
        result.final_score_micros =
            result.rrf_score_micros.saturating_mul(factor_millis) / WEIGHT_SCALE_MILLIS;
    }
    results.sort_by(|left, right| {
        right
            .final_score_micros
            .cmp(&left.final_score_micros)
            .then_with(|| left.symbol_id.cmp(&right.symbol_id))
    });
    Ok(())
}

/// Exact filter on symbol scalar/label attributes (post-fusion stage). A
/// symbol passes only if *every* filter key is present with the exact value —
/// missing attributes never pass (fail-closed, no fuzzy fallback). Composes
/// with the kernel's propagated-label filter (#69), which produces exactly this
/// attribute shape.
pub fn apply_exact_filters(
    results: &mut Vec<FusedResult>,
    filters: &BTreeMap<String, String>,
    attributes_by_symbol: &BTreeMap<String, BTreeMap<String, String>>,
) {
    if filters.is_empty() {
        return;
    }
    results.retain(|result| {
        let Some(attributes) = attributes_by_symbol.get(&result.symbol_id) else {
            return false;
        };
        filters
            .iter()
            .all(|(key, value)| attributes.get(key) == Some(value))
    });
}

/// The per-slot search abstraction the executor drives. Real implementations
/// wrap the per-slot indexes (BM25/HNSW/SPANN); tests use counting fakes to
/// prove a refused plan never scans.
pub trait SlotSearcher {
    fn search_slot(&self, slot: SlotId, query: &str, k: u64, ef: u64) -> SlotRanking;
}

/// Execute a validated plan end-to-end: per-slot search -> RRF fusion -> exact
/// filters -> bounded temporal boost. There is deliberately no entry point that
/// accepts a raw request: refusal happens in [`plan_search`] *before* any slot
/// is scanned.
pub fn run_search<S: SlotSearcher>(
    plan: &SearchPlan,
    searcher: &S,
    query: &str,
    filters: &BTreeMap<String, String>,
    attributes_by_symbol: &BTreeMap<String, BTreeMap<String, String>>,
    recency_millis_by_symbol: &BTreeMap<String, u64>,
) -> Result<Vec<FusedResult>, SearchError> {
    let mut rankings = Vec::with_capacity(plan.weights_millis.len());
    for slot in plan.weights_millis.keys() {
        rankings.push(searcher.search_slot(*slot, query, plan.k, plan.ef));
    }
    let mut results = fuse_rrf(plan, &rankings)?;
    apply_exact_filters(&mut results, filters, attributes_by_symbol);
    apply_temporal_boost(plan, &mut results, recency_millis_by_symbol)?;
    Ok(results)
}

/// Fail-closed search error `{code, message, remediation}` (invariant #6).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SearchError {
    code: &'static str,
    message: String,
    remediation: &'static str,
}

impl SearchError {
    pub(crate) fn new(code: &'static str, message: String, remediation: &'static str) -> Self {
        Self {
            code,
            message,
            remediation,
        }
    }

    pub fn code(&self) -> &str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn remediation(&self) -> &str {
        self.remediation
    }
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} — {}", self.code, self.message, self.remediation)
    }
}

impl std::error::Error for SearchError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn request(query: &str) -> SearchRequest {
        SearchRequest {
            query: query.to_string(),
            k: 10,
            ef: 64,
            timeout_ms: 1_000,
            fusion_override_millis: None,
            temporal_alpha_millis: 0,
        }
    }

    #[test]
    fn intent_classifier_is_deterministic_and_keyword_driven() {
        assert_eq!(
            classify_intent("functions similar to parse_config"),
            SearchIntent::Semantic
        );
        assert_eq!(
            classify_intent("what calls the auth middleware"),
            SearchIntent::ApiUsage
        );
        assert_eq!(
            classify_intent("symbols named FooBar"),
            SearchIntent::NameLookup
        );
        assert_eq!(
            classify_intent("nested struct pattern"),
            SearchIntent::Structural
        );
        assert_eq!(classify_intent("frobnicate widget"), SearchIntent::Mixed);
        // Determinism: repeated classification of the same query is identical.
        for _ in 0..10 {
            assert_eq!(
                classify_intent("what calls the auth middleware"),
                SearchIntent::ApiUsage
            );
        }
        // Case/whitespace insensitivity.
        assert_eq!(
            classify_intent("  WHAT   Calls\tthe auth"),
            SearchIntent::ApiUsage
        );
    }

    #[test]
    fn explicit_fusion_override_bypasses_classification() {
        let mut req = request("what calls the auth middleware");
        let mut weights = BTreeMap::new();
        weights.insert(SLOT_CODE_SEMANTIC, 700_u64);
        req.fusion_override_millis = Some(weights.clone());
        let plan = plan_search(&req, &SearchCaps::default_caps()).expect("plan");
        assert!(plan.fusion_overridden);
        assert_eq!(plan.weights_millis, weights);
        // Zero-weight override is refused, not silently dropped.
        let mut bad = request("x");
        let mut zero = BTreeMap::new();
        zero.insert(SLOT_CODE_SEMANTIC, 0_u64);
        bad.fusion_override_millis = Some(zero);
        let err = plan_search(&bad, &SearchCaps::default_caps()).expect_err("refuse");
        assert_eq!(err.code(), ASTRO_SEARCH_FUSION_INPUT);
    }

    #[test]
    fn planner_refuses_every_cap_breach_fail_closed() {
        let caps = SearchCaps::default_caps();
        let cases: Vec<(SearchRequest, &str)> = vec![
            (
                SearchRequest {
                    k: 101,
                    ..request("q")
                },
                "k=101",
            ),
            (
                SearchRequest {
                    ef: 513,
                    ..request("q")
                },
                "ef=513",
            ),
            (
                SearchRequest {
                    timeout_ms: 10_001,
                    ..request("q")
                },
                "timeout_ms=10001",
            ),
            (
                SearchRequest {
                    k: 100,
                    ef: 512,
                    fusion_override_millis: Some(
                        (0..17).map(|i| (SlotId::new(i), 100_u64)).collect(),
                    ),
                    ..request("q")
                },
                "slot count 17",
            ),
        ];
        for (req, needle) in cases {
            let err = plan_search(&req, &caps).expect_err("must refuse");
            assert_eq!(err.code(), PLAN_COST_EXCEEDED, "{needle}");
            assert!(
                err.message().contains(needle),
                "{} !~ {needle}",
                err.message()
            );
            assert!(!err.remediation().is_empty());
        }
        // Cost cap: a tighter cap refuses a plan that passes the per-axis caps.
        let tight = SearchCaps {
            max_cost_units: 100,
            ..caps
        };
        let err = plan_search(&request("q"), &tight).expect_err("cost refusal");
        assert_eq!(err.code(), PLAN_COST_EXCEEDED);
        assert!(err.message().contains("cost"), "{}", err.message());
    }

    /// Counting searcher: proves the scan stage never runs on a refused plan.
    struct CountingSearcher {
        calls: Cell<usize>,
    }

    impl SlotSearcher for CountingSearcher {
        fn search_slot(&self, slot: SlotId, _query: &str, _k: u64, _ef: u64) -> SlotRanking {
            self.calls.set(self.calls.get() + 1);
            SlotRanking {
                slot,
                ranked_symbol_ids: vec!["sym:a".to_string()],
            }
        }
    }

    #[test]
    fn refused_plan_never_scans_a_slot() {
        let searcher = CountingSearcher {
            calls: Cell::new(0),
        };
        let req = SearchRequest {
            k: 9_999,
            ..request("q")
        };
        let planned = plan_search(&req, &SearchCaps::default_caps());
        assert!(planned.is_err(), "plan must refuse");
        // There is no way to call run_search without a SearchPlan; the
        // instrumented counter proves no slot scan happened on this refusal.
        assert_eq!(searcher.calls.get(), 0, "refused plan must not scan");

        // And a valid plan scans exactly the planned slot count.
        let plan = plan_search(&request("q"), &SearchCaps::default_caps()).expect("plan");
        let empty = BTreeMap::new();
        let attrs = BTreeMap::new();
        let recency = BTreeMap::new();
        run_search(&plan, &searcher, "q", &empty, &attrs, &recency).expect("run");
        assert_eq!(searcher.calls.get(), plan.weights_millis.len());
    }

    #[test]
    fn rrf_golden_pins_exact_fused_ordering_at_k60() {
        // Hand-ranked inputs. Weights: slotX=1000, slotY=500 millis.
        // slotX: [a, b, c]  slotY: [b, a]
        // score(a) = 1000*1e6/61 + 500*1e6/62 = 16393442 + 8064516 = 24457958
        // score(b) = 1000*1e6/62 + 500*1e6/61 = 16129032 + 8196721 = 24325753
        // score(c) = 1000*1e6/63                = 15873015
        // Expected order: a, b, c.
        let mut weights = BTreeMap::new();
        weights.insert(SLOT_CODE_SEMANTIC, 1_000_u64);
        weights.insert(SLOT_LEXICAL_BM25, 500_u64);
        let req = SearchRequest {
            fusion_override_millis: Some(weights),
            ..request("golden")
        };
        let plan = plan_search(&req, &SearchCaps::default_caps()).expect("plan");
        let rankings = vec![
            SlotRanking {
                slot: SLOT_CODE_SEMANTIC,
                ranked_symbol_ids: vec!["a".into(), "b".into(), "c".into()],
            },
            SlotRanking {
                slot: SLOT_LEXICAL_BM25,
                ranked_symbol_ids: vec!["b".into(), "a".into()],
            },
        ];
        let results = fuse_rrf(&plan, &rankings).expect("fuse");
        let ids: Vec<&str> = results.iter().map(|r| r.symbol_id.as_str()).collect();
        assert_eq!(ids, ["a", "b", "c"]);
        assert_eq!(
            results[0].rrf_score_micros,
            1_000 * 1_000_000 / 61 + 500 * 1_000_000 / 62
        );
        assert_eq!(
            results[1].rrf_score_micros,
            1_000 * 1_000_000 / 62 + 500 * 1_000_000 / 61
        );
        assert_eq!(results[2].rrf_score_micros, 1_000 * 1_000_000 / 63);
        // Explain mode: per-lens contributions sum to the fused score.
        for result in &results {
            let sum: u64 = result.contributions.iter().map(|c| c.score_micros).sum();
            assert_eq!(sum, result.rrf_score_micros, "{}", result.symbol_id);
        }
        // Dedup: `a` and `b` each appear once with two contributions.
        assert_eq!(results[0].contributions.len(), 2);
        assert_eq!(results[1].contributions.len(), 2);
    }

    #[test]
    fn fusion_refuses_unplanned_slots_and_duplicate_ranks() {
        let plan = plan_search(&request("q"), &SearchCaps::default_caps()).expect("plan");
        let unplanned = SlotRanking {
            slot: SlotId::new(99),
            ranked_symbol_ids: vec!["a".into()],
        };
        let err = fuse_rrf(&plan, &[unplanned]).expect_err("unplanned slot refused");
        assert_eq!(err.code(), ASTRO_SEARCH_FUSION_INPUT);

        let slot = *plan.weights_millis.keys().next().expect("plan has slots");
        let duplicated = SlotRanking {
            slot,
            ranked_symbol_ids: vec!["a".into(), "a".into()],
        };
        let err = fuse_rrf(&plan, &[duplicated]).expect_err("duplicate rank refused");
        assert_eq!(err.code(), ASTRO_SEARCH_FUSION_INPUT);
    }

    /// SplitMix64 for the seeded property test (deterministic, no dev-dep).
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn temporal_boost_never_reorders_beyond_alpha_bound() {
        // Property (seeded, 2000 cases): for any two results whose RRF scores
        // satisfy rrf_hi * 1000 > rrf_lo * (1000 + alpha), no recency
        // assignment can put lo above hi. Boost factor is in [1, 1+alpha].
        let alpha = MAX_TEMPORAL_ALPHA_MILLIS; // worst case 0.10
        let mut rng = SplitMix64(20_260_711);
        for case in 0..2_000 {
            let rrf_lo = 1_000 + rng.next_u64() % 10_000_000;
            // Strictly beyond the bound: hi > lo * (1+alpha).
            let rrf_hi = rrf_lo.saturating_mul(1_000 + alpha) / 1_000 + 1 + rng.next_u64() % 1_000;
            let recency_hi = rng.next_u64() % 1_001;
            let recency_lo = rng.next_u64() % 1_001;
            let boosted_hi = rrf_hi * (1_000 + alpha * recency_hi / 1_000) / 1_000;
            let boosted_lo = rrf_lo * (1_000 + alpha * recency_lo / 1_000) / 1_000;
            assert!(
                boosted_hi > boosted_lo,
                "case {case}: reorder beyond bound (hi {rrf_hi}->{boosted_hi}, lo {rrf_lo}->{boosted_lo})"
            );
        }
    }

    #[test]
    fn temporal_boost_applies_through_the_pipeline_and_is_bounded() {
        let mut weights = BTreeMap::new();
        weights.insert(SLOT_CODE_SEMANTIC, 1_000_u64);
        let req = SearchRequest {
            fusion_override_millis: Some(weights),
            temporal_alpha_millis: 100,
            ..request("q")
        };
        let plan = plan_search(&req, &SearchCaps::default_caps()).expect("plan");
        let rankings = vec![SlotRanking {
            slot: SLOT_CODE_SEMANTIC,
            ranked_symbol_ids: vec!["old".into(), "fresh".into()],
        }];
        let mut results = fuse_rrf(&plan, &rankings).expect("fuse");
        let mut recency = BTreeMap::new();
        recency.insert("fresh".to_string(), 1_000_u64); // max recency
        apply_temporal_boost(&plan, &mut results, &recency).expect("boost");
        // rank0 old: 1000*1e6/61=16393442 (no boost); rank1 fresh:
        // 1000*1e6/62=16129032 * 1.10 = 17741935 -> fresh overtakes within the
        // documented alpha=0.10 envelope (gap was < 10%).
        assert_eq!(results[0].symbol_id, "fresh");
        assert_eq!(results[0].final_score_micros, 16_129_032 * 1_100 / 1_000);
        assert_eq!(results[1].final_score_micros, 16_393_442);
        // Out-of-range recency is refused.
        let mut bad = BTreeMap::new();
        bad.insert("fresh".to_string(), 1_001_u64);
        let err = apply_temporal_boost(&plan, &mut results, &bad).expect_err("range");
        assert_eq!(err.code(), ASTRO_SEARCH_FUSION_INPUT);
        // Alpha above the declared cap is refused at planning time.
        let over = SearchRequest {
            temporal_alpha_millis: 101,
            ..request("q")
        };
        let err = plan_search(&over, &SearchCaps::default_caps()).expect_err("alpha cap");
        assert_eq!(err.code(), ASTRO_SEARCH_TEMPORAL_ALPHA_RANGE);
    }

    #[test]
    fn exact_filters_are_fail_closed_on_missing_attributes() {
        let mut weights = BTreeMap::new();
        weights.insert(SLOT_CODE_SEMANTIC, 1_000_u64);
        let req = SearchRequest {
            fusion_override_millis: Some(weights),
            ..request("q")
        };
        let plan = plan_search(&req, &SearchCaps::default_caps()).expect("plan");
        let rankings = vec![SlotRanking {
            slot: SLOT_CODE_SEMANTIC,
            ranked_symbol_ids: vec!["labeled".into(), "unlabeled".into(), "wrong".into()],
        }];
        let mut results = fuse_rrf(&plan, &rankings).expect("fuse");

        let mut filters = BTreeMap::new();
        filters.insert("label:security-sensitive".to_string(), "true".to_string());
        let mut attrs = BTreeMap::new();
        attrs.insert("labeled".to_string(), {
            let mut map = BTreeMap::new();
            map.insert("label:security-sensitive".to_string(), "true".to_string());
            map
        });
        attrs.insert("wrong".to_string(), {
            let mut map = BTreeMap::new();
            map.insert("label:security-sensitive".to_string(), "false".to_string());
            map
        });
        // `unlabeled` has no attribute map at all: must not pass.
        apply_exact_filters(&mut results, &filters, &attrs);
        let ids: Vec<&str> = results.iter().map(|r| r.symbol_id.as_str()).collect();
        assert_eq!(ids, ["labeled"]);
    }

    #[test]
    fn identical_request_and_rankings_fuse_identically() {
        let plan =
            plan_search(&request("determinism probe"), &SearchCaps::default_caps()).expect("plan");
        let rankings: Vec<SlotRanking> = plan
            .weights_millis
            .keys()
            .map(|slot| SlotRanking {
                slot: *slot,
                ranked_symbol_ids: (0..20)
                    .map(|i| format!("sym:{:02}", (i * 7) % 20))
                    .collect(),
            })
            .collect();
        let first = fuse_rrf(&plan, &rankings).expect("fuse 1");
        let second = fuse_rrf(&plan, &rankings).expect("fuse 2");
        assert_eq!(first, second, "fusion must be deterministic");
    }
}
