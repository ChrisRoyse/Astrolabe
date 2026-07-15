//! Scored `trace_path` navigation (P6.7, #43).
//!
//! `trace_path`/`trace_call_path` is a CBM-native tool: its plain breadth-first
//! traversal is served byte-for-byte by libcbm and is NEVER altered here. The only
//! divergence is an opt-in `scored:true` knob, which post-ranks the CBM traversal
//! result into a weighted best-first ordering:
//!
//! - **×0.9 hop attenuation** — each additional hop away from the anchor multiplies
//!   a candidate's priority by the registry-declared attenuation factor (default
//!   900 permille = 0.9), so nearer symbols outrank farther ones at equal edge
//!   weight.
//! - **measured edge weights** — a promoted edge (#333) carries a measured integer
//!   `weight` (runtime-trace validation count) in the CBM hop payload; the score
//!   multiplies attenuation by that weight (an unpromoted edge contributes the
//!   neutral weight 1), so a measured, validated edge outranks an unmeasured one at
//!   equal depth.
//! - **direction-aware** — `callees` (outbound) and `callers` (inbound) are ranked
//!   independently, preserving CBM's direction semantics.
//! - **trust tags on hops** — every ranked hop carries a `trust` label: the CBM
//!   edge's own promotion trust when present, else the labeled `unweighted`
//!   (invariant 1: no unlabeled claim), and the anchor hop is labeled `root`.
//!
//! Fail-closed contract: a `scored:true` request whose CBM result is an error, or
//! whose payload cannot be parsed, is surfaced verbatim / as a coded refusal — the
//! scored path never fabricates a ranking over a missing traversal.

use astrolabe_domain::knobs::U64KnobDeclaration;

use super::*;

/// Surface schema tag for the scored `trace_path` envelope additions.
pub(crate) const TRACE_PATH_SCORED_SCHEMA: &str = "astrolabe.trace_path.scored.v1";

/// Registry version for the scored `trace_path` surface knobs.
pub(crate) const TRACE_PATH_KNOB_REGISTRY_VERSION: &str = "astro.server.trace_path_scored_knobs.v1";

/// Name of the per-hop attenuation knob.
pub(crate) const TRACE_PATH_HOP_ATTENUATION_PERMILLE_KNOB: &str =
    "trace_path_hop_attenuation_permille";

/// Default per-hop attenuation, in permille (900 = 0.9). Pinned by the #43 DoD.
pub(crate) const TRACE_PATH_HOP_ATTENUATION_DEFAULT_PERMILLE: u64 = 900;
/// Smallest legal attenuation. Zero is illegal: a zero factor collapses every hop
/// beyond the anchor to score 0, erasing the depth ordering this knob exists to
/// produce.
pub(crate) const TRACE_PATH_HOP_ATTENUATION_MIN_PERMILLE: u64 = 1;
/// Largest legal attenuation (1000 = 1.0). At the ceiling depth no longer
/// attenuates and the ordering reduces to pure edge weight; above it a hop would
/// *amplify* with depth, which is not an attenuation.
pub(crate) const TRACE_PATH_HOP_ATTENUATION_MAX_PERMILLE: u64 = 1000;

/// The scored `trace_path` knob registry (#43).
pub(crate) const TRACE_PATH_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: TRACE_PATH_KNOB_REGISTRY_VERSION,
    name: TRACE_PATH_HOP_ATTENUATION_PERMILLE_KNOB,
    default: TRACE_PATH_HOP_ATTENUATION_DEFAULT_PERMILLE,
    min: TRACE_PATH_HOP_ATTENUATION_MIN_PERMILLE,
    max: TRACE_PATH_HOP_ATTENUATION_MAX_PERMILLE,
    unit: "permille",
    source: "ASTROLABE #43 P6.7 navigation DoD (0.9 hop attenuation pinned) over the classic best-first / iterative-deepening decay heuristic that discounts a path by a fixed factor per expansion",
    rationale: "geometric per-hop decay so a weighted best-first ranking prefers nearer symbols at equal edge weight; 0.9 is the DoD-pinned seed, the ceiling (1000) disables decay and the floor (1) keeps at least a vestigial ordering; replace with a measured decay once traversal relevance is benchmarked against outcomes",
}];

/// Returns the scored-trace declaration for `name`, or `None` when undeclared.
pub(crate) fn trace_path_knob(name: &str) -> Option<&'static U64KnobDeclaration> {
    TRACE_PATH_KNOBS.iter().find(|knob| knob.name == name)
}

/// The effective per-hop attenuation factor as a fraction in `(0, 1]`.
fn attenuation_fraction(permille: u64) -> f64 {
    permille as f64 / 1000.0
}

/// True when the request opted into the scored best-first ordering.
pub(crate) fn trace_path_scored_requested(args: &Map<String, Value>) -> bool {
    args.get("scored").and_then(Value::as_bool) == Some(true)
}

/// MCP entry point for `trace_path`/`trace_call_path`.
///
/// Without `scored:true` this is a byte-identical passthrough to the CBM tool
/// (plain BFS preserved). With `scored:true` the CBM traversal is post-ranked into
/// the weighted best-first ordering documented on this module.
pub(crate) fn handle_trace_path(
    runner: &CbmToolRunner,
    args_json: &str,
) -> Result<String, DynError> {
    let Ok(args) = serde_json::from_str::<Value>(args_json) else {
        // Malformed args are the CBM tool's to reject, byte-for-byte.
        return Ok(runner.handle_tool_raw("trace_path", args_json)?);
    };
    let Some(args_obj) = args.as_object() else {
        return Ok(runner.handle_tool_raw("trace_path", args_json)?);
    };
    if !trace_path_scored_requested(args_obj) {
        // Pure legacy request — pass the original bytes through unchanged.
        return Ok(runner.handle_tool_raw("trace_path", args_json)?);
    }

    // Strip the Astrolabe-only `scored` knob before the CBM tool sees it.
    let mut sanitized = args_obj.clone();
    sanitized.remove("scored");
    let sanitized_json = serde_json::to_string(&Value::Object(sanitized))?;
    let raw = runner.handle_tool_raw("trace_path", &sanitized_json)?;
    if tool_result_is_error(&raw)? {
        return Ok(raw);
    }
    // Source the attenuation from its registry declaration (single source of the
    // default; invariant 4) rather than a bare inline constant.
    let attenuation_permille = trace_path_knob(TRACE_PATH_HOP_ATTENUATION_PERMILLE_KNOB)
        .map_or(TRACE_PATH_HOP_ATTENUATION_DEFAULT_PERMILLE, |knob| {
            knob.default
        });
    score_trace_result(&raw, attenuation_permille)
}

/// Post-ranks a CBM `trace_path` tool result into the scored best-first ordering.
///
/// Pure JSON→JSON transform (the FSV workhorse): the `callees` and `callers` hop
/// arrays are each scored and reordered, per-hop `score_micros`/`trust` are added,
/// and the scoring provenance + trust/freshness envelope is attached. Both the
/// `structuredContent` object and the mirrored `content[0].text` payload are kept
/// byte-consistent.
pub(crate) fn score_trace_result(raw: &str, attenuation_permille: u64) -> Result<String, DynError> {
    let mut envelope: Value = serde_json::from_str(raw)?;

    // Transform the structuredContent graph object in place.
    if let Some(structured) = envelope
        .get_mut("structuredContent")
        .and_then(Value::as_object_mut)
    {
        score_trace_graph_obj(structured, attenuation_permille);
    }

    // Mirror the transform onto content[0].text so a text-only client sees the
    // same ranking (augment_tool_result keeps these two consistent elsewhere).
    if let Some(text) = envelope
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(|item| item.get_mut("text"))
        && let Some(raw_text) = text.as_str()
        && let Ok(mut text_value) = serde_json::from_str::<Value>(raw_text)
        && let Some(text_obj) = text_value.as_object_mut()
    {
        score_trace_graph_obj(text_obj, attenuation_permille);
        *text = Value::String(serde_json::to_string(&text_value)?);
    }

    Ok(serde_json::to_string(&envelope)?)
}

/// Scores + reorders the `callees`/`callers` arrays of one CBM trace graph object
/// and stamps the scored envelope.
fn score_trace_graph_obj(graph: &mut Map<String, Value>, attenuation_permille: u64) {
    let fraction = attenuation_fraction(attenuation_permille);
    let mut ranked_directions: Vec<&'static str> = Vec::new();
    for direction in ["callees", "callers"] {
        if let Some(hops) = graph.get_mut(direction).and_then(Value::as_array_mut) {
            score_and_sort_hops(hops, fraction);
            ranked_directions.push(direction);
        }
    }

    graph.insert("scored".to_string(), json!(true));
    graph.insert(
        "scoring".to_string(),
        json!({
            "schema": TRACE_PATH_SCORED_SCHEMA,
            "knob_registry_version": TRACE_PATH_KNOB_REGISTRY_VERSION,
            "hop_attenuation_permille": attenuation_permille,
            "ranked_directions": ranked_directions,
            "formula": "score_micros = round(1_000_000 * (attenuation/1000)^hop * max(1, edge_weight))",
            "ordering": "score_micros descending, qualified_name ascending on a tie",
        }),
    );
    // Envelope labels (invariant 1): the scored ranking is grounded in the live
    // CBM traversal of the persisted store; freshness is `fresh` because the
    // traversal is computed on demand, not read from a cached ranking.
    graph.insert("trust".to_string(), json!("grounded"));
    graph.insert("freshness".to_string(), json!("fresh"));
    graph.insert(
        "provenance".to_string(),
        json!(format!(
            "{TRACE_PATH_SCORED_SCHEMA}: weighted best-first re-rank of the CBM trace_path BFS \
             (attenuation={attenuation_permille}permille, measured edge weights)"
        )),
    );
}

/// Scores each hop object and sorts the array by descending score, breaking ties
/// on `qualified_name` ascending for determinism.
fn score_and_sort_hops(hops: &mut [Value], fraction: f64) {
    for hop in hops.iter_mut() {
        let Some(obj) = hop.as_object_mut() else {
            continue;
        };
        let depth = obj.get("hop").and_then(Value::as_u64).unwrap_or(0);
        // A promoted edge (#333) carries a measured integer `weight`; an unpromoted
        // edge contributes the neutral weight 1 so it never dominates a measured one.
        let weight = obj
            .get("weight")
            .and_then(Value::as_u64)
            .filter(|w| *w > 0)
            .unwrap_or(1);
        let attenuation = fraction.powi(depth.min(i32::MAX as u64) as i32);
        let score = 1_000_000.0 * attenuation * weight as f64;
        let score_micros = score.round().max(0.0) as u64;
        obj.insert("score_micros".to_string(), json!(score_micros));
        obj.insert(
            "hop_attenuation_micros".to_string(),
            json!((attenuation * 1_000_000.0).round().max(0.0) as u64),
        );
        obj.insert("edge_weight_applied".to_string(), json!(weight));
        // Trust tag on every hop: the anchor (hop 0) has no incoming edge (`root`),
        // a promoted edge keeps its own trust, an unpromoted edge is `unweighted`.
        if !obj.contains_key("trust") {
            let tag = if depth == 0 { "root" } else { "unweighted" };
            obj.insert("trust".to_string(), json!(tag));
        }
    }

    hops.sort_by(|left, right| {
        let ls = left
            .get("score_micros")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let rs = right
            .get("score_micros")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        rs.cmp(&ls).then_with(|| {
            let lq = left
                .get("qualified_name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let rq = right
                .get("qualified_name")
                .and_then(Value::as_str)
                .unwrap_or("");
            lq.cmp(rq)
        })
    });
}

/// The Astrolabe `scored` extension advertised on the CBM `trace_path` schema in
/// tools/list, so a client can discover the opt-in best-first ordering (#43).
pub(crate) fn trace_path_astrolabe_property_overlay() -> Vec<(String, Value)> {
    vec![(
        "scored".to_string(),
        json!({
            "type": "boolean",
            "description": "Astrolabe extension (#43): when true, re-rank the CBM trace_path BFS \
                into a weighted best-first ordering — nearer hops win via a ×0.9 per-hop \
                attenuation, measured promoted-edge weights break equal-depth ties, callees \
                and callers are ranked independently, and every hop carries a trust tag plus a \
                score. Omitted/false keeps the byte-identical legacy BFS."
        }),
    )]
}
