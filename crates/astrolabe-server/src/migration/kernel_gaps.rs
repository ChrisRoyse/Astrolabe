use super::*;

use astrolabe_kernel::{
    COVERAGE_QUADRANT_SCHEMA, GROUNDING_GAP_SCHEMA, GapQuadrant, QuadrantConfig, classify_quadrant,
};

/// `get_kernel` refusal codes (fail-closed, `{code, message, remediation}`).
pub(crate) const ASTRO_GET_KERNEL_SHADOW_REQUIRED: &str = "ASTRO_GET_KERNEL_SHADOW_REQUIRED";
pub(crate) const ASTRO_GET_KERNEL_CONTEXT_UNAVAILABLE: &str =
    "ASTRO_GET_KERNEL_CONTEXT_UNAVAILABLE";
pub(crate) const ASTRO_GET_KERNEL_MODE_UNSUPPORTED: &str = "ASTRO_GET_KERNEL_MODE_UNSUPPORTED";

/// The "here be dragons" QA surface (#39): kernel members with no grounding
/// anchor, ranked and quadranted for readiness + UI overlay.
///
/// `mode="gaps"` (default) serves the grounding-gap report — the kernel members
/// carried in the persisted kernel context whose `grounded` flag is false —
/// ranked by persisted kernel weight (importance). `mode="quadrant"` serves the
/// coverage-vs-importance scatter, classifying every member by importance
/// (kernel weight normalized to permille against the scope maximum) against
/// coverage (grounded → covered) using the kernel crate's registry-knob split.
///
/// The report reads back the persisted `kernel_context_json` metadata (the
/// durable scope-summary rows), never an in-memory echo. The change-frequency
/// churn term and the exact hop-distance boundary of the grounding-gap ranking
/// live in the persisted kernel artifact, which this metadata surface does not
/// yet carry; that degradation is labeled on every response (`ranking_basis`,
/// `degraded`, `remediation`) rather than silently substituted (HONEST invariant
/// 3), and the full artifact-backed ranking is tracked as follow-up.
pub(crate) fn handle_get_kernel(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("get_kernel arguments must be a JSON object");
    };
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("get_kernel requires project");
    };
    let mode = string_arg(args_obj, "mode").unwrap_or("gaps");

    if read_dial(&project)? != MigrationDial::Shadow {
        return tool_json_error_result(get_kernel_refused(
            &project,
            mode,
            ASTRO_GET_KERNEL_SHADOW_REQUIRED,
            format!("get_kernel requires calyx shadow indexing for project {project:?}"),
            "run index_repository with calyx=\"shadow\" for this project before requesting kernel gaps",
        ));
    }

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let kernel_context = read_kernel_context_metadata(&cache_dir, &project)?;
    let members = match gap_members_from_kernel_context(&kernel_context) {
        Ok(members) => members,
        Err(reason) => {
            return tool_json_error_result(get_kernel_refused(
                &project,
                mode,
                ASTRO_GET_KERNEL_CONTEXT_UNAVAILABLE,
                reason,
                "rerun index_repository with calyx=\"shadow\" so the kernel context scope summaries are persisted before requesting kernel gaps",
            ));
        }
    };

    match mode {
        "gaps" => tool_json_result(gap_report_value(&project, &members)),
        "quadrant" => tool_json_result(quadrant_value(&project, &members)),
        other => tool_json_error_result(get_kernel_refused(
            &project,
            other,
            ASTRO_GET_KERNEL_MODE_UNSUPPORTED,
            format!("get_kernel mode {other:?} is not available"),
            "use mode=\"gaps\" (default) or mode=\"quadrant\"",
        )),
    }
}

/// One kernel member read back from the persisted kernel-context scope summaries.
#[derive(Debug, Clone)]
struct GapMember {
    scope_id: String,
    symbol_id: String,
    qualified_name: String,
    kernel_weight: u64,
    grounded: bool,
    provenance_ref: String,
}

/// Extracts the kernel members from the persisted kernel-context metadata, or a
/// reason string when the scope summaries are unavailable (fail-closed).
fn gap_members_from_kernel_context(kernel_context: &Value) -> Result<Vec<GapMember>, String> {
    let scope_summaries = kernel_context
        .get("scope_summaries")
        .ok_or_else(|| "kernel context carries no scope_summaries block".to_string())?;
    let status = scope_summaries
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    if status == "unavailable" {
        let reason = scope_summaries
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("kernel context scope summaries unavailable");
        return Err(reason.to_string());
    }

    let mut members = Vec::new();
    if let Some(summaries) = scope_summaries.get("summaries").and_then(Value::as_array) {
        for summary in summaries {
            let scope_id = summary
                .get("scope_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let Some(rows) = summary.get("members").and_then(Value::as_array) else {
                continue;
            };
            for row in rows {
                let symbol_id = row
                    .get("symbol_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if symbol_id.is_empty() {
                    continue;
                }
                members.push(GapMember {
                    scope_id: scope_id.clone(),
                    symbol_id,
                    qualified_name: row
                        .get("qualified_name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    kernel_weight: row
                        .get("kernel_weight")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    grounded: row
                        .get("grounded")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    provenance_ref: row
                        .get("provenance_ref")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                });
            }
        }
    }
    Ok(members)
}

/// The grounding-gap report envelope: ungrounded members ranked by persisted
/// kernel weight, `symbol_id` ascending on a tie.
fn gap_report_value(project: &str, members: &[GapMember]) -> Value {
    let mut gaps: Vec<&GapMember> = members.iter().filter(|member| !member.grounded).collect();
    gaps.sort_by(|left, right| {
        right
            .kernel_weight
            .cmp(&left.kernel_weight)
            .then_with(|| left.symbol_id.cmp(&right.symbol_id))
    });
    let gap_rows: Vec<Value> = gaps
        .iter()
        .map(|member| {
            json!({
                "scope_id": member.scope_id,
                "symbol_id": member.symbol_id,
                "qualified_name": member.qualified_name,
                "kernel_weight": member.kernel_weight,
                "grounded": false,
                "provenance_ref": member.provenance_ref,
            })
        })
        .collect();

    json!({
        "schema": GROUNDING_GAP_SCHEMA,
        "project": project,
        "mode": "gaps",
        "status": "served",
        "member_count": members.len(),
        "gap_count": gap_rows.len(),
        "gaps": gap_rows,
        // Honest degradation: the persisted kernel-context metadata carries the
        // grounded flag and kernel weight but not the change-frequency churn or the
        // exact hop-distance to the nearest Trusted anchor. The blueprint ranking is
        // kernel_score × churn; this surface ranks by persisted kernel weight alone
        // until the persisted kernel artifact is read back.
        "ranking_basis": "kernel_weight",
        "degraded": true,
        "remediation": "the full kernel_score × churn ranking and the 3-hop grounding boundary require the persisted kernel artifact; this metadata surface ranks by kernel_weight and derives gaps from the persisted grounded flag",
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": [
            format!("kernel_context.scope_summaries:project={project}"),
            "metadata:kernel_context_json",
            "gap=!scope_summary.member.grounded",
        ],
    })
}

/// The coverage-vs-importance quadrant envelope. Importance is the persisted
/// kernel weight normalized to permille against the scope maximum; coverage is
/// the persisted grounded flag (grounded → full density, gap → zero). Every
/// member is classified with the kernel crate's registry-knob split.
fn quadrant_value(project: &str, members: &[GapMember]) -> Value {
    let config = QuadrantConfig::with_registry_defaults();
    let max_weight = members
        .iter()
        .map(|member| member.kernel_weight)
        .max()
        .unwrap_or(0);

    let mut points: Vec<(GapQuadrant, u64, &GapMember)> = members
        .iter()
        .map(|member| {
            let importance_permille = if max_weight == 0 {
                0
            } else {
                member
                    .kernel_weight
                    .saturating_mul(1000)
                    .checked_div(max_weight)
                    .unwrap_or(0)
            };
            let density_permille = if member.grounded { 1000 } else { 0 };
            let quadrant = classify_quadrant(importance_permille, density_permille, &config);
            (quadrant, importance_permille, member)
        })
        .collect();
    points.sort_by(|left, right| {
        quadrant_ordinal(left.0)
            .cmp(&quadrant_ordinal(right.0))
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| left.2.symbol_id.cmp(&right.2.symbol_id))
    });

    let count_in = |target: GapQuadrant| {
        points
            .iter()
            .filter(|(quadrant, _, _)| *quadrant == target)
            .count()
    };
    let point_rows: Vec<Value> = points
        .iter()
        .map(|(quadrant, importance_permille, member)| {
            json!({
                "scope_id": member.scope_id,
                "symbol_id": member.symbol_id,
                "qualified_name": member.qualified_name,
                "kernel_weight": member.kernel_weight,
                "importance_permille": importance_permille,
                "anchor_density_permille": if member.grounded { 1000 } else { 0 },
                "grounded": member.grounded,
                "quadrant": quadrant.as_str(),
            })
        })
        .collect();

    json!({
        "schema": COVERAGE_QUADRANT_SCHEMA,
        "project": project,
        "mode": "quadrant",
        "status": "served",
        "importance_threshold_permille": config.importance_threshold_permille,
        "anchor_density_threshold_permille": config.anchor_density_threshold_permille,
        "member_count": members.len(),
        "critical_unverified_count": count_in(GapQuadrant::CriticalUnverified),
        "critical_covered_count": count_in(GapQuadrant::CriticalCovered),
        "peripheral_unverified_count": count_in(GapQuadrant::PeripheralUnverified),
        "peripheral_covered_count": count_in(GapQuadrant::PeripheralCovered),
        "points": point_rows,
        "degraded": true,
        "remediation": "importance is the persisted kernel_weight normalized to permille; the anchor-density axis is binary (grounded flag) because the per-member groundedness permille lives in the persisted kernel artifact, not this metadata surface",
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": [
            format!("kernel_context.scope_summaries:project={project}"),
            "metadata:kernel_context_json",
            "classify_quadrant:astrolabe_kernel::gaps",
        ],
    })
}

fn quadrant_ordinal(quadrant: GapQuadrant) -> u8 {
    match quadrant {
        GapQuadrant::CriticalUnverified => 0,
        GapQuadrant::CriticalCovered => 1,
        GapQuadrant::PeripheralUnverified => 2,
        GapQuadrant::PeripheralCovered => 3,
    }
}

fn get_kernel_refused(
    project: &str,
    mode: &str,
    code: &str,
    message: impl Into<String>,
    remediation: &str,
) -> Value {
    json!({
        "schema": GROUNDING_GAP_SCHEMA,
        "project": project,
        "mode": mode,
        "status": "refused",
        "code": code,
        "message": message.into(),
        "remediation": remediation,
        "trust": "provisional",
        "freshness": "not_evaluated",
        "provenance": ["refusal:get_kernel"],
    })
}
