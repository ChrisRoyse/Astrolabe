use super::*;

use astrolabe_kernel::{
    COVERAGE_QUADRANT_SCHEMA, CoverageImportanceQuadrant, GROUNDING_GAP_SCHEMA, GapQuadrant,
    GroundingGapReport, KernelArtifact, QuadrantConfig, classify_quadrant,
    coverage_importance_quadrant, coverage_importance_quadrant_artifact_bytes,
    grounding_gap_report, grounding_gap_report_artifact_bytes,
};

/// Serves the ranked grounding-gap report from the persisted `KernelArtifact`
/// (#365): the real `kernel_score × churn` ranking with the exact
/// groundedness-hop boundary and per-member groundedness permille, not the
/// degraded kernel-weight scope-summary surface. The served envelope carries the
/// crate's canonical report-bytes digest so an independent FSV recomputes
/// `grounding_gap_report_artifact_bytes(&grounding_gap_report(&artifact))` and
/// byte-matches it.
pub(crate) fn artifact_gap_report_value(project: &str, artifact: &KernelArtifact) -> Value {
    let report: GroundingGapReport = grounding_gap_report(artifact);
    let artifact_bytes = grounding_gap_report_artifact_bytes(&report);
    let report_sha256 = hex_lower(&Sha256::digest(&artifact_bytes));
    let gap_rows: Vec<Value> = report
        .gaps
        .iter()
        .map(|gap| {
            json!({
                "scope_id": report.scope_id,
                "symbol_id": hex_lower(gap.id.as_bytes()),
                "kernel_score_permille": gap.kernel_score_permille,
                "churn": gap.churn,
                "rank_score": gap.rank_score.to_string(),
                "groundedness_permille": gap.groundedness_permille,
                "in_fvs": gap.in_fvs,
                "grounded": false,
            })
        })
        .collect();

    json!({
        "schema": GROUNDING_GAP_SCHEMA,
        "project": project,
        "scope_id": report.scope_id,
        "mode": "gaps",
        "status": "served",
        "source": "kernel_artifact",
        "hop_limit": report.hop_limit,
        "has_trusted_anchor": report.has_trusted_anchor,
        "member_count": report.member_count,
        "gap_count": report.gap_count,
        "gaps": gap_rows,
        // The real blueprint ranking: kernel_score × churn with the exact hop
        // boundary, read back from the persisted artifact — no longer degraded.
        "ranking_basis": "kernel_score_times_churn",
        "degraded": false,
        "artifact_report_sha256": report_sha256,
        "trust": report.trust,
        "freshness": report.freshness,
        "provenance": [
            format!("kernel-artifact:scope={}", report.scope_id),
            "vault:ColumnFamily::Kernel".to_string(),
            "astrolabe_kernel::grounding_gap_report".to_string(),
        ],
    })
}

/// Serves the coverage-vs-importance quadrant from the persisted `KernelArtifact`
/// (#365): the anchor-density axis is the real per-member groundedness permille
/// (not the binary grounded flag). Carries the canonical quadrant-bytes digest for
/// a byte-match FSV. Fails closed (labeled) if a split threshold is out of bounds.
pub(crate) fn artifact_quadrant_value(project: &str, artifact: &KernelArtifact) -> Value {
    let config = QuadrantConfig::with_registry_defaults();
    let quadrant: CoverageImportanceQuadrant = match coverage_importance_quadrant(artifact, &config)
    {
        Ok(quadrant) => quadrant,
        Err(error) => {
            return json!({
                "schema": COVERAGE_QUADRANT_SCHEMA,
                "project": project,
                "mode": "quadrant",
                "status": "refused",
                "code": error.code(),
                "message": error.message(),
                "remediation": error.remediation(),
                "trust": "provisional",
                "freshness": "not_evaluated",
            });
        }
    };
    let artifact_bytes = coverage_importance_quadrant_artifact_bytes(&quadrant);
    let quadrant_sha256 = hex_lower(&Sha256::digest(&artifact_bytes));
    let point_rows: Vec<Value> = quadrant
        .points
        .iter()
        .map(|point| {
            json!({
                "scope_id": quadrant.scope_id,
                "symbol_id": hex_lower(point.id.as_bytes()),
                "kernel_score_permille": point.kernel_score_permille,
                "anchor_density_permille": point.anchor_density_permille,
                "churn": point.churn,
                "grounded": point.grounded,
                "quadrant": point.quadrant.as_str(),
            })
        })
        .collect();

    json!({
        "schema": COVERAGE_QUADRANT_SCHEMA,
        "project": project,
        "scope_id": quadrant.scope_id,
        "mode": "quadrant",
        "status": "served",
        "source": "kernel_artifact",
        "importance_threshold_permille": quadrant.config.importance_threshold_permille,
        "anchor_density_threshold_permille": quadrant.config.anchor_density_threshold_permille,
        "has_trusted_anchor": quadrant.has_trusted_anchor,
        "member_count": quadrant.member_count,
        "critical_unverified_count": quadrant.critical_unverified_count,
        "critical_covered_count": quadrant.critical_covered_count,
        "peripheral_unverified_count": quadrant.peripheral_unverified_count,
        "peripheral_covered_count": quadrant.peripheral_covered_count,
        "points": point_rows,
        // The real anchor-density axis is the per-member groundedness permille from
        // the persisted artifact — no longer the binary grounded-flag degradation.
        "degraded": false,
        "artifact_quadrant_sha256": quadrant_sha256,
        "trust": quadrant.trust,
        "freshness": quadrant.freshness,
        "provenance": [
            format!("kernel-artifact:scope={}", quadrant.scope_id),
            "vault:ColumnFamily::Kernel".to_string(),
            "astrolabe_kernel::coverage_importance_quadrant".to_string(),
        ],
    })
}

// #39 + #40 unification: the `get_kernel` MCP handler lives in `kernel_answer`
// (the single tool exposing modes read|gaps|quadrant|build). This module owns the
// grounding-gap (#39) member extraction, the ranked gap report, and the
// coverage-vs-importance quadrant that the `gaps`/`quadrant` modes serve; the
// handler calls `gap_members_from_kernel_context`, `gap_report_value`, and
// `quadrant_value` below.

/// One kernel member read back from the persisted kernel-context scope summaries.
#[derive(Debug, Clone)]
pub(crate) struct GapMember {
    scope_id: String,
    symbol_id: String,
    qualified_name: String,
    kernel_weight: u64,
    grounded: bool,
    provenance_ref: String,
}

/// Extracts the kernel members from the persisted kernel-context metadata, or a
/// reason string when the scope summaries are unavailable (fail-closed).
pub(crate) fn gap_members_from_kernel_context(
    kernel_context: &Value,
) -> Result<Vec<GapMember>, String> {
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
pub(crate) fn gap_report_value(project: &str, members: &[GapMember]) -> Value {
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
pub(crate) fn quadrant_value(project: &str, members: &[GapMember]) -> Value {
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
