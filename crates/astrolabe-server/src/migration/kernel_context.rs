use super::*;
pub(crate) const KERNEL_CONTEXT_SCHEMA: &str = "astrolabe.kernel_context.v1";
pub(crate) const SCOPE_SUMMARY_COLLECTION_SCHEMA: &str = "astrolabe.scope_summary_collection.v1";

/// Schema tag for the index-time persisted-kernel-artifact summary surfaced on the
/// shadow import outcome (#365).
pub(crate) const KERNEL_ARTIFACT_PERSIST_SCHEMA: &str = "astrolabe.kernel_artifact_persist.v1";

/// The stable scope identity a shadow-imported project's whole-repo kernel is
/// persisted and served under (#365). One serializer for the index-time persist
/// hook and every serve-time readback so the artifact key never diverges.
pub(crate) fn kernel_artifact_scope_id(project: &str) -> String {
    format!("repo:{project}")
}

/// Index-time hook (#365): persists the real `KernelArtifact` for the freshly
/// imported project into the vault Kernel CF via `build_and_persist_kernel`, using
/// the promotion-aware per-symbol anchor trust map (#352) as the groundedness
/// input, and returns a labeled summary for the import outcome.
///
/// Best-effort and fail-open on the *import*: a scope that cannot yet build a
/// kernel (no typed edges, an unreachable recall gate, an empty anchor set) is a
/// legitimate "not persisted yet" state, surfaced with a labeled reason rather
/// than aborting the whole index. The persist path itself is fail-closed
/// internally (it reads its own bytes back and refuses on divergence); this
/// wrapper only decides that a build refusal degrades the surface, never the
/// index. The persisted bytes are independently read back by the serve path.
pub(crate) fn persist_index_time_kernel_artifact<C>(vault: &AsterVault<C>, project: &str) -> Value
where
    C: Clock,
{
    let scope_id = kernel_artifact_scope_id(project);
    let anchor_trust = match astrolabe_anchors::effective_anchor_trust_map(vault) {
        Ok(map) => map,
        Err(error) => {
            return kernel_artifact_persist_unavailable(
                &scope_id,
                &format!("promotion-aware anchor trust map unavailable: {error}"),
            );
        }
    };
    let trusted_anchor_count = anchor_trust
        .values()
        .filter(|tag| matches!(tag, astrolabe_anchors::TrustTag::Trusted))
        .count();
    let config = astrolabe_kernel::KernelBuildConfig::with_registry_defaults();
    let options = astrolabe_ingest::GraphProjectionBuildOptions::new();
    match astrolabe_ingest::build_and_persist_kernel(
        vault,
        &scope_id,
        &anchor_trust,
        &config,
        &options,
    ) {
        Ok(report) => json!({
            "schema": KERNEL_ARTIFACT_PERSIST_SCHEMA,
            "status": "persisted",
            "scope_id": report.scope_id,
            "members_hash": report.members_hash,
            "member_count": report.member_count,
            "node_count": report.node_count,
            "recall_permille": report.recall_permille,
            "recall_gated": report.recall_gated,
            "anchor_grounded": report.anchor_grounded,
            "trusted_anchor_count": trusted_anchor_count,
            "rows_readback_verified": report.rows_readback_verified,
            "ledger_paired": report.ledger_paired,
            "commit_seq": report.commit_seq,
            "trust": if report.anchor_grounded { "verified" } else { "provisional" },
            "freshness": "fresh",
            "provenance": [
                format!("kernel-artifact:scope={scope_id}"),
                "vault:ColumnFamily::Kernel".to_string(),
                "anchors:effective_anchor_trust_map(#352)".to_string(),
            ],
        }),
        Err(error) => kernel_artifact_persist_unavailable(
            &scope_id,
            &format!("kernel build not persisted: {error}"),
        ),
    }
}

/// A labeled "not persisted" kernel-artifact summary — the honest surface when the
/// scope cannot yet yield a kernel (invariant 3).
pub(crate) fn kernel_artifact_persist_unavailable(scope_id: &str, reason: &str) -> Value {
    json!({
        "schema": KERNEL_ARTIFACT_PERSIST_SCHEMA,
        "status": "unavailable",
        "scope_id": scope_id,
        "reason": reason,
        "trust": "provisional",
        "freshness": "not_evaluated",
        "provenance": ["fallback:kernel-artifact-not-persisted"],
    })
}

pub(crate) fn kernel_context_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    let label_propagation = label_propagation_from_row_sink_rows(rows);
    let scope_summaries = scope_summaries_from_row_sink_rows(rows);
    kernel_context_json(label_propagation, scope_summaries)
}

pub(crate) fn label_propagation_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    let (seeds, tombstones, skipped_properties) = label_seed_inputs_from_rows(rows);
    let edges = label_graph_edges_from_rows(rows);
    match propagate_labels(
        &seeds,
        &edges,
        &tombstones,
        &LabelPropagationConfig::default(),
    ) {
        Ok(report) => label_propagation_json(
            &report,
            seeds.len(),
            edges.len(),
            tombstones.len(),
            skipped_properties,
        ),
        Err(error) => {
            label_propagation_unavailable_json(&format!("label propagation failed: {error}"))
        }
    }
}

pub(crate) fn label_seed_inputs_from_rows(
    rows: &CbmPipelineRows,
) -> (Vec<LabelSeed>, Vec<LabelTombstone>, usize) {
    let mut seeds = Vec::new();
    let mut tombstones = Vec::new();
    let mut skipped_properties = 0;

    for node in &rows.nodes {
        if node.qualified_name.trim().is_empty() || node.label.eq_ignore_ascii_case("project") {
            continue;
        }
        let properties = match serde_json::from_str::<Value>(&node.properties_json) {
            Ok(properties) => properties,
            Err(_) => {
                skipped_properties += 1;
                continue;
            }
        };
        if let Some(values) = properties
            .get("label_seeds")
            .or_else(|| properties.get("grounded_labels"))
            .and_then(Value::as_array)
        {
            for value in values {
                let Some(label) = value
                    .get("label")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|label| !label.is_empty())
                else {
                    skipped_properties += 1;
                    continue;
                };
                let confidence = value
                    .get("confidence_millipoints")
                    .and_then(Value::as_u64)
                    .unwrap_or(1_000);
                if confidence == 0 {
                    skipped_properties += 1;
                    continue;
                }
                let provenance = value
                    .get("provenance_ref")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| format!("row_sink:{}:{}#label_seed", node.project, node.id));
                seeds.push(LabelSeed::new(
                    node.qualified_name.clone(),
                    label.to_string(),
                    confidence,
                    provenance,
                ));
            }
        }
        if let Some(values) = properties.get("label_tombstones").and_then(Value::as_array) {
            for value in values {
                let symbol_id = value
                    .get("symbol_id")
                    .and_then(Value::as_str)
                    .unwrap_or(&node.qualified_name);
                let provenance = value
                    .get("provenance_ref")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| {
                        format!("row_sink:{}:{}#label_tombstone", node.project, node.id)
                    });
                tombstones.push(LabelTombstone::new(symbol_id.to_string(), provenance));
            }
        }
    }

    (seeds, tombstones, skipped_properties)
}

pub(crate) fn label_graph_edges_from_rows(rows: &CbmPipelineRows) -> Vec<LabelGraphEdge> {
    let node_names = rows
        .nodes
        .iter()
        .filter(|node| !node.qualified_name.trim().is_empty())
        .map(|node| (node.id, node.qualified_name.clone()))
        .collect::<BTreeMap<_, _>>();
    rows.edges
        .iter()
        .filter_map(|edge| {
            let left = node_names.get(&edge.source_id)?;
            let right = node_names.get(&edge.target_id)?;
            Some(LabelGraphEdge::new(
                left.clone(),
                right.clone(),
                label_edge_provenance(edge),
            ))
        })
        .collect()
}

pub(crate) fn label_edge_provenance(edge: &astrolabe_bridge::CbmPipelineEdgeRow) -> String {
    serde_json::from_str::<Value>(&edge.properties_json)
        .ok()
        .and_then(|properties| {
            properties
                .get("provenance_ref")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| format!("row_sink:edge:{}:{}", edge.id, edge.edge_type))
}

pub(crate) fn label_propagation_json(
    report: &LabelPropagationReport,
    seed_count: usize,
    edge_count: usize,
    tombstone_count: usize,
    skipped_properties: usize,
) -> Value {
    let artifact_bytes = label_propagation_artifact_bytes(report);
    let status = if skipped_properties > 0 {
        "partial"
    } else if report.empty_reason.is_some() {
        "empty"
    } else {
        "built"
    };
    json!({
        "schema": report.schema,
        "status": status,
        "knob_registry_version": report.knob_registry_version,
        "decay_milliper_step": report.decay_milliper_step,
        "seed_count": seed_count,
        "edge_count": edge_count,
        "tombstone_count": tombstone_count,
        "skipped_count": skipped_properties,
        "label_count": report.labels.len(),
        "empty_reason": report.empty_reason,
        "artifact_sha256": hex_lower(&Sha256::digest(&artifact_bytes)),
        "labels": report.labels.iter().map(propagated_label_json).collect::<Vec<_>>(),
        "freshness": report.freshness,
        "trust": if skipped_properties == 0 { report.trust } else { "provisional" },
    })
}

pub(crate) fn propagated_label_json(label: &astrolabe_kernel::PropagatedLabel) -> Value {
    json!({
        "symbol_id": label.symbol_id,
        "label": label.label,
        "confidence_millipoints": label.confidence_millipoints,
        "seed_symbol_id": label.seed_symbol_id,
        "seed_confidence_millipoints": label.seed_confidence_millipoints,
        "distance": label.distance,
        "provenance": {
            "seed_provenance_ref": label.provenance.seed_provenance_ref,
            "graph_provenance_refs": label.provenance.graph_provenance_refs,
            "math": label.provenance.math,
        },
        "freshness": label.freshness,
        "trust": label.trust.as_str(),
    })
}

pub(crate) fn label_propagation_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": LABEL_PROPAGATION_SCHEMA,
        "status": "unavailable",
        "knob_registry_version": LABEL_PROPAGATION_KNOB_REGISTRY_VERSION,
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": "rerun index_repository with label seed metadata and graph edges available before using propagated-label filters",
    })
}

pub(crate) fn scope_summaries_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    let (inputs, skipped_properties) = scope_summary_inputs_from_rows(rows);
    if inputs.is_empty() {
        return scope_summaries_unavailable_json(
            "scope summary metadata missing; row-sink nodes must declare kernel_scopes/summary_scopes/scopes",
        );
    }
    let summaries = inputs
        .iter()
        .map(summarize_scope_kernel)
        .collect::<Vec<_>>();
    scope_summaries_json(&summaries, skipped_properties)
}

pub(crate) fn scope_summary_inputs_from_rows(
    rows: &CbmPipelineRows,
) -> (Vec<ScopeSummaryInput>, usize) {
    let fingerprint = hex_lower(&row_sink_fingerprint(rows));
    let mut by_scope = BTreeMap::<String, Vec<ScopeSummaryMember>>::new();
    let mut grounded_by_scope = BTreeMap::<String, bool>::new();
    let mut recall_by_scope = BTreeMap::<String, ScopeRecallMeasurement>::new();
    let mut skipped_properties = 0;

    for node in &rows.nodes {
        if node.qualified_name.trim().is_empty() || node.label.eq_ignore_ascii_case("project") {
            continue;
        }
        let properties = match serde_json::from_str::<Value>(&node.properties_json) {
            Ok(properties) => properties,
            Err(_) => {
                skipped_properties += 1;
                continue;
            }
        };
        let scopes = scope_summary_scopes_for_node(&properties);
        if scopes.is_empty() {
            continue;
        }
        let grounded = properties
            .get("kernel_grounded")
            .or_else(|| properties.get("grounded"))
            .and_then(Value::as_bool)
            .unwrap_or(true);

        for scope in scopes {
            let member = ScopeSummaryMember::new(
                node.qualified_name.clone(),
                node.qualified_name.clone(),
                bridge_node_kernel_weight(&properties, &scope),
                grounded,
                scope_node_provenance(node, &properties, &scope),
            );
            by_scope.entry(scope.clone()).or_default().push(member);
            grounded_by_scope
                .entry(scope.clone())
                .and_modify(|scope_grounded| *scope_grounded = *scope_grounded && grounded)
                .or_insert(grounded);
            if let Some(recall) = scope_recall_for_node(&properties, &scope) {
                recall_by_scope.entry(scope).or_insert(recall);
            }
        }
    }

    let inputs = by_scope
        .into_iter()
        .map(|(scope_id, members)| {
            ScopeSummaryInput::new(
                scope_id.clone(),
                format!("row-sink:{fingerprint}:{scope_id}"),
                grounded_by_scope.get(&scope_id).copied().unwrap_or(false),
                members,
                recall_by_scope.get(&scope_id).copied(),
            )
        })
        .collect();
    (inputs, skipped_properties)
}

pub(crate) fn scope_summary_scopes_for_node(properties: &Value) -> Vec<String> {
    let mut scopes = BTreeSet::new();
    for field in ["kernel_scopes", "summary_scopes", "scope_ids", "scopes"] {
        if let Some(values) = properties.get(field).and_then(Value::as_array) {
            for value in values {
                if let Some(scope) = value
                    .as_str()
                    .map(str::trim)
                    .filter(|scope| !scope.is_empty())
                {
                    scopes.insert(scope.to_string());
                }
            }
        }
    }
    if let Some(scope) = properties
        .get("scope")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
    {
        scopes.insert(scope.to_string());
    }
    scopes.into_iter().collect()
}

pub(crate) fn scope_node_provenance(
    node: &astrolabe_bridge::CbmPipelineNodeRow,
    properties: &Value,
    scope: &str,
) -> String {
    properties
        .get("kernel_scope_provenance")
        .or_else(|| properties.get("scope_provenance"))
        .and_then(Value::as_object)
        .and_then(|provenance| provenance.get(scope))
        .and_then(Value::as_str)
        .or_else(|| properties.get("provenance_ref").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format!(
                "row_sink:{}:{}#scope_summary:{scope}",
                node.project, node.id
            )
        })
}

pub(crate) fn scope_recall_for_node(
    properties: &Value,
    scope: &str,
) -> Option<ScopeRecallMeasurement> {
    let recall = properties.get("scope_recall")?;
    let direct = recall
        .get("recalled")
        .and_then(Value::as_u64)
        .zip(recall.get("total").and_then(Value::as_u64));
    let scoped = recall
        .get(scope)
        .and_then(Value::as_object)
        .and_then(|value| {
            value
                .get("recalled")
                .and_then(Value::as_u64)
                .zip(value.get("total").and_then(Value::as_u64))
        });
    direct.or(scoped).and_then(|(recalled, total)| {
        (total > 0).then_some(ScopeRecallMeasurement { recalled, total })
    })
}

pub(crate) fn scope_summaries_json(summaries: &[ScopeSummary], skipped_properties: usize) -> Value {
    let mut artifact_bytes = Vec::new();
    for summary in summaries {
        artifact_bytes.extend(scope_summary_artifact_bytes(summary));
    }
    let all_verified =
        skipped_properties == 0 && summaries.iter().all(|summary| summary.trust == "verified");
    json!({
        "schema": SCOPE_SUMMARY_COLLECTION_SCHEMA,
        "summary_schema": SCOPE_SUMMARY_SCHEMA,
        "status": if skipped_properties == 0 { "built" } else { "partial" },
        "summary_count": summaries.len(),
        "skipped_count": skipped_properties,
        "artifact_sha256": hex_lower(&Sha256::digest(&artifact_bytes)),
        "summaries": summaries.iter().map(scope_summary_json).collect::<Vec<_>>(),
        "freshness": "fresh",
        "trust": if all_verified { "verified" } else { "provisional" },
    })
}

pub(crate) fn scope_summary_json(summary: &ScopeSummary) -> Value {
    json!({
        "schema": summary.schema,
        "scope_id": summary.scope_id,
        "dirty_region_hash": summary.dirty_region_hash,
        "summary_hash": summary.summary_hash,
        "recall": summary.recall.map(|recall| json!({
            "recalled": recall.recalled,
            "total": recall.total,
        })),
        "recall_millipoints": summary.recall_millipoints,
        "grounded_member_count": summary.grounded_member_count,
        "total_member_count": summary.total_member_count,
        "grounded_fraction_millipoints": summary.grounded_fraction_millipoints,
        "members": summary.members.iter().map(|member| {
            json!({
                "symbol_id": member.symbol_id,
                "qualified_name": member.qualified_name,
                "kernel_weight": member.kernel_weight,
                "grounded": member.grounded,
                "provenance_ref": member.provenance_ref,
            })
        }).collect::<Vec<_>>(),
        "freshness": summary.freshness,
        "trust": summary.trust,
    })
}

pub(crate) fn scope_summaries_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": SCOPE_SUMMARY_COLLECTION_SCHEMA,
        "summary_schema": SCOPE_SUMMARY_SCHEMA,
        "status": "unavailable",
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": "rerun index_repository with explicit scope metadata before using kernel summary architecture aspects",
    })
}

pub(crate) fn kernel_context_json(label_propagation: Value, scope_summaries: Value) -> Value {
    let label_status = label_propagation
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    let scope_status = scope_summaries
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    let status = if label_status == "unavailable" && scope_status == "unavailable" {
        "unavailable"
    } else if matches!(label_status, "built" | "empty") && scope_status == "built" {
        "built"
    } else {
        "partial"
    };
    let trust =
        if label_propagation["trust"] == "verified" && scope_summaries["trust"] == "verified" {
            "verified"
        } else {
            "provisional"
        };
    json!({
        "schema": KERNEL_CONTEXT_SCHEMA,
        "status": status,
        "label_propagation": label_propagation,
        "scope_summaries": scope_summaries,
        "freshness": if status == "unavailable" { "not_evaluated" } else { "fresh" },
        "trust": trust,
    })
}

pub(crate) fn kernel_context_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": KERNEL_CONTEXT_SCHEMA,
        "status": "unavailable",
        "label_propagation": label_propagation_unavailable_json(reason),
        "scope_summaries": scope_summaries_unavailable_json(reason),
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": "rerun index_repository with row-sink label and scope metadata before using kernel context surfaces",
    })
}

/// #69 box 5 — exact set of symbol ids carrying `label` as a *propagated* label in
/// the persisted kernel context. Fails closed (coded) when propagation is
/// unavailable so the search filter never silently degrades into an unfiltered or
/// spuriously empty result. Same exact-match semantics as the kernel's
/// [`astrolabe_kernel::filter_symbols_by_propagated_label`].
pub(crate) fn propagated_label_symbol_ids(
    kernel_context: &Value,
    label: &str,
) -> Result<BTreeSet<String>, String> {
    let propagation = kernel_context
        .get("label_propagation")
        .unwrap_or(&Value::Null);
    let status = propagation
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    if status == "unavailable" {
        let reason = propagation
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("label propagation metadata unavailable");
        return Err(format!(
            "ASTRO_SEARCH_GRAPH_PROPAGATED_LABEL_UNAVAILABLE: cannot apply propagated_label filter {label:?}: {reason}; remediation: rerun index_repository with calyx=\"shadow\" so label seeds and graph edges are propagated before filtering search_graph by a propagated label"
        ));
    }
    let mut ids = BTreeSet::new();
    if let Some(labels) = propagation.get("labels").and_then(Value::as_array) {
        for entry in labels {
            if entry.get("label").and_then(Value::as_str) == Some(label)
                && let Some(symbol_id) = entry
                    .get("symbol_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|symbol_id| !symbol_id.is_empty())
            {
                ids.insert(symbol_id.to_string());
            }
        }
    }
    Ok(ids)
}

/// #69 box 5 — rewrite a raw `search_graph` tool result, keeping only hits whose
/// symbol id is in `labeled_symbols` (exact match, original hit order preserved).
/// Annotates both the `structuredContent` and the mirrored `content[0].text`
/// payload with the applied filter, at provisional trust (propagated labels are
/// inferences, never trusted).
pub(crate) fn filter_search_graph_result_by_label(
    raw_result: &str,
    label: &str,
    labeled_symbols: &BTreeSet<String>,
) -> Result<String, DynError> {
    let mut value: Value = serde_json::from_str(raw_result)?;

    if let Some(structured) = value
        .get_mut("structuredContent")
        .and_then(Value::as_object_mut)
    {
        let (input_count, matched_count) = retain_labeled_results(structured, labeled_symbols);
        structured.insert(
            "astrolabe_propagated_label_filter".to_string(),
            search_graph_filter_meta_json(label, input_count, matched_count),
        );
    }

    if let Some(text) = value
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(|item| item.get_mut("text"))
        && let Some(raw_text) = text.as_str()
        && let Ok(mut text_value) = serde_json::from_str::<Value>(raw_text)
        && let Some(text_obj) = text_value.as_object_mut()
    {
        let (input_count, matched_count) = retain_labeled_results(text_obj, labeled_symbols);
        text_obj.insert(
            "astrolabe_propagated_label_filter".to_string(),
            search_graph_filter_meta_json(label, input_count, matched_count),
        );
        *text = Value::String(serde_json::to_string(&text_value)?);
    }

    Ok(serde_json::to_string(&value)?)
}

/// Retain only the `results[]` entries whose symbol id is in `labeled_symbols`.
/// Returns `(input_count, matched_count)` and rewrites any mirrored count field so
/// the surfaced total never lies about the post-filter hit count.
fn retain_labeled_results(
    obj: &mut Map<String, Value>,
    labeled_symbols: &BTreeSet<String>,
) -> (usize, usize) {
    let Some(results) = obj.get_mut("results").and_then(Value::as_array_mut) else {
        return (0, 0);
    };
    let input_count = results.len();
    results.retain(|hit| {
        let candidate = hit
            .get("qualified_name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .or_else(|| hit.get("name").and_then(Value::as_str))
            .unwrap_or_default();
        labeled_symbols.contains(candidate)
    });
    let matched_count = results.len();
    for key in ["result_count", "count", "total_results", "returned"] {
        if let Some(existing) = obj.get_mut(key)
            && existing.as_u64() == Some(input_count as u64)
        {
            *existing = json!(matched_count);
        }
    }
    (input_count, matched_count)
}

fn search_graph_filter_meta_json(label: &str, input_count: usize, matched_count: usize) -> Value {
    json!({
        "schema": "astrolabe.search_graph_propagated_label_filter.v1",
        "label": label,
        "input_count": input_count,
        "matched_count": matched_count,
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": "kernel_context.label_propagation (astrolabe.label_propagation.v1)",
    })
}

pub(crate) fn read_kernel_context_metadata(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let Some(raw) = read_config_value(cache_dir, &metadata_key(project, "kernel_context_json"))?
    else {
        return Ok(kernel_context_unavailable_json(
            "kernel context metadata missing; rerun index_repository with calyx shadow",
        ));
    };
    match serde_json::from_str::<Value>(&raw) {
        Ok(value) => Ok(value),
        Err(error) => Ok(kernel_context_unavailable_json(&format!(
            "stored kernel_context_json invalid: {error}"
        ))),
    }
}
