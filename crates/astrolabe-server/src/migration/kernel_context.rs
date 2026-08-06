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

fn stable_identity_by_cx<C>(
    vault: &AsterVault<C>,
    project: &str,
) -> Result<BTreeMap<String, (String, String)>, DynError>
where
    C: Clock,
{
    let snapshot = astrolabe_ingest::read_cbm_graph_snapshot(vault, project)?;
    let mut identity_by_cx = BTreeMap::new();
    let mut seen_atoms = BTreeSet::new();
    for node in snapshot.nodes {
        let Some(cx_id) = node.cx_id else {
            continue;
        };
        if node.atom_id.trim().is_empty() {
            return Err(format!(
                "ASTRO_KERNEL_IDENTITY_MISSING: CxId {cx_id} has no stable source atom (qualified_name={:?})",
                node.qualified_name
            )
            .into());
        }
        if !seen_atoms.insert(node.atom_id.clone()) {
            return Err(format!(
                "ASTRO_KERNEL_IDENTITY_DUPLICATE_ATOM: stable source atom {} maps to multiple CxIds",
                node.atom_id
            )
            .into());
        }
        if identity_by_cx
            .insert(
                cx_id.to_string(),
                (node.atom_id.clone(), node.qualified_name.clone()),
            )
            .is_some()
        {
            return Err(format!(
                "ASTRO_KERNEL_IDENTITY_DUPLICATE_CX: CxId {cx_id} maps to multiple source atoms"
            )
            .into());
        }
    }
    if identity_by_cx.is_empty() {
        return Err(format!(
            "ASTRO_KERNEL_IDENTITY_EMPTY: project {project:?} has no CxId-to-atom identity rows"
        )
        .into());
    }
    Ok(identity_by_cx)
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
        Ok(report) => {
            // #996: publication is not complete until the exact member HNSW and
            // CxId↔atom table are persisted and independently read back. Query
            // serving never builds this state synchronously.
            let artifact = match astrolabe_ingest::read_persisted_kernel_artifact(vault, &scope_id)
            {
                Ok(Some(artifact)) => artifact,
                Ok(None) => {
                    return kernel_artifact_persist_unavailable(
                        &scope_id,
                        "kernel artifact disappeared before member-index publication",
                    );
                }
                Err(error) => {
                    return kernel_artifact_persist_unavailable(
                        &scope_id,
                        &format!("read persisted kernel artifact for member-index build: {error}"),
                    );
                }
            };
            let member_ids = artifact
                .members
                .iter()
                .map(|member| member.id)
                .collect::<Vec<_>>();
            let member_index = match astrolabe_weave::build_kernel_member_index(
                vault,
                project,
                &member_ids,
                &artifact.members_hash,
                astrolabe_weave::search_index::IndexKnobs::defaults(0x4B45_524E_454C_0001),
            ) {
                Ok(index) => index,
                Err(error) => {
                    return kernel_artifact_persist_unavailable(
                        &scope_id,
                        &format!("build exact kernel-member index: {error}"),
                    );
                }
            };
            let member_index_report = match astrolabe_weave::persist_kernel_member_index(
                vault,
                project,
                &scope_id,
                &member_index,
            ) {
                Ok(report) => report,
                Err(error) => {
                    return kernel_artifact_persist_unavailable(
                        &scope_id,
                        &format!("persist exact kernel-member index: {error}"),
                    );
                }
            };
            json!({
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
                "ledger_ref": {
                    "seq": report.ledger_ref.seq,
                    "entry_hash": hex_lower(&report.ledger_ref.hash),
                },
                "member_index": {
                    "schema": astrolabe_weave::KERNEL_MEMBER_INDEX_SCHEMA,
                    "index_kind": member_index.index_kind.as_str(),
                    "base_seq": member_index.base_seq,
                    "indexed_member_count": member_index.indexed_member_count,
                    "missing_vector_members": member_index.missing_vector_members,
                    "semantic_dim": member_index.semantic_dim,
                    "descriptor_blake3": member_index_report.descriptor_blake3,
                    "bindings_blake3": member_index_report.bindings_blake3,
                    "hnsw_artifact_blake3": member_index_report.hnsw_artifact_blake3,
                    "commit_seq": member_index_report.commit_seq,
                    "ledger_ref": {
                        "seq": member_index_report.ledger_ref.seq,
                        "entry_hash": hex_lower(&member_index_report.ledger_ref.hash),
                    },
                    "ledger_physical_tiers": member_index_report.ledger_physical_tiers,
                    "rows_readback_verified": member_index_report.rows_readback_verified,
                },
                "trust": if report.anchor_grounded { "verified" } else { "provisional" },
                "freshness": "fresh",
                "provenance": [
                    format!("kernel-artifact:scope={scope_id}"),
                    "vault:ColumnFamily::Kernel".to_string(),
                    "anchors:effective_anchor_trust_map(#352)".to_string(),
                    "calyx:HnswIndex::to_artifact_bytes(#996)".to_string(),
                ],
            })
        }
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

/// #390 index-time hook (lane E): the grounded-label **seed producer** + live
/// propagation, run against real persisted data.
///
/// The served `kernel_context.label_propagation` was computed from the CBM
/// row-sink node properties (`label_seeds`/`grounded_labels`), which a real
/// corpus like `cbm/` never emits — so it always starved to `zero_seed_scope`.
/// This derives grounded seeds from data that genuinely exists after an index:
///
/// 1. the persisted `KernelArtifact` members (persisted immediately above by
///    [`persist_index_time_kernel_artifact`]) — the measured kernel core, each a
///    grounded, provenance-carrying seed of the `kernel-core` label; and
/// 2. any persisted `AnchorKind::Label(..)` anchors — genuine grounded labels
///    (the blueprint 5.9 / P7 source), folded in as caller seeds.
///
/// The ingest producer persists the seed graph and runs live propagation over
/// the persisted association graph (both ledger-paired and readback-verified),
/// then this reads the persisted propagated-label rows back **independently** and
/// builds the label_propagation block from those bytes. Best-effort on the index
/// (a scope that yields no grounded seed is a labeled empty, never an index
/// failure); the persistence beneath is fail-closed on its own bytes.
pub(crate) fn persist_index_time_label_propagation<C>(vault: &AsterVault<C>, project: &str) -> Value
where
    C: Clock,
{
    let scope_id = kernel_artifact_scope_id(project);
    let extra_seeds = label_anchor_seeds(vault);
    // Persisted propagation rows key on CxId. Resolve each one through the
    // current graph snapshot to the stable source atom used by search; qualified
    // name remains display metadata and may legitimately be shared.
    let identity_by_cx_hex = match stable_identity_by_cx(vault, project) {
        Ok(identity) => identity,
        Err(error) => {
            return label_propagation_unavailable_json(&format!(
                "graph identity snapshot unreadable before label propagation: {error}"
            ));
        }
    };
    match astrolabe_ingest::derive_and_propagate_index_time_labels(
        vault,
        &scope_id,
        &extra_seeds,
        &astrolabe_ingest::GraphProjectionBuildOptions::new(),
        &LabelPropagationConfig::default(),
        astrolabe_ingest::LABEL_SEED_ACTOR,
    ) {
        Ok(report) => match astrolabe_ingest::read_propagated_label_rows(vault) {
            Ok(rows) => persisted_label_propagation_json(&report, &rows, &identity_by_cx_hex),
            Err(error) => label_propagation_unavailable_json(&format!(
                "propagated label rows unreadable after propagation: {error}"
            )),
        },
        Err(error) => label_propagation_unavailable_json(&format!(
            "index-time label seed/propagation failed: {error}"
        )),
    }
}

/// Derives caller seeds from persisted `AnchorKind::Label(..)` anchors. Each
/// labeled symbol becomes one grounded seed carrying its highest-confidence
/// anchor as provenance. Fail-open on a read error (returns no anchor seeds) —
/// kernel-membership seeds still ground the scope.
fn label_anchor_seeds<C>(vault: &AsterVault<C>) -> Vec<LabelSeed>
where
    C: Clock,
{
    let Ok(rows) = astrolabe_anchors::read_anchor_rows(vault) else {
        return Vec::new();
    };
    let mut seeds = Vec::new();
    for persisted in rows {
        let calyx_core::AnchorKind::Label(name) = &persisted.row.kind else {
            continue;
        };
        let Some(best) = persisted.row.anchors.iter().max_by(|left, right| {
            left.confidence
                .partial_cmp(&right.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        }) else {
            continue;
        };
        let millipoints = (f64::from(best.confidence) * 1_000.0)
            .round()
            .clamp(1.0, 1_000.0) as u64;
        let symbol_id = persisted.row.cx_id.to_string();
        let provenance = format!("anchor:label:{name}:{}", best.source);
        seeds.push(LabelSeed::new(
            symbol_id,
            name.clone(),
            millipoints,
            provenance,
        ));
    }
    seeds
}

/// Builds the served `label_propagation` block from the **independently
/// read-back** persisted propagated-label rows (never from the producer's own
/// return value). Same field shape as [`label_propagation_json`] so the
/// `propagated_label` search filter ([`propagated_label_symbol_ids`]) consumes it
/// unchanged.
///
/// Each row's persisted `symbol_id` is a CxId hex. The served `symbol_id` is the
/// corresponding stable source atom; `qualified_name` is non-unique metadata.
fn persisted_label_propagation_json(
    report: &astrolabe_ingest::IndexTimeLabelReport,
    rows: &[astrolabe_ingest::PersistedPropagatedLabel],
    identity_by_cx_hex: &BTreeMap<String, (String, String)>,
) -> Value {
    let propagation = &report.propagation;
    if let Some(missing) = rows
        .iter()
        .find(|persisted| !identity_by_cx_hex.contains_key(&persisted.row.symbol_id))
    {
        return label_propagation_unavailable_json(&format!(
            "propagated label CxId {} has no live stable source-atom identity",
            missing.row.symbol_id
        ));
    }
    let status = if rows.is_empty() { "empty" } else { "built" };
    let labels = rows
        .iter()
        .map(|persisted| {
            let row = &persisted.row;
            let (symbol_id, qualified_name) = identity_by_cx_hex
                .get(&row.symbol_id)
                .cloned()
                .expect("all propagated label identities checked above");
            json!({
                "symbol_id": symbol_id,
                "cx_id": row.symbol_id,
                "qualified_name": qualified_name,
                "label": row.label,
                "confidence_millipoints": row.confidence_millipoints,
                "seed_symbol_id": row.seed_symbol_id,
                "seed_confidence_millipoints": row.seed_confidence_millipoints,
                "distance": row.distance,
                "provenance": {
                    "seed_provenance_ref": row.seed_provenance_ref,
                    "graph_provenance_refs": row.graph_provenance_refs,
                    "math": row.math,
                },
                "freshness": row.freshness,
                "trust": row.trust,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema": LABEL_PROPAGATION_SCHEMA,
        "status": status,
        "knob_registry_version": LABEL_PROPAGATION_KNOB_REGISTRY_VERSION,
        "decay_milliper_step": LabelPropagationConfig::default().decay_milliper_step,
        "seed_count": report.seed_count,
        "kernel_member_seed_count": report.kernel_member_seed_count,
        "extra_seed_count": report.extra_seed_count,
        "edge_count": report.edge_count,
        "seed_source_empty_reason": report.seed_source_empty_reason,
        "label_count": labels.len(),
        "empty_reason": propagation.empty_reason,
        "seeds_read": propagation.seeds_read,
        "edges_read": propagation.edges_read,
        "rows_written": propagation.rows_written,
        "ledger_seq": propagation.ledger_seq,
        "labels": labels,
        "freshness": propagation.freshness,
        "trust": propagation.trust,
        "provenance": propagation.provenance,
    })
}

/// #390: replace the row-sink-derived `label_propagation` on `base_kernel_context`
/// with the persisted-propagation block, keeping the existing `scope_summaries`,
/// and recompute the rolled-up kernel_context status/trust. Keeps the base block
/// only if the persisted one is `unavailable` (never downgrade a served surface).
pub(crate) fn kernel_context_with_persisted_labels(
    base_kernel_context: Value,
    persisted_label_propagation: Value,
) -> Value {
    // Strictly additive: only replace the served block when the persisted
    // propagation actually produced labels (`built`). An `empty`/`zero_seed_scope`
    // or `unavailable` persisted result never downgrades the row-sink block, which
    // already carries the honest empty on a corpus with no grounded seed source.
    let use_persisted = persisted_label_propagation
        .get("status")
        .and_then(Value::as_str)
        == Some("built");
    let label_propagation = if use_persisted {
        persisted_label_propagation
    } else {
        base_kernel_context
            .get("label_propagation")
            .cloned()
            .unwrap_or(persisted_label_propagation)
    };
    let scope_summaries = base_kernel_context
        .get("scope_summaries")
        .cloned()
        .unwrap_or_else(|| {
            scope_summaries_unavailable_json(
                "scope summaries missing during label-propagation merge",
            )
        });
    kernel_context_json(label_propagation, scope_summaries)
}

/// #400 index-time hook: builds the served `kernel_context.scope_summaries` block
/// from the persisted `KernelArtifact` for `project`, read back **independently**
/// of the write path.
///
/// The base `scope_summaries` (from [`scope_summaries_from_row_sink_rows`]) is
/// derived from the CBM row-sink node properties `kernel_scopes`/`summary_scopes`/
/// `scopes`, which a real corpus like `cbm/` never emits — so it always resolved
/// to the labeled `unavailable` block, and both `get_kernel mode=read` and the
/// `grounding_gaps` architecture aspect refused fail-closed even on a fully
/// indexed corpus (#400). This derives the scope summary from data that genuinely
/// exists after an index: the persisted `KernelArtifact` members — the measured
/// kernel core, each carrying a real kernel weight (`score_permille`), a
/// per-member groundedness flag, and artifact provenance. Member qualified names
/// are resolved from the persisted node map ([`read_node_map_cx_ids`]), falling
/// back to the member's `CxId` hex when a name is ambiguous/absent — never
/// invented. The single scope is the whole-repo kernel scope (`repo:<project>`),
/// the same scope `get_kernel mode=gaps`/`quadrant` already serve from the
/// artifact.
///
/// Returns the labeled `unavailable` block (preserving the fail-closed refusal)
/// when no artifact is persisted or it carries zero members: a genuinely
/// scope-less corpus still refuses.
pub(crate) fn scope_summaries_from_persisted_kernel_artifact<C>(
    vault: &AsterVault<C>,
    project: &str,
) -> Value
where
    C: Clock,
{
    let scope_id = kernel_artifact_scope_id(project);
    let artifact = match astrolabe_ingest::read_persisted_kernel_artifact(vault, &scope_id) {
        Ok(Some(artifact)) => artifact,
        Ok(None) => {
            return scope_summaries_unavailable_json(
                "no persisted kernel artifact for this project; index_repository built no kernel scope",
            );
        }
        Err(error) => {
            return scope_summaries_unavailable_json(&format!(
                "persisted kernel artifact read failed: {error}"
            ));
        }
    };
    if artifact.members.is_empty() {
        return scope_summaries_unavailable_json(
            "persisted kernel artifact carries no members; scope is empty",
        );
    }
    let identity_by_cx = match stable_identity_by_cx(vault, project) {
        Ok(identity) => identity,
        Err(error) => {
            return scope_summaries_unavailable_json(&format!(
                "persisted kernel identity snapshot unreadable: {error}"
            ));
        }
    };
    let mut members = Vec::with_capacity(artifact.members.len());
    for member in &artifact.members {
        let cx_id = member.id.to_string();
        let Some((symbol_id, qualified_name)) = identity_by_cx.get(&cx_id).cloned() else {
            return scope_summaries_unavailable_json(&format!(
                "persisted kernel member {cx_id} has no stable source-atom identity; rebuild the project kernel"
            ));
        };
        let provenance = format!(
            "kernel-artifact:scope={};member={symbol_id};cx_id={cx_id};members_hash={}",
            artifact.scope_id, artifact.members_hash
        );
        members.push(ScopeSummaryMember::new(
            symbol_id,
            qualified_name,
            member.score_permille,
            member.grounded,
            provenance,
        ));
    }
    let recall = Some(ScopeRecallMeasurement {
        recalled: artifact.recall.recalled,
        total: artifact.recall.total,
    });
    let input = ScopeSummaryInput::new(
        artifact.scope_id.clone(),
        artifact.members_hash.clone(),
        artifact.anchor_grounded,
        members,
        recall,
    );
    let summary = summarize_scope_kernel(&input);
    scope_summaries_json(&[summary], 0)
}

/// #400: replace the row-sink-derived `scope_summaries` on `base_kernel_context`
/// with the persisted-`KernelArtifact`-derived block, keeping the existing
/// `label_propagation`, and recompute the rolled-up kernel_context status/trust.
/// Keeps the base block when the persisted one is not `built` (never downgrade a
/// served surface, and preserve the honest `unavailable` refusal on a truly
/// scope-less corpus).
pub(crate) fn kernel_context_with_persisted_scope_summaries(
    base_kernel_context: Value,
    persisted_scope_summaries: Value,
) -> Value {
    let use_persisted = persisted_scope_summaries
        .get("status")
        .and_then(Value::as_str)
        == Some("built");
    let scope_summaries = if use_persisted {
        persisted_scope_summaries
    } else {
        base_kernel_context
            .get("scope_summaries")
            .cloned()
            .unwrap_or(persisted_scope_summaries)
    };
    let label_propagation = base_kernel_context
        .get("label_propagation")
        .cloned()
        .unwrap_or_else(|| {
            label_propagation_unavailable_json(
                "label propagation missing during scope-summary merge",
            )
        });
    kernel_context_json(label_propagation, scope_summaries)
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
                    node.atom_id.clone(),
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
                    .unwrap_or(&node.atom_id);
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
    let node_ids = rows
        .nodes
        .iter()
        .filter(|node| !node.atom_id.trim().is_empty())
        .map(|node| (node.id, node.atom_id.clone()))
        .collect::<BTreeMap<_, _>>();
    rows.edges
        .iter()
        .filter_map(|edge| {
            let left = node_ids.get(&edge.source_id)?;
            let right = node_ids.get(&edge.target_id)?;
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
                node.atom_id.clone(),
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

/// #69 box 5 — exact set of match keys carrying `label` as a *propagated* label in
/// the persisted kernel context. Fails closed (coded) when propagation is
/// unavailable so the search filter never silently degrades into an unfiltered or
/// spuriously empty result. Same exact-match semantics as the kernel's
/// [`astrolabe_kernel::filter_symbols_by_propagated_label`]. The returned key is
/// the served stable source-atom `symbol_id`; qualified name is display metadata
/// and is never used as an identity key.
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
            // Exact stable source-atom identity; never a qualified-name guess.
            if entry.get("label").and_then(Value::as_str) == Some(label)
                && let Some(candidate) = entry
                    .get("symbol_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|candidate| !candidate.is_empty())
            {
                ids.insert(candidate.to_string());
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
        let (input_count, matched_count) = retain_labeled_results(structured, labeled_symbols)?;
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
    {
        let raw_text = text.as_str().ok_or_else(|| -> DynError {
            "ASTRO_SEARCH_LABEL_FILTER_TEXT_TYPE: content[0].text is not a string"
                .to_string()
                .into()
        })?;
        let mut text_value = serde_json::from_str::<Value>(raw_text).map_err(|error| -> DynError {
            format!(
                "ASTRO_SEARCH_LABEL_FILTER_TEXT_JSON: content[0].text is not valid search JSON: {error}"
            )
            .into()
        })?;
        let text_obj = text_value.as_object_mut().ok_or_else(|| -> DynError {
            "ASTRO_SEARCH_LABEL_FILTER_TEXT_OBJECT: content[0].text search JSON is not an object"
                .to_string()
                .into()
        })?;
        let (input_count, matched_count) = retain_labeled_results(text_obj, labeled_symbols)?;
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
) -> Result<(usize, usize), DynError> {
    let mut input_count = 0;
    let mut matched_count = 0;
    for result_field in ["results", "semantic_results"] {
        let Some(results) = obj.get_mut(result_field).and_then(Value::as_array_mut) else {
            continue;
        };
        input_count += results.len();
        let mut retained = Vec::with_capacity(results.len());
        for (index, hit) in std::mem::take(results).into_iter().enumerate() {
            let candidate = hit
                .get("atom_id")
                .or_else(|| hit.get("symbol_id"))
                .and_then(Value::as_str)
                .filter(|identity| !identity.is_empty())
                .ok_or_else(|| -> DynError {
                    format!(
                        "ASTRO_SEARCH_LABEL_FILTER_IDENTITY: {result_field}[{index}] has no stable atom_id"
                    )
                    .into()
                })?;
            if labeled_symbols.contains(candidate) {
                retained.push(hit);
            }
        }
        matched_count += retained.len();
        *results = retained;
    }
    for key in ["result_count", "count", "total_results", "returned"] {
        if let Some(existing) = obj.get_mut(key)
            && existing.as_u64() == Some(input_count as u64)
        {
            *existing = json!(matched_count);
        }
    }
    Ok((input_count, matched_count))
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
