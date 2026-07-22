//! `get_kernel` + `kernel_answer` MCP surface (#40, blueprint 09 §4, 15 §2).
//!
//! `get_kernel` serves the kernel context in four modes: `read` (the scope-summary
//! members — qualified name, kernel weight, grounded flag, provenance — with their
//! recall metrics), `gaps` (the ungrounded members that still need grounding),
//! `quadrant` (the coverage-vs-importance scatter), and `build`. `read`/`gaps`/
//! `quadrant` serve the persisted kernel members (the S-lens scope-summary rollup
//! and the persisted `KernelArtifact`).
//!
//! `build` recomputes the feedback-vertex-set kernel over the vault association
//! graph on demand (#410): it opens the project's shadow vault read-write and runs
//! the same anchor-trust-grounded `astrolabe_ingest::build_and_persist_kernel` the
//! shadow import runs at index time (the `GraphProjectionCsr -> KernelGraph` vault
//! adapter it consumes landed under #343), persisting the `KernelArtifact` +
//! projection into the vault Kernel CF and serving a labeled `status:"built"`
//! summary. When the graph genuinely yields no kernel (empty graph, no typed edges,
//! an unreachable recall gate) it fails closed with a coded
//! `{code, message, remediation}` carrying the real build-layer reason rather than
//! fabricating a build.
//!
//! `kernel_answer` runs the hop-attenuated answer walk (the pinned `0.9` per-hop
//! attenuation, the ledger-required gate, the honest deficit refusal, implemented
//! in `astrolabe_kernel::answer`) over the persisted association-graph projection
//! and kernel artifact. When neither is persisted it fails closed with a coded
//! `{code, message, remediation}` directing the caller to `get_kernel mode="build"`
//! rather than fabricating an ungrounded answer.

use super::*;

use calyx_core::CxId;

/// Refusal: an unsupported `get_kernel` mode.
pub(crate) const ASTRO_GET_KERNEL_MODE_UNSUPPORTED: &str = "ASTRO_GET_KERNEL_MODE_UNSUPPORTED";
/// Refusal: the persisted kernel context is not available for the project.
pub(crate) const ASTRO_GET_KERNEL_UNAVAILABLE: &str = "ASTRO_GET_KERNEL_UNAVAILABLE";
/// Refusal: the requested scope is absent from the persisted kernel context.
pub(crate) const ASTRO_GET_KERNEL_SCOPE_UNKNOWN: &str = "ASTRO_GET_KERNEL_SCOPE_UNKNOWN";
/// Refusal: the on-demand FVS kernel build over the vault association graph
/// produced no kernel (empty graph, no typed edges, or an unreachable recall gate).
pub(crate) const ASTRO_KERNEL_BUILD_UNAVAILABLE: &str = "ASTRO_KERNEL_BUILD_UNAVAILABLE";
/// Refusal: `kernel_answer` requires a non-empty query.
pub(crate) const ASTRO_KERNEL_ANSWER_QUERY_REQUIRED: &str = "ASTRO_KERNEL_ANSWER_QUERY_REQUIRED";
/// Refusal: the project has no persisted kernel artifact or association-graph
/// projection to answer from — the answer-path substrate is absent until a kernel
/// is built (`get_kernel mode="build"`).
pub(crate) const ASTRO_KERNEL_ANSWER_ADAPTER_PENDING: &str = "ASTRO_KERNEL_ANSWER_ADAPTER_PENDING";

const GET_KERNEL_MODES: [&str; 4] = ["read", "gaps", "quadrant", "build"];

pub(crate) fn handle_get_kernel(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("get_kernel arguments must be a JSON object");
    };
    // #459: a fleet scope (fleet:<language>:<version>) is cross-project — it is
    // served from the fleet catalog vault and needs neither project nor dial.
    if let Some(scope_id) = string_arg(args_obj, "scope")
        && is_fleet_scope(scope_id)
    {
        let scope_id = scope_id.to_owned();
        return handle_get_kernel_fleet(args_obj, &scope_id);
    }
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("get_kernel requires project");
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return tool_error_result(
            "get_kernel requires calyx shadow indexing; run index_repository with calyx=\"shadow\"",
        );
    }
    let mode = string_arg(args_obj, "mode").unwrap_or("read");
    if !GET_KERNEL_MODES.contains(&mode) {
        return tool_error_result(format!(
            "{ASTRO_GET_KERNEL_MODE_UNSUPPORTED}: get_kernel mode {mode:?} is not available; remediation: use mode=\"read\", mode=\"gaps\", mode=\"quadrant\", or mode=\"build\""
        ));
    }
    let scope = string_arg(args_obj, "scope").map(ToOwned::to_owned);

    if mode == "build" {
        // #410: recompute the anchor-trust-grounded feedback-vertex-set kernel over
        // the vault association graph on demand — the exact index-time build the
        // shadow import runs (`persist_index_time_kernel_artifact` ->
        // `astrolabe_ingest::build_and_persist_kernel`, consuming the #343
        // GraphProjectionCsr -> KernelGraph adapter that landed long ago), executed
        // here against the persisted vault. Open the shadow vault read-write so the
        // rebuilt KernelArtifact + projection persist into the Kernel CF; the persist
        // layer is fail-closed on its own bytes (reads them back, refuses on
        // divergence). A scope that genuinely cannot yield a kernel surfaces as a
        // coded fail-closed refusal carrying the real build-layer reason — never a
        // fabricated build.
        let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
        let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(&cache_dir, &project)?;
        if !vault_dir.exists() {
            return tool_json_error_result(json!({
                "schema": "astrolabe.get_kernel.v1",
                "status": "refused",
                "mode": "build",
                "code": ASTRO_KERNEL_BUILD_UNAVAILABLE,
                "message": format!(
                    "no shadow vault persisted for project {project:?}; there is no association graph to build a kernel over"
                ),
                "remediation": "run index_repository with calyx=\"shadow\" for this project, then request get_kernel mode=\"build\"",
                "trust": "provisional",
                "freshness": "not_evaluated",
            }));
        }
        // Writable handles open every CF (the with-access contract ignores a CF
        // selection when not read-only), which the build + persist path requires
        // (Base/Graph to project, Anchors for the trust map, Kernel + Ledger to
        // persist the artifact inside the verified chain).
        let vault = open_shadow_vault_writable(&vault_dir, &vault_id, &vault_salt, Vec::new())?;
        let summary = persist_index_time_kernel_artifact(&vault, &project);
        let response = get_kernel_build_response_json(&project, &summary);
        return if response.get("status").and_then(Value::as_str) == Some("built") {
            tool_json_result(response)
        } else {
            tool_json_error_result(response)
        };
    }

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let kernel_context = read_kernel_context_metadata(&cache_dir, &project)?;

    // #39: gaps + quadrant serve the flattened cross-scope grounding-gap views
    // owned by `kernel_gaps`. gaps ranks the ungrounded members by persisted
    // kernel weight; quadrant classifies every member into the coverage-vs-
    // importance scatter. Both read back the same persisted kernel-context
    // metadata and fail closed when the scope summaries are unavailable.
    if mode == "gaps" || mode == "quadrant" {
        // #365/#540: the persisted KernelArtifact is the sole source of truth for
        // gap/quadrant reads. A missing or unreadable artifact is a state failure,
        // never permission to substitute a degraded scope summary.
        match read_project_kernel_artifact(&cache_dir, &project) {
            Ok(Some(artifact)) => {
                return if mode == "gaps" {
                    tool_json_result(artifact_gap_report_value(&project, &artifact))
                } else {
                    tool_json_result(artifact_quadrant_value(&project, &artifact))
                };
            }
            Ok(None) => {
                return tool_json_error_result(json!({
                    "schema": "astrolabe.get_kernel.v1",
                    "status": "refused",
                    "mode": mode,
                    "code": ASTRO_GET_KERNEL_UNAVAILABLE,
                    "message": format!("project {project:?} has no persisted Kernel artifact"),
                    "remediation": "build the real artifact with get_kernel mode=\"build\", then retry",
                    "trust": "provisional",
                    "freshness": "not_evaluated",
                }));
            }
            Err(error) => {
                return tool_json_error_result(json!({
                    "schema": "astrolabe.get_kernel.v1",
                    "status": "refused",
                    "mode": mode,
                    "code": ASTRO_GET_KERNEL_UNAVAILABLE,
                    "message": format!("persisted Kernel artifact read failed for project {project:?}: {error}"),
                    "remediation": "repair or rebuild the persisted Kernel artifact; no scope-summary substitute is served",
                    "trust": "provisional",
                    "freshness": "not_evaluated",
                }));
            }
        }
    }

    let summaries = match kernel_context_scope_summaries(&kernel_context) {
        Some(summaries) => summaries,
        None => {
            let reason = kernel_context
                .get("scope_summaries")
                .and_then(|value| value.get("reason"))
                .and_then(Value::as_str)
                .unwrap_or("kernel context scope summaries unavailable");
            return tool_json_error_result(json!({
                "schema": "astrolabe.get_kernel.v1",
                "status": "refused",
                "mode": mode,
                "code": ASTRO_GET_KERNEL_UNAVAILABLE,
                "message": reason,
                "remediation": "rerun index_repository with calyx=\"shadow\" so the kernel scope summaries are persisted before requesting get_kernel",
                "trust": "provisional",
                "freshness": "not_evaluated",
            }));
        }
    };

    let selected: Vec<&Value> = match &scope {
        Some(scope_id) => {
            let matched: Vec<&Value> = summaries
                .iter()
                .filter(|summary| {
                    summary.get("scope_id").and_then(Value::as_str) == Some(scope_id.as_str())
                })
                .collect();
            if matched.is_empty() {
                return tool_json_error_result(json!({
                    "schema": "astrolabe.get_kernel.v1",
                    "status": "refused",
                    "mode": mode,
                    "code": ASTRO_GET_KERNEL_SCOPE_UNKNOWN,
                    "message": format!("scope {scope_id:?} is absent from the persisted kernel context"),
                    "remediation": "request get_kernel without scope to list the available scopes, then retry with one of them",
                    "trust": "provisional",
                    "freshness": "not_evaluated",
                }));
            }
            matched
        }
        None => summaries.iter().collect(),
    };

    let scopes_json = selected
        .iter()
        .map(|summary| get_kernel_scope_json(summary, mode))
        .collect::<Vec<_>>();
    let all_grounded = selected.iter().all(|summary| {
        summary.get("grounded_member_count").and_then(Value::as_u64)
            == summary.get("total_member_count").and_then(Value::as_u64)
    });
    let total_gaps: u64 = selected
        .iter()
        .map(|summary| scope_gap_count(summary))
        .sum();

    // #365: the served index.json upgraded to embedding_backed_hnsw when the
    // persisted kernel members carry S18 vectors, labeled membership_manifest
    // otherwise (or absent when no artifact is persisted).
    let index = match read_project_kernel_artifact(&cache_dir, &project) {
        Ok(Some(artifact)) => serve_kernel_index_value(&cache_dir, &project, &artifact),
        Ok(None) => json!({
            "index_kind": "membership_manifest",
            "status": "unavailable",
            "reason": "no persisted kernel artifact for this project",
            "trust": "provisional",
            "freshness": "not_evaluated",
        }),
        Err(error) => json!({
            "index_kind": "membership_manifest",
            "status": "unavailable",
            "reason": format!("kernel artifact read failed: {error}"),
            "trust": "provisional",
            "freshness": "not_evaluated",
        }),
    };

    tool_json_result(json!({
        "schema": if mode == "gaps" { KERNEL_GAP_REPORT_SCHEMA } else { "astrolabe.get_kernel.v1" },
        "status": "served",
        "mode": mode,
        "project": project,
        "scope": scope,
        "scope_count": scopes_json.len(),
        "gap_count": total_gaps,
        "scopes": scopes_json,
        "index": index,
        "trust": if all_grounded { "verified" } else { "provisional" },
        "freshness": "fresh",
        "provenance": format!("kernel_context.scope_summaries (astrolabe.scope_summary.v1) of {project}"),
    }))
}

/// Reshapes the index-time kernel-artifact persist summary
/// ([`persist_index_time_kernel_artifact`]) into the `get_kernel mode="build"`
/// response (#410). A `persisted` summary serves `status:"built"` carrying the real
/// member/node/recall/readback fields the build produced and read back; any other
/// status is a fail-closed refusal carrying the build layer's real reason under
/// [`ASTRO_KERNEL_BUILD_UNAVAILABLE`] — never a fabricated build.
fn get_kernel_build_response_json(project: &str, summary: &Value) -> Value {
    let status = summary
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    if status == "persisted" {
        return json!({
            "schema": "astrolabe.get_kernel.v1",
            "status": "built",
            "mode": "build",
            "project": project,
            "scope_id": summary.get("scope_id"),
            "members_hash": summary.get("members_hash"),
            "member_count": summary.get("member_count"),
            "node_count": summary.get("node_count"),
            "recall_permille": summary.get("recall_permille"),
            "recall_gated": summary.get("recall_gated"),
            "anchor_grounded": summary.get("anchor_grounded"),
            "trusted_anchor_count": summary.get("trusted_anchor_count"),
            "rows_readback_verified": summary.get("rows_readback_verified"),
            "ledger_paired": summary.get("ledger_paired"),
            "commit_seq": summary.get("commit_seq"),
            "trust": summary.get("trust"),
            "freshness": summary.get("freshness"),
            "provenance": summary.get("provenance"),
        });
    }
    // `unavailable` (or an unexpected summary shape): the build produced no kernel.
    // Surface the persist layer's real reason verbatim rather than the retired
    // ADAPTER_PENDING stub.
    let reason = summary
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("kernel build did not persist a kernel artifact for this project");
    json!({
        "schema": "astrolabe.get_kernel.v1",
        "status": "refused",
        "mode": "build",
        "project": project,
        "code": ASTRO_KERNEL_BUILD_UNAVAILABLE,
        "message": reason,
        "remediation": "the vault association graph yielded no kernel (empty graph, no typed edges, an empty anchor set, or an unreachable recall gate); rerun index_repository with calyx=\"shadow\" over a corpus with typed associations and anchors, then retry get_kernel mode=\"build\"",
        "trust": "provisional",
        "freshness": "not_evaluated",
    })
}

/// Reads the persisted whole-repo `KernelArtifact` for a project back out of the
/// vault Kernel CF (#365), read-only and independent of the index-time write path.
/// `Ok(None)` when no kernel artifact was persisted for the project; callers
/// surface that absence explicitly and never substitute another representation.
pub(crate) fn read_project_kernel_artifact(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<astrolabe_kernel::KernelArtifact>, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(None);
    }
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Kernel,
            ColumnFamily::Graph,
            ColumnFamily::Base,
        ],
    )?;
    let scope_id = kernel_artifact_scope_id(project);
    let artifact = astrolabe_ingest::read_persisted_kernel_artifact(&vault, &scope_id)?;
    Ok(artifact)
}

/// Serves the kernel `index.json` for a project (#365), upgrading its
/// `index_kind` to `embedding_backed_hnsw` when the kernel members carry persisted
/// S18 code-semantic vectors — via the weave kernel-member index (#344) — and
/// labeling it `membership_manifest` otherwise (no member carried an S18 vector).
/// A read/build error degrades to a labeled membership_manifest, never a silent
/// upgrade claim.
pub(crate) fn serve_kernel_index_value(
    cache_dir: &Path,
    project: &str,
    artifact: &astrolabe_kernel::KernelArtifact,
) -> Value {
    use astrolabe_weave::search::SLOT_CODE_SEMANTIC;
    use astrolabe_weave::search_index::IndexKnobs;

    let member_cx_ids: Vec<_> = artifact.members.iter().map(|member| member.id).collect();
    let membership_manifest = |reason: &str| {
        json!({
            "schema": astrolabe_weave::KERNEL_MEMBER_INDEX_SCHEMA,
            "index_kind": "membership_manifest",
            "members_hash": artifact.members_hash,
            "member_count": artifact.member_count,
            "indexed_member_count": 0,
            "note": reason,
            "trust": "provisional",
            "freshness": "fresh",
        })
    };

    let config = match shadow_vault_config_at(cache_dir, project) {
        Ok(config) => config,
        Err(error) => return membership_manifest(&format!("vault config unavailable: {error}")),
    };
    let (vault_dir, vault_id, vault_salt) = config;
    if !vault_dir.exists() {
        return membership_manifest("shadow vault missing");
    }
    let vault = match open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Base,
            ColumnFamily::Graph,
            ColumnFamily::Kernel,
            ColumnFamily::Kv,
            ColumnFamily::slot(SLOT_CODE_SEMANTIC),
        ],
    ) {
        Ok(vault) => vault,
        Err(error) => return membership_manifest(&format!("vault unavailable: {error}")),
    };

    // Deterministic seed pinned per members_hash so the same member set yields the
    // same index bytes (invariant 5).
    let index = match astrolabe_weave::build_kernel_member_index(
        &vault,
        project,
        &member_cx_ids,
        &artifact.members_hash,
        IndexKnobs::defaults(0x4B45_524E_454C_0001),
    ) {
        Ok(index) => index,
        Err(error) => {
            return membership_manifest(&format!("kernel-member index unavailable: {error}"));
        }
    };

    let embedding_backed =
        index.index_kind == astrolabe_weave::KernelIndexKind::EmbeddingBackedHnsw;
    json!({
        "schema": astrolabe_weave::KERNEL_MEMBER_INDEX_SCHEMA,
        "index_kind": index.index_kind.as_str(),
        "members_hash": index.members_hash,
        "member_count": artifact.member_count,
        "indexed_member_count": index.indexed_member_count,
        "missing_vector_members": index.missing_vector_members,
        "semantic_dim": index.semantic_dim,
        "base_seq": index.base_seq,
        "trust": if embedding_backed { "verified" } else { "provisional" },
        "freshness": "fresh",
        "provenance": [
            format!("kernel-artifact:scope={}", artifact.scope_id),
            "vault:slot(SLOT_CODE_SEMANTIC)".to_string(),
            "astrolabe_weave::build_kernel_member_index(#344)".to_string(),
        ],
    })
}

/// Reshapes one persisted scope-summary into the `get_kernel` per-scope view.
/// `read` carries every member; `gaps` carries only the ungrounded members.
fn get_kernel_scope_json(summary: &Value, mode: &str) -> Value {
    let members = summary
        .get("members")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let member_views = members
        .iter()
        .filter(|member| {
            mode != "gaps" || member.get("grounded").and_then(Value::as_bool) != Some(true)
        })
        .map(|member| {
            json!({
                "symbol_id": member.get("symbol_id"),
                "qualified_name": member.get("qualified_name"),
                "kernel_score_permille": member.get("kernel_weight"),
                "grounded": member.get("grounded"),
                "provenance_ref": member.get("provenance_ref"),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "scope_id": summary.get("scope_id"),
        "summary_hash": summary.get("summary_hash"),
        "member_count": summary.get("total_member_count"),
        "grounded_member_count": summary.get("grounded_member_count"),
        "gap_count": scope_gap_count(summary),
        "grounded_fraction_millipoints": summary.get("grounded_fraction_millipoints"),
        "recall": summary.get("recall"),
        "recall_millipoints": summary.get("recall_millipoints"),
        "members": member_views,
        "trust": summary.get("trust"),
        "freshness": summary.get("freshness"),
    })
}

fn scope_gap_count(summary: &Value) -> u64 {
    let total = summary
        .get("total_member_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let grounded = summary
        .get("grounded_member_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    total.saturating_sub(grounded)
}

/// Extracts the persisted `scope_summaries.summaries` array from a kernel context
/// document, or `None` when scope summaries were not built (unavailable/empty).
fn kernel_context_scope_summaries(kernel_context: &Value) -> Option<Vec<Value>> {
    let scope_summaries = kernel_context.get("scope_summaries")?;
    if scope_summaries.get("status").and_then(Value::as_str) == Some("unavailable") {
        return None;
    }
    scope_summaries
        .get("summaries")
        .and_then(Value::as_array)
        .map(|summaries| summaries.to_vec())
}

pub(crate) fn handle_kernel_answer(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("kernel_answer arguments must be a JSON object");
    };
    // #459: fleet-scope answers serve from the fleet catalog vault (declared
    // exemplar retrieval with per-repo citations); project/dial not required.
    if let Some(scope_id) = string_arg(args_obj, "scope")
        && is_fleet_scope(scope_id)
    {
        let scope_id = scope_id.to_owned();
        return handle_kernel_answer_fleet(args_obj, &scope_id);
    }
    let Some(project) = status_project_from_args(args_obj)? else {
        return tool_error_result("kernel_answer requires project");
    };
    if read_dial(&project)? != MigrationDial::Shadow {
        return tool_error_result(
            "kernel_answer requires calyx shadow indexing; run index_repository with calyx=\"shadow\"",
        );
    }
    let Some(query) = string_arg(args_obj, "query") else {
        return tool_error_result(format!(
            "{ASTRO_KERNEL_ANSWER_QUERY_REQUIRED}: kernel_answer requires a non-empty query; remediation: pass the question to answer from the kernel"
        ));
    };
    let scope = string_arg(args_obj, "scope").map(ToOwned::to_owned);

    // The kernel-first answer walk consumes the association graph assembled by the
    // GraphProjectionCsr -> KernelGraph vault adapter (#343, landed wave-14). Read
    // the answer-path substrate back out of the persisted vault; when no kernel
    // artifact or projection is persisted there is nothing to answer from and we
    // fail closed rather than fabricate an ungrounded answer.
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    match build_kernel_answer_inputs(&cache_dir, &project)? {
        Some(inputs) => serve_kernel_answer(&cache_dir, &project, query, &scope, &inputs),
        None => tool_json_error_result(json!({
            "schema": KERNEL_ANSWER_SCHEMA,
            "status": "refused",
            "code": ASTRO_KERNEL_ANSWER_ADAPTER_PENDING,
            "project": project,
            "query": query,
            "scope": scope,
            "knob_registry_version": KERNEL_ANSWER_KNOB_REGISTRY_VERSION,
            "message": "no persisted kernel artifact or association-graph projection for this project; the answer-path substrate is unavailable",
            "remediation": "run index_repository with calyx=\"shadow\", then build the kernel with get_kernel mode=\"build\" (which recomputes and persists the association-graph projection and kernel artifact on demand), then retry kernel_answer",
            "ledger_required_code": CALYX_KERNEL_ANSWER_LEDGER_REQUIRED,
            "trust": "provisional",
            "freshness": "not_evaluated",
        })),
    }
}

/// The answer-engine substrate for one project, read back from the persisted vault
/// (#384): the answer nodes/edges, the kernel-first candidate entry set
/// (`matched_ids`), and the ledger head that timestamps a recorded answer.
pub(crate) struct KernelAnswerInputs {
    /// Answer nodes (one per persisted projection node), grounded + weighted from
    /// the kernel artifact, provenanced from the persisted provenance store.
    pub(crate) nodes: Vec<astrolabe_kernel::AnswerNode>,
    /// Directed weighted association edges from the composite projection CSR.
    pub(crate) edges: Vec<astrolabe_kernel::AnswerEdge>,
    /// Kernel-first candidate entry set (the persisted kernel members).
    pub(crate) matched_ids: Vec<CxId>,
    /// Ledger head of the serving vault (the recorded answer's freshness watermark).
    pub(crate) ledger: LedgerPointer,
}

/// Reads the persisted vault back into the answer-engine substrate for `project`
/// (#384). Topology comes from the composite kernel-graph projection (the #343
/// `GraphProjectionCsr -> KernelGraph` adapter); per-member grounding and kernel
/// weight come from the persisted kernel artifact; per-node provenance references
/// come from the persisted provenance store, joined by `CxId`.
///
/// Association edges now carry the per-hop ledger reference the graph producer
/// emits into the persisted projection CSR (#393): each projection edge renders the
/// attesting source edge row's Ledger CF pointer via
/// [`astrolabe_ingest::GraphProjectionCsrEdge::ledger_ref`], so a multi-hop answer
/// whose traversed edges and destination nodes are all attributed serves grounded.
/// An edge or node that genuinely lacks attribution still fails closed at the answer
/// engine's ledger-required gate ([`CALYX_KERNEL_ANSWER_LEDGER_REQUIRED`]); no
/// reference is ever fabricated — a node the provenance store does not cover stays
/// unprovenanced and the engine refuses to serve it as an entry.
///
/// `Ok(None)` when the project has no persisted kernel artifact or graph projection
/// (nothing to answer from); the caller fails closed with a coded dependency error.
pub(crate) fn build_kernel_answer_inputs(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<KernelAnswerInputs>, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(None);
    }
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Base,
            ColumnFamily::Graph,
            ColumnFamily::Kernel,
            ColumnFamily::Kv,
        ],
    )?;
    let scope_id = kernel_artifact_scope_id(project);
    let Some(artifact) = astrolabe_ingest::read_persisted_kernel_artifact(&vault, &scope_id)?
    else {
        return Ok(None);
    };
    let Some(csr) = astrolabe_ingest::read_graph_projection_csr(
        &vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
    )?
    else {
        return Ok(None);
    };

    // Per-node provenance references and the ledger head are required persisted
    // inputs. Store read failure is terminal; a zero-ledger substitute would make
    // the eventual refusal indistinguishable from genuine ungrounded state.
    let (node_provenance, ledger) = kernel_answer_provenance(cache_dir, project, &artifact)?;

    let member_by_id: BTreeMap<CxId, &astrolabe_kernel::KernelMember> = artifact
        .members
        .iter()
        .map(|member| (member.id, member))
        .collect();

    let mut nodes = Vec::with_capacity(csr.nodes.len());
    for node in &csr.nodes {
        let member = member_by_id.get(&node.id);
        nodes.push(astrolabe_kernel::AnswerNode::new(
            node.id,
            node.id.to_string(),
            member.is_some_and(|member| member.grounded),
            node_provenance.get(&node.id).cloned(),
            member.map_or(0, |member| member.score_permille),
        ));
    }

    let mut edges = Vec::with_capacity(csr.edges.len());
    for (src_index, window) in csr.offsets.windows(2).enumerate() {
        let src = csr.nodes[src_index].id;
        for edge in &csr.edges[window[0]..window[1]] {
            // #393: the per-edge ledger reference is now persisted in the projection
            // CSR (the attesting source edge row's Ledger CF pointer). An edge that
            // carries no attestation renders `None`, so a multi-hop answer traversing
            // it still fails closed at the engine's ledger-required gate — the
            // reference is never fabricated.
            edges.push(astrolabe_kernel::AnswerEdge::new(
                src,
                edge.dst,
                astrolabe_kernel::weight_to_permille(edge.weight),
                edge.ledger_ref(),
            ));
        }
    }

    // Kernel-first candidate entry set: the persisted kernel members are the
    // pre-selected high-value set the answer anchors into. Query-text narrowing of
    // this candidate set is a future refinement (tracked as a follow-up); the entry
    // is the highest-weight grounded, provenanced member the engine selects.
    let matched_ids: Vec<CxId> = artifact.members.iter().map(|member| member.id).collect();

    Ok(Some(KernelAnswerInputs {
        nodes,
        edges,
        matched_ids,
        ledger,
    }))
}

/// Joins per-`CxId` provenance references and the serving-vault ledger head out of
/// the persisted provenance store. A node's provenance reference is its latest
/// lineage event's ledger pointer rendered `seq:chain_hash`; only symbol keys that
/// parse as a `CxId` are joined (the enriched-index case). The provenance store is
/// part of the answer source of truth, so an unavailable/corrupt store is returned
/// to the caller as an error.
fn kernel_answer_provenance(
    cache_dir: &Path,
    project: &str,
    _artifact: &astrolabe_kernel::KernelArtifact,
) -> Result<(BTreeMap<CxId, String>, LedgerPointer), DynError> {
    let mut map = BTreeMap::new();
    let store = provenance_store_for_project(cache_dir, project)?;
    for (symbol_id, lineage) in &store.symbols {
        let Ok(cx) = symbol_id.parse::<CxId>() else {
            continue;
        };
        if let Some(latest) = lineage.versions.last() {
            map.insert(
                cx,
                format!("{}:{}", latest.ledger.seq, latest.ledger.chain_hash),
            );
        }
    }
    Ok((map, store.ledger_head))
}

/// Serves a kernel answer over the persisted substrate and, on a served answer,
/// records the reproduce fixture at serve time (#384) so
/// `get_provenance(mode="reproduce")` live re-execution engages server-side.
///
/// An honest deficit refusal (ungrounded / no entry) and a hard integrity refusal
/// (the ledger-required provenance gate, a knob-range violation) both surface as a
/// coded `{code, message, remediation}` tool error rather than a fabricated answer.
fn serve_kernel_answer(
    cache_dir: &Path,
    project: &str,
    query: &str,
    scope: &Option<String>,
    inputs: &KernelAnswerInputs,
) -> Result<String, DynError> {
    let config = astrolabe_kernel::AnswerConfig::with_registry_defaults();
    let resolution = match astrolabe_kernel::answer_query(
        &inputs.nodes,
        &inputs.edges,
        &inputs.matched_ids,
        query,
        &config,
    ) {
        Ok(resolution) => resolution,
        Err(error) => {
            // Hard integrity refusal (ledger-required provenance gate / knob range):
            // surface the engine's coded refusal verbatim, never an ungrounded answer.
            return tool_json_error_result(json!({
                "schema": KERNEL_ANSWER_SCHEMA,
                "status": "refused",
                "code": error.code(),
                "project": project,
                "query": query,
                "scope": scope,
                "knob_registry_version": KERNEL_ANSWER_KNOB_REGISTRY_VERSION,
                "message": error.message(),
                "remediation": error.remediation(),
                "trust": "provisional",
                "freshness": "not_evaluated",
            }));
        }
    };

    match resolution {
        astrolabe_kernel::AnswerResolution::Refused(refusal) => {
            tool_json_error_result(kernel_answer_refusal_json(project, scope, &refusal))
        }
        astrolabe_kernel::AnswerResolution::Answered(answer) => {
            // #384: capture the served answer as a reproduce fixture — the recorded
            // artifact bytes plus the current-vault graph the live reproduce
            // re-executes against — and persist it keyed by the answer's stable
            // content-addressed id before serving.
            let answer_id = answer.answer_hash.clone();
            let recorded = astrolabe_provenance::RecordedKernelAnswer::from_answer(
                answer_id.clone(),
                config,
                inputs.ledger.clone(),
                &answer,
            );
            let entry = reproduce_fixture_entry_json(
                &recorded,
                &inputs.nodes,
                &inputs.edges,
                &inputs.matched_ids,
            );
            persist_reproduce_fixture(cache_dir, project, &answer_id, entry)?;
            tool_json_result(served_kernel_answer_json(project, scope, &answer))
        }
    }
}

/// Renders a served kernel answer for the tool surface.
fn served_kernel_answer_json(
    project: &str,
    scope: &Option<String>,
    answer: &astrolabe_kernel::KernelAnswer,
) -> Value {
    json!({
        "schema": answer.schema,
        "status": "served",
        "project": project,
        "scope": scope,
        "query": answer.query,
        "knob_registry_version": answer.knob_registry_version,
        "attenuation_permille": answer.attenuation_permille,
        "answer_id": answer.answer_hash,
        "entry": {
            "symbol_id": answer.entry_id.to_string(),
            "qualified_name": answer.entry_qualified_name,
            "kernel_weight_permille": answer.entry_weight_permille,
            "provenance_ref": answer.entry_provenance_ref,
        },
        "hops": answer.hops.iter().map(|hop| json!({
            "depth": hop.depth,
            "from": hop.from_id.to_string(),
            "to": hop.to_id.to_string(),
            "to_qualified_name": hop.to_qualified_name,
            "edge_weight_permille": hop.edge_weight_permille,
            "attenuation_permille": hop.attenuation_permille,
            "hop_score_permille": hop.hop_score_permille,
            "to_grounded": hop.to_grounded,
            "ledger_ref": hop.ledger_ref,
            "node_provenance_ref": hop.node_provenance_ref,
        })).collect::<Vec<_>>(),
        "total_score_permille": answer.total_score_permille,
        "provenance_refs": answer.provenance_refs,
        "answer_node_ids": answer.answer_node_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "entry_selection": "kernel_weight_over_all_members (query-text narrowing pending)",
        "reproduce": "fixture persisted at serve time; get_provenance mode=\"reproduce\" subject=answer_id",
        "trust": answer.trust,
        "freshness": answer.freshness,
    })
}

/// Renders an honest answer-deficit refusal for the tool surface.
fn kernel_answer_refusal_json(
    project: &str,
    scope: &Option<String>,
    refusal: &astrolabe_kernel::AnswerRefusal,
) -> Value {
    json!({
        "schema": refusal.schema,
        "status": "refused",
        "project": project,
        "scope": scope,
        "query": refusal.query,
        "code": refusal.code,
        "deficits": refusal.deficits.iter().map(|deficit| json!({
            "lens": deficit.lens,
            "satisfied": deficit.satisfied,
            "detail": deficit.detail,
        })).collect::<Vec<_>>(),
        "message": refusal.message,
        "remediation": refusal.remediation,
        "trust": refusal.trust,
        "freshness": refusal.freshness,
    })
}

/// Builds one persisted reproduce-fixture entry for a served answer (#384): the
/// recorded artifact bytes (as UTF-8 text) plus the exact current-vault graph the
/// live reproduce re-executes against, in the shape
/// [`super::provenance::apply_live_reproduce`] reads back.
pub(crate) fn reproduce_fixture_entry_json(
    recorded: &astrolabe_provenance::RecordedKernelAnswer,
    nodes: &[astrolabe_kernel::AnswerNode],
    edges: &[astrolabe_kernel::AnswerEdge],
    matched_ids: &[CxId],
) -> Value {
    let recorded_artifact =
        String::from_utf8(astrolabe_provenance::recorded_kernel_answer_bytes(recorded))
            .expect("recorded kernel answer bytes are UTF-8");
    json!({
        "recorded_artifact": recorded_artifact,
        "graph": {
            "nodes": nodes.iter().map(reproduce_fixture_node_json).collect::<Vec<_>>(),
            "edges": edges.iter().map(reproduce_fixture_edge_json).collect::<Vec<_>>(),
            "matched_ids": matched_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        },
    })
}

fn reproduce_fixture_node_json(node: &astrolabe_kernel::AnswerNode) -> Value {
    json!({
        "id": node.id.to_string(),
        "qualified_name": node.qualified_name,
        "grounded": node.grounded,
        "provenance_ref": node.provenance_ref,
        "kernel_weight_permille": node.kernel_weight_permille,
    })
}

fn reproduce_fixture_edge_json(edge: &astrolabe_kernel::AnswerEdge) -> Value {
    json!({
        "src": edge.src.to_string(),
        "dst": edge.dst.to_string(),
        "weight_permille": edge.weight_permille,
        "ledger_ref": edge.ledger_ref,
    })
}

/// Merges one served answer's reproduce fixture into the per-project fixture map
/// persisted at [`super::provenance::PROVENANCE_REPRODUCE_FIXTURE_FIELD`], keyed by
/// answer id, and writes it back so `get_provenance(mode="reproduce")` live
/// re-execution engages (#384). A corrupt existing map fails closed rather than
/// silently discarding the persisted fixtures.
pub(crate) fn persist_reproduce_fixture(
    cache_dir: &Path,
    project: &str,
    answer_id: &str,
    entry: Value,
) -> Result<(), DynError> {
    let key = metadata_key(project, PROVENANCE_REPRODUCE_FIXTURE_FIELD);
    let mut fixtures = match read_config_value(cache_dir, &key)? {
        Some(raw) => serde_json::from_str::<Value>(&raw).map_err(|error| {
            DynError::from(format!(
                "ASTRO_KERNEL_ANSWER_FIXTURE_CORRUPT: persisted reproduce fixture map for {project} is not valid JSON: {error}; remediation: delete the {PROVENANCE_REPRODUCE_FIXTURE_FIELD} metadata key and re-serve the answer"
            ))
        })?,
        None => json!({}),
    };
    let Some(object) = fixtures.as_object_mut() else {
        return Err(format!(
            "ASTRO_KERNEL_ANSWER_FIXTURE_CORRUPT: persisted reproduce fixture map for {project} is not a JSON object; remediation: delete the {PROVENANCE_REPRODUCE_FIXTURE_FIELD} metadata key and re-serve the answer"
        )
        .into());
    };
    object.insert(answer_id.to_string(), entry);
    write_config_value(cache_dir, &key, &fixtures.to_string())
}
