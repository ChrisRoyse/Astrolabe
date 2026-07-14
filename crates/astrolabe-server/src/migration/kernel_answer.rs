//! `get_kernel` + `kernel_answer` MCP surface (#40, blueprint 09 §4, 15 §2).
//!
//! `get_kernel` serves the persisted kernel context — the scope-summary members
//! (qualified name, kernel weight, grounded flag, provenance) with their recall
//! metrics — in three modes: `read` (the members and recall), `gaps` (the
//! ungrounded members that still need grounding), and `build`. The kernel
//! members here are the S-lens scope-summary rollup persisted by the shadow
//! import; the full feedback-vertex-set kernel build over the vault association
//! graph, and the hop-attenuated `kernel_answer` walk, both consume the
//! `GraphProjectionCsr -> KernelGraph` vault adapter tracked in #343. Until that
//! adapter lands, `mode="build"` and `kernel_answer` fail closed with a coded
//! `{code, message, remediation}` naming the dependency rather than fabricating
//! an ungrounded answer — the answer-path algorithm itself (the pinned `0.9`
//! per-hop attenuation, the ledger-required gate, the honest deficit refusal) is
//! implemented and FSV-covered in `astrolabe_kernel::answer`.

use super::*;

/// Refusal: an unsupported `get_kernel` mode.
pub(crate) const ASTRO_GET_KERNEL_MODE_UNSUPPORTED: &str = "ASTRO_GET_KERNEL_MODE_UNSUPPORTED";
/// Refusal: the persisted kernel context is not available for the project.
pub(crate) const ASTRO_GET_KERNEL_UNAVAILABLE: &str = "ASTRO_GET_KERNEL_UNAVAILABLE";
/// Refusal: the requested scope is absent from the persisted kernel context.
pub(crate) const ASTRO_GET_KERNEL_SCOPE_UNKNOWN: &str = "ASTRO_GET_KERNEL_SCOPE_UNKNOWN";
/// Refusal: the FVS kernel build over the vault association graph is not wired
/// (depends on the `GraphProjectionCsr -> KernelGraph` adapter, #343).
pub(crate) const ASTRO_KERNEL_BUILD_ADAPTER_PENDING: &str = "ASTRO_KERNEL_BUILD_ADAPTER_PENDING";
/// Refusal: `kernel_answer` requires a non-empty query.
pub(crate) const ASTRO_KERNEL_ANSWER_QUERY_REQUIRED: &str = "ASTRO_KERNEL_ANSWER_QUERY_REQUIRED";
/// Refusal: the answer-path walk over the vault association graph is not wired
/// (depends on the `GraphProjectionCsr -> KernelGraph` adapter, #343).
pub(crate) const ASTRO_KERNEL_ANSWER_ADAPTER_PENDING: &str = "ASTRO_KERNEL_ANSWER_ADAPTER_PENDING";

const GET_KERNEL_MODES: [&str; 4] = ["read", "gaps", "quadrant", "build"];

pub(crate) fn handle_get_kernel(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("get_kernel arguments must be a JSON object");
    };
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
        // The FVS kernel build over the vault association graph consumes the
        // GraphProjectionCsr -> KernelGraph adapter (#343). Fail closed rather
        // than fabricate a build.
        return tool_json_error_result(json!({
            "schema": "astrolabe.get_kernel.v1",
            "status": "refused",
            "mode": "build",
            "code": ASTRO_KERNEL_BUILD_ADAPTER_PENDING,
            "message": "recomputing the feedback-vertex-set kernel over the vault association graph is not wired in this build",
            "remediation": "land the GraphProjectionCsr -> KernelGraph vault adapter (#343), then request mode=\"build\"; meanwhile mode=\"read\"/\"gaps\" serve the persisted scope-summary kernel members",
            "depends_on": "#343",
            "trust": "provisional",
            "freshness": "not_evaluated",
        }));
    }

    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    let kernel_context = read_kernel_context_metadata(&cache_dir, &project)?;

    // #39: gaps + quadrant serve the flattened cross-scope grounding-gap views
    // owned by `kernel_gaps`. gaps ranks the ungrounded members by persisted
    // kernel weight; quadrant classifies every member into the coverage-vs-
    // importance scatter. Both read back the same persisted kernel-context
    // metadata and fail closed when the scope summaries are unavailable.
    if mode == "gaps" || mode == "quadrant" {
        // #365: prefer the persisted KernelArtifact — the real kernel_score × churn
        // ranking, exact hop boundary, and per-member groundedness permille — read
        // back from the vault Kernel CF. Only when no artifact is persisted (a scope
        // that never built a kernel) do we fall back to the labeled degraded
        // scope-summary surface below.
        match read_project_kernel_artifact(&cache_dir, &project) {
            Ok(Some(artifact)) => {
                return if mode == "gaps" {
                    tool_json_result(artifact_gap_report_value(&project, &artifact))
                } else {
                    tool_json_result(artifact_quadrant_value(&project, &artifact))
                };
            }
            Ok(None) => {} // fall through to the labeled scope-summary fallback
            Err(_error) => {} // artifact read failed: labeled fallback below
        }

        let members = match gap_members_from_kernel_context(&kernel_context) {
            Ok(members) => members,
            Err(reason) => {
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
        return if mode == "gaps" {
            tool_json_result(gap_report_value(&project, &members))
        } else {
            tool_json_result(quadrant_value(&project, &members))
        };
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

/// Reads the persisted whole-repo `KernelArtifact` for a project back out of the
/// vault Kernel CF (#365), read-only and independent of the index-time write path.
/// `Ok(None)` when no kernel artifact was persisted for the project (a labeled
/// fallback, not an error).
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
        vec![ColumnFamily::Kernel, ColumnFamily::Graph, ColumnFamily::Base],
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
        Err(error) => return membership_manifest(&format!("kernel-member index unavailable: {error}")),
    };

    let embedding_backed = index.index_kind == astrolabe_weave::KernelIndexKind::EmbeddingBackedHnsw;
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

    // The kernel-first search -> anchored entry -> hop-attenuated answer walk
    // consumes the association graph (edges + per-hop ledger references) assembled
    // by the GraphProjectionCsr -> KernelGraph vault adapter (#343). The
    // attenuation math, the ledger-required gate (CALYX_KERNEL_ANSWER_LEDGER_REQUIRED),
    // and the honest deficit refusal are implemented and FSV-covered in
    // astrolabe_kernel::answer; only the vault-graph feed is pending. Fail closed
    // with the dependency rather than serve an ungrounded answer.
    tool_json_error_result(json!({
        "schema": KERNEL_ANSWER_SCHEMA,
        "status": "refused",
        "code": ASTRO_KERNEL_ANSWER_ADAPTER_PENDING,
        "project": project,
        "query": query,
        "scope": scope,
        "knob_registry_version": KERNEL_ANSWER_KNOB_REGISTRY_VERSION,
        "message": "assembling the answer-path association graph (edges + per-hop ledger references) over the vault is not wired in this build",
        "remediation": "land the GraphProjectionCsr -> KernelGraph vault adapter (#343), which feeds astrolabe_kernel::answer::answer_query; the answer-path algorithm, the 0.9 per-hop attenuation, and the ledger-required gate are already implemented and verified",
        "depends_on": "#343",
        "ledger_required_code": CALYX_KERNEL_ANSWER_LEDGER_REQUIRED,
        "trust": "provisional",
        "freshness": "not_evaluated",
    }))
}
