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
/// Refusal: the kernel member index could not be read for the project — a vault,
/// artifact, or index-build failure (#882). Distinct from
/// [`astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT`], which means the index honestly
/// does not exist; this one means the state could not be determined at all, and
/// neither is ever answered with a membership-manifest substitute.
pub(crate) const ASTRO_KERNEL_INDEX_UNAVAILABLE: &str = "ASTRO_KERNEL_INDEX_UNAVAILABLE";
/// Refusal: the process-local exact-generation index cache cannot be evaluated.
pub(crate) const ASTRO_KERNEL_INDEX_CACHE_POISONED: &str = "ASTRO_KERNEL_INDEX_CACHE_POISONED";
/// Refusal: `kernel_answer` requires a non-empty query.
pub(crate) const ASTRO_KERNEL_ANSWER_QUERY_REQUIRED: &str = "ASTRO_KERNEL_ANSWER_QUERY_REQUIRED";
/// Refusal: the query carried no token the frozen embedding table knows, so it
/// reaches no kernel member (#880). Refusing is the point: answering an
/// all-out-of-vocabulary question from the globally heaviest member would be a
/// confident guess with no relationship to what was asked (invariant 2).
pub(crate) const ASTRO_KERNEL_ANSWER_QUERY_OOV: &str = "ASTRO_KERNEL_ANSWER_QUERY_OOV";
/// Refusal: the project has no persisted kernel artifact or association-graph
/// projection to answer from — the answer-path substrate is absent until a kernel
/// is built (`get_kernel mode="build"`).
pub(crate) const ASTRO_KERNEL_ANSWER_ADAPTER_PENDING: &str = "ASTRO_KERNEL_ANSWER_ADAPTER_PENDING";

const GET_KERNEL_MODES: [&str; 4] = ["read", "gaps", "quadrant", "build"];
type KernelIndexLoad = Result<
    std::sync::Arc<astrolabe_weave::LoadedKernelMemberIndex>,
    astrolabe_weave::search::SearchError,
>;
type KernelIndexLoadCell = OnceLock<KernelIndexLoad>;

#[derive(Default)]
struct KernelIndexCache {
    clock: u64,
    entries: BTreeMap<String, (std::sync::Arc<KernelIndexLoadCell>, u64)>,
}

impl KernelIndexCache {
    fn load_cell(&mut self, key: String) -> std::sync::Arc<KernelIndexLoadCell> {
        self.clock = self.clock.saturating_add(1);
        if let Some((cell, last_used)) = self.entries.get_mut(&key) {
            *last_used = self.clock;
            return std::sync::Arc::clone(cell);
        }
        let capacity = kernel_index_cache_entries();
        if self.entries.len() >= capacity
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, last_used))| *last_used)
                .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest);
        }
        let cell = std::sync::Arc::new(OnceLock::new());
        self.entries
            .insert(key, (std::sync::Arc::clone(&cell), self.clock));
        cell
    }
}

static KERNEL_INDEX_CACHE: OnceLock<Mutex<KernelIndexCache>> = OnceLock::new();

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
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    if let Some(refusal) = shadow_graph_freshness_refusal(&cache_dir, &project, "get_kernel")? {
        return Ok(refusal);
    }

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

    // #365/#882: the served index.json reports the embedding-backed index only
    // when its physical manifest was actually built for this generation. A
    // membership manifest is capability ABSENCE, reported as such; a config,
    // vault, artifact, or index-build failure is a state failure and propagates
    // as a coded refusal. Neither is ever laundered into a served index.
    let index = match read_kernel_index_state(&cache_dir, &project) {
        Ok(Some(index)) => index,
        Ok(None) => kernel_index_absent_value(
            None,
            &format!(
                "project {project:?} has no persisted kernel artifact, so no member index exists"
            ),
        ),
        Err(error) => {
            return tool_json_error_result(json!({
                "schema": "astrolabe.get_kernel.v1",
                "status": "refused",
                "mode": mode,
                "project": project,
                "code": ASTRO_KERNEL_INDEX_UNAVAILABLE,
                "message": format!("kernel member index could not be read for project {project:?}: {error}"),
                "remediation": "repair the shadow vault and its persisted Kernel artifact, then retry get_kernel; no membership-manifest substitute is served for a read failure",
                "trust": "provisional",
                "freshness": "not_evaluated",
            }));
        }
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
            "ledger_ref": summary.get("ledger_ref"),
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

/// Renders the honest capability-absence view of a kernel member index (#882).
///
/// A kernel whose members carry no persisted S18 vectors has **no** semantic
/// member index. That is an absent capability, not a degraded one, so this value
/// carries `status:"absent"` and the same [`astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT`]
/// code `kernel_scoped_semantic_query` refuses with — never a `provisional`
/// membership manifest dressed as an index. `freshness` is `not_evaluated`
/// because nothing was measured.
pub(crate) fn kernel_index_absent_value(
    index: Option<&astrolabe_weave::KernelMemberIndex>,
    reason: &str,
) -> Value {
    json!({
        "schema": astrolabe_weave::KERNEL_MEMBER_INDEX_SCHEMA,
        "status": "absent",
        "code": astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT,
        "configured_index_kind": "embedding_backed_hnsw",
        "active_index_kind": index.map(|index| index.index_kind.as_str()),
        "members_hash": index.map(|index| index.members_hash.clone()),
        "base_seq": index.map(|index| index.base_seq),
        "indexed_member_count": index.map_or(0, |index| index.indexed_member_count),
        "missing_vector_members": index.map(|index| index.missing_vector_members.clone()),
        "message": reason,
        "remediation": "re-run index_repository with calyx=\"shadow\" so the kernel members carry persisted S18 code-semantic vectors, then rebuild the kernel with get_kernel mode=\"build\"; a membership manifest is not a substitute for the semantic member index",
        "trust": "not_evaluated",
        "freshness": "not_evaluated",
    })
}

/// Reads the persisted kernel artifact **and** builds its embedding-backed member
/// index for one project through a single read-only vault handle (#365/#344/#882).
///
/// One open per request, for one generation: the artifact read and the member
/// index are two views of the same immutable vault state, and opening the vault
/// twice let them disagree about which generation was served.
///
/// Fail-closed contract (#882): every config, vault, artifact, and index-build
/// failure is returned as an `Err` and surfaces as a coded refusal. `Ok(None)`
/// means no kernel artifact is persisted at all. A built index that is a labeled
/// [`astrolabe_weave::KernelIndexKind::MembershipManifestOnly`] returns the
/// capability-absence value — it is never reported as an equivalent index, and
/// the embedding-backed view is served only when the physical manifest exists and
/// its `members_hash` matches the artifact the same handle just read.
pub(crate) fn read_kernel_index_state(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<Value>, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !vault_dir.exists() {
        return Ok(None);
    }
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![ColumnFamily::Kernel],
    )?;
    let scope_id = kernel_artifact_scope_id(project);
    let Some(artifact) = astrolabe_ingest::read_persisted_kernel_artifact(&vault, &scope_id)?
    else {
        return Ok(None);
    };

    let Some(index) = astrolabe_weave::read_persisted_kernel_member_index(
        &vault,
        project,
        &scope_id,
        &artifact.members_hash,
    )?
    else {
        return Ok(Some(kernel_index_absent_value(
            None,
            "the kernel artifact exists but its exact persisted member-index generation is absent",
        )));
    };

    if index.descriptor.index_kind != astrolabe_weave::KernelIndexKind::EmbeddingBackedHnsw {
        return Ok(Some(kernel_index_absent_value(
            None,
            &format!(
                "{} of {} kernel member(s) carry a persisted S18 code-semantic vector, so no \
                 embedding-backed member index exists for members_hash {}",
                index.descriptor.indexed_member_count, artifact.member_count, artifact.members_hash
            ),
        )));
    }
    // The index is content-addressed by members_hash; serving it against a
    // different artifact would silently answer from another generation.
    if index.descriptor.members_hash != artifact.members_hash {
        return Err(format!(
            "{}: kernel member index members_hash {} does not match the artifact members_hash {} \
             read through the same vault handle",
            astrolabe_weave::ASTRO_KERNEL_INDEX_STALE,
            index.descriptor.members_hash,
            artifact.members_hash
        )
        .into());
    }

    Ok(Some(json!({
        "schema": astrolabe_weave::KERNEL_MEMBER_INDEX_SCHEMA,
        "status": "served",
        "index_kind": index.descriptor.index_kind.as_str(),
        "selection_reason": "persisted checksum-validated Calyx HNSW for this artifact's exact project/scope/members_hash/base_seq",
        "members_hash": index.descriptor.members_hash,
        "member_count": artifact.member_count,
        "indexed_member_count": index.descriptor.indexed_member_count,
        "missing_vector_members": index.descriptor.missing_vector_members,
        "semantic_dim": index.descriptor.semantic_dim,
        "base_seq": index.descriptor.base_seq,
        "binding_count": index.descriptor.binding_count,
        "bindings_blake3": index.descriptor.bindings_blake3,
        "hnsw_artifact_bytes": index.descriptor.hnsw_artifact_bytes,
        "hnsw_artifact_blake3": index.descriptor.hnsw_artifact_blake3,
        "backend": "hnsw",
        "trust": "verified",
        "freshness": "fresh",
        "provenance": [
            format!("kernel-artifact:scope={}", artifact.scope_id),
            "vault:slot(SLOT_CODE_SEMANTIC)".to_string(),
            "astrolabe_weave::read_persisted_kernel_member_index(#996)".to_string(),
        ],
    })))
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
    if let Some(refusal) = shadow_graph_freshness_refusal(&cache_dir, &project, "kernel_answer")? {
        return Ok(refusal);
    }
    match build_kernel_answer_inputs(&cache_dir, &project, query)? {
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
    /// Kernel-first candidate entry set for THIS query, best first (#880).
    pub(crate) matched_ids: Vec<CxId>,
    /// How the query reached that candidate set: index identity, generation, the
    /// embedded slot, and the ranked members. Served on both an answer and a
    /// refusal so the selection is physically observable either way.
    pub(crate) query_resolution: Value,
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
    query: &str,
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
            ColumnFamily::Graph,
            ColumnFamily::Kernel,
            // Composite projection and retained-snapshot provenance both bind
            // their exact Ledger rows. Query ranking itself reads Kernel only.
            ColumnFamily::Ledger,
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
    let (node_provenance, ledger) =
        kernel_answer_provenance(cache_dir, project, &vault, &artifact)?;

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

    // #880: the kernel members are the pre-selected high-value population; WHICH
    // of them this question reaches is resolved against the exact-generation
    // member index, so two unrelated queries cannot select the same entry.
    let (matched_ids, query_resolution) =
        resolve_query_candidates(&vault, project, &artifact, query)?;

    Ok(Some(KernelAnswerInputs {
        nodes,
        edges,
        matched_ids,
        query_resolution,
        ledger,
    }))
}

/// Resolves a free-text question into the kernel-first candidate set, best first
/// (#880), returning the ranked `CxId`s and the evidence that produced them.
///
/// The query is embedded with the same frozen static-embedding table the shadow
/// import measured the corpus with, then ranked on the embedding-backed
/// kernel-member index bound to this artifact's exact `members_hash`. Ranking is
/// exhaustive over the indexed members (`k` = the indexed member count), so no
/// silent truncation can hide a grounded candidate from the entry gate.
///
/// Fail-closed, never a global-weight fallback:
/// - [`ASTRO_KERNEL_ANSWER_QUERY_OOV`] when the query yields no S18 vector.
/// - [`astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT`] when the members carry no
///   persisted S18 vectors, so nothing can be ranked.
/// - A stale index, a dimension mismatch, or a table load failure propagates the
///   underlying coded error verbatim.
fn resolve_query_candidates<C>(
    vault: &AsterVault<C>,
    project: &str,
    artifact: &astrolabe_kernel::KernelArtifact,
    query: &str,
) -> Result<(Vec<CxId>, Value), DynError>
where
    C: Clock,
{
    use astrolabe_panel::{StaticEmbeddingInput, encode_static_embedding_slot};
    use astrolabe_weave::search::SLOT_CODE_SEMANTIC;
    use astrolabe_weave::search_index::split_identifier_tokens;

    let total_started = std::time::Instant::now();
    let usage_before = vault.process_usage_snapshot()?;
    // Embed the query into S18 with the frozen table the corpus was measured
    // with. This deliberately happens before touching project index state: an
    // OOV query refuses without loading or constructing an unrelated index.
    let table_started = std::time::Instant::now();
    let table = astrolabe_panel::shared_default_static_embedding_table()?;
    let table_resolution_ms = elapsed_millis(table_started.elapsed());
    let encoding_started = std::time::Instant::now();
    let input = StaticEmbeddingInput {
        body_tokens: split_identifier_tokens(query),
        doc_tokens: Vec::new(),
        name: query.to_string(),
        qualified_name: query.to_string(),
    };
    let encoded = encode_static_embedding_slot(SLOT_CODE_SEMANTIC, &input, table)?;
    let SlotVector::Dense {
        data: query_vector, ..
    } = encoded
    else {
        return Err(format!(
            "{ASTRO_KERNEL_ANSWER_QUERY_OOV}: query {query:?} carries no token the frozen \
             code-semantic embedding table knows, so it reaches no kernel member; remediation: \
             rephrase the query using identifiers or vocabulary the indexed corpus contains"
        )
        .into());
    };
    let query_encoding_ms = elapsed_millis(encoding_started.elapsed());

    let descriptor_started = std::time::Instant::now();
    let descriptor = astrolabe_weave::read_persisted_kernel_member_index_descriptor(
        vault,
        project,
        &artifact.scope_id,
        &artifact.members_hash,
    )?
    .ok_or_else(|| {
        astrolabe_weave::search::SearchError::new(
            astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT,
            format!(
                "kernel artifact {} has no persisted member-index generation",
                artifact.members_hash
            ),
            "Rebuild the kernel so descriptor/map/HNSW rows are published before serving queries.",
        )
    })?;
    let descriptor_read_ms = elapsed_millis(descriptor_started.elapsed());
    let cache_key = kernel_index_cache_key(&descriptor)?;
    let cache = KERNEL_INDEX_CACHE.get_or_init(|| Mutex::new(KernelIndexCache::default()));
    let (load_cell, cache_entries) = {
        let mut cache = cache.lock().map_err(|_| kernel_index_cache_poisoned())?;
        let cell = cache.load_cell(cache_key);
        (cell, cache.entries.len())
    };
    let artifact_load_started = std::time::Instant::now();
    let mut artifact_loaded_this_query = false;
    let index = load_cell
        .get_or_init(|| {
            artifact_loaded_this_query = true;
            let loaded = astrolabe_weave::read_persisted_kernel_member_index(
                vault,
                project,
                &artifact.scope_id,
                &artifact.members_hash,
            )?
            .ok_or_else(|| {
                astrolabe_weave::search::SearchError::new(
                    astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT,
                    "member-index descriptor disappeared before full artifact load".to_string(),
                    "Preserve the vault and rebuild the exact kernel generation.",
                )
            })?;
            Ok(std::sync::Arc::new(loaded))
        })
        .clone()?;
    let index_cache_hit = !artifact_loaded_this_query;
    let index_artifact_load_ms = elapsed_millis(artifact_load_started.elapsed());
    let k = index.descriptor.indexed_member_count as u64;
    let ranking_started = std::time::Instant::now();
    let ranked = astrolabe_weave::kernel_query_loaded_members(
        &index,
        &artifact.members_hash,
        &query_vector,
        k,
        k,
    )?;
    let ann_ranking_ms = elapsed_millis(ranking_started.elapsed());
    let process_usage = vault.process_usage_snapshot()?.phase_since(usage_before);
    let total_ms = elapsed_millis(total_started.elapsed());

    let mut matched_ids: Vec<CxId> = Vec::with_capacity(ranked.matches.len());
    let mut ranked_json: Vec<Value> = Vec::with_capacity(ranked.matches.len());
    for candidate in &ranked.matches {
        matched_ids.push(candidate.cx_id);
        ranked_json.push(json!({
            "rank": candidate.rank,
            "symbol_id": candidate.symbol_id,
            "cx_id": candidate.cx_id.to_string(),
        }));
    }

    let evidence = json!({
        "schema": "astrolabe.kernel_answer_query_resolution.v1",
        "entry_selection": "query_ranked_kernel_member_index",
        "query": query,
        "embedded_slot": SLOT_CODE_SEMANTIC.get(),
        "query_vector_dim": query_vector.len(),
        "index_kind": index.descriptor.index_kind.as_str(),
        "members_hash": ranked.members_hash,
        "base_seq": ranked.base_seq,
        "descriptor_bindings_blake3": index.descriptor.bindings_blake3,
        "descriptor_hnsw_artifact_blake3": index.descriptor.hnsw_artifact_blake3,
        "hnsw_artifact_bytes": index.descriptor.hnsw_artifact_bytes,
        "index_cache_hit": index_cache_hit,
        "index_artifact_loads_this_query": u64::from(artifact_loaded_this_query),
        "hnsw_rebuilds_this_query": 0,
        "graph_snapshot_reads_this_query": 0,
        "embedding_table_process_load_count": astrolabe_panel::shared_default_static_embedding_table_load_count(),
        "phase_timings_ms": {
            "embedding_table_resolution": table_resolution_ms,
            "query_encoding": query_encoding_ms,
            "descriptor_read": descriptor_read_ms,
            "index_artifact_load_or_wait": index_artifact_load_ms,
            "ann_ranking": ann_ranking_ms,
            "total": total_ms,
        },
        "process_usage": {
            "kernel_time_100ns": process_usage.kernel_time_100ns,
            "user_time_100ns": process_usage.user_time_100ns,
            "read_operations": process_usage.read_operations,
            "read_bytes": process_usage.read_bytes,
            "write_operations": process_usage.write_operations,
            "write_bytes": process_usage.write_bytes,
            "page_faults": process_usage.page_faults,
            "working_set_bytes_after": process_usage.working_set_bytes_after,
            "peak_working_set_bytes_after": process_usage.peak_working_set_bytes_after,
            "private_bytes_after": process_usage.private_bytes_after,
            "peak_private_bytes_after": process_usage.peak_private_bytes_after,
        },
        "cache": {
            "knob_registry_version": KERNEL_ANSWER_KNOB_REGISTRY_VERSION,
            "capacity_entries": kernel_index_cache_entries(),
            "resident_generation_cells": cache_entries,
            "single_flight": true,
        },
        "member_count": artifact.member_count,
        "indexed_member_count": ranked.indexed_member_count,
        "missing_vector_members": index.descriptor.missing_vector_members,
        "ranked_member_count": matched_ids.len(),
        "unresolved_symbol_ids": [],
        "ranked_members": ranked_json,
        "trust": "verified",
        "freshness": "fresh",
        "provenance": [
            format!("kernel-artifact:scope={}", artifact.scope_id),
            "vault:Kernel/member-index descriptor+bindings+HNSW".to_string(),
            "astrolabe_weave::kernel_query_loaded_members(#996)".to_string(),
        ],
    });
    Ok((matched_ids, evidence))
}

fn kernel_index_cache_key(
    descriptor: &astrolabe_weave::KernelMemberIndexDescriptor,
) -> Result<String, DynError> {
    let bytes = serde_json::to_vec(descriptor)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn kernel_index_cache_poisoned() -> astrolabe_weave::search::SearchError {
    astrolabe_weave::search::SearchError::new(
        ASTRO_KERNEL_INDEX_CACHE_POISONED,
        "kernel index cache mutex is poisoned, so resident generations cannot be evaluated"
            .to_string(),
        "Restart the Astrolabe server and inspect the preceding panic before serving more kernel answers.",
    )
}

fn kernel_index_cache_entries() -> usize {
    KERNEL_ANSWER_KNOBS
        .iter()
        .find(|knob| knob.name == KNOB_ANSWER_INDEX_CACHE_ENTRIES)
        .expect("kernel answer index-cache knob is declared")
        .default as usize
}

fn elapsed_millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Joins per-`CxId` provenance references and the serving-vault ledger head out of
/// the persisted provenance store. A node's provenance reference is its latest
/// lineage event's ledger pointer rendered `seq:chain_hash`; only symbol keys that
/// parse as a `CxId` are joined (the enriched-index case). The provenance store is
/// part of the answer source of truth, so an unavailable/corrupt store is returned
/// to the caller as an error.
fn kernel_answer_provenance<C>(
    cache_dir: &Path,
    project: &str,
    vault: &AsterVault<C>,
    _artifact: &astrolabe_kernel::KernelArtifact,
) -> Result<(BTreeMap<CxId, String>, LedgerPointer), DynError>
where
    C: Clock,
{
    let mut map = BTreeMap::new();
    let store = provenance_store_for_project_snapshot(cache_dir, project, vault)?;
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
        astrolabe_kernel::AnswerResolution::Refused(refusal) => tool_json_error_result(
            kernel_answer_refusal_json(project, scope, &refusal, &inputs.query_resolution),
        ),
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
            tool_json_result(served_kernel_answer_json(
                project,
                scope,
                &answer,
                &inputs.query_resolution,
            ))
        }
    }
}

/// Renders a served kernel answer for the tool surface.
fn served_kernel_answer_json(
    project: &str,
    scope: &Option<String>,
    answer: &astrolabe_kernel::KernelAnswer,
    query_resolution: &Value,
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
        "entry_selection": "query_ranked_kernel_member_index",
        "query_resolution": query_resolution,
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
    query_resolution: &Value,
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
        "query_resolution": query_resolution,
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
