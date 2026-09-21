//! `get_kernel` + `kernel_answer` MCP surface (#40, blueprint 09 §4, 15 §2).
//!
//! `get_kernel` serves the kernel context in four modes: `read` (the scope-summary
//! members — qualified name, kernel weight, grounded flag, provenance — with their
//! diagnostic graph-coverage metrics), `gaps` (the ungrounded members that still
//! need grounding), `quadrant` (the coverage-vs-importance scatter), and `build`.
//! Every read mode selects one atomically published complete kernel generation;
//! the `read` scope members and S20 index are derived under the same retained
//! snapshot rather than joining separately published metadata.
//!
//! `build` recomputes the feedback-vertex-set kernel over the vault association
//! graph on demand (#410): it opens the project's shadow vault read-write and runs
//! the same retained-snapshot composite publisher the shadow import runs at index
//! time. An explicit real `kernel_admission` corpus is mandatory, and visibility
//! changes only when the artifact, complete S20 member HNSW, real-query corpus,
//! graph-routed recall report, manifest, pointer, and Ledger evidence commit and
//! read back as one generation.
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
/// produced no kernel (empty graph, no typed edges, or an unreachable validity or
/// compactness contract).
pub(crate) const ASTRO_KERNEL_BUILD_UNAVAILABLE: &str = "ASTRO_KERNEL_BUILD_UNAVAILABLE";
/// Refusal: the kernel member index could not be read for the project — a vault,
/// artifact, or index-build failure (#882). Distinct from
/// [`astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT`], which means the index honestly
/// does not exist; this one means the state could not be determined at all, and
/// neither is ever answered with a membership-manifest substitute.
pub(crate) const ASTRO_KERNEL_INDEX_UNAVAILABLE: &str = "ASTRO_KERNEL_INDEX_UNAVAILABLE";
/// Refusal: the process-local exact-generation index cache cannot be evaluated.
pub(crate) const ASTRO_KERNEL_INDEX_CACHE_POISONED: &str = "ASTRO_KERNEL_INDEX_CACHE_POISONED";
/// Refusal: the resident-generation LRU clock cannot advance without losing
/// its total ordering.
pub(crate) const ASTRO_KERNEL_INDEX_CACHE_CLOCK_OVERFLOW: &str =
    "ASTRO_KERNEL_INDEX_CACHE_CLOCK_OVERFLOW";
/// Refusal: a measured phase duration is not representable in the receipt.
pub(crate) const ASTRO_KERNEL_ANSWER_TIMING_OVERFLOW: &str = "ASTRO_KERNEL_ANSWER_TIMING_OVERFLOW";
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
/// Refusal: a persisted kernel artifact was built from a different graph,
/// anchor-trust roster, or build configuration than the current read snapshot.
pub(crate) const ASTRO_KERNEL_SOURCE_IDENTITY_STALE: &str = "ASTRO_KERNEL_SOURCE_IDENTITY_STALE";
/// Refusal: the physical shadow-vault path could not be classified as present
/// or absent. Treating a metadata fault as absence would hide a broken kernel.
pub(crate) const ASTRO_KERNEL_VAULT_STATE_UNREADABLE: &str = "ASTRO_KERNEL_VAULT_STATE_UNREADABLE";

fn kernel_vault_present(vault_dir: &Path, project: &str, stage: &str) -> Result<bool, DynError> {
    vault_dir.try_exists().map_err(|error| {
        Box::new(
            ToolFault::new(
                ASTRO_KERNEL_VAULT_STATE_UNREADABLE,
                format!(
                    "cannot classify shadow vault {} for project {project:?} during {stage}: {error}",
                    vault_dir.display()
                ),
                "repair the named vault path so its physical presence can be read exactly, then retry the unchanged kernel operation",
            )
            .with_detail("project", project)
            .with_detail("stage", stage)
            .with_detail("vault_dir", vault_dir.display().to_string())
            .with_detail("os_error", error.to_string()),
        ) as DynError
    })
}

const GET_KERNEL_MODES: [&str; 4] = ["read", "gaps", "quadrant", "build"];
struct VerifiedKernelIndexLoad {
    index: astrolabe_weave::LoadedKernelMemberIndex,
    source: astrolabe_weave::KernelMemberIndexSourceVerification,
    generation_id: String,
}

type KernelIndexLoad =
    Result<std::sync::Arc<VerifiedKernelIndexLoad>, astrolabe_weave::search::SearchError>;
type KernelIndexLoadCell = OnceLock<KernelIndexLoad>;

#[derive(Default)]
struct KernelIndexCache {
    clock: u64,
    entries: BTreeMap<String, (std::sync::Arc<KernelIndexLoadCell>, u64)>,
}

impl KernelIndexCache {
    fn load_cell(
        &mut self,
        key: String,
    ) -> Result<std::sync::Arc<KernelIndexLoadCell>, astrolabe_weave::search::SearchError> {
        let capacity = kernel_index_cache_entries()?;
        self.clock = self.clock.checked_add(1).ok_or_else(|| {
            astrolabe_weave::search::SearchError::new(
                ASTRO_KERNEL_INDEX_CACHE_CLOCK_OVERFLOW,
                "kernel index cache LRU clock exhausted u64; resident-generation order cannot be advanced without aliasing an older access",
                "restart the Astrolabe server to create a fresh cache generation before serving another kernel answer",
            )
        })?;
        if let Some((cell, last_used)) = self.entries.get_mut(&key) {
            *last_used = self.clock;
            return Ok(std::sync::Arc::clone(cell));
        }
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
        Ok(cell)
    }
}

static KERNEL_INDEX_CACHE: OnceLock<Mutex<KernelIndexCache>> = OnceLock::new();

pub(crate) fn handle_get_kernel(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("get_kernel arguments must be a JSON object");
    };
    // #1151: a fleet scope is cross-project and resolves only through the
    // independently verified atomic fleet catalog generation.
    if let Some(scope_id) = string_arg(args_obj, "scope")
        && is_fleet_scope(scope_id)
    {
        if args_obj.contains_key(KERNEL_ADMISSION_ARG) {
            return ToolFault::new(
                "ASTRO_KERNEL_ADMISSION_WITHOUT_BUILD",
                "kernel_admission was supplied for a fleet-scope read",
                "remove kernel_admission for fleet reads; it is accepted only by a project-scoped get_kernel mode=\"build\"",
            )
            .with_argument(
                KERNEL_ADMISSION_ARG,
                "absent for fleet scope",
                args_obj.get(KERNEL_ADMISSION_ARG).unwrap_or(&Value::Null),
            )
            .into_result();
        }
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
    if mode != "build" && args_obj.contains_key(KERNEL_ADMISSION_ARG) {
        return ToolFault::new(
            "ASTRO_KERNEL_ADMISSION_WITHOUT_BUILD",
            format!("kernel_admission was supplied for get_kernel mode {mode:?}"),
            "remove kernel_admission or request mode=\"build\"; read/gaps/quadrant resolve the already-admitted current generation",
        )
        .with_argument(
            KERNEL_ADMISSION_ARG,
            "present only when mode is build",
            args_obj.get(KERNEL_ADMISSION_ARG).unwrap_or(&Value::Null),
        )
        .into_result();
    }
    let scope = string_arg(args_obj, "scope").map(ToOwned::to_owned);
    let cache_dir = astrolabe_bridge::cbm_cache_dir()?;
    if let Some(refusal) = shadow_graph_freshness_refusal(&cache_dir, &project, "get_kernel")? {
        return Ok(refusal);
    }

    if mode == "build" {
        if scope.is_some() {
            return ToolFault::new(
                "ASTRO_KERNEL_BUILD_SCOPE_UNSUPPORTED",
                "get_kernel mode=\"build\" received a scope even though the only production kernel-generation contract is the complete whole-repository graph",
                "remove scope and rebuild the whole-repository kernel; scoped/fleet kernels use separate explicit producers and are never inferred by ignoring an argument",
            )
            .with_argument(
                "scope",
                "absent when mode is build",
                args_obj.get("scope").unwrap_or(&Value::Null),
            )
            .into_result();
        }
        // #410/#1148: run the same retained-snapshot complete-generation publisher
        // as shadow import. The graph projection is a mandatory input and is never
        // materialized here. The shared per-project mutation lock remains held from
        // explicit admission parsing through atomic publication and independent
        // pointer/manifest/Ledger readback.
        let kernel_admission = match parse_kernel_admission_request(args_obj) {
            Ok(Some(admission)) => admission,
            Ok(None) => {
                return ToolFault::new(
                    astrolabe_weave::ASTRO_KERNEL_ADMISSION_REQUIRED,
                    "get_kernel mode=\"build\" requires an explicit real-query kernel_admission object",
                    "supply nonempty independently authored queries plus every explicit graph-routed recall/work control; no current corpus is inherited by an operator-requested build",
                )
                .with_argument(
                    KERNEL_ADMISSION_ARG,
                    "required closed kernel_admission object for mode=build",
                    &Value::Null,
                )
                .into_result();
            }
            Err(fault) => return fault.into_result(),
        };
        let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(&cache_dir, &project)?;
        let Some(shadow_import_lock) = try_shadow_import_lock(&cache_dir, &project)? else {
            return ToolFault::new(
                "ASTRO_SHADOW_IMPORT_BUSY",
                format!(
                    "a shadow publication or kernel build for project {project:?} is already active at {}",
                    shadow_import_lock_path(&cache_dir, &project).display()
                ),
                "retry after that exact project mutation owner completes",
            )
            .with_detail("project", project.clone())
            .with_detail(
                "lock_path",
                shadow_import_lock_path(&cache_dir, &project)
                    .display()
                    .to_string(),
            )
            .into_result();
        };
        shadow_import_lock.assert_owns(&cache_dir, &project)?;
        if !kernel_vault_present(&vault_dir, &project, "get_kernel_build")? {
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
        // One latest-state handle spans exactly the source and publication CFs:
        // Graph+Kernel for the persisted projection, Anchors+Kv for effective
        // trust, S20+Compression for the complete vector binding, and
        // Kernel+Ledger+TimeIndex for the one atomic generation commit. No
        // historical MVCC rows are restored.
        let vault = open_shadow_vault_writable_latest_selected(
            &vault_dir,
            &vault_id,
            &vault_salt,
            vec![
                ColumnFamily::Graph,
                ColumnFamily::Anchors,
                ColumnFamily::Kv,
                ColumnFamily::Kernel,
                ColumnFamily::slot(astrolabe_weave::search::SLOT_NAME_SEMANTIC),
                ColumnFamily::Compression,
                ColumnFamily::Ledger,
                ColumnFamily::TimeIndex,
            ],
        )?;
        let publication = persist_index_time_kernel_artifact(
            &vault,
            &vault_dir,
            &project,
            Some(&kernel_admission),
            KernelAdmissionContract::ExplicitRequired,
        )?;
        return tool_json_result(get_kernel_build_response_json(
            &project,
            &publication.receipt,
        )?);
    }

    // #39: gaps + quadrant serve the flattened cross-scope grounding-gap views
    // owned by `kernel_gaps`. gaps ranks the ungrounded members by persisted
    // kernel weight; quadrant classifies every member into the coverage-vs-
    // importance scatter. Both resolve their members and evidence from one
    // complete current generation rather than separately published context.
    if mode == "gaps" || mode == "quadrant" {
        // #365/#540: the persisted KernelArtifact is the sole source of truth for
        // gap/quadrant reads. A missing or unreadable artifact is a state failure,
        // never permission to substitute a degraded scope summary.
        match read_project_kernel_artifact(&cache_dir, &project) {
            Ok(Some(generation)) => {
                let mut response = if mode == "gaps" {
                    artifact_gap_report_value(&project, &generation.artifact)
                } else {
                    artifact_quadrant_value(&project, &generation.artifact)
                };
                attach_kernel_generation_evidence(&mut response, &generation)?;
                return tool_json_result(response);
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

    // One retained vault snapshot selects the artifact, complete S20 index, and
    // member-derived scope summaries. A separately persisted kernel-context
    // document is not a generation selector and must never be joined here.
    let state = match read_kernel_index_state(&cache_dir, &project) {
        Ok(Some(state)) => state,
        Ok(None) => {
            return tool_json_error_result(json!({
                "schema": "astrolabe.get_kernel.v1",
                "status": "refused",
                "mode": mode,
                "project": project,
                "code": astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT,
                "message": format!("project {project:?} has no complete persisted kernel artifact/member-index generation"),
                "remediation": "run index_repository with calyx=\"shadow\" and explicit kernel_admission so one complete graph-bound artifact, S20 member index, real-query corpus, and recall report are atomically published before reading the kernel",
                "trust": "not_evaluated",
                "freshness": "not_evaluated",
            }));
        }
        Err(error) => {
            return tool_json_error_result(json!({
                "schema": "astrolabe.get_kernel.v1",
                "status": "refused",
                "mode": mode,
                "project": project,
                "code": ASTRO_KERNEL_INDEX_UNAVAILABLE,
                "message": format!("complete kernel generation could not be read for project {project:?}: {error}"),
                "remediation": "repair the shadow vault and its current pointer/manifest/artifact/S20 index/query/report/Ledger generation, then retry; no metadata or legacy-index substitute is served",
                "trust": "not_evaluated",
                "freshness": "not_evaluated",
            }));
        }
    };
    let summaries = match scope_summaries_from_collection(&state.scope_summaries) {
        Ok(summaries) => summaries,
        Err(error) => {
            return tool_json_error_result(json!({
                "schema": "astrolabe.get_kernel.v1",
                "status": "refused",
                "mode": mode,
                "code": ASTRO_GET_KERNEL_UNAVAILABLE,
                "message": format!("the current complete generation produced an invalid member-derived scope summary: {error}"),
                "remediation": "repair the current artifact member/identity join and republish one complete generation",
                "trust": "not_evaluated",
                "freshness": "not_evaluated",
            }));
        }
    };

    let selected: Vec<&ValidatedScopeSummary> = match &scope {
        Some(scope_id) => {
            let matched: Vec<&ValidatedScopeSummary> = summaries
                .iter()
                .filter(|summary| {
                    summary.json.get("scope_id").and_then(Value::as_str) == Some(scope_id.as_str())
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
    let all_grounded = selected
        .iter()
        .all(|summary| summary.grounded_member_count == summary.total_member_count);
    let total_gaps = match selected.iter().try_fold(0_u64, |total, summary| {
        total.checked_add(scope_gap_count(summary))
    }) {
        Some(total) => total,
        None => {
            return tool_json_error_result(json!({
                "schema": "astrolabe.get_kernel.v1",
                "status": "refused",
                "mode": mode,
                "code": ASTRO_GET_KERNEL_UNAVAILABLE,
                "message": "the exact scope-summary gap total is not representable as u64",
                "remediation": "repair the scope-summary collection and republish one representable complete generation",
                "trust": "not_evaluated",
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
        "index": state.index,
        "trust": if all_grounded { "verified" } else { "provisional" },
        "freshness": "fresh",
        "provenance": format!("complete-kernel-generation member-derived scope summary of {project}"),
    }))
}

/// Reshapes the index-time complete-generation persist summary
/// ([`persist_index_time_kernel_artifact`]) into the `get_kernel mode="build"`
/// response (#410). A `persisted` summary serves `status:"built"` carrying the real
/// source/FVS/S20/query/report/pointer/readback fields the build produced and read back. Build
/// failures never reach this serializer: [`persist_index_time_kernel_artifact`]
/// returns a typed [`ASTRO_KERNEL_GENERATION_FAILED`] fault instead.
fn get_kernel_build_response_json(project: &str, summary: &Value) -> Result<Value, DynError> {
    if summary.get("schema").and_then(Value::as_str) != Some(KERNEL_ARTIFACT_PERSIST_SCHEMA)
        || summary.get("status").and_then(Value::as_str) != Some("persisted")
    {
        return Err(kernel_generation_fault(
            project,
            &kernel_artifact_scope_id(project),
            "response_validation",
            None,
            format!("unexpected successful kernel summary: {summary}"),
            None,
            "repair the kernel generation result serializer so it emits the exact persisted schema before retrying",
        ));
    }
    Ok(json!({
            "schema": "astrolabe.get_kernel.v1",
            "status": "built",
            "mode": "build",
            "project": project,
            "published": summary.get("published"),
            "scope_id": summary.get("scope_id"),
            "generation_id": summary.get("generation_id"),
            "source_generation_identity": summary.get("source_generation_identity"),
            "members_hash": summary.get("members_hash"),
            "member_count": summary.get("member_count"),
            "node_count": summary.get("node_count"),
            "graph_coverage": summary.get("graph_coverage"),
            "compactness": summary.get("compactness"),
            "fvs_validity": summary.get("fvs_validity"),
            "anchor_grounded": summary.get("anchor_grounded"),
            "trusted_anchor_count": summary.get("trusted_anchor_count"),
            "source_identity": summary.get("source_identity"),
            "source_identity_readback": summary.get("source_identity_readback"),
            "rows_readback_verified": summary.get("rows_readback_verified"),
            "readback_rows": summary.get("readback_rows"),
            "decoded_rows_verified": summary.get("decoded_rows_verified"),
            "ledger_paired": summary.get("ledger_paired"),
            "commit_seq": summary.get("commit_seq"),
            "ledger_ref": summary.get("ledger_ref"),
            "ledger_physical_tiers": summary.get("ledger_physical_tiers"),
            "manifest": summary.get("manifest"),
            "pointer": summary.get("pointer"),
            "retired_generation_id": summary.get("retired_generation_id"),
            "query_admission": summary.get("query_admission"),
            "member_index": summary.get("member_index"),
            "flush": summary.get("flush"),
            "trust": summary.get("trust"),
            "freshness": summary.get("freshness"),
            "provenance": summary.get("provenance"),
    }))
}

/// Resolves the current whole-repo artifact, real-query corpus, recall report,
/// manifest, and pointer as one read-only composite generation (#365/#1148).
/// `Ok(None)` means the project's shadow vault is absent. An existing vault
/// without a complete current pointer is an incomplete generation and fails
/// closed; no legacy fixed alias is substituted. Gaps/quadrant do not execute
/// vector search, so this reader verifies the member descriptor but deliberately
/// does not materialize bindings or HNSW bytes. Its work is bounded by artifact,
/// query/report, manifest, and descriptor bytes rather than `O(K*D)` index bytes.
struct ProjectKernelArtifactRead {
    artifact: astrolabe_kernel::KernelArtifact,
    query_corpus: astrolabe_weave::KernelRecallQueryCorpus,
    graph_routed_report: astrolabe_kernel::GraphRoutedRecallReport,
    manifest: astrolabe_weave::KernelGenerationManifest,
    pointer: astrolabe_weave::KernelGenerationPointer,
    descriptor: astrolabe_weave::KernelMemberIndexDescriptor,
    rows_verified: usize,
}

fn read_project_kernel_artifact(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<ProjectKernelArtifactRead>, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !kernel_vault_present(&vault_dir, project, "read_project_kernel_artifact")? {
        return Ok(None);
    }
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Kernel,
            ColumnFamily::Graph,
            ColumnFamily::Anchors,
            ColumnFamily::Kv,
            ColumnFamily::Slot(astrolabe_weave::search::SLOT_NAME_SEMANTIC),
            ColumnFamily::Compression,
            ColumnFamily::Ledger,
        ],
    )?;
    let read_lease = vault.retain_latest_snapshot();
    let read_seq = read_lease.seq();
    let scope_id = kernel_artifact_scope_id(project);
    let artifact_read =
        astrolabe_weave::read_current_kernel_generation_artifact(&vault, project, &scope_id)?
            .ok_or_else(|| {
            astrolabe_weave::search::SearchError::new(
                astrolabe_weave::ASTRO_KERNEL_GENERATION_INCOMPLETE,
                format!(
                    "shadow vault {} for project {project:?} exists but has no current complete kernel generation for scope {scope_id:?}",
                    vault_dir.display(),
                ),
                "rebuild and atomically publish the complete artifact/index/query/report generation; an existing shadow vault without its required current pointer is not an unindexed-project absence",
            )
            })?;
    let descriptor_read = astrolabe_weave::read_current_kernel_generation_descriptor(
        &vault,
        project,
        &scope_id,
        &artifact_read.artifact.members_hash,
    )?
    .ok_or_else(|| {
        astrolabe_weave::search::SearchError::new(
            astrolabe_weave::ASTRO_KERNEL_GENERATION_INCOMPLETE,
            format!(
                "current complete kernel generation for project {project:?} scope {scope_id:?} lost its member descriptor"
            ),
            "repair and atomically republish the complete generation; descriptor absence is never treated as a membership-only success",
        )
    })?;
    if descriptor_read.manifest != artifact_read.manifest
        || descriptor_read.pointer != artifact_read.pointer
    {
        return Err(format!(
            "{ASTRO_KERNEL_SOURCE_IDENTITY_STALE}: artifact and member descriptor resolved different current generation headers under retained seq {read_seq}; remediation: preserve and repair the composite pointer/manifest"
        )
        .into());
    }
    if vault.latest_seq() != read_seq {
        return Err(format!(
            "{ASTRO_KERNEL_SOURCE_IDENTITY_STALE}: vault moved from retained read sequence {read_seq} to {} while resolving the current complete generation; remediation: retry against one stable current generation",
            vault.latest_seq()
        )
        .into());
    }
    drop(read_lease);
    Ok(Some(ProjectKernelArtifactRead {
        artifact: artifact_read.artifact,
        query_corpus: artifact_read.query_corpus,
        graph_routed_report: artifact_read.graph_routed_report,
        manifest: artifact_read.manifest,
        pointer: artifact_read.pointer,
        descriptor: descriptor_read.descriptor,
        // Artifact/header validation accounts for 12 unique physical rows;
        // descriptor generation+alias adds two. Binding/HNSW bytes are
        // deliberately not read by gaps/quadrant.
        rows_verified: artifact_read.rows_verified + 2,
    }))
}

fn attach_kernel_generation_evidence(
    response: &mut Value,
    generation: &ProjectKernelArtifactRead,
) -> Result<(), DynError> {
    let object = response.as_object_mut().ok_or_else(|| -> DynError {
        "ASTRO_GET_KERNEL_RESPONSE_INVALID: kernel response is not an object"
            .to_string()
            .into()
    })?;
    object.insert(
        "generation".to_string(),
        json!({
            "generation_id": generation.manifest.generation_id,
            "manifest": generation.manifest,
            "pointer": generation.pointer,
            "query_corpus": generation.query_corpus,
            "graph_routed_report": generation.graph_routed_report,
            "decoded_rows_verified": generation.rows_verified,
            "member_index": {
                "descriptor": &generation.descriptor,
                "binding_count": generation.descriptor.binding_count,
                "read_scope": "descriptor_only_no_hnsw_materialization",
            },
            "artifact_source_identity": generation.artifact.source_identity,
            "fvs_validity": generation.artifact.fvs_validity,
            "compactness": generation.artifact.compactness,
            "graph_coverage": generation.artifact.graph_coverage,
        }),
    );
    Ok(())
}

/// Produces serving evidence from the already-verified complete-generation
/// source binding and the manifest-bound CSR. The generation reader has
/// independently point-read the durable Graph/Anchors/Kv generations and exact
/// projection manifest before this helper is called.
pub(crate) fn bounded_kernel_source_evidence(
    csr: &astrolabe_ingest::GraphProjectionCsr,
    artifact: &astrolabe_kernel::KernelArtifact,
    manifest: &astrolabe_weave::KernelGenerationManifest,
    snapshot: u64,
) -> Result<Value, DynError> {
    let projection = &manifest.generation_source_binding.projection_manifest;
    let observed_source_fingerprint = hex_lower(&csr.source_fingerprint_blake3);
    if observed_source_fingerprint != projection.source_fingerprint_blake3
        || csr.nodes.len() != projection.node_count
        || csr.edges.len() != projection.edge_count
        || csr.association_edge_count != projection.association_edge_count
        || artifact.source_identity != manifest.artifact_source_identity
    {
        return Err(Box::new(
            ToolFault::new(
                ASTRO_KERNEL_SOURCE_IDENTITY_STALE,
                format!(
                    "manifest-bound kernel source differs at snapshot {snapshot}: expected_fingerprint={}, observed_fingerprint={observed_source_fingerprint}, expected_nodes={}, observed_nodes={}, expected_edges={}, observed_edges={}, expected_association_edges={}, observed_association_edges={}",
                    projection.source_fingerprint_blake3,
                    projection.node_count,
                    csr.nodes.len(),
                    projection.edge_count,
                    csr.edges.len(),
                    projection.association_edge_count,
                    csr.association_edge_count,
                ),
                "preserve the current generation and rebuild it from one exact Graph/Anchors/Kv source binding; serving never substitutes a stale projection or artifact",
            )
            .with_detail("read_snapshot_seq", snapshot)
            .with_detail("generation_id", &manifest.generation_id)
            .with_detail("expected_projection_manifest", json!(projection))
            .with_detail("artifact_source_identity", json!(&artifact.source_identity)),
        ));
    }
    Ok(json!({
        "schema": "astrolabe.kernel_source_readback.v2",
        "read_snapshot_seq": snapshot,
        "generation_id": &manifest.generation_id,
        "source_identity": &artifact.source_identity,
        "generation_source_binding": &manifest.generation_source_binding,
        "projection_source_fingerprint_blake3": observed_source_fingerprint,
        "projection_node_count": csr.nodes.len(),
        "projection_edge_count": csr.edges.len(),
        "projection_association_edge_count": csr.association_edge_count,
        "verified": true,
    }))
}

/// Reads the persisted kernel artifact and its complete embedding-backed member
/// index for one project through a single read-only vault handle (#365/#344/#882).
///
/// One open per request, for one generation: the artifact read and the member
/// index are two views of the same immutable vault state, and opening the vault
/// twice let them disagree about which generation was served.
///
/// Fail-closed contract (#882): every config, vault, artifact, and index-build
/// failure is returned as an `Err` and surfaces as a coded refusal. `Ok(None)`
/// means the project's shadow vault is absent. Membership-only or partial
/// descriptors are invalid production state and return a structured error. The
/// embedding-backed view is served only when its complete physical roster,
/// source binding, and `members_hash` match the artifact read by this same handle.
pub(crate) struct ProjectKernelIndexState {
    pub(crate) index: Value,
    pub(crate) scope_summaries: Value,
}

pub(crate) fn read_kernel_index_state(
    cache_dir: &Path,
    project: &str,
) -> Result<Option<ProjectKernelIndexState>, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !kernel_vault_present(&vault_dir, project, "read_kernel_index_state")? {
        return Ok(None);
    }
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Kernel,
            ColumnFamily::Base,
            ColumnFamily::Graph,
            ColumnFamily::Anchors,
            ColumnFamily::Kv,
            ColumnFamily::Slot(astrolabe_weave::search::SLOT_NAME_SEMANTIC),
            ColumnFamily::Compression,
            ColumnFamily::Ledger,
        ],
    )?;
    let read_lease = vault.retain_latest_snapshot();
    let read_seq = read_lease.seq();
    let scope_id = kernel_artifact_scope_id(project);
    let generation = astrolabe_weave::read_current_kernel_generation(&vault, project, &scope_id)?
        .ok_or_else(|| {
            astrolabe_weave::search::SearchError::new(
                astrolabe_weave::ASTRO_KERNEL_GENERATION_INCOMPLETE,
                format!(
                    "shadow vault {} for project {project:?} exists but has no current complete kernel generation for scope {scope_id:?}",
                    vault_dir.display(),
                ),
                "rebuild and atomically publish the complete artifact/index/query/report generation; no partial or legacy member index is served",
            )
        })?;
    let csr = astrolabe_ingest::read_graph_projection_csr_bound_at(
        &vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        read_seq,
        &astrolabe_ingest::GraphProjectionReadBinding {
            graph_content_generation: generation
                .manifest
                .generation_source_binding
                .graph_content_generation,
            manifest: generation
                .manifest
                .generation_source_binding
                .projection_manifest
                .clone(),
        },
    )?;
    let kernel_source_verification =
        bounded_kernel_source_evidence(&csr, &generation.artifact, &generation.manifest, read_seq)?;
    let scope_summaries =
        scope_summaries_from_kernel_artifact(&vault, project, &generation.artifact)?;
    let index = &generation.index;

    if index.descriptor.index_kind != astrolabe_weave::KernelIndexKind::EmbeddingBackedHnsw {
        return Err(astrolabe_weave::search::SearchError::new(
            astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT,
            format!(
                "obsolete membership-only index found for members_hash {}; current serving requires one S20 name-semantic vector/HNSW row for all {} members",
                generation.artifact.members_hash, generation.artifact.member_count
            ),
            "rebuild and atomically publish the complete current S20 member-index generation; no membership-only substitute is served",
        )
        .into());
    }
    // The index is content-addressed by members_hash; serving it against a
    // different artifact would silently answer from another generation.
    if index.descriptor.members_hash != generation.artifact.members_hash {
        return Err(format!(
            "{}: kernel member index members_hash {} does not match the artifact members_hash {} \
             read through the same vault handle",
            astrolabe_weave::ASTRO_KERNEL_INDEX_STALE,
            index.descriptor.members_hash,
            generation.artifact.members_hash
        )
        .into());
    }
    let source_verification = astrolabe_weave::verify_kernel_member_index_source_at_latest(
        &vault,
        &vault_dir,
        &index.descriptor,
    )?;
    if vault.latest_seq() != read_seq {
        return Err(format!(
            "{ASTRO_KERNEL_SOURCE_IDENTITY_STALE}: vault moved from retained read sequence {read_seq} to {} while resolving the complete artifact/index generation; remediation: retry against one stable current generation",
            vault.latest_seq()
        )
        .into());
    }
    drop(read_lease);

    let index = json!({
        "schema": astrolabe_weave::KERNEL_MEMBER_INDEX_SCHEMA,
        "status": "served",
        "index_kind": index.descriptor.index_kind.as_str(),
        "selection_reason": "persisted checksum-validated Calyx HNSW for this artifact's exact project/scope/members_hash/base_seq",
        "generation_id": generation.manifest.generation_id,
        "source_generation_identity": generation.manifest.source_generation_identity,
        "manifest": generation.manifest,
        "pointer": generation.pointer,
        "query_corpus": generation.query_corpus,
        "graph_routed_report": generation.graph_routed_report,
        "decoded_rows_verified": generation.rows_verified,
        "artifact_source_identity": generation.artifact.source_identity,
        "fvs_validity": generation.artifact.fvs_validity,
        "compactness": generation.artifact.compactness,
        "graph_coverage": generation.artifact.graph_coverage,
        "members_hash": index.descriptor.members_hash,
        "member_count": generation.artifact.member_count,
        "indexed_member_count": index.descriptor.indexed_member_count,
        "missing_vector_members": index.descriptor.missing_vector_members,
        "semantic_dim": index.descriptor.semantic_dim,
        "base_seq": index.descriptor.base_seq,
        "binding_count": index.descriptor.binding_count,
        "bindings_blake3": index.descriptor.bindings_blake3,
        "source_binding_seq": index.descriptor.source_binding_seq,
        "source_final_verification_seq": index.descriptor.source_final_verification_seq,
        "source_binding": index.descriptor.source_binding,
        "source_read_verification": source_verification,
        "kernel_source_verification": kernel_source_verification,
        "hnsw_artifact_bytes": index.descriptor.hnsw_artifact_bytes,
        "hnsw_artifact_blake3": index.descriptor.hnsw_artifact_blake3,
        "backend": "hnsw",
        "trust": "verified",
        "freshness": "fresh",
        "provenance": [
            format!("kernel-generation:{}", generation.manifest.generation_id),
            "vault:slot(S20_NAME_SEMANTIC)".to_string(),
            "astrolabe_weave::read_current_kernel_generation(pointer+manifest+eight rows)".to_string(),
        ],
    });
    Ok(Some(ProjectKernelIndexState {
        index,
        scope_summaries,
    }))
}

/// Reshapes one persisted scope-summary into the `get_kernel` per-scope view.
/// `read` carries every member; `gaps` carries only the ungrounded members.
fn get_kernel_scope_json(summary: &ValidatedScopeSummary, mode: &str) -> Value {
    let member_views = summary
        .members
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
        "scope_id": summary.json.get("scope_id"),
        "summary_hash": summary.json.get("summary_hash"),
        "member_count": summary.total_member_count,
        "grounded_member_count": summary.grounded_member_count,
        "gap_count": scope_gap_count(summary),
        "grounded_fraction_millipoints": summary.json.get("grounded_fraction_millipoints"),
        "graph_coverage": summary.json.get("graph_coverage"),
        "graph_coverage_millipoints": summary.json.get("graph_coverage_millipoints"),
        "members": member_views,
        "trust": summary.json.get("trust"),
        "freshness": summary.json.get("freshness"),
    })
}

fn scope_gap_count(summary: &ValidatedScopeSummary) -> u64 {
    summary.total_member_count - summary.grounded_member_count
}

#[derive(Clone)]
struct ValidatedScopeSummary {
    json: Value,
    members: Vec<Value>,
    grounded_member_count: u64,
    total_member_count: u64,
}

/// Reconstructs and byte-semantically validates a complete, nonempty
/// member-derived scope-summary collection. Serving never defaults missing
/// counts/members or clamps contradictory persisted measurements.
fn scope_summaries_from_collection(
    scope_summaries: &Value,
) -> Result<Vec<ValidatedScopeSummary>, String> {
    if scope_summaries.get("schema").and_then(Value::as_str)
        != Some(SCOPE_SUMMARY_COLLECTION_SCHEMA)
        || scope_summaries
            .get("summary_schema")
            .and_then(Value::as_str)
            != Some(SCOPE_SUMMARY_SCHEMA)
        || scope_summaries.get("status").and_then(Value::as_str) != Some("built")
        || scope_summaries.get("skipped_count").and_then(Value::as_u64) != Some(0)
    {
        return Err("collection schema/status/summary_schema/skipped_count is not the complete built contract".to_string());
    }
    let summaries = scope_summaries
        .get("summaries")
        .and_then(Value::as_array)
        .filter(|summaries| !summaries.is_empty())
        .ok_or_else(|| "collection has no nonempty summaries array".to_string())?;
    if scope_summaries.get("summary_count").and_then(Value::as_u64)
        != u64::try_from(summaries.len()).ok()
    {
        return Err("collection summary_count does not equal the summaries roster".to_string());
    }

    let mut scope_ids = BTreeSet::new();
    let mut rebuilt = Vec::with_capacity(summaries.len());
    let mut validated = Vec::with_capacity(summaries.len());
    for (ordinal, summary) in summaries.iter().enumerate() {
        if summary.get("schema").and_then(Value::as_str) != Some(SCOPE_SUMMARY_SCHEMA)
            || summary.get("freshness").and_then(Value::as_str) != Some("fresh")
        {
            return Err(format!(
                "summary ordinal {ordinal} has an invalid schema/freshness"
            ));
        }
        let scope_id = required_nonempty_summary_string(summary, ordinal, "scope_id")?;
        if !scope_ids.insert(scope_id.to_string()) {
            return Err(format!("scope_id {scope_id:?} occurs more than once"));
        }
        let dirty_region_hash =
            required_nonempty_summary_string(summary, ordinal, "dirty_region_hash")?;
        let trust = summary
            .get("trust")
            .and_then(Value::as_str)
            .filter(|trust| matches!(*trust, "verified" | "provisional"))
            .ok_or_else(|| format!("summary ordinal {ordinal} has invalid trust"))?;
        let members = summary
            .get("members")
            .and_then(Value::as_array)
            .filter(|members| !members.is_empty())
            .ok_or_else(|| format!("summary ordinal {ordinal} has no members"))?;
        let mut member_ids = BTreeSet::new();
        let mut typed_members = Vec::with_capacity(members.len());
        for (member_ordinal, member) in members.iter().enumerate() {
            let symbol_id = required_nonempty_summary_string(member, member_ordinal, "symbol_id")?;
            if !member_ids.insert(symbol_id.to_string()) {
                return Err(format!(
                    "summary {scope_id:?} repeats member symbol_id {symbol_id:?}"
                ));
            }
            let qualified_name =
                required_nonempty_summary_string(member, member_ordinal, "qualified_name")?;
            let provenance_ref =
                required_nonempty_summary_string(member, member_ordinal, "provenance_ref")?;
            let kernel_weight = member
                .get("kernel_weight")
                .and_then(Value::as_u64)
                .filter(|weight| *weight <= 1_000)
                .ok_or_else(|| {
                    format!("summary {scope_id:?} member {symbol_id:?} has invalid kernel_weight")
                })?;
            let grounded = member
                .get("grounded")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    format!(
                        "summary {scope_id:?} member {symbol_id:?} has no boolean grounded value"
                    )
                })?;
            typed_members.push(ScopeSummaryMember::new(
                symbol_id,
                qualified_name,
                kernel_weight,
                grounded,
                provenance_ref,
            ));
        }
        let graph_coverage = match summary.get("graph_coverage") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let covered = value
                    .get("covered")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| format!("summary {scope_id:?} has invalid covered count"))?;
                let total = value
                    .get("total")
                    .and_then(Value::as_u64)
                    .filter(|total| *total > 0)
                    .ok_or_else(|| format!("summary {scope_id:?} has invalid coverage total"))?;
                if covered > total || covered.checked_mul(1_000).is_none() {
                    return Err(format!(
                        "summary {scope_id:?} coverage is contradictory or not representable"
                    ));
                }
                Some(ScopeGraphCoverageMeasurement { covered, total })
            }
        };
        let observed = summarize_scope_kernel(&ScopeSummaryInput::new(
            scope_id,
            dirty_region_hash,
            trust == "verified",
            typed_members,
            graph_coverage,
        ));
        let total_member_count = u64::try_from(observed.total_member_count)
            .map_err(|_| format!("summary {scope_id:?} member count exceeds u64"))?;
        let grounded_member_count = u64::try_from(observed.grounded_member_count)
            .map_err(|_| format!("summary {scope_id:?} grounded count exceeds u64"))?;
        rebuilt.push(observed);
        validated.push(ValidatedScopeSummary {
            json: summary.clone(),
            members: members.clone(),
            grounded_member_count,
            total_member_count,
        });
    }
    if scope_summaries_json(&rebuilt, 0) != *scope_summaries {
        return Err(
            "collection bytes do not equal the independently rebuilt canonical summaries"
                .to_string(),
        );
    }
    Ok(validated)
}

fn required_nonempty_summary_string<'a>(
    value: &'a Value,
    ordinal: usize,
    field: &str,
) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("row ordinal {ordinal} has no nonempty {field}"))
}

pub(crate) fn handle_kernel_answer(args_json: &str) -> Result<String, DynError> {
    let args = serde_json::from_str::<Value>(args_json)?;
    let Some(args_obj) = args.as_object() else {
        return tool_error_result("kernel_answer arguments must be a JSON object");
    };
    // #1151: fleet scopes resolve through their atomic artifact/index/query/
    // report generation. They never fall through to a project/dial reader or
    // the retained historical fixed-row fleet artifact.
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
/// `Ok(None)` only when the project's shadow vault is absent. Once the vault
/// exists, a missing current generation or graph projection is corrupt/incomplete
/// state and returns a coded error rather than masquerading as an unindexed project.
pub(crate) fn build_kernel_answer_inputs(
    cache_dir: &Path,
    project: &str,
    query: &str,
) -> Result<Option<KernelAnswerInputs>, DynError> {
    let (vault_dir, vault_id, vault_salt) = shadow_vault_config_at(cache_dir, project)?;
    if !kernel_vault_present(&vault_dir, project, "build_kernel_answer_inputs")? {
        return Ok(None);
    }
    let vault = open_shadow_vault_read_only(
        &vault_dir,
        &vault_id,
        &vault_salt,
        vec![
            ColumnFamily::Graph,
            ColumnFamily::Kernel,
            ColumnFamily::Anchors,
            ColumnFamily::Kv,
            ColumnFamily::Slot(astrolabe_weave::search::SLOT_NAME_SEMANTIC),
            ColumnFamily::Compression,
            // Composite projection and retained-snapshot provenance both bind
            // their exact Ledger rows. Query ranking itself reads Kernel only.
            ColumnFamily::Ledger,
        ],
    )?;
    let read_lease = vault.retain_latest_snapshot();
    let read_seq = read_lease.seq();
    let scope_id = kernel_artifact_scope_id(project);
    let generation = astrolabe_weave::read_current_kernel_generation_artifact(
        &vault, project, &scope_id,
    )?
    .ok_or_else(|| {
        astrolabe_weave::search::SearchError::new(
            astrolabe_weave::ASTRO_KERNEL_GENERATION_INCOMPLETE,
            format!(
                "shadow vault {} for project {project:?} exists but has no current complete kernel generation for scope {scope_id:?}",
                vault_dir.display(),
            ),
            "rebuild and atomically publish the complete artifact/index/query/report generation before serving kernel answers",
        )
    })?;
    let csr = astrolabe_ingest::read_graph_projection_csr_bound_at(
        &vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        read_seq,
        &astrolabe_ingest::GraphProjectionReadBinding {
            graph_content_generation: generation
                .manifest
                .generation_source_binding
                .graph_content_generation,
            manifest: generation
                .manifest
                .generation_source_binding
                .projection_manifest
                .clone(),
        },
    )?;
    let kernel_source_verification =
        bounded_kernel_source_evidence(&csr, &generation.artifact, &generation.manifest, read_seq)?;

    // Per-node provenance references and the ledger head are required persisted
    // inputs. Store read failure is terminal; a zero-ledger substitute would make
    // the eventual refusal indistinguishable from genuine ungrounded state.
    let (node_provenance, ledger) =
        kernel_answer_provenance(cache_dir, project, &vault, &generation.artifact)?;

    let member_by_id: BTreeMap<CxId, &astrolabe_kernel::KernelMember> = generation
        .artifact
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
    let (matched_ids, mut query_resolution) =
        resolve_query_candidates(&vault, &vault_dir, project, &generation, query)?;
    query_resolution
        .as_object_mut()
        .ok_or("ASTRO_KERNEL_QUERY_RESOLUTION_INVALID: query-resolution evidence is not an object")?
        .insert(
            "kernel_source_verification".to_string(),
            kernel_source_verification,
        );
    if vault.latest_seq() != read_seq {
        return Err(format!(
            "{ASTRO_KERNEL_SOURCE_IDENTITY_STALE}: vault moved from retained answer sequence {read_seq} to {} while selecting the complete generation; remediation: retry the query against one stable current generation",
            vault.latest_seq()
        )
        .into());
    }
    drop(read_lease);

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
/// - [`ASTRO_KERNEL_ANSWER_QUERY_OOV`] when the query yields no S20 vector.
/// - [`astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT`] when the members carry no
///   persisted S20 vectors, so nothing can be ranked.
/// - A stale index, a dimension mismatch, or a table load failure propagates the
///   underlying coded error verbatim.
fn resolve_query_candidates<C>(
    vault: &AsterVault<C>,
    vault_panel_root: &Path,
    project: &str,
    generation: &astrolabe_weave::CurrentKernelGenerationArtifact,
    query: &str,
) -> Result<(Vec<CxId>, Value), DynError>
where
    C: Clock,
{
    use astrolabe_panel::{StaticEmbeddingInput, encode_static_embedding_slot};
    use astrolabe_weave::search::SLOT_NAME_SEMANTIC;
    use astrolabe_weave::search_index::split_identifier_tokens;

    let total_started = std::time::Instant::now();
    let usage_before = vault.process_usage_snapshot()?;
    // Embed the query into S20 with the exact production input shape whose
    // encoder identity is persisted beside the admitted real-query corpus.
    // with. This deliberately happens before touching project index state: an
    // OOV query refuses without loading or constructing an unrelated index.
    let table_started = std::time::Instant::now();
    let table = astrolabe_panel::shared_default_static_embedding_table()?;
    let table_resolution_ms = elapsed_millis(table_started.elapsed())?;
    let encoding_started = std::time::Instant::now();
    let input = StaticEmbeddingInput {
        body_tokens: split_identifier_tokens(query),
        doc_tokens: Vec::new(),
        name: query.to_string(),
        qualified_name: query.to_string(),
    };
    let encoded = encode_static_embedding_slot(SLOT_NAME_SEMANTIC, &input, table)?;
    let SlotVector::Dense {
        data: query_vector, ..
    } = encoded
    else {
        return Err(format!(
            "{ASTRO_KERNEL_ANSWER_QUERY_OOV}: query {query:?} carries no token the frozen \
             name-semantic embedding table knows, so it reaches no kernel member; remediation: \
             rephrase the query using identifiers or vocabulary the indexed corpus contains"
        )
        .into());
    };
    let query_encoding_ms = elapsed_millis(encoding_started.elapsed())?;

    let descriptor_started = std::time::Instant::now();
    let descriptor_read = astrolabe_weave::read_current_kernel_generation_descriptor(
        vault,
        project,
        &generation.artifact.scope_id,
        &generation.artifact.members_hash,
    )?
    .ok_or_else(|| {
        astrolabe_weave::search::SearchError::new(
            astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT,
            format!(
                "complete kernel generation {} has no current member-index descriptor",
                generation.manifest.generation_id
            ),
            "Rebuild the kernel so artifact/descriptor/map/HNSW/query/report rows are atomically published before serving queries.",
        )
    })?;
    if descriptor_read.manifest.generation_id != generation.manifest.generation_id
        || descriptor_read.pointer != generation.pointer
    {
        return Err(astrolabe_weave::search::SearchError::new(
            astrolabe_weave::ASTRO_KERNEL_GENERATION_CORRUPT,
            format!(
                "kernel request selected artifact generation {} but descriptor generation {}",
                generation.manifest.generation_id, descriptor_read.manifest.generation_id
            ),
            "Retry only after one current composite pointer selects every artifact/index/query/report row; no cross-generation join is served.",
        )
        .into());
    }
    let descriptor = descriptor_read.descriptor;
    let request_source_verification = astrolabe_weave::verify_kernel_member_index_source_at_latest(
        vault,
        vault_panel_root,
        &descriptor,
    )?;
    let descriptor_read_ms = elapsed_millis(descriptor_started.elapsed())?;
    let cache_key = format!(
        "{}:{}",
        generation.manifest.generation_id,
        kernel_index_cache_key(&descriptor)?
    );
    let cache = KERNEL_INDEX_CACHE.get_or_init(|| Mutex::new(KernelIndexCache::default()));
    let (load_cell, cache_entries) = {
        let mut cache = cache.lock().map_err(|_| kernel_index_cache_poisoned())?;
        let cell = cache.load_cell(cache_key)?;
        (cell, cache.entries.len())
    };
    let artifact_load_started = std::time::Instant::now();
    let mut artifact_loaded_this_query = false;
    let index = load_cell
        .get_or_init(|| {
            artifact_loaded_this_query = true;
            let current = astrolabe_weave::read_current_kernel_generation(
                vault,
                project,
                &generation.artifact.scope_id,
            )?
            .ok_or_else(|| {
                astrolabe_weave::search::SearchError::new(
                    astrolabe_weave::ASTRO_KERNEL_INDEX_ABSENT,
                    "complete kernel generation disappeared before full HNSW load".to_string(),
                    "Preserve the vault and rebuild the exact complete kernel generation.",
                )
            })?;
            if current.manifest.generation_id != generation.manifest.generation_id
                || current.pointer != generation.pointer
            {
                return Err(astrolabe_weave::search::SearchError::new(
                    astrolabe_weave::ASTRO_KERNEL_GENERATION_CORRUPT,
                    format!(
                        "kernel request selected generation {} but HNSW load selected {}",
                        generation.manifest.generation_id, current.manifest.generation_id
                    ),
                    "Retry only after one stable composite pointer selects the entire generation.",
                ));
            }
            let source = astrolabe_weave::verify_kernel_member_index_source_at_latest(
                vault,
                vault_panel_root,
                &current.index.descriptor,
            )?;
            Ok(std::sync::Arc::new(VerifiedKernelIndexLoad {
                index: current.index,
                source,
                generation_id: current.manifest.generation_id,
            }))
        })
        .clone()?;
    if index.generation_id != generation.manifest.generation_id {
        return Err(astrolabe_weave::search::SearchError::new(
            astrolabe_weave::ASTRO_KERNEL_GENERATION_CORRUPT,
            format!(
                "kernel cache selected generation {} for request generation {}",
                index.generation_id, generation.manifest.generation_id
            ),
            "Clear the process by restarting Astrolabe and inspect the composite generation cache key; a different generation is never served.",
        )
        .into());
    }
    let index_cache_hit = !artifact_loaded_this_query;
    let index_artifact_load_ms = elapsed_millis(artifact_load_started.elapsed())?;
    let k = index.index.descriptor.indexed_member_count as u64;
    let ranking_started = std::time::Instant::now();
    let ranked = astrolabe_weave::kernel_query_loaded_members(
        &index.index,
        &generation.artifact.members_hash,
        &query_vector,
        k,
        k,
    )?;
    let ann_ranking_ms = elapsed_millis(ranking_started.elapsed())?;
    let process_usage = vault.process_usage_snapshot()?.phase_since(usage_before);
    let total_ms = elapsed_millis(total_started.elapsed())?;

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
        "embedded_slot": SLOT_NAME_SEMANTIC.get(),
        "generation_id": generation.manifest.generation_id,
        "source_generation_identity": generation.manifest.source_generation_identity,
        "query_encoder_identity": generation.query_corpus.encoder,
        "admission_query_corpus_hash": generation.query_corpus.corpus_hash,
        "admission_query_corpus": generation.query_corpus,
        "graph_routed_report_hash": generation.graph_routed_report.report_hash,
        "graph_routed_report": generation.graph_routed_report,
        "artifact_source_identity": generation.artifact.source_identity,
        "fvs_validity": generation.artifact.fvs_validity,
        "compactness": generation.artifact.compactness,
        "generation_manifest": generation.manifest,
        "generation_pointer": generation.pointer,
        "query_vector_dim": query_vector.len(),
        "index_kind": index.index.descriptor.index_kind.as_str(),
        "members_hash": ranked.members_hash,
        "base_seq": ranked.base_seq,
        "descriptor_bindings_blake3": index.index.descriptor.bindings_blake3,
        "descriptor_hnsw_artifact_blake3": index.index.descriptor.hnsw_artifact_blake3,
        "hnsw_artifact_bytes": index.index.descriptor.hnsw_artifact_bytes,
        "source_binding_seq": index.index.descriptor.source_binding_seq,
        "source_final_verification_seq": index.index.descriptor.source_final_verification_seq,
        "source_binding": index.index.descriptor.source_binding,
        "source_read_verification": request_source_verification,
        "cache_load_source_verification": index.source,
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
            "capacity_entries": kernel_index_cache_entries()?,
            "resident_generation_cells": cache_entries,
            "single_flight": true,
        },
        "member_count": generation.artifact.member_count,
        "indexed_member_count": ranked.indexed_member_count,
        "missing_vector_members": index.index.descriptor.missing_vector_members,
        "ranked_member_count": matched_ids.len(),
        "unresolved_symbol_ids": [],
        "ranked_members": ranked_json,
        "trust": "verified",
        "freshness": "fresh",
        "provenance": [
            format!("kernel-generation:{}", generation.manifest.generation_id),
            "vault:Kernel/current-pointer+manifest+artifact+S20-member-index+admission".to_string(),
            "astrolabe_weave::kernel_query_loaded_members(complete composite generation)".to_string(),
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

fn kernel_index_cache_entries() -> Result<usize, astrolabe_weave::search::SearchError> {
    let entries = KERNEL_ANSWER_KNOBS
        .iter()
        .find(|knob| knob.name == KNOB_ANSWER_INDEX_CACHE_ENTRIES)
        .ok_or_else(|| {
            astrolabe_weave::search::SearchError::new(
                ASTRO_KERNEL_INDEX_UNAVAILABLE,
                format!(
                    "kernel answer knob registry {} does not declare {:?}",
                    KERNEL_ANSWER_KNOB_REGISTRY_VERSION, KNOB_ANSWER_INDEX_CACHE_ENTRIES
                ),
                "restore the complete immutable kernel-answer knob registry before serving cached generations",
            )
        })?
        .default;
    if entries == 0 {
        return Err(astrolabe_weave::search::SearchError::new(
            ASTRO_KERNEL_INDEX_UNAVAILABLE,
            "kernel answer index-cache capacity is zero, so no resident generation can be admitted",
            "set the immutable cache-capacity knob to a positive value before serving kernel answers",
        ));
    }
    usize::try_from(entries).map_err(|_| {
        astrolabe_weave::search::SearchError::new(
            ASTRO_KERNEL_INDEX_UNAVAILABLE,
            format!(
                "kernel answer index-cache capacity {entries} is not representable as usize"
            ),
            "set the immutable cache-capacity knob to a positive value representable on this target",
        )
    })
}

fn elapsed_millis(
    duration: std::time::Duration,
) -> Result<u64, astrolabe_weave::search::SearchError> {
    u64::try_from(duration.as_millis()).map_err(|_| {
        astrolabe_weave::search::SearchError::new(
            ASTRO_KERNEL_ANSWER_TIMING_OVERFLOW,
            format!(
                "kernel answer phase duration {}ms is not representable as u64",
                duration.as_millis()
            ),
            "restart the operation with a receipt format capable of representing the measured duration",
        )
    })
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
            )?;
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
) -> Result<Value, DynError> {
    let recorded_artifact =
        String::from_utf8(astrolabe_provenance::recorded_kernel_answer_bytes(recorded))?;
    Ok(json!({
        "recorded_artifact": recorded_artifact,
        "graph": {
            "nodes": nodes.iter().map(reproduce_fixture_node_json).collect::<Vec<_>>(),
            "edges": edges.iter().map(reproduce_fixture_edge_json).collect::<Vec<_>>(),
            "matched_ids": matched_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        },
    }))
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
